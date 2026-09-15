#requires -Version 7.2
[CmdletBinding()]
param([string]$OutputRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../.tmp/personal-feed-result-20260907')),
    [string]$CompletedLinuxSnapshot = '')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ProductionFeedPromotion.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'ProductionReleaseState.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'PersonalFeedPromotionResult.psm1') -Force -DisableNameChecking
$module = Get-Module PersonalFeedPromotionResult
$root = Join-Path $OutputRoot ([Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory((Join-Path $root 'evidence'))
$signer = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
$count = 0
$actual = @{}
if ($CompletedLinuxSnapshot) {
    foreach($entry in Get-ChildItem -LiteralPath (Join-Path $CompletedLinuxSnapshot 'evidence') -File) {
        $actual[$entry.Name] = [IO.File]::ReadAllBytes($entry.FullName)
    }
}
function ActualJson([string]$Role) { ConvertFrom-StrictProductionJsonBytes -Bytes $actual[$Role] -Label "actual Linux $Role" }
function B64([byte[]]$Bytes) { [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_') }
function Sha([byte[]]$Bytes) { Get-ProductionSha256Bytes -Bytes $Bytes }
function Json($Value) { ConvertTo-ProductionJsonBytes -Value $Value }
function Clone($Value) { ConvertFrom-StrictProductionJsonBytes -Bytes (Json $Value) -Label 'test fixture' }
function Put([string]$Role, $Value, [switch]$Raw) {
    [byte[]]$bytes = if ($Raw) { $Value } else { Json $Value }
    [IO.File]::WriteAllBytes((Join-Path (Join-Path $root 'evidence') $Role),$bytes)
    return [ordered]@{role=$Role;sizeBytes=[int64]$bytes.Length;sha256=(Sha $bytes)}
}
function Sign([byte[]]$Bytes) {
    # Rejection sampling is test-only. Production signers must normalize low S.
    do {
        $signature = $signer.SignData($Bytes,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
        try { Assert-ProductionEs256P1363LowS $signature 'test signature'; $low = $true } catch { $low = $false }
    } until ($low)
    B64 $signature
}
function Domain([string]$Name,$Value) { & $module {param($n,$v) Get-PersonalResultDomainDigest $n $v} $Name $Value }
function SaveResult($Value, [switch]$Unsigned) {
    if (-not $Unsigned) { $Value.authentication.value = Sign (Get-PersonalFeedPromotionResultAuthenticationPayload (Clone $Value)) }
    [IO.File]::WriteAllBytes((Join-Path $root 'result.v1.json'),(Json $Value))
}
function Verify([switch]$Historical) {
    $admission = Open-PersonalFeedPromotionResult $root
    try { Assert-PersonalFeedPromotionResultBinding -Admission $admission @context -Fresh:(-not $Historical) }
    finally { Close-PersonalFeedPromotionResult $admission }
}
function Reject([string]$Name,[scriptblock]$Action,[string]$Expected) {
    try { & $Action } catch {
        if ($_.Exception.Message -notlike "*$Expected*") { throw "$Name failed for unexpected reason: $($_.Exception.Message)" }
        $script:count++; Write-Output "PASS $Name"; return
    }
    throw "$Name was incorrectly accepted."
}
try {
    $now = [DateTimeOffset]::UtcNow
    $created = $now.AddMinutes(-5).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    $authorizedAt = $now.AddMinutes(-4).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    $publishedAt = $now.AddMinutes(-3).ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'")
    $completedAt = $now.AddMinutes(-2).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    $expires = $now.AddHours(1).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    if ($actual.Count) {
        $publishedAt = (ActualJson operation-result).publishedAtUtc
        $created = ([DateTimeOffset]::Parse($publishedAt)).AddMinutes(-5).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
        $authorizedAt = ([DateTimeOffset]::Parse($publishedAt)).AddMinutes(-4).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    }
    $q = $signer.ExportParameters($false)
    $trust = [ordered]@{algorithm='ES256';keyId='isolated-feed-test';purpose='feed-promotion-response';x=(B64 $q.Q.X);y=(B64 $q.Q.Y)}
    $releaseTrust = [ordered]@{algorithm='ES256';keyId='isolated-release-test';purpose='release-manifest-signing';x=(B64 $q.Q.X);y=(B64 $q.Q.Y)}
    $plan = Clone ([ordered]@{edition='Personal';targetChannel='pilot';releaseSetId='personal-fixture-1';externalResponseTrusts=@{feedPromotion=$trust};releaseManifestTrust=$releaseTrust;authenticodePolicy=@{signerSha256Thumbprint=('a'*64)}})
    if ($actual.Count) {
        $actualTrust = ActualJson trust-configuration
        $plan.releaseManifestTrust.keyId=$actualTrust.releaseKeys[0].keyId
        $plan.releaseManifestTrust.x=$actualTrust.releaseKeys[0].x; $plan.releaseManifestTrust.y=$actualTrust.releaseKeys[0].y
        $plan.authenticodePolicy.signerSha256Thumbprint=$actualTrust.expectedAuthenticodeSignerSha256Thumbprint
    }
    $identity = Clone ([ordered]@{edition='Personal';planSha256=('b'*64);orchestrationId=[Guid]::NewGuid().ToString()})
    $context = @{Plan=$plan;Identity=$identity;IdentitySha256=('c'*64);R7HeadSha256=('d'*64);R8HeadSha256=('e'*64)}
    $operationId = [Guid]::NewGuid().ToString('N')
    if ($actual.Count) { $operationId=(ActualJson operation-result).operationId }
    $files = [Collections.Generic.List[object]]::new()
    $files.Add((Put launcher ([Text.Encoding]::UTF8.GetBytes('isolated-not-an-installable-launcher')) -Raw))
    $files.Add((Put runtime ([Text.Encoding]::UTF8.GetBytes('isolated-not-an-installable-runtime')) -Raw))
    if ($actual.Count) { $files.Clear(); $files.Add((Put launcher $actual.launcher -Raw)); $files.Add((Put runtime $actual.runtime -Raw)) }
    $artifacts = @(
        [ordered]@{component='client-bundle';releaseId='launcher-1';uri='https://feed.example.invalid/v2/releases/personal-fixture-1/client-bundle.zip';sizeBytes=$files[0].sizeBytes;sha256=$files[0].sha256;completeTreeSha256=('1'*64)},
        [ordered]@{component='runtime';releaseId='runtime-1';uri='https://feed.example.invalid/v2/releases/personal-fixture-1/runtime.zip';sizeBytes=$files[1].sizeBytes;sha256=$files[1].sha256;completeTreeSha256=('2'*64)}
    )
    $manifest = [ordered]@{schemaVersion=2;product='ensou-dsh-personal';environment='production';channel='pilot';releaseSetId=$plan.releaseSetId;generation=1;sequence=1;minAcceptedSequence=0;artifacts=$artifacts}
    if($actual.Count){$manifest=ActualJson release-manifest;$artifacts=$manifest.artifacts}
    $manifestDescriptor = if($actual.Count){Put release-manifest $actual['release-manifest'] -Raw}else{Put release-manifest $manifest}; $files.Add($manifestDescriptor)
    $channel = if($actual.Count){Put channel-head $actual['channel-head'] -Raw}else{Put channel-head $manifest}; $files.Add($channel)
    $candidate = @(
        [ordered]@{role='release-manifest';fileName='release-set.v2.json';relativePath='payload/release-set.v2.json';sizeBytes=$manifestDescriptor.sizeBytes;sha256=$manifestDescriptor.sha256},
        [ordered]@{role='launcher';fileName='client-bundle.zip';relativePath='payload/client-bundle.zip';sizeBytes=$files[0].sizeBytes;sha256=$files[0].sha256},
        [ordered]@{role='runtime';fileName='runtime.zip';relativePath='payload/runtime.zip';sizeBytes=$files[1].sizeBytes;sha256=$files[1].sha256}
    )
    $context.CandidateFiles = Clone $candidate
    $feedIdentity = if($actual.Count){Put feed-identity $actual['feed-identity'] -Raw}else{Put feed-identity ([ordered]@{schemaVersion=2;product='ensou-dsh-personal';environment='production';feedInstanceId=[Guid]::NewGuid().ToString('N')})}; $files.Add($feedIdentity)
    $executionTrust = if($actual.Count){Put trust-configuration $actual['trust-configuration'] -Raw}else{Put trust-configuration ([ordered]@{schemaVersion=1;manifestOrigin='https://feed.example.invalid/';artifactOrigin='https://feed.example.invalid/';releaseKeys=@(@{keyId=$releaseTrust.keyId;x=$releaseTrust.x;y=$releaseTrust.y});expectedAuthenticodeSignerSha256Thumbprint=('a'*64)})}; $files.Add($executionTrust)
    $cas = [ordered]@{channelHead=@{state='missing'};journalHead=@{state='missing'}}
    $request = [ordered]@{schemaVersion=1;requestType='ensou-dsh-launcher-offline-feed-promotion-request';operationId=$operationId;orchestrationId=$identity.orchestrationId;edition='Personal';exposureRing='pilot';feedChannel='pilot';publishScope='channel-head';releaseSetId=$plan.releaseSetId;
        sourceState=[ordered]@{schemaVersion=2;targetChannel='pilot';revision=7;phase='INSTALLER_SIGNATURE_IMPORTED';planSizeBytes=1;planSha256=$identity.planSha256;identitySizeBytes=1;identitySha256=$context.IdentitySha256;headSizeBytes=1;headSha256=$context.R7HeadSha256;receiptChainStartRevision=1;receiptChainSha256=('3'*64);candidateReceiptSha256=('4'*64)};
        expectedFeedIdentitySha256=$feedIdentity.sha256;feedCas=$cas;feedCasSha256=(Domain 'ensou-dsh-launcher-feed-promotion-cas-v1' $cas);payloadSetSha256=(Domain 'ensou-dsh-launcher-feed-promotion-payload-set-v1' $candidate);files=$candidate;authorizationTrust=$trust;requestNonce=('A'*43);createdAtUtc=$created;expiresAtUtc=$expires;productionAdmission='NO_GO';networkPublishPerformed=$false}
    $request.expiresAtUtc=([DateTimeOffset]::Parse($created)).AddMinutes(30).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    $requestDescriptor=Put offline-request $request; $files.Add($requestDescriptor); $context.SealedRequestSha256=$requestDescriptor.sha256
    $authorization = [ordered]@{schemaVersion=1;responseType='ensou-dsh-launcher-offline-feed-promotion-response';operationId=$operationId;orchestrationId=$identity.orchestrationId;edition='Personal';exposureRing='pilot';feedChannel='pilot';publishScope='channel-head';releaseSetId=$plan.releaseSetId;requestSha256=$requestDescriptor.sha256;requestNonce=$request.requestNonce;basePromotionHeadSha256=('5'*64);sourceStateHeadSha256=$context.R7HeadSha256;payloadSetSha256=$request.payloadSetSha256;feedCasSha256=$request.feedCasSha256;decision='AUTHORIZE_OFFLINE_BUNDLE';completedAtUtc=$authorizedAt;requestExpiresAtUtc=$expires;productionAdmission='OFFLINE_BUNDLE_ONLY';networkPublishPerformed=$false;authentication=[ordered]@{algorithm='ES256';keyId=$trust.keyId;purpose=$trust.purpose;payloadType='ensou-dsh-launcher-feed-promotion-response-authentication-v1';value=('A'*86)}}
    $promotionHead=[ordered]@{schemaVersion=1;stateType='ensou-dsh-launcher-offline-feed-promotion-state';operationId=$operationId;requestSha256=$requestDescriptor.sha256;requestNonce=$request.requestNonce;sourceStateHeadSha256=$context.R7HeadSha256;payloadSetSha256=$request.payloadSetSha256;status='PROMOTION_REQUEST_READY';productionAdmission='NO_GO';networkPublishPerformed=$false;updatedAtUtc=$created}
    $promotionHeadSha256=Sha (Json $promotionHead)
    $authorization.basePromotionHeadSha256=$promotionHeadSha256
    $authorization.requestExpiresAtUtc=$request.expiresAtUtc
    $authorization.authentication.value=Sign (Get-ProductionFeedPromotionResponseAuthenticationPayload (Clone $authorization))
    $authorizationDescriptor=Put offline-authorization $authorization; $files.Add($authorizationDescriptor)
    $operation=[ordered]@{schemaVersion=1;operationId=$operationId;requestSha256=('0'*64);product='ensou-dsh-personal';environment='production';channel='pilot';feedIdentitySha256=$feedIdentity.sha256;candidateManifestSizeBytes=$manifestDescriptor.sizeBytes;candidateManifestSha256=$manifestDescriptor.sha256;trustConfigurationSha256=$executionTrust.sha256;expectedChannelHead=@{state='missing';sizeBytes=$null;sha256=$null};expectedJournalHead=@{state='missing';sizeBytes=$null;sha256=$null}}
    $operation.requestSha256=Sha (Json $operation)
    if($actual.Count){$operation=ActualJson operation-request;$files.Add((Put operation-request $actual['operation-request'] -Raw))}else{$files.Add((Put operation-request $operation))}
    $journalArtifacts=@(); foreach($artifact in $artifacts){$journalArtifacts += [ordered]@{component=$artifact.component;releaseId=$artifact.releaseId;fileName=([Uri]$artifact.uri).Segments[-1];sizeBytes=$artifact.sizeBytes;sha256=$artifact.sha256;completeTreeSha256=$artifact.completeTreeSha256}}
    $entry=[ordered]@{schemaVersion=1;product='ensou-dsh-personal';environment='production';channel='pilot';releaseSetId=$plan.releaseSetId;generation=1;sequence=1;minAcceptedSequence=0;manifestSha256=$manifestDescriptor.sha256;previousEntryFileName='';previousEntrySha256=('0'*64);artifacts=$journalArtifacts;publishedAtUtc=$publishedAt}
    $journalDescriptor=if($actual.Count){Put journal-entry $actual['journal-entry'] -Raw}else{Put journal-entry $entry}; $files.Add($journalDescriptor)
    $head=[ordered]@{schemaVersion=1;product='ensou-dsh-personal';environment='production';channel='pilot';releaseSetId=$plan.releaseSetId;generation=1;sequence=1;manifestSha256=$manifestDescriptor.sha256;entryFileName='entry-1.json';entrySha256=$journalDescriptor.sha256}
    $headDescriptor=if($actual.Count){Put journal-head $actual['journal-head'] -Raw}else{Put journal-head $head}; $files.Add($headDescriptor)
    $receipt=[ordered]@{schemaVersion=1;operationId=$operationId;requestSha256=$operation.requestSha256;product='ensou-dsh-personal';environment='production';channel='pilot';releaseSetId=$plan.releaseSetId;generation=1;sequence=1;minAcceptedSequence=0;manifestSha256=$manifestDescriptor.sha256;channelManifestRelativePath='public/channels/pilot/release-set.v2.json';channelManifestUri='https://feed.example.invalid/v2/channels/pilot/release-set.v2.json';promotionJournalEntryRelativePath='journal/pilot/entry-1.json';promotionJournalSha256=$journalDescriptor.sha256;channelHead=@{state='present';sizeBytes=$channel.sizeBytes;sha256=$channel.sha256};journalHead=@{state='present';sizeBytes=$headDescriptor.sizeBytes;sha256=$headDescriptor.sha256};publishedAtUtc=$publishedAt;channelHeadChanged=$true;immutableReleaseCreated=$true}
    if($actual.Count){$files.Add((Put operation-result $actual['operation-result'] -Raw))}else{$files.Add((Put operation-result $receipt))}
    $bundleInventory=@([ordered]@{role='promotion-request';fileName='request.v1.json';relativePath='bundle/request.v1.json';sizeBytes=$requestDescriptor.sizeBytes;sha256=$requestDescriptor.sha256},[ordered]@{role='promotion-response';fileName='response.v1.json';relativePath='bundle/response.v1.json';sizeBytes=$authorizationDescriptor.sizeBytes;sha256=$authorizationDescriptor.sha256})
    foreach($file in $candidate){$bundleInventory += [ordered]@{role=$file.role;fileName=$file.fileName;relativePath=('bundle/payload/'+$file.fileName);sizeBytes=$file.sizeBytes;sha256=$file.sha256}}
    $result=[ordered]@{schemaVersion=1;resultType='ensou-dsh-personal-feed-execution-result';operationId=$operationId;orchestrationId=$identity.orchestrationId;releaseSetId=$plan.releaseSetId;planSha256=$identity.planSha256;sourceIdentitySha256=$context.IdentitySha256;sourceR7HeadSha256=$context.R7HeadSha256;sourceR8HeadSha256=$context.R8HeadSha256;requestSha256=$requestDescriptor.sha256;authorizationSha256=$authorizationDescriptor.sha256;promotionHeadSha256=('5'*64);bundleHeadSha256=('6'*64);bundleSetSha256=(Domain 'ensou-dsh-launcher-feed-promotion-offline-bundle-v1' $bundleInventory);completedAtUtc=$completedAt;expiresAtUtc=$expires;files=@($files.ToArray());authentication=[ordered]@{algorithm='ES256';keyId=$trust.keyId;purpose=$trust.purpose;payloadType='ensou-dsh-personal-feed-execution-result-v1';value=('A'*86)}}
    $bundleHead=[ordered]@{schemaVersion=1;stateType='ensou-dsh-launcher-offline-feed-promotion-bundle';operationId=$operationId;requestSha256=$requestDescriptor.sha256;requestNonce=$request.requestNonce;sourceStateHeadSha256=$context.R7HeadSha256;payloadSetSha256=$request.payloadSetSha256;basePromotionHeadSha256=$promotionHeadSha256;responseSha256=$authorizationDescriptor.sha256;bundleSetSha256=$result.bundleSetSha256;status='EXTERNAL_PUBLISH_BUNDLE_READY';productionAdmission='NO_GO';networkPublishPerformed=$false;updatedAtUtc=$authorizedAt}
    $result.promotionHeadSha256=$promotionHeadSha256; $result.bundleHeadSha256=Sha (Json $bundleHead)
    SaveResult $result; Verify; $count++; Write-Output 'PASS isolated authenticated completed result'
    Verify; $count++; Write-Output 'PASS exact result verification replay'
    $original=Clone $result
    $result.operationId=[Guid]::NewGuid().ToString('N'); SaveResult $result -Unsigned
    Reject 'wrong signature' {Verify} 'signature is invalid'
    SaveResult $result; Reject 'signed wrong operation' {Verify} 'operationId differs'
    $result=Clone $original; $result.sourceR8HeadSha256='9'*64; SaveResult $result
    Reject 'signed wrong r8' {Verify} 'sealed r8'
    $result=Clone $original; $result.bundleSetSha256='9'*64; SaveResult $result
    Reject 'signed wrong offline bundle' {Verify} 'bundle-set'
    $result=Clone $original; $result.authentication.payloadType='ensou-dsh-launcher-feed-promotion-response-authentication-v1'; SaveResult $result -Unsigned
    Reject 'offline authorization cannot masquerade as completed result' {Verify} 'schema'
    $result=Clone $original; SaveResult $result
    $artifactPath=Join-Path $root 'evidence/runtime'; $artifactBytes=[IO.File]::ReadAllBytes($artifactPath)
    [IO.File]::WriteAllBytes($artifactPath,[Text.Encoding]::UTF8.GetBytes('changed'))
    Reject 'published artifact drift' {Verify} 'raw bytes drifted'
    [IO.File]::WriteAllBytes($artifactPath,$artifactBytes)
    $result=Clone $original; $result.expiresAtUtc=$now.AddMinutes(-1).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"); SaveResult $result
    Reject 'expired new import' {Verify} 'expired'
    Verify -Historical; $count++; Write-Output 'PASS historical completed result does not expire'
    $result=Clone $original; SaveResult $result
    $result.files[0].role='../runtime'; SaveResult $result
    Reject 'path-shaped role' {Verify} 'schema'
    SaveResult $original
    $promotionRoot=$root+'-offline'
    [void][IO.Directory]::CreateDirectory((Join-Path $promotionRoot 'bundle/payload'))
    [IO.File]::WriteAllBytes((Join-Path $promotionRoot 'head.json'),(Json $promotionHead))
    [IO.File]::WriteAllBytes((Join-Path $promotionRoot 'bundle/head.v1.json'),(Json $bundleHead))
    [IO.File]::Copy((Join-Path $root 'evidence/offline-request'),(Join-Path $promotionRoot 'bundle/request.v1.json'))
    [IO.File]::Copy((Join-Path $root 'evidence/offline-authorization'),(Join-Path $promotionRoot 'bundle/response.v1.json'))
    foreach($file in $candidate){[IO.File]::Copy((Join-Path (Join-Path $root 'evidence') $file.role),(Join-Path (Join-Path $promotionRoot 'bundle/payload') $file.fileName))}
    $offlineArgs=@{PromotionRoot=$promotionRoot;ExpectedPromotionHeadSha256=$promotionHeadSha256;ExpectedBundleHeadSha256=$original.bundleHeadSha256;ExpectedSourceHeadSha256=$context.R7HeadSha256;ExpectedRequestSha256=$requestDescriptor.sha256;ExpectedResponseSha256=$authorizationDescriptor.sha256;ExpectedBundleSetSha256=$original.bundleSetSha256}
    Reject 'Personal bundle cannot use implicit Enterprise edition' { $wrong=Open-ProductionFeedPromotionBundleAdmission @offlineArgs; Close-ProductionFeedPromotionBundleAdmission $wrong } 'edition'
    $offline=Open-ProductionFeedPromotionBundleAdmission @offlineArgs -ExpectedEdition Personal
    try {
        $count++; Write-Output 'PASS Personal offline bundle real locked admission'
        if ($actual.Count) {
            Import-Module (Join-Path $PSScriptRoot 'PersonalFeedExecutionResultProducer.psm1') -Force -DisableNameChecking
            $producer=Get-Module PersonalFeedExecutionResultProducer
            $output=$root+'-produced'
            $fixtureSigner=$signer
            $callback={
                param([byte[]]$payload)
                do {
                    $sig=$fixtureSigner.SignData($payload,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
                    try{ProductionReleaseState\Assert-ProductionEs256P1363LowS $sig 'test signature';$low=$true}catch{$low=$false}
                }until($low)
                [Convert]::ToBase64String($sig).TrimEnd('=').Replace('+','-').Replace('/','_')
            }.GetNewClosure()
            $produced=& $producer {param($snapshot,$out,$ctx,$auth,$sign,$expire) New-PersonalExecutionResultFromSnapshot -SnapshotRoot $snapshot -OutputRoot $out -Context $ctx -Offline $auth -Signer $sign -ExpiresAtUtc $expire} ([IO.Path]::GetFullPath($CompletedLinuxSnapshot)) $output $context $offline $callback $now.AddHours(1)
            $signed=Open-PersonalFeedPromotionResult $output
            try{Assert-PersonalFeedPromotionResultBinding -Admission $signed @context -Fresh}finally{Close-PersonalFeedPromotionResult $signed}
            $count++; Write-Output 'PASS real Linux snapshot through offline signing producer core and full validator (not public r8 state integration)'
            foreach($overlap in @($root,(Join-Path $root 'nested'),[IO.Path]::GetDirectoryName($root))) {
                Reject 'public producer overlapping state/output rejects before signing' {
                    New-PersonalFeedExecutionResultBundle -StateRoot $root -PromotionRoot $promotionRoot -SnapshotRoot ([IO.Path]::GetFullPath($CompletedLinuxSnapshot)) -OutputRoot $overlap -ExpectedHeadSha256 $context.R8HeadSha256 -Signer {throw 'signer must not run'} -ExpiresAtUtc $now.AddHours(1)
                } 'must not overlap'
            }
            $checkout=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
            $publicArgs=@{StateRoot=$root;PromotionRoot=$promotionRoot;SnapshotRoot=[IO.Path]::GetFullPath($CompletedLinuxSnapshot);OutputRoot=($root+'-never-created');ExpectedHeadSha256=$context.R8HeadSha256;Signer={throw 'signer must not run'};ExpiresAtUtc=$now.AddHours(1)}
            foreach($member in @('OutputRoot','SnapshotRoot')) {
                $originalPath=$publicArgs[$member]
                foreach($forbidden in @($checkout,(Join-Path $checkout '.git/personal-result'),[IO.Path]::GetDirectoryName($checkout))) {
                    $publicArgs[$member]=$forbidden
                    Reject "public producer $member rejects checkout/git/ancestor" {New-PersonalFeedExecutionResultBundle @publicArgs} 'must not overlap'
                }
                $publicArgs[$member]='relative-result'
                Reject "public producer $member rejects relative path" {New-PersonalFeedExecutionResultBundle @publicArgs} 'must be absolute'
                $publicArgs[$member]=$originalPath
            }
        }
    }finally{Close-ProductionFeedPromotionBundleAdmission $offline}
    Reject 'generic Personal r8 evidence fails before reading/writing state' {
        Assert-PersonalFeedPromotionTransition -State ([pscustomobject]@{}) -Phase PILOT_PROMOTION_REQUESTED -Data ([pscustomobject]@{evidenceType='PILOT_PROMOTION_REQUESTED';relativePath='untrusted/generic.json';sha256=('0'*64)})
    } 'generic evidence cannot advance'
    Reject 'generic Personal r9 evidence fails before reading/writing state' {
        Assert-PersonalFeedPromotionTransition -State ([pscustomobject]@{}) -Phase PILOT_FEED_PROMOTED -Data ([pscustomobject]@{evidenceType='PILOT_FEED_PROMOTED';relativePath='untrusted/generic.json';sha256=('0'*64)})
    } 'generic evidence cannot advance'
    # Exercise the actual import entry's early path guards without executing the
    # dirty-checkout top-level script or manufacturing an authenticated r8 state.
    $tokens=$null;$parseErrors=$null
    $entryAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Invoke-LauncherProductionRelease.ps1'),[ref]$tokens,[ref]$parseErrors)
    foreach($name in @('Test-SameOrDescendantPath','Assert-PersonalCompletedResultPathBoundary','Invoke-PersonalPilotCompletedResultImport')) {
        $definition=@($entryAst.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
        if($definition.Count -ne 1){throw 'Import guard test requires one exact production function.'}
        . ([scriptblock]::Create($definition[0].Extent.Text))
    }
    $RepositoryRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
    $fakeState=[pscustomobject]@{Head=[pscustomobject]@{revision=8};StateRoot=$root}
    foreach($forbidden in @($RepositoryRoot,(Join-Path $RepositoryRoot '.git/personal-result'),[IO.Path]::GetDirectoryName($RepositoryRoot),$promotionRoot,$root)) {
        $PersonalFeedPromotionResultPath=Join-Path $forbidden 'result.v1.json'
        Reject 'actual import entry rejects checkout/git/ancestor/state/promotion result' {
            Invoke-PersonalPilotCompletedResultImport -Plan $null -PlanInput $null -StateSchemaPath '' -InitialState $fakeState
        } 'must be absolute and disjoint'
    }
    $PersonalFeedPromotionResultPath='relative/result.v1.json'
    Reject 'actual import entry rejects relative result path' {
        Invoke-PersonalPilotCompletedResultImport -Plan $null -PlanInput $null -StateSchemaPath '' -InitialState $fakeState
    } 'must be absolute'
    [IO.File]::WriteAllBytes(($root+'-verification.json'),(Json ([ordered]@{schemaVersion=1;assertions=$count;passed=$true;completedLinuxSnapshot=$CompletedLinuxSnapshot;fixtureRoot=$root;publicProducerPositive='UNVERIFIED_NO_AUTHENTIC_PERSONAL_R8_FIXTURE';publicR8ToR9Cas='UNVERIFIED';productionPublishPerformed=$false})))
    Write-Output "PERSONAL-FEED-RESULT-PASS assertions=$count fixture=$root scope=isolated-signature-fixture-not-production"
} finally { $signer.Dispose() }
