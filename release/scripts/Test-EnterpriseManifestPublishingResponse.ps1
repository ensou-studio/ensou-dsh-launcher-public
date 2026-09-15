#requires -Version 7.2
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# These are issuer plumbing/cryptography tests. The compiled Publisher verifier
# has separate production-trust tests. The issuer-function fixture below uses
# explicit seams; the real process helper also runs literal-output test children.
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$issuerPath = Join-Path $PSScriptRoot 'New-EnterpriseManifestPublishingResponse.ps1'
$modulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$schemaPath = Join-Path $root 'release\schemas\launcher-manifest-publishing-response-v1.schema.json'
Microsoft.PowerShell.Core\Import-Module $modulePath -Force

function Assert-Test([bool]$Condition,[string]$Message) { if(-not $Condition){throw "FAIL: $Message"} }
function B64([byte[]]$Bytes) { [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_') }

$tokens = $null; $errors = $null
[void][Management.Automation.Language.Parser]::ParseFile($issuerPath,[ref]$tokens,[ref]$errors)
Assert-Test ($errors.Count -eq 0) 'issuer parses without syntax errors'
$source = [IO.File]::ReadAllText($issuerPath)
foreach($required in @(
    'Enter-ProductionReleaseStateReadLock',
    'Get-ProductionReleaseState',
    'Assert-ProductionRuntimeSourceReleaseAdmission',
    'Assert-ProductionReleaseManifestCandidate',
    '--verify-runtime-source-admission',
    'ArgumentList.Add',
    'ExpectedPublisherVerifierSha256',
    'create-only and already exists',
    'Directory]::Move',
    'Get-ProductionReleaseManifestPublishingResponseAuthenticationPayload')) {
    Assert-Test $source.Contains($required) "issuer retains required gate '$required'"
}
Assert-Test (-not $source.Contains('VerifierInvoker')) 'issuer has no callable verifier-bypass parameter'
Assert-Test (-not $source.Contains('toolPath')) 'issuer cannot serialize verifier path into the response'

# Build an exact r5 response authentication payload with a generated P-256 key,
# normalize the signature low-S, and verify through the real response verifier.
$key = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
try {
    $public = $key.ExportParameters($false)
    $trust = [pscustomobject][ordered]@{ algorithm='ES256'; keyId='issuer-test'; purpose='manifest-publishing-response'; x=(B64 $public.Q.X); y=(B64 $public.Q.Y) }
    $response = [ordered]@{
        schemaVersion=1; responseType='ensou-dsh-launcher-manifest-publishing-response'
        orchestrationId='12345678-1234-4123-8123-123456789abc'; edition='Enterprise'; releaseSetId='issuer-test-r5'; channel='stable'
        planSha256=('a'*64); requestSha256=('b'*64); requestNonce=('A'*43); baseHeadSha256=('c'*64); admissionHeadSha256=('d'*64); admissionRevision=4
        requestExpiresAtUtc='2026-09-10T12:00:00Z'; completedAtUtc='2026-09-10T11:00:00Z'
        files=@(
            [ordered]@{role='release-manifest';fileName='release-set.v2.json';relativePath='candidate/release-set.v2.json';sizeBytes=1;sha256=('1'*64)},
            [ordered]@{role='release-public-key';fileName='release-public-key.v2.json';relativePath='candidate/release-public-key.v2.json';sizeBytes=1;sha256=('2'*64)},
            [ordered]@{role='launcher';fileName='launcher.zip';relativePath='candidate/launcher.zip';sizeBytes=1;sha256=('3'*64)},
            [ordered]@{role='runtime';fileName='runtime.zip';relativePath='candidate/runtime.zip';sizeBytes=1;sha256=('4'*64)},
            [ordered]@{role='plugin-policy';fileName='policy.zip';relativePath='candidate/policy.zip';sizeBytes=1;sha256=('5'*64)})
        authentication=[ordered]@{algorithm='ES256';keyId='issuer-test';purpose='manifest-publishing-response';payloadType='ensou-dsh-launcher-manifest-publishing-response-authentication-v1'}
    }
    $payload = ProductionReleaseState\Get-ProductionReleaseManifestPublishingResponseAuthenticationPayload -Response ([pscustomobject]$response)
    $signature = $key.SignData($payload,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
    # The test intentionally exercises the product low-S verifier: if random S
    # is high, derive n-S using the same P-256 order as the issuer contract.
    $n=[byte[]](0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51)
    $half=[byte[]](0x7f,0xff,0xff,0xff,0x80,0x00,0x00,0x00,0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xde,0x73,0x7d,0x56,0xd3,0x8b,0xcf,0x42,0x79,0xdc,0xe5,0x61,0x7e,0x31,0x92,0xa8)
    $high=$false;for($i=0;$i -lt 32;$i++){if($signature[32+$i] -gt $half[$i]){$high=$true;break};if($signature[32+$i] -lt $half[$i]){break}}
    if($high){$borrow=0;for($i=31;$i -ge 0;$i--){$v=[int]$n[$i]-[int]$signature[32+$i]-$borrow;if($v -lt 0){$v+=256;$borrow=1}else{$borrow=0};$signature[32+$i]=[byte]$v}}
    $response.authentication.value=B64 $signature
    $bytes=ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $response
    $parsed=ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes -Bytes $bytes -Label 'issuer test r5' -SchemaPath $schemaPath
    ProductionReleaseState\Assert-ProductionReleaseManifestPublishingResponseAuthentication -Response $parsed -Trust $trust
    $parsed.planSha256='f'*64
    $rejected=$false;try{ProductionReleaseState\Assert-ProductionReleaseManifestPublishingResponseAuthentication -Response $parsed -Trust $trust}catch{$rejected=$true}
    Assert-Test $rejected 'r5 response mutation invalidates real ES256 authentication'
} finally {$key.Dispose()}

Write-Host 'PASS: Enterprise manifest-publishing issuer source contract and real ES256 response authentication.'

# Execute the actual product function, not a rewritten issuer. Explicit test
# seams are only complete state replay, compiled-verifier execution, and full
# signed candidate validation. Real state/file/directory leases, strict schemas,
# r4 payload lookup, organization-proof binding, PKCS8 key import, r5 signing,
# staged output and copied bytes remain production code. This is NOT acceptance
# of a production runtime, compiled trust binary, or signed candidate archive.
$issuerAst=[Management.Automation.Language.Parser]::ParseFile($issuerPath,[ref]$tokens,[ref]$errors)
Assert-Test ($errors.Count -eq 0) 'issuer AST parses for execution'
$repositoryRoot=$root
$schemaRoot=Join-Path $root 'release\schemas'
$stateSchemaPath=Join-Path $schemaRoot 'launcher-production-release-state-v2.schema.json'
$requestSchemaPath=Join-Path $schemaRoot 'launcher-manifest-publishing-request-v1.schema.json'
$responseSchemaPath=$schemaPath
foreach($node in @($issuerAst.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -in @('$p256Order','$p256HalfOrder')},$false))) {
    . ([scriptblock]::Create($node.Extent.Text))
}
foreach($node in @($issuerAst.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false))) {
    . ([scriptblock]::Create($node.Extent.Text))
}
$actualVerifierHelper=(Get-Item Function:Invoke-PinnedVerifier).ScriptBlock
function Fixture-Json($Value) { return ,(ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $Value) }
function Fixture-Sha([byte[]]$Bytes) { ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $Bytes }

$module=Get-Module ProductionReleaseState
$originalState=& $module { (Get-Item Function:Get-ProductionReleaseState).ScriptBlock }
$originalCandidate=& $module { (Get-Item Function:Assert-ProductionReleaseManifestCandidate).ScriptBlock }
& $module {
    function script:Get-ProductionReleaseState {
        param([string]$StateRoot,[string]$StateSchemaPath)
        if($StateRoot -cne $script:IssuerFixtureState.StateRoot){throw 'TEST: wrong replay state root'}
        return $script:IssuerFixtureState
    }
    function script:Assert-ProductionReleaseManifestCandidate {
        param($Plan,$ManifestInput,$CandidateRoot,$Files,$ComponentReleaseIds,$RuntimeProvenance,$ValidationTimeUtc)
        $script:IssuerCandidateCalls++
        if(@($Files).Count -ne 5){throw 'TEST: expected five real candidate descriptors'}
        # Deliberately skip full manifest/artifact signature and archive checks.
    }
}
$script:verifierCalls=[Collections.Generic.List[object]]::new()
$script:rejectVerifier=$false
function Invoke-PinnedVerifier([string]$Exe,[string[]]$Arguments) {
    $script:verifierCalls.Add([pscustomobject]@{Exe=$Exe;Arguments=$Arguments})
    if($script:rejectVerifier){throw 'TEST_COMPILED_VERIFIER_REJECTED'}
    # Assert real issuer-held deny-write leases for verifier and r4 payloads.
    foreach($path in @($Exe,$Arguments[2],$Arguments[4],$Arguments[6],$Arguments[8])) {
        $blocked=$false
        try{$probe=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite);$probe.Dispose()}catch{$blocked=$true}
        Assert-Test $blocked 'issuer retains verifier/runtime input locks during compiled-verifier call'
    }
    return $script:fixtureProof
}

$fixtureRoot=Join-Path ([IO.Path]::GetTempPath()) ('enterprise-issuer-function-'+[Guid]::NewGuid().ToString('N'))
$fixtureKey=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
$wrongKey=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
try {
    [void][IO.Directory]::CreateDirectory($fixtureRoot)
    $fixtureFull=[IO.Path]::GetFullPath($fixtureRoot)
    $stateRoot=[IO.Directory]::CreateDirectory((Join-Path $fixtureFull 'state')).FullName
    $candidateRoot=[IO.Directory]::CreateDirectory((Join-Path $fixtureFull 'candidate-input')).FullName
    $outputsRoot=[IO.Directory]::CreateDirectory((Join-Path $fixtureFull 'outputs')).FullName
    [IO.File]::WriteAllBytes((Join-Path $stateRoot 'state.lock'),[byte[]](1))
    $contract=ProductionReleaseState\Get-ProductionManifestChannelContract -TargetChannel stable
    $requestRoot=[IO.Directory]::CreateDirectory((Join-Path $stateRoot ('requests/'+$contract.RequestBundleName))).FullName
    $payloadRoot=[IO.Directory]::CreateDirectory((Join-Path $requestRoot 'payload')).FullName
    $requestPath=Join-Path $requestRoot 'manifest-publishing-request.v1.json'
    $verifierPath=Join-Path $fixtureFull 'approved-verifier.exe'
    [IO.File]::WriteAllBytes($verifierPath,[Text.Encoding]::UTF8.GetBytes('fixture verifier bytes; never executed'))
    $verifierSha=(Get-FileHash -LiteralPath $verifierPath).Hash.ToLowerInvariant()
    $keyPath=Join-Path $fixtureFull 'response-key.pk8'
    $wrongKeyPath=Join-Path $fixtureFull 'wrong-key.pk8'
    [IO.File]::WriteAllBytes($keyPath,$fixtureKey.ExportPkcs8PrivateKey())
    [IO.File]::WriteAllBytes($wrongKeyPath,$wrongKey.ExportPkcs8PrivateKey())
    $pub=$fixtureKey.ExportParameters($false)
    $fixtureTrust=[pscustomobject][ordered]@{algorithm='ES256';keyId='fixture-response';purpose='manifest-publishing-response';x=(B64 $pub.Q.X);y=(B64 $pub.Q.Y)}
    $tag='managed-v2026.09.10.1'
    $runtimeBytes=[Text.Encoding]::UTF8.GetBytes('fixture runtime archive')
    $metadataBytes=[Text.Encoding]::UTF8.GetBytes('{"fixture":"runtime metadata"}')
    $hashBytes=[Text.Encoding]::ASCII.GetBytes((Fixture-Sha $runtimeBytes)+'  runtime.zip'+"`n")
    $runtimeFiles=@(
        [ordered]@{role='runtime-archive';fileName='runtime.zip';relativePath='payload/runtime.zip';sizeBytes=$runtimeBytes.LongLength;sha256=(Fixture-Sha $runtimeBytes)},
        [ordered]@{role='runtime-metadata';fileName='runtime.json';relativePath='payload/runtime.json';sizeBytes=$metadataBytes.LongLength;sha256=(Fixture-Sha $metadataBytes)},
        [ordered]@{role='runtime-hash-evidence';fileName='runtime.zip.sha256';relativePath='payload/runtime.zip.sha256';sizeBytes=$hashBytes.LongLength;sha256=(Fixture-Sha $hashBytes)})
    [IO.File]::WriteAllBytes((Join-Path $payloadRoot 'runtime.zip'),$runtimeBytes)
    [IO.File]::WriteAllBytes((Join-Path $payloadRoot 'runtime.json'),$metadataBytes)
    [IO.File]::WriteAllBytes((Join-Path $payloadRoot 'runtime.zip.sha256'),$hashBytes)
    $sourceAssets=@(for($i=0;$i -lt 3;$i++){
        [ordered]@{role=@('archive','metadata','hash-evidence')[$i];githubAssetId=(201L+$i);fileName=$runtimeFiles[$i].fileName;sizeBytes=$runtimeFiles[$i].sizeBytes;sha256=$runtimeFiles[$i].sha256}
    })
    $sourceRelease=[ordered]@{repository='ensou/runtime';githubReleaseId=200L;tagName=$tag;targetCommit=('a'*40);immutable=$true;assets=$sourceAssets}
    $orgReceipt=[ordered]@{schemaVersion=2;receiptType='ensou-dsh-runtime-organization-admission';releaseId=$tag;sourceRuntimeMetadataSha256=(Fixture-Sha $metadataBytes);decision='admitted';reviewedAtUnixSeconds=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();signature=[ordered]@{algorithm='ES256';keyId='fixture-org';value=('A'*86)};sourceRelease=$sourceRelease}
    $orgBytes=Fixture-Json $orgReceipt
    $receiptPath=Join-Path $payloadRoot 'organization.json'
    [IO.File]::WriteAllBytes($receiptPath,$orgBytes)
    $script:fixtureProof=[pscustomobject][ordered]@{receiptSha256=(Fixture-Sha $orgBytes);sourceRelease=[pscustomobject]$sourceRelease}
    $payloadFiles=@($runtimeFiles)+@([ordered]@{role='edition-runtime-organization-admission';fileName='organization.json';relativePath='payload/organization.json';sizeBytes=$orgBytes.LongLength;sha256=(Fixture-Sha $orgBytes)})
    foreach($name in @('launcher.exe','bootstrapper.exe','plugin.json')) {
        $bytes=[Text.Encoding]::UTF8.GetBytes('fixture '+$name)
        [IO.File]::WriteAllBytes((Join-Path $payloadRoot $name),$bytes)
        $payloadFiles+= [ordered]@{role=('fixture-'+$name.Replace('.','-'));fileName=$name;relativePath=('payload/'+$name);sizeBytes=$bytes.LongLength;sha256=(Fixture-Sha $bytes)}
    }
    $plan=[pscustomobject][ordered]@{schemaVersion=2;edition='Enterprise';targetChannel='stable';runtimeCandidate=[pscustomobject]@{githubRepository='ensou/runtime';githubReleaseCommit=('a'*40);githubReleaseTag=$tag;releaseId=$tag;archive=$runtimeFiles[0];metadata=$runtimeFiles[1];hashEvidence=$runtimeFiles[2]};externalResponseTrusts=[pscustomobject]@{manifestPublishing=$fixtureTrust}}
    $now=[DateTimeOffset]::UtcNow
    $request=[ordered]@{
        schemaVersion=1;requestType=$contract.RequestType;orchestrationId='12345678-1234-4123-8123-123456789abc';edition='Enterprise';releaseSetId='fixture-issuer-r5';channel='stable';planSha256=('b'*64);baseHeadSha256=('c'*64);requestedRevision=4;requestNonce=('A'*43)
        createdAtUtc=(ConvertTo-ProductionUtc $now.AddMinutes(-5));expiresAtUtc=(ConvertTo-ProductionUtc $now.AddMinutes(30))
        publisherInput=[ordered]@{descriptorRelativePath='publisher-input.v1.json';descriptorSha256=('d'*64);files=$payloadFiles}
        releaseManifestTrust=[ordered]@{algorithm='ES256';keyId='fixture-manifest';purpose='release-manifest-signing';x=(B64 $pub.Q.X);y=(B64 $pub.Q.Y)}
        releaseCompatibility=[ordered]@{startupStubProtocol=1};componentReleaseIds=[ordered]@{launcher='launcher-fixture';runtime=$tag;pluginPolicy='policy-fixture'}
        runtimeProvenance=[ordered]@{harnessSourceTag='v1.0.0';harnessSourceCommit=('f'*40)}
        responseAuthentication=[ordered]@{algorithm='ES256';keyId=$fixtureTrust.keyId;purpose=$fixtureTrust.purpose;payloadType='ensou-dsh-launcher-manifest-publishing-response-authentication-v1'}
        runtimeSourceReleaseExpectation=(Get-ProductionRuntimeSourceReleaseExpectation -Plan $plan)
    }
    $expectedHead='e'*64
    $fixtureState=[pscustomobject]@{StateRoot=$stateRoot;SchemaVersion=2;Plan=$plan;TargetChannel='stable';Head=[pscustomobject]@{revision=4;phase=$contract.RequestPhase};HeadSha256=$expectedHead;Identity=[pscustomobject]@{planSha256=$request.planSha256};Receipts=@($null,$null,$null,[pscustomobject]@{data=[pscustomobject]@{requestSha256='';baseHeadSha256=$request.baseHeadSha256}})}
    function Write-FixtureRequest {
        $bytes=Fixture-Json $request
        [IO.File]::WriteAllBytes($requestPath,$bytes)
        $fixtureState.Receipts[3].data.requestSha256=Fixture-Sha $bytes
        & $module {param($state) $script:IssuerFixtureState=$state} $fixtureState
    }
    Write-FixtureRequest
    $candidateArtifacts=@(foreach($component in @('launcher','runtime','plugin-policy')) {
        $name=$component+'.zip';$bytes=[Text.Encoding]::UTF8.GetBytes('candidate fixture '+$component)
        [IO.File]::WriteAllBytes((Join-Path $candidateRoot $name),$bytes)
        [ordered]@{component=$component;releaseId=($component+'-fixture');uri=('https://fixture.invalid/'+$name);sizeBytes=$bytes.LongLength;sha256=(Fixture-Sha $bytes);completeTreeSha256=('f'*64);signature=[ordered]@{algorithm='ES256';keyId='fixture-manifest';value=('A'*86)}}
    })
    $manifest=[ordered]@{schemaVersion=2;product='ensou-dsh-enterprise';environment='production';channel='stable';releaseSetId=$request.releaseSetId;generation=1;sequence=1;minAcceptedSequence=0;issuedAtUtc=$request.createdAtUtc;expiresAtUtc=$request.expiresAtUtc;startupStub=[ordered]@{minimumProtocol=1;maximumProtocol=1};revokedReleaseSetIds=@();artifacts=$candidateArtifacts;signature=[ordered]@{algorithm='ES256';keyId='fixture-manifest';value=('A'*86)}}
    [IO.File]::WriteAllBytes((Join-Path $candidateRoot 'release-set.v2.json'),(Fixture-Json $manifest))
    [IO.File]::WriteAllBytes((Join-Path $candidateRoot 'release-public-key.v2.json'),[Text.Encoding]::UTF8.GetBytes('{"fixture":"public key"}'))

    function Assert-FixtureLeasesReleased {
        foreach($path in @($requestPath,$receiptPath,$verifierPath,$keyPath,(Join-Path $stateRoot 'state.lock'))+@($runtimeFiles|ForEach-Object {Join-Path $payloadRoot $_.fileName})+@(Get-ChildItem -LiteralPath $candidateRoot -File|ForEach-Object FullName)) {
            $probe=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$probe.Dispose()
        }
    }
    function Invoke-IssuerCase([string]$Name,[string]$FailurePattern='',[string]$Head=$expectedHead,[string]$VerifierHash=$verifierSha,[string]$Key=$keyPath,[switch]$Existing) {
        $output=Join-Path $outputsRoot $Name
        $sentinelBytes=[Text.Encoding]::UTF8.GetBytes('must preserve existing output')
        if($Existing){[void][IO.Directory]::CreateDirectory($output);[IO.File]::WriteAllBytes((Join-Path $output 'sentinel'),$sentinelBytes)}
        $script:verifierCalls.Clear()
        & $module {$script:IssuerCandidateCalls=0}
        $observed=[Collections.Generic.List[object]]::new();$failure=''
        try {
            Invoke-EnterpriseManifestPublishingResponse -StateRoot $stateRoot -ExpectedHeadSha256 $Head -CandidateRoot $candidateRoot `
                -PublisherVerifierPath $verifierPath -ExpectedPublisherVerifierSha256 $VerifierHash -ResponsePrivateKeyPath $Key -OutputRoot $output |
                ForEach-Object {$observed.Add($_)}
        } catch {$failure=$_.Exception.Message}
        if($FailurePattern) {
            Assert-Test ($failure -match $FailurePattern) "$Name rejects at expected boundary; actual: $failure"
            Assert-Test ($observed.Count -eq 0) "$Name emits no output proof"
            if($Existing){Assert-Test ((Fixture-Sha ([IO.File]::ReadAllBytes((Join-Path $output 'sentinel')))) -ceq (Fixture-Sha $sentinelBytes)) 'existing output bytes preserved';Assert-Test (@(Get-ChildItem -LiteralPath $output -Force).Count -eq 1) 'existing output inventory preserved'}
            else {Assert-Test (-not (Test-Path -LiteralPath $output)) "$Name publishes no output directory"}
        } else {
            Assert-Test (-not $failure) "$Name executes actual issuer successfully; actual: $failure"
            Assert-Test ($observed.Count -eq 1) 'issuer emits exactly one result after publication'
            Assert-Test ($observed[0].OutputRoot -ceq $output -and $observed[0].NetworkPublishPerformed -eq $false) 'output identifies local-only publication'
            $responseFile=Join-Path $output 'manifest-publishing-response.v1.json'
            $bytes=[IO.File]::ReadAllBytes($responseFile)
            $actual=ConvertFrom-StrictProductionJsonBytes -Bytes $bytes -Label 'actual issuer output' -SchemaPath $responseSchemaPath
            Assert-ProductionReleaseManifestPublishingResponseAuthentication -Response $actual -Trust $fixtureTrust
            Assert-Test ((Fixture-Sha $bytes) -ceq $observed[0].ResponseSha256) 'result binds exact response bytes'
            Assert-Test ($actual.admissionHeadSha256 -ceq $expectedHead -and $actual.requestSha256 -ceq $fixtureState.Receipts[3].data.requestSha256) 'actual r5 binds exact r4 request/head'
            Assert-Test ($actual.runtimeSourceReleaseAdmission.receiptSha256 -ceq (Fixture-Sha $orgBytes)) 'actual r5 binds exact organization receipt'
            Assert-Test (@(Get-ChildItem -LiteralPath $output -Force).Count -eq 2) 'output has only response and candidate'
            Assert-Test (@(Get-ChildItem -LiteralPath (Join-Path $output 'candidate') -Force).Count -eq 5) 'exact five candidate files copied'
            foreach($file in @($actual.files)) {Assert-Test ((Get-FileHash -LiteralPath (Join-Path $output $file.relativePath)).Hash.ToLowerInvariant() -ceq $file.sha256) 'every copied file matches response digest'}
            Assert-Test ($script:verifierCalls.Count -eq 1) 'compiled verifier boundary invoked once'
            $args=$script:verifierCalls[0].Arguments
            Assert-Test ($args.Count -eq 15 -and $args[0] -ceq '--verify-runtime-source-admission') 'exact compiled verifier command shape'
            foreach($mapping in @(@(2,'runtime.zip'),@(4,'runtime.json'),@(6,'runtime.zip.sha256'),@(8,'organization.json'))) {
                Assert-Test ($args[$mapping[0]] -ceq (Join-Path $payloadRoot $mapping[1])) 'compiled verifier receives exact state-owned r4 payload path'
            }
            Assert-Test ($script:verifierCalls[0].Exe -ceq $verifierPath) 'compiled verifier uses the exact locked, digest-pinned executable'
            Assert-Test ($args[1] -ceq '--archive' -and $args[3] -ceq '--metadata' -and $args[5] -ceq '--hash-evidence' -and $args[7] -ceq '--receipt') 'runtime payload arguments retain their exact roles'
            Assert-Test ($args[9] -ceq '--repository' -and $args[10] -ceq 'ensou/runtime' -and $args[11] -ceq '--tag' -and $args[12] -ceq $tag -and $args[13] -ceq '--build-commit' -and $args[14] -ceq ('a'*40)) 'compiled verifier receives the original runtime repository/tag/build commit'
            $actual.runtimeSourceReleaseAdmission.sourceRelease.githubReleaseId++
            $rejected=$false;try{Assert-ProductionReleaseManifestPublishingResponseAuthentication -Response $actual -Trust $fixtureTrust}catch{$rejected=$true}
            Assert-Test $rejected 'mutation of actual emitted source proof invalidates real r5 ES256'
        }
        Assert-Test (@(Get-ChildItem -LiteralPath $outputsRoot -Force | Where-Object Name -Like ($Name+'.pending-*')).Count -eq 0) "$Name leaves no staging output"
        Assert-FixtureLeasesReleased
        Write-Host "PASS: actual issuer $Name"
    }
    Invoke-IssuerCase 'success'
    Invoke-IssuerCase 'wrong-head' 'exact committed' -Head ('9'*64)
    Assert-Test ($script:verifierCalls.Count -eq 0) 'wrong head rejected before compiled verifier'
    Invoke-IssuerCase 'wrong-verifier-hash' 'operator-pinned' -VerifierHash ('9'*64)
    Assert-Test ($script:verifierCalls.Count -eq 0) 'wrong executable rejected before invocation'
    [IO.File]::WriteAllBytes($receiptPath,[Text.Encoding]::UTF8.GetBytes('tampered receipt'))
    Invoke-IssuerCase 'wrong-receipt' 'receipt changed from r4 descriptor'
    [IO.File]::WriteAllBytes($receiptPath,$orgBytes)
    Invoke-IssuerCase 'wrong-key' 'does not match plan response trust' -Key $wrongKeyPath
    $normalExpiry=$request.expiresAtUtc;$request.expiresAtUtc=ConvertTo-ProductionUtc $now.AddMinutes(-1);Write-FixtureRequest
    Invoke-IssuerCase 'expired-request' 'outside its lifetime'
    $request.expiresAtUtc=$normalExpiry;Write-FixtureRequest
    Invoke-IssuerCase 'existing-output' 'create-only and already exists' -Existing
    $script:rejectVerifier=$true
    Invoke-IssuerCase 'verifier-reject' 'TEST_COMPILED_VERIFIER_REJECTED'
    $script:rejectVerifier=$false
    $extraCandidate=Join-Path $candidateRoot 'unexpected.txt'
    [IO.File]::WriteAllBytes($extraCandidate,[Text.Encoding]::UTF8.GetBytes('unexpected candidate file'))
    Invoke-IssuerCase 'extra-candidate-file' 'unexpected file inventory'
    Remove-Item -LiteralPath $extraCandidate -Force
    $originalProofSha=$script:fixtureProof.receiptSha256
    $script:fixtureProof.receiptSha256='9'*64
    Invoke-IssuerCase 'wrong-source-proof-receipt-hash' 'RUNTIME_SOURCE_RECEIPT_MISMATCH'
    $script:fixtureProof.receiptSha256=$originalProofSha

    # Exercise the original product process helper without its fixture seam.
    # pwsh is only a tiny local child emitting literal test output; it is NOT an
    # approved production Publisher and is never passed to the issuer function.
    # The helper itself has no override parameter and uses real ProcessStartInfo,
    # ArgumentList, exit/stderr checks, and strict JSON output parsing.
    $childExe=Join-Path $PSHOME 'pwsh.exe'
    Assert-Test ([IO.File]::Exists($childExe)) 'fixture PowerShell child exists'
    $literalProofBase64=[Convert]::ToBase64String((Fixture-Json $script:fixtureProof))
    $writeProof="[Console]::Out.WriteLine([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$literalProofBase64')))"
    function Invoke-VerifierProcessCase([string]$Name,[string]$Command,[bool]$Reject) {
        $observed=[Collections.Generic.List[object]]::new();$failure=''
        try {
            & $actualVerifierHelper -Exe $childExe -Arguments @('-NoLogo','-NoProfile','-NonInteractive','-Command',$Command) |
                ForEach-Object {$observed.Add($_)}
        } catch {$failure=$_.Exception.Message}
        if($Reject) {
            Assert-Test (-not [string]::IsNullOrWhiteSpace($failure)) "$Name rejects invalid process outcome"
            Assert-Test ($observed.Count -eq 0) "$Name returns no verifier proof on failure"
        } else {
            Assert-Test (-not $failure) "$Name executes actual process helper; actual: $failure"
            Assert-Test ($observed.Count -eq 1) "$Name returns exactly one parsed proof"
            Assert-Test ($observed[0].receiptSha256 -ceq $originalProofSha) "$Name retains literal child proof receipt hash"
            Assert-Test ((Fixture-Sha (Fixture-Json $observed[0].sourceRelease)) -ceq (Fixture-Sha (Fixture-Json $sourceRelease))) "$Name retains literal child source identity"
        }
        Write-Host "PASS: actual verifier process $Name"
    }
    Invoke-VerifierProcessCase 'valid-json' ($writeProof+'; exit 0') $false
    Invoke-VerifierProcessCase 'stderr' ($writeProof+"; [Console]::Error.WriteLine('fixture rejection'); exit 0") $true
    Invoke-VerifierProcessCase 'nonzero' ($writeProof+'; exit 7') $true
    Invoke-VerifierProcessCase 'invalid-json' "[Console]::Out.WriteLine('{'); exit 0" $true
    Invoke-VerifierProcessCase 'multiple-json-documents' "[Console]::Out.WriteLine('{}{}'); exit 0" $true
    Invoke-VerifierProcessCase 'duplicate-json-members' '[Console]::Out.WriteLine(''{"receiptSha256":1,"receiptSha256":2}''); exit 0' $true
    Write-Host 'PASS: actual issuer function success, four source locks, exact r4 CLI paths, real PKCS8/r5 ES256, copied bytes, nine no-output failures, actual verifier child-process outcomes and lease disposal.'
} finally {
    & $module {param($state,$candidate) Set-Item Function:script:Get-ProductionReleaseState $state;Set-Item Function:script:Assert-ProductionReleaseManifestCandidate $candidate} $originalState $originalCandidate
    $fixtureKey.Dispose();$wrongKey.Dispose()
    # Delete only this exact independently created temporary fixture, including
    # its generated PKCS8 fixture keys. No production or user key store is used.
    if(Test-Path -LiteralPath $fixtureRoot) {
        $resolved=[IO.Path]::GetFullPath($fixtureRoot)
        $tempBoundary=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar
        if(-not $resolved.StartsWith($tempBoundary,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -notmatch '^enterprise-issuer-function-[0-9a-f]{32}$'){throw 'Unsafe fixture cleanup target'}
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
