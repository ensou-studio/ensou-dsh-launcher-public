#requires -Version 7.2
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The executor reuses the plan's feedPromotion key, but signs a distinct domain.
# A signed offline authorization is never an execution result.
$script:ResultDomain = 'ensou-dsh-personal-feed-execution-result-v1'
$script:ResultRoles = @('offline-request', 'offline-authorization', 'feed-identity',
    'operation-request', 'operation-result', 'trust-configuration', 'channel-head',
    'journal-head', 'journal-entry', 'release-manifest', 'launcher', 'runtime')

function Assert-PersonalResultMembers {
    param($Value, [string[]]$Names, [string]$Label)
    $actual = @($Value.PSObject.Properties.Name)
    if ($actual.Count -ne $Names.Count -or @($actual | Where-Object { $_ -cnotin $Names }).Count) {
        throw "Personal result $Label has unexpected or missing members."
    }
}

function Get-PersonalFeedPromotionResultAuthenticationPayload {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result)
    $body = [ordered]@{}
    foreach ($name in @('schemaVersion','resultType','operationId','orchestrationId',
        'releaseSetId','planSha256','sourceIdentitySha256','sourceR7HeadSha256',
        'sourceR8HeadSha256','requestSha256','authorizationSha256','promotionHeadSha256',
        'bundleHeadSha256','bundleSetSha256','completedAtUtc','expiresAtUtc','files')) {
        $body[$name] = $Result.$name
    }
    $body.authentication = [ordered]@{
        algorithm = $Result.authentication.algorithm
        keyId = $Result.authentication.keyId
        purpose = $Result.authentication.purpose
        payloadType = $Result.authentication.payloadType
    }
    $domain = [Text.Encoding]::UTF8.GetBytes($script:ResultDomain + [char]10)
    $json = ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $body
    return [byte[]]($domain + $json)
}

function ConvertFrom-PersonalResultBase64Url {
    param([string]$Value)
    if ($Value -cnotmatch '^[A-Za-z0-9_-]+$') { throw 'Personal result signature encoding is invalid.' }
    $bytes = [Convert]::FromBase64String($Value.Replace('-','+').Replace('_','/') + ('=' * ((4-$Value.Length%4)%4)))
    if ([Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_') -cne $Value) {
        throw 'Personal result signature encoding is noncanonical.'
    }
    return ,$bytes
}

function Assert-PersonalResultSignature {
    param($Authentication, $Trust, [byte[]]$Payload, [string]$PayloadType)
    if ($Trust.algorithm -cne 'ES256' -or $Trust.purpose -cne 'feed-promotion-response' -or
        $Authentication.algorithm -cne 'ES256' -or $Authentication.keyId -cne $Trust.keyId -or
        $Authentication.purpose -cne 'feed-promotion-response' -or $Authentication.payloadType -cne $PayloadType) {
        throw 'Personal result authentication differs from the plan trust or signature domain.'
    }
    $signature = ConvertFrom-PersonalResultBase64Url $Authentication.value
    $x = ConvertFrom-PersonalResultBase64Url $Trust.x
    $y = ConvertFrom-PersonalResultBase64Url $Trust.y
    if ($signature.Length -ne 64 -or $x.Length -ne 32 -or $y.Length -ne 32) { throw 'Invalid Personal result ES256 sizes.' }
    ProductionReleaseState\Assert-ProductionEs256P1363LowS -Signature $signature -Label 'Personal result signature'
    $parameters = [Security.Cryptography.ECParameters]::new()
    $parameters.Curve = [Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $point = [Security.Cryptography.ECPoint]::new(); $point.X = $x; $point.Y = $y
    $parameters.Q = $point
    $key = [Security.Cryptography.ECDsa]::Create($parameters)
    try {
        if (-not $key.VerifyData($Payload, $signature, [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
            throw 'Personal result signature is invalid.'
        }
    } finally { $key.Dispose() }
}

function Close-PersonalFeedPromotionResult {
    param($Admission)
    if ($null -ne $Admission) {
        foreach ($input in $Admission.HeldDescriptors) { $input.Stream.Dispose() }
    }
}

function Open-PersonalFeedPromotionResult {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$BundleRoot)
    $held = [Collections.Generic.List[object]]::new()
    try {
        # No caller-selected paths inside the evidence bundle; every role is a flat file.
        foreach ($directory in @($BundleRoot, (Join-Path $BundleRoot 'evidence'))) {
            $item = Get-Item -LiteralPath $directory -Force
            if (-not $item.PSIsContainer) { throw 'Personal result bundle directory is missing.' }
            for ($parent = $item; $null -ne $parent; $parent = $parent.Parent) {
                if (($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Personal result bundle crosses a link.' }
            }
        }
        $top = @(Get-ChildItem -LiteralPath $BundleRoot -Force)
        if ($top.Count -ne 2 -or @($top.Name | Where-Object { $_ -cnotin @('result.v1.json','evidence') }).Count) {
            throw 'Personal result bundle has unexpected inventory.'
        }
        $envelope = ProductionReleaseState\Open-ProductionReleaseInput -Path (Join-Path $BundleRoot 'result.v1.json') -Label 'Personal execution envelope' -MaximumBytes 1MB
        $held.Add($envelope)
        $bytes = ProductionReleaseState\Read-ProductionReleaseInputBytes -Descriptor $envelope -Label 'Personal execution envelope'
        $result = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes -Bytes $bytes -Label 'Personal execution envelope' -SchemaPath (Join-Path $PSScriptRoot '../schemas/personal-feed-execution-result-v1.schema.json')
        [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput -Input ([pscustomobject]@{Bytes=$bytes;Value=$result;Sha256=$envelope.Sha256}) -Label 'Personal execution envelope')
        $files = @{}; $values = @{}
        $entries = @(Get-ChildItem -LiteralPath (Join-Path $BundleRoot 'evidence') -Force)
        if ($entries.Count -ne @($result.files).Count) { throw 'Personal result evidence inventory differs.' }
        foreach ($record in $result.files) {
            $role = [string]$record.role
            if ($files.ContainsKey($role) -or @($entries | Where-Object { $_.Name -ceq $role -and -not $_.PSIsContainer }).Count -ne 1) {
                throw 'Personal result evidence repeats or omits a role.'
            }
            $input = ProductionReleaseState\Open-ProductionReleaseInput -Path (Join-Path (Join-Path $BundleRoot 'evidence') $role) -Label "Personal result $role" -MaximumBytes 8GB
            $held.Add($input)
            if ($input.Sha256 -cne $record.sha256 -or $input.SizeBytes -ne $record.sizeBytes) { throw "Personal result $role raw bytes drifted." }
            $files[$role] = $input
            if ($role -notin @('launcher','runtime')) {
                if ($input.SizeBytes -gt 1MB) { throw 'Personal result JSON exceeds its bound.' }
                $json = ProductionReleaseState\Read-ProductionReleaseInputBytes -Descriptor $input -Label $role
                $schema = switch ($role) {
                    'offline-request' { Join-Path $PSScriptRoot '../schemas/launcher-feed-promotion-request-v1.schema.json' }
                    'offline-authorization' { Join-Path $PSScriptRoot '../schemas/launcher-feed-promotion-response-v1.schema.json' }
                    default { '' }
                }
                $values[$role] = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes -Bytes $json -Label $role -SchemaPath $schema
            }
        }
        foreach ($role in $script:ResultRoles) { if (-not $files.ContainsKey($role)) { throw "Personal result missing $role." } }
        return [pscustomobject]@{Root=[IO.Path]::GetFullPath($BundleRoot);Result=$result;Envelope=$envelope;Files=$files;Values=$values;HeldDescriptors=@($held)}
    } catch { foreach ($input in $held) { $input.Stream.Dispose() }; throw }
}

function Assert-PersonalResultEqual {
    param($Actual, $Expected, [string]$Label)
    $a = ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $Actual
    $b = ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $Expected
    if ([Convert]::ToHexString($a) -cne [Convert]::ToHexString($b)) { throw "Personal result $Label binding conflicts." }
}

function Get-PersonalOfflineAuthorizationPayload {
    param($Response)
    # Same existing offline protocol, kept local so historical state reads do not
    # force-import the mutation module (which itself reloads state).
    $body = [ordered]@{}
    foreach ($name in @('schemaVersion','responseType','operationId','orchestrationId','edition',
        'exposureRing','feedChannel','publishScope','releaseSetId','requestSha256','requestNonce',
        'basePromotionHeadSha256','sourceStateHeadSha256','payloadSetSha256','feedCasSha256',
        'decision','completedAtUtc','requestExpiresAtUtc','productionAdmission','networkPublishPerformed')) {
        $body[$name] = $Response.$name
    }
    $body.authentication = [ordered]@{algorithm=$Response.authentication.algorithm;keyId=$Response.authentication.keyId;purpose=$Response.authentication.purpose;payloadType=$Response.authentication.payloadType}
    return [byte[]]([Text.Encoding]::UTF8.GetBytes('ensou-dsh-launcher-feed-promotion-response-authentication-v1' + [char]10) +
        (ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $body))
}

function Assert-PersonalResultRawState {
    param($Expected, $Descriptor, [string]$Label)
    $names=@($Expected.PSObject.Properties.Name)
    if(@($names | Where-Object { $_ -cnotin @('state','sizeBytes','sha256') }).Count) { throw "Personal result $Label has unknown CAS state members." }
    if ($null -eq $Descriptor) {
        if ($Expected.state -cne 'missing' -or
            ($null -ne $Expected.PSObject.Properties['sizeBytes'] -and $null -ne $Expected.sizeBytes) -or
            ($null -ne $Expected.PSObject.Properties['sha256'] -and $null -ne $Expected.sha256)) { throw "Personal result $Label must be missing." }
    } elseif ($Expected.state -cne 'present' -or $Expected.sha256 -cne $Descriptor.Sha256 -or $Expected.sizeBytes -ne $Descriptor.SizeBytes) {
        throw "Personal result $Label raw CAS binding conflicts."
    }
}

function Get-PersonalResultDomainDigest {
    param([string]$Domain, $Value)
    return ProductionReleaseState\Get-ProductionSha256Bytes -Bytes ([byte[]]([Text.Encoding]::UTF8.GetBytes($Domain + [char]10) +
        (ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $Value)))
}

function Assert-PersonalFeedPromotionResultBindingCore {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Admission, [Parameter(Mandatory)]$Plan,
        [Parameter(Mandatory)]$Identity, [Parameter(Mandatory)][string]$IdentitySha256,
        [Parameter(Mandatory)][string]$R7HeadSha256, [Parameter(Mandatory)][string]$R8HeadSha256,
        [Parameter(Mandatory)][string]$SealedRequestSha256, [Parameter(Mandatory)]$CandidateFiles,
        [switch]$Fresh, [switch]$UnsignedPreparation)
    $r = $Admission.Result; $f = $Admission.Files; $v = $Admission.Values
    $request = $v['offline-request']; $authorization = $v['offline-authorization']
    $trust = $Plan.externalResponseTrusts.feedPromotion
    if ($Plan.edition -cne 'Personal' -or $Plan.targetChannel -cne 'pilot' -or
        $Identity.edition -cne 'Personal' -or $r.planSha256 -cne $Identity.planSha256 -or
        $r.sourceIdentitySha256 -cne $IdentitySha256 -or $r.sourceR7HeadSha256 -cne $R7HeadSha256 -or
        $r.sourceR8HeadSha256 -cne $R8HeadSha256 -or $r.orchestrationId -cne $Identity.orchestrationId -or
        $r.releaseSetId -cne $Plan.releaseSetId -or $r.requestSha256 -cne $SealedRequestSha256 -or
        $f['offline-request'].Sha256 -cne $SealedRequestSha256 -or $r.authorizationSha256 -cne $f['offline-authorization'].Sha256) {
        throw 'Personal result differs from the sealed r8 source state.'
    }
    Assert-PersonalResultEqual $request.authorizationTrust $trust 'offline authorization trust'
    if (-not $UnsignedPreparation) {
        Assert-PersonalResultSignature $r.authentication $trust (Get-PersonalFeedPromotionResultAuthenticationPayload $r) $script:ResultDomain
    }
    Assert-PersonalResultSignature $authorization.authentication $trust (Get-PersonalOfflineAuthorizationPayload $authorization) 'ensou-dsh-launcher-feed-promotion-response-authentication-v1'
    foreach ($name in @('operationId','orchestrationId','releaseSetId')) {
        if ($r.$name -cne $request.$name -or $r.$name -cne $authorization.$name) { throw "Personal result $name differs from authorization." }
    }
    if ($request.edition -cne 'Personal' -or $request.exposureRing -cne 'pilot' -or $request.feedChannel -cne 'pilot' -or
        $request.publishScope -cne 'channel-head' -or $request.sourceState.headSha256 -cne $R7HeadSha256 -or
        $request.sourceState.planSha256 -cne $r.planSha256 -or $request.sourceState.identitySha256 -cne $IdentitySha256 -or
        $authorization.edition -cne 'Personal' -or $authorization.exposureRing -cne 'pilot' -or
        $authorization.feedChannel -cne 'pilot' -or $authorization.publishScope -cne 'channel-head' -or
        $authorization.requestSha256 -cne $r.requestSha256 -or $authorization.requestNonce -cne $request.requestNonce -or
        $authorization.sourceStateHeadSha256 -cne $R7HeadSha256 -or $authorization.basePromotionHeadSha256 -cne $r.promotionHeadSha256 -or
        $authorization.payloadSetSha256 -cne $request.payloadSetSha256 -or $authorization.feedCasSha256 -cne $request.feedCasSha256 -or
        $authorization.requestExpiresAtUtc -cne $request.expiresAtUtc -or $authorization.productionAdmission -cne 'OFFLINE_BUNDLE_ONLY' -or
        $authorization.decision -cne 'AUTHORIZE_OFFLINE_BUNDLE' -or $authorization.networkPublishPerformed -ne $false) {
        throw 'Personal result offline authorization binding conflicts.'
    }
    if ((Get-PersonalResultDomainDigest 'ensou-dsh-launcher-feed-promotion-payload-set-v1' @($request.files)) -cne $request.payloadSetSha256 -or
        (Get-PersonalResultDomainDigest 'ensou-dsh-launcher-feed-promotion-cas-v1' $request.feedCas) -cne $request.feedCasSha256) { throw 'Personal result offline payload/CAS digest conflicts.' }
    $inventory = @(
        [ordered]@{role='promotion-request';fileName='request.v1.json';relativePath='bundle/request.v1.json';sizeBytes=$f['offline-request'].SizeBytes;sha256=$f['offline-request'].Sha256},
        [ordered]@{role='promotion-response';fileName='response.v1.json';relativePath='bundle/response.v1.json';sizeBytes=$f['offline-authorization'].SizeBytes;sha256=$f['offline-authorization'].Sha256}
    )
    foreach ($file in $request.files) { $inventory += [ordered]@{role=$file.role;fileName=$file.fileName;relativePath=('bundle/payload/' + $file.fileName);sizeBytes=$file.sizeBytes;sha256=$file.sha256} }
    if ((Get-PersonalResultDomainDigest 'ensou-dsh-launcher-feed-promotion-offline-bundle-v1' $inventory) -cne $r.bundleSetSha256) { throw 'Personal result offline bundle-set digest conflicts.' }
    $operation = $v['operation-request']; $receipt = $v['operation-result']
    Assert-PersonalResultMembers $operation @('schemaVersion','operationId','requestSha256','product','environment','channel','feedIdentitySha256','candidateManifestSizeBytes','candidateManifestSha256','trustConfigurationSha256','expectedChannelHead','expectedJournalHead') 'operation request'
    Assert-PersonalResultMembers $receipt @('schemaVersion','operationId','requestSha256','product','environment','channel','releaseSetId','generation','sequence','minAcceptedSequence','manifestSha256','channelManifestRelativePath','channelManifestUri','promotionJournalEntryRelativePath','promotionJournalSha256','channelHead','journalHead','publishedAtUtc','channelHeadChanged','immutableReleaseCreated') 'operation result'
    foreach ($document in @($operation,$receipt,$v['feed-identity'],$v['journal-head'],$v['journal-entry'],$v['release-manifest'])) {
        if ($document.product -cne 'ensou-dsh-personal' -or $document.environment -cne 'production') { throw 'Personal result product/environment conflicts.' }
    }
    if ($operation.schemaVersion -ne 1 -or $receipt.schemaVersion -ne 1 -or $operation.channel -cne 'pilot' -or $receipt.channel -cne 'pilot' -or
        $operation.operationId -cne $r.operationId -or $receipt.operationId -cne $r.operationId -or
        $operation.requestSha256 -cne $receipt.requestSha256 -or $operation.feedIdentitySha256 -cne $request.expectedFeedIdentitySha256 -or
        $f['feed-identity'].Sha256 -cne $request.expectedFeedIdentitySha256 -or
        $operation.candidateManifestSha256 -cne $f['release-manifest'].Sha256 -or
        $operation.candidateManifestSizeBytes -ne $f['release-manifest'].SizeBytes -or
        $operation.trustConfigurationSha256 -cne $f['trust-configuration'].Sha256 -or
        $receipt.manifestSha256 -cne $f['release-manifest'].Sha256 -or
        $receipt.channelManifestRelativePath -cne 'public/channels/pilot/release-set.v2.json' -or
        $receipt.channelHeadChanged -isnot [bool] -or $receipt.immutableReleaseCreated -isnot [bool] -or
        $receipt.channelHeadChanged -ne $true -or $receipt.immutableReleaseCreated -ne $true) {
        throw 'Personal result operation identity or committed effect conflicts.'
    }
    $operationBytes = ProductionReleaseState\Read-ProductionReleaseInputBytes -Descriptor $f['operation-request'] -Label 'operation digest'
    $operationText = [Text.Encoding]::UTF8.GetString($operationBytes)
    # Preserve the production serializer's exact whitespace when zeroing its self-digest.
    $normalized = $operationText.Replace('"' + [string]$operation.requestSha256 + '"', '"' + ('0'*64) + '"')
    if ($operation.requestSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        (ProductionReleaseState\Get-ProductionSha256Bytes -Bytes ([Text.Encoding]::UTF8.GetBytes($normalized))) -cne $operation.requestSha256) {
        throw 'Personal result operation request self-digest conflicts.'
    }
    foreach ($pair in @(@('channelHead','previous-channel-head','expectedChannelHead'),@('journalHead','previous-journal-head','expectedJournalHead'))) {
        $previous = if ($f.ContainsKey($pair[1])) { $f[$pair[1]] } else { $null }
        Assert-PersonalResultRawState $request.feedCas.($pair[0]) $previous $pair[0]
        Assert-PersonalResultRawState $operation.($pair[2]) $previous $pair[2]
    }
    Assert-PersonalResultRawState $receipt.channelHead $f['channel-head'] 'committed channel head'
    Assert-PersonalResultRawState $receipt.journalHead $f['journal-head'] 'committed journal head'
    if ($f['channel-head'].Sha256 -cne $f['release-manifest'].Sha256) { throw 'Personal result final channel head differs from candidate.' }
    $manifest = $v['release-manifest']; $entry = $v['journal-entry']; $head = $v['journal-head']
    $executionTrust = $v['trust-configuration']
    $releaseKeys = @($executionTrust.releaseKeys | Where-Object { $_.keyId -ceq $Plan.releaseManifestTrust.keyId -and $_.x -ceq $Plan.releaseManifestTrust.x -and $_.y -ceq $Plan.releaseManifestTrust.y })
    if ($releaseKeys.Count -ne 1 -or $executionTrust.expectedAuthenticodeSignerSha256Thumbprint -cne $Plan.authenticodePolicy.signerSha256Thumbprint) { throw 'Personal result executor trust differs from the plan.' }
    foreach ($document in @($receipt,$entry,$head)) {
        foreach ($name in @('releaseSetId','generation','sequence')) {
            if ($document.$name -cne $manifest.$name) { throw "Personal result final $name conflicts." }
        }
        if ($document.channel -cne 'pilot' -or $document.manifestSha256 -cne $f['release-manifest'].Sha256) { throw 'Personal result journal manifest binding conflicts.' }
    }
    if ($manifest.releaseSetId -cne $r.releaseSetId -or $manifest.channel -cne 'pilot' -or
        $receipt.minAcceptedSequence -ne $manifest.minAcceptedSequence -or $entry.minAcceptedSequence -ne $manifest.minAcceptedSequence -or
        $entry.publishedAtUtc -cne $receipt.publishedAtUtc -or $head.entrySha256 -cne $f['journal-entry'].Sha256 -or
        $receipt.promotionJournalSha256 -cne $f['journal-entry'].Sha256 -or
        $head.entryFileName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$' -or
        $receipt.promotionJournalEntryRelativePath -cne ('journal/pilot/' + $head.entryFileName)) { throw 'Personal result journal/head binding conflicts.' }
    if ($f.ContainsKey('previous-journal-head')) {
        if ($entry.previousEntrySha256 -cne $v['previous-journal-head'].entrySha256 -or $entry.previousEntryFileName -cne $v['previous-journal-head'].entryFileName) { throw 'Personal result journal predecessor conflicts.' }
    } elseif ($entry.previousEntrySha256 -cne ('0'*64) -or $entry.previousEntryFileName -cne '') { throw 'Personal result journal genesis conflicts.' }
    if (@($request.files).Count -ne 3 -or @($CandidateFiles).Count -ne 3 -or @($manifest.artifacts).Count -ne 2 -or @($entry.artifacts).Count -ne 2) { throw 'Personal result candidate inventory conflicts.' }
    foreach ($role in @('release-manifest','launcher','runtime')) {
        $original = @($CandidateFiles | Where-Object role -CEQ $role)
        $authorized = @($request.files | Where-Object role -CEQ $role)
        if ($original.Count -ne 1 -or $authorized.Count -ne 1 -or $original[0].sha256 -cne $f[$role].Sha256 -or $original[0].sizeBytes -ne $f[$role].SizeBytes -or
            $authorized[0].sha256 -cne $f[$role].Sha256 -or $authorized[0].sizeBytes -ne $f[$role].SizeBytes -or $authorized[0].fileName -cne $original[0].fileName) { throw "Personal result published $role differs from r5/authorization." }
        if ($role -ne 'release-manifest') {
            $component = if ($role -ceq 'launcher') { 'client-bundle' } else { 'runtime' }
            $artifact = @($manifest.artifacts | Where-Object component -CEQ $component)
            $recorded = @($entry.artifacts | Where-Object component -CEQ $component)
            if ($artifact.Count -ne 1 -or $recorded.Count -ne 1 -or $artifact[0].sha256 -cne $f[$role].Sha256 -or $artifact[0].sizeBytes -ne $f[$role].SizeBytes -or
                $recorded[0].sha256 -cne $f[$role].Sha256 -or $recorded[0].sizeBytes -ne $f[$role].SizeBytes -or $recorded[0].fileName -cne $original[0].fileName -or
                $recorded[0].releaseId -cne $artifact[0].releaseId -or $recorded[0].completeTreeSha256 -cne $artifact[0].completeTreeSha256) { throw 'Personal result published artifact binding conflicts.' }
            $uri = [Uri]$artifact[0].uri
            if ($uri.Scheme -cne 'https' -or $uri.UserInfo -cne '' -or $uri.Query -cne '' -or $uri.Fragment -cne '' -or
                $uri.AbsoluteUri -cne ([Uri]::new([Uri]$executionTrust.artifactOrigin, ('v2/releases/' + $manifest.releaseSetId + '/' + $original[0].fileName))).AbsoluteUri) { throw 'Personal result immutable artifact URI conflicts.' }
        }
    }
    $expectedUri = [Uri]::new([Uri]$v['trust-configuration'].manifestOrigin, 'v2/channels/pilot/release-set.v2.json')
    if ($expectedUri.Scheme -cne 'https' -or $receipt.channelManifestUri -cne $expectedUri.AbsoluteUri) { throw 'Personal result channel URI conflicts.' }
    $published = [DateTimeOffset]::Parse($receipt.publishedAtUtc)
    $completed = [DateTimeOffset]::Parse($r.completedAtUtc); $expires = [DateTimeOffset]::Parse($r.expiresAtUtc)
    if ([DateTimeOffset]::Parse($authorization.completedAtUtc) -lt [DateTimeOffset]::Parse($request.createdAtUtc) -or
        ([DateTimeOffset]::Parse($request.expiresAtUtc) - [DateTimeOffset]::Parse($request.createdAtUtc)) -gt [TimeSpan]::FromMinutes(60) -or
        [DateTimeOffset]::Parse($authorization.completedAtUtc) -ge [DateTimeOffset]::Parse($request.expiresAtUtc) -or
        $published.Offset -ne [TimeSpan]::Zero -or $published -lt [DateTimeOffset]::Parse($authorization.completedAtUtc) -or
        $published -gt [DateTimeOffset]::Parse($request.expiresAtUtc) -or $completed -lt $published -or
        $expires -le $completed -or $expires -gt $completed.AddHours(24)) { throw 'Personal result execution authorization time conflicts.' }
    if ($Fresh -and ([DateTimeOffset]::UtcNow -ge $expires -or $completed -gt [DateTimeOffset]::UtcNow.AddMinutes(5))) { throw 'Personal result is expired or future-dated.' }
    foreach ($input in $Admission.HeldDescriptors) {
        ProductionReleaseState\Assert-ProductionReleaseInputStillLocked -Descriptor $input -Label 'Personal result immutable evidence'
    }
}

function Assert-PersonalFeedPromotionResultBinding {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Admission, [Parameter(Mandatory)]$Plan,
        [Parameter(Mandatory)]$Identity, [Parameter(Mandatory)][string]$IdentitySha256,
        [Parameter(Mandatory)][string]$R7HeadSha256, [Parameter(Mandatory)][string]$R8HeadSha256,
        [Parameter(Mandatory)][string]$SealedRequestSha256, [Parameter(Mandatory)]$CandidateFiles, [switch]$Fresh)
    Assert-PersonalFeedPromotionResultBindingCore @PSBoundParameters
}

function Get-PersonalFeedPromotionStateContext {
    param([string]$StateRoot, $Plan, $Identity, [string]$IdentitySha256, $Receipts)
    if (@($Receipts).Count -lt 8) { throw 'Personal result requires sealed r8.' }
    $heads = @{}
    foreach ($revision in @(7,8)) {
        $receipt = $Receipts[$revision-1]
        $name = $revision.ToString('0000') + '-' + $receipt.phase.ToLowerInvariant().Replace('_','-') + '.json'
        $input = ProductionReleaseState\Open-ProductionReleaseInput -Path (Join-Path (Join-Path $StateRoot 'receipts') $name) -Label 'Personal historical source receipt' -MaximumBytes 1MB
        try {
            $head = [ordered]@{schemaVersion=2;stateType='ensou-dsh-launcher-production-release-head';orchestrationId=$Identity.orchestrationId;edition='Personal';planSha256=$Identity.planSha256;identitySha256=$IdentitySha256;revision=$revision;phase=$receipt.phase;receiptFileName=$name;receiptSha256=$input.Sha256;updatedAtUtc=$receipt.recordedAtUtc;targetChannel='pilot'}
            $heads[$revision] = ProductionReleaseState\Get-ProductionSha256Bytes -Bytes (ProductionReleaseState\ConvertTo-ProductionJsonBytes $head)
        } finally { $input.Stream.Dispose() }
    }
    $sealed = ProductionReleaseState\Open-ProductionReleaseInput -Path (Join-Path $StateRoot 'requests/pilot-feed-promotion.v1/request.v1.json') -Label 'Personal sealed r8 request' -MaximumBytes 1MB
    try {
        if ($Receipts[7].data.evidenceType -cne 'PILOT_PROMOTION_REQUESTED' -or
            $Receipts[7].data.relativePath -cne 'requests/pilot-feed-promotion.v1/request.v1.json' -or $Receipts[7].data.sha256 -cne $sealed.Sha256) { throw 'Personal sealed r8 request conflicts with its receipt.' }
        return @{Plan=$Plan;Identity=$Identity;IdentitySha256=$IdentitySha256;R7HeadSha256=$heads[7];R8HeadSha256=$heads[8];SealedRequestSha256=$sealed.Sha256;CandidateFiles=@($Receipts[4].data.files)}
    } finally { $sealed.Stream.Dispose() }
}

function Assert-PersonalFeedPromotionHistoricalState {
    param([string]$StateRoot, $Plan, $Identity, [string]$IdentitySha256, $Receipts, [int]$CommittedRevision, [int]$AdmittedRevision)
    $root = Join-Path $StateRoot 'imports/pilot-feed-result.v1'
    $exists = Test-Path -LiteralPath $root
    if (($exists -and $CommittedRevision -lt 8) -or ($AdmittedRevision -ge 9 -and -not $exists)) { throw 'Personal r9 completed result bundle is missing or premature.' }
    if ($AdmittedRevision -lt 8) { return }
    $context = Get-PersonalFeedPromotionStateContext -StateRoot $StateRoot -Plan $Plan -Identity $Identity -IdentitySha256 $IdentitySha256 -Receipts $Receipts
    if (-not $exists) { return }
    $admission = Open-PersonalFeedPromotionResult -BundleRoot $root
    try {
        Assert-PersonalFeedPromotionResultBinding -Admission $admission @context
        if ($AdmittedRevision -ge 9 -and ($Receipts[8].data.evidenceType -cne 'PILOT_FEED_PROMOTED' -or
            $Receipts[8].data.relativePath -cne 'imports/pilot-feed-result.v1/result.v1.json' -or
            $Receipts[8].data.sha256 -cne $admission.Envelope.Sha256)) { throw 'Personal r9 receipt differs from its authenticated completed result.' }
    } finally { Close-PersonalFeedPromotionResult $admission }
}

function Assert-PersonalFeedPromotionTransition {
    param($State,[string]$Phase,$Data)
    if($Phase -ceq 'PILOT_PROMOTION_REQUESTED') {
        if($Data.evidenceType -cne $Phase -or $Data.relativePath -cne 'requests/pilot-feed-promotion.v1/request.v1.json') { throw 'Personal r8 requires its exact sealed request; generic evidence cannot advance it.' }
        $path=Join-Path $State.StateRoot 'requests/pilot-feed-promotion.v1/request.v1.json'
        $input=ProductionReleaseState\Read-StrictProductionJsonFile -Path $path -Label 'Personal sealed request transition' -SchemaPath (Join-Path $PSScriptRoot '../schemas/launcher-feed-promotion-request-v1.schema.json')
        $request=$input.Value
        if($Data.evidenceType -cne $Phase -or $Data.relativePath -cne 'requests/pilot-feed-promotion.v1/request.v1.json' -or $Data.sha256 -cne $input.Sha256 -or
            $request.edition -cne 'Personal' -or $request.exposureRing -cne 'pilot' -or $request.feedChannel -cne 'pilot' -or $request.publishScope -cne 'channel-head' -or
            $request.sourceState.headSha256 -cne $State.HeadSha256 -or $request.sourceState.planSha256 -cne $State.Identity.planSha256 -or
            $request.sourceState.identitySha256 -cne $State.IdentitySha256 -or $request.orchestrationId -cne $State.Identity.orchestrationId -or $request.releaseSetId -cne $State.Plan.releaseSetId) { throw 'Personal r8 requires its exact sealed request; generic evidence cannot advance it.' }
        Assert-PersonalResultEqual $request.authorizationTrust $State.Plan.externalResponseTrusts.feedPromotion 'r8 plan trust'
        foreach($role in @('release-manifest','launcher','runtime')) {
            $candidate=@($State.Receipts[4].data.files | Where-Object role -CEQ $role)
            $file=@($request.files | Where-Object role -CEQ $role)
            if($candidate.Count -ne 1 -or $file.Count -ne 1 -or $candidate[0].sha256 -cne $file[0].sha256 -or $candidate[0].sizeBytes -ne $file[0].sizeBytes -or $candidate[0].fileName -cne $file[0].fileName){throw 'Personal r8 request candidate differs from r5.'}
        }
        return
    }
    if($Phase -ceq 'PILOT_FEED_PROMOTED') {
        if($Data.evidenceType -cne $Phase -or $Data.relativePath -cne 'imports/pilot-feed-result.v1/result.v1.json'){throw 'Personal r9 requires its authenticated completed result; generic evidence cannot advance it.'}
        $context=Get-PersonalFeedPromotionStateContext -StateRoot $State.StateRoot -Plan $State.Plan -Identity $State.Identity -IdentitySha256 $State.IdentitySha256 -Receipts $State.Receipts
        $admission=Open-PersonalFeedPromotionResult -BundleRoot (Join-Path $State.StateRoot 'imports/pilot-feed-result.v1')
        try {
            Assert-PersonalFeedPromotionResultBinding -Admission $admission @context -Fresh
            if($Data.evidenceType -cne $Phase -or $Data.relativePath -cne 'imports/pilot-feed-result.v1/result.v1.json' -or $Data.sha256 -cne $admission.Envelope.Sha256){throw 'Personal r9 requires its authenticated completed result; generic evidence cannot advance it.'}
        }finally{Close-PersonalFeedPromotionResult $admission}
    }
}

Export-ModuleMember -Function @('Get-PersonalFeedPromotionResultAuthenticationPayload','Open-PersonalFeedPromotionResult','Close-PersonalFeedPromotionResult','Assert-PersonalFeedPromotionResultBinding','Get-PersonalFeedPromotionStateContext','Assert-PersonalFeedPromotionHistoricalState','Assert-PersonalFeedPromotionTransition')
