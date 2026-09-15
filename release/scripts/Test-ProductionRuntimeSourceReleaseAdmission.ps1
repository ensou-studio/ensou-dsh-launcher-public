#Requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$schemaRoot = Join-Path $repositoryRoot 'release\schemas'
$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$publisherTestProject = Join-Path $repositoryRoot `
    'tests\Ensou.Dsh.Enterprise.ReleasePublisherTests\Ensou.Dsh.Enterprise.ReleasePublisherTests.csproj'
$script:Passed = 0

function Assert-Test {
    param([bool]$Condition, [string]$Label)
    if (-not $Condition) { throw "FAIL: $Label" }
    $script:Passed++
    Write-Output "PASS: $Label"
}

function Assert-Rejected {
    param([string]$Label, [scriptblock]$Action)
    $rejected = $false
    try { $null = & $Action } catch { $rejected = $true }
    Assert-Test $rejected $Label
}

function Copy-TestObject {
    param([Parameter(Mandatory = $true)]$Value)
    return $Value | ConvertTo-Json -Depth 100 -Compress |
        ConvertFrom-Json -Depth 100 -DateKind String
}

function Test-SchemaDocument {
    param([string]$SchemaName, [Parameter(Mandatory = $true)]$Value)
    return Test-Json -Json ($Value | ConvertTo-Json -Depth 100 -Compress) `
        -SchemaFile (Join-Path $schemaRoot $SchemaName) -ErrorAction Stop
}

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertTo-LowSP256Signature {
    param([byte[]]$Signature)
    if ($Signature.Length -ne 64) { throw 'Expected one P-256 P1363 signature.' }
    $order = [Numerics.BigInteger]::Parse(
        '0FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551',
        [Globalization.NumberStyles]::AllowHexSpecifier)
    $s = [Numerics.BigInteger]::Parse(
        '0' + [Convert]::ToHexString($Signature[32..63]),
        [Globalization.NumberStyles]::AllowHexSpecifier)
    if ($s -gt ($order / 2)) {
        $normalized = ($order - $s).ToByteArray($true, $true)
        $Signature[32..63] = [byte[]]::new(32)
        [Array]::Copy($normalized, 0, $Signature, 64 - $normalized.Length, $normalized.Length)
    }
    return ,$Signature
}

foreach ($path in @(
    $stateModulePath,
    $publisherTestProject,
    (Join-Path $schemaRoot 'launcher-production-release-plan-v2.schema.json'),
    (Join-Path $schemaRoot 'launcher-production-release-state-v2.schema.json'),
    (Join-Path $schemaRoot 'launcher-production-publisher-input-v1.schema.json'),
    (Join-Path $schemaRoot 'launcher-manifest-publishing-request-v1.schema.json'),
    (Join-Path $schemaRoot 'launcher-manifest-publishing-response-v1.schema.json')
)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required runtime source-release contract is missing: $path"
    }
}

foreach ($schemaName in @(
    'launcher-production-release-plan-v2.schema.json',
    'launcher-production-release-state-v2.schema.json',
    'launcher-production-publisher-input-v1.schema.json',
    'launcher-manifest-publishing-request-v1.schema.json',
    'launcher-manifest-publishing-response-v1.schema.json'
)) {
    $schemaPath = Join-Path $schemaRoot $schemaName
    Assert-Test (Test-Json -Json (Get-Content -Raw -LiteralPath $schemaPath) -ErrorAction Stop) `
        "Schema is valid JSON: $schemaName"
}

$planSchemaName = 'launcher-production-release-plan-v2.schema.json'
$personalPlan = Get-Content -Raw -LiteralPath `
    (Join-Path $repositoryRoot 'release\examples\personal-pilot-release-plan.example.json') |
    ConvertFrom-Json -Depth 100 -DateKind String
Assert-Test (Test-SchemaDocument $planSchemaName $personalPlan) `
    'Historical Personal plan remains valid without a source anchor'

$personalWithAnchor = Copy-TestObject $personalPlan
$personalWithAnchor.runtimeCandidate | Add-Member githubRepository 'ensou/runtime'
$personalWithAnchor.runtimeCandidate | Add-Member githubReleaseCommit ('b' * 40)
Assert-Rejected 'Personal plan cannot claim current Enterprise source readiness' {
    if (Test-SchemaDocument $planSchemaName $personalWithAnchor) {
        throw 'Schema unexpectedly accepted the Personal source anchor.'
    }
}

$enterprisePlan = Copy-TestObject $personalPlan
$enterprisePlan.edition = 'Enterprise'
$enterprisePlan.targetChannel = 'stable'
foreach ($name in @('personalAccountOrigin', 'personalPilotTemplateStatus', 'personalPilotDevices')) {
    $enterprisePlan.PSObject.Properties.Remove($name)
}
$enterprisePlan | Add-Member pilotEvidenceTrustPolicySha256 ('1' * 64)
$enterprisePlan.releaseCompatibility = [pscustomobject][ordered]@{ startupStubProtocol = 1 }
$enterprisePlan.externalResponseTrusts.installerSigning.purpose = 'installer-signing-response'
$enterprisePlan.runtimeCandidate | Add-Member githubRepository 'ensou/runtime'
$enterprisePlan.runtimeCandidate | Add-Member githubReleaseCommit ('b' * 40)
Assert-Test ([string]$enterprisePlan.sourceCommit -cne `
    [string]$enterprisePlan.runtimeCandidate.githubReleaseCommit) `
    'Runtime build commit remains distinct from the later Launcher source commit'
Assert-Test (Test-SchemaDocument $planSchemaName $enterprisePlan) `
    'Enterprise Stable plan accepts one paired source anchor'
$unpairedPlan = Copy-TestObject $enterprisePlan
$unpairedPlan.runtimeCandidate.PSObject.Properties.Remove('githubReleaseCommit')
Assert-Rejected 'Plan rejects an unpaired source anchor' {
    if (Test-SchemaDocument $planSchemaName $unpairedPlan) {
        throw 'Schema unexpectedly accepted an unpaired source anchor.'
    }
}

$sha = '0' * 64
$commit = 'b' * 40
$inputs = @()
foreach ($index in 1..4) {
    $inputs += [ordered]@{
        role = "role-$index"; fileName = "file$index.exe"; sizeBytes = 1
        sha256 = $sha; peContentSha256 = $sha
    }
}
$stateRuntime = [ordered]@{
    releaseId = 'managed-v2026.09.10.1'
    githubReleaseTag = 'managed-v2026.09.10.1'
    githubRepository = 'ensou/runtime'
    githubReleaseCommit = $commit
    harnessSourceTag = 'dsh-v0.1.2-rc.1'
    harnessSourceCommit = 'a' * 40
    archiveSha256 = $sha
    metadataSha256 = $sha
    hashEvidenceSha256 = $sha
    localMetadataPromotionEligible = $true
    publicationStatus = 'IMMUTABLE_SOURCE_RELEASE_UNVERIFIED'
}
$stateReceipt = [ordered]@{
    schemaVersion = 2
    receiptType = 'ensou-dsh-launcher-production-release-transition'
    orchestrationId = '11111111-1111-4111-8111-111111111111'
    edition = 'Enterprise'
    targetChannel = 'stable'
    planSha256 = $sha
    identitySha256 = $sha
    revision = 1
    phase = 'PLAN_ADMITTED'
    previousReceiptSha256 = $sha
    transitionSha256 = $sha
    data = [ordered]@{
        releaseSetId = 'managed-v2026.09.10.1'
        targetChannel = 'stable'
        sourceCommit = 'a' * 40
        sourceTree = 'a' * 40
        manifestUri = 'https://example.test/manifest'
        artifactBaseUri = 'https://example.test/artifacts'
        releaseManifestTrustSha256 = $sha
        releaseCompatibilitySha256 = $sha
        runtimeCandidate = $stateRuntime
        clientInputs = $inputs
    }
    recordedAtUtc = '2026-09-10T00:00:00Z'
}
$stateSchemaName = 'launcher-production-release-state-v2.schema.json'
Assert-Test (Test-SchemaDocument $stateSchemaName $stateReceipt) `
    'Enterprise Stable r1 receipt retains the paired source anchor'
$personalState = Copy-TestObject $stateReceipt
$personalState.edition = 'Personal'
$personalState.targetChannel = 'pilot'
$personalState.data.targetChannel = 'pilot'
Assert-Rejected 'Personal r1 receipt cannot claim current Enterprise source readiness' {
    if (Test-SchemaDocument $stateSchemaName $personalState) {
        throw 'Schema unexpectedly accepted a Personal source anchor.'
    }
}

Import-Module $stateModulePath -Force
$expectation = Get-ProductionRuntimeSourceReleaseExpectation -Plan $enterprisePlan
Assert-Test ($expectation.repository -ceq 'ensou/runtime' -and
    $expectation.tagName -ceq [string]$enterprisePlan.runtimeCandidate.githubReleaseTag -and
    $expectation.targetCommit -ceq $commit) `
    'Source expectation is derived only from the original runtime candidate anchor'

$archive = $enterprisePlan.runtimeCandidate.archive
$metadata = $enterprisePlan.runtimeCandidate.metadata
$hashEvidence = $enterprisePlan.runtimeCandidate.hashEvidence
$sourceRelease = [pscustomobject][ordered]@{
    repository = 'ensou/runtime'
    githubReleaseId = [long]10
    tagName = [string]$enterprisePlan.runtimeCandidate.githubReleaseTag
    targetCommit = $commit
    immutable = $true
    assets = @(
        [pscustomobject][ordered]@{ role = 'archive'; githubAssetId = [long]11; fileName = $archive.fileName; sizeBytes = [long]$archive.sizeBytes; sha256 = $archive.sha256 },
        [pscustomobject][ordered]@{ role = 'metadata'; githubAssetId = [long]12; fileName = $metadata.fileName; sizeBytes = [long]$metadata.sizeBytes; sha256 = $metadata.sha256 },
        [pscustomobject][ordered]@{ role = 'hash-evidence'; githubAssetId = [long]13; fileName = $hashEvidence.fileName; sizeBytes = [long]$hashEvidence.sizeBytes; sha256 = $hashEvidence.sha256 }
    )
}
$organizationReceipt = [ordered]@{
    schemaVersion = 2
    receiptType = 'ensou-dsh-runtime-organization-admission'
    releaseId = [string]$enterprisePlan.runtimeCandidate.releaseId
    sourceRuntimeMetadataSha256 = [string]$metadata.sha256
    decision = 'admitted'
    reviewedAtUnixSeconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    signature = [ordered]@{ algorithm = 'ES256'; keyId = 'runtime-admission'; value = 'A' * 86 }
    sourceRelease = $sourceRelease
}
$receiptBytes = ConvertTo-ProductionJsonBytes -Value $organizationReceipt
$receiptSha = Get-ProductionSha256Bytes -Bytes $receiptBytes
$admission = [pscustomobject][ordered]@{
    receiptSha256 = $receiptSha
    sourceRelease = $sourceRelease
}
$admissionResult = Assert-ProductionRuntimeSourceReleaseAdmission `
    -Admission $admission `
    -Plan $enterprisePlan `
    -OrganizationAdmissionReceiptInput ([pscustomobject]@{
        Bytes = $receiptBytes
        Sha256 = $receiptSha
    })
Assert-Test ($admissionResult.Status -ceq 'RUNTIME_SOURCE_RELEASE_AUTHENTICATED') `
    'r5 source admission binds the exact organization receipt and immutable tuple'

$reorderedAssets = @()
foreach ($asset in @($sourceRelease.assets)) {
    $reorderedAssets += [ordered]@{
        sha256 = [string]$asset.sha256
        sizeBytes = [long]$asset.sizeBytes
        fileName = [string]$asset.fileName
        githubAssetId = [long]$asset.githubAssetId
        role = [string]$asset.role
    }
}
$reorderedReceipt = [ordered]@{
    sourceRelease = [ordered]@{
        assets = $reorderedAssets
        immutable = $true
        targetCommit = $commit
        tagName = [string]$enterprisePlan.runtimeCandidate.githubReleaseTag
        githubReleaseId = [long]10
        repository = 'ensou/runtime'
    }
    signature = [ordered]@{ value = 'A' * 86; keyId = 'runtime-admission'; algorithm = 'ES256' }
    reviewedAtUnixSeconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    decision = 'admitted'
    sourceRuntimeMetadataSha256 = [string]$metadata.sha256
    releaseId = [string]$enterprisePlan.runtimeCandidate.releaseId
    receiptType = 'ensou-dsh-runtime-organization-admission'
    schemaVersion = 2
}
$reorderedReceiptBytes = ConvertTo-ProductionJsonBytes -Value $reorderedReceipt
$reorderedReceiptSha = Get-ProductionSha256Bytes -Bytes $reorderedReceiptBytes
$reorderedResult = Assert-ProductionRuntimeSourceReleaseAdmission `
    -Admission ([pscustomobject][ordered]@{ receiptSha256=$reorderedReceiptSha; sourceRelease=$sourceRelease }) `
    -Plan $enterprisePlan `
    -OrganizationAdmissionReceiptInput ([pscustomobject]@{ Bytes=$reorderedReceiptBytes; Sha256=$reorderedReceiptSha })
Assert-Test ($reorderedResult.Status -ceq 'RUNTIME_SOURCE_RELEASE_AUTHENTICATED') `
    'Valid reordered organization receipt, signature, source and asset members remain accepted'

foreach ($leadingKeyId in @('.runtime-admission', '_runtime-admission', '-runtime-admission')) {
    $keyReceipt = Copy-TestObject $reorderedReceipt
    $keyReceipt.signature.keyId = $leadingKeyId
    $keyReceiptBytes = ConvertTo-ProductionJsonBytes -Value $keyReceipt
    $keyReceiptSha = Get-ProductionSha256Bytes -Bytes $keyReceiptBytes
    $keyResult = Assert-ProductionRuntimeSourceReleaseAdmission `
        -Admission ([pscustomobject][ordered]@{ receiptSha256=$keyReceiptSha; sourceRelease=$sourceRelease }) `
        -Plan $enterprisePlan `
        -OrganizationAdmissionReceiptInput ([pscustomobject]@{ Bytes=$keyReceiptBytes; Sha256=$keyReceiptSha })
    Assert-Test ($keyResult.Status -ceq 'RUNTIME_SOURCE_RELEASE_AUTHENTICATED') `
        "Existing organization keyId grammar accepts leading '$($leadingKeyId[0])'"
}

$stringVersionReceipt = Copy-TestObject $reorderedReceipt
$stringVersionReceipt.schemaVersion = '2'
$stringVersionBytes = ConvertTo-ProductionJsonBytes -Value $stringVersionReceipt
$stringVersionSha = Get-ProductionSha256Bytes -Bytes $stringVersionBytes
Assert-Rejected 'Organization receipt rejects string schemaVersion 2' {
    Assert-ProductionRuntimeSourceReleaseAdmission `
        -Admission ([pscustomobject][ordered]@{ receiptSha256=$stringVersionSha; sourceRelease=$sourceRelease }) `
        -Plan $enterprisePlan `
        -OrganizationAdmissionReceiptInput ([pscustomobject]@{ Bytes=$stringVersionBytes; Sha256=$stringVersionSha })
}

$unknownCases = @(
    @{ Label='outer receipt'; Mutate={ param($value) $value | Add-Member extra $true } },
    @{ Label='signature'; Mutate={ param($value) $value.signature | Add-Member extra $true } },
    @{ Label='source release'; Mutate={ param($value) $value.sourceRelease | Add-Member extra $true } },
    @{ Label='source asset'; Mutate={ param($value) $value.sourceRelease.assets[0] | Add-Member extra $true } }
)
foreach ($case in $unknownCases) {
    $unknownReceipt = Copy-TestObject $reorderedReceipt
    & $case.Mutate $unknownReceipt
    $unknownBytes = ConvertTo-ProductionJsonBytes -Value $unknownReceipt
    $unknownSha = Get-ProductionSha256Bytes -Bytes $unknownBytes
    Assert-Rejected "Organization receipt rejects unknown $($case.Label) member" {
        Assert-ProductionRuntimeSourceReleaseAdmission `
            -Admission ([pscustomobject][ordered]@{ receiptSha256=$unknownSha; sourceRelease=$sourceRelease }) `
            -Plan $enterprisePlan `
            -OrganizationAdmissionReceiptInput ([pscustomobject]@{ Bytes=$unknownBytes; Sha256=$unknownSha })
    }
}
$unknownAdmission = Copy-TestObject $admission
$unknownAdmission | Add-Member extra $true
Assert-Rejected 'Authenticated r5 source admission rejects unknown outer member' {
    Assert-ProductionRuntimeSourceReleaseAdmission `
        -Admission $unknownAdmission -Plan $enterprisePlan `
        -OrganizationAdmissionReceiptInput ([pscustomobject]@{ Bytes=$receiptBytes; Sha256=$receiptSha })
}

$forgedAdmission = Copy-TestObject $admission
$forgedAdmission.sourceRelease.targetCommit = 'c' * 40
Assert-Rejected 'r5 rejects a source tuple that differs from the plan and receipt' {
    Assert-ProductionRuntimeSourceReleaseAdmission `
        -Admission $forgedAdmission `
        -Plan $enterprisePlan `
        -OrganizationAdmissionReceiptInput ([pscustomobject]@{ Bytes = $receiptBytes; Sha256 = $receiptSha })
}

$response = [pscustomobject][ordered]@{
    schemaVersion = 1
    responseType = 'ensou-dsh-launcher-manifest-publishing-response'
    orchestrationId = [string]$enterprisePlan.orchestrationId
    edition = 'Enterprise'
    releaseSetId = [string]$enterprisePlan.releaseSetId
    channel = 'stable'
    planSha256 = $sha
    requestSha256 = $sha
    requestNonce = 'N' * 43
    baseHeadSha256 = $sha
    admissionHeadSha256 = $sha
    admissionRevision = 4
    requestExpiresAtUtc = '2026-09-10T01:00:00Z'
    completedAtUtc = '2026-09-10T00:01:00Z'
    files = @()
    authentication = [ordered]@{
        algorithm = 'ES256'; keyId = 'publisher'; purpose = 'manifest-publishing-response'
        payloadType = 'ensou-dsh-launcher-manifest-publishing-response-authentication-v1'
        value = 'A' * 86
    }
    runtimeSourceReleaseAdmission = $admission
}
$authenticatedPayload = Get-ProductionReleaseManifestPublishingResponseAuthenticationPayload `
    -Response $response
$tamperedResponse = Copy-TestObject $response
$tamperedResponse.runtimeSourceReleaseAdmission.sourceRelease.githubReleaseId = [long]99
$tamperedPayload = Get-ProductionReleaseManifestPublishingResponseAuthenticationPayload `
    -Response $tamperedResponse
Assert-Test ((Get-ProductionSha256Bytes -Bytes $authenticatedPayload) -cne
    (Get-ProductionSha256Bytes -Bytes $tamperedPayload)) `
    'Manifest-publisher authentication payload covers the complete source admission'

# Exercise the historical verifier against the real committed-file layout. The
# State object below is intentionally the already-replayed caller projection;
# this focused test does not substitute for Get-ProductionReleaseState.
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) `
    ('ensou-runtime-source-history-' + [Guid]::NewGuid().ToString('N'))
$publisherSigner = [Security.Cryptography.ECDsa]::Create(
    [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
try {
    $publisherPoint = $publisherSigner.ExportParameters($false).Q
    $enterprisePlan.externalResponseTrusts.manifestPublishing.keyId = 'source-history-publisher'
    $enterprisePlan.externalResponseTrusts.manifestPublishing.x = ConvertTo-Base64Url $publisherPoint.X
    $enterprisePlan.externalResponseTrusts.manifestPublishing.y = ConvertTo-Base64Url $publisherPoint.Y

    $requestRoot = Join-Path $fixtureRoot 'requests\stable-manifest-publishing.v1'
    $requestPayloadRoot = Join-Path $requestRoot 'payload'
    $responseRoot = Join-Path $fixtureRoot 'imports\stable-signed-candidate.v1'
    $receiptsRoot = Join-Path $fixtureRoot 'receipts'
    foreach ($directory in @($requestPayloadRoot, $responseRoot, $receiptsRoot)) {
        [IO.Directory]::CreateDirectory($directory) | Out-Null
    }
    $organizationReceiptPath = Join-Path $requestPayloadRoot 'runtime-organization-admission.json'
    [IO.File]::WriteAllBytes($organizationReceiptPath, $receiptBytes)
    $publisherFiles = @(
        [ordered]@{ role='edition-runtime-organization-admission'; fileName='runtime-organization-admission.json'; relativePath='payload/runtime-organization-admission.json'; sizeBytes=[long]$receiptBytes.Length; sha256=$receiptSha }
    )
    foreach ($index in 1..6) {
        $publisherFiles += [ordered]@{ role="fixture-$index"; fileName="fixture$index.bin"; relativePath="payload/fixture$index.bin"; sizeBytes=1; sha256=$sha }
    }
    $request = [ordered]@{
        schemaVersion=1; requestType='ensou-dsh-launcher-manifest-publishing-request'
        orchestrationId=[string]$enterprisePlan.orchestrationId; edition='Enterprise'
        releaseSetId=[string]$enterprisePlan.releaseSetId; channel='stable'; planSha256=$sha
        baseHeadSha256='2' * 64; requestedRevision=4; requestNonce='N' * 43
        createdAtUtc='2026-09-10T00:00:00Z'; expiresAtUtc='2026-09-10T01:00:00Z'
        publisherInput=[ordered]@{ descriptorRelativePath='publisher-input.v1.json'; descriptorSha256='3' * 64; files=$publisherFiles }
        releaseManifestTrust=$enterprisePlan.releaseManifestTrust
        releaseCompatibility=[ordered]@{ startupStubProtocol=1 }
        componentReleaseIds=[ordered]@{ launcher='launcher'; runtime='runtime'; pluginPolicy='policy' }
        runtimeProvenance=[ordered]@{ harnessSourceTag='dsh-v0.1.2-rc.1'; harnessSourceCommit='a' * 40 }
        runtimeSourceReleaseExpectation=[ordered]@{ repository='ensou/runtime'; tagName=[string]$enterprisePlan.runtimeCandidate.githubReleaseTag; targetCommit=$commit }
        responseAuthentication=[ordered]@{ algorithm='ES256'; keyId='source-history-publisher'; purpose='manifest-publishing-response'; payloadType='ensou-dsh-launcher-manifest-publishing-response-authentication-v1' }
    }
    Assert-Test (Test-SchemaDocument 'launcher-manifest-publishing-request-v1.schema.json' $request) `
        'File-backed r4 request satisfies its exact schema'
    $requestBytes = ConvertTo-ProductionJsonBytes -Value $request
    $requestPath = Join-Path $requestRoot 'manifest-publishing-request.v1.json'
    [IO.File]::WriteAllBytes($requestPath, $requestBytes)
    $requestSha = Get-ProductionSha256Bytes -Bytes $requestBytes

    $identity = [pscustomobject][ordered]@{
        schemaVersion=2; identityType='ensou-dsh-launcher-production-release-state'
        orchestrationId=[string]$enterprisePlan.orchestrationId; edition='Enterprise'; targetChannel='stable'
        planSha256=$sha; initializationSha256='4' * 64; createdAtUtc='2026-09-10T00:00:00Z'
    }
    $identitySha = Get-ProductionSha256Bytes -Bytes (ConvertTo-ProductionJsonBytes -Value $identity)
    $r4 = [pscustomobject][ordered]@{
        schemaVersion=2; receiptType='ensou-dsh-launcher-production-release-transition'
        orchestrationId=[string]$enterprisePlan.orchestrationId; edition='Enterprise'; targetChannel='stable'
        planSha256=$sha; identitySha256=$identitySha; revision=4; phase='STABLE_MANIFEST_SIGNING_REQUESTED'
        previousReceiptSha256='5' * 64; transitionSha256='6' * 64
        data=[ordered]@{
            requestRelativePath='requests/stable-manifest-publishing.v1/manifest-publishing-request.v1.json'
            requestSha256=$requestSha; publisherInputDescriptorSha256='3' * 64
            baseHeadSha256='2' * 64; requestNonce='N' * 43
            createdAtUtc='2026-09-10T00:00:00Z'; expiresAtUtc='2026-09-10T01:00:00Z'
            responseAuthenticationKeyId='source-history-publisher'; responseAuthenticationPurpose='manifest-publishing-response'
            responseAuthenticationPayloadType='ensou-dsh-launcher-manifest-publishing-response-authentication-v1'
            releaseManifestTrustSha256='7' * 64; releaseCompatibilitySha256='8' * 64
            componentReleaseIdsSha256='9' * 64; runtimeProvenanceSha256='a' * 64
            compiledReleaseTrustStatus='VERIFIED'; files=$publisherFiles
        }
        recordedAtUtc='2026-09-10T00:00:01Z'
    }
    Assert-Test (Test-SchemaDocument $stateSchemaName $r4) 'Typed r4 receipt satisfies the state schema'
    $r4Bytes = ConvertTo-ProductionJsonBytes -Value $r4
    [IO.File]::WriteAllBytes((Join-Path $receiptsRoot '0004-stable-manifest-signing-requested.json'), $r4Bytes)
    $r4ReceiptSha = Get-ProductionSha256Bytes -Bytes $r4Bytes
    $r4Head = [ordered]@{
        schemaVersion=2; stateType='ensou-dsh-launcher-production-release-head'
        orchestrationId=[string]$enterprisePlan.orchestrationId; edition='Enterprise'
        planSha256=$sha; identitySha256=$identitySha; revision=4
        phase='STABLE_MANIFEST_SIGNING_REQUESTED'
        receiptFileName='0004-stable-manifest-signing-requested.json'; receiptSha256=$r4ReceiptSha
        updatedAtUtc='2026-09-10T00:00:01Z'; targetChannel='stable'
    }
    $r4HeadSha = Get-ProductionSha256Bytes -Bytes (ConvertTo-ProductionJsonBytes -Value $r4Head)

    $responseFiles = @(
        [ordered]@{ role='release-manifest'; fileName='release-set.v2.json'; relativePath='candidate/release-set.v2.json'; sizeBytes=1; sha256='b' * 64 },
        [ordered]@{ role='release-public-key'; fileName='release-public-key.v2.json'; relativePath='candidate/release-public-key.v2.json'; sizeBytes=1; sha256='c' * 64 },
        [ordered]@{ role='launcher'; fileName='launcher.zip'; relativePath='candidate/launcher.zip'; sizeBytes=1; sha256='d' * 64 },
        [ordered]@{ role='runtime'; fileName='runtime.zip'; relativePath='candidate/runtime.zip'; sizeBytes=1; sha256='e' * 64 },
        [ordered]@{ role='plugin-policy'; fileName='plugin-policy.zip'; relativePath='candidate/plugin-policy.zip'; sizeBytes=1; sha256='f' * 64 }
    )
    $historyResponse = [pscustomobject][ordered]@{
        schemaVersion=1; responseType='ensou-dsh-launcher-manifest-publishing-response'
        orchestrationId=[string]$enterprisePlan.orchestrationId; edition='Enterprise'
        releaseSetId=[string]$enterprisePlan.releaseSetId; channel='stable'; planSha256=$sha
        requestSha256=$requestSha; requestNonce='N' * 43; baseHeadSha256='2' * 64
        admissionHeadSha256=$r4HeadSha; admissionRevision=4
        requestExpiresAtUtc='2026-09-10T01:00:00Z'; completedAtUtc='2026-09-10T00:01:00Z'
        runtimeSourceReleaseAdmission=$admission; files=$responseFiles
        authentication=[ordered]@{ algorithm='ES256'; keyId='source-history-publisher'; purpose='manifest-publishing-response'; payloadType='ensou-dsh-launcher-manifest-publishing-response-authentication-v1'; value='A' * 86 }
    }
    $signature = $publisherSigner.SignData(
        (Get-ProductionReleaseManifestPublishingResponseAuthenticationPayload -Response $historyResponse),
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
    $historyResponse.authentication.value = ConvertTo-Base64Url `
        (ConvertTo-LowSP256Signature $signature)
    Assert-Test (Test-SchemaDocument 'launcher-manifest-publishing-response-v1.schema.json' $historyResponse) `
        'Signed file-backed r5 response satisfies its exact schema'
    $responseBytes = ConvertTo-ProductionJsonBytes -Value $historyResponse
    $responsePath = Join-Path $responseRoot 'manifest-publishing-response.v1.json'
    [IO.File]::WriteAllBytes($responsePath, $responseBytes)
    $responseSha = Get-ProductionSha256Bytes -Bytes $responseBytes
    $r5 = [pscustomobject][ordered]@{
        schemaVersion=2; receiptType='ensou-dsh-launcher-production-release-transition'
        orchestrationId=[string]$enterprisePlan.orchestrationId; edition='Enterprise'; targetChannel='stable'
        planSha256=$sha; identitySha256=$identitySha; revision=5; phase='STABLE_SIGNED_CANDIDATE_IMPORTED'
        previousReceiptSha256=$r4ReceiptSha; transitionSha256='1' * 64
        data=[ordered]@{
            responseRelativePath='imports/stable-signed-candidate.v1/manifest-publishing-response.v1.json'
            responseSha256=$responseSha; requestSha256=$requestSha; requestNonce='N' * 43
            baseHeadSha256='2' * 64; admissionHeadSha256=$r4HeadSha; admissionRevision=4
            requestExpiresAtUtc='2026-09-10T01:00:00Z'; completedAtUtc='2026-09-10T00:01:00Z'
            authenticationKeyId='source-history-publisher'; authenticationPurpose='manifest-publishing-response'
            authenticationPayloadType='ensou-dsh-launcher-manifest-publishing-response-authentication-v1'
            manifestRelativePath='imports/stable-signed-candidate.v1/candidate/release-set.v2.json'
            manifestSha256='b' * 64; releaseManifestTrustSha256='7' * 64
            releaseCompatibilitySha256='8' * 64; componentReleaseIdsSha256='9' * 64
            runtimeProvenanceSha256='a' * 64; compiledReleaseTrustStatus='VERIFIED'
            productionAdmission='NO_GO'; files=$responseFiles
        }
        recordedAtUtc='2026-09-10T00:01:01Z'
    }
    Assert-Test (Test-SchemaDocument $stateSchemaName $r5) 'Typed r5 receipt satisfies the state schema'
    $r5Bytes = ConvertTo-ProductionJsonBytes -Value $r5
    $r5ReceiptSha = Get-ProductionSha256Bytes -Bytes $r5Bytes
    $head = [pscustomobject][ordered]@{
        schemaVersion=2; stateType='ensou-dsh-launcher-production-release-head'
        orchestrationId=[string]$enterprisePlan.orchestrationId; edition='Enterprise'; targetChannel='stable'
        planSha256=$sha; identitySha256=$identitySha; revision=5; phase='STABLE_SIGNED_CANDIDATE_IMPORTED'
        receiptFileName='0005-stable-signed-candidate-imported.json'; receiptSha256=$r5ReceiptSha
        updatedAtUtc='2026-09-10T00:01:01Z'
    }
    $headBytes = ConvertTo-ProductionJsonBytes -Value $head
    $headPath = Join-Path $fixtureRoot 'head.json'
    [IO.File]::WriteAllBytes($headPath, $headBytes)
    $headSha = Get-ProductionSha256Bytes -Bytes $headBytes
    $state = [pscustomobject]@{
        StateRoot=$fixtureRoot; Identity=$identity; IdentitySha256=$identitySha
        Head=$head; HeadSha256=$headSha; Receipts=@([pscustomobject]@{}, [pscustomobject]@{}, [pscustomobject]@{}, $r4, $r5)
    }
    $history = Assert-ProductionRuntimeSourceReleaseHistory -State $state -Plan $enterprisePlan
    Assert-Test ($history.SourceReleaseVerified -and $history.TargetCommit -ceq $commit) `
        'Historical replay verifies raw r4/r5, signed response, organization receipt and current head'
    $oldPlan = Copy-TestObject $enterprisePlan
    $oldPlan.runtimeCandidate.PSObject.Properties.Remove('githubRepository')
    $oldPlan.runtimeCandidate.PSObject.Properties.Remove('githubReleaseCommit')
    $oldHistory = Assert-ProductionRuntimeSourceReleaseHistory -State $state -Plan $oldPlan
    Assert-Test (-not $oldHistory.SourceReleaseVerified) `
        'Historical plan without an original source anchor remains explicitly unverified'

    $originalOrganizationBytes = [IO.File]::ReadAllBytes($organizationReceiptPath)
    [IO.File]::WriteAllBytes($organizationReceiptPath, [byte[]]($originalOrganizationBytes + @(0x20)))
    Assert-Rejected 'Historical replay rejects changed raw organization receipt bytes' {
        Assert-ProductionRuntimeSourceReleaseHistory -State $state -Plan $enterprisePlan
    }
    [IO.File]::WriteAllBytes($organizationReceiptPath, $originalOrganizationBytes)
    $badR4State = Copy-TestObject $state
    $badR4State.Receipts[3].data.requestSha256 = 'f' * 64
    Assert-Rejected 'Historical replay rejects a forged typed r4 receipt binding' {
        Assert-ProductionRuntimeSourceReleaseHistory -State $badR4State -Plan $enterprisePlan
    }
    $badR5State = Copy-TestObject $state
    $badR5State.Receipts[4].data.responseSha256 = 'f' * 64
    Assert-Rejected 'Historical replay rejects a forged typed r5 receipt binding' {
        Assert-ProductionRuntimeSourceReleaseHistory -State $badR5State -Plan $enterprisePlan
    }
    [IO.File]::WriteAllBytes($headPath, [byte[]]($headBytes + @(0x20)))
    Assert-Rejected 'Historical replay rejects a changed current state head' {
        Assert-ProductionRuntimeSourceReleaseHistory -State $state -Plan $enterprisePlan
    }
}
finally {
    $publisherSigner.Dispose()
    if (Test-Path -LiteralPath $fixtureRoot) { [IO.Directory]::Delete($fixtureRoot, $true) }
}

$testOutput = @(& dotnet run --project $publisherTestProject --configuration Release `
    --no-build -- --runtime-source-release-checks 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw "Focused ReleasePublisher source-release checks failed.`n$($testOutput -join [Environment]::NewLine)"
}
Assert-Test (($testOutput -join [Environment]::NewLine).Contains(
    'runtime source-release v2 exact admission and v1 compatibility',
    [StringComparison]::Ordinal)) `
    'Existing-trust ES256 v2 admission and frozen v1 compatibility checks ran'
foreach ($expectedCoverage in @(
    'frozen v1 payload and admission unchanged; v1 has no source origin',
    'real ES256 v2 LF/CRLF proofs validate files and locked snapshots',
    'v2 signatures and strict shape/type/ID/name/checksum negatives',
    'signed v2 archive/metadata snapshot mismatches and unchanged age/key rejection'
)) {
    Assert-Test (($testOutput -join [Environment]::NewLine).Contains(
        $expectedCoverage,
        [StringComparison]::Ordinal)) `
        "Targeted C# source-release coverage ran: $expectedCoverage"
}

Write-Output "PRODUCTION-RUNTIME-SOURCE-RELEASE-ADMISSION-PASS: $script:Passed checks; no network, release, or production mutation."
