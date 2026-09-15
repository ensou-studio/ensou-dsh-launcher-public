#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Assertions = 0
$script:Utf8 = [Text.UTF8Encoding]::new($false, $true)
$script:P256Order = [Convert]::FromHexString(
    'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551')
$script:P256HalfOrder = [Convert]::FromHexString(
    '7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8')
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$modulePath = Join-Path $PSScriptRoot 'PersonalInstallerSigningPipeline.psm1'
$contractsPath = Join-Path $PSScriptRoot 'InstallerSigningContracts.psm1'
$statePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$sharedRequestSchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\launcher-installer-signing-request-v2.schema.json'
$personalResponseSchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\personal-installer-signing-response-v2.schema.json'

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $script:Assertions++
    if (-not $Condition) {
        throw "ASSERT-TRUE failed: $Message"
    }
}

function Assert-Equal {
    param(
        $Actual,
        $Expected,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $script:Assertions++
    if ($Actual -cne $Expected) {
        throw "ASSERT-EQUAL failed: $Message; expected '$Expected', got '$Actual'."
    }
}

function Assert-Fails {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $script:Assertions++
    try {
        & $Action
    }
    catch {
        if ($_.Exception.Message -notlike "*$Pattern*") {
            throw "ASSERT-FAILS wrong error: $Message; $($_.Exception.Message)"
        }
        return
    }
    throw "ASSERT-FAILS did not fail: $Message"
}

function Get-TestSha256 {
    param([Parameter(Mandatory = $true)][string]$Seed)

    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData(
            $script:Utf8.GetBytes($Seed))).ToLowerInvariant()
}

function ConvertTo-TestBase64Url {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return [Convert]::ToBase64String($Bytes).TrimEnd('=').
        Replace('+', '-').Replace('/', '_')
}

function Compare-TestBigEndian {
    param([byte[]]$Left, [byte[]]$Right)

    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -lt $Right[$index]) { return -1 }
        if ($Left[$index] -gt $Right[$index]) { return 1 }
    }
    return 0
}

function Subtract-TestBigEndian {
    param([byte[]]$Left, [byte[]]$Right)

    $result = [byte[]]::new($Left.Length)
    $borrow = 0
    for ($index = $Left.Length - 1; $index -ge 0; $index--) {
        $value = [int]$Left[$index] - [int]$Right[$index] - $borrow
        if ($value -lt 0) {
            $value += 256
            $borrow = 1
        }
        else {
            $borrow = 0
        }
        $result[$index] = [byte]$value
    }
    if ($borrow -ne 0) { throw 'Test P-256 subtraction underflowed.' }
    return $result
}

function ConvertTo-TestLowS {
    param([Parameter(Mandatory = $true)][byte[]]$Signature)

    if ($Signature.Length -ne 64) { throw 'Test signature is not P1363.' }
    [byte[]]$s = $Signature[32..63]
    if ((Compare-TestBigEndian $s $script:P256HalfOrder) -gt 0) {
        $s = Subtract-TestBigEndian $script:P256Order $s
        [Array]::Copy($s, 0, $Signature, 32, 32)
    }
    return $Signature
}

function Copy-TestObject {
    param([Parameter(Mandatory = $true)]$Value)

    $bytes = ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $Value
    return ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
        -Bytes $bytes `
        -Label 'Test object clone'
}

function ConvertTo-TestUtc {
    param([Parameter(Mandatory = $true)][DateTimeOffset]$Value)

    return ProductionReleaseState\ConvertTo-ProductionUtc -Value $Value
}

$parseErrors = $null
[void][Management.Automation.Language.Parser]::ParseFile(
    $modulePath, [ref]$null, [ref]$parseErrors)
Assert-Equal @($parseErrors).Count 0 'Pipeline module parses without syntax errors.'

Microsoft.PowerShell.Core\Import-Module $modulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $contractsPath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $statePath -Force -ErrorAction Stop
$module = Get-Module PersonalInstallerSigningPipeline
$exports = @(Get-Command -Module PersonalInstallerSigningPipeline |
        Sort-Object Name | Select-Object -ExpandProperty Name)
Assert-Equal $exports.Count 6 'Pipeline exports its two entrypoints and four dedicated Personal validators/builders.'
Assert-True ($exports -contains 'Prepare-PersonalInstallerSigningPipeline') `
    'Prepare entrypoint is exported.'
Assert-True ($exports -contains 'Import-PersonalInstallerSigningPipelineResponse') `
    'Import entrypoint is exported.'
Assert-True ($exports -contains 'Assert-PersonalInstallerSigningResponseV2Contract') `
    'Dedicated Personal response-v2 validator is exported.'
Assert-True ($exports -contains 'Get-PersonalInstallerSigningResponseAuthenticationPayload') `
    'Dedicated Personal response-v2 authentication payload builder is exported.'

$capability = & $module {
    Get-PersonalSigningPipelineSharedRequestCapability
}
Assert-Equal $capability.IsCompatible $true `
    'Shared request-v2 advertises the reviewed Personal Pilot branch.'
Assert-Equal $capability.SchemaAllowsPersonal $true `
    'Shared request-v2 schema includes Personal.'
Assert-Equal $capability.SchemaAllowsPilot $true `
    'Shared request-v2 schema includes Pilot.'
Assert-Equal $capability.ValidatorAllowsPersonalV2 $true `
    'Shared validator admits Personal schema-v2 identity before deep closure checks.'
Assert-Equal $capability.SchemaRejectsPersonalStable $true `
    'Shared request-v2 has no Personal Stable branch.'
Assert-Equal $capability.ValidatorRejectsPersonalStable $true `
    'Shared validator rejects Personal Stable identity.'

$schema = Get-Content -LiteralPath $sharedRequestSchemaPath -Raw |
    ConvertFrom-Json -Depth 64
Assert-True (@($schema.properties.edition.enum) -contains 'Personal') `
    'Shared request-v2 edition capability is explicit schema evidence.'
Assert-True (@($schema.properties.channel.enum) -contains 'pilot') `
    'Shared request-v2 Pilot capability is explicit schema evidence.'
$identityProbeFailure = ''
try {
    [void](InstallerSigningContracts\Assert-InstallerSigningRequestContract `
            -Request ([pscustomobject]@{
                schemaVersion = 2
                edition = 'Personal'
                channel = 'pilot'
            }))
}
catch {
    $identityProbeFailure = $_.Exception.Message
}
Assert-True (-not [string]::IsNullOrWhiteSpace($identityProbeFailure)) `
    'Identity-only probe still fails closed before a full request is provided.'
Assert-True ($identityProbeFailure -cne
    'Installer-signing request edition/channel identity is invalid.') `
    'Identity-only probe reaches Personal v2 deep closure validation.'
$stableIdentityFailure = ''
try {
    [void](InstallerSigningContracts\Assert-InstallerSigningRequestContract `
            -Request ([pscustomobject]@{
                schemaVersion = 2
                edition = 'Personal'
                channel = 'stable'
            }))
}
catch {
    $stableIdentityFailure = $_.Exception.Message
}
Assert-Equal $stableIdentityFailure `
    'Installer-signing request edition/channel identity is invalid.' `
    'Personal Stable request identity fails closed.'

$readyPreparation = [pscustomobject][ordered]@{
    Status = 'PERSONAL_SHARED_REQUEST_V2_VALIDATED_NO_GO'
    Blocker = 'INSTALLER_SIGNING_RESPONSE_REQUIRED'
    ProductionAdmission = 'NO_GO'
    SharedRequestV2Status =
        'VALIDATED_PERSONAL_PILOT_EXTERNAL_SIGNER_ELIGIBLE'
    RequestDraftSha256 = Get-TestSha256 'personal-request-draft'
    R5HeadSha256 = Get-TestSha256 'personal-r5-head'
    R5ReceiptSha256 = Get-TestSha256 'personal-r5-receipt'
    DependencyBlockers = @()
    UnsignedArtifactExecution = 'FORBIDDEN_AND_NOT_PERFORMED'
    SignedArtifactExecution = 'NOT_PERFORMED'
    ExternalSigningRequestEligible = $true
}
$awaitingResponse = Import-PersonalInstallerSigningPipelineResponse `
    -Preparation $readyPreparation
Assert-Equal $awaitingResponse.Status `
    'PERSONAL_INSTALLER_SIGNING_RESPONSE_REQUIRED_NO_GO' `
    'Missing genuine signing response remains one explicit NO_GO result.'
Assert-Equal $awaitingResponse.Blocker `
    'INSTALLER_SIGNING_RESPONSE_REQUIRED' `
    'Missing-response result preserves the exact external dependency.'
Assert-Equal $awaitingResponse.ProductionAdmission 'NO_GO' `
    'Missing response cannot produce production admission.'
Assert-Equal $awaitingResponse.UnsignedArtifactExecution `
    'FORBIDDEN_AND_NOT_PERFORMED' `
    'Missing response records unsigned zero execution.'
Assert-Equal $awaitingResponse.SignedArtifactExecution 'NOT_PERFORMED' `
    'Missing response cannot execute any would-be signed executable.'
Assert-Equal @($awaitingResponse.DependencyBlockers).Count 0 `
    'Closed builder safety items are no longer reported as dependencies.'
Assert-Equal $awaitingResponse.ExternalSigningRequestEligible $true `
    'The exact Personal Pilot request remains eligible for external signing.'
Assert-Fails `
    -Action {
        $bad = Copy-TestObject $readyPreparation
        $bad.ProductionAdmission = 'GO'
        [void](Import-PersonalInstallerSigningPipelineResponse -Preparation $bad)
    } `
    -Pattern 'PERSONAL_SIGNING_PIPELINE_PREPARATION_INVALID' `
    -Message 'Import rejects a forged GO preparation.'
Assert-Fails `
    -Action {
        $bad = Copy-TestObject $readyPreparation
        $bad.ExternalSigningRequestEligible = $false
        [void](Import-PersonalInstallerSigningPipelineResponse -Preparation $bad)
    } `
    -Pattern 'PERSONAL_SIGNING_PIPELINE_PREPARATION_INVALID' `
    -Message 'Prepared Personal Pilot request cannot lose external eligibility.'
Assert-Fails `
    -Action {
        $bad = Copy-TestObject $readyPreparation
        $bad.DependencyBlockers = @('forged-dependency')
        [void](Import-PersonalInstallerSigningPipelineResponse -Preparation $bad)
    } `
    -Pattern 'PERSONAL_SIGNING_PIPELINE_PREPARATION_INVALID' `
    -Message 'Prepared Personal Pilot request cannot inject a dependency blocker.'

$orchestrationId = '12345678-1234-4abc-8def-1234567890ab'
$planSha = Get-TestSha256 'personal-plan'
$headSha = Get-TestSha256 'personal-head'
$receiptSha = Get-TestSha256 'personal-r5-receipt-bytes'
$releaseTrust = [pscustomobject][ordered]@{
    algorithm = 'ES256'
    keyId = 'personal-release-key'
    purpose = 'release-manifest-signing'
    x = 'A' * 43
    y = 'B' * 43
}
$planInput = [pscustomobject]@{
    Sha256 = $planSha
    Value = [pscustomobject]@{
        orchestrationId = $orchestrationId
        edition = 'Personal'
        targetChannel = 'pilot'
        releaseManifestTrust = $releaseTrust
    }
}
$recorded = ConvertTo-TestUtc ([DateTimeOffset]::UtcNow.AddMinutes(-2))
$headInput = [pscustomobject]@{
    Sha256 = $headSha
    Value = [pscustomobject]@{
        schemaVersion = 2
        stateType = 'ensou-dsh-launcher-production-release-head'
        orchestrationId = $orchestrationId
        edition = 'Personal'
        targetChannel = 'pilot'
        planSha256 = $planSha
        revision = 5
        phase = 'PILOT_SIGNED_CANDIDATE_IMPORTED'
        receiptFileName = '0005-pilot-signed-candidate-imported.json'
        receiptSha256 = $receiptSha
        updatedAtUtc = $recorded
    }
}
$payloadFiles = @(
    [pscustomobject][ordered]@{
        role = 'release-manifest'; fileName = 'release-set.v2.json'
        relativePath = 'payload/release-set.v2.json'; sizeBytes = 101
        sha256 = Get-TestSha256 'manifest'
    },
    [pscustomobject][ordered]@{
        role = 'startup-stub'; fileName = 'Ensou.Dsh.Bootstrapper.exe'
        relativePath = 'payload/Ensou.Dsh.Bootstrapper.exe'; sizeBytes = 202
        sha256 = Get-TestSha256 'startup'
    },
    [pscustomobject][ordered]@{
        role = 'client-bundle'; fileName = 'client-bundle.zip'
        relativePath = 'payload/client-bundle.zip'; sizeBytes = 303
        sha256 = Get-TestSha256 'client'
    },
    [pscustomobject][ordered]@{
        role = 'runtime'; fileName = 'runtime.zip'
        relativePath = 'payload/runtime.zip'; sizeBytes = 404
        sha256 = Get-TestSha256 'runtime'
    }
)
$candidateFiles = foreach ($payloadIndex in @(0, 2, 3)) {
    $payload = $payloadFiles[$payloadIndex]
    [pscustomobject][ordered]@{
        role = [string]$payload.role
        fileName = [string]$payload.fileName
        relativePath =
            "imports/pilot-signed-candidate.v1/candidate/$($payload.fileName)"
        sizeBytes = [int64]$payload.sizeBytes
        sha256 = [string]$payload.sha256
    }
}
$receiptInput = [pscustomobject]@{
    Sha256 = $receiptSha
    Value = [pscustomobject]@{
        schemaVersion = 2
        receiptType = 'ensou-dsh-launcher-production-release-transition'
        orchestrationId = $orchestrationId
        edition = 'Personal'
        targetChannel = 'pilot'
        planSha256 = $planSha
        revision = 5
        phase = 'PILOT_SIGNED_CANDIDATE_IMPORTED'
        data = [pscustomobject]@{
            files = @($candidateFiles)
            manifestSha256 = [string]$payloadFiles[0].sha256
            releaseManifestTrustSha256 =
                InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                    -Value $releaseTrust
            compiledReleaseTrustStatus = 'VERIFIED'
            productionAdmission = 'NO_GO'
        }
        recordedAtUtc = $recorded
    }
}
$request = [pscustomobject]@{
    channel = 'pilot'
    baseHeadSha256 = $headSha
    baseRevision = 5
    basePhase = 'PILOT_SIGNED_CANDIDATE_IMPORTED'
    requestedRevision = 6
    payload = [pscustomobject]@{ files = @($payloadFiles) }
}
Assert-True ([bool](& $module {
            param($p, $h, $r, $q, $expected)
            Assert-PersonalSigningPipelineR5CasBinding `
                -PlanInput $p -HeadInput $h -ReceiptInput $r `
                -Request $q -ExpectedR5HeadSha256 $expected
        } $planInput $headInput $receiptInput $request $headSha)) `
    'Exact Personal r5 head, receipt, plan, and payload closure is accepted.'
Assert-Fails `
    -Action {
        & $module {
            param($p, $h, $r, $q)
            Assert-PersonalSigningPipelineR5CasBinding `
                -PlanInput $p -HeadInput $h -ReceiptInput $r `
                -Request $q -ExpectedR5HeadSha256 ('f' * 64)
        } $planInput $headInput $receiptInput $request
    } `
    -Pattern 'PERSONAL_SIGNING_PIPELINE_R5_CAS_INVALID' `
    -Message 'Stale r5 compare-and-swap head is rejected.'
Assert-Fails `
    -Action {
        $badReceipt = Copy-TestObject $receiptInput
        $badReceipt.Value.data.files[1].sha256 = Get-TestSha256 'substitution'
        & $module {
            param($p, $h, $r, $q, $expected)
            Assert-PersonalSigningPipelineR5CasBinding `
                -PlanInput $p -HeadInput $h -ReceiptInput $r `
                -Request $q -ExpectedR5HeadSha256 $expected
        } $planInput $headInput $badReceipt $request $headSha
    } `
    -Pattern 'PERSONAL_SIGNING_PIPELINE_R5_CLOSURE_INVALID' `
    -Message 'r5 client-bundle byte substitution is rejected.'
Assert-Fails `
    -Action {
        $badReceipt = Copy-TestObject $receiptInput
        $badReceipt.Value.data.releaseManifestTrustSha256 =
            Get-TestSha256 'wrong-release-trust'
        & $module {
            param($p, $h, $r, $q, $expected)
            Assert-PersonalSigningPipelineR5CasBinding `
                -PlanInput $p -HeadInput $h -ReceiptInput $r `
                -Request $q -ExpectedR5HeadSha256 $expected
        } $planInput $headInput $badReceipt $request $headSha
    } `
    -Pattern 'PERSONAL_SIGNING_PIPELINE_R5_CLOSURE_INVALID' `
    -Message 'r5 release-manifest trust substitution is rejected.'

$r6R5ReceiptSha = Get-TestSha256 'personal-r6-cas-r5-receipt'
$r6IdentitySha = Get-TestSha256 'personal-r6-cas-identity'
$r6Recorded = ConvertTo-TestUtc ([DateTimeOffset]::UtcNow.AddMinutes(-1))
$r6R5Receipt = [pscustomobject]@{
    FileName = '0005-pilot-signed-candidate-imported.json'
    Sha256 = $r6R5ReceiptSha
    Value = [pscustomobject][ordered]@{
        schemaVersion = 2
        receiptType = 'ensou-dsh-launcher-production-release-transition'
        orchestrationId = $orchestrationId
        edition = 'Personal'
        targetChannel = 'pilot'
        planSha256 = $planSha
        identitySha256 = $r6IdentitySha
        revision = 5
        phase = 'PILOT_SIGNED_CANDIDATE_IMPORTED'
        recordedAtUtc = $recorded
    }
}
$r6HistoricalR5Head = [ordered]@{
    schemaVersion = 2
    stateType = 'ensou-dsh-launcher-production-release-head'
    orchestrationId = $orchestrationId
    edition = 'Personal'
    planSha256 = $planSha
    identitySha256 = $r6IdentitySha
    revision = 5
    phase = 'PILOT_SIGNED_CANDIDATE_IMPORTED'
    receiptFileName = '0005-pilot-signed-candidate-imported.json'
    receiptSha256 = $r6R5ReceiptSha
    updatedAtUtc = $recorded
    targetChannel = 'pilot'
}
$r6BaseHeadSha = ProductionReleaseState\Get-ProductionSha256Bytes `
    -Bytes (ProductionReleaseState\ConvertTo-ProductionJsonBytes `
        -Value $r6HistoricalR5Head)
$r6Request = [pscustomobject][ordered]@{
    orchestrationId = $orchestrationId
    channel = 'pilot'
    planSha256 = $planSha
    baseHeadSha256 = $r6BaseHeadSha
    source = [pscustomobject]@{ value = 'source' }
    payload = [pscustomobject]@{ value = 'payload' }
    compiledTrust = [pscustomobject]@{ value = 'compiled-trust' }
    toolchain = [pscustomobject]@{ value = 'toolchain' }
    buildExecution = [pscustomobject]@{ value = 'build-execution' }
    resourceBinding = [pscustomobject]@{ value = 'resource-binding' }
    trustedBuildEvidence = [pscustomobject]@{ value = 'trusted-evidence' }
    admission = [pscustomobject]@{ value = 'admission' }
    responseAuthentication = [pscustomobject]@{
        keyId = 'personal-response-key'
    }
}
$r6RequestInput = [pscustomobject]@{
    Sha256 = Get-TestSha256 'personal-r6-request'
    Value = $r6Request
}
$r6Bindings = Get-PersonalInstallerSigningRequestBindings -Request $r6Request
$r6ReceiptSha = Get-TestSha256 'personal-r6-cas-receipt'
$r6Receipt = [pscustomobject]@{
    FileName = '0006-installer-signing-requested.json'
    Sha256 = $r6ReceiptSha
    Value = [pscustomobject][ordered]@{
        schemaVersion = 2
        receiptType = 'ensou-dsh-launcher-production-release-transition'
        orchestrationId = $orchestrationId
        edition = 'Personal'
        targetChannel = 'pilot'
        planSha256 = $planSha
        identitySha256 = $r6IdentitySha
        revision = 6
        phase = 'INSTALLER_SIGNING_REQUESTED'
        previousReceiptSha256 = $r6R5ReceiptSha
        data = [pscustomobject][ordered]@{
            requestRelativePath =
                'requests/installer-signing.v2/installer-signing-request.v2.json'
            requestSha256 = [string]$r6RequestInput.Sha256
            baseHeadSha256 = $r6BaseHeadSha
            baseReceiptSha256 = $r6R5ReceiptSha
            sourceSha256 = [string]$r6Bindings.sourceSha256
            payloadSha256 = [string]$r6Bindings.payloadSha256
            compiledTrustSha256 = [string]$r6Bindings.compiledTrustSha256
            toolchainSha256 = [string]$r6Bindings.toolchainSha256
            buildExecutionSha256 = [string]$r6Bindings.buildExecutionSha256
            resourceBindingSha256 = [string]$r6Bindings.resourceBindingSha256
            trustedBuildEvidenceSha256 =
                [string]$r6Bindings.trustedBuildEvidenceSha256
            admissionSha256 = [string]$r6Bindings.admissionSha256
            authenticationKeyId = 'personal-response-key'
            authenticationPurpose = 'personal-installer-signing-response'
            authenticationPayloadType =
                'ensou-dsh-personal-installer-signing-response-authentication-v2'
            admissionReason = 'INSTALLER_SIGNING_RESPONSE_REQUIRED'
            productionAdmission = 'NO_GO'
        }
        recordedAtUtc = $r6Recorded
    }
}
$r6HistoricalHead = [ordered]@{
    schemaVersion = 2
    stateType = 'ensou-dsh-launcher-production-release-head'
    orchestrationId = $orchestrationId
    edition = 'Personal'
    planSha256 = $planSha
    identitySha256 = $r6IdentitySha
    revision = 6
    phase = 'INSTALLER_SIGNING_REQUESTED'
    receiptFileName = '0006-installer-signing-requested.json'
    receiptSha256 = $r6ReceiptSha
    updatedAtUtc = $r6Recorded
    targetChannel = 'pilot'
}
$r6HeadSha = ProductionReleaseState\Get-ProductionSha256Bytes `
    -Bytes (ProductionReleaseState\ConvertTo-ProductionJsonBytes `
        -Value $r6HistoricalHead)
Assert-True ([bool](& $module {
            param($requestValue, $receiptValue, $r5Value, $headShaValue)
            Assert-PersonalSigningPipelineR6CasBinding `
                -RequestInput $requestValue `
                -ReceiptInput $receiptValue `
                -R5ReceiptInput $r5Value `
                -ExpectedR6HeadSha256 $headShaValue
        } $r6RequestInput $r6Receipt $r6R5Receipt $r6HeadSha)) `
    'Exact r5 receipt, r6 request/receipt, and reconstructed r6 CAS head are accepted.'
foreach ($r6Mutation in @(
        [pscustomobject]@{
            Name = 'request hash'
            Apply = { param($value) $value.Value.data.requestSha256 =
                Get-TestSha256 'personal-r6-request-substitution' }
        },
        [pscustomobject]@{
            Name = 'previous receipt hash'
            Apply = { param($value) $value.Value.previousReceiptSha256 =
                Get-TestSha256 'personal-r6-previous-receipt-substitution' }
        })) {
    Assert-Fails `
        -Action {
            $badR6 = Copy-TestObject $r6Receipt
            & $r6Mutation.Apply $badR6
            & $module {
                param($requestValue, $receiptValue, $r5Value, $headShaValue)
                [void](Assert-PersonalSigningPipelineR6CasBinding `
                    -RequestInput $requestValue `
                    -ReceiptInput $receiptValue `
                    -R5ReceiptInput $r5Value `
                    -ExpectedR6HeadSha256 $headShaValue)
            } $r6RequestInput $badR6 $r6R5Receipt $r6HeadSha
        } `
        -Pattern 'PERSONAL_SIGNING_PIPELINE_R6_CAS_INVALID' `
        -Message "r6 $($r6Mutation.Name) substitution is rejected."
}
Assert-Fails `
    -Action {
        $staleR6HeadSha = Get-TestSha256 'stale-r6-head'
        & $module {
            param($requestValue, $receiptValue, $r5Value, $staleHeadValue)
            [void](Assert-PersonalSigningPipelineR6CasBinding `
                -RequestInput $requestValue `
                -ReceiptInput $receiptValue `
                -R5ReceiptInput $r5Value `
                -ExpectedR6HeadSha256 $staleHeadValue)
        } $r6RequestInput $r6Receipt $r6R5Receipt $staleR6HeadSha
    } `
    -Pattern 'PERSONAL_SIGNING_PIPELINE_R6_CAS_INVALID' `
    -Message 'Stale r6 CAS head is rejected.'

$now = [DateTimeOffset]::UtcNow
$windowRequest = [pscustomobject]@{
    createdAtUtc = ConvertTo-TestUtc $now.AddMinutes(-5)
    expiresAtUtc = ConvertTo-TestUtc $now.AddMinutes(10)
}
$windowResponse = [pscustomobject]@{
    completedAtUtc = ConvertTo-TestUtc $now.AddMinutes(-2)
    authenticode = [pscustomobject]@{
        timestampUtc = ConvertTo-TestUtc $now.AddMinutes(-4)
    }
    payloadSelfCheck = [pscustomobject]@{
        completedAtUtc = ConvertTo-TestUtc $now.AddMinutes(-3)
    }
}
Assert-True ([bool](& $module {
            param($requestValue, $responseValue)
            Assert-PersonalSigningPipelineResponseWindow `
                -Request $requestValue -Response $responseValue `
                -EnforceCurrentLifetime
        } $windowRequest $windowResponse)) `
    'Live response, RFC3161, and self-check ordering is accepted.'
Assert-Fails `
    -Action {
        $expiredRequest = Copy-TestObject $windowRequest
        $expiredRequest.createdAtUtc = ConvertTo-TestUtc $now.AddMinutes(-30)
        $expiredRequest.expiresAtUtc = ConvertTo-TestUtc $now.AddMinutes(-20)
        & $module {
            param($requestValue, $responseValue)
            Assert-PersonalSigningPipelineResponseWindow `
                -Request $requestValue -Response $responseValue `
                -EnforceCurrentLifetime
        } $expiredRequest $windowResponse
    } `
    -Pattern 'PERSONAL_SIGNING_PIPELINE_RESPONSE_LIFETIME_INVALID' `
    -Message 'Expired response window is rejected.'
Assert-Fails `
    -Action {
        $badResponse = Copy-TestObject $windowResponse
        $badResponse.authenticode.timestampUtc =
            ConvertTo-TestUtc $now.AddMinutes(-1)
        & $module {
            param($requestValue, $responseValue)
            Assert-PersonalSigningPipelineResponseWindow `
                -Request $requestValue -Response $responseValue
        } $windowRequest $badResponse
    } `
    -Pattern 'PERSONAL_SIGNING_PIPELINE_RESPONSE_LIFETIME_INVALID' `
    -Message 'RFC3161 timestamp after the response self-check is rejected.'

$responseSigner = [Security.Cryptography.ECDsa]::Create(
    [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
try {
    $public = $responseSigner.ExportParameters($false)
    $responseTrust = [pscustomobject][ordered]@{
        algorithm = 'ES256'
        keyId = 'personal-installer-response-key'
        purpose = 'personal-installer-signing-response'
        x = ConvertTo-TestBase64Url $public.Q.X
        y = ConvertTo-TestBase64Url $public.Q.Y
    }
    $authRequest = [pscustomobject]@{
        responseAuthentication = [pscustomobject]@{
            algorithm = 'ES256'
            keyId = [string]$responseTrust.keyId
            purpose = 'personal-installer-signing-response'
            payloadType =
                'ensou-dsh-personal-installer-signing-response-authentication-v2'
            trustSha256 =
                InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                    -Value $responseTrust
        }
    }
    $authResponse = [pscustomobject][ordered]@{
        schemaVersion = 2
        responseType = 'ensou-dsh-personal-installer-signing-response'
        completedAtUtc = ConvertTo-TestUtc $now
        authentication = [pscustomobject][ordered]@{
            algorithm = 'ES256'
            keyId = [string]$responseTrust.keyId
            purpose = 'personal-installer-signing-response'
            payloadType =
                'ensou-dsh-personal-installer-signing-response-authentication-v2'
            value = 'A' * 86
        }
    }
    [byte[]]$payload =
        Get-PersonalInstallerSigningResponseAuthenticationPayload `
            -Response $authResponse
    [byte[]]$signature = $responseSigner.SignData(
        $payload,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
    $signature = ConvertTo-TestLowS $signature
    $authResponse.authentication.value = ConvertTo-TestBase64Url $signature
    Assert-True ([bool](
            & $module {
                param($responseValue, $requestValue, $trustValue)
                Assert-PersonalInstallerSigningResponseAuthentication `
                    -Response $responseValue `
                    -Request $requestValue `
                    -InstallerSigningTrust $trustValue
            } $authResponse $authRequest $responseTrust)) `
        'Canonical low-S ES256 response authentication is accepted.'
    Assert-Fails `
        -Action {
            $tampered = Copy-TestObject $authResponse
            $tampered.completedAtUtc = ConvertTo-TestUtc $now.AddSeconds(1)
            & $module {
                param($responseValue, $requestValue, $trustValue)
                [void](Assert-PersonalInstallerSigningResponseAuthentication `
                    -Response $responseValue -Request $requestValue `
                    -InstallerSigningTrust $trustValue)
            } $tampered $authRequest $responseTrust
        } `
        -Pattern 'PERSONAL_SIGNING_PIPELINE_RESPONSE_AUTH_INVALID' `
        -Message 'Authenticated response body substitution is rejected.'
    Assert-Fails `
        -Action {
            $wrongTrustRequest = Copy-TestObject $authRequest
            $wrongTrustRequest.responseAuthentication.trustSha256 =
                Get-TestSha256 'wrong-installer-response-key'
            & $module {
                param($responseValue, $requestValue, $trustValue)
                [void](Assert-PersonalInstallerSigningResponseAuthentication `
                    -Response $responseValue -Request $requestValue `
                    -InstallerSigningTrust $trustValue)
            } $authResponse $wrongTrustRequest $responseTrust
        } `
        -Pattern 'PERSONAL_SIGNING_PIPELINE_RESPONSE_AUTH_INVALID' `
        -Message 'Response trust-key substitution is rejected before signature acceptance.'
}
finally {
    $responseSigner.Dispose()
}

$tempRoot = Join-Path `
    ([IO.Path]::GetTempPath()) `
    ('ensou-personal-signing-pipeline-test-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($tempRoot) | Out-Null
$heldSigned = $null
$heldNoncanonical = $null
try {
    $signedPath = Join-Path $tempRoot 'Ensou.Dsh.Personal.Installer.exe'
    [byte[]]$fakeSignedBytes = $script:Utf8.GetBytes(
        'fixture-only-not-an-executable-and-never-executed')
    [IO.File]::WriteAllBytes($signedPath, $fakeSignedBytes)
    $heldSigned = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $signedPath `
        -Label 'Focused fake signed identity' `
        -MaximumBytes 1MB
    $identityResponse = [pscustomobject]@{
        signedInstaller = [pscustomobject]@{
            fileName = 'Ensou.Dsh.Personal.Installer.exe'
            sizeBytes = [int64]$heldSigned.SizeBytes
            sha256 = [string]$heldSigned.Sha256
        }
    }
    Assert-True ([bool](& $module {
                param($inputValue, $responseValue)
                Assert-PersonalSigningPipelineSignedIdentity `
                    -SignedInstallerInput $inputValue -Response $responseValue
            } $heldSigned $identityResponse)) `
        'Held signed-file identity matches its authenticated descriptor.'
    Assert-Fails `
        -Action {
            $badIdentity = Copy-TestObject $identityResponse
            $badIdentity.signedInstaller.sha256 = Get-TestSha256 'swap-after-response'
            & $module {
                param($inputValue, $responseValue)
                Assert-PersonalSigningPipelineSignedIdentity `
                    -SignedInstallerInput $inputValue -Response $responseValue
            } $heldSigned $badIdentity
        } `
        -Pattern 'PERSONAL_SIGNING_PIPELINE_SIGNED_IDENTITY_INVALID' `
        -Message 'Signed-file byte substitution is rejected while the original is held.'

    $schemaPath = Join-Path $tempRoot 'simple.schema.json'
    $jsonPath = Join-Path $tempRoot 'noncanonical.json'
    [IO.File]::WriteAllText(
        $schemaPath,
        '{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","additionalProperties":false,"required":["a"],"properties":{"a":{"type":"integer"}}}',
        $script:Utf8)
    [IO.File]::WriteAllText($jsonPath, "{ `"a`": 1 }", $script:Utf8)
    $heldNoncanonical = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $jsonPath `
        -Label 'Focused noncanonical JSON' `
        -MaximumBytes 1MB
    Assert-Fails `
        -Action {
            & $module {
                param($descriptor, $schema)
                Read-PersonalSigningPipelineHeldJson `
                    -Descriptor $descriptor `
                    -SchemaPath $schema `
                    -Label 'Focused noncanonical JSON'
            } $heldNoncanonical $schemaPath
        } `
        -Pattern 'PERSONAL_SIGNING_PIPELINE_JSON_INVALID' `
        -Message 'Schema-valid but noncanonical request JSON is rejected.'
}
finally {
    if ($null -ne $heldNoncanonical) { $heldNoncanonical.Stream.Dispose() }
    if ($null -ne $heldSigned) { $heldSigned.Stream.Dispose() }
    [IO.Directory]::Delete($tempRoot, $true)
}

$source = Get-Content -LiteralPath $modulePath -Raw
$importOffset = $source.IndexOf(
    'function Import-PersonalInstallerSigningPipelineResponse',
    [StringComparison]::Ordinal)
Assert-True ($importOffset -ge 0) 'Import implementation is present.'
$importSource = $source.Substring($importOffset)
$responseContractOffset = $importSource.IndexOf(
    'Assert-PersonalInstallerSigningResponseV2Contract', [StringComparison]::Ordinal)
$heldIdentityOffset = $importSource.IndexOf(
    'Assert-PersonalSigningPipelineSignedIdentity', [StringComparison]::Ordinal)
$authenticodeOffset = $importSource.IndexOf(
    'Assert-SignedInstallerAuthenticode', [StringComparison]::Ordinal)
$selfCheckOffset = $importSource.IndexOf(
    'Invoke-PersonalInstallerProductionPayloadSelfCheck',
    [StringComparison]::Ordinal)
Assert-True ($responseContractOffset -ge 0 -and
    $responseContractOffset -lt $heldIdentityOffset) `
    'Response ES256/lifetime contract precedes held executable identity admission.'
Assert-True ($heldIdentityOffset -lt $authenticodeOffset) `
    'Held executable identity precedes Authenticode/RFC3161 admission.'
Assert-True ($authenticodeOffset -lt $selfCheckOffset) `
    'Pinned Authenticode/RFC3161 admission precedes Personal payload execution.'
Assert-True ($importSource -notmatch '(?i)Start-Process|Invoke-Expression') `
    'Import contains no alternate process execution primitive.'
Assert-True ($source -notmatch
    'PERSONAL_TRUSTED_BUILD_INPUT_SAFETY_NOT_CLOSED') `
    'Closed trusted-build safety blocker is removed from the pipeline.'
Assert-True ($source -notmatch
    'PERSONAL_BUILDER_UNSIGNED_ASSEMBLY_LOAD_SAFETY_NOT_CLOSED') `
    'Closed unsigned assembly-load dependency is removed.'
Assert-True ($source -notmatch
    'PERSONAL_BUILDER_RESOURCE_BINDING_TOCTOU_NOT_CLOSED') `
    'Closed source TOCTOU dependency is removed.'
Assert-True ($source -match
    'VALIDATED_PERSONAL_PILOT_EXTERNAL_SIGNER_ELIGIBLE') `
    'Pipeline carries explicit Personal Pilot request eligibility.'
Assert-True ($source -match
    'PERSONAL_INSTALLER_SIGNING_RESPONSE_REQUIRED_NO_GO') `
    'Pipeline emits explicit NO_GO while a genuine response is absent.'
Assert-True ($source -match 'FORBIDDEN_AND_NOT_PERFORMED') `
    'Pipeline carries explicit unsigned zero-execution evidence.'

"PASS Test-PersonalInstallerSigningPipeline assertions=$script:Assertions sharedRequestV2Compatible=$($capability.IsCompatible) personalChannel=PILOT_ONLY blocker=INSTALLER_SIGNING_RESPONSE_REQUIRED signedFixture=ABSENT productionAdmission=NO_GO"
