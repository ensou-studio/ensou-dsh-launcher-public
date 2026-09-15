#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$adapterPath = Join-Path `
    $PSScriptRoot `
    'New-EnterpriseProductionPilotEvidenceInput.ps1'
$stateSchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\launcher-production-release-state-v2.schema.json'
$planSchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\launcher-production-release-plan-v2.schema.json'
$outputSchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\enterprise-production-pilot-evidence-input-v1.schema.json'
$trustSchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\enterprise-production-pilot-evidence-trust-v1.schema.json'
$verificationReportSchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\enterprise-windows-pilot-verification-report-v2.schema.json'
$pilotEvidenceModulePath = Join-Path `
    $PSScriptRoot `
    'EnterpriseProductionPilotEvidence.psm1'
$tempParent = [IO.Path]::TrimEndingDirectorySeparator(
    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()))
$tempRoot = Join-Path `
    $tempParent `
    ('ensou-r8-adapter-' + [Guid]::NewGuid().ToString('N'))

function Assert-R8Test {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $adapterPath,
    [ref]$tokens,
    [ref]$parseErrors)
Assert-R8Test `
    (@($parseErrors).Count -eq 0) `
    ('r8 adapter has PowerShell parse errors: ' +
     (@($parseErrors | ForEach-Object Message) -join '; '))

$parameterNames = @($ast.ParamBlock.Parameters | ForEach-Object {
    $_.Name.VariablePath.UserPath
})
foreach ($requiredParameter in @(
        'StateRoot',
        'ExpectedR7HeadSha256',
        'WindowsPilotReadinessSchemaVersion')) {
    Assert-R8Test `
        ($parameterNames -ccontains $requiredParameter) `
        "r8 adapter is missing mandatory state binding '$requiredParameter'."
}

$schemaVersionParameter = @($ast.ParamBlock.Parameters | Where-Object {
    $_.Name.VariablePath.UserPath -ceq 'WindowsPilotReadinessSchemaVersion'
})
Assert-R8Test `
    ($schemaVersionParameter.Count -eq 1 -and
     [string]$schemaVersionParameter[0].DefaultValue.Extent.Text -ceq '1') `
    'Readiness schema selector does not preserve the v1 default.'
$schemaVersionAttributes = @(
    $schemaVersionParameter[0].Attributes |
        ForEach-Object { [string]$_.Extent.Text }) -join ''
Assert-R8Test `
    (($schemaVersionAttributes -replace '\s', '').Contains(
        'ValidateSet(1,2)',
        [StringComparison]::Ordinal)) `
    'Readiness schema selector is not restricted to v1/v2.'
foreach ($removedParameter in @(
        'ProductionPlanPath',
        'R7HeadPath',
        'R7ReceiptPath',
        'SignedInstallerPath',
        'ExpectedPilotTrustPolicySha256')) {
    Assert-R8Test `
        ($parameterNames -cnotcontains $removedParameter) `
        "r8 adapter still trusts caller-selected '$removedParameter'."
}

$adapterText = [IO.File]::ReadAllText($adapterPath)
foreach ($requiredText in @(
        'Enter-ProductionReleaseStateReadLock',
        'Get-ProductionReleaseState',
        'launcher-production-release-state-v2.schema.json',
        'launcher-production-release-plan-v2.schema.json',
        '@($state.Receipts).Count -ne 7',
        '$null -ne $state.OrphanReceipt',
        'ExpectedR7HeadSha256',
        '0007-installer-signature-imported.json',
        'Read-ProductionReleaseInputBytes',
        'Get-PeContentSha256',
        'R7_INSTALLER_BYTES_MISMATCH',
        'R7_TRUSTED_BUILD_SOURCE_MISSING',
        'R7_PRODUCTION_ADMISSION_REASON_REJECTED',
        'INSTALLER_SIGNING_RESPONSE_REQUIRED',
        'ELIGIBLE_FOR_PILOT_SIGNING',
        'Assert-InstallerSigningResponseContract',
        'Assert-SignedInstallerAuthenticode',
        'Assert-EnterpriseProductionPilotEvidence',
        'enterprise-pilot-readiness-v$WindowsPilotReadinessSchemaVersion.schema.json',
        'enterprise-pilot-readiness-report-v$WindowsPilotReadinessSchemaVersion.schema.json',
        '-WindowsPilotReadinessSchemaVersion',
        'plan.pilotEvidenceTrustPolicySha256',
        'R8_TRUST_POLICY_PLAN_ANCHOR_MISMATCH',
        'planAnchor = [ordered]@{',
        'Open-CertifiedDistributionLockedDirectory',
        'Assert-CertifiedDistributionLockedDirectoryUnchanged',
        'RequireOrdinarySingleLink',
        'R8_OUTPUT_PATH_INVALID',
        'Write-R8CreateNewOutput',
        'windowsBodyInput.Value.completedAtUtc',
        'PILOT_EVIDENCE_INPUT_READY_NO_GO',
        'nextRequiredGate = ''PILOT_EVIDENCE_BOUND''')) {
    Assert-R8Test `
        $adapterText.Contains($requiredText, [StringComparison]::Ordinal) `
        "r8 fail-closed foundation is missing '$requiredText'."
}
foreach ($forbiddenText in @(
        'ExpectedPilotTrustPolicySha256',
        'SDK_FILE_CLOSURE_EXTERNAL_HOST_PREREQUISITE',
        'EXTERNAL_HOST_PREREQUISITE_NOT_SNAPSHOTTED',
        'PublishedOutputCreatedAtUtc',
        'BindPilotEvidence',
        'productionAdmission = ''GO''',
        'productionAdmission = ''ADMITTED''')) {
    Assert-R8Test `
        (-not $adapterText.Contains(
            $forbiddenText,
            [StringComparison]::Ordinal)) `
        "r8 fail-closed foundation contains forbidden success path '$forbiddenText'."
}

$stateSchema = Get-Content -Raw -LiteralPath $stateSchemaPath |
    ConvertFrom-Json -Depth 64
$r7DataSchema = $stateSchema.definitions.installerSignatureImportData
$r7Admission = $r7DataSchema.properties.productionAdmission.PSObject.Properties['const'].Value
Assert-R8Test `
    ([string]$r7Admission -ceq 'NO_GO') `
    'r7 must remain NO_GO while r8 binds Pilot evidence.'
Assert-R8Test `
    ([string]$r7DataSchema.properties.admissionReason.PSObject.Properties['const'].Value -ceq `
        'INSTALLER_SIGNING_RESPONSE_REQUIRED') `
    'r7 must expose the one allowed pre-Pilot NO_GO reason.'

$planSchema = Get-Content -Raw -LiteralPath $planSchemaPath |
    ConvertFrom-Json -Depth 64
$planTrustAnchor =
    $planSchema.properties.PSObject.Properties[
        'pilotEvidenceTrustPolicySha256']
Assert-R8Test `
    ($null -ne $planTrustAnchor) `
    'Plan v2 is missing the Pilot evidence trust-policy SHA-256 property.'
$editionConditions = @(foreach ($condition in $planSchema.allOf) {
    $ifMember = $condition.PSObject.Properties['if']
    if ($null -eq $ifMember) { continue }
    $propertiesMember = $ifMember.Value.PSObject.Properties['properties']
    if ($null -eq $propertiesMember) { continue }
    $editionMember = $propertiesMember.Value.PSObject.Properties['edition']
    if ($null -eq $editionMember) { continue }
    $constMember = $editionMember.Value.PSObject.Properties['const']
    if ($null -ne $constMember -and [string]$constMember.Value -ceq 'Personal') {
        $condition
    }
})
Assert-R8Test `
    ($editionConditions.Count -eq 1) `
    'Plan v2 must have exactly one Personal/Enterprise edition conditional.'
$enterpriseBranch = $editionConditions[0].PSObject.Properties['else']
Assert-R8Test `
    ($null -ne $enterpriseBranch) `
    'Plan v2 edition conditional is missing its Enterprise branch.'
Assert-R8Test `
    (@($enterpriseBranch.Value.required) -ccontains
        'pilotEvidenceTrustPolicySha256') `
    'Enterprise plan v2 does not require its Pilot trust-policy anchor before r1.'
$sha256Fixture = 'a' * 64
$coordinateFixture = 'A' * 43
$inputFixture = [ordered]@{
    fileName = 'fixture.bin'
    path = 'C:\fixtures\fixture.bin'
    sizeBytes = 1
    sha256 = $sha256Fixture
}
$trustFixture = {
    param([string]$KeyId, [string]$Purpose)
    return [ordered]@{
        algorithm = 'ES256'
        keyId = $KeyId
        purpose = $Purpose
        x = $coordinateFixture
        y = $coordinateFixture
    }
}
$planFixture = [ordered]@{
    schemaVersion = 2
    planType = 'ensou-dsh-launcher-production-release'
    orchestrationId = '11111111-1111-4111-8111-111111111111'
    edition = 'Enterprise'
    releaseSetId = 'enterprise-r8-plan-anchor-fixture'
    targetChannel = 'stable'
    sourceCommit = 'b' * 40
    manifestUri =
        'https://updates.ensou.example/v2/channels/stable/release-set.v2.json'
    artifactBaseUri = 'https://artifacts.ensou.example/launcher/'
    pilotEvidenceTrustPolicySha256 = 'c' * 64
    runtimeCandidate = [ordered]@{
        releaseId = 'dsh-v0.1.2-rc.1'
        githubReleaseTag = 'dsh-v0.1.2-rc.1'
        archive = $inputFixture
        metadata = $inputFixture
        hashEvidence = $inputFixture
    }
    authenticodePolicy = [ordered]@{
        signerSha256Thumbprint = $sha256Fixture
        requireTrustedTimestamp = $true
        maximumResponseAgeMinutes = 60
    }
    releaseManifestTrust =
        & $trustFixture 'r8-release-manifest' 'release-manifest-signing'
    releaseCompatibility = [ordered]@{ startupStubProtocol = 1 }
    externalResponseTrusts = [ordered]@{
        clientSigning =
            & $trustFixture 'r8-client-signing' 'client-signing-response'
        manifestPublishing =
            & $trustFixture 'r8-manifest-publishing' 'manifest-publishing-response'
        installerSigning =
            & $trustFixture 'r8-installer-signing' 'installer-signing-response'
        feedPromotion =
            & $trustFixture 'r8-feed-promotion' 'feed-promotion-response'
    }
    clientSigningInputs = @(
        @('bootstrapper', 'Ensou.Dsh.Enterprise.Bootstrapper.exe'),
        @('launcher', 'Ensou.Dsh.Enterprise.Launcher.exe'),
        @('client-bootstrapper',
            'Ensou.Dsh.Enterprise.ClientBootstrapper.exe'),
        @('maintenance', 'Ensou.Dsh.Enterprise.Maintenance.exe') |
            ForEach-Object {
                [ordered]@{
                    role = [string]$_[0]
                    fileName = [string]$_[1]
                    path = 'C:\fixtures\' + [string]$_[1]
                    sizeBytes = 1
                    sha256 = $sha256Fixture
                    peContentSha256 = $sha256Fixture
                }
            })
}
$planFixtureJson = $planFixture | ConvertTo-Json -Depth 64 -Compress
Assert-R8Test `
    (Test-Json `
        -Json $planFixtureJson `
        -SchemaFile $planSchemaPath `
        -ErrorAction Stop) `
    'Enterprise plan v2 anchor fixture did not satisfy its schema.'
$missingAnchorPlan = $planFixtureJson |
    ConvertFrom-Json -Depth 64 -DateKind String
$missingAnchorPlan.PSObject.Properties.Remove(
    'pilotEvidenceTrustPolicySha256')
Assert-R8Test `
    (-not (Test-Json `
        -Json ($missingAnchorPlan | ConvertTo-Json -Depth 64 -Compress) `
        -SchemaFile $planSchemaPath `
        -ErrorAction SilentlyContinue)) `
    'Enterprise plan v2 schema accepted a missing Pilot trust-policy anchor.'
$uppercaseAnchorPlan = $planFixtureJson |
    ConvertFrom-Json -Depth 64 -DateKind String
$uppercaseAnchorPlan.pilotEvidenceTrustPolicySha256 = 'C' * 64
Assert-R8Test `
    (-not (Test-Json `
        -Json ($uppercaseAnchorPlan | ConvertTo-Json -Depth 64 -Compress) `
        -SchemaFile $planSchemaPath `
        -ErrorAction SilentlyContinue)) `
    'Enterprise plan v2 schema accepted a non-lowercase trust-policy anchor.'

$outputSchema = Get-Content -Raw -LiteralPath $outputSchemaPath |
    ConvertFrom-Json -Depth 64
Assert-R8Test `
    (@($outputSchema.required) -ccontains 'planAnchor') `
    'r8 output schema does not require the authoritative plan anchor.'
Assert-R8Test `
    ((@($outputSchema.properties.planAnchor.required) -join ',') -ceq
        'planSha256,pilotEvidenceTrustPolicySha256') `
    'r8 output schema plan anchor member set drifted.'

$trustSchema = Get-Content -Raw -LiteralPath $trustSchemaPath |
    ConvertFrom-Json -Depth 64
Assert-R8Test `
    (@($trustSchema.required) -ccontains 'windowsPilotVerifier') `
    'r8 trust schema does not require the independent Windows verifier key.'
Assert-R8Test `
    ([string]$trustSchema.properties.windowsPilotVerifier.allOf[1].properties.purpose.const -ceq
        'enterprise-windows-pilot-verifier-report') `
    'r8 Windows verifier trust key is not purpose-separated.'

$verificationReportSchema =
    Get-Content -Raw -LiteralPath $verificationReportSchemaPath |
    ConvertFrom-Json -Depth 64
Assert-R8Test `
    (@($verificationReportSchema.required) -ccontains 'authentication') `
    'Windows Pilot verification report schema does not require authentication.'
Assert-R8Test `
    ([string]$verificationReportSchema.properties.authentication.properties.purpose.const -ceq
        'enterprise-windows-pilot-verifier-report') `
    'Windows Pilot verification report authentication purpose drifted.'

$pilotEvidenceModuleText = [IO.File]::ReadAllText($pilotEvidenceModulePath)
$windowsEvidenceFunctionIndex = $pilotEvidenceModuleText.IndexOf(
    'function Assert-R8WindowsEvidence',
    [StringComparison]::Ordinal)
$reportAuthenticationIndex = $pilotEvidenceModuleText.IndexOf(
    'Assert-R8WindowsVerificationReportAuthentication',
    $windowsEvidenceFunctionIndex,
    [StringComparison]::Ordinal)
$reportDecisionIndex = $pilotEvidenceModuleText.IndexOf(
    '$VerificationReport.decision',
    $windowsEvidenceFunctionIndex,
    [StringComparison]::Ordinal)
Assert-R8Test `
    ($windowsEvidenceFunctionIndex -ge 0 -and
     $reportAuthenticationIndex -gt $windowsEvidenceFunctionIndex -and
     $reportDecisionIndex -gt $reportAuthenticationIndex) `
    'r8 trusts Windows verifier report claims before authenticating the report.'

function New-R8ReadinessContractFixture {
    param([Parameter(Mandatory = $true)][ValidateSet(1, 2)][int]$Version)

    $config = if ($Version -eq 1) {
        [pscustomobject][ordered]@{
            schemaVersion = 1
            launcherTrust = [pscustomobject][ordered]@{
                gatewayOrigin = 'https://gateway.ensou.example/'
            }
        }
    }
    else {
        [pscustomobject][ordered]@{
            schemaVersion = 2
            launcherDirectLocalTrust = [pscustomobject][ordered]@{
                runtimeProfile = 'enterprise-direct-local'
                apiProvider = 'deepseek'
            }
        }
    }
    $newReport = {
        $report = [pscustomobject][ordered]@{
            schemaVersion = $Version
            reportType = 'ensou-dsh-enterprise-pilot-readiness'
            updateContractId =
                'release-set-v2-startup-check-atomic-health-rollback-offline-7d-plugin-policy-v1'
        }
        if ($Version -eq 2) {
            $report | Add-Member `
                -NotePropertyName productionTrustContractId `
                -NotePropertyValue 'ensou-dsh-enterprise-production-trust-v2'
            $report | Add-Member `
                -NotePropertyName runtimeProfile `
                -NotePropertyValue 'enterprise-direct-local'
            $report | Add-Member `
                -NotePropertyName apiProvider `
                -NotePropertyValue 'deepseek'
        }
        return $report
    }
    return [pscustomobject]@{
        Config = $config
        Stored = & $newReport
        Replayed = & $newReport
    }
}

function Copy-R8ReadinessContractFixture {
    param([Parameter(Mandatory = $true)]$Fixture)

    return ($Fixture | ConvertTo-Json -Depth 16 -Compress |
        ConvertFrom-Json -Depth 16 -DateKind String)
}

function Invoke-R8ReadinessSchemaContractFixture {
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)]$Fixture,
        [ValidateSet(1, 2)][int]$Version = 1,
        [switch]$UseDefault
    )

    & $Module {
        param($Value, [int]$ExpectedVersion, [bool]$DefaultVersion)
        if ($DefaultVersion) {
            Assert-R8ReadinessSchemaContract `
                -Config $Value.Config `
                -StoredReport $Value.Stored `
                -ReplayedReport $Value.Replayed
        }
        else {
            Assert-R8ReadinessSchemaContract `
                -WindowsPilotReadinessSchemaVersion $ExpectedVersion `
                -Config $Value.Config `
                -StoredReport $Value.Stored `
                -ReplayedReport $Value.Replayed
        }
    } $Fixture $Version $UseDefault.IsPresent
}

$pilotEvidenceModule = Microsoft.PowerShell.Core\Import-Module `
    -Name $pilotEvidenceModulePath -Force -PassThru -ErrorAction Stop
try {
    $v1Fixture = New-R8ReadinessContractFixture -Version 1
    $v2Fixture = New-R8ReadinessContractFixture -Version 2
    Invoke-R8ReadinessSchemaContractFixture `
        -Module $pilotEvidenceModule -Fixture $v1Fixture -UseDefault
    Invoke-R8ReadinessSchemaContractFixture `
        -Module $pilotEvidenceModule -Fixture $v2Fixture -Version 2

    $v2WithLegacyTrust = Copy-R8ReadinessContractFixture $v2Fixture
    $v2WithLegacyTrust.Config | Add-Member `
        -NotePropertyName launcherTrust `
        -NotePropertyValue ([pscustomobject]@{
            gatewayOrigin = 'https://gateway.ensou.example/'
        })
    $v2WithGateway = Copy-R8ReadinessContractFixture $v2Fixture
    $v2WithGateway.Config.launcherDirectLocalTrust | Add-Member `
        -NotePropertyName gatewayOrigin `
        -NotePropertyValue 'https://gateway.ensou.example/'
    $v1WithDirectReport = Copy-R8ReadinessContractFixture $v1Fixture
    $v1WithDirectReport.Stored | Add-Member `
        -NotePropertyName runtimeProfile `
        -NotePropertyValue 'enterprise-direct-local'
    $v2WrongProfile = Copy-R8ReadinessContractFixture $v2Fixture
    $v2WrongProfile.Replayed.runtimeProfile = 'enterprise-managed'
    $v2WrongProvider = Copy-R8ReadinessContractFixture $v2Fixture
    $v2WrongProvider.Config.launcherDirectLocalTrust.apiProvider = 'other'
    $v2WrongContract = Copy-R8ReadinessContractFixture $v2Fixture
    $v2WrongContract.Stored.productionTrustContractId =
        'ensou-dsh-enterprise-production-trust-v1'

    foreach ($case in @(
            [pscustomobject]@{
                Name = 'default v1 with v2 evidence'
                Fixture = $v2Fixture
                Version = 1
                UseDefault = $true
            },
            [pscustomobject]@{
                Name = 'explicit v2 with v1 evidence'
                Fixture = $v1Fixture
                Version = 2
                UseDefault = $false
            },
            [pscustomobject]@{
                Name = 'v2 config with v1 stored report'
                Fixture = [pscustomobject]@{
                    Config = $v2Fixture.Config
                    Stored = $v1Fixture.Stored
                    Replayed = $v2Fixture.Replayed
                }
                Version = 2
                UseDefault = $false
            },
            [pscustomobject]@{
                Name = 'v2 config with v1 replayed report'
                Fixture = [pscustomobject]@{
                    Config = $v2Fixture.Config
                    Stored = $v2Fixture.Stored
                    Replayed = $v1Fixture.Replayed
                }
                Version = 2
                UseDefault = $false
            },
            [pscustomobject]@{
                Name = 'v2 with legacy trust member'
                Fixture = $v2WithLegacyTrust
                Version = 2
                UseDefault = $false
            },
            [pscustomobject]@{
                Name = 'v2 with gateway origin'
                Fixture = $v2WithGateway
                Version = 2
                UseDefault = $false
            },
            [pscustomobject]@{
                Name = 'v1 with direct report member'
                Fixture = $v1WithDirectReport
                Version = 1
                UseDefault = $false
            },
            [pscustomobject]@{
                Name = 'v2 with wrong runtime profile'
                Fixture = $v2WrongProfile
                Version = 2
                UseDefault = $false
            },
            [pscustomobject]@{
                Name = 'v2 with wrong API provider'
                Fixture = $v2WrongProvider
                Version = 2
                UseDefault = $false
            },
            [pscustomobject]@{
                Name = 'v2 with wrong trust contract'
                Fixture = $v2WrongContract
                Version = 2
                UseDefault = $false
            })) {
        $rejected = $false
        try {
            Invoke-R8ReadinessSchemaContractFixture `
                -Module $pilotEvidenceModule `
                -Fixture $case.Fixture `
                -Version $case.Version `
                -UseDefault:$case.UseDefault
        }
        catch {
            $rejected = $_.Exception.Message.StartsWith(
                'R8_READINESS_',
                [StringComparison]::Ordinal)
        }
        Assert-R8Test $rejected `
            "Readiness schema contract accepted $($case.Name)."
    }
}
finally {
    Microsoft.PowerShell.Core\Remove-Module `
        -ModuleInfo $pilotEvidenceModule -Force -ErrorAction SilentlyContinue
}
Write-Output 'PASS readiness schema v1 default, explicit v2, and mixed-evidence rejection matrix.'

& (Join-Path $PSScriptRoot `
    'Test-EnterpriseProductionPilotEvidenceCryptography.ps1')

try {
    [IO.Directory]::CreateDirectory($tempRoot) | Out-Null
    $stateRoot = Join-Path $tempRoot 'state'
    $outsideRoot = Join-Path $tempRoot 'outside'
    [IO.Directory]::CreateDirectory($stateRoot) | Out-Null
    [IO.Directory]::CreateDirectory($outsideRoot) | Out-Null
    [IO.File]::WriteAllBytes(
        (Join-Path $stateRoot 'state.lock'),
        [Text.UTF8Encoding]::new($false).GetBytes('r8-lock'))
    $outputPath = Join-Path $outsideRoot 'must-not-exist.json'
    $dummyPath = Join-Path $outsideRoot 'caller-self-attested.json'
    $adapterArguments = @{
        StateRoot = $stateRoot
        ExpectedR7HeadSha256 = '1' * 64
        WindowsPilotEvidenceEnvelopePath = $dummyPath
        WindowsPilotEvidenceBodyPath = $dummyPath
        WindowsPilotVerificationReportPath = $dummyPath
        WindowsPilotReadinessConfigPath = $dummyPath
        WindowsPilotStoredReadinessReportPath = $dummyPath
        WindowsPilotReplayedReadinessReportPath = $dummyPath
        LocalDataCertificationReceiptPath = $dummyPath
        StablePrivatePilotObservationPath = $dummyPath
        PilotTrustPolicyPath = $dummyPath
        OutputPath = $outputPath
    }
    [IO.File]::WriteAllBytes(
        $outputPath,
        [Text.UTF8Encoding]::new($false).GetBytes('{"stale":true}'))
    $existingRejected = $false
    try {
        & $adapterPath @adapterArguments
    }
    catch {
        $existingRejected = $_.Exception.Message.Contains(
            'R8_OUTPUT_ALREADY_EXISTS',
            [StringComparison]::Ordinal)
    }
    Assert-R8Test `
        $existingRejected `
        'A pre-existing r8 output was not rejected with create-new semantics.'
    Remove-Item -LiteralPath $outputPath -Force

    $rejected = $false
    try {
        & $adapterPath @adapterArguments
    }
    catch {
        $rejected = $true
    }
    Assert-R8Test `
        $rejected `
        'A caller-built incomplete r7 state was not rejected.'
    Assert-R8Test `
        (-not (Test-Path -LiteralPath $outputPath)) `
        'A rejected r8 invocation created an output file.'

    $insideStateArguments = @{} + $adapterArguments
    $insideStateArguments.OutputPath = Join-Path `
        $stateRoot `
        'must-never-be-written.json'
    $insideStateRejected = $false
    try {
        & $adapterPath @insideStateArguments
    }
    catch {
        $insideStateRejected = $_.Exception.Message.Contains(
            'R8_OUTPUT_PATH_INVALID',
            [StringComparison]::Ordinal)
    }
    Assert-R8Test `
        $insideStateRejected `
        'r8 accepted an output path inside the immutable state root.'

    if ($IsWindows) {
        $junctionPath = Join-Path $outsideRoot 'state-junction'
        New-Item `
            -ItemType Junction `
            -Path $junctionPath `
            -Target $stateRoot | Out-Null
        try {
            $junctionArguments = @{} + $adapterArguments
            $junctionArguments.OutputPath = Join-Path `
                $junctionPath `
                'junction-output.json'
            $junctionRejected = $false
            try {
                & $adapterPath @junctionArguments
            }
            catch {
                $junctionRejected = $_.Exception.Message.Contains(
                    'R8_OUTPUT_PATH_INVALID',
                    [StringComparison]::Ordinal)
            }
            Assert-R8Test `
                $junctionRejected `
                'r8 accepted an output path through a junction into the state root.'
            Assert-R8Test `
                (-not (Test-Path -LiteralPath `
                    (Join-Path $stateRoot 'junction-output.json'))) `
                'A rejected junction output created bytes inside the state root.'
        }
        finally {
            if (Test-Path -LiteralPath $junctionPath) {
                [IO.Directory]::Delete($junctionPath, $false)
            }
        }
    }
}
finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}

Write-Output 'ENTERPRISE-PRODUCTION-PILOT-EVIDENCE-ADAPTER-PASS'
