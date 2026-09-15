#requires -Version 7.2

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$path = Join-Path $repositoryRoot 'release\examples\personal-pilot-release-plan.example.json'
$schemaPath = Join-Path $repositoryRoot 'release\schemas\launcher-production-release-plan-v2.schema.json'
$lockPath = Join-Path $repositoryRoot 'versions\locked.json'
$planJson = Get-Content -LiteralPath $path -Raw
$plan = $planJson | ConvertFrom-Json
$lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
$adapterPath = Join-Path $repositoryRoot `
    'release\scripts\PersonalProductionReleaseAdapter.psm1'
Import-Module $adapterPath -Force

function Assert-True([bool]$condition, [string]$message) {
    if (-not $condition) { throw $message }
}

function Assert-SchemaRejects($candidate, [string]$message) {
    $json = $candidate | ConvertTo-Json -Depth 30 -Compress
    try {
        $valid = Test-Json -Json $json -SchemaFile $schemaPath -ErrorAction Stop
    } catch {
        $valid = $false
    }
    Assert-True (-not $valid) $message
}

Assert-True (Test-Json -Json $planJson -SchemaFile $schemaPath -ErrorAction Stop) `
    'Personal Pilot example must satisfy the production release-plan schema.'

Assert-True ([int]$plan.schemaVersion -eq 2) 'Personal example plan schemaVersion must be 2.'
Assert-True ([string]$plan.edition -ceq 'Personal') 'Personal example plan edition mismatch.'
Assert-True ([string]$plan.targetChannel -ceq 'pilot') 'Personal example plan must target pilot.'
Assert-True ([string]$plan.personalPilotTemplateStatus -ceq 'NO_GO_TEMPLATE_PENDING_REAL_DEVICE_EVIDENCE') 'Personal plan example must be visibly NO_GO until real-device evidence exists.'
Assert-True ([string]$plan.sourceCommit -ceq ('0' * 40)) 'Personal example sourceCommit must be an obvious non-production placeholder.'
Assert-True ([string]$plan.sourceCommit -cne [string]$lock.officialCommit) 'Personal plan sourceCommit must not be confused with the upstream Harness commit.'
Assert-True ([string]$plan.releaseCompatibility.startupStubVersion -ceq '1.2.0') 'Fresh Personal Pilot installations require Startup Stub 1.2.0 for atomic home-writer coordination.'
$retiredFreshStubPlan = $plan | ConvertTo-Json -Depth 30 | ConvertFrom-Json
$retiredFreshStubPlan.releaseCompatibility.startupStubVersion = '1.1.0'
Assert-SchemaRejects $retiredFreshStubPlan 'Schema must reject Startup Stub 1.1.0 for fresh Personal Pilot releases; historical replay is a separate contract.'
Assert-True ([string]$plan.manifestUri -ceq 'https://updates.dsh.example.invalid/v2/channels/pilot/release-set.v2.json') 'Personal manifest origin mismatch.'
Assert-True ([string]$plan.artifactBaseUri -ceq 'https://updates.dsh.example.invalid/') 'Personal artifact origin mismatch.'
Assert-True (([Uri]$plan.manifestUri).Host -ceq ([Uri]$plan.artifactBaseUri).Host) 'Personal machine-update manifest and artifacts must stay under the Ensou update authority.'
Assert-True ([string]$plan.manifestUri -notmatch 'example\\.|example$|invalid|localhost|127\\.') 'Personal manifest must not use a placeholder origin.'
Assert-True ([string]$plan.artifactBaseUri -notmatch 'example\\.|example$|invalid|localhost|127\\.') 'Personal artifact origin must not use a placeholder origin.'
Assert-True ([string]$plan.personalAccountOrigin -ceq 'https://accounts.example.invalid/') `
    'Personal account origin example must remain illustrative and is not a chosen production endpoint.'
$missingAccountOrigin = $plan | ConvertTo-Json -Depth 30 | ConvertFrom-Json
$missingAccountOrigin.PSObject.Properties.Remove('personalAccountOrigin')
Assert-SchemaRejects $missingAccountOrigin `
    'Schema must reject a Personal plan without an account origin.'
$nonCanonicalAccountOrigin = $plan | ConvertTo-Json -Depth 30 | ConvertFrom-Json
$nonCanonicalAccountOrigin.personalAccountOrigin = 'https://accounts.example.invalid:443/'
Assert-SchemaRejects $nonCanonicalAccountOrigin `
    'Schema must reject a noncanonical Personal account origin.'
Assert-True (@($plan.personalPilotDevices).Count -eq 2) 'Personal Pilot requires exactly two Windows devices.'
Assert-True ((@($plan.personalPilotDevices | ForEach-Object deviceId) -join ',') -ceq 'pilot-desktop-desktop,pilot-notebook') 'Personal Pilot device lanes are not canonical.'
$sharedChecks = @('startup-update-detection','runtime-only-update','launcher-only-update','failed-update-rollback','offline-last-known-good','local-chat-and-workspace-unchanged','no-command-window')
$expectedDevices = @(
    [pscustomobject]@{ DeviceId = 'pilot-desktop-desktop'; HostLabel = 'PILOT-DESKTOP'; Lane = 'existing-install-upgrade'; RoleAcceptance = 'existing-version-upgrade' },
    [pscustomobject]@{ DeviceId = 'pilot-notebook'; HostLabel = 'PilotNotebook notebook'; Lane = 'clean-first-install'; RoleAcceptance = 'first-install' }
)
for ($index = 0; $index -lt $expectedDevices.Count; $index++) {
    $device = $plan.personalPilotDevices[$index]
    $expected = $expectedDevices[$index]
    Assert-True ([string]$device.deviceId -ceq [string]$expected.DeviceId) "Personal Pilot device $index ID mismatch."
    Assert-True ([string]$device.hostLabel -ceq [string]$expected.HostLabel) "Personal Pilot device $($device.deviceId) host mismatch."
    Assert-True ([string]$device.architecture -ceq 'win-x64') "Personal Pilot device $($device.deviceId) must be Windows x64."
    Assert-True ([string]$device.lane -ceq [string]$expected.Lane) "Personal Pilot device $($device.deviceId) lane mismatch."
    Assert-True ([string]$device.installationIdentity -ceq 'separate-device-identity') "Personal Pilot device $($device.deviceId) must be independent."
    Assert-True ([bool]$device.tokenOrSecretIncluded -eq $false) "Personal Pilot device $($device.deviceId) must not contain a token or secret."
    Assert-True ([string]$device.roleAcceptance -ceq [string]$expected.RoleAcceptance) "Personal Pilot device $($device.deviceId) has the wrong role-only check."
    Assert-True ((@($device.perDeviceAcceptance) -join ',') -ceq ($sharedChecks -join ',')) "Personal Pilot device $($device.deviceId) must run the exact seven shared checks."
}
Assert-True ([string]$plan.runtimeCandidate.githubReleaseTag -ceq [string]$plan.runtimeCandidate.releaseId) 'Runtime GitHub candidate tag must equal the reserved managed releaseId used by the orchestrator.'
$runtimeBase = "EnsouDshRuntime-$($plan.runtimeCandidate.releaseId)-win-x64.zip"
Assert-True ([string]$plan.runtimeCandidate.archive.fileName -ceq $runtimeBase) 'Runtime candidate archive name is not the source-runtime input contract.'
Assert-True ([string]$plan.runtimeCandidate.metadata.fileName -ceq ($runtimeBase -replace '[.]zip$', '.metadata.json')) 'Runtime candidate metadata name is not canonical.'
Assert-True ([string]$plan.runtimeCandidate.hashEvidence.fileName -ceq ($runtimeBase + '.sha256')) 'Runtime candidate hash-evidence name is not canonical.'
foreach ($descriptor in @($plan.runtimeCandidate.archive, $plan.runtimeCandidate.metadata, $plan.runtimeCandidate.hashEvidence)) {
    Assert-True ([string]$descriptor.sha256 -ceq ('0' * 64)) 'Template runtime descriptor unexpectedly claims production evidence.'
}
$templateRejected = $false
try {
    PersonalProductionReleaseAdapter\Assert-PersonalProductionReleasePlan `
        -Plan $plan
}
catch {
    $templateRejected = $_.ToString() -match 'NO-GO.*template'
}
Assert-True $templateRejected `
    'Personal production adapter accepted the explicit NO_GO plan template.'
$historicalV1Plan = [pscustomobject]@{
    schemaVersion = 1
    edition = 'Personal'
}
$v1MutationRejected = $false
try {
    PersonalProductionReleaseAdapter\Assert-PersonalProductionReleasePlan `
        -Plan $historicalV1Plan
}
catch {
    $v1MutationRejected = $_.ToString() -match
        'historical Status replay only'
}
Assert-True $v1MutationRejected `
    'Personal production adapter admitted plan v1 without the explicit historical Status-only mode.'
PersonalProductionReleaseAdapter\Assert-PersonalProductionReleasePlan `
    -Plan $historicalV1Plan `
    -AllowHistoricalV1Status
Assert-True $true `
    'Personal production adapter rejected an explicit historical v1 Status replay.'
$missingLane = $plan | ConvertTo-Json -Depth 30 | ConvertFrom-Json
$missingLane.personalPilotDevices[1].lane = 'existing-install-upgrade'
Assert-SchemaRejects $missingLane 'Schema must reject two Personal devices without both required lanes.'
$wrongRole = $plan | ConvertTo-Json -Depth 30 | ConvertFrom-Json
$wrongRole.personalPilotDevices[0].roleAcceptance = 'first-install'
Assert-SchemaRejects $wrongRole 'Schema must reject a role check on the wrong Personal device lane.'
$missingSharedCheck = $plan | ConvertTo-Json -Depth 30 | ConvertFrom-Json
$missingSharedCheck.personalPilotDevices[1].perDeviceAcceptance = @($sharedChecks | Select-Object -First 6)
Assert-SchemaRejects $missingSharedCheck 'Schema must reject a device missing one of the seven shared checks.'
$personalWithEnterpriseField = $plan | ConvertTo-Json -Depth 30 | ConvertFrom-Json
$personalWithEnterpriseField | Add-Member -NotePropertyName pilotEvidenceTrustPolicySha256 -NotePropertyValue ('0' * 64)
Assert-SchemaRejects $personalWithEnterpriseField 'Schema must reject enterprise-only pilot evidence policy on Personal plans.'
$enterpriseWithPersonalFields = $plan | ConvertTo-Json -Depth 30 | ConvertFrom-Json
$enterpriseWithPersonalFields.edition = 'Enterprise'
$enterpriseWithPersonalFields.targetChannel = 'stable'
$enterpriseWithPersonalFields.releaseCompatibility = [pscustomobject]@{ startupStubProtocol = 1 }
$enterpriseWithPersonalFields.externalResponseTrusts.installerSigning.purpose = 'installer-signing-response'
$enterpriseWithPersonalFields | Add-Member -NotePropertyName pilotEvidenceTrustPolicySha256 -NotePropertyValue ('0' * 64)
Assert-SchemaRejects $enterpriseWithPersonalFields 'Schema must reject Personal device fields on Enterprise plans.'
$enterpriseWithAccountOrigin = $plan | ConvertTo-Json -Depth 30 | ConvertFrom-Json
$enterpriseWithAccountOrigin.edition = 'Enterprise'
$enterpriseWithAccountOrigin.targetChannel = 'stable'
$enterpriseWithAccountOrigin.releaseCompatibility = [pscustomobject]@{ startupStubProtocol = 1 }
$enterpriseWithAccountOrigin.externalResponseTrusts.installerSigning.purpose = 'installer-signing-response'
$enterpriseWithAccountOrigin | Add-Member -NotePropertyName pilotEvidenceTrustPolicySha256 -NotePropertyValue ('0' * 64)
$enterpriseWithAccountOrigin.PSObject.Properties.Remove('personalPilotDevices')
$enterpriseWithAccountOrigin.PSObject.Properties.Remove('personalPilotTemplateStatus')
Assert-SchemaRejects $enterpriseWithAccountOrigin `
    'Schema must reject a Personal account origin on an Enterprise plan.'
Assert-True (@($plan.clientSigningInputs).Count -eq 4) 'Personal example plan must contain four client signing inputs.'
Assert-True ((@($plan.clientSigningInputs) | ForEach-Object role) -join ',' -ceq 'startup-stub,client-bootstrapper,launcher,maintenance') 'Personal signing roles are not canonical.'

Write-Output 'PERSONAL-PILOT-RELEASE-PLAN-EXAMPLE-PASS'
