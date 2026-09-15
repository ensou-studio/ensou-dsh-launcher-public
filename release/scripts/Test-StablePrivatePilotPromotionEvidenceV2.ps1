#requires -Version 7.2

[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$schemaPath = Join-Path $RepositoryRoot `
    'release\schemas\launcher-enterprise-stable-private-pilot-promotion-evidence-v2.schema.json'
$fixturePath = Join-Path $RepositoryRoot `
    'release\fixtures\stable-private-pilot-promotion-v2\synthetic.no-go.json'
$canonicalManifestUri =
    'https://updates.ensou.example/v2/channels/stable/release-set.v2.json'
$capabilityProbeSha256 =
    '5216e34e0a76cc1c20a8d23dd24ea69a2186c58c3044c20b5f912a4e13bcf005'
$capabilityProbeSize = 651

function Copy-TestValue([Parameter(Mandatory = $true)][psobject]$Value) {
    return $Value | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100
}

function Test-EvidenceSchema([Parameter(Mandatory = $true)][psobject]$Value) {
    try {
        return [bool](Test-Json `
            -Json ($Value | ConvertTo-Json -Depth 100 -Compress) `
            -SchemaFile $schemaPath `
            -ErrorAction Stop)
    }
    catch {
        return $false
    }
}

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Assert-Equal {
    param(
        [AllowNull()][object]$Actual,
        [AllowNull()][object]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ([string]$Actual -cne [string]$Expected) {
        throw "$Label differs from its exact binding."
    }
}

function ConvertTo-WholeSecondUtc {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $text = if ($Value -is [DateTime]) {
        ([DateTime]$Value).ToUniversalTime().ToString(
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            [Globalization.CultureInfo]::InvariantCulture)
    }
    else {
        [string]$Value
    }
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            $text,
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor
                [Globalization.DateTimeStyles]::AdjustToUniversal,
            [ref]$parsed)) {
        throw "$Label is not canonical whole-second UTC."
    }
    return $parsed
}

function Get-ObjectKey([Parameter(Mandatory = $true)][psobject]$Value) {
    return [string]$Value.role
}

function Assert-ExactObjectSet {
    param(
        [Parameter(Mandatory = $true)][object[]]$Actual,
        [Parameter(Mandatory = $true)][object[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )
    Assert-True ($Actual.Count -eq $Expected.Count) "$Label count differs."
    $actualRoles = @($Actual | ForEach-Object { Get-ObjectKey $_ })
    Assert-True (($actualRoles | Select-Object -Unique).Count -eq $actualRoles.Count) `
        "$Label contains duplicate roles."
    foreach ($expectedObject in $Expected) {
        $matches = @($Actual | Where-Object {
            [string]$_.role -ceq [string]$expectedObject.role
        })
        Assert-True ($matches.Count -eq 1) `
            "$Label lacks one exact $($expectedObject.role) object."
        $actualObject = $matches[0]
        foreach ($name in @(
                'role',
                'fileName',
                'uri',
                'objectVersionId',
                'etag',
                'sizeBytes',
                'sha256')) {
            Assert-Equal $actualObject.$name $expectedObject.$name `
                "$Label $($expectedObject.role) $name"
        }
    }
}

function Assert-InstallerIdentity {
    param(
        [Parameter(Mandatory = $true)][psobject]$Actual,
        [Parameter(Mandatory = $true)][psobject]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )
    foreach ($name in @(
            'fileName',
            'relativePath',
            'sizeBytes',
            'sha256',
            'peContentSha256',
            'immutableInstallerIdentitySha256')) {
        Assert-Equal $Actual.$name $Expected.$name "$Label $name"
    }
}

function Assert-EvidenceSemantics(
    [Parameter(Mandatory = $true)][psobject]$Evidence) {
    Assert-Equal $Evidence.canonicalStableManifestUri $canonicalManifestUri `
        'root canonical Stable URI'
    Assert-True `
        ([string]$Evidence.sourceBaseline.releaseSetId -cne
            [string]$Evidence.targetRelease.releaseSetId) `
        'Source and target release-set IDs must be distinct.'
    Assert-True `
        ([long]$Evidence.sourceBaseline.sequence -lt
            [long]$Evidence.targetRelease.sequence) `
        'Target sequence must advance the signed source baseline.'
    Assert-InstallerIdentity `
        $Evidence.r7.signedInstaller `
        $Evidence.targetRelease.signedInstaller `
        'r7 exact signed Installer'
    Assert-Equal $Evidence.sourceBaseline.manifest.uri $canonicalManifestUri `
        'source manifest canonical URI'
    Assert-Equal $Evidence.targetRelease.manifest.uri $canonicalManifestUri `
        'target manifest canonical URI'

    $probe = $Evidence.sourceBaseline.capabilityProbe
    Assert-Equal $probe.stdoutSha256 $capabilityProbeSha256 `
        'baseline capability probe SHA-256'
    Assert-True ([long]$probe.stdoutSizeBytes -eq $capabilityProbeSize) `
        'Baseline capability probe byte size differs.'
    Assert-Equal `
        $probe.parsed.sideEffectContract `
        'no-secrets-no-network-no-mutation' `
        'baseline capability side-effect contract'

    $devices = @($Evidence.privatePilot.devices)
    Assert-True ($devices.Count -eq 2) 'Exactly two Windows devices are required.'
    $deviceIds = @($devices | ForEach-Object { [string]$_.deviceIdentitySha256 })
    $installIds = @($devices | ForEach-Object { [string]$_.installationId })
    $machineIds = @($devices | ForEach-Object { [string]$_.machineIdentitySha256 })
    $inventoryIds = @($devices | ForEach-Object { [string]$_.inventorySha256 })
    foreach ($identitySet in @($deviceIds, $installIds, $machineIds, $inventoryIds)) {
        Assert-True (@($identitySet | Select-Object -Unique).Count -eq 2) `
            'Pilot Windows device inventories are not distinct.'
    }
    $lanes = @($devices | ForEach-Object { [string]$_.lane })
    Assert-True `
        (@($lanes | Where-Object { $_ -ceq 'fresh-install' }).Count -eq 1 -and
            @($lanes | Where-Object { $_ -ceq 'online-upgrade' }).Count -eq 1) `
        'Private Pilot must contain one fresh-install and one online-upgrade lane.'
    $allowlist = @($Evidence.privatePilot.allowlist.authorizedDeviceIdentitySha256)
    Assert-True ($allowlist.Count -eq 2) 'Allowlist must contain exactly two identities.'
    foreach ($deviceId in $deviceIds) {
        Assert-True ($allowlist -ccontains $deviceId) `
            'Device inventory does not close the exact allowlist.'
    }
    $activeFrom = ConvertTo-WholeSecondUtc `
        $Evidence.privatePilot.allowlist.activeFromUtc `
        'allowlist activeFromUtc'
    $activeUntil = ConvertTo-WholeSecondUtc `
        $Evidence.privatePilot.allowlist.activeUntilUtc `
        'allowlist activeUntilUtc'
    Assert-True ($activeFrom -lt $activeUntil) 'Allowlist window is inverted.'

    $fresh = @($devices | Where-Object { $_.lane -ceq 'fresh-install' })[0]
    $upgrade = @($devices | Where-Object { $_.lane -ceq 'online-upgrade' })[0]
    Assert-True ($null -eq $fresh.sourceReleaseSetId) `
        'Fresh-install lane cannot claim a source release.'
    Assert-Equal `
        $upgrade.sourceReleaseSetId `
        $Evidence.sourceBaseline.releaseSetId `
        'online-upgrade source release-set'
    Assert-Equal `
        $upgrade.sourceCapabilityProbeSha256 `
        $probe.stdoutSha256 `
        'online-upgrade baseline capability probe'
    Assert-Equal `
        $Evidence.sourceBaseline.installedDeviceIdentitySha256 `
        $upgrade.deviceIdentitySha256 `
        'installed source baseline device'
    Assert-InstallerIdentity `
        $fresh.installerUsed `
        $Evidence.r7.signedInstaller `
        'fresh-install exact signed Installer'
    Assert-True ($null -eq $upgrade.installerUsed) `
        'Online-upgrade lane cannot claim a fresh Installer.'
    Assert-Equal `
        $upgrade.updateReceipt.sourceReleaseSetId `
        $Evidence.sourceBaseline.releaseSetId `
        'online-upgrade receipt source release-set'

    $targetObjects = @($Evidence.targetRelease.manifest) +
        @($Evidence.targetRelease.artifacts)
    foreach ($device in $devices) {
        Assert-Equal $device.canonicalManifestUri $canonicalManifestUri `
            "$($device.lane) canonical Stable URI"
        Assert-Equal $device.targetReleaseSetId $Evidence.targetRelease.releaseSetId `
            "$($device.lane) target release-set"
        Assert-Equal `
            $device.bootstrapperHealth.targetReleaseSetId `
            $Evidence.targetRelease.releaseSetId `
            "$($device.lane) Bootstrapper health target"
        Assert-Equal `
            $device.updateReceipt.targetReleaseSetId `
            $Evidence.targetRelease.releaseSetId `
            "$($device.lane) update receipt target"
        $healthCompleted = ConvertTo-WholeSecondUtc `
            $device.bootstrapperHealth.completedAtUtc `
            "$($device.lane) Bootstrapper health completion"
        $receiptCompleted = ConvertTo-WholeSecondUtc `
            $device.updateReceipt.completedAtUtc `
            "$($device.lane) update receipt completion"
        Assert-True `
            ($healthCompleted -ge $activeFrom -and
                $healthCompleted -le $activeUntil -and
                $receiptCompleted -ge $healthCompleted -and
                $receiptCompleted -le $activeUntil) `
            "$($device.lane) completion is outside the allowlist window or out of order."
        Assert-ExactObjectSet @($device.observedObjects) $targetObjects `
            "$($device.lane) observed target bytes"
    }

    $control = $Evidence.privatePilot.unauthorizedControl
    Assert-True ($deviceIds -cnotcontains [string]$control.deviceIdentitySha256) `
        'Unauthorized control identity aliases an allowlisted device.'
    Assert-Equal $control.canonicalManifestUri $canonicalManifestUri `
        'unauthorized control canonical Stable URI'
    Assert-Equal $control.observedReleaseSetId $Evidence.sourceBaseline.releaseSetId `
        'unauthorized prior public release-set'
    Assert-Equal $control.observedManifestSha256 $Evidence.sourceBaseline.manifest.sha256 `
        'unauthorized prior public manifest'
    foreach ($observation in @($control.observations)) {
        Assert-Equal $observation.releaseSetId $Evidence.sourceBaseline.releaseSetId `
            'unauthorized observation release-set'
        Assert-Equal $observation.manifestSha256 $Evidence.sourceBaseline.manifest.sha256 `
            'unauthorized observation manifest'
    }
    $controlBefore = ConvertTo-WholeSecondUtc `
        $control.observations[0].observedAtUtc `
        'unauthorized before observation'
    $controlAfter = ConvertTo-WholeSecondUtc `
        $control.observations[1].observedAtUtc `
        'unauthorized after observation'
    $deviceReceiptTimes = @($devices | ForEach-Object {
        ConvertTo-WholeSecondUtc $_.updateReceipt.completedAtUtc `
            "$($_.lane) receipt chronology"
    })
    Assert-True `
        ($controlBefore -ge $activeFrom -and
            $controlBefore -lt ($deviceReceiptTimes | Measure-Object -Minimum).Minimum -and
            $controlAfter -gt ($deviceReceiptTimes | Measure-Object -Maximum).Maximum -and
            $controlAfter -le $activeUntil) `
        'Unauthorized control does not bracket the private Pilot run.'

    $promotion = $Evidence.publicPromotion
    Assert-Equal $promotion.canonicalManifestUri $canonicalManifestUri `
        'public promotion canonical Stable URI'
    Assert-Equal `
        $promotion.publicHeadBefore.releaseSetId `
        $Evidence.sourceBaseline.releaseSetId `
        'public head before release-set'
    Assert-Equal `
        $promotion.publicHeadBefore.manifestSha256 `
        $Evidence.sourceBaseline.manifest.sha256 `
        'public head before manifest'
    Assert-Equal `
        $promotion.publicHeadBefore.etag `
        $Evidence.sourceBaseline.manifest.etag `
        'public head before ETag'
    Assert-Equal `
        $promotion.publicHeadAfter.releaseSetId `
        $Evidence.targetRelease.releaseSetId `
        'public head after release-set'
    Assert-Equal `
        $promotion.publicHeadAfter.manifestSha256 `
        $Evidence.targetRelease.manifest.sha256 `
        'public head after manifest'
    Assert-Equal `
        $promotion.publicHeadAfter.etag `
        $Evidence.targetRelease.manifest.etag `
        'public head after ETag'
    Assert-ExactObjectSet @($promotion.promotedObjects) $targetObjects `
        'private-to-public exact promoted bytes'

    Assert-True (@($Evidence.attestations.devices).Count -eq 2) `
        'Exactly two device attestation envelopes are required.'
    if ($Evidence.evidenceMode -ceq 'synthetic-fixture') {
        foreach ($name in $Evidence.verificationStatus.PSObject.Properties.Name) {
            Assert-Equal $Evidence.verificationStatus.$name 'PENDING' `
                "synthetic $name status"
        }
        Assert-Equal $Evidence.productionAdmission 'NO_GO' `
            'synthetic production admission'
    }
}

function Assert-ContractAccepts {
    param(
        [Parameter(Mandatory = $true)][psobject]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )
    Assert-True (Test-EvidenceSchema $Value) "$Label failed strict schema validation."
    Assert-EvidenceSemantics $Value
}

function Assert-SchemaRejects {
    param(
        [Parameter(Mandatory = $true)][psobject]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )
    Assert-True (-not (Test-EvidenceSchema $Value)) `
        "$Label was accepted by the strict schema."
}

function Assert-SemanticsRejects {
    param(
        [Parameter(Mandatory = $true)][psobject]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )
    Assert-True (Test-EvidenceSchema $Value) `
        "$Label unexpectedly failed structure before semantic validation."
    $rejected = $false
    try {
        Assert-EvidenceSemantics $Value
    }
    catch {
        $rejected = $true
    }
    Assert-True $rejected "$Label was accepted by semantic validation."
}

$raw = Get-Content -Raw -LiteralPath $fixturePath
$fixture = $raw | ConvertFrom-Json -Depth 100
Assert-ContractAccepts $fixture 'Synthetic NO-GO foundation fixture'

$case = Copy-TestValue $fixture
$case.targetRelease.releaseSetId = $case.sourceBaseline.releaseSetId
Assert-SemanticsRejects $case 'Same source and target release-set'

$case = Copy-TestValue $fixture
$case.privatePilot.devices[1].deviceIdentitySha256 =
    $case.privatePilot.devices[0].deviceIdentitySha256
Assert-SemanticsRejects $case 'Duplicate Windows device identity'

$case = Copy-TestValue $fixture
$case.privatePilot.devices[1].inventorySha256 =
    $case.privatePilot.devices[0].inventorySha256
Assert-SemanticsRejects $case 'Duplicate Windows inventory identity'

$case = Copy-TestValue $fixture
$case.privatePilot.devices[1].lane = 'fresh-install'
$case.privatePilot.devices[1].sourceReleaseSetId = $null
$case.privatePilot.devices[1].sourceCapabilityProbeSha256 = $null
$case.privatePilot.devices[1].previousInstallAbsent = $true
$case.privatePilot.devices[1].installerUsed =
    Copy-TestValue $case.r7.signedInstaller
$case.privatePilot.devices[1].updateReceipt.sourceReleaseSetId = $null
Assert-SemanticsRejects $case 'Two fresh-install lanes'

$case = Copy-TestValue $fixture
$case.sourceBaseline.PSObject.Properties.Remove('capabilityProbe')
Assert-SchemaRejects $case 'Missing signed baseline capability probe'

$case = Copy-TestValue $fixture
$case.sourceBaseline.capabilityProbe.sideEffects.networkRequests = 1
Assert-SchemaRejects $case 'Capability probe network side effect'

$case = Copy-TestValue $fixture
$case.sourceBaseline.capabilityProbe.arguments += 'unexpected'
Assert-SchemaRejects $case 'Capability probe extra argument accepted'

$case = Copy-TestValue $fixture
$case.sourceBaseline.capabilityProbe.stdoutSha256 = 'f' * 64
Assert-SemanticsRejects $case 'Wrong capability probe hash'

$case = Copy-TestValue $fixture
$case.privatePilot.devices[1].sameVersionNoOp = $true
Assert-SchemaRejects $case 'Online-upgrade same-version no-op'

$case = Copy-TestValue $fixture
$case.privatePilot.devices[0].installerUsed.sha256 = 'f' * 64
Assert-SemanticsRejects $case 'Fresh-install signed Installer mismatch'

$case = Copy-TestValue $fixture
$case.privatePilot.devices[1].updateReceipt.sourceReleaseSetId = 'other-stable'
Assert-SemanticsRejects $case 'Online-upgrade receipt source mismatch'

$case = Copy-TestValue $fixture
$case.privatePilot.devices[0].bootstrapperHealth.completed = $false
Assert-SchemaRejects $case 'Missing target Bootstrapper health completion'

$case = Copy-TestValue $fixture
$case.privatePilot.devices[1].updateReceipt.completed = $false
Assert-SchemaRejects $case 'Missing target update receipt completion'

$case = Copy-TestValue $fixture
$case.privatePilot.unauthorizedControl.deviceIdentitySha256 =
    $case.privatePilot.devices[0].deviceIdentitySha256
Assert-SemanticsRejects $case 'Unauthorized control aliases allowlisted device'

$case = Copy-TestValue $fixture
$case.privatePilot.unauthorizedControl.observedReleaseSetId =
    $case.targetRelease.releaseSetId
Assert-SemanticsRejects $case 'Unauthorized control sees target release'

$case = Copy-TestValue $fixture
$case.privatePilot.unauthorizedControl.candidateBytesDisclosed = $true
Assert-SchemaRejects $case 'Candidate bytes leak to third identity'

$case = Copy-TestValue $fixture
$case.publicPromotion.promotedObjects[0].sha256 = 'e' * 64
Assert-SemanticsRejects $case 'Public promotion changed target manifest bytes'

$case = Copy-TestValue $fixture
$case.privatePilot.devices[0].observedObjects[2].objectVersionId = 'other-version'
Assert-SemanticsRejects $case 'Pilot device observed different target object version'

$case = Copy-TestValue $fixture
$case.r7.signedInstaller.sha256 = 'd' * 64
Assert-SemanticsRejects $case 'r7 signed Installer mismatch'

$case = Copy-TestValue $fixture
$case.targetRelease.manifest.etag = 'W/"weak-etag"'
Assert-SchemaRejects $case 'Weak target ETag'

$case = Copy-TestValue $fixture
$case.canonicalStableManifestUri =
    'https://updates.ensou.example/v2/channels/pilot/release-set.v2.json'
Assert-SchemaRejects $case 'Cross-channel Pilot URI'

$case = Copy-TestValue $fixture
$case.sourceBaseline.launcherBinary | Add-Member -NotePropertyName unknown -NotePropertyValue $true
Assert-SchemaRejects $case 'Unknown baseline field'

$case = Copy-TestValue $fixture
$case.verificationStatus.authenticode = 'VERIFIED'
Assert-SchemaRejects $case 'Synthetic fixture claims verified Authenticode'

$case = Copy-TestValue $fixture
$case.productionAdmission = 'GO'
Assert-SchemaRejects $case 'Synthetic fixture claims production GO'

$case = Copy-TestValue $fixture
$case.privatePilot.allowlist.activeUntilUtc = '2026-08-30T23:59:59Z'
Assert-SemanticsRejects $case 'Inverted allowlist window'

$case = Copy-TestValue $fixture
$case.privatePilot.devices[1].updateReceipt.completedAtUtc = '2026-08-31T06:00:01Z'
Assert-SemanticsRejects $case 'Device receipt outside allowlist window'

$case = Copy-TestValue $fixture
$case.privatePilot.unauthorizedControl.observations[1].observedAtUtc =
    '2026-08-31T02:30:00Z'
Assert-SemanticsRejects $case 'Unauthorized control does not bracket Pilot'

$case = Copy-TestValue $fixture
$case.sourceBaseline.authenticode.verificationStatus = 'VERIFIED'
$case.sourceBaseline.authenticode.status = 'Valid'
Assert-SchemaRejects $case 'Synthetic baseline claims verified Authenticode'

$case = Copy-TestValue $fixture
$case.attestations.devices[0].verificationStatus = 'VERIFIED'
Assert-SchemaRejects $case 'Synthetic device attestation claims verified'

Write-Output 'STABLE-PRIVATE-PILOT-PROMOTION-EVIDENCE-V2-PASS'
