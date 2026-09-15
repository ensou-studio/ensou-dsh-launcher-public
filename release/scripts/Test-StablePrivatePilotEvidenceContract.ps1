#requires -Version 7.2

[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$schemaPath = Join-Path $RepositoryRoot `
    'release\schemas\launcher-stable-private-pilot-evidence-v1.schema.json'
$canonicalManifestUri =
    'https://updates.ensou.example/v2/channels/stable/release-set.v2.json'

function New-TestSha256([int]$Value) {
    return $Value.ToString('x64', [Globalization.CultureInfo]::InvariantCulture)
}

function Copy-TestValue([Parameter(Mandatory = $true)][psobject]$Value) {
    return $Value |
        ConvertTo-Json -Depth 64 |
        ConvertFrom-Json -Depth 64
}

function Test-EvidenceSchema([Parameter(Mandatory = $true)][psobject]$Value) {
    $json = $Value | ConvertTo-Json -Depth 64 -Compress
    try {
        return [bool](Test-Json `
            -Json $json `
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

    if ($Actual -is [string] -or $Expected -is [string]) {
        if ([string]$Actual -cne [string]$Expected) {
            throw "$Label differs from its exact binding."
        }
        return
    }
    if ($Actual -ne $Expected) {
        throw "$Label differs from its exact binding."
    }
}

function ConvertTo-WholeSecondUtc {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            $Value,
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal,
            [ref]$parsed)) {
        throw "$Label is not canonical whole-second UTC."
    }
    return $parsed.ToUniversalTime()
}

function Assert-CanonicalStableUri {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Assert-Equal -Actual $Value -Expected $Expected -Label $Label
    $uri = [Uri]::new($Value, [UriKind]::Absolute)
    if ($uri.Scheme -cne 'https' -or
        $uri.UserInfo -or
        $uri.Query -or
        $uri.Fragment -or
        $uri.AbsolutePath -cne '/v2/channels/stable/release-set.v2.json' -or
        $uri.AbsoluteUri -cne $Value) {
        throw "$Label is not the exact canonical Stable manifest URI."
    }
}

function Assert-Bindings {
    param(
        [Parameter(Mandatory = $true)][psobject]$Observed,
        [Parameter(Mandatory = $true)][psobject]$Evidence,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Assert-Equal $Observed.releaseSetId $Evidence.releaseSetId "$Label releaseSetId"
    Assert-Equal $Observed.manifestSha256 $Evidence.bindings.manifest.sha256 `
        "$Label manifest SHA-256"
    Assert-Equal $Observed.candidateSetSha256 $Evidence.bindings.candidateSetSha256 `
        "$Label candidate-set SHA-256"
    Assert-Equal $Observed.payloadSetSha256 $Evidence.bindings.payloadSetSha256 `
        "$Label payload-set SHA-256"
    Assert-Equal `
        $Observed.releaseTrustProbeSha256 `
        $Evidence.bindings.releaseTrustProbeSha256 `
        "$Label release-trust probe SHA-256"
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

function Assert-FetchMatchesObject {
    param(
        [Parameter(Mandatory = $true)][psobject]$Fetch,
        [Parameter(Mandatory = $true)][psobject]$Object,
        [Parameter(Mandatory = $true)][string]$DeviceIdentitySha256,
        [Parameter(Mandatory = $true)][string]$Lane,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Assert-Equal $Fetch.deviceIdentitySha256 $DeviceIdentitySha256 `
        "$Label device identity"
    Assert-Equal $Fetch.lane $Lane "$Label lane"
    foreach ($name in @(
        'role', 'uri', 'objectVersionId', 'etag', 'sizeBytes', 'sha256')) {
        Assert-Equal $Fetch.$name $Object.$name "$Label $name"
    }
}

function Assert-StablePrivatePilotEvidenceSemantics {
    param([Parameter(Mandatory = $true)][psobject]$Evidence)

    $expectedProduct = if ($Evidence.edition -ceq 'Personal') {
        'ensou-dsh-personal'
    }
    else {
        'ensou-dsh-enterprise'
    }
    $expectedInstallerName = if ($Evidence.edition -ceq 'Personal') {
        'Ensou.Dsh.Personal.Installer.exe'
    }
    else {
        'Ensou.Dsh.Enterprise.Installer.exe'
    }
    $expectedCandidateRoles = if ($Evidence.edition -ceq 'Personal') {
        @('client-bundle', 'runtime')
    }
    else {
        @('release-public-key', 'launcher', 'runtime', 'plugin-policy')
    }

    Assert-Equal $Evidence.product $expectedProduct 'Product/edition binding'
    Assert-Equal $Evidence.targetChannel 'stable' 'Target channel'
    Assert-Equal $Evidence.r7.installer.fileName $expectedInstallerName `
        'r7 Installer file name'
    Assert-True `
        -Condition $Evidence.r7.installer.relativePath.EndsWith(
            '/' + $expectedInstallerName,
            [StringComparison]::Ordinal) `
        -Message 'r7 Installer path does not name the edition Installer.'
    Assert-CanonicalStableUri `
        $Evidence.canonicalStableManifestUri `
        $canonicalManifestUri `
        'Root canonical Stable manifest URI'

    $manifestObject = $Evidence.server.objects.manifestObject
    Assert-Equal $manifestObject.role 'release-manifest' 'Server manifest role'
    Assert-Equal $manifestObject.fileName 'release-set.v2.json' `
        'Server manifest file name'
    Assert-CanonicalStableUri `
        $manifestObject.uri `
        $canonicalManifestUri `
        'Server manifest object URI'
    Assert-Equal $manifestObject.sizeBytes $Evidence.bindings.manifest.sizeBytes `
        'Server manifest size'
    Assert-Equal $manifestObject.sha256 $Evidence.bindings.manifest.sha256 `
        'Server manifest SHA-256'

    $candidateObjects = @($Evidence.server.objects.candidateObjects)
    Assert-Equal $candidateObjects.Count $expectedCandidateRoles.Count `
        'Candidate object count'
    $candidateByRole = @{}
    for ($index = 0; $index -lt $expectedCandidateRoles.Count; $index++) {
        $candidate = $candidateObjects[$index]
        Assert-Equal $candidate.role $expectedCandidateRoles[$index] `
            "Candidate role index $index"
        if ($candidateByRole.ContainsKey([string]$candidate.role)) {
            throw "Candidate role '$($candidate.role)' is duplicated."
        }
        $candidateByRole[[string]$candidate.role] = $candidate
    }

    $installerObject = $Evidence.server.objects.installerObject
    Assert-Equal $installerObject.role 'installer' 'Server Installer role'
    Assert-Equal $installerObject.fileName $expectedInstallerName `
        'Server Installer file name'
    Assert-Equal $installerObject.sizeBytes $Evidence.r7.installer.sizeBytes `
        'Server/r7 Installer size'
    Assert-Equal $installerObject.sha256 $Evidence.r7.installer.sha256 `
        'Server/r7 Installer SHA-256'

    $fresh = $Evidence.devices.freshInstall
    $upgrade = $Evidence.devices.onlineUpgrade
    $freshId = [string]$fresh.device.deviceIdentitySha256
    $upgradeId = [string]$upgrade.device.deviceIdentitySha256
    if ($freshId -ceq $upgradeId) {
        throw 'Fresh-install and online-upgrade evidence use the same device identity.'
    }
    Assert-InstallerIdentity $fresh.installer $Evidence.r7.installer `
        'Fresh-install exact Installer'
    Assert-CanonicalStableUri `
        $fresh.canonicalManifestUri `
        $canonicalManifestUri `
        'Fresh-install manifest URI'
    Assert-CanonicalStableUri `
        $upgrade.canonicalManifestUri `
        $canonicalManifestUri `
        'Online-upgrade manifest URI'
    Assert-Bindings $fresh.observedBindings $Evidence 'Fresh-install observed'
    Assert-Bindings $upgrade.observedBindings $Evidence 'Online-upgrade observed'

    if ($upgrade.priorStable.releaseSetId -ceq $Evidence.releaseSetId -or
        $upgrade.priorStable.manifestSha256 -ceq $Evidence.bindings.manifest.sha256 -or
        [int64]$upgrade.priorStable.sequence -ge [int64]$upgrade.candidateSequence) {
        throw 'Online-upgrade lane is a same-version/no-op or non-forward transition.'
    }
    Assert-Equal `
        $upgrade.rollback.restoredReleaseSetId `
        $upgrade.priorStable.releaseSetId `
        'Rollback restored release'
    Assert-Equal `
        $upgrade.recovery.activeReleaseSetId `
        $Evidence.releaseSetId `
        'Recovery active release'

    $allowlistIds = @($Evidence.server.allowlist.authorizedDeviceIdentitySha256)
    Assert-Equal $allowlistIds.Count 2 'Allowlist identity count'
    $expectedAllowlistIds = @($freshId, $upgradeId) | Sort-Object -CaseSensitive
    $actualAllowlistIds = $allowlistIds | Sort-Object -CaseSensitive
    for ($index = 0; $index -lt 2; $index++) {
        Assert-Equal $actualAllowlistIds[$index] $expectedAllowlistIds[$index] `
            "Allowlist device index $index"
    }

    $allowFrom = ConvertTo-WholeSecondUtc `
        $Evidence.server.allowlist.activeFromUtc 'Allowlist start'
    $allowUntil = ConvertTo-WholeSecondUtc `
        $Evidence.server.allowlist.activeUntilUtc 'Allowlist end'
    $freshStart = ConvertTo-WholeSecondUtc $fresh.device.startedAtUtc 'Fresh start'
    $freshEnd = ConvertTo-WholeSecondUtc $fresh.device.completedAtUtc 'Fresh end'
    $upgradeStart = ConvertTo-WholeSecondUtc $upgrade.device.startedAtUtc 'Upgrade start'
    $upgradeEnd = ConvertTo-WholeSecondUtc $upgrade.device.completedAtUtc 'Upgrade end'
    if ($allowFrom -ge $allowUntil -or
        $freshStart -ge $freshEnd -or
        $upgradeStart -ge $upgradeEnd -or
        $freshStart -lt $allowFrom -or
        $upgradeStart -lt $allowFrom -or
        $freshEnd -gt $allowUntil -or
        $upgradeEnd -gt $allowUntil) {
        throw 'Device evidence is outside the exact allowlist window.'
    }

    $before = $Evidence.publicHeadContinuity.before
    $after = $Evidence.publicHeadContinuity.after
    foreach ($name in @('headSha256', 'releaseSetId', 'manifestSha256', 'etag')) {
        Assert-Equal $after.$name $before.$name "Public head $name continuity"
    }
    if ($before.manifestSha256 -ceq $Evidence.bindings.manifest.sha256) {
        throw 'Candidate manifest was already visible through the public Stable head.'
    }
    $beforeAt = ConvertTo-WholeSecondUtc $before.observedAtUtc 'Public before time'
    $afterAt = ConvertTo-WholeSecondUtc $after.observedAtUtc 'Public after time'
    if ($beforeAt -ge $afterAt) {
        throw 'Public Stable head observations are not ordered.'
    }

    $fetchById = @{}
    foreach ($fetch in @($Evidence.fetchAudit.allowlisted)) {
        $id = [string]$fetch.requestId
        if ($fetchById.ContainsKey($id)) {
            throw "Allowlisted fetch request '$id' is duplicated."
        }
        if ($fetch.deviceIdentitySha256 -cne $freshId -and
            $fetch.deviceIdentitySha256 -cne $upgradeId) {
            throw "Allowlisted fetch '$id' is not bound to either evidence device."
        }
        $fetchById[$id] = $fetch
    }

    $referencedFetchIds = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $freshInstallerFetch = $fetchById[[string]$fresh.installerFetchRequestId]
    if ($null -eq $freshInstallerFetch) {
        throw 'Fresh-install Installer fetch audit is missing.'
    }
    [void]$referencedFetchIds.Add([string]$fresh.installerFetchRequestId)
    Assert-FetchMatchesObject `
        $freshInstallerFetch $installerObject $freshId 'fresh-install' `
        'Fresh Installer fetch'
    foreach ($requestId in @($fresh.manifestFetchRequestIds)) {
        $fetch = $fetchById[[string]$requestId]
        if ($null -eq $fetch) {
            throw "Fresh manifest fetch '$requestId' is missing."
        }
        [void]$referencedFetchIds.Add([string]$requestId)
        Assert-FetchMatchesObject `
            $fetch $manifestObject $freshId 'fresh-install' `
            "Fresh manifest fetch $requestId"
    }

    $upgradeManifestFetch = $fetchById[[string]$upgrade.manifestFetchRequestId]
    if ($null -eq $upgradeManifestFetch) {
        throw 'Online-upgrade manifest fetch audit is missing.'
    }
    [void]$referencedFetchIds.Add([string]$upgrade.manifestFetchRequestId)
    Assert-FetchMatchesObject `
        $upgradeManifestFetch $manifestObject $upgradeId 'online-upgrade' `
        'Upgrade manifest fetch'

    $expectedDownloadedRoles = @($expectedCandidateRoles |
        Where-Object { $_ -cne 'release-public-key' })
    Assert-Equal `
        @($upgrade.artifactFetchRequestIds).Count `
        $expectedDownloadedRoles.Count `
        'Online-upgrade artifact fetch count'
    for ($index = 0; $index -lt $expectedDownloadedRoles.Count; $index++) {
        $requestId = [string]$upgrade.artifactFetchRequestIds[$index]
        $fetch = $fetchById[$requestId]
        if ($null -eq $fetch) {
            throw "Online-upgrade artifact fetch '$requestId' is missing."
        }
        [void]$referencedFetchIds.Add($requestId)
        Assert-FetchMatchesObject `
            $fetch `
            $candidateByRole[$expectedDownloadedRoles[$index]] `
            $upgradeId `
            'online-upgrade' `
            "Upgrade artifact fetch $requestId"
    }
    Assert-Equal $referencedFetchIds.Count $fetchById.Count `
        'Allowlisted fetch inventory closure'

    $probePhases = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($probe in @($Evidence.fetchAudit.nonAllowlisted)) {
        Assert-CanonicalStableUri `
            $probe.uri $canonicalManifestUri 'Non-allowlisted probe URI'
        if (-not $probePhases.Add([string]$probe.observationPhase)) {
            throw "Non-allowlisted '$($probe.observationPhase)' probe is duplicated."
        }
        if ([int]$probe.httpStatus -eq 200) {
            Assert-Equal `
                $probe.observedPublicManifestSha256 `
                $before.manifestSha256 `
                'Non-allowlisted public manifest observation'
        }
        elseif ($null -ne $probe.observedPublicManifestSha256) {
            throw 'Denied non-allowlisted response cannot claim a manifest body.'
        }
    }
    foreach ($phase in @('before', 'after')) {
        if (-not $probePhases.Contains($phase)) {
            throw "Non-allowlisted '$phase' control probe is missing."
        }
    }

    Assert-Equal `
        $Evidence.attestations.server.subjectId `
        $Evidence.server.deployment.id `
        'Server attestation subject'
    Assert-Equal `
        $Evidence.attestations.devices.freshInstall.subjectId `
        $freshId `
        'Fresh device attestation subject'
    Assert-Equal `
        $Evidence.attestations.devices.onlineUpgrade.subjectId `
        $upgradeId `
        'Upgrade device attestation subject'

    $collectedAt = ConvertTo-WholeSecondUtc `
        $Evidence.collectedAtUtc 'Evidence collection time'
    if ($collectedAt -lt $freshEnd -or
        $collectedAt -lt $upgradeEnd -or
        $collectedAt -lt $afterAt -or
        $collectedAt -gt $allowUntil) {
        throw 'Evidence collection time does not close the observation window.'
    }
}

function New-ServerObject {
    param(
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][int]$HashSeed,
        [Parameter(Mandatory = $true)][int64]$SizeBytes
    )

    return [ordered]@{
        role = $Role
        fileName = $FileName
        uri = $Uri
        objectVersionId = "object-v$HashSeed"
        etag = '"object-' + $HashSeed + '"'
        sizeBytes = $SizeBytes
        sha256 = New-TestSha256 $HashSeed
        immutable = $true
        cachePartition = 'private-allowlist'
    }
}

function New-Fetch {
    param(
        [Parameter(Mandatory = $true)][string]$RequestId,
        [Parameter(Mandatory = $true)][string]$DeviceId,
        [Parameter(Mandatory = $true)][string]$Lane,
        [Parameter(Mandatory = $true)][psobject]$Object,
        [Parameter(Mandatory = $true)][string]$FetchedAtUtc
    )

    return [ordered]@{
        requestId = $RequestId
        deviceIdentitySha256 = $DeviceId
        lane = $Lane
        authorizationDecision = 'allow-candidate'
        authorized = $true
        uri = $Object.uri
        role = $Object.role
        objectVersionId = $Object.objectVersionId
        etag = $Object.etag
        sizeBytes = $Object.sizeBytes
        sha256 = $Object.sha256
        httpStatus = 200
        candidateBytesDisclosed = $true
        fetchedAtUtc = $FetchedAtUtc
    }
}

function New-SignatureEnvelope {
    param(
        [Parameter(Mandatory = $true)][string]$SubjectId,
        [Parameter(Mandatory = $true)][string]$Purpose,
        [Parameter(Mandatory = $true)][string]$PayloadType,
        [Parameter(Mandatory = $true)][int]$HashSeed
    )

    return [ordered]@{
        schemaVersion = 1
        envelopeType = 'ensou-dsh-launcher-stable-private-pilot-attestation'
        subjectId = $SubjectId
        purpose = $Purpose
        payloadType = $PayloadType
        payloadSha256 = New-TestSha256 $HashSeed
        signedAtUtc = '2026-08-31T04:05:00Z'
        signature = [ordered]@{
            algorithm = 'ES256'
            keyId = "fixture-key-$HashSeed"
            value = 'A' * 86
        }
    }
}

function New-ValidEvidence {
    param([Parameter(Mandatory = $true)][ValidateSet('Personal', 'Enterprise')][string]$Edition)

    $isPersonal = $Edition -ceq 'Personal'
    $product = if ($isPersonal) { 'ensou-dsh-personal' } else { 'ensou-dsh-enterprise' }
    $installerName = if ($isPersonal) {
        'Ensou.Dsh.Personal.Installer.exe'
    }
    else {
        'Ensou.Dsh.Enterprise.Installer.exe'
    }
    $releaseSetId = if ($isPersonal) {
        'personal-v2026.08.31.1'
    }
    else {
        'enterprise-v2026.08.31.1'
    }
    $freshId = New-TestSha256 41
    $upgradeId = New-TestSha256 42
    $manifestObject = New-ServerObject `
        'release-manifest' `
        'release-set.v2.json' `
        $canonicalManifestUri `
        51 `
        4096
    $candidateObjects = if ($isPersonal) {
        @(
            (New-ServerObject `
                -Role 'client-bundle' `
                -FileName 'client-bundle.zip' `
                -Uri 'https://artifacts.ensou.example/stable/client-bundle.zip' `
                -HashSeed 52 `
                -SizeBytes 1048576)
            (New-ServerObject `
                -Role 'runtime' `
                -FileName 'runtime.zip' `
                -Uri 'https://artifacts.ensou.example/stable/runtime.zip' `
                -HashSeed 53 `
                -SizeBytes 2097152)
        )
    }
    else {
        @(
            (New-ServerObject `
                -Role 'release-public-key' `
                -FileName 'release-public-key.v2.json' `
                -Uri 'https://artifacts.ensou.example/stable/release-public-key.v2.json' `
                -HashSeed 54 `
                -SizeBytes 256)
            (New-ServerObject `
                -Role 'launcher' `
                -FileName 'launcher.zip' `
                -Uri 'https://artifacts.ensou.example/stable/launcher.zip' `
                -HashSeed 55 `
                -SizeBytes 1048576)
            (New-ServerObject `
                -Role 'runtime' `
                -FileName 'runtime.zip' `
                -Uri 'https://artifacts.ensou.example/stable/runtime.zip' `
                -HashSeed 56 `
                -SizeBytes 2097152)
            (New-ServerObject `
                -Role 'plugin-policy' `
                -FileName 'plugin-policy.zip' `
                -Uri 'https://artifacts.ensou.example/stable/plugin-policy.zip' `
                -HashSeed 57 `
                -SizeBytes 524288)
        )
    }
    $installerObject = New-ServerObject `
        'installer' `
        $installerName `
        ("https://downloads.ensou.example/stable/$installerName") `
        58 `
        3145728
    $installerIdentity = [ordered]@{
        fileName = $installerName
        relativePath = "imports/installer-signing.v1/signed/$installerName"
        sizeBytes = $installerObject.sizeBytes
        sha256 = $installerObject.sha256
        peContentSha256 = New-TestSha256 59
        immutableInstallerIdentitySha256 = New-TestSha256 60
    }
    $bindings = [ordered]@{
        manifest = [ordered]@{
            fileName = 'release-set.v2.json'
            sizeBytes = $manifestObject.sizeBytes
            sha256 = $manifestObject.sha256
        }
        candidateSetSha256 = New-TestSha256 61
        payloadSetSha256 = New-TestSha256 62
        releaseTrustProbeSha256 = New-TestSha256 63
        releaseManifestTrustSha256 = New-TestSha256 64
    }
    $observedBindings = [ordered]@{
        releaseSetId = $releaseSetId
        manifestSha256 = $bindings.manifest.sha256
        candidateSetSha256 = $bindings.candidateSetSha256
        payloadSetSha256 = $bindings.payloadSetSha256
        releaseTrustProbeSha256 = $bindings.releaseTrustProbeSha256
    }
    $freshDevice = [ordered]@{
        deviceIdentitySha256 = $freshId
        osFamily = 'Windows'
        osVersion = 'Windows 11 24H2'
        architecture = 'win-x64'
        startedAtUtc = '2026-08-31T01:00:00Z'
        completedAtUtc = '2026-08-31T02:00:00Z'
    }
    $upgradeDevice = [ordered]@{
        deviceIdentitySha256 = $upgradeId
        osFamily = 'Windows'
        osVersion = 'Windows 11 24H2'
        architecture = 'win-x64'
        startedAtUtc = '2026-08-31T02:00:00Z'
        completedAtUtc = '2026-08-31T04:00:00Z'
    }
    $downloadedObjects = @($candidateObjects |
        Where-Object { $_.role -cne 'release-public-key' })
    $artifactFetchIds = [Collections.Generic.List[string]]::new()
    $allowlistedFetches = [Collections.Generic.List[object]]::new()
    $allowlistedFetches.Add((New-Fetch `
        'fresh-installer' $freshId 'fresh-install' $installerObject `
        '2026-08-31T01:05:00Z'))
    $allowlistedFetches.Add((New-Fetch `
        'fresh-manifest' $freshId 'fresh-install' $manifestObject `
        '2026-08-31T01:30:00Z'))
    $allowlistedFetches.Add((New-Fetch `
        'upgrade-manifest' $upgradeId 'online-upgrade' $manifestObject `
        '2026-08-31T02:10:00Z'))
    for ($index = 0; $index -lt $downloadedObjects.Count; $index++) {
        $requestId = "upgrade-artifact-$index"
        $artifactFetchIds.Add($requestId)
        $allowlistedFetches.Add((New-Fetch `
            $requestId `
            $upgradeId `
            'online-upgrade' `
            $downloadedObjects[$index] `
            '2026-08-31T02:15:00Z'))
    }
    $publicHead = [ordered]@{
        headSha256 = New-TestSha256 71
        releaseSetId = 'previous-stable-v2026.08.20.1'
        manifestSha256 = New-TestSha256 72
        etag = '"public-stable-previous"'
    }

    return [ordered]@{
        schemaVersion = 1
        evidenceType = 'ensou-dsh-launcher-stable-private-pilot-evidence'
        orchestrationId = '11111111-1111-4111-8111-111111111111'
        edition = $Edition
        product = $product
        releaseSetId = $releaseSetId
        targetChannel = 'stable'
        exposureRing = 'private-pilot'
        planSha256 = New-TestSha256 1
        r7 = [ordered]@{
            revision = 7
            phase = 'INSTALLER_SIGNATURE_IMPORTED'
            headSha256 = New-TestSha256 2
            receiptRelativePath = 'receipts/0007-installer-signature-imported.json'
            receiptSha256 = New-TestSha256 3
            installer = $installerIdentity
        }
        bindings = $bindings
        canonicalStableManifestUri = $canonicalManifestUri
        server = [ordered]@{
            deployment = [ordered]@{
                id = 'deployment-2026.08.31'
                revision = 'revision-1'
                sha256 = New-TestSha256 4
            }
            configuration = [ordered]@{
                id = 'stable-private-pilot-config'
                revision = 'revision-1'
                sha256 = New-TestSha256 5
            }
            allowlist = [ordered]@{
                policyId = 'stable-private-pilot-allowlist'
                policyVersion = 'version-1'
                policySha256 = New-TestSha256 6
                identityKind = if ($isPersonal) {
                    'private-vpn-egress-allowlist'
                }
                else {
                    'enterprise-device-authorization'
                }
                activeFromUtc = '2026-08-31T00:30:00Z'
                activeUntilUtc = '2026-08-31T05:00:00Z'
                authorizedDeviceIdentitySha256 = @($freshId, $upgradeId)
                defaultDecision = 'deny-candidate'
            }
            cacheIsolation = [ordered]@{
                cacheControl = 'private, no-store'
                privateResponse = $true
                noStore = $true
                varyAuthorization = $true
                sharedCacheBypassed = $true
                candidateCachePartition = 'private-allowlist'
                verificationSha256 = New-TestSha256 7
            }
            objects = [ordered]@{
                manifestObject = $manifestObject
                candidateObjects = $candidateObjects
                installerObject = $installerObject
            }
        }
        publicHeadContinuity = [ordered]@{
            unchanged = $true
            before = [ordered]@{
                observedAtUtc = '2026-08-31T00:45:00Z'
                headSha256 = $publicHead.headSha256
                releaseSetId = $publicHead.releaseSetId
                manifestSha256 = $publicHead.manifestSha256
                etag = $publicHead.etag
            }
            after = [ordered]@{
                observedAtUtc = '2026-08-31T04:02:00Z'
                headSha256 = $publicHead.headSha256
                releaseSetId = $publicHead.releaseSetId
                manifestSha256 = $publicHead.manifestSha256
                etag = $publicHead.etag
            }
        }
        fetchAudit = [ordered]@{
            allowlisted = @($allowlistedFetches)
            nonAllowlisted = @(
                [ordered]@{
                    requestId = 'public-probe-before'
                    probeId = 'external-control-before'
                    uri = $canonicalManifestUri
                    authorizationDecision = 'deny-candidate'
                    authorized = $false
                    httpStatus = 200
                    candidateBytesDisclosed = $false
                    observedPublicManifestSha256 = $publicHead.manifestSha256
                    cacheIsolationVerified = $true
                    observationPhase = 'before'
                    fetchedAtUtc = '2026-08-31T00:46:00Z'
                },
                [ordered]@{
                    requestId = 'public-probe-after'
                    probeId = 'external-control-after'
                    uri = $canonicalManifestUri
                    authorizationDecision = 'deny-candidate'
                    authorized = $false
                    httpStatus = 200
                    candidateBytesDisclosed = $false
                    observedPublicManifestSha256 = $publicHead.manifestSha256
                    cacheIsolationVerified = $true
                    observationPhase = 'after'
                    fetchedAtUtc = '2026-08-31T04:03:00Z'
                })
        }
        devices = [ordered]@{
            freshInstall = [ordered]@{
                device = $freshDevice
                lane = 'fresh-install'
                previousInstallAbsent = $true
                installer = $installerIdentity
                canonicalManifestUri = $canonicalManifestUri
                installerFetchRequestId = 'fresh-installer'
                manifestFetchRequestIds = @('fresh-manifest')
                observedBindings = $observedBindings
                checks = [ordered]@{
                    payloadSelfCheckPassed = $true
                    installationCompleted = $true
                    noExternalFnmRequired = $true
                    noSystemDotnetRequired = $true
                    noVisibleCmdWindow = $true
                    trayReady = $true
                    webUiReady = $true
                    restartPassed = $true
                    localDataPersistencePassed = $true
                }
            }
            onlineUpgrade = [ordered]@{
                device = $upgradeDevice
                lane = 'online-upgrade'
                upgradeKind = 'old-stable-to-candidate'
                sameVersionNoOp = $false
                priorStable = [ordered]@{
                    releaseSetId = $publicHead.releaseSetId
                    sequence = 9
                    manifestSha256 = $publicHead.manifestSha256
                    activeBeforeUpgrade = $true
                }
                candidateSequence = 10
                canonicalManifestUri = $canonicalManifestUri
                manifestFetchRequestId = 'upgrade-manifest'
                artifactFetchRequestIds = @($artifactFetchIds)
                actualArtifactDownload = $true
                productionBytesModified = $false
                observedBindings = $observedBindings
                healthFailure = [ordered]@{
                    injectionKind = 'process-termination-during-health-window'
                    productionBytesUnmodified = $true
                    failedActivationDetected = $true
                }
                rollback = [ordered]@{
                    completed = $true
                    restoredReleaseSetId = $publicHead.releaseSetId
                    workspacePreserved = $true
                    historyPreserved = $true
                }
                recovery = [ordered]@{
                    sameCandidateRetried = $true
                    completed = $true
                    healthConfirmed = $true
                    activeReleaseSetId = $releaseSetId
                }
            }
        }
        attestations = [ordered]@{
            server = New-SignatureEnvelope `
                'deployment-2026.08.31' `
                'stable-private-pilot-server-attestation' `
                'ensou-dsh-launcher-stable-private-pilot-server-observations-v1' `
                81
            devices = [ordered]@{
                freshInstall = New-SignatureEnvelope `
                    $freshId `
                    'stable-private-pilot-device-attestation' `
                    'ensou-dsh-launcher-fresh-install-device-evidence-v1' `
                    82
                onlineUpgrade = New-SignatureEnvelope `
                    $upgradeId `
                    'stable-private-pilot-device-attestation' `
                    'ensou-dsh-launcher-online-upgrade-device-evidence-v1' `
                    83
            }
        }
        collectedAtUtc = '2026-08-31T04:10:00Z'
        productionAdmission = 'NO_GO'
    }
}

function Assert-ContractAccepts {
    param(
        [Parameter(Mandatory = $true)][psobject]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not (Test-EvidenceSchema $Value)) {
        throw "$Label failed the strict evidence schema."
    }
    Assert-StablePrivatePilotEvidenceSemantics $Value
}

function Assert-SchemaRejects {
    param(
        [Parameter(Mandatory = $true)][psobject]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (Test-EvidenceSchema $Value) {
        throw "$Label was accepted by the strict evidence schema."
    }
}

function Assert-SemanticsReject {
    param(
        [Parameter(Mandatory = $true)][psobject]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not (Test-EvidenceSchema $Value)) {
        throw "$Label unexpectedly failed structure before semantic validation."
    }
    $rejected = $false
    try {
        Assert-StablePrivatePilotEvidenceSemantics $Value
    }
    catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw "$Label was accepted by semantic evidence validation."
    }
}

$personal = New-ValidEvidence Personal
$enterprise = New-ValidEvidence Enterprise
Assert-ContractAccepts $personal 'Valid Personal Stable private Pilot evidence'
Assert-ContractAccepts $enterprise 'Valid Enterprise Stable private Pilot evidence'

$case = Copy-TestValue $enterprise
$case.devices.PSObject.Properties.Remove('freshInstall')
Assert-SchemaRejects $case 'Missing fresh-install device'

$case = Copy-TestValue $enterprise
$case.devices.onlineUpgrade.device.deviceIdentitySha256 =
    $case.devices.freshInstall.device.deviceIdentitySha256
Assert-SemanticsReject $case 'Duplicate device identity'

$case = Copy-TestValue $enterprise
$case.devices.onlineUpgrade.lane = 'fresh-install'
Assert-SchemaRejects $case 'Two fresh-install lanes'

$case = Copy-TestValue $enterprise
$case.devices.onlineUpgrade.priorStable.releaseSetId = $case.releaseSetId
Assert-SemanticsReject $case 'Same-version no-op online update'

$case = Copy-TestValue $enterprise
$case.devices.onlineUpgrade.canonicalManifestUri =
    'https://other.ensou.example/v2/channels/stable/release-set.v2.json'
Assert-SemanticsReject $case 'Wrong canonical Stable URI'

$case = Copy-TestValue $enterprise
$case.fetchAudit.nonAllowlisted[1].candidateBytesDisclosed = $true
Assert-SchemaRejects $case 'Candidate leak to non-allowlisted probe'

$case = Copy-TestValue $enterprise
$case.publicHeadContinuity.after.headSha256 = New-TestSha256 99
Assert-SemanticsReject $case 'Changed public Stable head'

$case = Copy-TestValue $enterprise
$case.devices.freshInstall.installer.sha256 = New-TestSha256 100
Assert-SemanticsReject $case 'Fresh-install wrong Installer hash'

$case = Copy-TestValue $enterprise
$case.fetchAudit.allowlisted[3].sha256 = New-TestSha256 101
Assert-SemanticsReject $case 'Allowlisted fetch wrong object hash'

$case = Copy-TestValue $enterprise
$case.server.objects.candidateObjects[0].etag = 'W/"weak-private-etag"'
Assert-SchemaRejects $case 'Weak private candidate ETag'

$case = Copy-TestValue $enterprise
$case.fetchAudit.allowlisted[0].etag = 'W/"weak-private-fetch-etag"'
Assert-SchemaRejects $case 'Weak allowlisted fetch ETag'

$case = Copy-TestValue $enterprise
$case.server.objects.candidateObjects[2].role = 'launcher'
Assert-SemanticsReject $case 'Duplicate candidate role'

$case = Copy-TestValue $enterprise
$case.publicHeadContinuity.before.manifestSha256 = $case.bindings.manifest.sha256
$case.publicHeadContinuity.after.manifestSha256 = $case.bindings.manifest.sha256
$case.fetchAudit.nonAllowlisted[0].observedPublicManifestSha256 =
    $case.bindings.manifest.sha256
$case.fetchAudit.nonAllowlisted[1].observedPublicManifestSha256 =
    $case.bindings.manifest.sha256
Assert-SemanticsReject $case 'Candidate already visible on public Stable head'

$case = Copy-TestValue $enterprise
$case | Add-Member -NotePropertyName unexpected -NotePropertyValue $true
Assert-SchemaRejects $case 'Unknown top-level member'

$case = Copy-TestValue $enterprise
$case.targetChannel = 'pilot'
Assert-SchemaRejects $case 'Enterprise cross-channel evidence'

$case = Copy-TestValue $personal
$case.targetChannel = 'pilot'
Assert-SchemaRejects $case 'Personal cross-channel evidence'

$case = Copy-TestValue $enterprise
$case.devices.onlineUpgrade.PSObject.Properties.Remove('healthFailure')
Assert-SchemaRejects $case 'Missing rollback-triggering health failure'

Write-Output 'STABLE-PRIVATE-PILOT-EVIDENCE-CONTRACT-PASS'
