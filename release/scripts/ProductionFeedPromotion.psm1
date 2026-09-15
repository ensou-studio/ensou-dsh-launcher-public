Set-StrictMode -Version Latest

$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
Import-Module $stateModulePath -Force -DisableNameChecking
$installerSigningContractsPath = Join-Path `
    $PSScriptRoot 'InstallerSigningContracts.psm1'
$personalInstallerSigningPipelinePath = Join-Path `
    $PSScriptRoot 'PersonalInstallerSigningPipeline.psm1'
Import-Module $installerSigningContractsPath -Force -DisableNameChecking
Import-Module $personalInstallerSigningPipelinePath -Force -DisableNameChecking

$script:Utf8Strict = [Text.UTF8Encoding]::new($false, $true)
$script:MaximumJsonBytes = 1MB
$script:MaximumPayloadBytes = 8L * 1024 * 1024 * 1024
$script:RequestSchemaPath = Join-Path `
    (Join-Path $PSScriptRoot '..\schemas') `
    'launcher-feed-promotion-request-v1.schema.json'
$script:ResponseSchemaPath = Join-Path `
    (Join-Path $PSScriptRoot '..\schemas') `
    'launcher-feed-promotion-response-v1.schema.json'
$script:PromotionHeadSchemaPath = Join-Path `
    (Join-Path $PSScriptRoot '..\schemas') `
    'launcher-feed-promotion-state-v1.schema.json'
$script:PlanSchemaPath = Join-Path `
    (Join-Path $PSScriptRoot '..\schemas') `
    'launcher-production-release-plan-v2.schema.json'
$script:StateSchemaPath = Join-Path `
    (Join-Path $PSScriptRoot '..\schemas') `
    'launcher-production-release-state-v2.schema.json'
$script:InstallerSigningRequestSchemaPath = Join-Path `
    (Join-Path $PSScriptRoot '..\schemas') `
    'launcher-installer-signing-request-v2.schema.json'
$script:PersonalInstallerSigningResponseSchemaPath = Join-Path `
    (Join-Path $PSScriptRoot '..\schemas') `
    'personal-installer-signing-response-v2.schema.json'

function ConvertTo-FeedPromotionUtc {
    param([Parameter(Mandatory = $true)][DateTimeOffset]$Value)

    return $Value.ToUniversalTime().ToString(
        'yyyy-MM-ddTHH:mm:ssZ',
        [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-FeedPromotionBase64Url {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-FeedPromotionBase64Url {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ([string]::IsNullOrEmpty($Value) -or $Value -cnotmatch '^[A-Za-z0-9_-]+$') {
        throw "$Label is not canonical base64url."
    }
    $padded = $Value.Replace('-', '+').Replace('_', '/')
    switch ($padded.Length % 4) {
        0 {}
        2 { $padded += '==' }
        3 { $padded += '=' }
        default { throw "$Label has an invalid base64url length." }
    }
    try {
        $bytes = [Convert]::FromBase64String($padded)
    }
    catch {
        throw "$Label is not valid base64url."
    }
    if ((ConvertTo-FeedPromotionBase64Url -Bytes $bytes) -cne $Value) {
        throw "$Label is not canonical base64url."
    }
    return $bytes
}

function Get-FeedPromotionDomainDigest {
    param(
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)]$Value
    )

    $domainBytes = $script:Utf8Strict.GetBytes($Domain + [char]10)
    $valueBytes = ConvertTo-ProductionJsonBytes -Value $Value
    $bytes = [byte[]]::new($domainBytes.Length + $valueBytes.Length)
    [Array]::Copy($domainBytes, 0, $bytes, 0, $domainBytes.Length)
    [Array]::Copy($valueBytes, 0, $bytes, $domainBytes.Length, $valueBytes.Length)
    return Get-ProductionSha256Bytes -Bytes $bytes
}

function Test-FeedPromotionBytesEqual {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Left,
        [Parameter(Mandatory = $true)][byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length) {
        return $false
    }
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -ne $Right[$index]) {
            return $false
        }
    }
    return $true
}

function Assert-FeedPromotionOrdinaryDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw "$Label path must be absolute."
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must be one ordinary non-linked directory: $fullPath"
    }
    for ($current = $item; $null -ne $current; $current = $current.Parent) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label crosses a filesystem link: $fullPath"
        }
    }
    return $fullPath
}

function Assert-FeedPromotionPathSeparation {
    param(
        [Parameter(Mandatory = $true)][string]$First,
        [Parameter(Mandatory = $true)][string]$Second,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $firstFull = [IO.Path]::GetFullPath($First).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $secondFull = [IO.Path]::GetFullPath($Second).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $separator = [string][IO.Path]::DirectorySeparatorChar
    if ($firstFull -ceq $secondFull -or
        $firstFull.StartsWith($secondFull + $separator, [StringComparison]::OrdinalIgnoreCase) -or
        $secondFull.StartsWith($firstFull + $separator, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label paths must not overlap."
    }
}

function Enter-FeedPromotionLock {
    param([Parameter(Mandatory = $true)][string]$PromotionRoot)

    if (-not [IO.Path]::IsPathFullyQualified($PromotionRoot)) {
        throw 'Promotion root must be absolute.'
    }
    $fullRoot = [IO.Path]::GetFullPath($PromotionRoot)
    $parentPath = [IO.Path]::GetDirectoryName($fullRoot)
    if ([string]::IsNullOrWhiteSpace($parentPath)) {
        throw 'Promotion root must name one child directory.'
    }
    [void](Assert-FeedPromotionOrdinaryDirectory `
        -Path $parentPath `
        -Label 'Promotion root parent')
    if (-not (Test-Path -LiteralPath $fullRoot)) {
        [IO.Directory]::CreateDirectory($fullRoot) | Out-Null
    }
    $fullRoot = Assert-FeedPromotionOrdinaryDirectory `
        -Path $fullRoot `
        -Label 'Promotion root'
    $lockPath = Join-Path $fullRoot 'promotion.lock'
    try {
        $stream = [IO.File]::Open(
            $lockPath,
            [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None)
    }
    catch {
        throw 'Promotion root is locked by another promotion process.'
    }
    try {
        [void][EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinarySingleLink(
            $stream.SafeFileHandle)
        $allowed = @(
            'promotion.lock', 'request', 'response', 'bundle',
            'head.json', 'head.json.pending')
        foreach ($entry in Get-ChildItem -LiteralPath $fullRoot -Force) {
            if ($entry.Name -notin $allowed -or
                ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($entry.PSIsContainer -and $entry.Name -notin @('request', 'response', 'bundle')) -or
                (-not $entry.PSIsContainer -and $entry.Name -in @('request', 'response', 'bundle'))) {
                throw "Promotion root contains unexpected entry '$($entry.Name)'."
            }
        }
        return [pscustomobject]@{
            Root = $fullRoot
            Stream = $stream
        }
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Get-FeedPromotionFileBytes {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [int64]$MaximumBytes = $script:MaximumPayloadBytes
    )

    $input = Open-ProductionReleaseInput `
        -Path $Path `
        -Label $Label `
        -MaximumBytes $MaximumBytes
    try {
        return Read-ProductionReleaseInputBytes -Descriptor $input -Label $Label
    }
    finally {
        $input.Stream.Dispose()
    }
}

function Write-FeedPromotionCreateOnlyFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [switch]$FaultAfterPending
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $parent = Assert-FeedPromotionOrdinaryDirectory `
        -Path ([IO.Path]::GetDirectoryName($fullPath)) `
        -Label 'Promotion output parent'
    if ([IO.Path]::GetDirectoryName($fullPath) -cne $parent) {
        throw 'Promotion output parent path is not canonical.'
    }
    $pendingPath = $fullPath + '.pending'
    if (Test-Path -LiteralPath $fullPath) {
        if (Test-Path -LiteralPath $pendingPath) {
            throw 'Committed promotion file has unexpected pending residue.'
        }
        $existing = Get-FeedPromotionFileBytes `
            -Path $fullPath `
            -Label 'Existing promotion output' `
            -MaximumBytes ([Math]::Max([int64]$Bytes.LongLength, 1L))
        if (-not (Test-FeedPromotionBytesEqual -Left $existing -Right $Bytes)) {
            throw 'Create-only promotion output conflicts with existing bytes.'
        }
        return
    }
    if (Test-Path -LiteralPath $pendingPath) {
        $pending = Get-FeedPromotionFileBytes `
            -Path $pendingPath `
            -Label 'Pending promotion output' `
            -MaximumBytes ([Math]::Max([int64]$Bytes.LongLength, 1L))
        if (-not (Test-FeedPromotionBytesEqual -Left $pending -Right $Bytes)) {
            throw 'Pending promotion output conflicts with deterministic replay bytes.'
        }
    }
    else {
        $stream = [IO.File]::Open(
            $pendingPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        try {
            [void][EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinarySingleLink(
                $stream.SafeFileHandle)
            $stream.Write($Bytes, 0, $Bytes.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
    }
    if ($FaultAfterPending) {
        throw 'INJECTED-CRASH-AFTER-PROMOTION-FILE-PENDING'
    }
    [IO.File]::Move($pendingPath, $fullPath)
}

function Get-FeedPromotionCurrentHead {
    param([Parameter(Mandatory = $true)][string]$PromotionRoot)

    $path = Join-Path $PromotionRoot 'head.json'
    $pendingPath = $path + '.pending'
    if ((Test-Path -LiteralPath $path) -and
        (Test-Path -LiteralPath $pendingPath)) {
        throw 'Committed promotion head has conflicting pending residue.'
    }
    if (-not (Test-Path -LiteralPath $path)) {
        return $null
    }
    $input = Read-StrictProductionJsonFile `
        -Path $path `
        -Label 'Offline promotion head'
    [void](Assert-CanonicalProductionJsonInput `
        -Input $input `
        -Label 'Offline promotion head')
    $status = [string]$input.Value.status
    if ($status -cne 'PROMOTION_REQUEST_READY') {
        throw 'Offline promotion head has an unknown fail-closed status.'
    }
    $expected = @(
        'schemaVersion', 'stateType', 'operationId', 'requestSha256',
        'requestNonce', 'sourceStateHeadSha256', 'payloadSetSha256',
        'status', 'productionAdmission', 'networkPublishPerformed',
        'updatedAtUtc')
    Assert-ExactProductionJsonMembers `
        -Value $input.Value `
        -Expected $expected `
        -Label 'Offline promotion head'
    if ([int]$input.Value.schemaVersion -ne 1 -or
        [string]$input.Value.stateType -cne 'ensou-dsh-launcher-offline-feed-promotion-state' -or
        [string]$input.Value.operationId -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$input.Value.requestSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$input.Value.sourceStateHeadSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$input.Value.payloadSetSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$input.Value.productionAdmission -cne 'NO_GO' -or
        [bool]$input.Value.networkPublishPerformed) {
        throw 'Offline promotion head violates its fail-closed contract.'
    }
    [void](ConvertFrom-ProductionUtc `
        -Value ([string]$input.Value.updatedAtUtc) `
        -Label 'Offline promotion head timestamp')
    return [pscustomobject]@{
        Path = $path
        Bytes = $input.Bytes
        Sha256 = $input.Sha256
        Value = $input.Value
    }
}

function Get-FeedPromotionBundleHead {
    param([Parameter(Mandatory = $true)][string]$PromotionRoot)

    $bundleRoot = Join-Path $PromotionRoot 'bundle'
    if (-not (Test-Path -LiteralPath $bundleRoot)) {
        return $null
    }
    $path = Join-Path $bundleRoot 'head.v1.json'
    $pendingPath = $path + '.pending'
    if ((Test-Path -LiteralPath $path) -and
        (Test-Path -LiteralPath $pendingPath)) {
        throw 'Committed bundle head has conflicting pending residue.'
    }
    if (-not (Test-Path -LiteralPath $path)) {
        return $null
    }
    $input = Read-StrictProductionJsonFile `
        -Path $path `
        -Label 'Offline promotion bundle head'
    [void](Assert-CanonicalProductionJsonInput `
        -Input $input `
        -Label 'Offline promotion bundle head')
    Assert-ExactProductionJsonMembers `
        -Value $input.Value `
        -Expected @(
            'schemaVersion', 'stateType', 'operationId', 'requestSha256',
            'requestNonce', 'sourceStateHeadSha256', 'payloadSetSha256',
            'basePromotionHeadSha256', 'responseSha256',
            'bundleSetSha256', 'status', 'productionAdmission',
            'networkPublishPerformed', 'updatedAtUtc') `
        -Label 'Offline promotion bundle head'
    if ([int]$input.Value.schemaVersion -ne 1 -or
        [string]$input.Value.stateType -cne
            'ensou-dsh-launcher-offline-feed-promotion-bundle' -or
        [string]$input.Value.operationId -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$input.Value.requestSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$input.Value.sourceStateHeadSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$input.Value.payloadSetSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$input.Value.basePromotionHeadSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$input.Value.responseSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$input.Value.bundleSetSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$input.Value.status -cne 'EXTERNAL_PUBLISH_BUNDLE_READY' -or
        [string]$input.Value.productionAdmission -cne 'NO_GO' -or
        [bool]$input.Value.networkPublishPerformed) {
        throw 'Offline promotion bundle head violates its fail-closed contract.'
    }
    [void](ConvertFrom-ProductionUtc `
        -Value ([string]$input.Value.updatedAtUtc) `
        -Label 'Offline promotion bundle head timestamp')
    return [pscustomobject]@{
        Path = $path
        Bytes = $input.Bytes
        Sha256 = $input.Sha256
        Value = $input.Value
    }
}

function Write-FeedPromotionHeadCas {
    param(
        [Parameter(Mandatory = $true)][string]$PromotionRoot,
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ExpectedHeadSha256,
        [switch]$FaultAfterPending
    )

    $headPath = Join-Path $PromotionRoot 'head.json'
    $pendingPath = $headPath + '.pending'
    if (-not [string]::IsNullOrEmpty($ExpectedHeadSha256)) {
        throw 'Promotion head is append-only and cannot replace an admitted head.'
    }
    $current = Get-FeedPromotionCurrentHead -PromotionRoot $PromotionRoot
    $currentSha256 = if ($null -eq $current) { '' } else { [string]$current.Sha256 }
    if ($currentSha256 -cne $ExpectedHeadSha256) {
        throw 'Offline promotion head changed before compare-and-swap.'
    }
    if (Test-Path -LiteralPath $pendingPath) {
        $pending = Get-FeedPromotionFileBytes `
            -Path $pendingPath `
            -Label 'Pending offline promotion head' `
            -MaximumBytes $script:MaximumJsonBytes
        if (-not (Test-FeedPromotionBytesEqual -Left $pending -Right $Bytes)) {
            throw 'Pending offline promotion head conflicts with deterministic replay bytes.'
        }
    }
    else {
        $stream = [IO.File]::Open(
            $pendingPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        try {
            [void][EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinarySingleLink(
                $stream.SafeFileHandle)
            $stream.Write($Bytes, 0, $Bytes.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
    }
    if ($FaultAfterPending) {
        throw 'INJECTED-CRASH-AFTER-PROMOTION-HEAD-PENDING'
    }
    $current = Get-FeedPromotionCurrentHead -PromotionRoot $PromotionRoot
    $currentSha256 = if ($null -eq $current) { '' } else { [string]$current.Sha256 }
    if ($currentSha256 -cne $ExpectedHeadSha256) {
        throw 'Offline promotion head changed during compare-and-swap.'
    }
    [IO.File]::Move($pendingPath, $headPath)
}

function Get-FeedPromotionJsonMemberNames {
    param([Parameter(Mandatory = $true)]$Value)

    if ($Value -is [Collections.IDictionary]) {
        return @($Value.Keys | ForEach-Object { [string]$_ })
    }
    return @($Value.PSObject.Properties.Name)
}

function ConvertTo-FeedPromotionRawStateExpectation {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $names = @(Get-FeedPromotionJsonMemberNames -Value $Value)
    $stateProperty = $Value.PSObject.Properties['state']
    if ($null -eq $stateProperty -and $Value -is [Collections.IDictionary]) {
        $state = [string]$Value['state']
    }
    else {
        $state = [string]$stateProperty.Value
    }
    if ($state -ceq 'missing') {
        if ($names.Count -ne 1 -or $names[0] -cne 'state') {
            throw "$Label missing CAS expectation may contain only state."
        }
        return [ordered]@{ state = 'missing' }
    }
    if ($state -cne 'present' -or
        $names.Count -ne 3 -or
        @($names | Where-Object { $_ -notin @('state', 'sizeBytes', 'sha256') }).Count -ne 0) {
        throw "$Label must be an exact missing/present CAS union."
    }
    $size = [int64]$Value.sizeBytes
    $sha256 = [string]$Value.sha256
    if ($size -le 0 -or $size -gt $script:MaximumPayloadBytes -or
        $sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "$Label present CAS expectation requires bounded raw size and SHA-256."
    }
    return [ordered]@{
        state = 'present'
        sizeBytes = $size
        sha256 = $sha256
    }
}

function Assert-FeedPromotionTrustIsolation {
    param([Parameter(Mandatory = $true)][psobject]$Plan)

    $trusts = @(
        [pscustomobject]@{ Label = 'release manifest'; Value = $Plan.releaseManifestTrust },
        [pscustomobject]@{ Label = 'client signing response'; Value = $Plan.externalResponseTrusts.clientSigning },
        [pscustomobject]@{ Label = 'manifest publishing response'; Value = $Plan.externalResponseTrusts.manifestPublishing },
        [pscustomobject]@{ Label = 'Installer signing response'; Value = $Plan.externalResponseTrusts.installerSigning },
        [pscustomobject]@{ Label = 'feed promotion response'; Value = $Plan.externalResponseTrusts.feedPromotion })
    $keyIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $publicPoints = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($trust in $trusts) {
        if (-not $keyIds.Add([string]$trust.Value.keyId)) {
            throw 'Production plan reuses a key ID across isolated trust domains.'
        }
        $identity = Get-ProductionReleaseP256PublicKeyIdentity `
            -Trust $trust.Value `
            -Label ([string]$trust.Label)
        if (-not $publicPoints.Add([string]$identity)) {
            throw 'Production plan reuses one P-256 key across isolated trust domains.'
        }
    }
    if ([string]$Plan.externalResponseTrusts.feedPromotion.purpose -cne
        'feed-promotion-response') {
        throw 'Production plan does not isolate a feed-promotion response trust.'
    }
    $expectedInstallerPurpose = if ([string]$Plan.edition -ceq 'Personal') {
        'personal-installer-signing-response'
    }
    else {
        'installer-signing-response'
    }
    if ([string]$Plan.externalResponseTrusts.installerSigning.purpose -cne
        $expectedInstallerPurpose) {
        throw 'Production plan does not isolate its edition-specific Installer-signing response trust.'
    }
}

function Get-FeedPromotionSourceTransitionSha256 {
    param(
        [Parameter(Mandatory = $true)][psobject]$Receipt,
        [Parameter(Mandatory = $true)][string]$TargetChannel
    )

    $transition = [ordered]@{
        transitionType = 'ensou-dsh-launcher-production-release-transition-v2'
        schemaVersion = 2
        targetChannel = $TargetChannel
        orchestrationId = [string]$Receipt.orchestrationId
        edition = [string]$Receipt.edition
        planSha256 = [string]$Receipt.planSha256
        identitySha256 = [string]$Receipt.identitySha256
        revision = [int]$Receipt.revision
        phase = [string]$Receipt.phase
        previousReceiptSha256 = [string]$Receipt.previousReceiptSha256
        data = $Receipt.data
    }
    return Get-ProductionSha256Bytes `
        -Bytes (ConvertTo-ProductionJsonBytes -Value $transition)
}

function Assert-FeedPromotionValidatedLifecycle {
    param(
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][psobject]$ValidatedState,
        [Parameter(Mandatory = $true)][ValidateSet('pilot', 'stable')]
        [string]$ExposureRing,
        [switch]$AllowPersonalPilotPromotionRequestState
    )

    if ([string]$Plan.edition -ceq 'Personal') {
        if ([string]$Plan.targetChannel -cne 'pilot' -or
            $ExposureRing -cne 'pilot') {
            throw 'Personal feed promotion requires the exact Pilot r7 Installer-signature closure.'
        }
    }
    elseif ([string]$Plan.targetChannel -cne 'stable') {
        throw 'Enterprise private Pilot and public Stable both require a Stable-channel candidate.'
    }
    if ($AllowPersonalPilotPromotionRequestState -and
        ([string]$Plan.edition -cne 'Personal' -or $ExposureRing -cne 'pilot')) {
        throw 'Only Personal Pilot response import can admit its exact r8 promotion-request state.'
    }
    $expectedRevision = if ($AllowPersonalPilotPromotionRequestState) {
        8
    }
    elseif ($ExposureRing -ceq 'pilot') {
        7
    }
    else {
        8
    }
    $expectedPhase = if ($AllowPersonalPilotPromotionRequestState) {
        'PILOT_PROMOTION_REQUESTED'
    }
    elseif ($ExposureRing -ceq 'pilot') {
        'INSTALLER_SIGNATURE_IMPORTED'
    }
    else {
        'PILOT_EVIDENCE_BOUND'
    }
    if ([int]$ValidatedState.Head.revision -ne $expectedRevision -or
        [string]$ValidatedState.Head.phase -cne $expectedPhase -or
        @($ValidatedState.Receipts).Count -ne $expectedRevision) {
        throw "Feed-promotion $ExposureRing exposure requires the complete certified source revision $expectedRevision phase $expectedPhase."
    }
}

function Assert-FeedPromotionCandidateManifest {
    param(
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)]$ManifestInput,
        [Parameter(Mandatory = $true)][object[]]$Files
    )

    [void](Assert-CanonicalProductionJsonInput `
        -Input $ManifestInput `
        -Label 'Feed-promotion signed candidate manifest')
    $manifest = $ManifestInput.Value
    $manifestMembers = if ([string]$Plan.edition -ceq 'Personal') {
        @(
            'schemaVersion', 'product', 'environment', 'channel',
            'releaseSetId', 'provenance', 'generation', 'sequence',
            'minAcceptedSequence', 'issuedAtUtc', 'expiresAtUtc',
            'maximumOfflineGraceSeconds', 'startupStub',
            'revokedReleaseSetIds', 'artifacts', 'signature')
    }
    else {
        @(
            'schemaVersion', 'product', 'environment', 'channel',
            'releaseSetId', 'generation', 'sequence', 'minAcceptedSequence',
            'issuedAtUtc', 'expiresAtUtc', 'startupStub',
            'revokedReleaseSetIds', 'artifacts', 'signature')
    }
    Assert-ExactProductionJsonMembers `
        -Value $manifest `
        -Expected $manifestMembers `
        -Label 'Feed-promotion signed candidate manifest'
    Assert-ExactProductionJsonMembers `
        -Value $manifest.signature `
        -Expected @('algorithm', 'keyId', 'value') `
        -Label 'Feed-promotion release-manifest signature'
    $product = if ([string]$Plan.edition -ceq 'Personal') {
        'ensou-dsh-personal'
    }
    else {
        'ensou-dsh-enterprise'
    }
    if ([int]$manifest.schemaVersion -ne 2 -or
        [string]$manifest.product -cne $product -or
        [string]$manifest.environment -cne 'production' -or
        [string]$manifest.channel -cne [string]$Plan.targetChannel -or
        [string]$manifest.releaseSetId -cne [string]$Plan.releaseSetId -or
        [string]$manifest.signature.algorithm -cne 'ES256' -or
        [string]$manifest.signature.keyId -cne [string]$Plan.releaseManifestTrust.keyId -or
        [string]$manifest.signature.value -cnotmatch '^[A-Za-z0-9_-]{86}$') {
        throw 'Feed-promotion candidate manifest is not bound to the production plan.'
    }
    $expectedComponents = if ([string]$Plan.edition -ceq 'Personal') {
        @('client-bundle', 'runtime')
    }
    else {
        @('launcher', 'runtime', 'plugin-policy')
    }
    $offset = if ([string]$Plan.edition -ceq 'Personal') { 1 } else { 2 }
    if (@($manifest.artifacts).Count -ne $expectedComponents.Count -or
        $Files.Count -ne $expectedComponents.Count + $offset) {
        throw 'Feed-promotion candidate has an incorrect edition-fixed inventory.'
    }
    for ($index = 0; $index -lt $expectedComponents.Count; $index++) {
        $artifact = $manifest.artifacts[$index]
        Assert-ExactProductionJsonMembers `
            -Value $artifact `
            -Expected @(
                'component', 'releaseId', 'uri', 'sizeBytes', 'sha256',
                'completeTreeSha256', 'signature') `
            -Label "Feed-promotion manifest artifact index $index"
        $file = $Files[$index + $offset]
        [Uri]$uri = $null
        if (-not [Uri]::TryCreate([string]$artifact.uri, [UriKind]::Absolute, [ref]$uri) -or
            $uri.Scheme -cne 'https' -or
            [IO.Path]::GetFileName($uri.AbsolutePath) -cne [string]$file.fileName -or
            [string]$artifact.component -cne $expectedComponents[$index] -or
            [string]$file.role -cne $expectedComponents[$index] -or
            [int64]$artifact.sizeBytes -ne [int64]$file.sizeBytes -or
            [string]$artifact.sha256 -cne [string]$file.sha256) {
            throw "Feed-promotion candidate artifact index $index differs from its locked file."
        }
    }
}

function Assert-PersonalFeedPromotionInstallerClosure {
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][object[]]$Receipts,
        [Parameter(Mandatory = $true)]$ReceiptDescriptors,
        [Parameter(Mandatory = $true)]$Descriptors
    )

    $r5 = $Receipts[4]
    $r6 = $Receipts[5]
    $r7 = $Receipts[6]
    $r5Descriptor = $ReceiptDescriptors[4]
    $r6Descriptor = $ReceiptDescriptors[5]
    if ([string]$r6.previousReceiptSha256 -cne
            [string]$r5Descriptor.Sha256 -or
        [string]$r7.previousReceiptSha256 -cne
            [string]$r6Descriptor.Sha256 -or
        [string]$r6.data.baseReceiptSha256 -cne
            [string]$r5Descriptor.Sha256 -or
        [string]$r7.data.r6ReceiptSha256 -cne
            [string]$r6Descriptor.Sha256) {
        throw 'Personal feed promotion r5/r6/r7 receipt CAS linkage is incomplete.'
    }

    $historicalR5Head = [ordered]@{
        schemaVersion = 2
        stateType = 'ensou-dsh-launcher-production-release-head'
        orchestrationId = [string]$r5.orchestrationId
        edition = 'Personal'
        planSha256 = [string]$r5.planSha256
        identitySha256 = [string]$r5.identitySha256
        revision = 5
        phase = 'PILOT_SIGNED_CANDIDATE_IMPORTED'
        receiptFileName = '0005-pilot-signed-candidate-imported.json'
        receiptSha256 = [string]$r5Descriptor.Sha256
        updatedAtUtc = [string]$r5.recordedAtUtc
        targetChannel = 'pilot'
    }
    $r5HeadSha256 = Get-ProductionSha256Bytes `
        -Bytes (ConvertTo-ProductionJsonBytes -Value $historicalR5Head)
    $historicalR6Head = [ordered]@{
        schemaVersion = 2
        stateType = 'ensou-dsh-launcher-production-release-head'
        orchestrationId = [string]$r6.orchestrationId
        edition = 'Personal'
        planSha256 = [string]$r6.planSha256
        identitySha256 = [string]$r6.identitySha256
        revision = 6
        phase = 'INSTALLER_SIGNING_REQUESTED'
        receiptFileName = '0006-installer-signing-requested.json'
        receiptSha256 = [string]$r6Descriptor.Sha256
        updatedAtUtc = [string]$r6.recordedAtUtc
        targetChannel = 'pilot'
    }
    $r6HeadSha256 = Get-ProductionSha256Bytes `
        -Bytes (ConvertTo-ProductionJsonBytes -Value $historicalR6Head)
    if ([string]$r6.data.baseHeadSha256 -cne $r5HeadSha256 -or
        [string]$r7.data.admissionHeadSha256 -cne $r6HeadSha256) {
        throw 'Personal feed promotion r6/r7 receipts do not bind their reconstructed CAS heads.'
    }

    $requestDescriptor = Open-ProductionReleaseInput `
        -Path (Join-Path $StateRoot `
            'requests\installer-signing.v2\installer-signing-request.v2.json') `
        -Label 'Personal feed-promotion r6 request' `
        -MaximumBytes $script:MaximumJsonBytes
    $Descriptors.Add($requestDescriptor)
    $requestBytes = Read-ProductionReleaseInputBytes `
        -Descriptor $requestDescriptor `
        -Label 'Personal feed-promotion r6 request'
    $request = ConvertFrom-StrictProductionJsonBytes `
        -Bytes $requestBytes `
        -Label 'Personal feed-promotion r6 request' `
        -SchemaPath $script:InstallerSigningRequestSchemaPath
    $requestInput = [pscustomobject]@{
        Value = $request
        Bytes = $requestBytes
        Sha256 = [string]$requestDescriptor.Sha256
    }
    [void](Assert-CanonicalProductionJsonInput `
        -Input $requestInput `
        -Label 'Personal feed-promotion r6 request')
    [void](InstallerSigningContracts\Assert-InstallerSigningRequestContract `
        -Request $request `
        -InstallerSigningTrust $Plan.externalResponseTrusts.installerSigning `
        -ReleaseManifestTrust $Plan.releaseManifestTrust)
    $bindings =
        PersonalInstallerSigningPipeline\Get-PersonalInstallerSigningRequestBindings `
            -Request $request
    foreach ($bindingName in @(
            'sourceSha256', 'payloadSha256', 'compiledTrustSha256',
            'toolchainSha256', 'buildExecutionSha256',
            'resourceBindingSha256', 'trustedBuildEvidenceSha256',
            'admissionSha256')) {
        if ([string]$r6.data.$bindingName -cne
            [string]$bindings.$bindingName) {
            throw "Personal feed promotion r6 binding '$bindingName' differs from its request-v2."
        }
    }
    if ([string]$r6.data.requestSha256 -cne
            [string]$requestDescriptor.Sha256 -or
        [string]$r7.data.requestSha256 -cne
            [string]$requestDescriptor.Sha256 -or
        [string]$request.baseHeadSha256 -cne $r5HeadSha256) {
        throw 'Personal feed promotion request-v2 does not match the r5/r6/r7 CAS chain.'
    }

    $responseDescriptor = Open-ProductionReleaseInput `
        -Path (Join-Path $StateRoot `
            'imports\installer-signing.v2\personal-installer-signing-response.v2.json') `
        -Label 'Personal feed-promotion r7 response' `
        -MaximumBytes $script:MaximumJsonBytes
    $Descriptors.Add($responseDescriptor)
    $responseBytes = Read-ProductionReleaseInputBytes `
        -Descriptor $responseDescriptor `
        -Label 'Personal feed-promotion r7 response'
    $response = ConvertFrom-StrictProductionJsonBytes `
        -Bytes $responseBytes `
        -Label 'Personal feed-promotion r7 response' `
        -SchemaPath $script:PersonalInstallerSigningResponseSchemaPath
    $responseInput = [pscustomobject]@{
        Value = $response
        Bytes = $responseBytes
        Sha256 = [string]$responseDescriptor.Sha256
    }
    [void](Assert-CanonicalProductionJsonInput `
        -Input $responseInput `
        -Label 'Personal feed-promotion r7 response')
    [void](PersonalInstallerSigningPipeline\Assert-PersonalInstallerSigningResponseV2Contract `
        -RequestInput $requestInput `
        -ResponseInput $responseInput `
        -R6HeadSha256 $r6HeadSha256 `
        -R6ReceiptSha256 ([string]$r6Descriptor.Sha256) `
        -InstallerSigningTrust $Plan.externalResponseTrusts.installerSigning)
    if ([string]$r7.data.responseSha256 -cne
            [string]$responseDescriptor.Sha256 -or
        [string]$r7.data.payloadSelfCheckCanonicalJsonSha256 -cne
            [string]$response.payloadSelfCheck.canonicalJsonSha256 -or
        [string]$r7.data.authenticationKeyId -cne
            [string]$Plan.externalResponseTrusts.installerSigning.keyId) {
        throw 'Personal feed promotion r7 receipt differs from its authenticated response-v2.'
    }

    $signedDescriptor = Open-ProductionReleaseInput `
        -Path (Join-Path $StateRoot `
            'imports\installer-signing.v2\signed\Ensou.Dsh.Personal.Installer.exe') `
        -Label 'Personal feed-promotion signed Installer' `
        -MaximumBytes $script:MaximumPayloadBytes
    $Descriptors.Add($signedDescriptor)
    if ([string]$signedDescriptor.Sha256 -cne
            [string]$response.signedInstaller.sha256 -or
        [string]$signedDescriptor.Sha256 -cne
            [string]$r7.data.signedInstaller.sha256 -or
        [int64]$signedDescriptor.SizeBytes -ne
            [int64]$response.signedInstaller.sizeBytes -or
        [int64]$signedDescriptor.SizeBytes -ne
            [int64]$r7.data.signedInstaller.sizeBytes) {
        throw 'Personal feed promotion signed Installer differs from r7 response and receipt.'
    }
    $authenticode = InstallerSigningContracts\Assert-SignedInstallerAuthenticode `
        -Path ([string]$signedDescriptor.Path) `
        -Response $response `
        -ExpectedSignerCertificateSha256 `
            ([string]$Plan.authenticodePolicy.signerSha256Thumbprint)
    if ([string]$authenticode.PeContentSha256 -cne
            [string]$r7.data.signedInstaller.peContentSha256 -or
        [string]$r7.data.timestampProtocol -cne 'RFC3161') {
        throw 'Personal feed promotion signed Installer lacks the exact r7 PE/RFC3161 binding.'
    }
}

function Open-FeedPromotionSourceSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][string]$CandidateRoot,
        [Parameter(Mandatory = $true)][ValidateSet('pilot', 'stable')]
        [string]$ExposureRing,
        [Parameter(Mandatory = $true)][string]$ExpectedSourcePlanSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedSourceIdentitySha256,
        [Parameter(Mandatory = $true)][string]$ExpectedSourceHeadSha256,
        [switch]$AllowPersonalPilotPromotionRequestState
    )

    $stateLock = Enter-ProductionReleaseStateReadLock -StateRoot $StateRoot
    $descriptors = [Collections.Generic.List[object]]::new()
    try {
        foreach ($anchor in @(
                [pscustomobject]@{
                    Label = 'Expected source plan'
                    Value = $ExpectedSourcePlanSha256
                },
                [pscustomobject]@{
                    Label = 'Expected source identity'
                    Value = $ExpectedSourceIdentitySha256
                },
                [pscustomobject]@{
                    Label = 'Expected source head'
                    Value = $ExpectedSourceHeadSha256
                })) {
            if ([string]$anchor.Value -cnotmatch '^[0-9a-f]{64}$') {
                throw "$($anchor.Label) trust root must be one exact SHA-256."
            }
        }

        $candidate = Assert-FeedPromotionOrdinaryDirectory `
            -Path $CandidateRoot `
            -Label 'Feed-promotion candidate root'
        $planDescriptor = Open-ProductionReleaseInput `
            -Path (Join-Path $stateLock.StateRoot 'plan.json') `
            -Label 'Feed-promotion production plan' `
            -MaximumBytes $script:MaximumJsonBytes
        $descriptors.Add($planDescriptor)
        $planBytes = Read-ProductionReleaseInputBytes `
            -Descriptor $planDescriptor `
            -Label 'Feed-promotion production plan'
        $plan = ConvertFrom-StrictProductionJsonBytes `
            -Bytes $planBytes `
            -Label 'Feed-promotion production plan' `
            -SchemaPath $script:PlanSchemaPath
        Assert-FeedPromotionTrustIsolation -Plan $plan

        $identityDescriptor = Open-ProductionReleaseInput `
            -Path (Join-Path $stateLock.StateRoot 'identity.json') `
            -Label 'Feed-promotion state identity' `
            -MaximumBytes $script:MaximumJsonBytes
        $descriptors.Add($identityDescriptor)
        $identityBytes = Read-ProductionReleaseInputBytes `
            -Descriptor $identityDescriptor `
            -Label 'Feed-promotion state identity'
        $identity = ConvertFrom-StrictProductionJsonBytes `
            -Bytes $identityBytes `
            -Label 'Feed-promotion state identity' `
            -SchemaPath $script:StateSchemaPath

        $headDescriptor = Open-ProductionReleaseInput `
            -Path (Join-Path $stateLock.StateRoot 'head.json') `
            -Label 'Feed-promotion source state head' `
            -MaximumBytes $script:MaximumJsonBytes
        $descriptors.Add($headDescriptor)
        $headBytes = Read-ProductionReleaseInputBytes `
            -Descriptor $headDescriptor `
            -Label 'Feed-promotion source state head'
        $head = ConvertFrom-StrictProductionJsonBytes `
            -Bytes $headBytes `
            -Label 'Feed-promotion source state head' `
            -SchemaPath $script:StateSchemaPath
        [void](Assert-CanonicalProductionJsonInput `
            -Input ([pscustomobject]@{
                Value = $identity
                Bytes = $identityBytes
                Sha256 = [string]$identityDescriptor.Sha256
            }) `
            -Label 'Feed-promotion state identity')
        [void](Assert-CanonicalProductionJsonInput `
            -Input ([pscustomobject]@{
                Value = $head
                Bytes = $headBytes
                Sha256 = [string]$headDescriptor.Sha256
            }) `
            -Label 'Feed-promotion source state head')

        if ([int]$identity.schemaVersion -ne 2 -or
            [int]$head.schemaVersion -ne 2 -or
            [string]$identity.planSha256 -cne [string]$planDescriptor.Sha256 -or
            [string]$head.planSha256 -cne [string]$planDescriptor.Sha256 -or
            [string]$head.identitySha256 -cne [string]$identityDescriptor.Sha256 -or
            [string]$head.orchestrationId -cne [string]$plan.orchestrationId -or
            [string]$identity.orchestrationId -cne [string]$plan.orchestrationId -or
            [string]$head.edition -cne [string]$plan.edition -or
            [string]$identity.edition -cne [string]$plan.edition -or
            [string]$head.targetChannel -cne [string]$plan.targetChannel -or
            [string]$identity.targetChannel -cne [string]$plan.targetChannel) {
            throw 'Feed-promotion source plan, identity, and head are not hash-bound.'
        }
        if ([string]$planDescriptor.Sha256 -cne $ExpectedSourcePlanSha256 -or
            [string]$identityDescriptor.Sha256 -cne $ExpectedSourceIdentitySha256 -or
            [string]$headDescriptor.Sha256 -cne $ExpectedSourceHeadSha256 -or
            [string]$identity.planSha256 -cne $ExpectedSourcePlanSha256) {
            throw 'Feed-promotion source differs from its externally locked plan, identity, or head trust root.'
        }
        # This is the authoritative state-machine validation boundary. It
        # validates the complete r1..HEAD receipt chain and every admitted
        # state-owned payload before any feed candidate is considered.
        $validatedState = Get-ProductionReleaseState `
            -StateRoot $stateLock.StateRoot `
            -StateSchemaPath $script:StateSchemaPath
        if ($null -eq $validatedState.Head -or
            $null -ne $validatedState.OrphanReceipt -or
            (Test-Path -LiteralPath (Join-Path $stateLock.StateRoot 'head.json.pending')) -or
            [string]$validatedState.IdentitySha256 -cne $ExpectedSourceIdentitySha256 -or
            [string]$validatedState.HeadSha256 -cne $ExpectedSourceHeadSha256 -or
            [string]$validatedState.Identity.planSha256 -cne $ExpectedSourcePlanSha256) {
            throw 'Feed-promotion source must be one externally anchored, fully admitted state with no pending or orphan transition.'
        }
        Assert-FeedPromotionValidatedLifecycle `
            -Plan $plan `
            -ValidatedState $validatedState `
            -ExposureRing $ExposureRing `
            -AllowPersonalPilotPromotionRequestState:$AllowPersonalPilotPromotionRequestState

        $expectedRevision = if ($AllowPersonalPilotPromotionRequestState) {
            8
        }
        elseif ($ExposureRing -ceq 'pilot') {
            7
        }
        else {
            8
        }
        $expectedPhase = if ($AllowPersonalPilotPromotionRequestState) {
            'PILOT_PROMOTION_REQUESTED'
        }
        elseif ($expectedRevision -eq 7) {
            'INSTALLER_SIGNATURE_IMPORTED'
        }
        else {
            'PILOT_EVIDENCE_BOUND'
        }
        if ([int]$head.revision -ne $expectedRevision -or
            [string]$head.phase -cne $expectedPhase) {
            throw "Feed-promotion $ExposureRing exposure requires source revision $expectedRevision phase $expectedPhase."
        }

        $lifecycle = Get-ProductionReleaseLifecycleContract `
            -SchemaVersion 2 `
            -TargetChannel ([string]$plan.targetChannel)
        $receiptDescriptors = [Collections.Generic.List[object]]::new()
        $receipts = [Collections.Generic.List[object]]::new()
        $previousReceiptSha256 = '0' * 64
        for ($revision = 1; $revision -le $expectedRevision; $revision++) {
            $transition = $lifecycle.Transitions[$revision - 1]
            $fileName = $revision.ToString('0000') + '-' +
                ([string]$transition.Phase).ToLowerInvariant().Replace('_', '-') + '.json'
            $descriptor = Open-ProductionReleaseInput `
                -Path (Join-Path (Join-Path $stateLock.StateRoot 'receipts') $fileName) `
                -Label "Feed-promotion source receipt $revision" `
                -MaximumBytes $script:MaximumJsonBytes
            $descriptors.Add($descriptor)
            $receiptDescriptors.Add($descriptor)
            $bytes = Read-ProductionReleaseInputBytes `
                -Descriptor $descriptor `
                -Label "Feed-promotion source receipt $revision"
            $receipt = ConvertFrom-StrictProductionJsonBytes `
                -Bytes $bytes `
                -Label "Feed-promotion source receipt $revision" `
                -SchemaPath $script:StateSchemaPath
            [void](Assert-CanonicalProductionJsonInput `
                -Input ([pscustomobject]@{
                    Value = $receipt
                    Bytes = $bytes
                    Sha256 = [string]$descriptor.Sha256
                }) `
                -Label "Feed-promotion source receipt $revision")
            if ([int]$receipt.revision -ne $revision -or
                [string]$receipt.phase -cne [string]$transition.Phase -or
                [string]$receipt.orchestrationId -cne [string]$plan.orchestrationId -or
                [string]$receipt.edition -cne [string]$plan.edition -or
                [string]$receipt.targetChannel -cne [string]$plan.targetChannel -or
                [string]$receipt.planSha256 -cne [string]$planDescriptor.Sha256 -or
                [string]$receipt.identitySha256 -cne [string]$identityDescriptor.Sha256 -or
                [string]$receipt.previousReceiptSha256 -cne $previousReceiptSha256 -or
                [string]$receipt.transitionSha256 -cne
                    (Get-FeedPromotionSourceTransitionSha256 `
                        -Receipt $receipt `
                        -TargetChannel ([string]$plan.targetChannel))) {
                throw "Feed-promotion source receipt $revision is not an exact canonical chain member."
            }
            $previousReceiptSha256 = [string]$descriptor.Sha256
            $receipts.Add($receipt)
        }
        $lastDescriptor = $receiptDescriptors[$receiptDescriptors.Count - 1]
        $lastReceipt = $receipts[$receipts.Count - 1]
        if ([string]$head.receiptFileName -cne [string]$lastDescriptor.FileName -or
            [string]$head.receiptSha256 -cne [string]$lastDescriptor.Sha256 -or
            [string]$head.updatedAtUtc -cne [string]$lastReceipt.recordedAtUtc) {
            throw 'Feed-promotion source head does not bind the exact final source receipt.'
        }

        $candidateReceipt = $receipts[4]
        if ([int]$candidateReceipt.revision -ne 5 -or
            [string]$candidateReceipt.data.productionAdmission -cne 'NO_GO' -or
            [string]$candidateReceipt.data.authenticationPurpose -cne
                'manifest-publishing-response' -or
            [string]$candidateReceipt.data.authenticationKeyId -cne
                [string]$plan.externalResponseTrusts.manifestPublishing.keyId) {
            throw 'Feed-promotion source lacks a fail-closed signed-candidate receipt at revision 5.'
        }
        $installerReceipt = $receipts[6]
        if ([int]$installerReceipt.revision -ne 7 -or
            [string]$installerReceipt.data.evidenceType -cne
                'INSTALLER_SIGNATURE_IMPORTED') {
            throw 'Feed-promotion source lacks the exact Installer-signature import gate.'
        }
        if ([string]$plan.edition -ceq 'Enterprise' -and
            ([string]$installerReceipt.data.productionAdmission -cne 'NO_GO' -or
             [string]$installerReceipt.data.timestampProtocol -cne 'RFC3161' -or
             [string]$installerReceipt.data.authenticationPurpose -cne
                'installer-signing-response' -or
             [string]$installerReceipt.data.authenticationKeyId -cne
                [string]$plan.externalResponseTrusts.installerSigning.keyId)) {
            throw 'Enterprise feed promotion requires the typed RFC3161 Installer-signature gate.'
        }
        if ([string]$plan.edition -ceq 'Personal') {
            if ([string]$installerReceipt.data.productionAdmission -cne 'NO_GO' -or
                [string]$installerReceipt.data.admissionReason -cne
                    'PERSONAL_SIGNED_WINDOWS_PILOT_REQUIRED' -or
                [string]$installerReceipt.data.timestampProtocol -cne 'RFC3161' -or
                [string]$installerReceipt.data.authenticationPurpose -cne
                    'personal-installer-signing-response' -or
                [string]$installerReceipt.data.authenticationPayloadType -cne
                    'ensou-dsh-personal-installer-signing-response-authentication-v2' -or
                [string]$installerReceipt.data.authenticationKeyId -cne
                    [string]$plan.externalResponseTrusts.installerSigning.keyId) {
                throw 'Personal feed promotion requires the typed response-v2 RFC3161 Installer-signature gate.'
            }
            Assert-PersonalFeedPromotionInstallerClosure `
                -StateRoot $stateLock.StateRoot `
                -Plan $plan `
                -Receipts @($receipts) `
                -ReceiptDescriptors $receiptDescriptors `
                -Descriptors $descriptors
        }
        if ($expectedRevision -eq 8 -and
            [string]$receipts[7].data.evidenceType -cne 'PILOT_EVIDENCE_BOUND') {
            throw 'Stable feed promotion requires the exact Pilot-evidence binding gate.'
        }
        if ($ExposureRing -ceq 'stable') {
            $pilotEvidencePath = Join-Path `
                (Join-Path $stateLock.StateRoot 'imports\pilot-evidence.v1') `
                'pilot-evidence-input.v1.json'
            $pilotEvidenceDescriptor = Open-ProductionReleaseInput `
                -Path $pilotEvidencePath `
                -Label 'Certified Enterprise Pilot evidence' `
                -MaximumBytes $script:MaximumJsonBytes
            $descriptors.Add($pilotEvidenceDescriptor)
            $pilotEvidenceBytes = Read-ProductionReleaseInputBytes `
                -Descriptor $pilotEvidenceDescriptor `
                -Label 'Certified Enterprise Pilot evidence'
            $pilotEvidence = ConvertFrom-StrictProductionJsonBytes `
                -Bytes $pilotEvidenceBytes `
                -Label 'Certified Enterprise Pilot evidence' `
                -SchemaPath (Join-Path `
                    (Join-Path $PSScriptRoot '..\schemas') `
                    'enterprise-production-pilot-evidence-input-v1.schema.json')
            [void](Assert-EnterpriseProductionPilotEvidenceInputBinding `
                -PilotEvidenceInput ([pscustomobject]@{
                    Value = $pilotEvidence
                    Bytes = $pilotEvidenceBytes
                    Sha256 = [string]$pilotEvidenceDescriptor.Sha256
                }) `
                -Plan $plan `
                -Identity $identity `
                -IdentitySha256 ([string]$identityDescriptor.Sha256) `
                -Receipts $receipts `
                -StateRoot $stateLock.StateRoot `
                -EnforceCurrentLifetime)
        }
        $expectedRoles = if ([string]$plan.edition -ceq 'Personal') {
            @('release-manifest', 'client-bundle', 'runtime')
        }
        else {
            @('release-manifest', 'release-public-key', 'launcher', 'runtime', 'plugin-policy')
        }
        $candidateFiles = @($candidateReceipt.data.files)
        if ($candidateFiles.Count -ne $expectedRoles.Count) {
            throw 'Feed-promotion r5 candidate receipt has an incorrect edition-fixed inventory.'
        }
        $expectedNames = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        for ($index = 0; $index -lt $expectedRoles.Count; $index++) {
            $file = $candidateFiles[$index]
            if ([string]$file.role -cne $expectedRoles[$index] -or
                [string]$file.relativePath -cne ('candidate/' + [string]$file.fileName) -or
                -not $expectedNames.Add([string]$file.fileName)) {
                throw "Feed-promotion r5 candidate file index $index violates its edition-fixed role order."
            }
        }
        foreach ($entry in Get-ChildItem -LiteralPath $candidate -Force) {
            if ($entry.PSIsContainer -or
                ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                -not $expectedNames.Contains($entry.Name)) {
                throw "Feed-promotion candidate root contains unexpected entry '$($entry.Name)'."
            }
        }
        if (@(Get-ChildItem -LiteralPath $candidate -Force).Count -ne $expectedNames.Count) {
            throw 'Feed-promotion candidate root is missing an exact r5 candidate file.'
        }
        $lockedFiles = [Collections.Generic.List[object]]::new()
        for ($index = 0; $index -lt $candidateFiles.Count; $index++) {
            $recorded = $candidateFiles[$index]
            $descriptor = Open-ProductionReleaseInput `
                -Path (Join-Path $candidate ([string]$recorded.fileName)) `
                -Label "Feed-promotion candidate role $($recorded.role)" `
                -MaximumBytes $script:MaximumPayloadBytes
            $descriptors.Add($descriptor)
            if ([int64]$descriptor.SizeBytes -ne [int64]$recorded.sizeBytes -or
                [string]$descriptor.Sha256 -cne [string]$recorded.sha256) {
                throw "Feed-promotion candidate role '$($recorded.role)' differs from the r5 receipt."
            }
            $lockedFiles.Add([pscustomobject]@{
                role = [string]$recorded.role
                fileName = [string]$recorded.fileName
                relativePath = 'payload/' + [string]$recorded.fileName
                sizeBytes = [int64]$descriptor.SizeBytes
                sha256 = [string]$descriptor.Sha256
                Descriptor = $descriptor
            })
        }
        $manifestDescriptor = $lockedFiles[0].Descriptor
        $manifestBytes = Read-ProductionReleaseInputBytes `
            -Descriptor $manifestDescriptor `
            -Label 'Feed-promotion candidate manifest'
        $manifest = ConvertFrom-StrictProductionJsonBytes `
            -Bytes $manifestBytes `
            -Label 'Feed-promotion candidate manifest'
        Assert-FeedPromotionCandidateManifest `
            -Plan $plan `
            -ManifestInput ([pscustomobject]@{
                Value = $manifest
                Bytes = $manifestBytes
                Sha256 = [string]$manifestDescriptor.Sha256
            }) `
            -Files @($lockedFiles)

        $receiptIdentities = [Collections.Generic.List[object]]::new()
        for ($index = 0; $index -lt $receiptDescriptors.Count; $index++) {
            $descriptor = $receiptDescriptors[$index]
            $receiptIdentities.Add([ordered]@{
                revision = $index + 1
                fileName = [string]$descriptor.FileName
                sizeBytes = [int64]$descriptor.SizeBytes
                sha256 = [string]$descriptor.Sha256
            })
        }
        $receiptChainSha256 = Get-FeedPromotionDomainDigest `
            -Domain 'ensou-dsh-launcher-feed-promotion-source-receipt-chain-v1' `
            -Value @($receiptIdentities)
        $sourceHead = $head
        $sourceHeadDescriptor = $headDescriptor
        $promotionRequestSha256 = ''
        if ($AllowPersonalPilotPromotionRequestState) {
            $r7Descriptor = $receiptDescriptors[6]
            $r7Receipt = $receipts[6]
            $historicalR7Head = [ordered]@{
                schemaVersion = 2
                stateType = 'ensou-dsh-launcher-production-release-head'
                orchestrationId = [string]$r7Receipt.orchestrationId
                edition = 'Personal'
                planSha256 = [string]$r7Receipt.planSha256
                identitySha256 = [string]$r7Receipt.identitySha256
                revision = 7
                phase = 'INSTALLER_SIGNATURE_IMPORTED'
                receiptFileName = '0007-installer-signature-imported.json'
                receiptSha256 = [string]$r7Descriptor.Sha256
                updatedAtUtc = [string]$r7Receipt.recordedAtUtc
                targetChannel = 'pilot'
            }
            $historicalR7HeadBytes = ConvertTo-ProductionJsonBytes -Value $historicalR7Head
            $sourceHead = [pscustomobject]$historicalR7Head
            $sourceHeadDescriptor = [pscustomobject]@{
                SizeBytes = [int64]$historicalR7HeadBytes.LongLength
                Sha256 = Get-ProductionSha256Bytes -Bytes $historicalR7HeadBytes
            }
            $receiptChainSha256 = Get-FeedPromotionDomainDigest `
                -Domain 'ensou-dsh-launcher-feed-promotion-source-receipt-chain-v1' `
                -Value @($receiptIdentities | Select-Object -First 7)
            $r8 = $receipts[7]
            if ([string]$r8.data.evidenceType -cne 'PILOT_PROMOTION_REQUESTED' -or
                [string]$r8.data.relativePath -cne
                    'requests/pilot-feed-promotion.v1/request.v1.json' -or
                [string]$r8.data.sha256 -cnotmatch '^[0-9a-f]{64}$') {
                throw 'Personal r8 promotion-request receipt does not bind its canonical state-owned request.'
            }
            $requestDescriptor = Open-ProductionReleaseInput `
                -Path (Join-Path $stateLock.StateRoot `
                    'requests\pilot-feed-promotion.v1\request.v1.json') `
                -Label 'Personal r8 state-owned feed-promotion request' `
                -MaximumBytes $script:MaximumJsonBytes
            $descriptors.Add($requestDescriptor)
            $requestBytes = Read-ProductionReleaseInputBytes `
                -Descriptor $requestDescriptor `
                -Label 'Personal r8 state-owned feed-promotion request'
            $request = ConvertFrom-StrictProductionJsonBytes `
                -Bytes $requestBytes `
                -Label 'Personal r8 state-owned feed-promotion request' `
                -SchemaPath $script:RequestSchemaPath
            [void](Assert-CanonicalProductionJsonInput `
                -Input ([pscustomobject]@{
                    Value = $request
                    Bytes = $requestBytes
                    Sha256 = [string]$requestDescriptor.Sha256
                }) `
                -Label 'Personal r8 state-owned feed-promotion request')
            if ([string]$requestDescriptor.Sha256 -cne [string]$r8.data.sha256 -or
                [string]$request.edition -cne 'Personal' -or
                [string]$request.exposureRing -cne 'pilot' -or
                [string]$request.sourceState.headSha256 -cne
                    [string]$sourceHeadDescriptor.Sha256 -or
                [int64]$request.sourceState.headSizeBytes -ne
                    [int64]$sourceHeadDescriptor.SizeBytes -or
                [string]$request.sourceState.receiptChainSha256 -cne $receiptChainSha256) {
                throw 'Personal r8 state-owned promotion request does not bind the exact historical r7 source closure.'
            }
            $promotionRequestSha256 = [string]$requestDescriptor.Sha256
        }
        return [pscustomobject]@{
            StateLock = $stateLock
            Descriptors = $descriptors
            Plan = $plan
            PlanDescriptor = $planDescriptor
            Identity = $identity
            IdentityDescriptor = $identityDescriptor
            Head = $sourceHead
            HeadDescriptor = $sourceHeadDescriptor
            CurrentHead = $head
            CurrentHeadDescriptor = $headDescriptor
            CandidateReceiptDescriptor = $receiptDescriptors[4]
            ReceiptChainSha256 = $receiptChainSha256
            PromotionRequestSha256 = $promotionRequestSha256
            Files = @($lockedFiles)
            CandidateRoot = $candidate
        }
    }
    catch {
        foreach ($descriptor in $descriptors) {
            $descriptor.Stream.Dispose()
        }
        $stateLock.Stream.Dispose()
        throw
    }
}

function Close-FeedPromotionSourceSnapshot {
    param([AllowNull()]$Snapshot)

    if ($null -eq $Snapshot) {
        return
    }
    foreach ($descriptor in $Snapshot.Descriptors) {
        $descriptor.Stream.Dispose()
    }
    $Snapshot.StateLock.Stream.Dispose()
}

function Assert-FeedPromotionSourceStillLocked {
    param([Parameter(Mandatory = $true)]$Snapshot)

    foreach ($descriptor in $Snapshot.Descriptors) {
        Assert-ProductionReleaseInputStillLocked `
            -Descriptor $descriptor `
            -Label "Locked feed-promotion input $($descriptor.FileName)"
    }
}

function Get-FeedPromotionMode {
    param(
        [Parameter(Mandatory = $true)][string]$Edition,
        [Parameter(Mandatory = $true)][string]$ExposureRing,
        [Parameter(Mandatory = $true)][string]$TargetChannel
    )

    if ($Edition -ceq 'Personal') {
        return [pscustomobject]@{
            FeedChannel = $TargetChannel
            PublishScope = 'channel-head'
        }
    }
    return [pscustomobject]@{
        FeedChannel = 'stable'
        PublishScope = if ($ExposureRing -ceq 'pilot') {
            'private-pilot-allowlist'
        }
        else {
            'public-stable'
        }
    }
}

function Get-FeedPromotionRequestInput {
    param([Parameter(Mandatory = $true)][string]$PromotionRoot)

    $path = Join-Path (Join-Path $PromotionRoot 'request') 'request.v1.json'
    $pending = $false
    if ((Test-Path -LiteralPath $path) -and
        (Test-Path -LiteralPath ($path + '.pending'))) {
        throw 'Committed feed-promotion request has unexpected pending residue.'
    }
    if (-not (Test-Path -LiteralPath $path) -and
        (Test-Path -LiteralPath ($path + '.pending'))) {
        $path += '.pending'
        $pending = $true
    }
    if (-not (Test-Path -LiteralPath $path)) {
        return $null
    }
    $input = Read-StrictProductionJsonFile `
        -Path $path `
        -Label 'Offline feed-promotion request' `
        -SchemaPath $script:RequestSchemaPath
    [void](Assert-CanonicalProductionJsonInput `
        -Input $input `
        -Label 'Offline feed-promotion request')
    $input | Add-Member -NotePropertyName Pending -NotePropertyValue $pending
    return $input
}

function Get-FeedPromotionRequestComparable {
    param([Parameter(Mandatory = $true)][psobject]$Request)

    return [ordered]@{
        orchestrationId = [string]$Request.orchestrationId
        edition = [string]$Request.edition
        exposureRing = [string]$Request.exposureRing
        feedChannel = [string]$Request.feedChannel
        publishScope = [string]$Request.publishScope
        releaseSetId = [string]$Request.releaseSetId
        sourceState = $Request.sourceState
        expectedFeedIdentitySha256 = [string]$Request.expectedFeedIdentitySha256
        feedCas = $Request.feedCas
        feedCasSha256 = [string]$Request.feedCasSha256
        payloadSetSha256 = [string]$Request.payloadSetSha256
        files = @($Request.files)
        authorizationTrust = $Request.authorizationTrust
        productionAdmission = [string]$Request.productionAdmission
        networkPublishPerformed = [bool]$Request.networkPublishPerformed
    }
}

function New-FeedPromotionRequestValue {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$ExposureRing,
        [Parameter(Mandatory = $true)]$FeedCas,
        [Parameter(Mandatory = $true)][string]$ExpectedFeedIdentitySha256,
        [Parameter(Mandatory = $true)][DateTimeOffset]$NowUtc,
        [Parameter(Mandatory = $true)][int]$ResponseLifetimeMinutes,
        [Parameter(Mandatory = $true)][string]$OperationId,
        [Parameter(Mandatory = $true)][string]$RequestNonce
    )

    $mode = Get-FeedPromotionMode `
        -Edition ([string]$Snapshot.Plan.edition) `
        -ExposureRing $ExposureRing `
        -TargetChannel ([string]$Snapshot.Plan.targetChannel)
    $files = [Collections.Generic.List[object]]::new()
    foreach ($file in $Snapshot.Files) {
        $files.Add([ordered]@{
            role = [string]$file.role
            fileName = [string]$file.fileName
            relativePath = [string]$file.relativePath
            sizeBytes = [int64]$file.sizeBytes
            sha256 = [string]$file.sha256
        })
    }
    $payloadSetSha256 = Get-FeedPromotionDomainDigest `
        -Domain 'ensou-dsh-launcher-feed-promotion-payload-set-v1' `
        -Value @($files)
    $feedCasSha256 = Get-FeedPromotionDomainDigest `
        -Domain 'ensou-dsh-launcher-feed-promotion-cas-v1' `
        -Value $FeedCas
    $createdAt = $NowUtc.ToUniversalTime()
    $expiresAt = $createdAt.AddMinutes($ResponseLifetimeMinutes)
    return [ordered]@{
        schemaVersion = 1
        requestType = 'ensou-dsh-launcher-offline-feed-promotion-request'
        operationId = $OperationId
        orchestrationId = [string]$Snapshot.Plan.orchestrationId
        edition = [string]$Snapshot.Plan.edition
        exposureRing = $ExposureRing
        feedChannel = [string]$mode.FeedChannel
        publishScope = [string]$mode.PublishScope
        releaseSetId = [string]$Snapshot.Plan.releaseSetId
        sourceState = [ordered]@{
            schemaVersion = 2
            targetChannel = [string]$Snapshot.Plan.targetChannel
            revision = [int]$Snapshot.Head.revision
            phase = [string]$Snapshot.Head.phase
            planSizeBytes = [int64]$Snapshot.PlanDescriptor.SizeBytes
            planSha256 = [string]$Snapshot.PlanDescriptor.Sha256
            identitySizeBytes = [int64]$Snapshot.IdentityDescriptor.SizeBytes
            identitySha256 = [string]$Snapshot.IdentityDescriptor.Sha256
            headSizeBytes = [int64]$Snapshot.HeadDescriptor.SizeBytes
            headSha256 = [string]$Snapshot.HeadDescriptor.Sha256
            receiptChainStartRevision = 1
            receiptChainSha256 = [string]$Snapshot.ReceiptChainSha256
            candidateReceiptSha256 = [string]$Snapshot.CandidateReceiptDescriptor.Sha256
        }
        expectedFeedIdentitySha256 = $ExpectedFeedIdentitySha256
        feedCas = $FeedCas
        feedCasSha256 = $feedCasSha256
        payloadSetSha256 = $payloadSetSha256
        files = @($files)
        authorizationTrust = [ordered]@{
            algorithm = 'ES256'
            keyId = [string]$Snapshot.Plan.externalResponseTrusts.feedPromotion.keyId
            purpose = 'feed-promotion-response'
            x = [string]$Snapshot.Plan.externalResponseTrusts.feedPromotion.x
            y = [string]$Snapshot.Plan.externalResponseTrusts.feedPromotion.y
        }
        requestNonce = $RequestNonce
        createdAtUtc = ConvertTo-FeedPromotionUtc -Value $createdAt
        expiresAtUtc = ConvertTo-FeedPromotionUtc -Value $expiresAt
        productionAdmission = 'NO_GO'
        networkPublishPerformed = $false
    }
}

function Assert-FeedPromotionRequestMatchesSnapshot {
    param(
        [Parameter(Mandatory = $true)][psobject]$Request,
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$ExposureRing,
        [Parameter(Mandatory = $true)]$FeedCas,
        [Parameter(Mandatory = $true)][string]$ExpectedFeedIdentitySha256
    )

    $candidate = New-FeedPromotionRequestValue `
        -Snapshot $Snapshot `
        -ExposureRing $ExposureRing `
        -FeedCas $FeedCas `
        -ExpectedFeedIdentitySha256 $ExpectedFeedIdentitySha256 `
        -NowUtc ([DateTimeOffset]::UnixEpoch) `
        -ResponseLifetimeMinutes 1 `
        -OperationId ([string]$Request.operationId) `
        -RequestNonce ([string]$Request.requestNonce)
    $existingComparable = ConvertTo-ProductionJsonBytes `
        -Value (Get-FeedPromotionRequestComparable -Request $Request)
    $candidateComparable = ConvertTo-ProductionJsonBytes `
        -Value (Get-FeedPromotionRequestComparable -Request ([pscustomobject]$candidate))
    if (-not (Test-FeedPromotionBytesEqual `
            -Left $existingComparable `
            -Right $candidateComparable)) {
        throw 'Existing feed-promotion request conflicts with current locked inputs.'
    }
}

function Assert-FeedPromotionRequestPayload {
    param(
        [Parameter(Mandatory = $true)][string]$PromotionRoot,
        [Parameter(Mandatory = $true)][psobject]$Request,
        [Parameter(Mandatory = $true)]$Snapshot
    )

    $payloadRoot = Assert-FeedPromotionOrdinaryDirectory `
        -Path (Join-Path (Join-Path $PromotionRoot 'request') 'payload') `
        -Label 'Offline feed-promotion request payload'
    $allowed = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in @($Request.files)) {
        [void]$allowed.Add([string]$file.fileName)
    }
    foreach ($entry in Get-ChildItem -LiteralPath $payloadRoot -Force) {
        if ($entry.PSIsContainer -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $entry.Name.EndsWith('.pending', [StringComparison]::Ordinal) -or
            -not $allowed.Contains($entry.Name)) {
            throw "Offline feed-promotion request payload contains unexpected entry '$($entry.Name)'."
        }
    }
    foreach ($file in $Snapshot.Files) {
        $input = Open-ProductionReleaseInput `
            -Path (Join-Path $payloadRoot ([string]$file.fileName)) `
            -Label "Offline request payload role $($file.role)" `
            -MaximumBytes $script:MaximumPayloadBytes
        try {
            if ([int64]$input.SizeBytes -ne [int64]$file.sizeBytes -or
                [string]$input.Sha256 -cne [string]$file.sha256) {
                throw "Offline request payload role '$($file.role)' differs from locked source bytes."
            }
        }
        finally {
            $input.Stream.Dispose()
        }
    }
}

function Assert-FeedPromotionRequestInventory {
    param([Parameter(Mandatory = $true)][string]$PromotionRoot)

    $requestRoot = Assert-FeedPromotionOrdinaryDirectory `
        -Path (Join-Path $PromotionRoot 'request') `
        -Label 'Offline feed-promotion request directory'
    foreach ($entry in Get-ChildItem -LiteralPath $requestRoot -Force) {
        if ($entry.Name -notin @('request.v1.json', 'payload') -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($entry.Name -ceq 'payload' -and -not $entry.PSIsContainer) -or
            ($entry.Name -ceq 'request.v1.json' -and $entry.PSIsContainer)) {
            throw "Offline feed-promotion request directory contains unexpected entry '$($entry.Name)'."
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $requestRoot 'request.v1.json') -PathType Leaf) -or
        -not (Test-Path -LiteralPath (Join-Path $requestRoot 'payload') -PathType Container)) {
        throw 'Offline feed-promotion request directory is incomplete.'
    }
}

function Assert-FeedPromotionOfflineBundle {
    param(
        [Parameter(Mandatory = $true)][string]$PromotionRoot,
        [Parameter(Mandatory = $true)]$RequestInput,
        [Parameter(Mandatory = $true)]$ResponseInput,
        [Parameter(Mandatory = $true)]$Snapshot,
        [switch]$AllowPendingBundleHead
    )

    $responseRoot = Assert-FeedPromotionOrdinaryDirectory `
        -Path (Join-Path $PromotionRoot 'response') `
        -Label 'Offline feed-promotion response directory'
    $responseEntries = @(Get-ChildItem -LiteralPath $responseRoot -Force)
    if ($responseEntries.Count -ne 1 -or
        $responseEntries[0].Name -cne 'response.v1.json' -or
        $responseEntries[0].PSIsContainer -or
        ($responseEntries[0].Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Offline feed-promotion response directory has a non-exact inventory.'
    }
    $storedResponse = Open-ProductionReleaseInput `
        -Path $responseEntries[0].FullName `
        -Label 'Stored offline feed-promotion response' `
        -MaximumBytes $script:MaximumJsonBytes
    try {
        if ([int64]$storedResponse.SizeBytes -ne [int64]$ResponseInput.Bytes.LongLength -or
            [string]$storedResponse.Sha256 -cne [string]$ResponseInput.Sha256) {
            throw 'Stored offline feed-promotion response differs from authenticated bytes.'
        }
    }
    finally {
        $storedResponse.Stream.Dispose()
    }

    $bundleRoot = Assert-FeedPromotionOrdinaryDirectory `
        -Path (Join-Path $PromotionRoot 'bundle') `
        -Label 'Offline feed-promotion bundle directory'
    $bundleEntries = @(Get-ChildItem -LiteralPath $bundleRoot -Force)
    $requiredTop = @('payload', 'request.v1.json', 'response.v1.json')
    $allowedTop = if ($AllowPendingBundleHead) {
        $requiredTop + @('head.v1.json.pending')
    }
    else {
        $requiredTop + @('head.v1.json')
    }
    if (@($bundleEntries | Where-Object { $_.Name -notin $allowedTop }).Count -ne 0 -or
        @($requiredTop | Where-Object {
                -not (Test-Path -LiteralPath (Join-Path $bundleRoot $_))
            }).Count -ne 0 -or
        (-not $AllowPendingBundleHead -and
         $bundleEntries.Count -ne $allowedTop.Count)) {
        throw 'Offline feed-promotion bundle has a non-exact top-level inventory.'
    }
    $bundleRequest = Open-ProductionReleaseInput `
        -Path (Join-Path $bundleRoot 'request.v1.json') `
        -Label 'Bundled feed-promotion request' `
        -MaximumBytes $script:MaximumJsonBytes
    $bundleResponse = $null
    try {
        $bundleResponse = Open-ProductionReleaseInput `
            -Path (Join-Path $bundleRoot 'response.v1.json') `
            -Label 'Bundled feed-promotion response' `
            -MaximumBytes $script:MaximumJsonBytes
        if ([string]$bundleRequest.Sha256 -cne [string]$RequestInput.Sha256 -or
            [int64]$bundleRequest.SizeBytes -ne [int64]$RequestInput.Bytes.LongLength -or
            [string]$bundleResponse.Sha256 -cne [string]$ResponseInput.Sha256 -or
            [int64]$bundleResponse.SizeBytes -ne [int64]$ResponseInput.Bytes.LongLength) {
            throw 'Offline feed-promotion bundle request/response bytes are not exact.'
        }
    }
    finally {
        if ($null -ne $bundleResponse) {
            $bundleResponse.Stream.Dispose()
        }
        $bundleRequest.Stream.Dispose()
    }
    $payloadRoot = Assert-FeedPromotionOrdinaryDirectory `
        -Path (Join-Path $bundleRoot 'payload') `
        -Label 'Offline feed-promotion bundle payload directory'
    $payloadEntries = @(Get-ChildItem -LiteralPath $payloadRoot -Force)
    if ($payloadEntries.Count -ne $Snapshot.Files.Count) {
        throw 'Offline feed-promotion bundle payload has an incorrect file count.'
    }
    foreach ($file in $Snapshot.Files) {
        $bundled = Open-ProductionReleaseInput `
            -Path (Join-Path $payloadRoot ([string]$file.fileName)) `
            -Label "Bundled feed-promotion role $($file.role)" `
            -MaximumBytes $script:MaximumPayloadBytes
        try {
            if ([int64]$bundled.SizeBytes -ne [int64]$file.sizeBytes -or
                [string]$bundled.Sha256 -cne [string]$file.sha256) {
                throw "Bundled feed-promotion role '$($file.role)' differs from locked bytes."
            }
        }
        finally {
            $bundled.Stream.Dispose()
        }
    }
    return Get-FeedPromotionBundleSetSha256 `
        -RequestSha256 ([string]$RequestInput.Sha256) `
        -RequestSizeBytes ([int64]$RequestInput.Bytes.LongLength) `
        -ResponseSha256 ([string]$ResponseInput.Sha256) `
        -ResponseSizeBytes ([int64]$ResponseInput.Bytes.LongLength) `
        -Files @($Snapshot.Files)
}

function New-ProductionFeedPromotionRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$PromotionRoot,
        [Parameter(Mandatory = $true)][string]$SourceStateRoot,
        [Parameter(Mandatory = $true)][string]$CandidateRoot,
        [Parameter(Mandatory = $true)][ValidateSet('pilot', 'stable')]
        [string]$ExposureRing,
        [Parameter(Mandatory = $true)]$ExpectedChannelHead,
        [Parameter(Mandatory = $true)]$ExpectedJournalHead,
        [Parameter(Mandatory = $true)][string]$ExpectedFeedIdentitySha256,
        [Parameter(Mandatory = $true)][string]$ExpectedSourcePlanSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedSourceIdentitySha256,
        [Parameter(Mandatory = $true)][string]$ExpectedSourceHeadSha256,
        [ValidateRange(1, 60)][int]$ResponseLifetimeMinutes = 30,
        [DateTimeOffset]$NowUtc = [DateTimeOffset]::UtcNow,
        [ValidateSet(
            '', 'AfterRequestPending', 'AfterRequestCommit',
            'AfterFirstPayloadCommit', 'AfterReadyHeadPending')]
        [string]$FaultPoint = ''
    )

    $promotionLock = Enter-FeedPromotionLock -PromotionRoot $PromotionRoot
    $snapshot = $null
    try {
        Assert-FeedPromotionPathSeparation `
            -First $promotionLock.Root `
            -Second $SourceStateRoot `
            -Label 'Promotion output and production state'
        Assert-FeedPromotionPathSeparation `
            -First $promotionLock.Root `
            -Second $CandidateRoot `
            -Label 'Promotion output and feed candidate'
        $snapshot = Open-FeedPromotionSourceSnapshot `
            -StateRoot $SourceStateRoot `
            -CandidateRoot $CandidateRoot `
            -ExposureRing $ExposureRing `
            -ExpectedSourcePlanSha256 $ExpectedSourcePlanSha256 `
            -ExpectedSourceIdentitySha256 $ExpectedSourceIdentitySha256 `
            -ExpectedSourceHeadSha256 $ExpectedSourceHeadSha256
        $feedCas = [ordered]@{
            channelHead = ConvertTo-FeedPromotionRawStateExpectation `
                -Value $ExpectedChannelHead `
                -Label 'Expected channel head'
            journalHead = ConvertTo-FeedPromotionRawStateExpectation `
                -Value $ExpectedJournalHead `
                -Label 'Expected journal head'
        }
        if ($ExpectedFeedIdentitySha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'Expected production feed identity must be one exact SHA-256.'
        }
        $requestRoot = Join-Path $promotionLock.Root 'request'
        if (-not (Test-Path -LiteralPath $requestRoot)) {
            [IO.Directory]::CreateDirectory($requestRoot) | Out-Null
        }
        [void](Assert-FeedPromotionOrdinaryDirectory `
            -Path $requestRoot `
            -Label 'Offline promotion request directory')
        $payloadRoot = Join-Path $requestRoot 'payload'
        if (-not (Test-Path -LiteralPath $payloadRoot)) {
            [IO.Directory]::CreateDirectory($payloadRoot) | Out-Null
        }
        [void](Assert-FeedPromotionOrdinaryDirectory `
            -Path $payloadRoot `
            -Label 'Offline promotion request payload directory')

        $existing = Get-FeedPromotionRequestInput -PromotionRoot $promotionLock.Root
        if ($null -eq $existing) {
            $nonceBytes = [byte[]]::new(32)
            [Security.Cryptography.RandomNumberGenerator]::Fill($nonceBytes)
            $request = New-FeedPromotionRequestValue `
                -Snapshot $snapshot `
                -ExposureRing $ExposureRing `
                -FeedCas $feedCas `
                -ExpectedFeedIdentitySha256 $ExpectedFeedIdentitySha256 `
                -NowUtc $NowUtc `
                -ResponseLifetimeMinutes $ResponseLifetimeMinutes `
                -OperationId ([Guid]::NewGuid().ToString('N')) `
                -RequestNonce (ConvertTo-FeedPromotionBase64Url -Bytes $nonceBytes)
            $requestBytes = ConvertTo-ProductionJsonBytes -Value $request
            [void](ConvertFrom-StrictProductionJsonBytes `
                -Bytes $requestBytes `
                -Label 'Generated offline feed-promotion request' `
                -SchemaPath $script:RequestSchemaPath)
            Write-FeedPromotionCreateOnlyFile `
                -Path (Join-Path $requestRoot 'request.v1.json') `
                -Bytes $requestBytes `
                -FaultAfterPending:($FaultPoint -ceq 'AfterRequestPending')
            if ($FaultPoint -ceq 'AfterRequestCommit') {
                throw 'INJECTED-CRASH-AFTER-PROMOTION-REQUEST-COMMIT'
            }
            $existing = Get-FeedPromotionRequestInput -PromotionRoot $promotionLock.Root
        }
        Assert-FeedPromotionRequestMatchesSnapshot `
            -Request $existing.Value `
            -Snapshot $snapshot `
            -ExposureRing $ExposureRing `
            -FeedCas $feedCas `
            -ExpectedFeedIdentitySha256 $ExpectedFeedIdentitySha256
        if ([bool]$existing.Pending) {
            Write-FeedPromotionCreateOnlyFile `
                -Path (Join-Path $requestRoot 'request.v1.json') `
                -Bytes $existing.Bytes
            $existing = Get-FeedPromotionRequestInput -PromotionRoot $promotionLock.Root
        }
        $expiresAt = ConvertFrom-ProductionUtc `
            -Value ([string]$existing.Value.expiresAtUtc) `
            -Label 'Offline promotion request expiry'
        if ($NowUtc.ToUniversalTime() -gt $expiresAt) {
            throw 'Existing offline feed-promotion request is expired.'
        }

        for ($index = 0; $index -lt $snapshot.Files.Count; $index++) {
            $file = $snapshot.Files[$index]
            $bytes = Read-ProductionReleaseInputBytes `
                -Descriptor $file.Descriptor `
                -Label "Locked feed-promotion candidate role $($file.role)"
            Write-FeedPromotionCreateOnlyFile `
                -Path (Join-Path $payloadRoot ([string]$file.fileName)) `
                -Bytes $bytes
            if ($index -eq 0 -and $FaultPoint -ceq 'AfterFirstPayloadCommit') {
                throw 'INJECTED-CRASH-AFTER-FIRST-PROMOTION-PAYLOAD'
            }
        }
        Assert-FeedPromotionRequestPayload `
            -PromotionRoot $promotionLock.Root `
            -Request $existing.Value `
            -Snapshot $snapshot
        Assert-FeedPromotionRequestInventory -PromotionRoot $promotionLock.Root
        Assert-FeedPromotionSourceStillLocked -Snapshot $snapshot

        $head = Get-FeedPromotionCurrentHead -PromotionRoot $promotionLock.Root
        if ($null -eq $head) {
            $headValue = [ordered]@{
                schemaVersion = 1
                stateType = 'ensou-dsh-launcher-offline-feed-promotion-state'
                operationId = [string]$existing.Value.operationId
                requestSha256 = [string]$existing.Sha256
                requestNonce = [string]$existing.Value.requestNonce
                sourceStateHeadSha256 = [string]$existing.Value.sourceState.headSha256
                payloadSetSha256 = [string]$existing.Value.payloadSetSha256
                status = 'PROMOTION_REQUEST_READY'
                productionAdmission = 'NO_GO'
                networkPublishPerformed = $false
                updatedAtUtc = [string]$existing.Value.createdAtUtc
            }
            Write-FeedPromotionHeadCas `
                -PromotionRoot $promotionLock.Root `
                -Bytes (ConvertTo-ProductionJsonBytes -Value $headValue) `
                -ExpectedHeadSha256 '' `
                -FaultAfterPending:($FaultPoint -ceq 'AfterReadyHeadPending')
            $head = Get-FeedPromotionCurrentHead -PromotionRoot $promotionLock.Root
        }
        if ([string]$head.Value.operationId -cne [string]$existing.Value.operationId -or
            [string]$head.Value.requestSha256 -cne [string]$existing.Sha256 -or
            [string]$head.Value.payloadSetSha256 -cne [string]$existing.Value.payloadSetSha256) {
            throw 'Offline promotion head conflicts with the exact persisted request.'
        }
        return [pscustomobject]@{
            PromotionRoot = $promotionLock.Root
            OperationId = [string]$existing.Value.operationId
            RequestPath = [string]$existing.Path
            RequestSha256 = [string]$existing.Sha256
            PromotionHeadSha256 = [string]$head.Sha256
            HeadSha256 = [string]$head.Sha256
            Status = [string]$head.Value.status
            ProductionAdmission = 'NO_GO'
            NetworkPublishPerformed = $false
        }
    }
    finally {
        Close-FeedPromotionSourceSnapshot -Snapshot $snapshot
        $promotionLock.Stream.Dispose()
    }
}

function Get-ProductionFeedPromotionResponseAuthenticationPayload {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][psobject]$Response)

    $body = [ordered]@{
        schemaVersion = [int]$Response.schemaVersion
        responseType = [string]$Response.responseType
        operationId = [string]$Response.operationId
        orchestrationId = [string]$Response.orchestrationId
        edition = [string]$Response.edition
        exposureRing = [string]$Response.exposureRing
        feedChannel = [string]$Response.feedChannel
        publishScope = [string]$Response.publishScope
        releaseSetId = [string]$Response.releaseSetId
        requestSha256 = [string]$Response.requestSha256
        requestNonce = [string]$Response.requestNonce
        basePromotionHeadSha256 = [string]$Response.basePromotionHeadSha256
        sourceStateHeadSha256 = [string]$Response.sourceStateHeadSha256
        payloadSetSha256 = [string]$Response.payloadSetSha256
        feedCasSha256 = [string]$Response.feedCasSha256
        decision = [string]$Response.decision
        completedAtUtc = [string]$Response.completedAtUtc
        requestExpiresAtUtc = [string]$Response.requestExpiresAtUtc
        productionAdmission = [string]$Response.productionAdmission
        networkPublishPerformed = [bool]$Response.networkPublishPerformed
        authentication = [ordered]@{
            algorithm = [string]$Response.authentication.algorithm
            keyId = [string]$Response.authentication.keyId
            purpose = [string]$Response.authentication.purpose
            payloadType = [string]$Response.authentication.payloadType
        }
    }
    $domain = $script:Utf8Strict.GetBytes(
        'ensou-dsh-launcher-feed-promotion-response-authentication-v1' + [char]10)
    $json = ConvertTo-ProductionJsonBytes -Value $body
    $payload = [byte[]]::new($domain.Length + $json.Length)
    [Array]::Copy($domain, 0, $payload, 0, $domain.Length)
    [Array]::Copy($json, 0, $payload, $domain.Length, $json.Length)
    return $payload
}

function Assert-FeedPromotionResponseAuthentication {
    param(
        [Parameter(Mandatory = $true)][psobject]$Response,
        [Parameter(Mandatory = $true)][psobject]$Trust
    )

    if ([string]$Trust.algorithm -cne 'ES256' -or
        [string]$Trust.purpose -cne 'feed-promotion-response' -or
        [string]$Response.authentication.algorithm -cne 'ES256' -or
        [string]$Response.authentication.keyId -cne [string]$Trust.keyId -or
        [string]$Response.authentication.purpose -cne 'feed-promotion-response' -or
        [string]$Response.authentication.payloadType -cne
            'ensou-dsh-launcher-feed-promotion-response-authentication-v1') {
        throw 'Feed-promotion response authentication does not match its isolated plan trust.'
    }
    $x = ConvertFrom-FeedPromotionBase64Url `
        -Value ([string]$Trust.x) `
        -Label 'Feed-promotion response key X'
    $y = ConvertFrom-FeedPromotionBase64Url `
        -Value ([string]$Trust.y) `
        -Label 'Feed-promotion response key Y'
    $signature = ConvertFrom-FeedPromotionBase64Url `
        -Value ([string]$Response.authentication.value) `
        -Label 'Feed-promotion response signature'
    if ($x.Length -ne 32 -or $y.Length -ne 32 -or $signature.Length -ne 64) {
        throw 'Feed-promotion response authentication uses invalid P-256 P1363 sizes.'
    }
    Assert-ProductionEs256P1363LowS `
        -Signature $signature `
        -Label 'Feed-promotion response signature'
    $parameters = [Security.Cryptography.ECParameters]::new()
    $parameters.Curve = [Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $point = [Security.Cryptography.ECPoint]::new()
    $point.X = $x
    $point.Y = $y
    $parameters.Q = $point
    $ecdsa = [Security.Cryptography.ECDsa]::Create()
    try {
        try {
            $ecdsa.ImportParameters($parameters)
        }
        catch {
            throw 'Feed-promotion response trust is not one valid P-256 public point.'
        }
        $payload = Get-ProductionFeedPromotionResponseAuthenticationPayload `
            -Response $Response
        if (-not $ecdsa.VerifyData(
                $payload,
                $signature,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
            throw 'Feed-promotion response authentication signature is invalid.'
        }
    }
    finally {
        $ecdsa.Dispose()
    }
}

function Assert-FeedPromotionResponseBinding {
    param(
        [Parameter(Mandatory = $true)][psobject]$Response,
        [Parameter(Mandatory = $true)]$RequestInput,
        [Parameter(Mandatory = $true)]$Head,
        [Parameter(Mandatory = $true)][DateTimeOffset]$NowUtc,
        [switch]$AllowCommittedReplay
    )

    $request = $RequestInput.Value
    if ([string]$Response.operationId -cne [string]$request.operationId -or
        [string]$Response.orchestrationId -cne [string]$request.orchestrationId -or
        [string]$Response.edition -cne [string]$request.edition -or
        [string]$Response.exposureRing -cne [string]$request.exposureRing -or
        [string]$Response.feedChannel -cne [string]$request.feedChannel -or
        [string]$Response.publishScope -cne [string]$request.publishScope -or
        [string]$Response.releaseSetId -cne [string]$request.releaseSetId -or
        [string]$Response.requestSha256 -cne [string]$RequestInput.Sha256 -or
        [string]$Response.requestNonce -cne [string]$request.requestNonce -or
        [string]$Response.basePromotionHeadSha256 -cne [string]$Head.Sha256 -or
        [string]$Response.sourceStateHeadSha256 -cne [string]$request.sourceState.headSha256 -or
        [string]$Response.payloadSetSha256 -cne [string]$request.payloadSetSha256 -or
        [string]$Response.feedCasSha256 -cne [string]$request.feedCasSha256 -or
        [string]$Response.requestExpiresAtUtc -cne [string]$request.expiresAtUtc -or
        [string]$Response.decision -cne 'AUTHORIZE_OFFLINE_BUNDLE' -or
        [string]$Response.productionAdmission -cne 'OFFLINE_BUNDLE_ONLY' -or
        [bool]$Response.networkPublishPerformed) {
        throw 'Feed-promotion response is not bound to the exact request and CAS head.'
    }
    $createdAt = ConvertFrom-ProductionUtc `
        -Value ([string]$request.createdAtUtc) `
        -Label 'Feed-promotion request creation time'
    $expiresAt = ConvertFrom-ProductionUtc `
        -Value ([string]$request.expiresAtUtc) `
        -Label 'Feed-promotion request expiry'
    $completedAt = ConvertFrom-ProductionUtc `
        -Value ([string]$Response.completedAtUtc) `
        -Label 'Feed-promotion response completion time'
    $now = $NowUtc.ToUniversalTime()
    if ($expiresAt -le $createdAt -or
        ($expiresAt - $createdAt) -gt [TimeSpan]::FromMinutes(60) -or
        $completedAt -lt $createdAt -or
        $completedAt -gt $expiresAt -or
        (-not $AllowCommittedReplay -and $completedAt -gt $now.AddMinutes(2)) -or
        (-not $AllowCommittedReplay -and $now -gt $expiresAt)) {
        throw 'Feed-promotion response is expired, future-dated, or outside its request lifetime.'
    }
}

function Get-FeedPromotionBundleSetSha256 {
    param(
        [Parameter(Mandatory = $true)][string]$RequestSha256,
        [Parameter(Mandatory = $true)][int64]$RequestSizeBytes,
        [Parameter(Mandatory = $true)][string]$ResponseSha256,
        [Parameter(Mandatory = $true)][int64]$ResponseSizeBytes,
        [Parameter(Mandatory = $true)][object[]]$Files
    )

    $inventory = [Collections.Generic.List[object]]::new()
    $inventory.Add([ordered]@{
        role = 'promotion-request'
        fileName = 'request.v1.json'
        relativePath = 'bundle/request.v1.json'
        sizeBytes = $RequestSizeBytes
        sha256 = $RequestSha256
    })
    $inventory.Add([ordered]@{
        role = 'promotion-response'
        fileName = 'response.v1.json'
        relativePath = 'bundle/response.v1.json'
        sizeBytes = $ResponseSizeBytes
        sha256 = $ResponseSha256
    })
    foreach ($file in $Files) {
        $inventory.Add([ordered]@{
            role = [string]$file.role
            fileName = [string]$file.fileName
            relativePath = 'bundle/payload/' + [string]$file.fileName
            sizeBytes = [int64]$file.sizeBytes
            sha256 = [string]$file.sha256
        })
    }
    return Get-FeedPromotionDomainDigest `
        -Domain 'ensou-dsh-launcher-feed-promotion-offline-bundle-v1' `
        -Value @($inventory)
}

function Open-FeedPromotionLockedJsonInput {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [string]$SchemaPath = ''
    )

    $descriptor = Open-ProductionReleaseInput `
        -Path $Path `
        -Label $Label `
        -MaximumBytes $script:MaximumJsonBytes
    try {
        $bytes = Read-ProductionReleaseInputBytes `
            -Descriptor $descriptor `
            -Label $Label
        $value = ConvertFrom-StrictProductionJsonBytes `
            -Bytes $bytes `
            -Label $Label `
            -SchemaPath $SchemaPath
        $descriptor | Add-Member -NotePropertyName Bytes -NotePropertyValue $bytes
        $descriptor | Add-Member -NotePropertyName Value -NotePropertyValue $value
        [void](Assert-CanonicalProductionJsonInput `
            -Input $descriptor `
            -Label $Label)
        return $descriptor
    }
    catch {
        $descriptor.Stream.Dispose()
        throw
    }
}

function Assert-FeedPromotionBundleAdmissionHeadContract {
    param([Parameter(Mandatory = $true)]$BundleHeadInput)

    Assert-ExactProductionJsonMembers `
        -Value $BundleHeadInput.Value `
        -Expected @(
            'schemaVersion', 'stateType', 'operationId', 'requestSha256',
            'requestNonce', 'sourceStateHeadSha256', 'payloadSetSha256',
            'basePromotionHeadSha256', 'responseSha256',
            'bundleSetSha256', 'status', 'productionAdmission',
            'networkPublishPerformed', 'updatedAtUtc') `
        -Label 'Locked offline promotion bundle head'
    if ([int]$BundleHeadInput.Value.schemaVersion -ne 1 -or
        [string]$BundleHeadInput.Value.stateType -cne
            'ensou-dsh-launcher-offline-feed-promotion-bundle' -or
        [string]$BundleHeadInput.Value.operationId -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$BundleHeadInput.Value.requestSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$BundleHeadInput.Value.sourceStateHeadSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$BundleHeadInput.Value.payloadSetSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$BundleHeadInput.Value.basePromotionHeadSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$BundleHeadInput.Value.responseSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$BundleHeadInput.Value.bundleSetSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$BundleHeadInput.Value.status -cne 'EXTERNAL_PUBLISH_BUNDLE_READY' -or
        [string]$BundleHeadInput.Value.productionAdmission -cne 'NO_GO' -or
        [bool]$BundleHeadInput.Value.networkPublishPerformed) {
        throw 'Locked offline promotion bundle head violates its fail-closed contract.'
    }
    [void](ConvertFrom-ProductionUtc `
        -Value ([string]$BundleHeadInput.Value.updatedAtUtc) `
        -Label 'Locked offline promotion bundle head timestamp')
}

function Close-ProductionFeedPromotionBundleAdmission {
    [CmdletBinding()]
    param([AllowNull()]$Admission)

    if ($null -eq $Admission) {
        return
    }
    $heldDescriptors = @($Admission.HeldDescriptors)
    for ($index = $heldDescriptors.Count - 1; $index -ge 0; $index--) {
        $descriptor = $heldDescriptors[$index]
        if ($null -ne $descriptor -and
            $null -ne $descriptor.PSObject.Properties['Stream'] -and
            $null -ne $descriptor.Stream) {
            $descriptor.Stream.Dispose()
        }
    }
    if ($null -ne $Admission.PSObject.Properties['PromotionLock'] -and
        $null -ne $Admission.PromotionLock -and
        $null -ne $Admission.PromotionLock.Stream) {
        $Admission.PromotionLock.Stream.Dispose()
    }
}

function Open-ProductionFeedPromotionBundleAdmission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$PromotionRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedPromotionHeadSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedBundleHeadSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedSourceHeadSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedRequestSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedResponseSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedBundleSetSha256,
        [ValidateSet('Enterprise', 'Personal')][string]$ExpectedEdition = 'Enterprise'
    )

    # This is deliberately the first acquired lock. The caller may acquire a
    # production-state lock only after this complete external bundle is pinned.
    $promotionLock = Enter-FeedPromotionLock -PromotionRoot $PromotionRoot
    $heldDescriptors = [Collections.Generic.List[object]]::new()
    try {
        foreach ($expected in @(
                [pscustomobject]@{
                    Label = 'Expected promotion head SHA-256'
                    Value = $ExpectedPromotionHeadSha256
                },
                [pscustomobject]@{
                    Label = 'Expected bundle head SHA-256'
                    Value = $ExpectedBundleHeadSha256
                },
                [pscustomobject]@{
                    Label = 'Expected source head SHA-256'
                    Value = $ExpectedSourceHeadSha256
                },
                [pscustomobject]@{
                    Label = 'Expected request SHA-256'
                    Value = $ExpectedRequestSha256
                },
                [pscustomobject]@{
                    Label = 'Expected response SHA-256'
                    Value = $ExpectedResponseSha256
                },
                [pscustomobject]@{
                    Label = 'Expected bundle-set SHA-256'
                    Value = $ExpectedBundleSetSha256
                })) {
            if ([string]$expected.Value -cnotmatch '^[0-9a-f]{64}$') {
                throw "$($expected.Label) must be one exact lowercase SHA-256."
            }
        }

        if (Test-Path -LiteralPath (Join-Path $promotionLock.Root 'head.json.pending')) {
            throw 'Completed external promotion bundle has unresolved promotion-head residue.'
        }
        $promotionHeadEntry = Get-Item `
            -LiteralPath (Join-Path $promotionLock.Root 'head.json') `
            -Force `
            -ErrorAction Stop
        if ($promotionHeadEntry.Name -cne 'head.json' -or
            $promotionHeadEntry.PSIsContainer -or
            ($promotionHeadEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Completed external promotion bundle has a noncanonical promotion-head path.'
        }
        $bundleRoot = Assert-FeedPromotionOrdinaryDirectory `
            -Path (Join-Path $promotionLock.Root 'bundle') `
            -Label 'Completed external promotion bundle directory'
        if ((Get-Item -LiteralPath $bundleRoot -Force).Name -cne 'bundle') {
            throw 'Completed external promotion bundle directory name is not canonical.'
        }
        $bundleEntries = @(Get-ChildItem -LiteralPath $bundleRoot -Force)
        $requiredTop = @(
            'request.v1.json', 'response.v1.json', 'head.v1.json', 'payload')
        if ($bundleEntries.Count -ne $requiredTop.Count -or
            @($bundleEntries | Where-Object { $_.Name -cnotin $requiredTop }).Count -ne 0) {
            throw 'Completed external promotion bundle has a non-exact top-level inventory.'
        }
        foreach ($entry in $bundleEntries) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($entry.Name -ceq 'payload' -and -not $entry.PSIsContainer) -or
                ($entry.Name -cne 'payload' -and $entry.PSIsContainer)) {
                throw "Completed external promotion bundle entry '$($entry.Name)' has an invalid type."
            }
        }

        $requestInput = Open-FeedPromotionLockedJsonInput `
            -Path (Join-Path $bundleRoot 'request.v1.json') `
            -Label 'Locked bundled feed-promotion request' `
            -SchemaPath $script:RequestSchemaPath
        $heldDescriptors.Add($requestInput)
        $responseInput = Open-FeedPromotionLockedJsonInput `
            -Path (Join-Path $bundleRoot 'response.v1.json') `
            -Label 'Locked bundled feed-promotion response' `
            -SchemaPath $script:ResponseSchemaPath
        $heldDescriptors.Add($responseInput)
        $promotionHeadInput = Open-FeedPromotionLockedJsonInput `
            -Path (Join-Path $promotionLock.Root 'head.json') `
            -Label 'Locked feed-promotion CAS head' `
            -SchemaPath $script:PromotionHeadSchemaPath
        $heldDescriptors.Add($promotionHeadInput)
        $bundleHeadInput = Open-FeedPromotionLockedJsonInput `
            -Path (Join-Path $bundleRoot 'head.v1.json') `
            -Label 'Locked offline promotion bundle head'
        $heldDescriptors.Add($bundleHeadInput)
        Assert-FeedPromotionBundleAdmissionHeadContract `
            -BundleHeadInput $bundleHeadInput

        # Existing Enterprise callers keep their exact five-file admission.
        # Personal must be selected explicitly and cannot use this entry point
        # to admit a stable/plugin publication or an Enterprise-shaped bundle.
        $requiredRoles = if ($ExpectedEdition -ceq 'Personal') {
            @('release-manifest', 'launcher', 'runtime')
        }
        else {
            @('release-manifest', 'release-public-key', 'launcher', 'runtime',
                'plugin-policy')
        }
        if ([string]$requestInput.Value.edition -cne $ExpectedEdition -or
            @($requestInput.Value.files).Count -ne $requiredRoles.Count) {
            throw "Completed external promotion bundle must match the caller-pinned $ExpectedEdition edition and its exact payload count."
        }
        if ($ExpectedEdition -ceq 'Personal' -and
            ([string]$requestInput.Value.exposureRing -cne 'pilot' -or
             [string]$requestInput.Value.feedChannel -cne 'pilot' -or
             [string]$requestInput.Value.publishScope -cne 'channel-head')) {
            throw 'Completed Personal promotion bundle is restricted to Pilot channel-head publication.'
        }
        $payloadRoot = Assert-FeedPromotionOrdinaryDirectory `
            -Path (Join-Path $bundleRoot 'payload') `
            -Label 'Completed external promotion bundle payload directory'
        $payloadEntries = @(Get-ChildItem -LiteralPath $payloadRoot -Force)
        if ($payloadEntries.Count -ne $requiredRoles.Count) {
            throw "Completed external promotion bundle payload inventory must contain exactly $($requiredRoles.Count) files."
        }
        $allowedPayloadNames = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        $payloadInputs = [Collections.Generic.List[object]]::new()
        for ($index = 0; $index -lt $requiredRoles.Count; $index++) {
            $recorded = @($requestInput.Value.files)[$index]
            if ([string]$recorded.role -cne $requiredRoles[$index] -or
                [string]$recorded.relativePath -cne
                    ('payload/' + [string]$recorded.fileName) -or
                -not $allowedPayloadNames.Add([string]$recorded.fileName)) {
                throw "Completed external promotion payload index $index violates its fixed $ExpectedEdition role order."
            }
        }
        foreach ($entry in $payloadEntries) {
            if ($entry.PSIsContainer -or
                ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                -not $allowedPayloadNames.Contains($entry.Name) -or
                @(@($requestInput.Value.files) | Where-Object {
                        [string]$_.fileName -ceq $entry.Name
                    }).Count -ne 1) {
                throw "Completed external promotion payload contains unexpected entry '$($entry.Name)'."
            }
        }
        for ($index = 0; $index -lt $requiredRoles.Count; $index++) {
            $recorded = @($requestInput.Value.files)[$index]
            $descriptor = Open-ProductionReleaseInput `
                -Path (Join-Path $payloadRoot ([string]$recorded.fileName)) `
                -Label "Locked external promotion payload role $($recorded.role)" `
                -MaximumBytes $script:MaximumPayloadBytes
            $heldDescriptors.Add($descriptor)
            if ([int64]$descriptor.SizeBytes -ne [int64]$recorded.sizeBytes -or
                [string]$descriptor.Sha256 -cne [string]$recorded.sha256) {
                throw "External promotion payload role '$($recorded.role)' differs from its request identity."
            }
            $payloadInputs.Add([pscustomobject]@{
                role = [string]$recorded.role
                fileName = [string]$recorded.fileName
                relativePath = [string]$recorded.relativePath
                sizeBytes = [int64]$descriptor.SizeBytes
                sha256 = [string]$descriptor.Sha256
                Descriptor = $descriptor
            })
        }

        $computedPayloadSetSha256 = Get-FeedPromotionDomainDigest `
            -Domain 'ensou-dsh-launcher-feed-promotion-payload-set-v1' `
            -Value @($requestInput.Value.files)
        $computedBundleSetSha256 = Get-FeedPromotionBundleSetSha256 `
            -RequestSha256 ([string]$requestInput.Sha256) `
            -RequestSizeBytes ([int64]$requestInput.SizeBytes) `
            -ResponseSha256 ([string]$responseInput.Sha256) `
            -ResponseSizeBytes ([int64]$responseInput.SizeBytes) `
            -Files @($requestInput.Value.files)

        if ([string]$promotionHeadInput.Sha256 -cne $ExpectedPromotionHeadSha256 -or
            [string]$bundleHeadInput.Sha256 -cne $ExpectedBundleHeadSha256 -or
            [string]$requestInput.Sha256 -cne $ExpectedRequestSha256 -or
            [string]$responseInput.Sha256 -cne $ExpectedResponseSha256 -or
            [string]$requestInput.Value.sourceState.headSha256 -cne
                $ExpectedSourceHeadSha256 -or
            $computedPayloadSetSha256 -cne [string]$requestInput.Value.payloadSetSha256 -or
            $computedBundleSetSha256 -cne $ExpectedBundleSetSha256) {
            throw 'Completed external promotion bundle does not equal every caller-pinned digest.'
        }

        $promotionHead = $promotionHeadInput.Value
        $request = $requestInput.Value
        if ([string]$promotionHead.operationId -cne [string]$request.operationId -or
            [string]$promotionHead.requestSha256 -cne [string]$requestInput.Sha256 -or
            [string]$promotionHead.requestNonce -cne [string]$request.requestNonce -or
            [string]$promotionHead.sourceStateHeadSha256 -cne
                $ExpectedSourceHeadSha256 -or
            [string]$promotionHead.payloadSetSha256 -cne
                $computedPayloadSetSha256 -or
            [string]$promotionHead.updatedAtUtc -cne [string]$request.createdAtUtc) {
            throw 'Locked promotion head is not bound to the exact bundled request.'
        }
        Assert-FeedPromotionResponseBinding `
            -Response $responseInput.Value `
            -RequestInput $requestInput `
            -Head $promotionHeadInput `
            -NowUtc ([DateTimeOffset]::UtcNow) `
            -AllowCommittedReplay
        Assert-FeedPromotionResponseAuthentication `
            -Response $responseInput.Value `
            -Trust $request.authorizationTrust

        $bundleHead = $bundleHeadInput.Value
        if ([string]$bundleHead.operationId -cne [string]$request.operationId -or
            [string]$bundleHead.requestSha256 -cne [string]$requestInput.Sha256 -or
            [string]$bundleHead.requestNonce -cne [string]$request.requestNonce -or
            [string]$bundleHead.sourceStateHeadSha256 -cne
                $ExpectedSourceHeadSha256 -or
            [string]$bundleHead.payloadSetSha256 -cne
                $computedPayloadSetSha256 -or
            [string]$bundleHead.basePromotionHeadSha256 -cne
                [string]$promotionHeadInput.Sha256 -or
            [string]$bundleHead.responseSha256 -cne
                [string]$responseInput.Sha256 -or
            [string]$bundleHead.bundleSetSha256 -cne
                $computedBundleSetSha256 -or
            [string]$bundleHead.updatedAtUtc -cne
                [string]$responseInput.Value.completedAtUtc) {
            throw 'Locked bundle head is not bound to the exact completed external bundle.'
        }
        foreach ($descriptor in $heldDescriptors) {
            Assert-ProductionReleaseInputStillLocked `
                -Descriptor $descriptor `
                -Label "Locked external promotion input $($descriptor.FileName)"
        }

        return [pscustomobject]@{
            Root = $promotionLock.Root
            PromotionRoot = $promotionLock.Root
            PromotionLock = $promotionLock
            RequestInput = $requestInput
            ResponseInput = $responseInput
            PromotionHeadInput = $promotionHeadInput
            BundleHeadInput = $bundleHeadInput
            PayloadInputs = @($payloadInputs)
            HeldDescriptors = @($heldDescriptors)
            PromotionHeadSha256 = [string]$promotionHeadInput.Sha256
            BundleHeadSha256 = [string]$bundleHeadInput.Sha256
            BundleSetSha256 = $computedBundleSetSha256
            RequestSha256 = [string]$requestInput.Sha256
            ResponseSha256 = [string]$responseInput.Sha256
            SourceHeadSha256 = $ExpectedSourceHeadSha256
            OperationId = [string]$request.operationId
            Status = [string]$bundleHead.status
            ProductionAdmission = 'NO_GO'
            NetworkPublishPerformed = $false
        }
    }
    catch {
        for ($index = $heldDescriptors.Count - 1; $index -ge 0; $index--) {
            $heldDescriptors[$index].Stream.Dispose()
        }
        $promotionLock.Stream.Dispose()
        throw
    }
}

function Import-ProductionFeedPromotionResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$PromotionRoot,
        [Parameter(Mandatory = $true)][string]$SourceStateRoot,
        [Parameter(Mandatory = $true)][string]$CandidateRoot,
        [Parameter(Mandatory = $true)][ValidateSet('pilot', 'stable')]
        [string]$ExposureRing,
        [Parameter(Mandatory = $true)][string]$ResponsePath,
        [Parameter(Mandatory = $true)][string]$ExpectedPromotionHeadSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedSourcePlanSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedSourceIdentitySha256,
        [Parameter(Mandatory = $true)][string]$ExpectedSourceHeadSha256,
        [switch]$AllowPersonalPilotPromotionRequestState,
        [ValidateSet(
            '', 'AfterResponsePending', 'AfterResponseCommit',
            'AfterFirstBundlePayloadCommit', 'AfterReadyHeadPending')]
        [string]$FaultPoint = ''
    )

    if ($ExpectedPromotionHeadSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Response import requires the exact current promotion head SHA-256.'
    }
    $observedNowUtc = [DateTimeOffset]::UtcNow
    $responseInput = Read-StrictProductionJsonFile `
        -Path $ResponsePath `
        -Label 'External feed-promotion response' `
        -SchemaPath $script:ResponseSchemaPath
    [void](Assert-CanonicalProductionJsonInput `
        -Input $responseInput `
        -Label 'External feed-promotion response')
    $promotionLock = Enter-FeedPromotionLock -PromotionRoot $PromotionRoot
    $snapshot = $null
    try {
        Assert-FeedPromotionPathSeparation `
            -First $promotionLock.Root `
            -Second $SourceStateRoot `
            -Label 'Promotion output and production state'
        Assert-FeedPromotionPathSeparation `
            -First $promotionLock.Root `
            -Second $CandidateRoot `
            -Label 'Promotion output and feed candidate'
        $requestInput = Get-FeedPromotionRequestInput -PromotionRoot $promotionLock.Root
        if ($null -eq $requestInput) {
            throw 'External response cannot be imported before an exact promotion request exists.'
        }
        $head = Get-FeedPromotionCurrentHead -PromotionRoot $promotionLock.Root
        if ($null -eq $head) {
            throw 'External response cannot be imported before the request CAS head exists.'
        }
        $bundleHead = Get-FeedPromotionBundleHead `
            -PromotionRoot $promotionLock.Root
        if ($null -ne $bundleHead) {
            if ([string]$head.Sha256 -cne $ExpectedPromotionHeadSha256 -or
                [string]$bundleHead.Value.basePromotionHeadSha256 -cne
                    $ExpectedPromotionHeadSha256 -or
                [string]$bundleHead.Value.responseSha256 -cne
                    [string]$responseInput.Sha256) {
                throw 'Committed offline bundle conflicts with this response import retry.'
            }
            Assert-FeedPromotionResponseBinding `
                -Response $responseInput.Value `
                -RequestInput $requestInput `
                -Head $head `
                -NowUtc $observedNowUtc `
                -AllowCommittedReplay
            Assert-FeedPromotionResponseAuthentication `
                -Response $responseInput.Value `
                -Trust $requestInput.Value.authorizationTrust
            $snapshot = Open-FeedPromotionSourceSnapshot `
                -StateRoot $SourceStateRoot `
                -CandidateRoot $CandidateRoot `
                -ExposureRing $ExposureRing `
                -ExpectedSourcePlanSha256 $ExpectedSourcePlanSha256 `
                -ExpectedSourceIdentitySha256 $ExpectedSourceIdentitySha256 `
                -ExpectedSourceHeadSha256 $ExpectedSourceHeadSha256 `
                -AllowPersonalPilotPromotionRequestState:$AllowPersonalPilotPromotionRequestState
            if ($AllowPersonalPilotPromotionRequestState -and
                [string]$requestInput.Sha256 -cne [string]$snapshot.PromotionRequestSha256) {
                throw 'External Personal promotion request differs from the exact request sealed by r8.'
            }
            $feedCas = [ordered]@{
                channelHead = ConvertTo-FeedPromotionRawStateExpectation `
                    -Value $requestInput.Value.feedCas.channelHead `
                    -Label 'Persisted expected channel head'
                journalHead = ConvertTo-FeedPromotionRawStateExpectation `
                    -Value $requestInput.Value.feedCas.journalHead `
                    -Label 'Persisted expected journal head'
            }
            Assert-FeedPromotionRequestMatchesSnapshot `
                -Request $requestInput.Value `
                -Snapshot $snapshot `
                -ExposureRing $ExposureRing `
                -FeedCas $feedCas `
                -ExpectedFeedIdentitySha256 ([string]$requestInput.Value.expectedFeedIdentitySha256)
            Assert-FeedPromotionRequestPayload `
                -PromotionRoot $promotionLock.Root `
                -Request $requestInput.Value `
                -Snapshot $snapshot
            Assert-FeedPromotionRequestInventory -PromotionRoot $promotionLock.Root
            $bundleSetSha256 = Assert-FeedPromotionOfflineBundle `
                -PromotionRoot $promotionLock.Root `
                -RequestInput $requestInput `
                -ResponseInput $responseInput `
                -Snapshot $snapshot
            Assert-FeedPromotionSourceStillLocked -Snapshot $snapshot
            if ($bundleSetSha256 -cne [string]$bundleHead.Value.bundleSetSha256) {
                throw 'Committed offline bundle digest differs from its promotion head.'
            }
            return [pscustomobject]@{
                PromotionRoot = $promotionLock.Root
                OperationId = [string]$bundleHead.Value.operationId
                ResponseSha256 = [string]$bundleHead.Value.responseSha256
                BundleSetSha256 = [string]$bundleHead.Value.bundleSetSha256
                PromotionHeadSha256 = [string]$head.Sha256
                BundleHeadSha256 = [string]$bundleHead.Sha256
                HeadSha256 = [string]$bundleHead.Sha256
                Status = [string]$bundleHead.Value.status
                ProductionAdmission = 'NO_GO'
                NetworkPublishPerformed = $false
            }
        }
        if ([string]$head.Value.status -cne 'PROMOTION_REQUEST_READY' -or
            [string]$head.Sha256 -cne $ExpectedPromotionHeadSha256) {
            throw 'External response rejected a stale or non-request promotion head.'
        }
        Assert-FeedPromotionResponseBinding `
            -Response $responseInput.Value `
            -RequestInput $requestInput `
            -Head $head `
            -NowUtc $observedNowUtc
        Assert-FeedPromotionResponseAuthentication `
            -Response $responseInput.Value `
            -Trust $requestInput.Value.authorizationTrust

        $snapshot = Open-FeedPromotionSourceSnapshot `
            -StateRoot $SourceStateRoot `
            -CandidateRoot $CandidateRoot `
            -ExposureRing $ExposureRing `
            -ExpectedSourcePlanSha256 $ExpectedSourcePlanSha256 `
            -ExpectedSourceIdentitySha256 $ExpectedSourceIdentitySha256 `
            -ExpectedSourceHeadSha256 $ExpectedSourceHeadSha256 `
            -AllowPersonalPilotPromotionRequestState:$AllowPersonalPilotPromotionRequestState
        if ($AllowPersonalPilotPromotionRequestState -and
            [string]$requestInput.Sha256 -cne [string]$snapshot.PromotionRequestSha256) {
            throw 'External Personal promotion request differs from the exact request sealed by r8.'
        }
        $feedCas = [ordered]@{
            channelHead = ConvertTo-FeedPromotionRawStateExpectation `
                -Value $requestInput.Value.feedCas.channelHead `
                -Label 'Persisted expected channel head'
            journalHead = ConvertTo-FeedPromotionRawStateExpectation `
                -Value $requestInput.Value.feedCas.journalHead `
                -Label 'Persisted expected journal head'
        }
        Assert-FeedPromotionRequestMatchesSnapshot `
            -Request $requestInput.Value `
            -Snapshot $snapshot `
            -ExposureRing $ExposureRing `
            -FeedCas $feedCas `
            -ExpectedFeedIdentitySha256 ([string]$requestInput.Value.expectedFeedIdentitySha256)
        Assert-FeedPromotionRequestPayload `
            -PromotionRoot $promotionLock.Root `
            -Request $requestInput.Value `
            -Snapshot $snapshot
        Assert-FeedPromotionSourceStillLocked -Snapshot $snapshot

        $responseRoot = Join-Path $promotionLock.Root 'response'
        if (-not (Test-Path -LiteralPath $responseRoot)) {
            [IO.Directory]::CreateDirectory($responseRoot) | Out-Null
        }
        [void](Assert-FeedPromotionOrdinaryDirectory `
            -Path $responseRoot `
            -Label 'Offline promotion response directory')
        Write-FeedPromotionCreateOnlyFile `
            -Path (Join-Path $responseRoot 'response.v1.json') `
            -Bytes $responseInput.Bytes `
            -FaultAfterPending:($FaultPoint -ceq 'AfterResponsePending')
        if ($FaultPoint -ceq 'AfterResponseCommit') {
            throw 'INJECTED-CRASH-AFTER-PROMOTION-RESPONSE-COMMIT'
        }

        $bundleRoot = Join-Path $promotionLock.Root 'bundle'
        if (-not (Test-Path -LiteralPath $bundleRoot)) {
            [IO.Directory]::CreateDirectory($bundleRoot) | Out-Null
        }
        [void](Assert-FeedPromotionOrdinaryDirectory `
            -Path $bundleRoot `
            -Label 'Offline promotion bundle directory')
        $bundlePayloadRoot = Join-Path $bundleRoot 'payload'
        if (-not (Test-Path -LiteralPath $bundlePayloadRoot)) {
            [IO.Directory]::CreateDirectory($bundlePayloadRoot) | Out-Null
        }
        [void](Assert-FeedPromotionOrdinaryDirectory `
            -Path $bundlePayloadRoot `
            -Label 'Offline promotion bundle payload directory')
        Write-FeedPromotionCreateOnlyFile `
            -Path (Join-Path $bundleRoot 'request.v1.json') `
            -Bytes $requestInput.Bytes
        Write-FeedPromotionCreateOnlyFile `
            -Path (Join-Path $bundleRoot 'response.v1.json') `
            -Bytes $responseInput.Bytes
        for ($index = 0; $index -lt $snapshot.Files.Count; $index++) {
            $file = $snapshot.Files[$index]
            $bytes = Read-ProductionReleaseInputBytes `
                -Descriptor $file.Descriptor `
                -Label "Locked offline bundle role $($file.role)"
            Write-FeedPromotionCreateOnlyFile `
                -Path (Join-Path $bundlePayloadRoot ([string]$file.fileName)) `
                -Bytes $bytes
            if ($index -eq 0 -and
                $FaultPoint -ceq 'AfterFirstBundlePayloadCommit') {
                throw 'INJECTED-CRASH-AFTER-FIRST-OFFLINE-BUNDLE-PAYLOAD'
            }
        }
        Assert-FeedPromotionSourceStillLocked -Snapshot $snapshot
        Assert-FeedPromotionRequestInventory -PromotionRoot $promotionLock.Root
        $bundleSetSha256 = Assert-FeedPromotionOfflineBundle `
            -PromotionRoot $promotionLock.Root `
            -RequestInput $requestInput `
            -ResponseInput $responseInput `
            -Snapshot $snapshot `
            -AllowPendingBundleHead
        $readyHead = [ordered]@{
            schemaVersion = 1
            stateType = 'ensou-dsh-launcher-offline-feed-promotion-bundle'
            operationId = [string]$requestInput.Value.operationId
            requestSha256 = [string]$requestInput.Sha256
            requestNonce = [string]$requestInput.Value.requestNonce
            sourceStateHeadSha256 = [string]$requestInput.Value.sourceState.headSha256
            payloadSetSha256 = [string]$requestInput.Value.payloadSetSha256
            basePromotionHeadSha256 = [string]$head.Sha256
            responseSha256 = [string]$responseInput.Sha256
            bundleSetSha256 = $bundleSetSha256
            status = 'EXTERNAL_PUBLISH_BUNDLE_READY'
            productionAdmission = 'NO_GO'
            networkPublishPerformed = $false
            updatedAtUtc = [string]$responseInput.Value.completedAtUtc
        }
        Write-FeedPromotionCreateOnlyFile `
            -Path (Join-Path $bundleRoot 'head.v1.json') `
            -Bytes (ConvertTo-ProductionJsonBytes -Value $readyHead) `
            -FaultAfterPending:($FaultPoint -ceq 'AfterReadyHeadPending')
        $committed = Get-FeedPromotionBundleHead -PromotionRoot $promotionLock.Root
        $verifiedBundleSetSha256 = Assert-FeedPromotionOfflineBundle `
            -PromotionRoot $promotionLock.Root `
            -RequestInput $requestInput `
            -ResponseInput $responseInput `
            -Snapshot $snapshot
        if ($verifiedBundleSetSha256 -cne $bundleSetSha256) {
            throw 'Committed offline bundle changed while its append-only head was admitted.'
        }
        return [pscustomobject]@{
            PromotionRoot = $promotionLock.Root
            OperationId = [string]$requestInput.Value.operationId
            ResponseSha256 = [string]$responseInput.Sha256
            BundleSetSha256 = $bundleSetSha256
            PromotionHeadSha256 = [string]$head.Sha256
            BundleHeadSha256 = [string]$committed.Sha256
            HeadSha256 = [string]$committed.Sha256
            Status = [string]$committed.Value.status
            ProductionAdmission = 'NO_GO'
            NetworkPublishPerformed = $false
        }
    }
    finally {
        Close-FeedPromotionSourceSnapshot -Snapshot $snapshot
        $promotionLock.Stream.Dispose()
    }
}

Export-ModuleMember -Function @(
    'Close-ProductionFeedPromotionBundleAdmission',
    'Get-ProductionFeedPromotionResponseAuthenticationPayload',
    'Import-ProductionFeedPromotionResponse',
    'New-ProductionFeedPromotionRequest',
    'Open-ProductionFeedPromotionBundleAdmission')
