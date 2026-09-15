#requires -Version 7.2

[CmdletBinding(DefaultParameterSetName = 'Create')]
param(
    [Parameter(Mandatory = $true)][string]$StateRoot,
    [Parameter(Mandatory = $true, ParameterSetName = 'Create')]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedR7HeadSha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'Revalidate')]
    [switch]$RevalidateOnly,
    [Parameter(Mandatory = $true, ParameterSetName = 'Revalidate')]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedHeadSha256,
    [Parameter(Mandatory = $true)][string]$WindowsPilotEvidenceEnvelopePath,
    [Parameter(Mandatory = $true)][string]$WindowsPilotEvidenceBodyPath,
    [Parameter(Mandatory = $true)][string]$WindowsPilotVerificationReportPath,
    [Parameter(Mandatory = $true)][string]$WindowsPilotReadinessConfigPath,
    [Parameter(Mandatory = $true)][string]$WindowsPilotStoredReadinessReportPath,
    [Parameter(Mandatory = $true)][string]$WindowsPilotReplayedReadinessReportPath,
    [Parameter(Mandatory = $true)][string]$LocalDataCertificationReceiptPath,
    [Parameter(Mandatory = $true)][string]$StablePrivatePilotObservationPath,
    [Parameter(Mandatory = $true)][string]$PilotTrustPolicyPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Create')][string]$OutputPath,
    [ValidateSet(1, 2)]
    [int]$WindowsPilotReadinessSchemaVersion = 1
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$schemaRoot = Join-Path $repositoryRoot 'release\schemas'
$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$signingModulePath = Join-Path $PSScriptRoot 'InstallerSigningContracts.psm1'
$pilotModulePath = Join-Path $PSScriptRoot 'EnterpriseProductionPilotEvidence.psm1'
$certifiedDistributionInputPath = Join-Path `
    $PSScriptRoot `
    'CertifiedDistributionInput.ps1'
$schemas = @{
    Plan = Join-Path $schemaRoot 'launcher-production-release-plan-v2.schema.json'
    State = Join-Path $schemaRoot 'launcher-production-release-state-v2.schema.json'
    SigningRequest = Join-Path $schemaRoot 'launcher-installer-signing-request-v2.schema.json'
    SigningResponse = Join-Path $schemaRoot 'launcher-installer-signing-response-v1.schema.json'
    TrustedBuild = Join-Path $schemaRoot 'enterprise-installer-trusted-build-evidence-v1.schema.json'
    Trust = Join-Path $schemaRoot 'enterprise-production-pilot-evidence-trust-v1.schema.json'
    WindowsEnvelope = Join-Path $schemaRoot 'enterprise-windows-pilot-evidence-envelope-v2.schema.json'
    WindowsBody = Join-Path $schemaRoot 'enterprise-windows-pilot-evidence-body-v2.schema.json'
    WindowsReport = Join-Path $schemaRoot 'enterprise-windows-pilot-verification-report-v2.schema.json'
    ReadinessConfig = Join-Path $schemaRoot (
        "enterprise-pilot-readiness-v$WindowsPilotReadinessSchemaVersion.schema.json")
    ReadinessReport = Join-Path $schemaRoot (
        "enterprise-pilot-readiness-report-v$WindowsPilotReadinessSchemaVersion.schema.json")
    LocalData = Join-Path $schemaRoot 'enterprise-local-data-compatibility-certification-receipt-v1.schema.json'
    StableObservation = Join-Path $schemaRoot 'enterprise-production-stable-private-pilot-observation-v1.schema.json'
    GateContract = Join-Path $schemaRoot 'enterprise-windows-pilot-gate-contract-v2.schema.json'
    Output = Join-Path $schemaRoot 'enterprise-production-pilot-evidence-input-v1.schema.json'
}
$gateContractPath = Join-Path `
    $repositoryRoot `
    'release\enterprise-windows-pilot-gate-contract-v2.json'
$expectedGateContractSha256 =
    'a7fff40aad6690d12042d62ba1a8deb80e36431abdd62bc4874fa04388d26331'

Microsoft.PowerShell.Core\Import-Module `
    -Name $stateModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module `
    -Name $signingModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module `
    -Name $pilotModulePath -Force -ErrorAction Stop
# Both verifier modules import ProductionReleaseState into private module
# scopes. Re-import it last so this script's module-qualified state calls stay
# bound after PowerShell processes their -Force imports.
Microsoft.PowerShell.Core\Import-Module `
    -Name $stateModulePath -Force -ErrorAction Stop
. $certifiedDistributionInputPath

$leases = [Collections.Generic.List[object]]::new()
$outputDirectoryLeases = [Collections.Generic.List[IDisposable]]::new()
$stateLock = $null
$outputDirectory = $null
$stateRootDirectory = $null

function Open-R8JsonInput {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][int64]$MaximumBytes,
        [Parameter(Mandatory = $true)][string]$SchemaPath
    )

    $lease = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $Path -Label $Label -MaximumBytes $MaximumBytes
    try {
        $bytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
            -Descriptor $lease -Label $Label
        $value = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
            -Bytes $bytes -Label $Label -SchemaPath $SchemaPath
        $input = [pscustomobject]@{
            Lease = $lease
            Path = [string]$lease.Path
            SizeBytes = [int64]$lease.SizeBytes
            Sha256 = [string]$lease.Sha256
            Bytes = $bytes
            Value = $value
        }
        $leases.Add($lease)
        return $input
    }
    catch {
        $lease.Stream.Dispose()
        throw
    }
}

function Assert-R8Equal {
    param(
        [AllowNull()][object]$Actual,
        [AllowNull()][object]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ([string]$Actual -cne [string]$Expected) {
        throw "R7_PRODUCTION_STATE_BINDING_MISMATCH: $Label differs from the authoritative r7 state."
    }
}

function Get-R8RequiredProperty {
    param(
        [Parameter(Mandatory = $true)][psobject]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        throw "R7_PRODUCTION_STATE_BINDING_MISMATCH: $Label is missing '$Name'."
    }
    return $property.Value
}

function Get-R8ReceiptSnapshotSha256 {
    param([Parameter(Mandatory = $true)][psobject]$Receipt)

    return ProductionReleaseState\Get-ProductionSha256Bytes `
        -Bytes (ProductionReleaseState\ConvertTo-ProductionJsonBytes `
            -Value $Receipt)
}

function Get-R8HistoricalHeadSha256 {
    param(
        [Parameter(Mandatory = $true)][psobject]$State,
        [Parameter(Mandatory = $true)][psobject]$Receipt,
        [Parameter(Mandatory = $true)][string]$ReceiptSha256
    )

    $revision = [int]$Receipt.revision
    $phase = [string]$Receipt.phase
    $head = [ordered]@{
        schemaVersion = 2
        stateType = 'ensou-dsh-launcher-production-release-head'
        orchestrationId = [string]$State.Identity.orchestrationId
        edition = 'Enterprise'
        planSha256 = [string]$State.Identity.planSha256
        identitySha256 = [string]$State.IdentitySha256
        revision = $revision
        phase = $phase
        receiptFileName = $revision.ToString('0000') + '-' +
            $phase.ToLowerInvariant().Replace('_', '-') + '.json'
        receiptSha256 = $ReceiptSha256
        updatedAtUtc = [string]$Receipt.recordedAtUtc
        targetChannel = 'stable'
    }
    return ProductionReleaseState\Get-ProductionSha256Bytes `
        -Bytes (ProductionReleaseState\ConvertTo-ProductionJsonBytes `
            -Value $head)
}

function Get-R8EvidencePolicyValidUntilUtc {
    param(
        [Parameter(Mandatory = $true)][psobject]$Trust,
        [Parameter(Mandatory = $true)][DateTimeOffset]$WindowsCompletedAtUtc,
        [Parameter(Mandatory = $true)][psobject]$LocalDataReceipt,
        [Parameter(Mandatory = $true)][psobject]$StableObservation
    )

    # These objects have passed the existing signature and policy verifier.
    # This additional deadline never changes the committed r8 evidence bytes.
    $maximumAge = [TimeSpan]::FromHours([int]$Trust.maximumEvidenceAgeHours)
    $minimumRemaining = [TimeSpan]::FromMinutes([int]$Trust.minimumRemainingValidityMinutes)
    $localIssued = [DateTimeOffset]::FromUnixTimeSeconds([int64]$LocalDataReceipt.issuedAtUnixSeconds)
    $localExpires = [DateTimeOffset]::FromUnixTimeSeconds([int64]$LocalDataReceipt.expiresAtUnixSeconds)
    $stableCollected = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$StableObservation.collectedAtUtc) -Label 'authenticated Stable collection'
    $allowlistExpires = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$StableObservation.privatePilot.allowlist.activeUntilUtc) `
        -Label 'authenticated Stable allowlist expiry'
    $deadlines = @(
        $WindowsCompletedAtUtc.Add($maximumAge)
        $localIssued.Add($maximumAge)
        $stableCollected.Add($maximumAge)
        $localExpires.Subtract($minimumRemaining)
        $allowlistExpires.Subtract($minimumRemaining)
        $localExpires
        $allowlistExpires
    )
    $earliest = $deadlines[0]
    foreach ($deadline in $deadlines) {
        if ($deadline -lt $earliest) { $earliest = $deadline }
    }
    return [DateTimeOffset]$earliest
}

function Assert-R8FinalEvidenceLifetime {
    param(
        [Parameter(Mandatory = $true)][DateTimeOffset]$PolicyValidUntilUtc,
        [Parameter(Mandatory = $true)][DateTimeOffset]$ExpiresAtUtc,
        [Parameter(Mandatory = $true)][DateTimeOffset]$ValidationTimeUtc
    )

    if ($ExpiresAtUtc -le $ValidationTimeUtc) {
        throw 'R8_EVIDENCE_EXPIRED: Pilot evidence expired while final input leases were held.'
    }
    # Existing maximum-age and minimum-remaining checks accept equality;
    # absolute expiry above rejects equality. Keep those semantics distinct.
    if ($ValidationTimeUtc -gt $PolicyValidUntilUtc) {
        throw 'R8_EVIDENCE_POLICY_EXPIRED: Pilot evidence exceeded its maximum age or minimum remaining validity while final input leases were held.'
    }
}

function New-R8FileBinding {
    param([Parameter(Mandatory = $true)]$InputObject)

    $descriptor = if ($null -ne $InputObject.PSObject.Properties['Lease']) {
        $InputObject.Lease
    }
    else {
        $InputObject
    }
    return [ordered]@{
        fileName = [IO.Path]::GetFileName([string]$descriptor.Path)
        sizeBytes = [int64]$descriptor.SizeBytes
        sha256 = [string]$descriptor.Sha256
    }
}

function Test-R8SameOrDescendantPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $fullRoot = [IO.Path]::TrimEndingDirectorySeparator(
        [IO.Path]::GetFullPath($Root))
    return $fullPath.Equals(
            $fullRoot,
            [StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith(
            $fullRoot + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)
}

function Get-R8NewLocalOutputPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or
        -not [IO.Path]::IsPathFullyQualified($Path) -or
        $Path.StartsWith('\\', [StringComparison]::Ordinal) -or
        $Path.StartsWith('//', [StringComparison]::Ordinal)) {
        throw 'R8_OUTPUT_PATH_INVALID: OutputPath must be one absolute local Windows file.'
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetDirectoryName($fullPath)
    if ([string]::IsNullOrWhiteSpace($parent) -or
        -not [IO.Directory]::Exists($parent)) {
        throw 'R8_OUTPUT_PATH_INVALID: OutputPath parent must already exist as a local directory.'
    }
    if (Test-Path -LiteralPath $fullPath) {
        throw 'R8_OUTPUT_ALREADY_EXISTS: Refusing to overwrite or bless a stale Pilot evidence adapter output.'
    }
    return $fullPath
}

function Open-R8LockedOrdinaryDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    try {
        return Open-CertifiedDistributionLockedDirectory `
            -Path $Path -Label $Label -Leases $outputDirectoryLeases
    }
    catch {
        throw [IO.IOException]::new(
            "R8_OUTPUT_PATH_INVALID: $Label must be one ordinary local directory with no reparse-point ancestor.",
            $_.Exception)
    }
}

function Assert-R8OutputOutsideStateRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$OutputDirectory,
        [Parameter(Mandatory = $true)]$StateRootDirectory
    )

    if (Test-R8SameOrDescendantPath `
            -Path $Path -Root ([string]$StateRootDirectory.Path)) {
        throw 'R8_OUTPUT_PATH_INVALID: Pilot adapter output must remain outside the immutable r7 state root.'
    }
    foreach ($entry in @($OutputDirectory.Chain)) {
        if ([uint32]$entry.VolumeSerialNumber -eq
                [uint32]$StateRootDirectory.VolumeSerialNumber -and
            [uint64]$entry.FileIndex -eq
                [uint64]$StateRootDirectory.FileIndex) {
            throw 'R8_OUTPUT_PATH_INVALID: Pilot adapter output resolves inside the immutable r7 state root.'
        }
    }
}

function Write-R8CreateNewOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)]$DirectoryDescriptor
    )

    $fullPath = Get-R8NewLocalOutputPath -Path $Path
    $parent = [IO.Path]::GetDirectoryName($fullPath)
    if (-not $parent.Equals(
            [string]$DirectoryDescriptor.Path,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'R8_OUTPUT_PATH_INVALID: OutputPath parent differs from the locked ordinary directory.'
    }
    Assert-CertifiedDistributionLockedDirectoryUnchanged `
        -Descriptor $DirectoryDescriptor

    $pending = Join-Path $parent (
        '.' + [IO.Path]::GetFileName($fullPath) + '.' +
        [Guid]::NewGuid().ToString('N') + '.pending')
    $stream = $null
    $publishedStream = $null
    $published = $false
    try {
        $stream = [IO.FileStream]::new(
            $pending,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            ([IO.FileShare]::Read -bor [IO.FileShare]::Delete),
            4096,
            [IO.FileOptions]::WriteThrough)
        $pendingIdentity =
            [EnsouDshCertifiedDistributionInput.NativeFileIdentity]::
                RequireOrdinarySingleLink($stream.SafeFileHandle)
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
        Assert-CertifiedDistributionLockedDirectoryUnchanged `
            -Descriptor $DirectoryDescriptor
        if (Test-Path -LiteralPath $fullPath) {
            throw 'R8_OUTPUT_ALREADY_EXISTS: Refusing to overwrite or bless a stale Pilot evidence adapter output.'
        }
        [IO.File]::Move($pending, $fullPath, $false)
        $published = $true
        Assert-CertifiedDistributionLockedDirectoryUnchanged `
            -Descriptor $DirectoryDescriptor
        $publishedStream = [IO.FileStream]::new(
            $fullPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete),
            4096,
            [IO.FileOptions]::SequentialScan)
        $publishedIdentity =
            [EnsouDshCertifiedDistributionInput.NativeFileIdentity]::
                RequireOrdinarySingleLink($publishedStream.SafeFileHandle)
        if ([uint32]$publishedIdentity.VolumeSerialNumber -ne
                [uint32]$pendingIdentity.VolumeSerialNumber -or
            [uint64]$publishedIdentity.FileIndex -ne
                [uint64]$pendingIdentity.FileIndex -or
            $publishedStream.Length -ne $Bytes.LongLength) {
            throw 'R8_OUTPUT_PATH_CHANGED: OutputPath does not name the exact create-new pending file after the atomic move.'
        }
        $actualSha256 = ([Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($publishedStream))).ToLowerInvariant()
        $expectedSha256 = ([Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($Bytes))).ToLowerInvariant()
        if ($actualSha256 -cne $expectedSha256) {
            throw 'R8_OUTPUT_PATH_CHANGED: Output bytes changed during the atomic move.'
        }
        Assert-CertifiedDistributionLockedDirectoryUnchanged `
            -Descriptor $DirectoryDescriptor
    }
    catch {
        $writeError = $_
        if ($null -ne $publishedStream) {
            $publishedStream.Dispose()
            $publishedStream = $null
        }
        if ($null -ne $stream) {
            $stream.Dispose()
            $stream = $null
        }
        if ([IO.File]::Exists($pending)) {
            [IO.File]::Delete($pending)
        }
        if ($published -and [IO.File]::Exists($fullPath)) {
            $cleanupStream = $null
            try {
                $cleanupStream = [IO.FileStream]::new(
                    $fullPath,
                    [IO.FileMode]::Open,
                    [IO.FileAccess]::Read,
                    ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
                $cleanupIdentity =
                    [EnsouDshCertifiedDistributionInput.NativeFileIdentity]::
                        RequireOrdinarySingleLink(
                            $cleanupStream.SafeFileHandle)
                $ownsPublishedPath =
                    [uint32]$cleanupIdentity.VolumeSerialNumber -eq
                        [uint32]$pendingIdentity.VolumeSerialNumber -and
                    [uint64]$cleanupIdentity.FileIndex -eq
                        [uint64]$pendingIdentity.FileIndex
            }
            catch {
                $ownsPublishedPath = $false
            }
            finally {
                if ($null -ne $cleanupStream) {
                    $cleanupStream.Dispose()
                }
            }
            if ($ownsPublishedPath) {
                [IO.File]::Delete($fullPath)
            }
        }
        if (-not $published -and [IO.File]::Exists($fullPath)) {
            throw 'R8_OUTPUT_ALREADY_EXISTS: Refusing to overwrite or bless a stale Pilot evidence adapter output.'
        }
        throw $writeError
    }
    finally {
        if ($null -ne $publishedStream) {
            $publishedStream.Dispose()
        }
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

try {
    $outputPathFull = ''
    if (-not $RevalidateOnly) {
        # Preserve Create's existing create-new rejection ordering: a stale
        # caller output is never masked by state replay diagnostics.
        $outputPathFull = Get-R8NewLocalOutputPath -Path $OutputPath
    }
    $stateLock = ProductionReleaseState\Enter-ProductionReleaseStateReadLock `
        -StateRoot $StateRoot
    $stateRootDirectory = Open-R8LockedOrdinaryDirectory `
        -Path ([string]$stateLock.StateRoot) `
        -Label 'immutable production state root'
    if (-not $RevalidateOnly) {
        $outputDirectory = Open-R8LockedOrdinaryDirectory `
            -Path ([IO.Path]::GetDirectoryName($outputPathFull)) `
            -Label 'OutputPath parent'
        Assert-R8OutputOutsideStateRoot `
            -Path $outputPathFull `
            -OutputDirectory $outputDirectory `
            -StateRootDirectory $stateRootDirectory
    }
    $state = ProductionReleaseState\Get-ProductionReleaseState `
        -StateRoot $stateLock.StateRoot -StateSchemaPath $schemas.State

    $baseStateRejected = [int]$state.SchemaVersion -ne 2 -or
        [string]$state.Identity.edition -cne 'Enterprise' -or
        [string]$state.TargetChannel -cne 'stable' -or
        $null -eq $state.Head -or
        $null -ne $state.OrphanReceipt
    if ($baseStateRejected) {
        if ($RevalidateOnly) {
            throw 'R8_REVALIDATION_STATE_REJECTED: Pilot evidence requires a replayed Enterprise Stable state with no orphan transition.'
        }
        throw 'R7_PRODUCTION_STATE_REPLAY_REQUIRED: Pilot evidence requires one exact, fully replayed Enterprise Stable r7 state with no orphan transition.'
    }
    if ($RevalidateOnly) {
        $expectedPhases = @{
            8 = 'PILOT_EVIDENCE_BOUND'
            9 = 'STABLE_PROMOTION_REQUESTED'
            10 = 'STABLE_FEED_PROMOTED'
        }
        $currentRevision = [int]$state.Head.revision
        if (-not $expectedPhases.Contains($currentRevision) -or
            [string]$state.Head.phase -cne $expectedPhases[$currentRevision] -or
            @($state.Receipts).Count -lt 8 -or
            [string]$state.HeadSha256 -cne $ExpectedHeadSha256) {
            throw 'R8_REVALIDATION_STATE_REJECTED: Revalidation requires the exact committed Enterprise Stable r8, r9, or r10 head.'
        }
    }
    elseif ([int]$state.Head.revision -ne 7 -or
        [string]$state.Head.phase -cne 'INSTALLER_SIGNATURE_IMPORTED' -or
        @($state.Receipts).Count -ne 7) {
        throw 'R7_PRODUCTION_STATE_REPLAY_REQUIRED: Pilot evidence requires one exact, fully replayed Enterprise Stable r7 state with no orphan transition.'
    }
    elseif ([string]$state.HeadSha256 -cne $ExpectedR7HeadSha256) {
        throw 'R7_PRODUCTION_STATE_HEAD_MISMATCH: Pilot evidence rejected a stale, replayed, or different r7 state head.'
    }

    $stateRootFull = [string]$stateLock.StateRoot
    $receiptRoot = Join-Path $stateRootFull 'receipts'
    $planInput = Open-R8JsonInput `
        -Path (Join-Path $stateRootFull 'plan.json') `
        -Label 'production release plan' -MaximumBytes 4MB `
        -SchemaPath $schemas.Plan
    $headInput = Open-R8JsonInput `
        -Path (Join-Path $stateRootFull 'head.json') `
        -Label 'r7 production state head' -MaximumBytes 1MB `
        -SchemaPath $schemas.State
    $r3Input = Open-R8JsonInput `
        -Path (Join-Path $receiptRoot '0003-client-signatures-imported.json') `
        -Label 'r3 production receipt' -MaximumBytes 8MB `
        -SchemaPath $schemas.State
    $r5Input = Open-R8JsonInput `
        -Path (Join-Path $receiptRoot '0005-stable-signed-candidate-imported.json') `
        -Label 'r5 production receipt' -MaximumBytes 8MB `
        -SchemaPath $schemas.State
    $r6Input = Open-R8JsonInput `
        -Path (Join-Path $receiptRoot '0006-installer-signing-requested.json') `
        -Label 'r6 production receipt' -MaximumBytes 8MB `
        -SchemaPath $schemas.State
    $r7Input = Open-R8JsonInput `
        -Path (Join-Path $receiptRoot '0007-installer-signature-imported.json') `
        -Label 'r7 production receipt' -MaximumBytes 8MB `
        -SchemaPath $schemas.State
    $installerPath = Join-Path `
        $stateRootFull `
        'imports\installer-signing.v1\signed\Ensou.Dsh.Enterprise.Installer.exe'
    $installerInput = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $installerPath -Label 'r7 signed Enterprise Installer' `
        -MaximumBytes 1GB
    $leases.Add($installerInput)

    Assert-R8Equal $planInput.Sha256 $state.Identity.planSha256 `
        'production plan SHA-256'
    Assert-R8Equal $headInput.Sha256 $state.HeadSha256 'current head SHA-256'
    Assert-R8Equal $r7Input.Sha256 `
        (Get-R8ReceiptSnapshotSha256 -Receipt $state.Receipts[6]) `
        'r7 receipt SHA-256'
    foreach ($receiptSnapshot in @(
            [pscustomobject]@{ Input = $r3Input; Index = 2; Label = 'r3 receipt' },
            [pscustomobject]@{ Input = $r5Input; Index = 4; Label = 'r5 receipt' },
            [pscustomobject]@{ Input = $r6Input; Index = 5; Label = 'r6 receipt' },
            [pscustomobject]@{ Input = $r7Input; Index = 6; Label = 'r7 receipt' })) {
        Assert-R8Equal `
            $receiptSnapshot.Input.Sha256 `
            (Get-R8ReceiptSnapshotSha256 `
                -Receipt $state.Receipts[$receiptSnapshot.Index]) `
            "$($receiptSnapshot.Label) replay snapshot"
    }

    $plan = $planInput.Value
    $r3Data = $r3Input.Value.data
    $r5Data = $r5Input.Value.data
    $r6Data = $r6Input.Value.data
    $r7Data = $r7Input.Value.data
    $signedInstaller = Get-R8RequiredProperty `
        -Object $r7Data -Name 'signedInstaller' -Label 'r7 receipt data'

    $r7HeadSha256 = Get-R8HistoricalHeadSha256 `
        -State $state -Receipt $r7Input.Value -ReceiptSha256 $r7Input.Sha256
    if (-not $RevalidateOnly) {
        Assert-R8Equal $r7HeadSha256 $ExpectedR7HeadSha256 'r7 historical head SHA-256'
    }

    Assert-R8Equal $plan.orchestrationId $state.Identity.orchestrationId `
        'plan orchestration ID'
    Assert-R8Equal $headInput.Value.orchestrationId `
        $state.Identity.orchestrationId 'current head orchestration ID'
    Assert-R8Equal $r7Input.Value.orchestrationId `
        $state.Identity.orchestrationId 'receipt orchestration ID'
    Assert-R8Equal $r7Input.Value.planSha256 $planInput.Sha256 `
        'r7 receipt plan SHA-256'
    Assert-R8Equal $headInput.Value.planSha256 $planInput.Sha256 `
        'head plan SHA-256'
    if (-not $RevalidateOnly) {
        Assert-R8Equal $headInput.Value.receiptFileName `
            '0007-installer-signature-imported.json' 'head receipt filename'
    }

    $responseSha256 = [string](Get-R8RequiredProperty `
        -Object $r7Data -Name 'responseSha256' -Label 'r7 receipt data')
    $authenticationKeyId = [string](Get-R8RequiredProperty `
        -Object $r7Data -Name 'authenticationKeyId' -Label 'r7 receipt data')
    $authenticationPurpose = [string](Get-R8RequiredProperty `
        -Object $r7Data -Name 'authenticationPurpose' -Label 'r7 receipt data')
    $signerCertificateSha256 = [string](Get-R8RequiredProperty `
        -Object $r7Data -Name 'signerCertificateSha256' -Label 'r7 receipt data')
    $timestampSignerCertificateSha256 = [string](Get-R8RequiredProperty `
        -Object $r7Data -Name 'timestampSignerCertificateSha256' -Label 'r7 receipt data')
    if ($responseSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $signerCertificateSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $timestampSignerCertificateSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $authenticationPurpose -cne 'installer-signing-response') {
        throw 'R7_PRODUCTION_STATE_BINDING_MISMATCH: r7 signing-response authority is invalid.'
    }
    Assert-R8Equal $plan.externalResponseTrusts.installerSigning.keyId `
        $authenticationKeyId 'installer-signing response key ID'
    Assert-R8Equal $plan.externalResponseTrusts.installerSigning.purpose `
        $authenticationPurpose 'installer-signing response purpose'
    Assert-R8Equal $plan.authenticodePolicy.signerSha256Thumbprint `
        $signerCertificateSha256 'Authenticode signer policy'

    if ([string]$signedInstaller.fileName -cne
            'Ensou.Dsh.Enterprise.Installer.exe' -or
        [string]$signedInstaller.relativePath -cne
            'imports/installer-signing.v1/signed/Ensou.Dsh.Enterprise.Installer.exe' -or
        [int64]$signedInstaller.sizeBytes -ne [int64]$installerInput.SizeBytes -or
        [string]$signedInstaller.sha256 -cne [string]$installerInput.Sha256) {
        throw 'R7_INSTALLER_BYTES_MISMATCH: The locked signed Installer differs from the exact r7 receipt authority.'
    }
    $installerBytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
        -Descriptor $installerInput -Label 'r7 signed Enterprise Installer'
    $peContentSha256 = ProductionReleaseState\Get-PeContentSha256 `
        -Bytes $installerBytes
    if ([string]$signedInstaller.peContentSha256 -cne $peContentSha256) {
        throw 'R7_INSTALLER_BYTES_MISMATCH: The signed Installer PE-content hash differs from the exact r7 receipt authority.'
    }

    $trustedBuildReceiptFields = @(
        'requestSchemaVersion',
        'requestSha256',
        'trustedBuildEvidenceSha256',
        'resourceBindingSha256',
        'sdkFileClosureStatus',
        'signingRequestEligibilityStatus',
        'sourceBuildInputSetSha256',
        'targetBuildIdentitySha256',
        'payloadSetSha256',
        'admissionReason',
        'productionAdmission')
    $missingFields = [Collections.Generic.List[string]]::new()
    foreach ($scope in @(
            [pscustomobject]@{ Name = 'r6'; Value = $r6Data },
            [pscustomobject]@{ Name = 'r7'; Value = $r7Data })) {
        foreach ($field in $trustedBuildReceiptFields) {
            if ($null -eq $scope.Value.PSObject.Properties[$field]) {
                $missingFields.Add("$($scope.Name).$field")
            }
        }
    }
    foreach ($r6OnlyField in @(
            'requestRelativePath',
            'trustedBuildEvidenceRelativePath')) {
        if ($null -eq $r6Data.PSObject.Properties[$r6OnlyField]) {
            $missingFields.Add("r6.$r6OnlyField")
        }
    }
    if ($missingFields.Count -gt 0) {
        throw ('R7_TRUSTED_BUILD_SOURCE_MISSING: r6/r7 do not bind the ' +
            'trusted request-v2 build source fields: ' +
            ($missingFields -join ', ') + '.')
    }

    foreach ($field in $trustedBuildReceiptFields) {
        Assert-R8Equal $r7Data.$field $r6Data.$field `
            "r6/r7 trusted-build field $field"
    }
    if ([int]$r7Data.requestSchemaVersion -ne 2 -or
        [string]$r6Data.requestRelativePath -cne
            'requests/installer-signing.v2/installer-signing-request.v2.json' -or
        [string]$r7Data.sdkFileClosureStatus -cne
            'VERIFIED' -or
        [string]$r7Data.signingRequestEligibilityStatus -cne
            'ELIGIBLE_FOR_PILOT_SIGNING' -or
        [string]$r7Data.productionAdmission -cne 'NO_GO' -or
        [string]$r7Data.admissionReason -cne
            'INSTALLER_SIGNING_RESPONSE_REQUIRED') {
        throw 'R7_PRODUCTION_ADMISSION_REASON_REJECTED: r8 accepts only a verified portable SDK byte closure whose remaining blocker is the authenticated Installer-signing response.'
    }

    $requestInput = Open-R8JsonInput `
        -Path (Join-Path $stateRootFull ([string]$r6Data.requestRelativePath)) `
        -Label 'r6 Installer signing request v2' -MaximumBytes 64MB `
        -SchemaPath $schemas.SigningRequest
    [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
        -JsonInput $requestInput -Label 'r6 Installer signing request v2')
    Assert-R8Equal $requestInput.Sha256 $r6Data.requestSha256 `
        'r6 request-v2 SHA-256'
    Assert-R8Equal $requestInput.Value.orchestrationId `
        $state.Identity.orchestrationId 'request orchestration ID'
    Assert-R8Equal $requestInput.Value.planSha256 $planInput.Sha256 `
        'request plan SHA-256'
    Assert-R8Equal $requestInput.Value.releaseSetId $plan.releaseSetId `
        'request release set'
    Assert-R8Equal $requestInput.Value.r3Evidence.receiptSha256 `
        $r3Input.Sha256 'request/r3 receipt SHA-256'
    Assert-R8Equal $requestInput.Value.r5Evidence.receiptSha256 `
        $r5Input.Sha256 'request/r5 receipt SHA-256'
    Assert-R8Equal $r6Data.baseReceiptSha256 $r5Input.Sha256 `
        'r6/r5 receipt SHA-256'

    $trustedBuildRelativePath =
        'requests/installer-signing.v2/trusted-build/trusted-build-evidence.v1.json'
    Assert-R8Equal $r6Data.trustedBuildEvidenceRelativePath `
        $trustedBuildRelativePath 'r6 trusted-build evidence path'
    $trustedBuildInput = Open-R8JsonInput `
        -Path (Join-Path $stateRootFull $trustedBuildRelativePath) `
        -Label 'r6 trusted-build evidence' -MaximumBytes 64MB `
        -SchemaPath $schemas.TrustedBuild
    Assert-R8Equal $trustedBuildInput.Sha256 `
        $r6Data.trustedBuildEvidenceSha256 `
        'r6 trusted-build evidence SHA-256'
    Assert-R8Equal $trustedBuildInput.Value.orchestrationId `
        $state.Identity.orchestrationId 'trusted-build orchestration ID'
    Assert-R8Equal $trustedBuildInput.Value.planSha256 $planInput.Sha256 `
        'trusted-build plan SHA-256'
    Assert-R8Equal $trustedBuildInput.Value.r5ReceiptSha256 `
        $r5Input.Sha256 'trusted-build/r5 receipt SHA-256'
    Assert-R8Equal $requestInput.Value.trustedBuildEvidence.sha256 `
        $trustedBuildInput.Sha256 'request trusted-build evidence SHA-256'
    Assert-R8Equal $requestInput.Value.trustedBuildEvidence.relativePath `
        'trusted-build/trusted-build-evidence.v1.json' `
        'request trusted-build relative path'

    $resourceBindingSha256 =
        InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
            -Value $requestInput.Value.resourceBinding
    Assert-R8Equal $resourceBindingSha256 $r6Data.resourceBindingSha256 `
        'r6 resource binding SHA-256'
    Assert-R8Equal `
        (InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
            -Value $trustedBuildInput.Value.resourceBinding) `
        $resourceBindingSha256 'trusted-build resource binding'
    Assert-R8Equal $requestInput.Value.sourceBuildInputSetSha256 `
        $r6Data.sourceBuildInputSetSha256 'request source-build input set'
    Assert-R8Equal `
        $trustedBuildInput.Value.sourceBuildInputs.inventorySha256 `
        $r6Data.sourceBuildInputSetSha256 'trusted-build source input set'
    Assert-R8Equal `
        $requestInput.Value.buildExecution.targetBuildIdentitySha256 `
        $r6Data.targetBuildIdentitySha256 'request target-build identity'
    Assert-R8Equal `
        $trustedBuildInput.Value.buildExecution.targetBuildIdentitySha256 `
        $r6Data.targetBuildIdentitySha256 'trusted-build target identity'
    Assert-R8Equal $requestInput.Value.installerPayload.inventorySha256 `
        $r6Data.payloadSetSha256 'request payload set'
    Assert-R8Equal $trustedBuildInput.Value.installerPayload.inventorySha256 `
        $r6Data.payloadSetSha256 'trusted-build payload set'
    Assert-R8Equal $trustedBuildInput.Value.signingRequestEligibility.status `
        $r6Data.signingRequestEligibilityStatus `
        'trusted-build signing eligibility'
    Assert-R8Equal $trustedBuildInput.Value.signingRequestEligibility.blocker `
        $r6Data.admissionReason 'trusted-build admission reason'

    $responseInput = Open-R8JsonInput `
        -Path (Join-Path $stateRootFull `
            'imports\installer-signing.v1\installer-signing-response.v1.json') `
        -Label 'r7 Installer signing response' -MaximumBytes 64MB `
        -SchemaPath $schemas.SigningResponse
    [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
        -JsonInput $responseInput -Label 'r7 Installer signing response')
    Assert-R8Equal $responseInput.Sha256 $responseSha256 `
        'r7 signing response SHA-256'
    $r6HeadSha256 = Get-R8HistoricalHeadSha256 `
        -State $state -Receipt $r6Input.Value `
        -ReceiptSha256 $r6Input.Sha256
    Assert-R8Equal $r7Data.r6ReceiptSha256 $r6Input.Sha256 `
        'r7/r6 receipt SHA-256'
    Assert-R8Equal $r7Data.admissionHeadSha256 $r6HeadSha256 `
        'r7/r6 admission head SHA-256'
    [void](InstallerSigningContracts\Assert-InstallerSigningResponseContract `
        -RequestInput $requestInput -ResponseInput $responseInput `
        -R6HeadSha256 $r6HeadSha256 `
        -R6ReceiptSha256 $r6Input.Sha256 `
        -InstallerSigningTrust $plan.externalResponseTrusts.installerSigning)
    $authenticode =
        InstallerSigningContracts\Assert-SignedInstallerAuthenticode `
            -Path $installerPath -Response $responseInput.Value `
            -ExpectedSignerCertificateSha256 `
                ([string]$plan.authenticodePolicy.signerSha256Thumbprint)
    Assert-R8Equal $authenticode.SignerCertificateSha256 `
        $signerCertificateSha256 'r7 Authenticode signer replay'
    Assert-R8Equal $authenticode.TimestampSignerCertificateSha256 `
        $timestampSignerCertificateSha256 'r7 RFC3161 signer replay'
    Assert-R8Equal $authenticode.TimestampUtc $r7Data.timestampUtc `
        'r7 RFC3161 timestamp replay'

    $trustInput = Open-R8JsonInput `
        -Path $PilotTrustPolicyPath -Label 'r8 Pilot trust policy' `
        -MaximumBytes 1MB -SchemaPath $schemas.Trust
    if ([string]$trustInput.Sha256 -cne
        [string]$plan.pilotEvidenceTrustPolicySha256) {
        throw 'R8_TRUST_POLICY_PLAN_ANCHOR_MISMATCH: Pilot trust-policy bytes differ from the exact SHA-256 fixed in the immutable production plan before r1.'
    }
    $windowsEnvelopeInput = Open-R8JsonInput `
        -Path $WindowsPilotEvidenceEnvelopePath `
        -Label 'Windows Pilot evidence envelope' -MaximumBytes 4MB `
        -SchemaPath $schemas.WindowsEnvelope
    $windowsBodyInput = Open-R8JsonInput `
        -Path $WindowsPilotEvidenceBodyPath `
        -Label 'Windows Pilot evidence body' -MaximumBytes 64MB `
        -SchemaPath $schemas.WindowsBody
    $windowsReportInput = Open-R8JsonInput `
        -Path $WindowsPilotVerificationReportPath `
        -Label 'Windows Pilot verification report' -MaximumBytes 16MB `
        -SchemaPath $schemas.WindowsReport
    $readinessConfigInput = Open-R8JsonInput `
        -Path $WindowsPilotReadinessConfigPath `
        -Label 'Windows Pilot readiness config' -MaximumBytes 16MB `
        -SchemaPath $schemas.ReadinessConfig
    $storedReadinessInput = Open-R8JsonInput `
        -Path $WindowsPilotStoredReadinessReportPath `
        -Label 'stored Windows Pilot readiness report' -MaximumBytes 16MB `
        -SchemaPath $schemas.ReadinessReport
    $replayedReadinessInput = Open-R8JsonInput `
        -Path $WindowsPilotReplayedReadinessReportPath `
        -Label 'replayed Windows Pilot readiness report' -MaximumBytes 16MB `
        -SchemaPath $schemas.ReadinessReport
    $localDataInput = Open-R8JsonInput `
        -Path $LocalDataCertificationReceiptPath `
        -Label 'local-data compatibility certification' -MaximumBytes 4MB `
        -SchemaPath $schemas.LocalData
    $stableObservationInput = Open-R8JsonInput `
        -Path $StablePrivatePilotObservationPath `
        -Label 'Stable private Pilot observation' -MaximumBytes 64MB `
        -SchemaPath $schemas.StableObservation
    $gateContractInput = Open-R8JsonInput `
        -Path $gateContractPath -Label 'pinned Windows Pilot gate contract' `
        -MaximumBytes 1MB -SchemaPath $schemas.GateContract
    $gateContractCanonicalSha256 =
        ProductionReleaseState\Get-ProductionSha256Bytes `
            -Bytes (ProductionReleaseState\ConvertTo-ProductionJsonBytes `
                -Value $gateContractInput.Value)
    Assert-R8Equal $gateContractCanonicalSha256 `
        $expectedGateContractSha256 `
        'pinned Windows Pilot gate contract canonical SHA-256'

    $authority = [pscustomobject]@{
        OrchestrationId = [string]$state.Identity.orchestrationId
        HeadSha256 = $r7HeadSha256
        R7ReceiptSha256 = [string]$r7Input.Sha256
        InstallerIdentity = $signedInstaller
        InstallerSigningTrust = $plan.externalResponseTrusts.installerSigning
        Plan = $plan
        R3Data = $r3Data
        R5Data = $r5Data
        R6Data = $r6Data
        R7Data = $r7Data
    }
    $validationTimeUtc = [DateTimeOffset]::UtcNow
    $verified =
        EnterpriseProductionPilotEvidence\Assert-EnterpriseProductionPilotEvidence `
            -Trust $trustInput.Value -TrustInput $trustInput `
            -WindowsEnvelope $windowsEnvelopeInput.Value `
            -WindowsEnvelopeInput $windowsEnvelopeInput `
            -WindowsBody $windowsBodyInput.Value `
            -WindowsBodyInput $windowsBodyInput `
            -WindowsVerificationReport $windowsReportInput.Value `
            -WindowsVerificationReportInput $windowsReportInput `
            -ReadinessConfig $readinessConfigInput.Value `
            -ReadinessConfigInput $readinessConfigInput `
            -StoredReadinessReport $storedReadinessInput.Value `
            -StoredReadinessInput $storedReadinessInput `
            -ReplayedReadinessReport $replayedReadinessInput.Value `
            -ReplayedReadinessInput $replayedReadinessInput `
            -WindowsPilotReadinessSchemaVersion `
                $WindowsPilotReadinessSchemaVersion `
            -LocalDataReceipt $localDataInput.Value `
            -LocalDataReceiptInput $localDataInput `
            -StableObservation $stableObservationInput.Value `
            -StableObservationInput $stableObservationInput `
            -InstallerInput $installerInput `
            -GateContract $gateContractInput.Value `
            -Authority $authority -ValidationTimeUtc $validationTimeUtc

    # Output identity must be reproducible across bundle-first recovery while
    # freshness is still evaluated against the real current clock above. The
    # Windows body completion time is covered by the authenticated envelope
    # and is therefore an immutable evidence-derived creation time.
    $createdAtUtc = ProductionReleaseState\ConvertTo-ProductionUtc `
        -Value ([DateTimeOffset]$verified.Windows.BodyCompletedAtUtc)
    $expiresAt = if ($verified.LocalData.ExpiresAtUtc -lt
        $verified.Stable.AllowlistExpiresAtUtc) {
        $verified.LocalData.ExpiresAtUtc
    }
    else {
        $verified.Stable.AllowlistExpiresAtUtc
    }
    if ($expiresAt -le [DateTimeOffset]::UtcNow) {
        throw 'R8_EVIDENCE_EXPIRED: Pilot evidence expired before the canonical r8 output could be committed.'
    }
    $policyValidUntilUtc = Get-R8EvidencePolicyValidUntilUtc `
        -Trust $trustInput.Value `
        -WindowsCompletedAtUtc ([DateTimeOffset]$verified.Windows.BodyCompletedAtUtc) `
        -LocalDataReceipt $localDataInput.Value `
        -StableObservation $stableObservationInput.Value
    $output = [ordered]@{
        schemaVersion = 1
        inputType =
            'ensou-dsh-enterprise-production-pilot-evidence-import-input'
        orchestrationId = [string]$state.Identity.orchestrationId
        edition = 'Enterprise'
        targetChannel = 'stable'
        releaseSetId = [string]$plan.releaseSetId
        createdAtUtc = $createdAtUtc
        expiresAtUtc = ProductionReleaseState\ConvertTo-ProductionUtc `
            -Value $expiresAt
        planAnchor = [ordered]@{
            planSha256 = [string]$planInput.Sha256
            pilotEvidenceTrustPolicySha256 =
                [string]$plan.pilotEvidenceTrustPolicySha256
        }
        r7 = [ordered]@{
            revision = 7
            phase = 'INSTALLER_SIGNATURE_IMPORTED'
            headSha256 = $r7HeadSha256
            planSha256 = [string]$planInput.Sha256
            receiptRelativePath =
                'receipts/0007-installer-signature-imported.json'
            receiptSha256 = [string]$r7Input.Sha256
            productionAdmission = 'NO_GO'
            signingResponseSha256 = $responseSha256
            signingResponseAuthenticationKeyId = $authenticationKeyId
            signingResponseAuthenticationPurpose = $authenticationPurpose
            signerCertificateSha256 = $signerCertificateSha256
            timestampSignerCertificateSha256 =
                $timestampSignerCertificateSha256
            timestampUtc = [string]$r7Data.timestampUtc
            signedInstaller = [ordered]@{
                fileName = [string]$signedInstaller.fileName
                relativePath = [string]$signedInstaller.relativePath
                sizeBytes = [int64]$signedInstaller.sizeBytes
                sha256 = [string]$signedInstaller.sha256
                peContentSha256 = [string]$signedInstaller.peContentSha256
            }
        }
        trustPolicy = New-R8FileBinding -InputObject $trustInput
        windowsOperationalPilot = [ordered]@{
            envelope = New-R8FileBinding -InputObject $windowsEnvelopeInput
            body = New-R8FileBinding -InputObject $windowsBodyInput
            verificationReport = New-R8FileBinding `
                -InputObject $windowsReportInput
            readinessConfig = New-R8FileBinding `
                -InputObject $readinessConfigInput
            storedReadinessReport = New-R8FileBinding `
                -InputObject $storedReadinessInput
            replayedReadinessReport = New-R8FileBinding `
                -InputObject $replayedReadinessInput
            testRunId = [string]$verified.Windows.TestRunId
            customerAudienceId = [string]$verified.Windows.CustomerAudienceId
            completedAtUtc = [string]$windowsBodyInput.Value.completedAtUtc
            evidenceKeyId = [string]$trustInput.Value.windowsPilotEvidence.keyId
            installerSha256 = [string]$signedInstaller.sha256
            gateCount = 21
        }
        stablePrivatePilot = [ordered]@{
            sourceEvidence = New-R8FileBinding `
                -InputObject $stableObservationInput
            r8SubsetSha256 = [string]$verified.Stable.R8SubsetSha256
            collectedAtUtc = [string]$stableObservationInput.Value.collectedAtUtc
            allowlistExpiresAtUtc = [string](
                $stableObservationInput.Value.privatePilot.allowlist.activeUntilUtc)
            freshInstallDeviceIdentitySha256 =
                [string]$verified.Stable.FreshDeviceIdentitySha256
            onlineUpgradeDeviceIdentitySha256 =
                [string]$verified.Stable.UpgradeDeviceIdentitySha256
            freshInstallInventorySha256 =
                [string]$verified.Stable.FreshInventorySha256
            onlineUpgradeInventorySha256 =
                [string]$verified.Stable.UpgradeInventorySha256
            targetManifestSha256 =
                [string]$verified.Stable.TargetManifestSha256
            targetObjectSetSha256 =
                [string]$verified.Stable.TargetObjectSetSha256
            installerSha256 = [string]$signedInstaller.sha256
        }
        localDataCertification = [ordered]@{
            receipt = New-R8FileBinding -InputObject $localDataInput
            certificationId = [string]$verified.LocalData.CertificationId
            certificationAudienceId =
                [string]$verified.LocalData.CertificationAudienceId
            keyId = [string]$verified.LocalData.KeyId
            evidenceReportSha256 =
                [string]$verified.LocalData.EvidenceReportSha256
            targetRuntimeSha256 =
                [string]$verified.LocalData.TargetRuntimeSha256
            expiresAtUtc = ProductionReleaseState\ConvertTo-ProductionUtc `
                -Value $verified.LocalData.ExpiresAtUtc
        }
        verification = [ordered]@{
            r7ReceiptAuthoritative = 'VERIFIED'
            exactSignedInstallerBytes = 'VERIFIED'
            exactSigningResponse = 'VERIFIED'
            productionWindowsPilotVerifierReport = 'VERIFIED'
            independentEvidenceTrustPolicy = 'VERIFIED'
            twentyOneOperationalGates = 'VERIFIED'
            noVisibleConsoleGate = 'VERIFIED'
            rollbackAndRecoveryGates = 'VERIFIED'
            revocationGates = 'VERIFIED'
            localDataCertification = 'VERIFIED'
            twoDistinctWindowsDevices = 'VERIFIED'
            freshInstallLane = 'VERIFIED'
            onlineUpgradeLane = 'VERIFIED'
            stableTargetObjects = 'VERIFIED'
            freshEvidence = 'VERIFIED'
            purposeSeparatedKeys = 'VERIFIED'
        }
        productionAdmission = 'NO_GO'
        nextRequiredGate = 'PILOT_EVIDENCE_BOUND'
    }
    $outputBytes = ProductionReleaseState\ConvertTo-ProductionJsonBytes `
        -Value $output
    [void](ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
        -Bytes $outputBytes -Label 'r8 Pilot evidence import input' `
        -SchemaPath $schemas.Output)
    $committedR8Input = $null
    if ($RevalidateOnly) {
        $committedR8Input = Open-R8JsonInput `
            -Path (Join-Path $stateRootFull `
                'imports\pilot-evidence.v1\pilot-evidence-input.v1.json') `
            -Label 'committed r8 Pilot evidence input' -MaximumBytes 4MB `
            -SchemaPath $schemas.Output
        $committedR8Receipt = $state.Receipts[7]
        if ([int]$committedR8Receipt.revision -ne 8 -or
            [string]$committedR8Receipt.phase -cne 'PILOT_EVIDENCE_BOUND' -or
            [string]$committedR8Receipt.data.evidenceType -cne
                'PILOT_EVIDENCE_BOUND' -or
            [string]$committedR8Receipt.data.relativePath -cne
                'imports/pilot-evidence.v1/pilot-evidence-input.v1.json' -or
            [string]$committedR8Receipt.data.sha256 -cne
                [string]$committedR8Input.Sha256) {
            throw 'R8_REVALIDATION_STATE_REJECTED: The committed r8 receipt does not bind its canonical Pilot evidence input.'
        }
        [void](ProductionReleaseState\Assert-EnterpriseProductionPilotEvidenceInputBinding `
            -Input $committedR8Input -Plan $plan -Identity $state.Identity `
            -IdentitySha256 ([string]$state.IdentitySha256) `
            -Receipts $state.Receipts -StateRoot $stateRootFull `
            -ExpectedR7HeadSha256 $r7HeadSha256 -EnforceCurrentLifetime)
        if ($outputBytes.Length -ne $committedR8Input.Bytes.Length -or
            -not [System.Linq.Enumerable]::SequenceEqual(
                [byte[]]$outputBytes, [byte[]]$committedR8Input.Bytes) -or
            (ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $outputBytes) -cne
                [string]$committedR8Input.Sha256) {
            throw 'R8_REVALIDATION_SUMMARY_MISMATCH: Revalidated proof does not reproduce the committed canonical r8 summary bytes.'
        }
    }
    foreach ($lease in $leases) {
        [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $lease -Label "r8 locked input '$($lease.FileName)'")
    }
    $completedAtUtc = [DateTimeOffset]::UtcNow
    Assert-R8FinalEvidenceLifetime -PolicyValidUntilUtc $policyValidUntilUtc `
        -ExpiresAtUtc $expiresAt -ValidationTimeUtc $completedAtUtc
    if ($RevalidateOnly) {
        return [pscustomobject]@{
            Status = 'R8_EVIDENCE_REVALIDATED_NO_GO'
            ProductionAdmission = 'NO_GO'
            CurrentHeadSha256 = [string]$state.HeadSha256
            R7HeadSha256 = $r7HeadSha256
            PilotEvidenceInputSha256 = [string]$committedR8Input.Sha256
            # The whole-second return contract conservatively floors any
            # fractional Windows deadline; the internal check retains ticks.
            PolicyValidUntilUtc = ProductionReleaseState\ConvertTo-ProductionUtc `
                -Value $policyValidUntilUtc
            ValidatedAtUtc = ProductionReleaseState\ConvertTo-ProductionUtc `
                -Value $completedAtUtc
        }
    }
    Write-R8CreateNewOutput `
        -Path $outputPathFull `
        -Bytes $outputBytes `
        -DirectoryDescriptor $outputDirectory

    return [pscustomobject]@{
        Status = 'PILOT_EVIDENCE_INPUT_READY_NO_GO'
        ProductionAdmission = 'NO_GO'
        NextRequiredGate = 'PILOT_EVIDENCE_BOUND'
        OutputPath = $outputPathFull
        OutputSha256 = ProductionReleaseState\Get-ProductionSha256Bytes `
            -Bytes $outputBytes
    }
}
finally {
    for ($index = $leases.Count - 1; $index -ge 0; $index--) {
        $leases[$index].Stream.Dispose()
    }
    if ($null -ne $stateLock) {
        $stateLock.Stream.Dispose()
    }
    for ($index = $outputDirectoryLeases.Count - 1;
        $index -ge 0;
        $index--) {
        $outputDirectoryLeases[$index].Dispose()
    }
}
