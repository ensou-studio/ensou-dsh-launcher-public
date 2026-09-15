#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PlanPath,

    [Parameter(Mandatory = $true)]
    [string]$StateRoot,

    [Parameter(Mandatory = $true)]
    [string]$PublisherPolicyPath,

    [Parameter(Mandatory = $true)]
    [string]$RuntimeOrganizationAdmissionReceiptPath,

    [Parameter(Mandatory = $true)]
    [string]$PluginPolicyArchivePath,

    [Parameter(Mandatory = $true)]
    [string]$PluginPolicyMetadataPath,

    [Parameter(Mandatory = $true)]
    [string]$PluginPromotionHandoffPath,

    [Parameter(Mandatory = $true)]
    [string]$PluginHarnessCompatibilityReceiptPath,

    [Parameter(Mandatory = $true)]
    [string]$PluginGenerationReservationPath,

    [Parameter(Mandatory = $true)]
    [string]$PluginGenerationLedgerPath,

    [Parameter(Mandatory = $true)]
    [string]$PluginOrganizationAdmissionReceiptPath,

    [Parameter(Mandatory = $true)]
    [string]$PluginPromotionJournalAuthorizationPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$planSchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\launcher-production-release-plan-v2.schema.json'
$stateSchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\launcher-production-release-state-v2.schema.json'
$publisherInputSchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\launcher-production-publisher-input-v1.schema.json'
$publisherPolicySchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\enterprise-production-publisher-policy-v1.schema.json'
$productionPayloadModulePath = Join-Path `
    $repositoryRoot `
    'scripts\EnterpriseProductionPayload.psm1'

Microsoft.PowerShell.Core\Import-Module `
    -Name $productionPayloadModulePath `
    -Force `
    -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module `
    -Name $stateModulePath `
    -Force `
    -ErrorAction Stop

function Assert-OrdinaryLocalDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not [IO.Path]::IsPathFullyQualified($Path) -or
        $Path.StartsWith('\\', [StringComparison]::Ordinal) -or
        $Path.StartsWith('//', [StringComparison]::Ordinal)) {
        throw "$Label must be one absolute local directory."
    }
    $full = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must be one ordinary directory: $full"
    }
    for ($current = $item; $null -ne $current; $current = $current.Parent) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label crosses a filesystem link: $full"
        }
    }
    return $full
}

function Copy-LockedPublisherInput {
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][int64]$MaximumBytes,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $source = Open-ProductionReleaseInput `
        -Path $SourcePath `
        -Label $Label `
        -MaximumBytes $MaximumBytes
    try {
        $destination = [IO.Path]::GetFullPath($DestinationPath)
        if (Test-Path -LiteralPath $destination) {
            throw "$Label create-only destination already exists: $destination"
        }
        $writer = [IO.File]::Open(
            $destination,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        try {
            $source.Stream.Position = 0
            $source.Stream.CopyTo($writer)
            $writer.Flush($true)
        }
        finally {
            $writer.Dispose()
        }
        Assert-ProductionReleaseInputStillLocked `
            -Descriptor $source `
            -Label $Label
        $copied = Open-ProductionReleaseInput `
            -Path $destination `
            -Label "$Label copied payload" `
            -MaximumBytes $MaximumBytes
        try {
            if ([int64]$copied.SizeBytes -ne [int64]$source.SizeBytes -or
                [string]$copied.Sha256 -cne [string]$source.Sha256) {
                throw "$Label copied bytes differ from the locked input."
            }
        }
        finally {
            $copied.Stream.Dispose()
        }
        return [pscustomobject]@{
            FileName = [string]$source.FileName
            SizeBytes = [int64]$source.SizeBytes
            Sha256 = [string]$source.Sha256
        }
    }
    finally {
        $source.Stream.Dispose()
    }
}

function New-LauncherArchiveFromImportedClients {
    param(
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][psobject]$ClientReceipt,
        [Parameter(Mandatory = $true)][string]$ImportedSignedRoot,
        [Parameter(Mandatory = $true)][string]$ArchivePath,
        [Parameter(Mandatory = $true)][string]$OwnedStagingRoot
    )

    $includedRoles = @('launcher', 'client-bootstrapper', 'maintenance')
    $leases = [Collections.Generic.List[object]]::new()
    $byRole = @{}
    $profilePath = Join-Path $OwnedStagingRoot '.canonical-enterprise-build-profile.json'
    try {
        foreach ($role in $includedRoles) {
            $index = -1
            for ($candidate = 0; $candidate -lt @($Plan.clientSigningInputs).Count; $candidate++) {
                if ([string]$Plan.clientSigningInputs[$candidate].role -ceq $role) {
                    $index = $candidate
                    break
                }
            }
            if ($index -lt 0) {
                throw "Enterprise signed-client plan is missing role '$role'."
            }
            $planned = $Plan.clientSigningInputs[$index]
            $imported = $ClientReceipt.data.files[$index]
            if ([string]$imported.role -cne $role -or
                [string]$imported.fileName -cne [string]$planned.fileName) {
                throw "Enterprise imported client role '$role' is not in canonical plan order."
            }
            $lease = Open-ProductionReleaseInput `
                -Path (Join-Path $ImportedSignedRoot ([string]$planned.fileName)) `
                -Label "Imported signed Enterprise client $role" `
                -MaximumBytes 512MB
            if ([int64]$lease.SizeBytes -ne [int64]$imported.sizeBytes -or
                [string]$lease.Sha256 -cne [string]$imported.sha256) {
                $lease.Stream.Dispose()
                throw "Imported signed Enterprise client '$role' differs from its r3 receipt."
            }
            $leases.Add([pscustomobject]@{
                Role = $role
                FileName = [string]$planned.fileName
                Descriptor = $lease
            })
            $byRole[$role] = $lease
        }

        $profileBytes = ConvertTo-ProductionJsonBytes -Value ([ordered]@{
            schemaVersion = 1
            layoutProfile = 'enterprise'
        })
        Write-ProductionStateFile -Path $profilePath -Bytes $profileBytes
        $profile = Open-ProductionReleaseInput `
            -Path $profilePath `
            -Label 'Canonical Enterprise production profile marker' `
            -MaximumBytes 4KB
        try {
            Add-Member `
                -InputObject $byRole['launcher'] `
                -NotePropertyName RelativePath `
                -NotePropertyValue 'Ensou.Dsh.Enterprise.Launcher.exe'
            Add-Member `
                -InputObject $profile `
                -NotePropertyName RelativePath `
                -NotePropertyValue 'enterprise-build-profile.json'
            $launcherTree = [pscustomobject]@{
                Label = 'Imported signed Enterprise Launcher'
                Files = @($byRole['launcher'], $profile)
            }
            $archive = EnterpriseProductionPayload\New-EnterpriseProductionLauncherArchive `
                -LauncherTree $launcherTree `
                -ClientBootstrapper $byRole['client-bootstrapper'] `
                -Maintenance $byRole['maintenance'] `
                -Path $ArchivePath
            foreach ($lease in $leases) {
                Assert-ProductionReleaseInputStillLocked `
                    -Descriptor $lease.Descriptor `
                    -Label "Imported signed Enterprise client $($lease.Role)"
            }
            Assert-ProductionReleaseInputStillLocked `
                -Descriptor $profile `
                -Label 'Canonical Enterprise production profile marker'
            return $archive
        }
        finally {
            $profile.Stream.Dispose()
        }
    }
    finally {
        foreach ($lease in $leases) {
            $lease.Descriptor.Stream.Dispose()
        }
        if (Test-Path -LiteralPath $profilePath -PathType Leaf) {
            [IO.File]::Delete($profilePath)
        }
    }
}

function Assert-PublisherPolicySemantics {
    param(
        [Parameter(Mandatory = $true)][psobject]$Policy,
        [Parameter(Mandatory = $true)][psobject]$Plan
    )

    if ([int64]$Policy.minAcceptedSequence -gt [int64]$Policy.sequence) {
        throw 'Enterprise Publisher minAcceptedSequence cannot exceed sequence.'
    }
    $expiry = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            [string]$Policy.expiresAtUtc,
            "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",
            [Globalization.CultureInfo]::InvariantCulture,
            ([Globalization.DateTimeStyles]::AssumeUniversal -bor
             [Globalization.DateTimeStyles]::AdjustToUniversal),
            [ref]$expiry) -or
        $expiry.Offset -ne [TimeSpan]::Zero) {
        throw 'Enterprise Publisher expiresAtUtc must be exact UTC.'
    }
    $now = [DateTimeOffset]::UtcNow
    if ($expiry -le $now.AddMinutes(5) -or $expiry -gt $now.AddDays(31)) {
        throw 'Enterprise Publisher expiry must be more than five minutes and at most 31 days in the future.'
    }
    $previous = $null
    foreach ($releaseSetId in @($Policy.revokedReleaseSetIds)) {
        if ([string]$releaseSetId -ceq [string]$Plan.releaseSetId -or
            ($null -ne $previous -and
             [string]::CompareOrdinal([string]$previous, [string]$releaseSetId) -ge 0)) {
            throw 'Enterprise Publisher revocation IDs must be strictly ordinal and cannot revoke the candidate.'
        }
        $previous = [string]$releaseSetId
    }
    $componentIds = @(
        [string]$Policy.launcherReleaseId,
        [string]$Plan.runtimeCandidate.releaseId,
        [string]$Policy.pluginPolicyReleaseId)
    if (@($componentIds | Select-Object -Unique).Count -ne 3) {
        throw 'Enterprise Publisher component release IDs must be distinct.'
    }
}

$planInput = Read-StrictProductionJsonFile `
    -Path $PlanPath `
    -Label 'Enterprise production release plan' `
    -SchemaPath $planSchemaPath
[void](Assert-CanonicalProductionJsonInput `
    -Input $planInput `
    -Label 'Enterprise production release plan')
$plan = $planInput.Value
if ([int]$plan.schemaVersion -ne 2 -or
    [string]$plan.edition -cne 'Enterprise' -or
    [string]$plan.targetChannel -cne 'stable') {
    throw 'Enterprise production Publisher input requires one v2 Enterprise stable plan.'
}

$stateLock = Enter-ProductionReleaseStateReadLock -StateRoot $StateRoot
try {
$state = Get-ProductionReleaseState `
    -StateRoot $stateLock.StateRoot `
    -StateSchemaPath $stateSchemaPath
if ([int]$state.SchemaVersion -ne 2 -or
    [string]$state.Identity.edition -cne 'Enterprise' -or
    [string]$state.TargetChannel -cne 'stable' -or
    [int]$state.Head.revision -ne 3 -or
    [string]$state.Head.phase -cne 'CLIENT_SIGNATURES_IMPORTED' -or
    [string]$state.Identity.planSha256 -cne [string]$planInput.Sha256) {
    throw 'Enterprise production Publisher input requires the exact r3 CLIENT_SIGNATURES_IMPORTED state for this plan.'
}

$policyInput = Read-StrictProductionJsonFile `
    -Path $PublisherPolicyPath `
    -Label 'Enterprise production Publisher policy' `
    -SchemaPath $publisherPolicySchemaPath
[void](Assert-CanonicalProductionJsonInput `
    -Input $policyInput `
    -Label 'Enterprise production Publisher policy')
Assert-PublisherPolicySemantics -Policy $policyInput.Value -Plan $plan

if (-not [IO.Path]::IsPathFullyQualified($OutputDirectory)) {
    throw 'Enterprise Publisher input output directory must be absolute.'
}
$outputFull = [IO.Path]::GetFullPath($OutputDirectory)
$outputParentPath = [IO.Path]::GetDirectoryName($outputFull)
$outputName = [IO.Path]::GetFileName($outputFull)
if ([string]::IsNullOrWhiteSpace($outputParentPath) -or
    [string]::IsNullOrWhiteSpace($outputName) -or
    (Test-Path -LiteralPath $outputFull)) {
    throw 'Enterprise Publisher input output must be one new child directory.'
}
$outputParent = Assert-OrdinaryLocalDirectory `
    -Path $outputParentPath `
    -Label 'Enterprise Publisher input output parent'
$stagingName = ".ensou-enterprise-publisher-input-$([Guid]::NewGuid().ToString('N'))"
$stagingRoot = Join-Path $outputParent $stagingName
$stagingPayload = Join-Path $stagingRoot 'payload'
[IO.Directory]::CreateDirectory($stagingPayload) | Out-Null

$files = [Collections.Generic.List[object]]::new()
$fileNames = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase)
$editionFiles = [Collections.Generic.List[object]]::new()

function Add-PayloadDescriptor {
    param(
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][int64]$MaximumBytes,
        [switch]$EditionSpecific
    )

    $sourceName = [IO.Path]::GetFileName([IO.Path]::GetFullPath($SourcePath))
    if (-not $fileNames.Add($sourceName)) {
        throw "Enterprise Publisher payload has a case-insensitive filename collision: $sourceName"
    }
    $copied = Copy-LockedPublisherInput `
        -SourcePath $SourcePath `
        -DestinationPath (Join-Path $stagingPayload $sourceName) `
        -MaximumBytes $MaximumBytes `
        -Label "Enterprise Publisher payload role $Role"
    $descriptor = [ordered]@{
        role = $Role
        fileName = $sourceName
        relativePath = 'payload/' + $sourceName
        sizeBytes = [int64]$copied.SizeBytes
        sha256 = [string]$copied.Sha256
    }
    if ($EditionSpecific) {
        $editionFiles.Add($descriptor)
    }
    else {
        $files.Add($descriptor)
    }
}

$completed = $false
try {
    $clientReceipt = $state.Receipts[2]
    $signedRoot = Join-Path $state.StateRoot 'imports\client-signing.v1\signed'
    for ($index = 0; $index -lt @($plan.clientSigningInputs).Count; $index++) {
        $planned = $plan.clientSigningInputs[$index]
        $imported = $clientReceipt.data.files[$index]
        if ([string]$planned.role -cne [string]$imported.role -or
            [string]$planned.fileName -cne [string]$imported.fileName) {
            throw "Enterprise imported client index $index differs from the plan."
        }
        Add-PayloadDescriptor `
            -Role ('client-' + [string]$planned.role) `
            -SourcePath (Join-Path $signedRoot ([string]$planned.fileName)) `
            -MaximumBytes 512MB
    }

    $runtimeRoles = @(
        'runtime-archive',
        'runtime-metadata',
        'runtime-hash-evidence')
    $runtimeInputs = @(
        $plan.runtimeCandidate.archive,
        $plan.runtimeCandidate.metadata,
        $plan.runtimeCandidate.hashEvidence)
    for ($index = 0; $index -lt $runtimeInputs.Count; $index++) {
        Add-PayloadDescriptor `
            -Role $runtimeRoles[$index] `
            -SourcePath ([string]$runtimeInputs[$index].path) `
            -MaximumBytes $(if ($index -eq 0) { 8GB } else { 4MB })
    }

    $launcherArchiveName =
        "Ensou.Dsh.Enterprise.Launcher-$($plan.releaseSetId)-win-x64.zip"
    if (-not $fileNames.Add($launcherArchiveName)) {
        throw 'Enterprise Launcher archive filename collides with another Publisher payload.'
    }
    $launcherArchivePath = Join-Path $stagingPayload $launcherArchiveName
    [void](New-LauncherArchiveFromImportedClients `
        -Plan $plan `
        -ClientReceipt $clientReceipt `
        -ImportedSignedRoot $signedRoot `
        -ArchivePath $launcherArchivePath `
        -OwnedStagingRoot $stagingRoot)
    $launcherArchive = Open-ProductionReleaseInput `
        -Path $launcherArchivePath `
        -Label 'Generated Enterprise Launcher archive' `
        -MaximumBytes 1GB
    try {
        $editionFiles.Add([ordered]@{
            role = 'edition-launcher-archive'
            fileName = $launcherArchiveName
            relativePath = 'payload/' + $launcherArchiveName
            sizeBytes = [int64]$launcherArchive.SizeBytes
            sha256 = [string]$launcherArchive.Sha256
        })
    }
    finally {
        $launcherArchive.Stream.Dispose()
    }

    Add-PayloadDescriptor -EditionSpecific `
        -Role 'edition-plugin-generation-ledger' `
        -SourcePath $PluginGenerationLedgerPath `
        -MaximumBytes 16MB
    Add-PayloadDescriptor -EditionSpecific `
        -Role 'edition-plugin-generation-reservation' `
        -SourcePath $PluginGenerationReservationPath `
        -MaximumBytes 4MB
    Add-PayloadDescriptor -EditionSpecific `
        -Role 'edition-plugin-harness-compatibility' `
        -SourcePath $PluginHarnessCompatibilityReceiptPath `
        -MaximumBytes 16MB
    Add-PayloadDescriptor -EditionSpecific `
        -Role 'edition-plugin-metadata' `
        -SourcePath $PluginPolicyMetadataPath `
        -MaximumBytes 4MB
    Add-PayloadDescriptor -EditionSpecific `
        -Role 'edition-plugin-organization-admission' `
        -SourcePath $PluginOrganizationAdmissionReceiptPath `
        -MaximumBytes 4MB
    Add-PayloadDescriptor -EditionSpecific `
        -Role 'edition-plugin-policy-archive' `
        -SourcePath $PluginPolicyArchivePath `
        -MaximumBytes 512MB
    Add-PayloadDescriptor -EditionSpecific `
        -Role 'edition-plugin-promotion-handoff' `
        -SourcePath $PluginPromotionHandoffPath `
        -MaximumBytes 4MB
    Add-PayloadDescriptor -EditionSpecific `
        -Role 'edition-plugin-promotion-journal-authorization' `
        -SourcePath $PluginPromotionJournalAuthorizationPath `
        -MaximumBytes 4MB
    Add-PayloadDescriptor -EditionSpecific `
        -Role 'edition-publisher-policy' `
        -SourcePath $policyInput.Path `
        -MaximumBytes 4MB
    Add-PayloadDescriptor -EditionSpecific `
        -Role 'edition-runtime-organization-admission' `
        -SourcePath $RuntimeOrganizationAdmissionReceiptPath `
        -MaximumBytes 4MB

    foreach ($editionFile in @($editionFiles | Sort-Object {
                [string]$_.role
            })) {
        $files.Add($editionFile)
    }
    $descriptor = [ordered]@{
        schemaVersion = 1
        descriptorType = 'ensou-dsh-launcher-production-publisher-input'
        orchestrationId = [string]$plan.orchestrationId
        edition = 'Enterprise'
        releaseSetId = [string]$plan.releaseSetId
        channel = 'stable'
        planSha256 = [string]$state.Identity.planSha256
        sourceCommit = [string]$plan.sourceCommit
        manifestUri = [string]$plan.manifestUri
        artifactBaseUri = [string]$plan.artifactBaseUri
        releaseManifestTrust = $plan.releaseManifestTrust
        releaseCompatibility = $plan.releaseCompatibility
        componentReleaseIds = [ordered]@{
            launcher = [string]$policyInput.Value.launcherReleaseId
            runtime = [string]$plan.runtimeCandidate.releaseId
            pluginPolicy = [string]$policyInput.Value.pluginPolicyReleaseId
        }
        runtimeProvenance = [ordered]@{
            harnessSourceTag =
                [string]$state.Receipts[0].data.runtimeCandidate.harnessSourceTag
            harnessSourceCommit =
                [string]$state.Receipts[0].data.runtimeCandidate.harnessSourceCommit
        }
        files = $files
    }
    $runtimeSourceReleaseExpectation =
        ProductionReleaseState\Get-ProductionRuntimeSourceReleaseExpectation -Plan $plan
    if ($null -ne $runtimeSourceReleaseExpectation) {
        # This anchor belongs to the independently built runtime candidate. It
        # is intentionally not substituted with the later Launcher sourceCommit.
        $descriptor.Insert(
            14,
            'runtimeSourceReleaseExpectation',
            [ordered]@{
                repository = [string]$runtimeSourceReleaseExpectation.repository
                tagName = [string]$runtimeSourceReleaseExpectation.tagName
                targetCommit = [string]$runtimeSourceReleaseExpectation.targetCommit
            })
    }
    $descriptorBytes = ConvertTo-ProductionJsonBytes -Value $descriptor
    [void](ConvertFrom-StrictProductionJsonBytes `
        -Bytes $descriptorBytes `
        -Label 'Generated Enterprise production Publisher input descriptor' `
        -SchemaPath $publisherInputSchemaPath)
    $descriptorPath = Join-Path $stagingRoot 'publisher-input.v1.json'
    Write-ProductionStateFile -Path $descriptorPath -Bytes $descriptorBytes
    $descriptorInput = Read-StrictProductionJsonFile `
        -Path $descriptorPath `
        -Label 'Generated Enterprise production Publisher input descriptor' `
        -SchemaPath $publisherInputSchemaPath
    [void](Assert-ProductionPublisherInputFileSet `
        -Plan $plan `
        -PlanSha256 ([string]$state.Identity.planSha256) `
        -PlanAdmissionReceipt $state.Receipts[0] `
        -ClientImportReceipt $clientReceipt `
        -DescriptorInput $descriptorInput `
        -PayloadRoot $stagingPayload)

    [IO.Directory]::Move($stagingRoot, $outputFull)
    $completed = $true
    [pscustomobject]@{
        OutputDirectory = $outputFull
        PublisherInputPath = Join-Path $outputFull 'publisher-input.v1.json'
        PublisherInputSha256 = [string]$descriptorInput.Sha256
        LauncherArchivePath = Join-Path `
            (Join-Path $outputFull 'payload') `
            $launcherArchiveName
        FileCount = [int]$files.Count
        StateRevision = 3
        StatePhase = 'CLIENT_SIGNATURES_IMPORTED'
        NoGo = 'External Enterprise ReleasePublisher and manifest-publishing-response signing remain required.'
    }
}
finally {
    if (-not $completed -and
        (Test-Path -LiteralPath $stagingRoot -PathType Container) -and
        [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($stagingRoot)) -ceq
            [IO.Path]::GetFullPath($outputParent) -and
        [IO.Path]::GetFileName($stagingRoot).StartsWith(
            '.ensou-enterprise-publisher-input-',
            [StringComparison]::Ordinal)) {
        [IO.Directory]::Delete($stagingRoot, $true)
    }
}
}
finally {
    $stateLock.Stream.Dispose()
}
