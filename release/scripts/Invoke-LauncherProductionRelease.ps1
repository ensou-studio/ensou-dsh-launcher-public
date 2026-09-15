#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Personal', 'Enterprise')]
    [string]$Edition,

    [Parameter(Mandatory = $true)]
    [ValidateSet(
        'Prepare',
        'ImportClientSignatures',
        'PrepareManifestSigning',
        'ImportSignedCandidate',
        'PrepareInstallerSigning',
        'ImportInstallerSignature',
        'BindPilotEvidence',
        'Promote',
        'Status')]
    [string]$Phase,

    [Parameter(Mandatory = $true)]
    [string]$PlanPath,

    [Parameter(Mandatory = $true)]
    [string]$StateRoot,

    [string]$RepositoryRoot = [IO.Path]::GetFullPath(
        [IO.Path]::Combine($PSScriptRoot, '..', '..')),

    [string]$ResponsePath = '',

    [string]$PublisherInputPath = '',

    [string]$InstallerSigningInputPath = '',

    [string]$EnterpriseInstallerPayloadPath = '',

    [string]$EnterpriseInstallerPackageDirectory = '',

    [string]$EnterpriseInstallerDotNetSdkArchivePath = '',

    [string]$PersonalInstallerPayloadPath = '',

    [string]$PersonalInstallerPackageDirectory = '',

    [string]$PersonalInstallerDotNetSdkArchivePath = '',

    [string]$WindowsPilotEvidenceEnvelopePath = '',

    [string]$WindowsPilotEvidenceBodyPath = '',

    [string]$WindowsPilotVerificationReportPath = '',

    [string]$WindowsPilotReadinessConfigPath = '',

    [string]$WindowsPilotStoredReadinessReportPath = '',

    [string]$WindowsPilotReplayedReadinessReportPath = '',

    [string]$LocalDataCertificationReceiptPath = '',

    [string]$StablePrivatePilotObservationPath = '',

    [string]$PilotTrustPolicyPath = '',

    [switch]$RevalidatePilotEvidence,

    [string]$PromotionRoot = '',

    [string]$FeedPromotionResponsePath = '',

    [string]$PersonalFeedPromotionResultPath = '',

    [string]$EnterpriseStablePublicationResultBundlePath = '',

    [string]$EnterpriseStablePublicationContextPath = '',

    [string]$ExpectedFeedIdentitySha256 = '',

    [string]$ExpectedChannelHead = '',

    [string]$ExpectedJournalHead = '',

    [string]$ExpectedHeadSha256 = '',

    [Parameter(DontShow = $true)]
    [ValidateSet(
        '',
        'AfterPlanReceipt',
        'AfterInitializationRoot',
        'AfterPlanPending',
        'AfterPlanSnapshot',
        'AfterIdentityPending',
        'AfterIdentity',
        'AfterRequestFile',
        'AfterClientRequestReceipt',
        'AfterImportSnapshot',
        'AfterImportReceipt',
        'AfterManifestRequestBundle',
        'AfterManifestRequestReceipt',
        'AfterSignedCandidateBundle',
        'AfterSignedCandidateReceipt',
        'AfterInstallerRequestBundle',
        'AfterInstallerRequestReceipt',
        'AfterInstallerImportBundle',
        'AfterInstallerImportReceipt',
        'AfterPilotEvidenceBundle',
        'AfterPilotEvidenceReceipt',
        'AfterStablePromotionStateBundle',
        'AfterStablePromotionReceipt',
        'AfterStablePublicationBundle',
        'AfterStablePublicationReceipt',
        'TestOnlyWaitBeforeRequestCheckoutAdmission',
        'TestOnlyWaitBeforeImportCheckoutAdmission',
        'TestOnlyWaitBeforeManifestRequestCheckoutAdmission',
        'TestOnlyWaitBeforeSignedCandidateCheckoutAdmission',
        'TestOnlyWaitBeforeInstallerRequestCheckoutAdmission',
        'TestOnlyWaitBeforeInstallerImportCheckoutAdmission',
        'TestOnlyWaitBeforePilotEvidenceCheckoutAdmission',
        'TestOnlyWaitBeforeStablePromotionCheckoutAdmission',
        'TestOnlyWaitBeforeValidatedBundleAtomicMove')]
    [string]$FaultPoint = '',

    [ValidateSet(1, 2)]
    [int]$WindowsPilotReadinessSchemaVersion = 1,

    [ValidateSet('enterprise-managed', 'enterprise-direct-local')]
    [string]$EnterpriseRuntimeProfile = 'enterprise-managed'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Edition -cne 'Enterprise' -and $WindowsPilotReadinessSchemaVersion -ne 1) {
    throw 'Versioned Windows Pilot readiness selection is available only for Enterprise.'
}
if ($Edition -cne 'Enterprise' -and $EnterpriseRuntimeProfile -cne 'enterprise-managed') {
    throw 'Direct-local runtime selection is available only for Enterprise.'
}

$utf8Strict = [Text.UTF8Encoding]::new($false, $true)
$script:releaseProbeProcessType = $null

function Test-SameOrDescendantPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $boundary = [IO.Path]::GetFullPath($Root).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    return $candidate.Equals($boundary, [StringComparison]::OrdinalIgnoreCase) -or
        $candidate.StartsWith(
            $boundary + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)
}

function Invoke-ProductionGitRead {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $output = @(& git -C $Root @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed: $($output -join ' ')"
    }
    return @($output | ForEach-Object { [string]$_ })
}

function Assert-RequiredProductionCmdlet {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ModuleName
    )

    $effective = Microsoft.PowerShell.Core\Get-Command -Name $Name -ErrorAction Stop
    if ($effective.CommandType -ne [Management.Automation.CommandTypes]::Cmdlet -or
        [string]$effective.ModuleName -cne $ModuleName) {
        throw "Production orchestration rejects a caller override of $Name."
    }
    $qualified = @(Microsoft.PowerShell.Core\Get-Command -Name ($ModuleName + '\' + $Name) -ErrorAction Stop)
    if ($qualified.Count -ne 1 -or
        $qualified[0].CommandType -ne [Management.Automation.CommandTypes]::Cmdlet -or
        [string]$qualified[0].ModuleName -cne $ModuleName) {
        throw "Required production cmdlet $ModuleName\$Name is unavailable."
    }
}

function Assert-ProductionCmdletBoundary {
    foreach ($contract in @(
        [pscustomobject]@{ Name = 'Get-AuthenticodeSignature'; Module = 'Microsoft.PowerShell.Security' },
        [pscustomobject]@{ Name = 'Test-Json'; Module = 'Microsoft.PowerShell.Utility' },
        [pscustomobject]@{ Name = 'ConvertTo-Json'; Module = 'Microsoft.PowerShell.Utility' },
        [pscustomobject]@{ Name = 'ConvertFrom-Json'; Module = 'Microsoft.PowerShell.Utility' },
        [pscustomobject]@{ Name = 'Test-Path'; Module = 'Microsoft.PowerShell.Management' },
        [pscustomobject]@{ Name = 'Get-Item'; Module = 'Microsoft.PowerShell.Management' },
        [pscustomobject]@{ Name = 'Get-ChildItem'; Module = 'Microsoft.PowerShell.Management' },
        [pscustomobject]@{ Name = 'Join-Path'; Module = 'Microsoft.PowerShell.Management' },
        [pscustomobject]@{ Name = 'Import-Module'; Module = 'Microsoft.PowerShell.Core' },
        [pscustomobject]@{ Name = 'Add-Type'; Module = 'Microsoft.PowerShell.Utility' },
        [pscustomobject]@{ Name = 'ForEach-Object'; Module = 'Microsoft.PowerShell.Core' },
        [pscustomobject]@{ Name = 'Sort-Object'; Module = 'Microsoft.PowerShell.Utility' }
    )) {
        Assert-RequiredProductionCmdlet -Name $contract.Name -ModuleName $contract.Module
    }
}

function Assert-LauncherCodeCheckoutBootstrap {
    param()

    if (-not [IO.Path]::IsPathFullyQualified($RepositoryRoot)) {
        throw 'Launcher repository root must be absolute.'
    }
    $root = [IO.Path]::GetFullPath($RepositoryRoot)
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Launcher repository root must be one ordinary non-linked directory.'
    }
    $topLevel = @(Invoke-ProductionGitRead -Root $root -Arguments @('rev-parse', '--show-toplevel') -Label 'Launcher code Git root admission')
    if ($topLevel.Count -ne 1 -or
        -not [IO.Path]::GetFullPath($topLevel[0]).Equals(
            $root,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Launcher repository root is not the exact Git top-level checkout.'
    }
    $status = @(Invoke-ProductionGitRead -Root $root -Arguments @('status', '--porcelain=v1', '--untracked-files=all') -Label 'Launcher code clean-tree admission')
    if ($status.Count -ne 0) {
        throw 'Launcher production orchestration code must come from a clean tracked and untracked Git checkout.'
    }

    $relativePaths = @(
        'release/scripts/Invoke-LauncherProductionRelease.ps1',
        'release/scripts/ProductionReleaseState.psm1',
        'src/Ensou.Dsh.Host/WindowsJobObject.cs',
        'release/scripts/ProductionReleaseProbeProcess.cs',
        'release/scripts/PersonalProductionReleaseAdapter.psm1',
        'release/scripts/EnterpriseProductionReleaseAdapter.psm1',
        'release/scripts/New-EnterpriseProductionPilotEvidenceInput.ps1',
        'release/scripts/EnterpriseProductionPilotEvidence.psm1',
        'release/scripts/CertifiedDistributionInput.ps1',
        'release/scripts/InstallerSigningContracts.psm1',
        'release/scripts/PersonalInstallerTrustedBuild.psm1',
        'release/scripts/PersonalInstallerSigningPipeline.psm1',
        'release/scripts/PersonalInstallerProductionPayloadSelfCheck.psm1',
        'release/scripts/ProductionBoundedProcess.psm1',
        'release/scripts/EnterpriseInstallerTrustedBuild.psm1',
        'release/scripts/ProductionFeedPromotion.psm1',
        'release/scripts/PersonalFeedPromotionResult.psm1',
        'release/scripts/PersonalFeedExecutionResultProducer.psm1',
        'release/scripts/EnterpriseStablePublicationResult.psm1',
        'release/schemas/enterprise-stable-publication-context-v1.schema.json',
        'release/schemas/enterprise-stable-publication-result-v1.schema.json',
        'release/schemas/enterprise-stable-publication-statement-v1.schema.json',
        'release/schemas/personal-feed-execution-result-v1.schema.json',
        'release/scripts/PortableDotNetSdkClosure.psm1',
        'release/locks/dotnet-sdk-10.0.302-win-x64.files.lock.json',
        'scripts/EnterpriseProductionPayload.psm1',
        'release/scripts/Test-SourceRuntimeMetadata.ps1',
        'release/schemas/launcher-production-release-plan-v1.schema.json',
        'release/schemas/launcher-production-release-plan-v2.schema.json',
        'release/schemas/launcher-external-signing-request-v1.schema.json',
        'release/schemas/launcher-external-signing-response-v1.schema.json',
        'release/schemas/launcher-production-publisher-input-v1.schema.json',
        'release/schemas/launcher-manifest-publishing-request-v1.schema.json',
        'release/schemas/launcher-manifest-publishing-response-v1.schema.json',
        'release/schemas/launcher-installer-signing-request-v1.schema.json',
        'release/schemas/launcher-installer-signing-request-v2.schema.json',
        'release/schemas/personal-installer-signing-request-v2.schema.json',
        'release/schemas/personal-installer-signing-response-v2.schema.json',
        'release/schemas/personal-installer-trusted-build-evidence-v1.schema.json',
        'release/schemas/personal-installer-production-payload-self-check-result-v1.schema.json',
        'release/schemas/personal-installer-production-payload-self-check-evidence-v1.schema.json',
        'release/schemas/launcher-enterprise-installer-signing-request-v2.schema.json',
        'release/schemas/launcher-installer-signing-response-v1.schema.json',
        'release/schemas/enterprise-installer-trusted-build-evidence-v1.schema.json',
        'release/schemas/enterprise-production-pilot-evidence-input-v1.schema.json',
        'release/schemas/enterprise-production-pilot-evidence-trust-v1.schema.json',
        'release/schemas/enterprise-windows-pilot-evidence-envelope-v2.schema.json',
        'release/schemas/enterprise-windows-pilot-evidence-body-v2.schema.json',
        'release/schemas/enterprise-windows-pilot-verification-report-v2.schema.json',
        'release/schemas/enterprise-pilot-readiness-v1.schema.json',
        'release/schemas/enterprise-pilot-readiness-report-v1.schema.json',
        'release/schemas/enterprise-pilot-readiness-v2.schema.json',
        'release/schemas/enterprise-pilot-readiness-report-v2.schema.json',
        'release/schemas/enterprise-local-data-compatibility-certification-receipt-v1.schema.json',
        'release/schemas/enterprise-production-stable-private-pilot-observation-v1.schema.json',
        'release/schemas/enterprise-windows-pilot-gate-contract-v2.schema.json',
        'release/schemas/launcher-feed-promotion-request-v1.schema.json',
        'release/schemas/launcher-feed-promotion-response-v1.schema.json',
        'release/schemas/launcher-feed-promotion-state-v1.schema.json',
        'release/schemas/launcher-feed-promotion-admission-v1.schema.json',
        'release/enterprise-windows-pilot-gate-contract-v2.json',
        'release/schemas/launcher-production-release-state-v1.schema.json',
        'release/schemas/launcher-production-release-state-v2.schema.json',
        'release/schemas/source-runtime-metadata.schema.json',
        'release/schemas/enterprise-direct-local-source-runtime-metadata.schema.json',
        'installer/personal-publish-runtime-packs.lock.json'
    )
    $expectedScript = [IO.Path]::GetFullPath(
        (Join-Path $root $relativePaths[0].Replace('/', [IO.Path]::DirectorySeparatorChar)))
    if (-not [IO.Path]::GetFullPath($PSCommandPath).Equals(
            $expectedScript,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Launcher production orchestrator must execute from its canonical tracked repository path.'
    }

    $leases = [Collections.Generic.List[IDisposable]]::new()
    $descriptors = [Collections.Generic.List[object]]::new()
    try {
        foreach ($relativePath in $relativePaths) {
            $nativeRelative = $relativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)
            $fullPath = [IO.Path]::GetFullPath((Join-Path $root $nativeRelative))
            $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
            if ($item.PSIsContainer -or
                ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                $item.Length -le 0) {
                throw "Tracked production orchestrator input is missing, linked, or empty: $relativePath"
            }
            for ($current = $item.Directory; $null -ne $current; $current = $current.Parent) {
                if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "Tracked production orchestrator input crosses a filesystem link: $relativePath"
                }
            }
            [void](Invoke-ProductionGitRead -Root $root -Arguments @('ls-files', '--error-unmatch', '--', $relativePath) -Label "Tracked code admission $relativePath")
            $headBlob = @(Invoke-ProductionGitRead -Root $root -Arguments @('rev-parse', "HEAD:$relativePath") -Label "HEAD code blob admission $relativePath")
            $workingBlob = @(Invoke-ProductionGitRead -Root $root -Arguments @('hash-object', "--path=$relativePath", '--', $fullPath) -Label "Working code blob admission $relativePath")
            if ($headBlob.Count -ne 1 -or
                $workingBlob.Count -ne 1 -or
                [string]$headBlob[0] -cne [string]$workingBlob[0]) {
                throw "Tracked production orchestrator input differs from HEAD: $relativePath"
            }
            $stream = [IO.File]::Open(
                $fullPath,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::Read)
            $leases.Add($stream)
            $sha256 = ([Convert]::ToHexString(
                [Security.Cryptography.SHA256]::HashData($stream))).ToLowerInvariant()
            $stream.Position = 0
            $descriptors.Add([pscustomobject]@{
                RelativePath = $relativePath
                Path = $fullPath
                SizeBytes = $stream.Length
                Sha256 = $sha256
                BootstrapStream = $stream
            })
        }
        return [pscustomobject]@{
            Root = $root
            BootstrapLeases = $leases
            Descriptors = $descriptors
        }
    }
    catch {
        for ($index = $leases.Count - 1; $index -ge 0; $index--) {
            $leases[$index].Dispose()
        }
        throw
    }
}

function ConvertTo-LauncherCodeLockedAdmission {
    param([Parameter(Mandatory = $true)]$Bootstrap)

    $leases = [Collections.Generic.List[IDisposable]]::new()
    $descriptors = [Collections.Generic.List[object]]::new()
    try {
        foreach ($descriptor in @($Bootstrap.Descriptors)) {
            $locked = Open-ProductionReleaseInput -Path ([string]$descriptor.Path) -Label "Tracked orchestrator input $($descriptor.RelativePath)" -MaximumBytes 16MB
            if ($locked.SizeBytes -ne [int64]$descriptor.SizeBytes -or
                $locked.Sha256 -cne [string]$descriptor.Sha256) {
                $locked.Stream.Dispose()
                throw "Tracked orchestrator input changed during module admission: $($descriptor.RelativePath)"
            }
            $leases.Add($locked.Stream)
            $descriptors.Add($locked)
        }
        for ($index = $Bootstrap.BootstrapLeases.Count - 1; $index -ge 0; $index--) {
            $Bootstrap.BootstrapLeases[$index].Dispose()
        }
        return [pscustomobject]@{
            Leases = $leases
            Descriptors = $descriptors
        }
    }
    catch {
        for ($index = $leases.Count - 1; $index -ge 0; $index--) {
            $leases[$index].Dispose()
        }
        throw
    }
}

function Assert-PersonalCompletedResultPathBoundary {
    param([string]$ResultPath,[string]$CheckoutRoot,[string]$StatePath,[string]$PromotionPath)
    if (-not [IO.Path]::IsPathFullyQualified($ResultPath)) { throw 'Personal completed result path must be absolute.' }
    $resultRoot=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($ResultPath))
    foreach($boundary in @($CheckoutRoot,$StatePath,$PromotionPath)) {
        if ([string]::IsNullOrWhiteSpace($boundary)) { continue }
        if (-not [IO.Path]::IsPathFullyQualified($boundary) -or
            (Test-SameOrDescendantPath -Path $resultRoot -Root $boundary) -or
            (Test-SameOrDescendantPath -Path $boundary -Root $resultRoot)) {
            throw 'Personal completed result bundle must be absolute and disjoint from checkout, production state, and promotion workspace.'
        }
    }
}

function Assert-ProductionExternalPathBoundary {
    param(
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $externalPaths = @(
        $PlanPath,
        $StateRoot,
        $Plan.runtimeCandidate.archive.path,
        $Plan.runtimeCandidate.metadata.path,
        $Plan.runtimeCandidate.hashEvidence.path
    ) + @($Plan.clientSigningInputs | ForEach-Object { $_.path })
    foreach ($externalPath in $externalPaths) {
        if (-not [IO.Path]::IsPathFullyQualified([string]$externalPath) -or
            (Test-SameOrDescendantPath -Path ([string]$externalPath) -Root $Root)) {
            throw 'Production state, plan, runtime evidence, and signing inputs must be absolute and outside the Launcher checkout.'
        }
    }
    if ($ResponsePath -and
        (-not [IO.Path]::IsPathFullyQualified($ResponsePath) -or
         (Test-SameOrDescendantPath -Path $ResponsePath -Root $Root) -or
         (Test-SameOrDescendantPath -Path $ResponsePath -Root $StateRoot))) {
        throw 'External response must be absolute and remain outside the Launcher checkout and production state.'
    }
    if ($PublisherInputPath -and
        (-not [IO.Path]::IsPathFullyQualified($PublisherInputPath) -or
         (Test-SameOrDescendantPath -Path $PublisherInputPath -Root $Root) -or
         (Test-SameOrDescendantPath -Path $PublisherInputPath -Root $StateRoot))) {
        throw 'External production Publisher input must be absolute and remain outside the Launcher checkout and production state.'
    }
    if ($InstallerSigningInputPath -and
        (-not [IO.Path]::IsPathFullyQualified($InstallerSigningInputPath) -or
         (Test-SameOrDescendantPath -Path $InstallerSigningInputPath -Root $Root) -or
         (Test-SameOrDescendantPath -Path $InstallerSigningInputPath -Root $StateRoot))) {
        throw 'External Installer-signing input must be absolute and remain outside the Launcher checkout and production state.'
    }
    if ($PromotionRoot -and
        (-not [IO.Path]::IsPathFullyQualified($PromotionRoot) -or
         (Test-SameOrDescendantPath -Path $PromotionRoot -Root $Root) -or
         (Test-SameOrDescendantPath -Path $PromotionRoot -Root $StateRoot) -or
         (Test-SameOrDescendantPath -Path $StateRoot -Root $PromotionRoot))) {
        throw 'Offline feed-promotion workspace must be absolute, external, and disjoint from the Launcher checkout and production state.'
    }
    if ($FeedPromotionResponsePath -and
        (-not [IO.Path]::IsPathFullyQualified($FeedPromotionResponsePath) -or
         (Test-SameOrDescendantPath -Path $FeedPromotionResponsePath -Root $Root) -or
         (Test-SameOrDescendantPath -Path $FeedPromotionResponsePath -Root $StateRoot) -or
         ($PromotionRoot -and
          (Test-SameOrDescendantPath -Path $FeedPromotionResponsePath -Root $PromotionRoot)))) {
        throw 'Feed-promotion authorization response must be absolute and remain outside the Launcher checkout, production state, and promotion workspace.'
    }
    if ($PersonalFeedPromotionResultPath) {
        Assert-PersonalCompletedResultPathBoundary -ResultPath $PersonalFeedPromotionResultPath -CheckoutRoot $Root -StatePath $StateRoot -PromotionPath $PromotionRoot
    }
    foreach ($publicationPath in @($EnterpriseStablePublicationResultBundlePath, $EnterpriseStablePublicationContextPath)) {
        if ($publicationPath) {
            if ($Edition -cne 'Enterprise' -or $Phase -cne 'Promote' -or
                -not [IO.Path]::IsPathFullyQualified($publicationPath)) { throw 'Stable publication inputs require Enterprise Promote and absolute external paths.' }
            foreach ($protected in @($Root, $StateRoot, $PromotionRoot) | Where-Object { $_ }) {
                if ((Test-SameOrDescendantPath -Path $publicationPath -Root $protected) -or
                    (Test-SameOrDescendantPath -Path $protected -Root $publicationPath)) { throw 'Stable publication evidence must be disjoint from checkout, state and offline promotion workspace.' }
            }
        }
    }
    if ($EnterpriseStablePublicationResultBundlePath -and $EnterpriseStablePublicationContextPath) { throw 'Export a publication context or import a result, not both in one operation.' }
    foreach ($pilotEvidencePath in @(
            $WindowsPilotEvidenceEnvelopePath,
            $WindowsPilotEvidenceBodyPath,
            $WindowsPilotVerificationReportPath,
            $WindowsPilotReadinessConfigPath,
            $WindowsPilotStoredReadinessReportPath,
            $WindowsPilotReplayedReadinessReportPath,
            $LocalDataCertificationReceiptPath,
            $StablePrivatePilotObservationPath,
            $PilotTrustPolicyPath)) {
        if ($pilotEvidencePath -and
            (-not [IO.Path]::IsPathFullyQualified($pilotEvidencePath) -or
             (Test-SameOrDescendantPath -Path $pilotEvidencePath -Root $Root) -or
             (Test-SameOrDescendantPath -Path $pilotEvidencePath -Root $StateRoot))) {
            throw 'External Pilot evidence must be absolute and remain outside the Launcher checkout and production state.'
        }
    }
    foreach ($trustedBuildPath in @(
            [pscustomobject]@{
                Path = $EnterpriseInstallerPayloadPath
                Label = 'Enterprise Installer payload directory'
            },
            [pscustomobject]@{
                Path = $EnterpriseInstallerPackageDirectory
                Label = 'Enterprise Installer offline package directory'
            })) {
        if ([string]$trustedBuildPath.Path -and
            (-not [IO.Path]::IsPathFullyQualified([string]$trustedBuildPath.Path) -or
             (Test-SameOrDescendantPath `
                    -Path ([string]$trustedBuildPath.Path) `
                    -Root $Root) -or
             (Test-SameOrDescendantPath `
                    -Path ([string]$trustedBuildPath.Path) `
                    -Root $StateRoot))) {
            throw "$($trustedBuildPath.Label) must be absolute and remain outside the Launcher checkout and production state."
        }
    }
    if ($EnterpriseInstallerDotNetSdkArchivePath) {
        if (-not [IO.Path]::IsPathFullyQualified(
                $EnterpriseInstallerDotNetSdkArchivePath) -or
            (Test-SameOrDescendantPath `
                -Path $EnterpriseInstallerDotNetSdkArchivePath `
                -Root $Root) -or
            (Test-SameOrDescendantPath `
                -Path $EnterpriseInstallerDotNetSdkArchivePath `
                -Root $StateRoot)) {
            throw 'Enterprise portable .NET SDK archive must be absolute and remain outside the Launcher checkout and production state.'
        }
        $sdkArchiveItem = Get-Item `
            -LiteralPath ([IO.Path]::GetFullPath(
                $EnterpriseInstallerDotNetSdkArchivePath)) `
            -Force `
            -ErrorAction Stop
        if ($sdkArchiveItem.PSIsContainer -or
            ($sdkArchiveItem.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $sdkArchiveItem.Length -le 0) {
            throw 'Enterprise portable .NET SDK archive must be one non-empty ordinary file.'
        }
        for ($current = $sdkArchiveItem.Directory;
             $null -ne $current;
             $current = $current.Parent) {
            if (($current.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Enterprise portable .NET SDK archive must not cross a filesystem link.'
            }
        }
    }
}

function Assert-LauncherSourceCheckout {
    param([Parameter(Mandatory = $true)][psobject]$Plan)

    if (-not [IO.Path]::IsPathFullyQualified($RepositoryRoot)) {
        throw 'Launcher repository root must be absolute.'
    }
    $root = [IO.Path]::GetFullPath($RepositoryRoot)
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Launcher repository root must be one ordinary non-linked directory.'
    }
    $topLevel = @(Invoke-ProductionGitRead -Root $root -Arguments @('rev-parse', '--show-toplevel') -Label 'Launcher Git root admission')
    if ($topLevel.Count -ne 1 -or
        -not [IO.Path]::GetFullPath($topLevel[0]).Equals(
            $root,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Launcher repository root is not the exact Git top-level checkout.'
    }
    $head = @(Invoke-ProductionGitRead -Root $root -Arguments @('rev-parse', '--verify', 'HEAD') -Label 'Launcher HEAD admission')
    $tree = @(Invoke-ProductionGitRead -Root $root -Arguments @('rev-parse', '--verify', 'HEAD^{tree}') -Label 'Launcher tree admission')
    $status = @(Invoke-ProductionGitRead -Root $root -Arguments @('status', '--porcelain=v1', '--untracked-files=all') -Label 'Launcher clean-tree admission')
    if ($head.Count -ne 1 -or
        [string]$head[0] -cne [string]$Plan.sourceCommit) {
        throw 'Launcher checkout HEAD differs from plan.sourceCommit.'
    }
    if ($tree.Count -ne 1 -or [string]$tree[0] -notmatch '^[0-9a-f]{40,64}$') {
        throw 'Launcher checkout tree identity is invalid.'
    }
    if ($status.Count -ne 0) {
        throw 'Launcher production orchestration requires a clean tracked and untracked Git checkout.'
    }
    foreach ($descriptor in @($codeAdmission.Descriptors)) {
        Assert-ProductionReleaseInputStillLocked -Descriptor $descriptor -Label 'Tracked production orchestrator code'
    }
    Assert-ProductionExternalPathBoundary -Plan $Plan -Root $root
    return [pscustomobject]@{
        Root = $root
        Commit = [string]$head[0]
        Tree = [string]$tree[0]
    }
}

function Assert-ExactProductionDirectoryInventory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Collections.IDictionary]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $directory = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if (-not $directory.PSIsContainer -or
        ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must be one ordinary directory."
    }
    $entries = @(Get-ChildItem -LiteralPath $fullPath -Force)
    if ($entries.Count -ne $Expected.Count) {
        throw "$Label does not contain its exact expected inventory."
    }
    foreach ($entry in $entries) {
        if (-not $Expected.Contains($entry.Name) -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label contains unexpected or linked entry '$($entry.Name)'."
        }
        $expectedDirectory = [bool]$Expected[$entry.Name]
        if ([bool]$entry.PSIsContainer -ne $expectedDirectory) {
            throw "$Label entry '$($entry.Name)' has the wrong file type."
        }
    }
    return $fullPath
}

function Assert-OrdinaryProductionStagingDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedParent,
        [Parameter(Mandatory = $true)][string]$ExpectedName,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $parentPath = [IO.Path]::GetFullPath($ExpectedParent)
    if ([IO.Path]::GetFileName($fullPath) -cne $ExpectedName -or
        -not [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($fullPath)).Equals(
            $parentPath,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label is not the exact operation-owned sibling path."
    }
    $directory = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if (-not $directory.PSIsContainer -or
        ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must be one ordinary non-linked directory."
    }
    for ($current = $directory; $null -ne $current; $current = $current.Parent) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label crosses a filesystem link."
        }
    }
    return $fullPath
}

function Protect-ProductionStagingDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $directory = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $directory.PSIsContainer -or
        ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Production staging ACL target must be one ordinary directory.'
    }
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $currentSid) {
        throw 'Production staging could not resolve the current Windows identity.'
    }
    $allowedSids = @(
        $currentSid,
        [Security.Principal.SecurityIdentifier]::new(
            [Security.Principal.WellKnownSidType]::LocalSystemSid,
            $null),
        [Security.Principal.SecurityIdentifier]::new(
            [Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,
            $null)
    )
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in $allowedSids) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        [void]$security.AddAccessRule($rule)
    }
    [IO.FileSystemAclExtensions]::SetAccessControl($directory, $security)

    $effective = [IO.FileSystemAclExtensions]::GetAccessControl($directory)
    if (-not $effective.AreAccessRulesProtected) {
        throw 'Production staging directory did not retain its private protected ACL.'
    }
    $allowedSidValues = @($allowedSids | ForEach-Object { $_.Value })
    foreach ($rule in @($effective.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            [string]$rule.IdentityReference.Value -notin $allowedSidValues) {
            throw 'Production staging directory contains an unexpected explicit ACL entry.'
        }
    }
}

function New-ProductionBundleStagingRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'request',
            'import',
            'manifest-request',
            'manifest-import',
            'installer-request',
            'installer-import',
            'pilot-evidence-import',
            'pilot-feed-promotion',
            'stable-feed-result',
            'stable-feed-promotion')]
        [string]$Purpose
    )

    $stateRoot = [IO.Path]::GetFullPath($Root)
    $stateDirectory = Get-Item -LiteralPath $stateRoot -Force -ErrorAction Stop
    if (-not $stateDirectory.PSIsContainer -or
        ($stateDirectory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Production state root must remain one ordinary directory before staging.'
    }
    $parent = $stateDirectory.Parent
    if ($null -eq $parent -or
        ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Production state parent must remain one ordinary directory before staging.'
    }
    for ($current = $parent; $null -ne $current; $current = $current.Parent) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Production staging parent crosses a filesystem link.'
        }
    }

    $operationId = ([Guid]::Parse([string]$Plan.orchestrationId)).ToString('N')
    $nonce = [Guid]::NewGuid().ToString('N')
    $prefix = ".ensou-launcher-production-staging-$operationId-$Purpose-"
    $name = $prefix + $nonce
    $stagingRoot = Join-Path $parent.FullName $name
    if (Test-Path -LiteralPath $stagingRoot) {
        throw 'Random production bundle staging path unexpectedly already exists.'
    }
    $created = $false
    $owner = $null
    try {
        [IO.Directory]::CreateDirectory($stagingRoot) | Out-Null
        $created = $true
        $stagingRoot = Assert-OrdinaryProductionStagingDirectory `
            -Path $stagingRoot `
            -ExpectedParent $parent.FullName `
            -ExpectedName $name `
            -Label 'Production bundle staging root'
        Protect-ProductionStagingDirectory -Path $stagingRoot

        $ownerBytes = ConvertTo-ProductionJsonBytes -Value ([ordered]@{
            schemaVersion = 1
            ownerType = 'ensou-dsh-launcher-production-bundle-staging'
            orchestrationId = [string]$Plan.orchestrationId
            edition = [string]$Plan.edition
            purpose = $Purpose
            nonce = $nonce
        })
        $ownerPath = Join-Path $stagingRoot 'staging-owner.v1.json'
        Write-ProductionStateFile -Path $ownerPath -Bytes $ownerBytes
        $owner = Open-ProductionReleaseInput `
            -Path $ownerPath `
            -Label 'Production bundle staging owner' `
            -MaximumBytes 16KB
        return [pscustomobject]@{
            Root = $stagingRoot
            Parent = [IO.Path]::GetFullPath($parent.FullName)
            Name = $name
            Prefix = $prefix
            Purpose = $Purpose
            Nonce = $nonce
            Owner = $owner
            Published = $false
        }
    }
    catch {
        $failure = $_
        if ($null -ne $owner) {
            $owner.Stream.Dispose()
        }
        if ($created -and (Test-Path -LiteralPath $stagingRoot)) {
            try {
                $cleanupRoot = Assert-OrdinaryProductionStagingDirectory `
                    -Path $stagingRoot `
                    -ExpectedParent $parent.FullName `
                    -ExpectedName $name `
                    -Label 'Failed production bundle staging root'
                $linked = @(
                    Get-ChildItem -LiteralPath $cleanupRoot -Force -Recurse |
                        Where-Object {
                            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
                        })
                if ($linked.Count -eq 0) {
                    [IO.Directory]::Delete($cleanupRoot, $true)
                }
            }
            catch {
                # Fail closed: never broaden cleanup beyond this random exact root.
            }
        }
        throw $failure
    }
}

function Assert-ProductionBundleStagingOwner {
    param([Parameter(Mandatory = $true)]$Staging)

    $root = Assert-OrdinaryProductionStagingDirectory `
        -Path ([string]$Staging.Root) `
        -ExpectedParent ([string]$Staging.Parent) `
        -ExpectedName ([string]$Staging.Name) `
        -Label 'Production bundle staging root'
    if (-not [string]$Staging.Name.StartsWith(
            [string]$Staging.Prefix,
            [StringComparison]::Ordinal) -or
        -not [string]$Staging.Name.EndsWith(
            [string]$Staging.Nonce,
            [StringComparison]::Ordinal)) {
        throw 'Production bundle staging ownership metadata is inconsistent.'
    }
    Assert-ProductionReleaseInputStillLocked `
        -Descriptor $Staging.Owner `
        -Label 'Production bundle staging owner'
    return $root
}

function Wait-TestOnlyProductionCheckoutAdmission {
    param(
        [Parameter(Mandatory = $true)]$Staging,
        [Parameter(Mandatory = $true)][string]$ExpectedFaultPoint
    )

    if ($FaultPoint -cne $ExpectedFaultPoint) {
        return
    }
    $root = Assert-ProductionBundleStagingOwner -Staging $Staging
    $readyPath = Join-Path $root 'checkout-admission.ready'
    $continuePath = Join-Path $root 'checkout-admission.continue'
    $readyBytes = ConvertTo-ProductionJsonBytes -Value ([ordered]@{
        schemaVersion = 1
        gateType = 'ensou-dsh-launcher-test-only-checkout-admission'
        purpose = [string]$Staging.Purpose
        nonce = [string]$Staging.Nonce
    })
    Write-ProductionStateFile -Path $readyPath -Bytes $readyBytes
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
    while (-not (Test-Path -LiteralPath $continuePath)) {
        if ([DateTimeOffset]::UtcNow -ge $deadline) {
            throw 'Test-only production checkout admission gate timed out.'
        }
        Start-Sleep -Milliseconds 25
    }
    $continuation = Open-ProductionReleaseInput `
        -Path $continuePath `
        -Label 'Test-only checkout admission continuation' `
        -MaximumBytes 16KB
    try {
        if ([int64]$continuation.SizeBytes -ne [int64]$readyBytes.LongLength -or
            [string]$continuation.Sha256 -cne (Get-ProductionSha256Bytes -Bytes $readyBytes)) {
            throw 'Test-only checkout admission continuation does not match its operation gate.'
        }
    }
    finally {
        $continuation.Stream.Dispose()
    }
}

function Complete-ProductionBundleAfterCheckoutAdmission {
    param(
        [Parameter(Mandatory = $true)]$Staging,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][string]$RelativeBundlePath,
        [Parameter(Mandatory = $true)][string]$DestinationParent,
        [switch]$AllowExisting
    )

    $root = Assert-ProductionBundleStagingOwner -Staging $Staging
    $source = [IO.Path]::GetFullPath((Join-Path $root $RelativeBundlePath))
    if (-not (Test-SameOrDescendantPath -Path $source -Root $root)) {
        throw 'Staged production bundle escaped its operation-owned root.'
    }
    $sourceItem = Get-Item -LiteralPath $source -Force -ErrorAction Stop
    if (-not $sourceItem.PSIsContainer -or
        ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Staged production bundle must be one ordinary directory.'
    }
    $destinationParentPath = [IO.Path]::GetFullPath($DestinationParent)
    $destinationParentItem = Get-Item -LiteralPath $destinationParentPath -Force -ErrorAction Stop
    if (-not $destinationParentItem.PSIsContainer -or
        ($destinationParentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Production bundle destination parent must be one ordinary directory.'
    }
    $destination = Join-Path $destinationParentPath $sourceItem.Name
    if (Test-Path -LiteralPath $destination) {
        if (-not $AllowExisting) {
            throw 'Production bundle destination already exists before atomic publication.'
        }
        [void](Assert-LauncherSourceCheckout -Plan $Plan)
        return [IO.Path]::GetFullPath($destination)
    }
    if ($AllowExisting) {
        throw 'Expected recoverable production bundle is missing before checkout admission.'
    }
    if (-not [IO.Path]::GetPathRoot($source).Equals(
            [IO.Path]::GetPathRoot($destination),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Production bundle staging and destination must remain on the same volume.'
    }
    [void](Assert-LauncherSourceCheckout -Plan $Plan)
    [IO.Directory]::Move($source, $destination)
    $Staging.Published = $true
    return [IO.Path]::GetFullPath($destination)
}

function Complete-ValidatedProductionBundleAfterCheckoutAdmission {
    param(
        [Parameter(Mandatory = $true)]$Staging,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][string]$RelativeBundlePath,
        [Parameter(Mandatory = $true)][string]$DestinationParent,
        [Parameter(Mandatory = $true)]$PostWaitAdmission,
        [Parameter(Mandatory = $true)][Collections.IDictionary]$ExpectedPins,
        [Parameter(Mandatory = $true)][scriptblock]$OpenFinalAdmission,
        [Parameter(Mandatory = $true)][string]$Label,
        [string]$ExpectedPreMoveFaultPoint = '',
        [switch]$AllowExisting
    )

    $root = Assert-ProductionBundleStagingOwner -Staging $Staging
    $source = [IO.Path]::GetFullPath((Join-Path $root $RelativeBundlePath))
    if (-not (Test-SameOrDescendantPath -Path $source -Root $root) -or
        -not [IO.Path]::GetFullPath([string]$PostWaitAdmission.BundleRoot).Equals(
            $source,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label admission does not name its exact operation-owned bundle."
    }
    $sourceItem = Get-Item -LiteralPath $source -Force -ErrorAction Stop
    if (-not $sourceItem.PSIsContainer -or
        ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label source must remain one ordinary directory."
    }
    $destinationParentPath = [IO.Path]::GetFullPath($DestinationParent)
    $destinationParentItem = Get-Item -LiteralPath $destinationParentPath -Force -ErrorAction Stop
    if (-not $destinationParentItem.PSIsContainer -or
        ($destinationParentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label destination parent must remain one ordinary directory."
    }
    $destination = Join-Path $destinationParentPath $sourceItem.Name
    if (-not [IO.Path]::GetPathRoot($source).Equals(
            [IO.Path]::GetPathRoot($destination),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label staging and destination must remain on the same volume."
    }

    $moveLease = $null
    $finalAdmission = $null
    $publishedByThisCall = $false
    try {
        Assert-ProductionBundleAdmissionStillLocked `
            -Admission $PostWaitAdmission -Label $Label
        Assert-ProductionBundleAdmissionMatchesPins `
            -Admission $PostWaitAdmission -Pins $ExpectedPins `
            -Label $Label -RequireSameFileIdentity
        [void](Assert-LauncherSourceCheckout -Plan $Plan)

        if ($AllowExisting) {
            if (-not (Test-Path -LiteralPath $destination)) {
                throw "$Label expected recoverable canonical bundle is missing."
            }
            Close-ProductionBundleAdmission -Admission $PostWaitAdmission
            $PostWaitAdmission = $null
            $finalAdmission = & $OpenFinalAdmission $destination
            Assert-ProductionBundleAdmissionMatchesPins `
                -Admission $finalAdmission -Pins $ExpectedPins -Label $Label
            Assert-ProductionBundleAdmissionStillLocked `
                -Admission $finalAdmission -Label $Label
            $finalRootLease = @(
                $finalAdmission.DirectoryLeases |
                    Where-Object { [string]$_.AdmissionRelativePath -ceq '.' })
            if ($finalRootLease.Count -ne 1) {
                throw "$Label recovery admission must hold exactly one root-directory lease."
            }
            $moveLease = Open-ProductionReleaseDirectoryMoveLease `
                -Path $destination -Label "$Label retained publication root"
            if ($moveLease.VolumeSerialNumber -ne
                    $finalRootLease[0].VolumeSerialNumber -or
                $moveLease.FileIndex -ne $finalRootLease[0].FileIndex) {
                throw "$Label retained publication lease does not name the recovered directory."
            }
            $finalAdmission | Add-Member `
                -NotePropertyName PublicationDirectoryLease `
                -NotePropertyValue $moveLease -Force
            $moveLease = $null
            return [pscustomobject]@{
                Path = [IO.Path]::GetFullPath($destination)
                Admission = $finalAdmission
                PublishedNew = $false
            }
        }
        if (Test-Path -LiteralPath $destination) {
            throw "$Label destination already exists before atomic publication."
        }

        $rootDirectoryLease = @(
            $PostWaitAdmission.DirectoryLeases |
                Where-Object { [string]$_.AdmissionRelativePath -ceq '.' })
        if ($rootDirectoryLease.Count -ne 1) {
            throw "$Label admission must hold exactly one root-directory lease."
        }
        $moveLease = Open-ProductionReleaseDirectoryMoveLease `
            -Path $source -Label "$Label atomic-move root"
        if ($moveLease.VolumeSerialNumber -ne
                $rootDirectoryLease[0].VolumeSerialNumber -or
            $moveLease.FileIndex -ne $rootDirectoryLease[0].FileIndex) {
            throw "$Label atomic-move lease does not name the admitted directory."
        }

        # The pinned root handle denies rename/delete while child handles are
        # released for the handle-based same-volume atomic move. Child changes
        # in this narrow interval are rejected by the full final admission.
        Assert-ProductionBundleAdmissionStillLocked `
            -Admission $PostWaitAdmission -Label $Label
        Close-ProductionBundleAdmission -Admission $PostWaitAdmission
        $PostWaitAdmission = $null
        if ($ExpectedPreMoveFaultPoint) {
            Wait-TestOnlyProductionCheckoutAdmission `
                -Staging $Staging `
                -ExpectedFaultPoint $ExpectedPreMoveFaultPoint
        }
        Assert-ProductionReleaseDirectoryStillLocked `
            -Descriptor $moveLease -Label "$Label atomic-move root"
        if (Test-Path -LiteralPath $destination) {
            throw "$Label destination appeared before atomic publication."
        }
        [void](Assert-LauncherSourceCheckout -Plan $Plan)
        [void](Move-ProductionReleaseDirectoryLease `
            -Descriptor $moveLease `
            -DestinationPath $destination `
            -Label "$Label atomic publication")
        $Staging.Published = $true
        $publishedByThisCall = $true

        $finalAdmission = & $OpenFinalAdmission $destination
        Assert-ProductionBundleAdmissionMatchesPins `
            -Admission $finalAdmission -Pins $ExpectedPins `
            -Label $Label -RequireSameFileIdentity
        $finalRootLease = @(
            $finalAdmission.DirectoryLeases |
                Where-Object { [string]$_.AdmissionRelativePath -ceq '.' })
        if ($finalRootLease.Count -ne 1 -or
            $finalRootLease[0].VolumeSerialNumber -ne $moveLease.VolumeSerialNumber -or
            $finalRootLease[0].FileIndex -ne $moveLease.FileIndex) {
            throw "$Label final path does not name the atomically moved directory."
        }
        Assert-ProductionBundleAdmissionStillLocked `
            -Admission $finalAdmission -Label $Label
        $finalAdmission | Add-Member `
            -NotePropertyName PublicationDirectoryLease `
            -NotePropertyValue $moveLease -Force
        $moveLease = $null
        return [pscustomobject]@{
            Path = [IO.Path]::GetFullPath($destination)
            Admission = $finalAdmission
            PublishedNew = $true
        }
    }
    catch {
        $failure = $_
        if ($null -ne $finalAdmission) {
            Close-ProductionBundleAdmission -Admission $finalAdmission
            $finalAdmission = $null
        }
        if ($publishedByThisCall -and $null -ne $moveLease) {
            try {
                Assert-ProductionReleaseDirectoryStillLocked `
                    -Descriptor $moveLease `
                    -Label "$Label rejected atomic publication"
                $stateRoot = [IO.Path]::GetDirectoryName($destinationParentPath)
                $quarantineParent = [IO.Path]::GetDirectoryName($stateRoot)
                $quarantineItem = Get-Item -LiteralPath $quarantineParent -Force -ErrorAction Stop
                if (-not $quarantineItem.PSIsContainer -or
                    ($quarantineItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "$Label rejected-bundle quarantine is not an ordinary directory."
                }
                $operationId =
                    ([Guid]::Parse([string]$Plan.orchestrationId)).ToString('N')
                $quarantinePath = Join-Path $quarantineParent `
                    (".ensou-launcher-production-rejected-$operationId-$($Staging.Purpose)-$($Staging.Nonce)")
                [void](Move-ProductionReleaseDirectoryLease `
                    -Descriptor $moveLease `
                    -DestinationPath $quarantinePath `
                    -Label "$Label rejected atomic publication quarantine")
            }
            catch {
                throw "$($failure.Exception.Message) Rejected canonical bundle could not be identity-bound quarantined: $($_.Exception.Message)"
            }
        }
        throw $failure
    }
    finally {
        if ($null -ne $moveLease) {
            $moveLease.Handle.Dispose()
        }
        if ($null -ne $PostWaitAdmission) {
            Close-ProductionBundleAdmission -Admission $PostWaitAdmission
        }
    }
}

function Add-ProductionBundlePublicationLease {
    param(
        [Parameter(Mandatory = $true)]$Admission,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($null -ne $Admission.PSObject.Properties['PublicationDirectoryLease']) {
        throw "$Label already carries a retained publication lease."
    }
    $rootDirectoryLease = @(
        $Admission.DirectoryLeases |
            Where-Object { [string]$_.AdmissionRelativePath -ceq '.' })
    if ($rootDirectoryLease.Count -ne 1) {
        throw "$Label must hold exactly one root-directory lease."
    }
    $moveLease = Open-ProductionReleaseDirectoryMoveLease `
        -Path ([string]$Admission.BundleRoot) `
        -Label "$Label retained publication root"
    try {
        if ($moveLease.VolumeSerialNumber -ne
                $rootDirectoryLease[0].VolumeSerialNumber -or
            $moveLease.FileIndex -ne $rootDirectoryLease[0].FileIndex) {
            throw "$Label retained publication lease does not name its locked root."
        }
        Assert-ProductionBundleAdmissionStillLocked `
            -Admission $Admission -Label $Label
        $Admission | Add-Member `
            -NotePropertyName PublicationDirectoryLease `
            -NotePropertyValue $moveLease -Force
        $moveLease = $null
        return $Admission
    }
    finally {
        if ($null -ne $moveLease) {
            $moveLease.Handle.Dispose()
        }
    }
}

function Move-RejectedEnterprisePilotEvidenceCanonical {
    param(
        [Parameter(Mandatory = $true)]$Admission,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $stateRootPath = [IO.Path]::GetFullPath($StateRoot)
    $expectedRoot = [IO.Path]::GetFullPath((Join-Path `
        $stateRootPath 'imports\pilot-evidence.v1'))
    if (-not [IO.Path]::GetFullPath([string]$Admission.BundleRoot).Equals(
            $expectedRoot,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label does not name the exact uncommitted Pilot-evidence canonical root."
    }
    $stateParent = [IO.Path]::GetDirectoryName($stateRootPath)
    $stateParentItem = Get-Item -LiteralPath $stateParent -Force -ErrorAction Stop
    if (-not $stateParentItem.PSIsContainer -or
        ($stateParentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label quarantine parent must remain one ordinary directory."
    }
    for ($current = $stateParentItem; $null -ne $current; $current = $current.Parent) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label quarantine path crosses a filesystem link."
        }
    }
    $operationId =
        ([Guid]::Parse([string]$Plan.orchestrationId)).ToString('N')
    $quarantinePath = Join-Path $stateParent `
        ('.ensou-launcher-production-rejected-' + $operationId +
         '-pilot-evidence-orphan-' + [Guid]::NewGuid().ToString('N'))
    if (Test-Path -LiteralPath $quarantinePath) {
        throw "$Label unique quarantine destination unexpectedly exists."
    }

    $rootDirectoryLease = @(
        $Admission.DirectoryLeases |
            Where-Object { [string]$_.AdmissionRelativePath -ceq '.' })
    if ($rootDirectoryLease.Count -ne 1) {
        throw "$Label must hold exactly one root-directory lease before quarantine."
    }
    $moveLease = $null
    try {
        $publicationLeaseProperty =
            $Admission.PSObject.Properties['PublicationDirectoryLease']
        if ($null -ne $publicationLeaseProperty -and
            $null -ne $publicationLeaseProperty.Value) {
            $moveLease = $publicationLeaseProperty.Value
        }
        else {
            $moveLease = Open-ProductionReleaseDirectoryMoveLease `
                -Path $expectedRoot -Label "$Label quarantine root"
        }
        if ($moveLease.VolumeSerialNumber -ne
                $rootDirectoryLease[0].VolumeSerialNumber -or
            $moveLease.FileIndex -ne $rootDirectoryLease[0].FileIndex) {
            throw "$Label quarantine handle does not name its admitted root."
        }
        Assert-ProductionBundleAdmissionStillLocked `
            -Admission $Admission -Label $Label
        if ($null -ne $publicationLeaseProperty) {
            $publicationLeaseProperty.Value = $null
        }
        Close-ProductionBundleAdmission -Admission $Admission
        Assert-ProductionReleaseDirectoryStillLocked `
            -Descriptor $moveLease -Label "$Label quarantine root"
        if (Test-Path -LiteralPath $quarantinePath) {
            throw "$Label unique quarantine destination appeared before move."
        }
        [void](Move-ProductionReleaseDirectoryLease `
            -Descriptor $moveLease `
            -DestinationPath $quarantinePath `
            -Label "$Label diagnostic quarantine")
        return [IO.Path]::GetFullPath($quarantinePath)
    }
    finally {
        if ($null -ne $moveLease) {
            $moveLease.Handle.Dispose()
        }
    }
}

function Open-CanonicalProductionJsonLease {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$SchemaPath,
        [Parameter(Mandatory = $true)][string]$Label,
        [int64]$MaximumBytes = 64MB
    )

    $descriptor = Open-ProductionReleaseInput `
        -Path $Path -Label $Label -MaximumBytes $MaximumBytes
    try {
        [byte[]]$bytes = Read-ProductionReleaseInputBytes `
            -Descriptor $descriptor -Label $Label
        $input = [pscustomobject]@{
            Path = [string]$descriptor.Path
            Bytes = $bytes
            Sha256 = [string]$descriptor.Sha256
            Value = ConvertFrom-StrictProductionJsonBytes `
                -Bytes $bytes -Label $Label -SchemaPath $SchemaPath
        }
        [void](Assert-CanonicalProductionJsonInput `
            -JsonInput $input -Label $Label)
        return [pscustomobject]@{
            Input = $input
            Descriptor = $descriptor
        }
    }
    catch {
        $descriptor.Stream.Dispose()
        throw
    }
}

function Close-ProductionBundleAdmission {
    param([AllowNull()]$Admission)

    if ($null -eq $Admission) { return }
    foreach ($directory in @($Admission.DirectoryLeases)) {
        if ($null -ne $directory -and $null -ne $directory.Handle) {
            $directory.Handle.Dispose()
        }
    }
    foreach ($descriptor in @($Admission.FileLeases)) {
        if ($null -ne $descriptor -and $null -ne $descriptor.Stream) {
            $descriptor.Stream.Dispose()
        }
    }
    $publicationLeaseProperty =
        $Admission.PSObject.Properties['PublicationDirectoryLease']
    if ($null -ne $publicationLeaseProperty -and
        $null -ne $publicationLeaseProperty.Value -and
        $null -ne $publicationLeaseProperty.Value.Handle) {
        $publicationLeaseProperty.Value.Handle.Dispose()
    }
}

function Get-ProductionBundleAdmissionPins {
    param([Parameter(Mandatory = $true)]$Admission)

    $pins = [ordered]@{}
    foreach ($descriptor in @($Admission.FileLeases)) {
        $relativePath = [string]$descriptor.AdmissionRelativePath
        if ([string]::IsNullOrWhiteSpace($relativePath) -or
            $pins.Contains($relativePath)) {
            throw 'Production bundle admission cannot pin a missing or duplicate relative path.'
        }
        $pins[$relativePath] = [pscustomobject]@{
            RelativePath = $relativePath
            SizeBytes = [int64]$descriptor.SizeBytes
            Sha256 = [string]$descriptor.Sha256
            VolumeSerialNumber = $descriptor.VolumeSerialNumber
            FileIndex = $descriptor.FileIndex
        }
    }
    return $pins
}

function Assert-ProductionBundleAdmissionMatchesPins {
    param(
        [Parameter(Mandatory = $true)]$Admission,
        [Parameter(Mandatory = $true)][Collections.IDictionary]$Pins,
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$RequireSameFileIdentity
    )

    if (@($Admission.FileLeases).Count -ne $Pins.Count) {
        throw "$Label changed its exact file inventory after admission."
    }
    foreach ($descriptor in @($Admission.FileLeases)) {
        $relativePath = [string]$descriptor.AdmissionRelativePath
        if (-not $Pins.Contains($relativePath)) {
            throw "$Label added unexpected file '$relativePath' after admission."
        }
        $pin = $Pins[$relativePath]
        if ([int64]$descriptor.SizeBytes -ne [int64]$pin.SizeBytes -or
            [string]$descriptor.Sha256 -cne [string]$pin.Sha256 -or
            ($RequireSameFileIdentity -and
             ($descriptor.VolumeSerialNumber -ne $pin.VolumeSerialNumber -or
              $descriptor.FileIndex -ne $pin.FileIndex))) {
            throw "$Label file '$relativePath' changed after admission."
        }
    }
}

function Assert-ProductionBundleAdmissionStillLocked {
    param(
        [Parameter(Mandatory = $true)]$Admission,
        [Parameter(Mandatory = $true)][string]$Label
    )

    foreach ($directory in @($Admission.DirectoryLeases)) {
        Assert-ProductionReleaseDirectoryStillLocked `
            -Descriptor $directory `
            -Label "$Label directory '$($directory.AdmissionRelativePath)'"
    }
    foreach ($descriptor in @($Admission.FileLeases)) {
        Assert-ProductionReleaseInputStillLocked `
            -Descriptor $descriptor `
            -Label "$Label file '$($descriptor.AdmissionRelativePath)'"
    }
    $publicationLeaseProperty =
        $Admission.PSObject.Properties['PublicationDirectoryLease']
    if ($null -ne $publicationLeaseProperty -and
        $null -ne $publicationLeaseProperty.Value) {
        Assert-ProductionReleaseDirectoryStillLocked `
            -Descriptor $publicationLeaseProperty.Value `
            -Label "$Label retained publication root"
    }
    [void](Assert-ExactProductionDirectoryInventory `
        -Path ([string]$Admission.BundleRoot) `
        -Expected $Admission.RootInventory `
        -Label $Label)
    foreach ($inventory in @($Admission.ChildInventories)) {
        [void](Assert-ExactProductionDirectoryInventory `
            -Path ([string]$inventory.Path) `
            -Expected $inventory.Expected `
            -Label ([string]$inventory.Label))
    }
}

function Add-ProductionAdmissionRelativePath {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )

    Add-Member -InputObject $Descriptor -NotePropertyName `
        AdmissionRelativePath -NotePropertyValue $RelativePath -Force
    return $Descriptor
}

function Open-PersonalInstallerRequestBundleAdmission {
    param(
        [Parameter(Mandatory = $true)][string]$BundleRoot,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][string]$RequestSchemaPath,
        [Parameter(Mandatory = $true)][string]$EvidenceSchemaPath,
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$EnforceCurrentLifetime
    )

    $root = [IO.Path]::GetFullPath($BundleRoot)
    $rootInventory = [ordered]@{
        'installer-signing-request.v2.json' = $false
        'payload' = $true
        'trusted-build' = $true
        'unsigned' = $true
    }
    $unsignedInventory = [ordered]@{
        'Ensou.Dsh.Personal.Installer.exe' = $false
    }
    $trustedInventory = [ordered]@{
        'trusted-build-evidence.v1.json' = $false
    }
    [void](Assert-ExactProductionDirectoryInventory `
        -Path $root -Expected $rootInventory -Label $Label)
    $unsignedRoot = Join-Path $root 'unsigned'
    $trustedRoot = Join-Path $root 'trusted-build'
    $payloadRoot = Join-Path $root 'payload'
    [void](Assert-ExactProductionDirectoryInventory `
        -Path $unsignedRoot -Expected $unsignedInventory `
        -Label "$Label unsigned payload")
    [void](Assert-ExactProductionDirectoryInventory `
        -Path $trustedRoot -Expected $trustedInventory `
        -Label "$Label trusted-build evidence")

    $fileLeases = [Collections.Generic.List[object]]::new()
    $directoryLeases = [Collections.Generic.List[object]]::new()
    try {
        $requestLease = Open-CanonicalProductionJsonLease `
            -Path (Join-Path $root 'installer-signing-request.v2.json') `
            -SchemaPath $RequestSchemaPath -Label "$Label request"
        $requestDescriptor = Add-ProductionAdmissionRelativePath `
            -Descriptor $requestLease.Descriptor `
            -RelativePath 'installer-signing-request.v2.json'
        $fileLeases.Add($requestDescriptor)
        $request = $requestLease.Input.Value
        [void](Assert-InstallerSigningRequestContract `
            -Request $request `
            -InstallerSigningTrust $Plan.externalResponseTrusts.installerSigning `
            -ReleaseManifestTrust $Plan.releaseManifestTrust)
        $requestExpiry = ConvertFrom-ProductionUtc `
            -Value ([string]$request.expiresAtUtc) `
            -Label "$Label request expiry"
        if ($EnforceCurrentLifetime -and
            [DateTimeOffset]::UtcNow -gt $requestExpiry) {
            throw "$Label request has expired before canonical publication."
        }

        $evidenceLease = Open-CanonicalProductionJsonLease `
            -Path (Join-Path $trustedRoot 'trusted-build-evidence.v1.json') `
            -SchemaPath $EvidenceSchemaPath -Label "$Label evidence"
        $evidenceDescriptor = Add-ProductionAdmissionRelativePath `
            -Descriptor $evidenceLease.Descriptor `
            -RelativePath 'trusted-build/trusted-build-evidence.v1.json'
        $fileLeases.Add($evidenceDescriptor)
        $evidence = $evidenceLease.Input.Value
        if ([string]$request.trustedBuildEvidence.fileName -cne
                'trusted-build-evidence.v1.json' -or
            [string]$request.trustedBuildEvidence.relativePath -cne
                'trusted-build/trusted-build-evidence.v1.json' -or
            [int64]$request.trustedBuildEvidence.sizeBytes -ne
                [int64]$evidenceDescriptor.SizeBytes -or
            [string]$request.trustedBuildEvidence.sha256 -cne
                [string]$evidenceDescriptor.Sha256) {
            throw "$Label evidence differs from its exact request descriptor."
        }
        foreach ($pair in @(
                [pscustomobject]@{ Left = $request.source; Right = $evidence.source },
                [pscustomobject]@{ Left = $request.payload; Right = $evidence.payload },
                [pscustomobject]@{ Left = $request.compiledTrust; Right = $evidence.compiledTrust },
                [pscustomobject]@{ Left = $request.toolchain.packageClosure; Right = $evidence.packageClosure },
                [pscustomobject]@{ Left = $request.toolchain.sdkClosure; Right = $evidence.sdkClosure },
                [pscustomobject]@{ Left = $request.buildExecution; Right = $evidence.buildExecution },
                [pscustomobject]@{ Left = $request.unsignedInstaller; Right = $evidence.unsignedInstaller },
                [pscustomobject]@{ Left = $request.resourceBinding; Right = $evidence.resourceBinding },
                [pscustomobject]@{ Left = $request.admission; Right = $evidence.signingRequestEligibility })) {
            if ((Get-InstallerSigningObjectSha256 -Value $pair.Left) -cne
                (Get-InstallerSigningObjectSha256 -Value $pair.Right)) {
                throw "$Label request and evidence do not close the same trusted-build tuple."
            }
        }

        $unsignedDescriptor = Open-ProductionReleaseInput `
            -Path (Join-Path $unsignedRoot 'Ensou.Dsh.Personal.Installer.exe') `
            -Label "$Label unsigned Installer" -MaximumBytes 1GB
        [void](Add-ProductionAdmissionRelativePath `
            -Descriptor $unsignedDescriptor `
            -RelativePath 'unsigned/Ensou.Dsh.Personal.Installer.exe')
        $fileLeases.Add($unsignedDescriptor)
        [void](Assert-UnsignedInstallerSigningInput `
            -Path ([string]$unsignedDescriptor.Path) `
            -Descriptor $request.unsignedInstaller)

        $payloadInventory = [ordered]@{}
        foreach ($file in @($request.payload.files)) {
            if ($payloadInventory.Contains([string]$file.fileName)) {
                throw "$Label request contains a duplicate payload file name."
            }
            $payloadInventory[[string]$file.fileName] = $false
        }
        [void](Assert-ExactProductionDirectoryInventory `
            -Path $payloadRoot -Expected $payloadInventory `
            -Label "$Label payload")
        foreach ($file in @($request.payload.files)) {
            $relativePath = 'payload/' + [string]$file.fileName
            if ([string]$file.relativePath -cne $relativePath) {
                throw "$Label payload role '$($file.role)' has a noncanonical path."
            }
            $payloadDescriptor = Open-ProductionReleaseInput `
                -Path (Join-Path $payloadRoot ([string]$file.fileName)) `
                -Label "$Label payload role $($file.role)" -MaximumBytes 8GB
            [void](Add-ProductionAdmissionRelativePath `
                -Descriptor $payloadDescriptor -RelativePath $relativePath)
            $fileLeases.Add($payloadDescriptor)
            if ([int64]$payloadDescriptor.SizeBytes -ne [int64]$file.sizeBytes -or
                [string]$payloadDescriptor.Sha256 -cne [string]$file.sha256) {
                throw "$Label payload role '$($file.role)' differs from its request descriptor."
            }
        }

        foreach ($directorySpec in @(
                [pscustomobject]@{ Path = $root; RelativePath = '.' },
                [pscustomobject]@{ Path = $unsignedRoot; RelativePath = 'unsigned' },
                [pscustomobject]@{ Path = $trustedRoot; RelativePath = 'trusted-build' },
                [pscustomobject]@{ Path = $payloadRoot; RelativePath = 'payload' })) {
            $directory = Open-ProductionReleaseDirectoryLease `
                -Path $directorySpec.Path `
                -Label "$Label directory $($directorySpec.RelativePath)"
            Add-Member -InputObject $directory -NotePropertyName `
                AdmissionRelativePath -NotePropertyValue `
                ([string]$directorySpec.RelativePath) -Force
            $directoryLeases.Add($directory)
        }
        $admission = [pscustomobject]@{
            BundleRoot = $root
            RequestInput = $requestLease.Input
            EvidenceInput = $evidenceLease.Input
            FileLeases = @($fileLeases)
            DirectoryLeases = @($directoryLeases)
            RootInventory = $rootInventory
            ChildInventories = @(
                [pscustomobject]@{ Path = $unsignedRoot; Expected = $unsignedInventory; Label = "$Label unsigned payload" },
                [pscustomobject]@{ Path = $trustedRoot; Expected = $trustedInventory; Label = "$Label trusted-build evidence" },
                [pscustomobject]@{ Path = $payloadRoot; Expected = $payloadInventory; Label = "$Label payload" })
        }
        Assert-ProductionBundleAdmissionStillLocked `
            -Admission $admission -Label $Label
        return $admission
    }
    catch {
        foreach ($directory in @($directoryLeases)) { $directory.Handle.Dispose() }
        foreach ($descriptor in @($fileLeases)) { $descriptor.Stream.Dispose() }
        throw
    }
}

function Open-PersonalInstallerImportBundleAdmission {
    param(
        [Parameter(Mandatory = $true)][string]$BundleRoot,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][string]$ResponseSchemaPath,
        [Parameter(Mandatory = $true)]$RequestInput,
        [Parameter(Mandatory = $true)]$R6ReceiptInput,
        [Parameter(Mandatory = $true)][string]$R6HeadSha256,
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$EnforceCurrentLifetime
    )

    $root = [IO.Path]::GetFullPath($BundleRoot)
    $signedRoot = Join-Path $root 'signed'
    $rootInventory = [ordered]@{
        'personal-installer-signing-response.v2.json' = $false
        'signed' = $true
    }
    $signedInventory = [ordered]@{
        'Ensou.Dsh.Personal.Installer.exe' = $false
    }
    [void](Assert-ExactProductionDirectoryInventory `
        -Path $root -Expected $rootInventory -Label $Label)
    [void](Assert-ExactProductionDirectoryInventory `
        -Path $signedRoot -Expected $signedInventory `
        -Label "$Label signed payload")
    $fileLeases = [Collections.Generic.List[object]]::new()
    $directoryLeases = [Collections.Generic.List[object]]::new()
    try {
        $responseLease = Open-CanonicalProductionJsonLease `
            -Path (Join-Path $root `
                'personal-installer-signing-response.v2.json') `
            -SchemaPath $ResponseSchemaPath -Label "$Label response"
        [void](Add-ProductionAdmissionRelativePath `
            -Descriptor $responseLease.Descriptor `
            -RelativePath 'personal-installer-signing-response.v2.json')
        $fileLeases.Add($responseLease.Descriptor)
        $signedInput = Open-ProductionReleaseInput `
            -Path (Join-Path $signedRoot `
                'Ensou.Dsh.Personal.Installer.exe') `
            -Label "$Label signed Installer" -MaximumBytes 1GB
        [void](Add-ProductionAdmissionRelativePath `
            -Descriptor $signedInput `
            -RelativePath 'signed/Ensou.Dsh.Personal.Installer.exe')
        $fileLeases.Add($signedInput)
        [void](PersonalInstallerSigningPipeline\Assert-PersonalInstallerSigningResponseV2Contract `
            -RequestInput $RequestInput `
            -ResponseInput $responseLease.Input `
            -R6HeadSha256 $R6HeadSha256 `
            -R6ReceiptSha256 ([string]$R6ReceiptInput.Sha256) `
            -InstallerSigningTrust `
                $Plan.externalResponseTrusts.installerSigning `
            -EnforceCurrentLifetime:$EnforceCurrentLifetime)
        if ([int64]$signedInput.SizeBytes -ne
                [int64]$responseLease.Input.Value.signedInstaller.sizeBytes -or
            [string]$signedInput.Sha256 -cne
                [string]$responseLease.Input.Value.signedInstaller.sha256) {
            throw "$Label signed Installer differs from its authenticated response."
        }
        $authenticode = Assert-SignedInstallerAuthenticode `
            -Path ([string]$signedInput.Path) `
            -Response $responseLease.Input.Value `
            -ExpectedSignerCertificateSha256 `
                ([string]$Plan.authenticodePolicy.signerSha256Thumbprint)
        if ([string]$authenticode.SignedInstallerSha256 -cne
                [string]$signedInput.Sha256 -or
            [string]$authenticode.PeContentSha256 -cne
                [string]$responseLease.Input.Value.signedInstaller.peContentSha256) {
            throw "$Label Authenticode result differs from its exact signed-byte and PE-content closure."
        }
        foreach ($directorySpec in @(
                [pscustomobject]@{ Path = $root; RelativePath = '.' },
                [pscustomobject]@{ Path = $signedRoot; RelativePath = 'signed' })) {
            $directory = Open-ProductionReleaseDirectoryLease `
                -Path $directorySpec.Path `
                -Label "$Label directory $($directorySpec.RelativePath)"
            Add-Member -InputObject $directory -NotePropertyName `
                AdmissionRelativePath -NotePropertyValue `
                ([string]$directorySpec.RelativePath) -Force
            $directoryLeases.Add($directory)
        }
        $admission = [pscustomobject]@{
            BundleRoot = $root
            ResponseInput = $responseLease.Input
            SignedInstallerInput = $signedInput
            Authenticode = $authenticode
            FileLeases = @($fileLeases)
            DirectoryLeases = @($directoryLeases)
            RootInventory = $rootInventory
            ChildInventories = @(
                [pscustomobject]@{ Path = $signedRoot; Expected = $signedInventory; Label = "$Label signed payload" })
        }
        Assert-ProductionBundleAdmissionStillLocked `
            -Admission $admission -Label $Label
        return $admission
    }
    catch {
        foreach ($directory in @($directoryLeases)) { $directory.Handle.Dispose() }
        foreach ($descriptor in @($fileLeases)) { $descriptor.Stream.Dispose() }
        throw
    }
}

function Open-EnterpriseInstallerRequestBundleAdmission {
    param(
        [Parameter(Mandatory = $true)][string]$BundleRoot,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][psobject]$State,
        [Parameter(Mandatory = $true)][string]$BaseHeadSha256,
        [Parameter(Mandatory = $true)][string]$BaseReceiptSha256,
        [Parameter(Mandatory = $true)][string]$SourceTree,
        [Parameter(Mandatory = $true)][string]$RequestSchemaPath,
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$EnforceCurrentLifetime
    )

    $root = [IO.Path]::GetFullPath($BundleRoot)
    $rootInventory = [ordered]@{
        'installer-signing-request.v2.json' = $false
        'payload' = $true
        'trusted-build' = $true
        'unsigned' = $true
    }
    $trustedInventory = [ordered]@{
        'trusted-build-evidence.v1.json' = $false
    }
    $unsignedInventory = [ordered]@{
        'Ensou.Dsh.Enterprise.Installer.exe' = $false
    }
    [void](Assert-ExactProductionDirectoryInventory `
        -Path $root -Expected $rootInventory -Label $Label)
    $payloadRoot = Join-Path $root 'payload'
    $trustedRoot = Join-Path $root 'trusted-build'
    $unsignedRoot = Join-Path $root 'unsigned'
    [void](Assert-ExactProductionDirectoryInventory `
        -Path $trustedRoot -Expected $trustedInventory `
        -Label "$Label trusted-build evidence")
    [void](Assert-ExactProductionDirectoryInventory `
        -Path $unsignedRoot -Expected $unsignedInventory `
        -Label "$Label unsigned payload")
    $fileLeases = [Collections.Generic.List[object]]::new()
    $directoryLeases = [Collections.Generic.List[object]]::new()
    try {
        $requestLease = Open-CanonicalProductionJsonLease `
            -Path (Join-Path $root 'installer-signing-request.v2.json') `
            -SchemaPath $RequestSchemaPath -Label "$Label request"
        [void](Add-ProductionAdmissionRelativePath `
            -Descriptor $requestLease.Descriptor `
            -RelativePath 'installer-signing-request.v2.json')
        $fileLeases.Add($requestLease.Descriptor)
        [void](Assert-EnterpriseInstallerSigningRequestStateClosure `
            -RequestInput $requestLease.Input -Plan $Plan -State $State `
            -BaseHeadSha256 $BaseHeadSha256 `
            -BaseReceiptSha256 $BaseReceiptSha256 `
            -SourceTree $SourceTree -BundleRoot $root)
        $created = ConvertFrom-ProductionUtc `
            -Value ([string]$requestLease.Input.Value.createdAtUtc) `
            -Label "$Label creation time"
        $expires = ConvertFrom-ProductionUtc `
            -Value ([string]$requestLease.Input.Value.expiresAtUtc) `
            -Label "$Label expiry"
        $r5Completed = ConvertFrom-ProductionUtc `
            -Value ([string]$State.Receipts[4].data.completedAtUtc) `
            -Label "$Label r5 completion time"
        if ($created -lt $r5Completed -or
            $created -gt [DateTimeOffset]::UtcNow.AddMinutes(5) -or
            ($EnforceCurrentLifetime -and [DateTimeOffset]::UtcNow -gt $expires)) {
            throw "$Label build/request lifetime is outside its authenticated r5 window."
        }

        $evidence = Open-ProductionReleaseInput `
            -Path (Join-Path $trustedRoot 'trusted-build-evidence.v1.json') `
            -Label "$Label evidence" -MaximumBytes 64MB
        [void](Add-ProductionAdmissionRelativePath `
            -Descriptor $evidence `
            -RelativePath 'trusted-build/trusted-build-evidence.v1.json')
        $fileLeases.Add($evidence)
        $unsigned = Open-ProductionReleaseInput `
            -Path (Join-Path $unsignedRoot `
                'Ensou.Dsh.Enterprise.Installer.exe') `
            -Label "$Label unsigned Installer" -MaximumBytes 1GB
        [void](Add-ProductionAdmissionRelativePath `
            -Descriptor $unsigned `
            -RelativePath 'unsigned/Ensou.Dsh.Enterprise.Installer.exe')
        $fileLeases.Add($unsigned)
        [void](Assert-UnsignedInstallerSigningInput `
            -Path ([string]$unsigned.Path) `
            -Descriptor $requestLease.Input.Value.unsignedInstaller)

        $payloadInventory = [ordered]@{}
        foreach ($file in @($requestLease.Input.Value.installerPayload.files)) {
            if ($payloadInventory.Contains([string]$file.fileName)) {
                throw "$Label request contains a duplicate payload file name."
            }
            $payloadInventory[[string]$file.fileName] = $false
        }
        [void](Assert-ExactProductionDirectoryInventory `
            -Path $payloadRoot -Expected $payloadInventory `
            -Label "$Label payload")
        foreach ($file in @($requestLease.Input.Value.installerPayload.files)) {
            $relativePath = 'payload/' + [string]$file.fileName
            if ([string]$file.relativePath -cne $relativePath) {
                throw "$Label payload role '$($file.role)' has a noncanonical path."
            }
            $payload = Open-ProductionReleaseInput `
                -Path (Join-Path $payloadRoot ([string]$file.fileName)) `
                -Label "$Label payload role $($file.role)" -MaximumBytes 8GB
            [void](Add-ProductionAdmissionRelativePath `
                -Descriptor $payload -RelativePath $relativePath)
            $fileLeases.Add($payload)
            if ([int64]$payload.SizeBytes -ne [int64]$file.sizeBytes -or
                [string]$payload.Sha256 -cne [string]$file.sha256) {
                throw "$Label payload role '$($file.role)' differs from its request descriptor."
            }
        }
        # Repeat the semantic/path closure while every bundle file is held.
        [void](Assert-EnterpriseInstallerSigningRequestStateClosure `
            -RequestInput $requestLease.Input -Plan $Plan -State $State `
            -BaseHeadSha256 $BaseHeadSha256 `
            -BaseReceiptSha256 $BaseReceiptSha256 `
            -SourceTree $SourceTree -BundleRoot $root)
        foreach ($directorySpec in @(
                [pscustomobject]@{ Path = $root; RelativePath = '.' },
                [pscustomobject]@{ Path = $payloadRoot; RelativePath = 'payload' },
                [pscustomobject]@{ Path = $trustedRoot; RelativePath = 'trusted-build' },
                [pscustomobject]@{ Path = $unsignedRoot; RelativePath = 'unsigned' })) {
            $directory = Open-ProductionReleaseDirectoryLease `
                -Path $directorySpec.Path `
                -Label "$Label directory $($directorySpec.RelativePath)"
            Add-Member -InputObject $directory -NotePropertyName `
                AdmissionRelativePath -NotePropertyValue `
                ([string]$directorySpec.RelativePath) -Force
            $directoryLeases.Add($directory)
        }
        $admission = [pscustomobject]@{
            BundleRoot = $root
            RequestInput = $requestLease.Input
            FileLeases = @($fileLeases)
            DirectoryLeases = @($directoryLeases)
            RootInventory = $rootInventory
            ChildInventories = @(
                [pscustomobject]@{ Path = $payloadRoot; Expected = $payloadInventory; Label = "$Label payload" },
                [pscustomobject]@{ Path = $trustedRoot; Expected = $trustedInventory; Label = "$Label trusted-build evidence" },
                [pscustomobject]@{ Path = $unsignedRoot; Expected = $unsignedInventory; Label = "$Label unsigned payload" })
        }
        Assert-ProductionBundleAdmissionStillLocked `
            -Admission $admission -Label $Label
        return $admission
    }
    catch {
        foreach ($directory in @($directoryLeases)) { $directory.Handle.Dispose() }
        foreach ($descriptor in @($fileLeases)) { $descriptor.Stream.Dispose() }
        throw
    }
}

function Open-EnterpriseInstallerImportBundleAdmission {
    param(
        [Parameter(Mandatory = $true)][string]$BundleRoot,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)]$RequestInput,
        [Parameter(Mandatory = $true)]$R6ReceiptInput,
        [Parameter(Mandatory = $true)][string]$R6HeadSha256,
        [Parameter(Mandatory = $true)][string]$ResponseSchemaPath,
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$EnforceCurrentLifetime
    )

    $root = [IO.Path]::GetFullPath($BundleRoot)
    $signedRoot = Join-Path $root 'signed'
    $rootInventory = [ordered]@{
        'installer-signing-response.v1.json' = $false
        'signed' = $true
    }
    $signedInventory = [ordered]@{
        'Ensou.Dsh.Enterprise.Installer.exe' = $false
    }
    [void](Assert-ExactProductionDirectoryInventory `
        -Path $root -Expected $rootInventory -Label $Label)
    [void](Assert-ExactProductionDirectoryInventory `
        -Path $signedRoot -Expected $signedInventory `
        -Label "$Label signed payload")
    $fileLeases = [Collections.Generic.List[object]]::new()
    $directoryLeases = [Collections.Generic.List[object]]::new()
    try {
        $responseLease = Open-CanonicalProductionJsonLease `
            -Path (Join-Path $root 'installer-signing-response.v1.json') `
            -SchemaPath $ResponseSchemaPath -Label "$Label response"
        [void](Add-ProductionAdmissionRelativePath `
            -Descriptor $responseLease.Descriptor `
            -RelativePath 'installer-signing-response.v1.json')
        $fileLeases.Add($responseLease.Descriptor)
        [void](Assert-InstallerSigningResponseContract `
            -RequestInput $RequestInput `
            -ResponseInput $responseLease.Input `
            -R6HeadSha256 $R6HeadSha256 `
            -R6ReceiptSha256 ([string]$R6ReceiptInput.Sha256) `
            -InstallerSigningTrust $Plan.externalResponseTrusts.installerSigning `
            -EnforceCurrentLifetime:$EnforceCurrentLifetime)
        $signed = Open-ProductionReleaseInput `
            -Path (Join-Path $signedRoot `
                'Ensou.Dsh.Enterprise.Installer.exe') `
            -Label "$Label signed Installer" -MaximumBytes 1GB
        [void](Add-ProductionAdmissionRelativePath `
            -Descriptor $signed `
            -RelativePath 'signed/Ensou.Dsh.Enterprise.Installer.exe')
        $fileLeases.Add($signed)
        if ([int64]$signed.SizeBytes -ne
                [int64]$responseLease.Input.Value.signedInstaller.sizeBytes -or
            [string]$signed.Sha256 -cne
                [string]$responseLease.Input.Value.signedInstaller.sha256) {
            throw "$Label signed Installer differs from its authenticated response."
        }
        [void](Assert-SignedInstallerAuthenticode `
            -Path ([string]$signed.Path) `
            -Response $responseLease.Input.Value `
            -ExpectedSignerCertificateSha256 `
                ([string]$Plan.authenticodePolicy.signerSha256Thumbprint))
        Assert-InstallerSigningPayloadSelfCheck `
            -InstallerPath ([string]$signed.Path) `
            -Request $RequestInput.Value `
            -SelfCheck $responseLease.Input.Value.payloadSelfCheck `
            -Label "$Label payload self-check"
        foreach ($directorySpec in @(
                [pscustomobject]@{ Path = $root; RelativePath = '.' },
                [pscustomobject]@{ Path = $signedRoot; RelativePath = 'signed' })) {
            $directory = Open-ProductionReleaseDirectoryLease `
                -Path $directorySpec.Path `
                -Label "$Label directory $($directorySpec.RelativePath)"
            Add-Member -InputObject $directory -NotePropertyName `
                AdmissionRelativePath -NotePropertyValue `
                ([string]$directorySpec.RelativePath) -Force
            $directoryLeases.Add($directory)
        }
        $admission = [pscustomobject]@{
            BundleRoot = $root
            ResponseInput = $responseLease.Input
            SignedInstallerInput = $signed
            FileLeases = @($fileLeases)
            DirectoryLeases = @($directoryLeases)
            RootInventory = $rootInventory
            ChildInventories = @(
                [pscustomobject]@{ Path = $signedRoot; Expected = $signedInventory; Label = "$Label signed payload" })
        }
        Assert-ProductionBundleAdmissionStillLocked `
            -Admission $admission -Label $Label
        return $admission
    }
    catch {
        foreach ($directory in @($directoryLeases)) { $directory.Handle.Dispose() }
        foreach ($descriptor in @($fileLeases)) { $descriptor.Stream.Dispose() }
        throw
    }
}

function Open-EnterprisePilotEvidenceBundleAdmission {
    param(
        [Parameter(Mandatory = $true)][string]$BundleRoot,
        [Parameter(Mandatory = $true)][string]$SchemaPath,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][psobject]$State,
        [string]$ExpectedR7HeadSha256 = '',
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$RequireCommittedR8Receipt,
        [switch]$EnforceCurrentLifetime
    )

    $root = [IO.Path]::GetFullPath($BundleRoot)
    $rootInventory = [ordered]@{
        'pilot-evidence-input.v1.json' = $false
    }
    [void](Assert-ExactProductionDirectoryInventory `
        -Path $root -Expected $rootInventory -Label $Label)
    $fileLeases = [Collections.Generic.List[object]]::new()
    $directoryLeases = [Collections.Generic.List[object]]::new()
    try {
        $inputLease = Open-CanonicalProductionJsonLease `
            -Path (Join-Path $root 'pilot-evidence-input.v1.json') `
            -SchemaPath $SchemaPath -Label "$Label input"
        [void](Add-ProductionAdmissionRelativePath `
            -Descriptor $inputLease.Descriptor `
            -RelativePath 'pilot-evidence-input.v1.json')
        $fileLeases.Add($inputLease.Descriptor)
        $bindingR7HeadSha256 = $ExpectedR7HeadSha256
        if ($RequireCommittedR8Receipt) {
            if (-not [string]::IsNullOrWhiteSpace($ExpectedR7HeadSha256)) {
                throw "$Label cannot combine a caller-selected r7 head with committed-r8 receipt binding."
            }
            if ($null -eq $State.Head -or
                [int]$State.Head.revision -lt 8 -or
                @($State.Receipts).Count -lt 8) {
                throw "$Label requires one committed Enterprise r8 receipt."
            }
            $committedR8Receipt = $State.Receipts[7]
            if ([int]$committedR8Receipt.revision -ne 8 -or
                [string]$committedR8Receipt.phase -cne
                    'PILOT_EVIDENCE_BOUND' -or
                [string]$committedR8Receipt.data.evidenceType -cne
                    'PILOT_EVIDENCE_BOUND' -or
                [string]$committedR8Receipt.data.relativePath -cne
                    'imports/pilot-evidence.v1/pilot-evidence-input.v1.json' -or
                [string]$committedR8Receipt.data.sha256 -cne
                    [string]$inputLease.Input.Sha256) {
                throw "$Label differs from its committed Enterprise r8 receipt."
            }
            $bindingR7HeadSha256 =
                [string]$inputLease.Input.Value.r7.headSha256
        }
        elseif ([string]::IsNullOrWhiteSpace($ExpectedR7HeadSha256)) {
            throw "$Label requires the exact authoritative r7 head SHA-256."
        }
        [void](ProductionReleaseState\Assert-EnterpriseProductionPilotEvidenceInputBinding `
            -Input $inputLease.Input `
            -Plan $Plan `
            -Identity $State.Identity `
            -IdentitySha256 ([string]$State.IdentitySha256) `
            -Receipts $State.Receipts `
            -StateRoot $State.StateRoot `
            -ExpectedR7HeadSha256 $bindingR7HeadSha256 `
            -EnforceCurrentLifetime:$EnforceCurrentLifetime)
        $directory = Open-ProductionReleaseDirectoryLease `
            -Path $root -Label "$Label directory"
        Add-Member -InputObject $directory -NotePropertyName `
            AdmissionRelativePath -NotePropertyValue '.' -Force
        $directoryLeases.Add($directory)
        $admission = [pscustomobject]@{
            BundleRoot = $root
            Input = $inputLease.Input
            FileLeases = @($fileLeases)
            DirectoryLeases = @($directoryLeases)
            RootInventory = $rootInventory
            ChildInventories = @()
        }
        Assert-ProductionBundleAdmissionStillLocked `
            -Admission $admission -Label $Label
        return $admission
    }
    catch {
        foreach ($directory in @($directoryLeases)) { $directory.Handle.Dispose() }
        foreach ($descriptor in @($fileLeases)) { $descriptor.Stream.Dispose() }
        throw
    }
}

function ConvertFrom-StableFeedRawStateArgument {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][int64]$MaximumBytes
    )

    if ($Value -ceq 'missing') {
        return [ordered]@{ state = 'missing' }
    }
    if ($Value -cnotmatch '^present:([1-9][0-9]*):([0-9a-f]{64})$') {
        throw "$Label must be exactly 'missing' or 'present:<sizeBytes>:<lowercase-sha256>'."
    }
    [int64]$sizeBytes = 0
    if (-not [int64]::TryParse(
            $Matches[1],
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$sizeBytes) -or
        $sizeBytes -le 0 -or
        $sizeBytes -gt $MaximumBytes) {
        throw "$Label declares an invalid or over-limit byte length."
    }
    return [ordered]@{
        state = 'present'
        sizeBytes = $sizeBytes
        sha256 = [string]$Matches[2]
    }
}

function Test-ProductionJsonValueEqual {
    param(
        [Parameter(Mandatory = $true)]$First,
        [Parameter(Mandatory = $true)]$Second
    )

    [byte[]]$firstBytes = ConvertTo-ProductionJsonBytes -Value $First
    [byte[]]$secondBytes = ConvertTo-ProductionJsonBytes -Value $Second
    return [int64]$firstBytes.LongLength -eq [int64]$secondBytes.LongLength -and
        [string](Get-ProductionSha256Bytes -Bytes $firstBytes) -ceq
            [string](Get-ProductionSha256Bytes -Bytes $secondBytes)
}

function Assert-StableFeedPromotionFileDescriptor {
    param(
        [Parameter(Mandatory = $true)][psobject]$Recorded,
        [Parameter(Mandatory = $true)]$JsonInput,
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ([string]$Recorded.fileName -cne $FileName -or
        [int64]$Recorded.sizeBytes -ne [int64]$JsonInput.Bytes.LongLength -or
        [string]$Recorded.sha256 -cne [string]$JsonInput.Sha256) {
        throw "$Label descriptor differs from its exact canonical file."
    }
}

function Open-StableFeedPromotionStateBundleAdmission {
    param(
        [Parameter(Mandatory = $true)][string]$BundleRoot,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][string]$ExpectedSourceHeadSha256,
        [string]$ExpectedAdmissionSha256 = '',
        [Parameter(Mandatory = $true)][string]$Label
    )

    $root = [IO.Path]::GetFullPath($BundleRoot)
    $rootInventory = [ordered]@{
        'request.v1.json' = $false
        'response.v1.json' = $false
        'promotion-head.v1.json' = $false
        'bundle-head.v1.json' = $false
        'promotion-admission.v1.json' = $false
    }
    [void](Assert-ExactProductionDirectoryInventory `
        -Path $root -Expected $rootInventory -Label $Label)
    $fileLeases = [Collections.Generic.List[object]]::new()
    $directoryLeases = [Collections.Generic.List[object]]::new()
    try {
        $specifications = @(
            [pscustomobject]@{
                Name = 'request.v1.json'
                Schema = $feedPromotionRequestSchemaPath
            },
            [pscustomobject]@{
                Name = 'response.v1.json'
                Schema = $feedPromotionResponseSchemaPath
            },
            [pscustomobject]@{
                Name = 'promotion-head.v1.json'
                Schema = $feedPromotionStateSchemaPath
            },
            [pscustomobject]@{
                Name = 'bundle-head.v1.json'
                Schema = ''
            },
            [pscustomobject]@{
                Name = 'promotion-admission.v1.json'
                Schema = $feedPromotionAdmissionSchemaPath
            })
        $inputs = [ordered]@{}
        foreach ($specification in $specifications) {
            if ([string]$specification.Schema) {
                $lease = Open-CanonicalProductionJsonLease `
                    -Path (Join-Path $root ([string]$specification.Name)) `
                    -SchemaPath ([string]$specification.Schema) `
                    -Label "$Label $($specification.Name)"
            }
            else {
                $descriptor = Open-ProductionReleaseInput `
                    -Path (Join-Path $root ([string]$specification.Name)) `
                    -Label "$Label $($specification.Name)" `
                    -MaximumBytes 64MB
                try {
                    [byte[]]$bytes = Read-ProductionReleaseInputBytes `
                        -Descriptor $descriptor `
                        -Label "$Label $($specification.Name)"
                    $lockedInput = [pscustomobject]@{
                        Path = [string]$descriptor.Path
                        Bytes = $bytes
                        Sha256 = [string]$descriptor.Sha256
                        Value = ConvertFrom-StrictProductionJsonBytes `
                            -Bytes $bytes `
                            -Label "$Label $($specification.Name)"
                    }
                    [void](Assert-CanonicalProductionJsonInput `
                        -JsonInput $lockedInput `
                        -Label "$Label $($specification.Name)")
                    $lease = [pscustomobject]@{
                        Input = $lockedInput
                        Descriptor = $descriptor
                    }
                    $descriptor = $null
                }
                finally {
                    if ($null -ne $descriptor) { $descriptor.Stream.Dispose() }
                }
            }
            [void](Add-ProductionAdmissionRelativePath `
                -Descriptor $lease.Descriptor `
                -RelativePath ([string]$specification.Name))
            $fileLeases.Add($lease.Descriptor)
            $inputs[[string]$specification.Name] = $lease.Input
        }

        $requestInput = $inputs['request.v1.json']
        $responseInput = $inputs['response.v1.json']
        $promotionHeadInput = $inputs['promotion-head.v1.json']
        $bundleHeadInput = $inputs['bundle-head.v1.json']
        $admissionInput = $inputs['promotion-admission.v1.json']
        $request = $requestInput.Value
        $response = $responseInput.Value
        $promotionHead = $promotionHeadInput.Value
        $bundleHead = $bundleHeadInput.Value
        $admission = $admissionInput.Value

        Assert-ExactProductionJsonMembers `
            -Value $bundleHead `
            -Expected @(
                'schemaVersion', 'stateType', 'operationId', 'requestSha256',
                'requestNonce', 'sourceStateHeadSha256', 'payloadSetSha256',
                'basePromotionHeadSha256', 'responseSha256',
                'bundleSetSha256', 'status', 'productionAdmission',
                'networkPublishPerformed', 'updatedAtUtc') `
            -Label "$Label bundle head"

        if ($ExpectedSourceHeadSha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [int]$request.schemaVersion -ne 1 -or
            [string]$request.edition -cne 'Enterprise' -or
            [string]$request.exposureRing -cne 'stable' -or
            [string]$request.feedChannel -cne 'stable' -or
            [string]$request.publishScope -cne 'public-stable' -or
            [string]$request.orchestrationId -cne [string]$Plan.orchestrationId -or
            [string]$request.releaseSetId -cne [string]$Plan.releaseSetId -or
            [string]$request.sourceState.headSha256 -cne $ExpectedSourceHeadSha256 -or
            [string]$request.authorizationTrust.keyId -cne
                [string]$Plan.externalResponseTrusts.feedPromotion.keyId -or
            [string]$request.authorizationTrust.purpose -cne
                'feed-promotion-response') {
            throw "$Label request is not bound to the exact Enterprise Stable r8 source and plan."
        }
        if ([string]$response.operationId -cne [string]$request.operationId -or
            [string]$response.requestSha256 -cne [string]$requestInput.Sha256 -or
            [string]$response.requestNonce -cne [string]$request.requestNonce -or
            [string]$response.sourceStateHeadSha256 -cne $ExpectedSourceHeadSha256 -or
            [string]$response.payloadSetSha256 -cne [string]$request.payloadSetSha256 -or
            [string]$response.feedCasSha256 -cne [string]$request.feedCasSha256 -or
            [string]$response.decision -cne 'AUTHORIZE_OFFLINE_BUNDLE' -or
            [string]$response.authentication.keyId -cne
                [string]$Plan.externalResponseTrusts.feedPromotion.keyId -or
            [bool]$response.networkPublishPerformed) {
            throw "$Label response is not bound to its exact request, source, and isolated trust."
        }
        if ([string]$promotionHead.stateType -cne
                'ensou-dsh-launcher-offline-feed-promotion-state' -or
            [string]$promotionHead.operationId -cne [string]$request.operationId -or
            [string]$promotionHead.requestSha256 -cne [string]$requestInput.Sha256 -or
            [string]$promotionHead.sourceStateHeadSha256 -cne $ExpectedSourceHeadSha256 -or
            [string]$promotionHead.status -cne 'PROMOTION_REQUEST_READY' -or
            [bool]$promotionHead.networkPublishPerformed) {
            throw "$Label promotion head does not bind the request-ready CAS state."
        }
        if ([string]$bundleHead.stateType -cne
                'ensou-dsh-launcher-offline-feed-promotion-bundle' -or
            [string]$bundleHead.operationId -cne [string]$request.operationId -or
            [string]$bundleHead.requestSha256 -cne [string]$requestInput.Sha256 -or
            [string]$bundleHead.basePromotionHeadSha256 -cne
                [string]$promotionHeadInput.Sha256 -or
            [string]$bundleHead.responseSha256 -cne [string]$responseInput.Sha256 -or
            [string]$bundleHead.sourceStateHeadSha256 -cne $ExpectedSourceHeadSha256 -or
            [string]$bundleHead.status -cne 'EXTERNAL_PUBLISH_BUNDLE_READY' -or
            [bool]$bundleHead.networkPublishPerformed) {
            throw "$Label bundle head does not bind the exact authenticated offline bundle."
        }

        Assert-StableFeedPromotionFileDescriptor `
            -Recorded $admission.request -JsonInput $requestInput `
            -FileName 'request.v1.json' -Label "$Label request"
        Assert-StableFeedPromotionFileDescriptor `
            -Recorded $admission.response -JsonInput $responseInput `
            -FileName 'response.v1.json' -Label "$Label response"
        Assert-StableFeedPromotionFileDescriptor `
            -Recorded $admission.promotionHead -JsonInput $promotionHeadInput `
            -FileName 'promotion-head.v1.json' -Label "$Label promotion head"
        Assert-StableFeedPromotionFileDescriptor `
            -Recorded $admission.bundleHead -JsonInput $bundleHeadInput `
            -FileName 'bundle-head.v1.json' -Label "$Label bundle head"

        if ([string]$admission.evidenceType -cne 'STABLE_PROMOTION_REQUESTED' -or
            [string]$admission.orchestrationId -cne [string]$Plan.orchestrationId -or
            [string]$admission.releaseSetId -cne [string]$Plan.releaseSetId -or
            [string]$admission.operationId -cne [string]$request.operationId -or
            [string]$admission.sourceState.headSha256 -cne
                $ExpectedSourceHeadSha256 -or
            [string]$admission.payloadSetSha256 -cne
                [string]$request.payloadSetSha256 -or
            [string]$admission.bundleHead.bundleSetSha256 -cne
                [string]$bundleHead.bundleSetSha256 -or
            [bool]$admission.networkPublishPerformed -or
            -not (Test-ProductionJsonValueEqual `
                -First $admission.feedFoundation.expectedChannelHead `
                -Second $request.feedCas.channelHead) -or
            -not (Test-ProductionJsonValueEqual `
                -First $admission.feedFoundation.expectedJournalHead `
                -Second $request.feedCas.journalHead)) {
            throw "$Label admission summary is not bound to the external bundle and feed CAS."
        }
        if (@($admission.files).Count -ne 5 -or
            @($request.files).Count -ne 5) {
            throw "$Label must bind exactly five Enterprise payload roles."
        }
        for ($index = 0; $index -lt 5; $index++) {
            $recorded = $admission.files[$index]
            $source = $request.files[$index]
            if ([string]$recorded.role -cne [string]$source.role -or
                [string]$recorded.fileName -cne [string]$source.fileName -or
                [int64]$recorded.sizeBytes -ne [int64]$source.sizeBytes -or
                [string]$recorded.sha256 -cne [string]$source.sha256) {
                throw "$Label payload descriptor index $index differs from its locked request."
            }
        }
        if ($ExpectedAdmissionSha256 -and
            [string]$admissionInput.Sha256 -cne $ExpectedAdmissionSha256) {
            throw "$Label admission summary differs from its pre-publication pin."
        }

        $directory = Open-ProductionReleaseDirectoryLease `
            -Path $root -Label "$Label directory"
        Add-Member -InputObject $directory -NotePropertyName `
            AdmissionRelativePath -NotePropertyValue '.' -Force
        $directoryLeases.Add($directory)
        $result = [pscustomobject]@{
            BundleRoot = $root
            Inputs = $inputs
            AdmissionInput = $admissionInput
            FileLeases = @($fileLeases)
            DirectoryLeases = @($directoryLeases)
            RootInventory = $rootInventory
            ChildInventories = @()
        }
        Assert-ProductionBundleAdmissionStillLocked `
            -Admission $result -Label $Label
        return $result
    }
    catch {
        foreach ($directory in @($directoryLeases)) {
            if ($null -ne $directory.Handle) { $directory.Handle.Dispose() }
        }
        foreach ($descriptor in @($fileLeases)) {
            if ($null -ne $descriptor.Stream) { $descriptor.Stream.Dispose() }
        }
        throw
    }
}

function Remove-ProductionBundleStagingRoot {
    param([Parameter(Mandatory = $true)]$Staging)

    $root = Assert-ProductionBundleStagingOwner -Staging $Staging
    foreach ($entry in @(Get-ChildItem -LiteralPath $root -Force -Recurse)) {
        $entryPath = [IO.Path]::GetFullPath($entry.FullName)
        if (-not (Test-SameOrDescendantPath -Path $entryPath -Root $root) -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Refusing to clean a changed or linked production staging tree.'
        }
    }
    $Staging.Owner.Stream.Dispose()
    [IO.Directory]::Delete($root, $true)
}

function Assert-ProductionHttpsUri {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label,
        [string]$ExpectedPath = '',
        [switch]$RequireTrailingSlash
    )

    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -cne 'https' -or
        -not [string]::IsNullOrEmpty($uri.UserInfo) -or
        -not [string]::IsNullOrEmpty($uri.Query) -or
        -not [string]::IsNullOrEmpty($uri.Fragment) -or
        $uri.IsLoopback -or
        $uri.IdnHost -in @('localhost', '127.0.0.1', '::1') -or
        $uri.IdnHost.EndsWith('.invalid', [StringComparison]::OrdinalIgnoreCase) -or
        $uri.IdnHost.EndsWith('.test', [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must be one production HTTPS origin without credentials, query, fragment, or Lab host."
    }
    if ($ExpectedPath -and $uri.AbsolutePath -cne $ExpectedPath) {
        throw "$Label does not use the canonical channel-head path '$ExpectedPath'."
    }
    if ($RequireTrailingSlash -and -not $uri.AbsolutePath.EndsWith('/', [StringComparison]::Ordinal)) {
        throw "$Label must end in one path separator."
    }
}

function Assert-PlanSemanticContract {
    param([Parameter(Mandatory = $true)][psobject]$Plan)

    if ([string]$Plan.edition -cne $Edition) {
        throw 'The -Edition argument differs from the signed production plan edition.'
    }
    if ($Edition -ceq 'Personal') {
        Assert-PersonalProductionReleasePlan `
            -Plan $Plan `
            -AllowHistoricalV1Status:($Phase -ceq 'Status')
    }
    else {
        Assert-EnterpriseProductionReleasePlan -Plan $Plan
    }
    if ([string]$Plan.runtimeCandidate.githubReleaseTag -cne [string]$Plan.runtimeCandidate.releaseId) {
        throw 'Runtime candidate tag must equal the reserved release ID.'
    }
    $targetChannel = if ([int]$Plan.schemaVersion -eq 1) {
        [string]$Plan.channel
    }
    else {
        [string]$Plan.targetChannel
    }
    if ([int]$Plan.schemaVersion -eq 2) {
        Assert-ExactProductionJsonMembers `
            -Value $Plan.releaseManifestTrust `
            -Expected @('algorithm', 'purpose', 'keyId', 'x', 'y') `
            -Label 'Plan v2 release-manifest trust'
        $releaseCompatibilityMembers = if ([string]$Plan.edition -ceq 'Personal') {
            @('startupStubVersion', 'canonicalLowSFromSequence')
        }
        else {
            @('startupStubProtocol')
        }
        Assert-ExactProductionJsonMembers `
            -Value $Plan.releaseCompatibility `
            -Expected $releaseCompatibilityMembers `
            -Label 'Plan v2 release compatibility'
        $trustDomains = @(
            $Plan.releaseManifestTrust,
            $Plan.externalResponseTrusts.clientSigning,
            $Plan.externalResponseTrusts.manifestPublishing,
            $Plan.externalResponseTrusts.installerSigning,
            $Plan.externalResponseTrusts.feedPromotion
        )
        $keyIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $publicKeyPoints = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($trustDomain in $trustDomains) {
            if (-not $keyIds.Add([string]$trustDomain.keyId)) {
                throw 'Plan v2 release-manifest and purpose-specific response trust domains require five distinct key IDs.'
            }
            $publicKeyPoint = Get-ProductionReleaseP256PublicKeyIdentity `
                -Trust $trustDomain `
                -Label ("Plan v2 trust domain '" + [string]$trustDomain.purpose + "'")
            if (-not $publicKeyPoints.Add($publicKeyPoint)) {
                throw 'Plan v2 release-manifest and purpose-specific response trust domains require five distinct P-256 public key points.'
            }
        }
        if ($null -ne $Plan.PSObject.Properties['stablePublicationTrust']) {
            [void](EnterpriseStablePublicationResult\Assert-EnterpriseStablePublicationTrust -Plan $Plan)
        }
        if ([string]$Plan.edition -ceq 'Enterprise' -and
            [string]$Plan.targetChannel -cne 'stable') {
            throw 'Enterprise production plan v2 must target the Stable channel directly.'
        }
    }
    Assert-ProductionHttpsUri -Value ([string]$Plan.manifestUri) -Label 'Manifest URI' -ExpectedPath ("/v2/channels/$targetChannel/release-set.v2.json")
    Assert-ProductionHttpsUri -Value ([string]$Plan.artifactBaseUri) -Label 'Artifact base URI' -RequireTrailingSlash
}

function Get-ClientSigningResponseTrust {
    param([Parameter(Mandatory = $true)][psobject]$Plan)

    if ([int]$Plan.schemaVersion -eq 1) {
        return $Plan.externalResponseTrust
    }
    return $Plan.externalResponseTrusts.clientSigning
}

function Get-ClientSigningAuthenticationContract {
    param([Parameter(Mandatory = $true)][psobject]$Plan)

    $trust = Get-ClientSigningResponseTrust -Plan $Plan
    if ([int]$Plan.schemaVersion -eq 1) {
        return [pscustomobject]@{
            Trust = $trust
            PayloadType = 'ensou-dsh-launcher-external-signing-response-authentication-v1'
            Purpose = ''
        }
    }
    return [pscustomobject]@{
        Trust = $trust
        PayloadType = 'ensou-dsh-launcher-external-signing-response-authentication-v2'
        Purpose = [string]$trust.purpose
    }
}

function Assert-DescriptorMatchesLockedInput {
    param(
        [Parameter(Mandatory = $true)][psobject]$Descriptor,
        [Parameter(Mandatory = $true)]$Locked,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ([string]$Descriptor.fileName -cne [string]$Locked.FileName -or
        [int64]$Descriptor.sizeBytes -ne [int64]$Locked.SizeBytes -or
        [string]$Descriptor.sha256 -cne [string]$Locked.Sha256) {
        throw "$Label differs from the exact plan descriptor."
    }
}

function New-ProductionVerificationRoot {
    param([Parameter(Mandatory = $true)][string]$Root)

    $verificationRoot = Join-Path $Root '.verification'
    if (Test-Path -LiteralPath $verificationRoot) {
        throw 'Production state contains a stale or unexpected path-verification workspace.'
    }
    [IO.Directory]::CreateDirectory($verificationRoot) | Out-Null
    $directory = Get-Item -LiteralPath $verificationRoot -Force -ErrorAction Stop
    if (-not $directory.PSIsContainer -or
        ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Production path-verification workspace is not one ordinary directory.'
    }
    return [IO.Path]::GetFullPath($directory.FullName)
}

function New-ProductionVerificationSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$VerificationRoot,
        [Parameter(Mandatory = $true)]$Locked,
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ([IO.Path]::GetFileName($FileName) -cne $FileName) {
        throw "$Label verification snapshot file name is not canonical."
    }
    $snapshotPath = Join-Path $VerificationRoot $FileName
    $writer = [IO.File]::Open(
        $snapshotPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try {
        $Locked.Stream.Position = 0
        $Locked.Stream.CopyTo($writer)
        $writer.Flush($true)
        $Locked.Stream.Position = 0
    }
    finally {
        $writer.Dispose()
    }
    $snapshot = Open-ProductionReleaseInput -Path $snapshotPath -Label "$Label private verification snapshot" -MaximumBytes ([int64]$Locked.SizeBytes)
    try {
        if ([int64]$snapshot.SizeBytes -ne [int64]$Locked.SizeBytes -or
            [string]$snapshot.Sha256 -cne [string]$Locked.Sha256) {
            throw "$Label private verification snapshot differs from the locked admitted bytes."
        }
        return $snapshot
    }
    catch {
        $snapshot.Stream.Dispose()
        throw
    }
}

function Remove-ProductionVerificationSnapshot {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Assert-ProductionReleaseInputStillLocked -Descriptor $Snapshot -Label "$Label private verification snapshot"
    $Snapshot.Stream.Dispose()
    [IO.File]::Delete([string]$Snapshot.Path)
}

function Remove-ProductionVerificationRoot {
    param([Parameter(Mandatory = $true)][string]$VerificationRoot)

    $directory = Get-Item -LiteralPath $VerificationRoot -Force -ErrorAction Stop
    if (-not $directory.PSIsContainer -or
        ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        [IO.Directory]::EnumerateFileSystemEntries($directory.FullName).GetEnumerator().MoveNext()) {
        throw 'Production path-verification workspace changed or is not empty.'
    }
    [IO.Directory]::Delete($directory.FullName, $false)
}

function Open-AndAdmitPlanInputs {
    param(
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $leases = [Collections.Generic.List[IDisposable]]::new()
    $clientSnapshots = [Collections.Generic.List[object]]::new()
    $verificationSnapshots = [Collections.Generic.List[object]]::new()
    $verificationRoot = $null
    try {
        $verificationRoot = New-ProductionVerificationRoot -Root $Root
        $runtimeArchive = Open-ProductionReleaseInput -Path ([string]$Plan.runtimeCandidate.archive.path) -Label 'Runtime candidate archive' -MaximumBytes (8L * 1024 * 1024 * 1024)
        $leases.Add($runtimeArchive.Stream)
        $runtimeMetadata = Open-ProductionReleaseInput -Path ([string]$Plan.runtimeCandidate.metadata.path) -Label 'Runtime candidate metadata' -MaximumBytes 4MB
        $leases.Add($runtimeMetadata.Stream)
        $runtimeHashEvidence = Open-ProductionReleaseInput -Path ([string]$Plan.runtimeCandidate.hashEvidence.path) -Label 'Runtime candidate hash evidence' -MaximumBytes 128KB
        $leases.Add($runtimeHashEvidence.Stream)
        Assert-DescriptorMatchesLockedInput -Descriptor $Plan.runtimeCandidate.archive -Locked $runtimeArchive -Label 'Runtime candidate archive'
        Assert-DescriptorMatchesLockedInput -Descriptor $Plan.runtimeCandidate.metadata -Locked $runtimeMetadata -Label 'Runtime candidate metadata'
        Assert-DescriptorMatchesLockedInput -Descriptor $Plan.runtimeCandidate.hashEvidence -Locked $runtimeHashEvidence -Label 'Runtime candidate hash evidence'
        if ([string]$runtimeHashEvidence.FileName -cne ([string]$runtimeArchive.FileName + '.sha256')) {
            throw 'Runtime candidate hash-evidence file name is not canonical.'
        }
        $hashBytes = Read-ProductionReleaseInputBytes -Descriptor $runtimeHashEvidence -Label 'Runtime candidate hash evidence'
        try {
            $hashText = $utf8Strict.GetString($hashBytes)
        }
        catch {
            throw 'Runtime candidate hash evidence is not strict UTF-8.'
        }
        $canonicalHashLine = [string]$runtimeArchive.Sha256 + '  ' + [string]$runtimeArchive.FileName
        if ($hashText -cne $canonicalHashLine -and
            $hashText -cne ($canonicalHashLine + [char]10) -and
            $hashText -cne ($canonicalHashLine + [char]13 + [char]10)) {
            throw 'Runtime candidate hash evidence is not the exact canonical archive digest record.'
        }
        $runtimeArchiveSnapshot = New-ProductionVerificationSnapshot -VerificationRoot $verificationRoot -Locked $runtimeArchive -FileName ([string]$runtimeArchive.FileName) -Label 'Runtime candidate archive'
        $verificationSnapshots.Add($runtimeArchiveSnapshot)
        $runtimeMetadataSnapshot = New-ProductionVerificationSnapshot -VerificationRoot $verificationRoot -Locked $runtimeMetadata -FileName ([string]$runtimeMetadata.FileName) -Label 'Runtime candidate metadata'
        $verificationSnapshots.Add($runtimeMetadataSnapshot)
        $metadataResult = @(& $metadataValidatorPath -MetadataPath $runtimeMetadataSnapshot.Path -ArtifactPath $runtimeArchiveSnapshot.Path -ExpectedReleaseId ([string]$Plan.runtimeCandidate.releaseId) -ExpectedArtifactFileName ([string]$runtimeArchive.FileName) -ExpectedArtifactSha256 ([string]$runtimeArchive.Sha256) -ExpectedRuntimeProfile $EnterpriseRuntimeProfile)
        if ($metadataResult.Count -ne 1 -or
            [bool]$metadataResult[0].promotionEligible -ne $true) {
            throw 'Runtime candidate is not exact production-eligible source metadata.'
        }
        foreach ($snapshot in @($runtimeArchiveSnapshot, $runtimeMetadataSnapshot)) {
            Assert-ProductionReleaseInputStillLocked -Descriptor $snapshot -Label "Validated $($snapshot.FileName) private snapshot"
        }
        for ($index = $verificationSnapshots.Count - 1; $index -ge 0; $index--) {
            Remove-ProductionVerificationSnapshot -Snapshot $verificationSnapshots[$index] -Label 'Runtime candidate'
        }
        $verificationSnapshots.Clear()
        foreach ($locked in @($runtimeArchive, $runtimeMetadata, $runtimeHashEvidence)) {
            Assert-ProductionReleaseInputStillLocked -Descriptor $locked -Label "Locked $($locked.FileName)"
        }

        foreach ($input in @($Plan.clientSigningInputs)) {
            $locked = Open-ProductionReleaseInput -Path ([string]$input.path) -Label "Unsigned client role $($input.role)" -MaximumBytes 512MB
            $leases.Add($locked.Stream)
            Assert-DescriptorMatchesLockedInput -Descriptor $input -Locked $locked -Label "Unsigned client role $($input.role)"
            $bytes = Read-ProductionReleaseInputBytes -Descriptor $locked -Label "Unsigned client role $($input.role)"
            $peContentSha256 = Get-PeContentSha256 -Bytes $bytes
            if ($peContentSha256 -cne [string]$input.peContentSha256) {
                throw "Unsigned client role '$($input.role)' differs from its PE content identity."
            }
            $verificationSnapshot = New-ProductionVerificationSnapshot -VerificationRoot $verificationRoot -Locked $locked -FileName ([string]$locked.FileName) -Label "Unsigned client role $($input.role)"
            $verificationSnapshots.Add($verificationSnapshot)
            $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $verificationSnapshot.Path
            if ($signature.Status -ne [Management.Automation.SignatureStatus]::NotSigned -or
                $null -ne $signature.SignerCertificate) {
                throw "Unsigned client role '$($input.role)' is already signed or has an ambiguous signature."
            }
            Remove-ProductionVerificationSnapshot -Snapshot $verificationSnapshot -Label "Unsigned client role $($input.role)"
            $verificationSnapshots.RemoveAt($verificationSnapshots.Count - 1)
            Assert-ProductionReleaseInputStillLocked -Descriptor $locked -Label "Unsigned client role $($input.role)"
            $clientSnapshots.Add([pscustomobject]@{
                Role = [string]$input.role
                FileName = [string]$input.fileName
                SizeBytes = [int64]$input.sizeBytes
                Sha256 = [string]$input.sha256
                PeContentSha256 = [string]$input.peContentSha256
                Bytes = $bytes
            })
        }
        Remove-ProductionVerificationRoot -VerificationRoot $verificationRoot
        $verificationRoot = $null
        return [pscustomobject]@{
            Leases = $leases
            ClientSnapshots = $clientSnapshots
            RuntimePromotionEligible = $true
            RuntimeMetadata = $metadataResult[0]
        }
    }
    catch {
        for ($index = $verificationSnapshots.Count - 1; $index -ge 0; $index--) {
            try {
                Remove-ProductionVerificationSnapshot -Snapshot $verificationSnapshots[$index] -Label 'Failed path verification'
            }
            catch {
            }
        }
        if ($null -ne $verificationRoot -and (Test-Path -LiteralPath $verificationRoot)) {
            try {
                Remove-ProductionVerificationRoot -VerificationRoot $verificationRoot
            }
            catch {
            }
        }
        for ($index = $leases.Count - 1; $index -ge 0; $index--) {
            $leases[$index].Dispose()
        }
        throw
    }
}

function Get-PlanAdmissionData {
    param(
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)]$SourceCheckout,
        [AllowNull()]$RuntimeMetadata
    )

    $clientSet = [Collections.Generic.List[object]]::new()
    foreach ($input in @($Plan.clientSigningInputs)) {
        $clientSet.Add([ordered]@{
            role = [string]$input.role
            fileName = [string]$input.fileName
            sizeBytes = [int64]$input.sizeBytes
            sha256 = [string]$input.sha256
            peContentSha256 = [string]$input.peContentSha256
        })
    }
    $data = [ordered]@{
        releaseSetId = [string]$Plan.releaseSetId
        sourceCommit = [string]$SourceCheckout.Commit
        sourceTree = [string]$SourceCheckout.Tree
        manifestUri = [string]$Plan.manifestUri
        artifactBaseUri = [string]$Plan.artifactBaseUri
        runtimeCandidate = [ordered]@{
            releaseId = [string]$Plan.runtimeCandidate.releaseId
            githubReleaseTag = [string]$Plan.runtimeCandidate.githubReleaseTag
            archiveSha256 = [string]$Plan.runtimeCandidate.archive.sha256
            metadataSha256 = [string]$Plan.runtimeCandidate.metadata.sha256
            hashEvidenceSha256 = [string]$Plan.runtimeCandidate.hashEvidence.sha256
            localMetadataPromotionEligible = $true
            publicationStatus = 'IMMUTABLE_SOURCE_RELEASE_UNVERIFIED'
        }
        clientInputs = $clientSet
    }
    if ([int]$Plan.schemaVersion -eq 1) {
        $data.Insert(1, 'channel', [string]$Plan.channel)
    }
    else {
        if ($null -eq $RuntimeMetadata) {
            throw 'Plan v2 admission requires the validated runtime metadata identity.'
        }
        $runtimeSourceReleaseExpectation =
            ProductionReleaseState\Get-ProductionRuntimeSourceReleaseExpectation -Plan $Plan
        $runtimeCandidateInsertIndex = 2
        if ($null -ne $runtimeSourceReleaseExpectation) {
            $data.runtimeCandidate.Insert(
                $runtimeCandidateInsertIndex++,
                'githubRepository',
                [string]$Plan.runtimeCandidate.githubRepository)
            $data.runtimeCandidate.Insert(
                $runtimeCandidateInsertIndex++,
                'githubReleaseCommit',
                [string]$Plan.runtimeCandidate.githubReleaseCommit)
        }
        $data.runtimeCandidate.Insert(
            $runtimeCandidateInsertIndex++,
            'harnessSourceTag',
            [string]$RuntimeMetadata.sourceTag)
        $data.runtimeCandidate.Insert(
            $runtimeCandidateInsertIndex,
            'harnessSourceCommit',
            [string]$RuntimeMetadata.sourceCommit)
        $data.Insert(1, 'targetChannel', [string]$Plan.targetChannel)
        $data.Insert(6, 'releaseManifestTrustSha256', (
                Get-ProductionSha256Bytes -Bytes (
                    ConvertTo-ProductionJsonBytes -Value $Plan.releaseManifestTrust)))
        $data.Insert(7, 'releaseCompatibilitySha256', (
                Get-ProductionSha256Bytes -Bytes (
                    ConvertTo-ProductionJsonBytes -Value $Plan.releaseCompatibility)))
    }
    return $data
}

function Get-RequestBundle {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [AllowNull()]$ClientSnapshots
    )

    $requestRoot = Join-Path (Join-Path $Root 'requests') 'client-signing.v1'
    $unsignedRoot = Join-Path $requestRoot 'unsigned'
    if (-not (Test-Path -LiteralPath $requestRoot)) {
        [IO.Directory]::CreateDirectory($requestRoot) | Out-Null
    }
    if (-not (Test-Path -LiteralPath $unsignedRoot)) {
        [IO.Directory]::CreateDirectory($unsignedRoot) | Out-Null
    }

    $requestPath = Join-Path $requestRoot 'signing-request.v1.json'
    if (-not (Test-Path -LiteralPath $requestPath)) {
        if ($null -eq $ClientSnapshots -or @($ClientSnapshots).Count -ne 4) {
            throw 'Unsigned client inputs are required to create a new external signing request.'
        }
        foreach ($snapshot in @($ClientSnapshots)) {
            Write-ProductionStateFile -Path (Join-Path $unsignedRoot ([string]$snapshot.FileName)) -Bytes ([byte[]]$snapshot.Bytes)
        }
        $nonceBytes = [byte[]]::new(32)
        [Security.Cryptography.RandomNumberGenerator]::Fill($nonceBytes)
        $nonce = [Convert]::ToBase64String($nonceBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        [Array]::Clear($nonceBytes, 0, $nonceBytes.Length)
        $created = [DateTimeOffset]::UtcNow
        $expires = $created.AddMinutes([int]$Plan.authenticodePolicy.maximumResponseAgeMinutes)
        $files = [Collections.Generic.List[object]]::new()
        foreach ($input in @($Plan.clientSigningInputs)) {
            $files.Add([ordered]@{
                role = [string]$input.role
                fileName = [string]$input.fileName
                relativePath = 'unsigned/' + [string]$input.fileName
                sizeBytes = [int64]$input.sizeBytes
                sha256 = [string]$input.sha256
                peContentSha256 = [string]$input.peContentSha256
            })
        }
        $authenticationContract = Get-ClientSigningAuthenticationContract -Plan $Plan
        $responseAuthentication = [ordered]@{
            algorithm = 'ES256'
            keyId = [string]$authenticationContract.Trust.keyId
            payloadType = [string]$authenticationContract.PayloadType
        }
        if ([int]$Plan.schemaVersion -eq 2) {
            $responseAuthentication.Insert(2, 'purpose', [string]$authenticationContract.Purpose)
        }
        $request = [ordered]@{
            schemaVersion = 1
            requestType = 'ensou-dsh-launcher-client-authenticode-signing'
            orchestrationId = [string]$Plan.orchestrationId
            edition = [string]$Plan.edition
            releaseSetId = [string]$Plan.releaseSetId
            planSha256 = Get-ProductionSha256Bytes -Bytes $planInput.Bytes
            nonce = $nonce
            createdAtUtc = ConvertTo-ProductionUtc -Value $created
            expiresAtUtc = ConvertTo-ProductionUtc -Value $expires
            responseAuthentication = $responseAuthentication
            authenticode = [ordered]@{
                signerSha256Thumbprint = [string]$Plan.authenticodePolicy.signerSha256Thumbprint
                requireTrustedTimestamp = $true
            }
            files = $files
        }
        $requestBytes = ConvertTo-ProductionJsonBytes -Value $request
        [void](ConvertFrom-StrictProductionJsonBytes -Bytes $requestBytes -Label 'Generated external signing request' -SchemaPath $requestSchemaPath)
        Write-ProductionStateFile -Path $requestPath -Bytes $requestBytes
    }

    $requestInput = Read-StrictProductionJsonFile -Path $requestPath -Label 'External signing request' -SchemaPath $requestSchemaPath
    $request = $requestInput.Value
    $authenticationContract = Get-ClientSigningAuthenticationContract -Plan $Plan
    $requestPurposeProperty = $request.responseAuthentication.PSObject.Properties['purpose']
    $requestPurpose = if ($null -eq $requestPurposeProperty) { '' } else { [string]$requestPurposeProperty.Value }
    if ([string]$request.orchestrationId -cne [string]$Plan.orchestrationId -or
        [string]$request.edition -cne [string]$Plan.edition -or
        [string]$request.releaseSetId -cne [string]$Plan.releaseSetId -or
        [string]$request.planSha256 -cne (Get-ProductionSha256Bytes -Bytes $planInput.Bytes) -or
        [string]$request.responseAuthentication.keyId -cne [string]$authenticationContract.Trust.keyId -or
        [string]$request.responseAuthentication.payloadType -cne [string]$authenticationContract.PayloadType -or
        $requestPurpose -cne [string]$authenticationContract.Purpose -or
        ([int]$Plan.schemaVersion -eq 1 -and $null -ne $requestPurposeProperty) -or
        ([int]$Plan.schemaVersion -eq 2 -and $null -eq $requestPurposeProperty) -or
        [string]$request.authenticode.signerSha256Thumbprint -cne [string]$Plan.authenticodePolicy.signerSha256Thumbprint) {
        throw 'External signing request is not bound to the exact production plan.'
    }
    $expectedNames = [ordered]@{}
    foreach ($input in @($Plan.clientSigningInputs)) {
        $expectedNames[[string]$input.fileName] = $false
    }
    [void](Assert-ExactProductionDirectoryInventory -Path $unsignedRoot -Expected $expectedNames -Label 'Unsigned signing-request payload')
    for ($index = 0; $index -lt @($Plan.clientSigningInputs).Count; $index++) {
        $input = $Plan.clientSigningInputs[$index]
        $requested = $request.files[$index]
        if ([string]$requested.role -cne [string]$input.role -or
            [string]$requested.fileName -cne [string]$input.fileName -or
            [string]$requested.relativePath -cne ('unsigned/' + [string]$input.fileName) -or
            [int64]$requested.sizeBytes -ne [int64]$input.sizeBytes -or
            [string]$requested.sha256 -cne [string]$input.sha256 -or
            [string]$requested.peContentSha256 -cne [string]$input.peContentSha256) {
            throw "External signing request role index $index differs from the plan."
        }
        $unsigned = Open-ProductionReleaseInput -Path (Join-Path $unsignedRoot ([string]$input.fileName)) -Label "Request payload role $($input.role)" -MaximumBytes 512MB
        try {
            $bytes = Read-ProductionReleaseInputBytes -Descriptor $unsigned -Label "Request payload role $($input.role)"
            if ($unsigned.SizeBytes -ne [int64]$input.sizeBytes -or
                $unsigned.Sha256 -cne [string]$input.sha256 -or
                (Get-PeContentSha256 -Bytes $bytes) -cne [string]$input.peContentSha256) {
                throw "Request payload role '$($input.role)' changed after snapshot."
            }
        }
        finally {
            $unsigned.Stream.Dispose()
        }
    }
    $requestRootExpected = [ordered]@{
        'signing-request.v1.json' = $false
        'unsigned' = $true
    }
    [void](Assert-ExactProductionDirectoryInventory -Path $requestRoot -Expected $requestRootExpected -Label 'External signing-request bundle')
    return $requestInput
}

function Get-RequestReceiptData {
    param([Parameter(Mandatory = $true)]$RequestInput)

    $fileSet = [Collections.Generic.List[object]]::new()
    foreach ($file in @($RequestInput.Value.files)) {
        $fileSet.Add([ordered]@{
            role = [string]$file.role
            fileName = [string]$file.fileName
            sha256 = [string]$file.sha256
            peContentSha256 = [string]$file.peContentSha256
        })
    }
    return [ordered]@{
        requestRelativePath = 'requests/client-signing.v1/signing-request.v1.json'
        requestSha256 = [string]$RequestInput.Sha256
        nonce = [string]$RequestInput.Value.nonce
        createdAtUtc = [string]$RequestInput.Value.createdAtUtc
        expiresAtUtc = [string]$RequestInput.Value.expiresAtUtc
        files = $fileSet
    }
}

function Assert-ResponseCore {
    param(
        [Parameter(Mandatory = $true)][psobject]$Response,
        [Parameter(Mandatory = $true)]$RequestInput,
        [Parameter(Mandatory = $true)][psobject]$Plan
    )

    $request = $RequestInput.Value
    $authenticationContract = Get-ClientSigningAuthenticationContract -Plan $Plan
    $responsePurposeProperty = $Response.authentication.PSObject.Properties['purpose']
    $responsePayloadTypeProperty = $Response.authentication.PSObject.Properties['payloadType']
    $responsePurpose = if ($null -eq $responsePurposeProperty) { '' } else { [string]$responsePurposeProperty.Value }
    $responsePayloadType = if ($null -eq $responsePayloadTypeProperty) { '' } else { [string]$responsePayloadTypeProperty.Value }
    if ([string]$Response.orchestrationId -cne [string]$request.orchestrationId -or
        [string]$Response.edition -cne [string]$request.edition -or
        [string]$Response.releaseSetId -cne [string]$request.releaseSetId -or
        [string]$Response.planSha256 -cne [string]$request.planSha256 -or
        [string]$Response.requestSha256 -cne [string]$RequestInput.Sha256 -or
        [string]$Response.requestNonce -cne [string]$request.nonce -or
        [string]$Response.authentication.algorithm -cne 'ES256' -or
        [string]$Response.authentication.keyId -cne [string]$request.responseAuthentication.keyId -or
        $responsePurpose -cne [string]$authenticationContract.Purpose -or
        ([int]$Plan.schemaVersion -eq 1 -and
         ($null -ne $responsePurposeProperty -or $null -ne $responsePayloadTypeProperty)) -or
        ([int]$Plan.schemaVersion -eq 2 -and
         ($null -eq $responsePurposeProperty -or
          $null -eq $responsePayloadTypeProperty -or
          $responsePayloadType -cne [string]$request.responseAuthentication.payloadType))) {
        throw 'External signing response is not bound to the exact request nonce and plan.'
    }
    $created = ConvertFrom-ProductionUtc -Value ([string]$request.createdAtUtc) -Label 'Signing request creation time'
    $expires = ConvertFrom-ProductionUtc -Value ([string]$request.expiresAtUtc) -Label 'Signing request expiry time'
    $completed = ConvertFrom-ProductionUtc -Value ([string]$Response.completedAtUtc) -Label 'Signing response completion time'
    $now = [DateTimeOffset]::UtcNow
    if ($completed -lt $created -or
        $completed -gt $expires -or
        $completed -gt $now.AddMinutes(5) -or
        $completed -lt $now.AddMinutes(-[int]$Plan.authenticodePolicy.maximumResponseAgeMinutes)) {
        throw 'External signing response is stale, future-dated, or outside its request lifetime.'
    }
    Assert-ProductionReleaseSigningResponseAuthentication -Response $Response -Trust (Get-ClientSigningResponseTrust -Plan $Plan)
}

function Initialize-ProductionReleaseProbeProcess {
    param(
        [Parameter(Mandatory = $true)]$Admission,
        [Parameter(Mandatory = $true)][string]$CheckoutRoot
    )

    # Compile only bytes read from the already admitted, still-locked checkout.
    # A private namespace prevents reuse of a caller-preloaded type or a type
    # compiled from another checkout earlier in this PowerShell process.
    $sources = [Collections.Generic.List[string]]::new()
    foreach ($relativePath in @(
            'src/Ensou.Dsh.Host/WindowsJobObject.cs',
            'release/scripts/ProductionReleaseProbeProcess.cs')) {
        $expectedPath = [IO.Path]::GetFullPath((Join-Path $CheckoutRoot $relativePath))
        $matchedDescriptors = @($Admission.Descriptors | Where-Object {
            [string]::Equals([string]$_.Path, $expectedPath, [StringComparison]::OrdinalIgnoreCase)
        })
        if ($matchedDescriptors.Count -ne 1) {
            throw "Release probe code is not in the exact locked checkout closure: $relativePath"
        }
        $sourceBytes = Read-ProductionReleaseInputBytes `
            -Descriptor $matchedDescriptors[0] -Label "Release probe source $relativePath"
        $sources.Add($utf8Strict.GetString($sourceBytes))
    }
    $scope = 'EnsouReleaseProbe_' + [Guid]::NewGuid().ToString('N')
    $source = "#nullable enable`nnamespace $scope {`n" + ($sources -join "`n") + "`n}"
    $types = @(Microsoft.PowerShell.Utility\Add-Type `
        -TypeDefinition $source -CompilerOptions '/langversion:10' -PassThru)
    $expectedType = $scope + '.EnsouLauncherProductionProbe.ReleaseProbeProcess'
    $probeTypes = @($types | Where-Object { $_.FullName -ceq $expectedType })
    if ($probeTypes.Count -ne 1) {
        throw 'Release probe compilation did not return its exact private runtime type.'
    }
    return $probeTypes[0]
}

function Invoke-ReleaseManifestTrustProbe {
    param(
        [Parameter(Mandatory = $true)][string]$ExecutablePath,
        [Parameter(Mandatory = $true)]$VerificationSnapshot,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string]$FileName
    )

    if ([string]$Plan.edition -ceq 'Enterprise' -and $Role -ceq 'maintenance') {
        return $null
    }
    if (-not [string]::Equals(
            $ExecutablePath, [string]$VerificationSnapshot.Path,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Release trust probe must execute its exact locked verification snapshot.'
    }
    Assert-ProductionReleaseInputStillLocked `
        -Descriptor $VerificationSnapshot -Label "Signed client role '$Role' before trust probe"
    if ($null -eq $script:releaseProbeProcessType) {
        $script:releaseProbeProcessType = Initialize-ProductionReleaseProbeProcess `
            -Admission $codeAdmission -CheckoutRoot $repositoryRootFull
    }
    $probeProcessType = $script:releaseProbeProcessType
    try {
        $stdout = $probeProcessType::Execute(
            $ExecutablePath,
            $VerificationSnapshot.Stream.SafeFileHandle,
            ([string]$Plan.edition -ceq 'Personal'))
        if ($stdout.Length -le 0 -or $stdout.Length -gt 32768) {
            throw "Signed client role '$Role' release-manifest trust probe output is empty or unbounded."
        }
        $probeBytes = $utf8Strict.GetBytes($stdout)
        $probeInput = [pscustomobject]@{
            Path = $ExecutablePath
            FileName = $FileName
            SizeBytes = [int64]$probeBytes.LongLength
            Sha256 = Get-ProductionSha256Bytes -Bytes $probeBytes
            Bytes = $probeBytes
            Value = ConvertFrom-StrictProductionJsonBytes `
                -Bytes $probeBytes `
                -Label "Signed client role '$Role' release-manifest trust probe" `
                -SchemaPath $releaseTrustProbeSchemaPath
        }
        [void](Assert-CanonicalProductionJsonInput `
            -Input $probeInput `
            -Label "Signed client role '$Role' release-manifest trust probe")
        $probe = $probeInput.Value
        $manifestUri = [Uri]::new([string]$Plan.manifestUri, [UriKind]::Absolute)
        $artifactUri = [Uri]::new([string]$Plan.artifactBaseUri, [UriKind]::Absolute)
        $manifestOrigin = $manifestUri.GetLeftPart([UriPartial]::Authority) + '/'
        $artifactOrigin = $artifactUri.GetLeftPart([UriPartial]::Authority) + '/'
        if ([string]$Plan.edition -ceq 'Personal') {
            if ([int]$probe.schemaVersion -ne 2 -or
                -not [bool]$probe.productionBuild -or
                [string]$probe.product -cne 'ensou-dsh-personal' -or
                [string]$probe.environment -cne 'production' -or
                [string]$probe.channel -cne [string]$Plan.targetChannel -or
                [string]$probe.manifestOrigin -cne $manifestOrigin -or
                [string]$probe.artifactOrigin -cne $artifactOrigin -or
                [string]$probe.releaseKeyId -cne [string]$Plan.releaseManifestTrust.keyId -or
                [string]$probe.releaseKeyX -cne [string]$Plan.releaseManifestTrust.x -or
                [string]$probe.releaseKeyY -cne [string]$Plan.releaseManifestTrust.y -or
                [string]$probe.startupStubVersion -cne
                    [string]$Plan.releaseCompatibility.startupStubVersion -or
                [int64]$probe.canonicalLowSFromSequence -ne
                    [int64]$Plan.releaseCompatibility.canonicalLowSFromSequence -or
                ([string]$probe.authenticodeSignerSha256Thumbprint).ToLowerInvariant() -cne
                    [string]$Plan.authenticodePolicy.signerSha256Thumbprint) {
                throw "Signed client role '$Role' compiled Personal release-manifest trust differs from the exact plan."
            }
        }
        else {
            Assert-ExactProductionJsonMembers `
                -Value $probe `
                -Expected @(
                    'schemaVersion', 'probeType', 'edition', 'product',
                    'environment', 'channel', 'manifestUri', 'manifestOrigin',
                    'artifactOrigin', 'authenticodeSignerSha256Thumbprint',
                    'releaseManifestTrust', 'releaseCompatibility') `
                -Label "Signed client role '$Role' Enterprise release-manifest trust probe"
            Assert-ExactProductionJsonMembers `
                -Value $probe.releaseManifestTrust `
                -Expected @('algorithm', 'purpose', 'keyId', 'x', 'y') `
                -Label "Signed client role '$Role' Enterprise release-manifest trust"
            Assert-ExactProductionJsonMembers `
                -Value $probe.releaseCompatibility `
                -Expected @('startupStubProtocol') `
                -Label "Signed client role '$Role' Enterprise release compatibility"
            if ([int]$probe.schemaVersion -ne 1 -or
                [string]$probe.probeType -cne
                    'ensou-dsh-enterprise-release-manifest-trust-probe-v1' -or
                [string]$probe.edition -cne 'Enterprise' -or
                [string]$probe.product -cne 'ensou-dsh-enterprise' -or
                [string]$probe.environment -cne 'production' -or
                [string]$probe.channel -cne 'stable' -or
                [string]$probe.manifestUri -cne [string]$Plan.manifestUri -or
                [string]$probe.manifestOrigin -cne $manifestOrigin -or
                [string]$probe.artifactOrigin -cne $artifactOrigin -or
                [string]$probe.authenticodeSignerSha256Thumbprint -cne
                    [string]$Plan.authenticodePolicy.signerSha256Thumbprint -or
                (Get-ProductionSha256Bytes -Bytes (
                        ConvertTo-ProductionJsonBytes -Value $probe.releaseManifestTrust)) -cne
                    (Get-ProductionSha256Bytes -Bytes (
                        ConvertTo-ProductionJsonBytes -Value $Plan.releaseManifestTrust)) -or
                (Get-ProductionSha256Bytes -Bytes (
                        ConvertTo-ProductionJsonBytes -Value $probe.releaseCompatibility)) -cne
                    (Get-ProductionSha256Bytes -Bytes (
                        ConvertTo-ProductionJsonBytes -Value $Plan.releaseCompatibility))) {
                throw "Signed client role '$Role' compiled Enterprise release-manifest trust differs from the exact plan."
            }
        }
        return [pscustomobject]@{
            Role = $Role
            FileName = $FileName
            ProbeSha256 = [string]$probeInput.Sha256
        }
    }
    finally {
        Assert-ProductionReleaseInputStillLocked `
            -Descriptor $VerificationSnapshot -Label "Signed client role '$Role' after trust probe"
    }
}

function Import-ClientSigningResponse {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)]$RequestInput,
        [Parameter(Mandatory = $true)][string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'ImportClientSignatures requires -ResponsePath.'
    }
    $responseInput = Read-StrictProductionJsonFile -Path $Path -Label 'External signing response' -SchemaPath $responseSchemaPath
    $response = $responseInput.Value
    Assert-ResponseCore -Response $response -RequestInput $RequestInput -Plan $Plan
    $responseRoot = [IO.Path]::GetDirectoryName($responseInput.Path)
    $signedRoot = Join-Path $responseRoot 'signed'
    $rootExpected = [ordered]@{
        ([IO.Path]::GetFileName($responseInput.Path)) = $false
        'signed' = $true
    }
    if ([IO.Path]::GetFileName($responseInput.Path) -cne 'signing-response.v1.json') {
        throw 'External signing response file name must be signing-response.v1.json.'
    }
    [void](Assert-ExactProductionDirectoryInventory -Path $responseRoot -Expected $rootExpected -Label 'External signing-response bundle')
    $signedExpected = [ordered]@{}
    foreach ($input in @($Plan.clientSigningInputs)) {
        $signedExpected[[string]$input.fileName] = $false
    }
    [void](Assert-ExactProductionDirectoryInventory -Path $signedRoot -Expected $signedExpected -Label 'External signed-client payload')

    $leases = [Collections.Generic.List[IDisposable]]::new()
    $signedSnapshots = [Collections.Generic.List[object]]::new()
    $releaseManifestTrustProbes = [Collections.Generic.List[object]]::new()
    $verificationSnapshots = [Collections.Generic.List[object]]::new()
    $verificationRoot = $null
    try {
        $verificationRoot = New-ProductionVerificationRoot -Root $Root
        for ($index = 0; $index -lt @($RequestInput.Value.files).Count; $index++) {
            $requested = $RequestInput.Value.files[$index]
            $returned = $response.files[$index]
            if ([string]$returned.role -cne [string]$requested.role -or
                [string]$returned.fileName -cne [string]$requested.fileName -or
                [string]$returned.relativePath -cne ('signed/' + [string]$requested.fileName) -or
                [string]$returned.inputSha256 -cne [string]$requested.sha256 -or
                [string]$returned.inputPeContentSha256 -cne [string]$requested.peContentSha256 -or
                [string]$returned.signedPeContentSha256 -cne [string]$requested.peContentSha256) {
                throw "External signing response role index $index differs from its exact request."
            }
            $signedPath = Join-Path $signedRoot ([string]$returned.fileName)
            $locked = Open-ProductionReleaseInput -Path $signedPath -Label "Signed client role $($returned.role)" -MaximumBytes 512MB
            $leases.Add($locked.Stream)
            $bytes = Read-ProductionReleaseInputBytes -Descriptor $locked -Label "Signed client role $($returned.role)"
            $peContentSha256 = Get-PeContentSha256 -Bytes $bytes
            if ($locked.SizeBytes -ne [int64]$returned.sizeBytes -or
                $locked.Sha256 -cne [string]$returned.sha256 -or
                $peContentSha256 -cne [string]$returned.signedPeContentSha256) {
                throw "Signed client role '$($returned.role)' differs from the authenticated response."
            }
            $verificationSnapshot = New-ProductionVerificationSnapshot -VerificationRoot $verificationRoot -Locked $locked -FileName ([string]$locked.FileName) -Label "Signed client role $($returned.role)"
            $verificationSnapshots.Add($verificationSnapshot)
            $authenticodeEvidence =
                InstallerSigningContracts\Get-ExactPeAuthenticodeEvidence `
                    -Path $verificationSnapshot.Path `
                    -ExpectedSignerCertificateSha256 `
                        ([string]$Plan.authenticodePolicy.signerSha256Thumbprint) `
                    -ExpectedPeContentSha256 `
                        ([string]$requested.peContentSha256)
            if ([string]$authenticodeEvidence.AuthenticodeStatus -cne 'Valid' -or
                [string]$authenticodeEvidence.TimestampProtocol -cne 'RFC3161' -or
                [int]$authenticodeEvidence.PrimarySignerCount -ne 1 -or
                [bool]$authenticodeEvidence.LegacyCounterSignaturePresent) {
                throw "Signed client role '$($returned.role)' lacks one exact Authenticode signer and one exact RFC3161 timestamp."
            }
            if ([int]$Plan.schemaVersion -eq 2) {
                $probe = Invoke-ReleaseManifestTrustProbe `
                    -ExecutablePath $verificationSnapshot.Path `
                    -VerificationSnapshot $verificationSnapshot `
                    -Plan $Plan `
                    -Role ([string]$returned.role) `
                    -FileName ([string]$returned.fileName)
                if ($null -ne $probe) {
                    $releaseManifestTrustProbes.Add($probe)
                }
            }
            Remove-ProductionVerificationSnapshot -Snapshot $verificationSnapshot -Label "Signed client role $($returned.role)"
            $verificationSnapshots.RemoveAt($verificationSnapshots.Count - 1)
            Assert-ProductionReleaseInputStillLocked -Descriptor $locked -Label "Signed client role $($returned.role)"
            $signedSnapshots.Add([pscustomobject]@{
                Role = [string]$returned.role
                FileName = [string]$returned.fileName
                SizeBytes = [int64]$returned.sizeBytes
                Sha256 = [string]$returned.sha256
                PeContentSha256 = [string]$returned.signedPeContentSha256
                TimestampProtocol = 'RFC3161'
                Bytes = $bytes
            })
        }

        $importRoot = Join-Path (Join-Path $Root 'imports') 'client-signing.v1'
        $importSignedRoot = Join-Path $importRoot 'signed'
        if (-not (Test-Path -LiteralPath $importRoot)) {
            [IO.Directory]::CreateDirectory($importRoot) | Out-Null
        }
        if (-not (Test-Path -LiteralPath $importSignedRoot)) {
            [IO.Directory]::CreateDirectory($importSignedRoot) | Out-Null
        }
        Write-ProductionStateFile -Path (Join-Path $importRoot 'signing-response.v1.json') -Bytes $responseInput.Bytes
        foreach ($snapshot in $signedSnapshots) {
            Write-ProductionStateFile -Path (Join-Path $importSignedRoot ([string]$snapshot.FileName)) -Bytes ([byte[]]$snapshot.Bytes)
        }
        $importRootExpected = [ordered]@{
            'signing-response.v1.json' = $false
            'signed' = $true
        }
        [void](Assert-ExactProductionDirectoryInventory -Path $importRoot -Expected $importRootExpected -Label 'Imported signing-response bundle')
        [void](Assert-ExactProductionDirectoryInventory -Path $importSignedRoot -Expected $signedExpected -Label 'Imported signed-client payload')
        Remove-ProductionVerificationRoot -VerificationRoot $verificationRoot
        $verificationRoot = $null
        return [pscustomobject]@{
            ResponseInput = $responseInput
            SignedSnapshots = $signedSnapshots
            ReleaseManifestTrustProbes = $releaseManifestTrustProbes
        }
    }
    finally {
        for ($index = $verificationSnapshots.Count - 1; $index -ge 0; $index--) {
            try {
                Remove-ProductionVerificationSnapshot -Snapshot $verificationSnapshots[$index] -Label 'Failed signed-client path verification'
            }
            catch {
            }
        }
        if ($null -ne $verificationRoot -and (Test-Path -LiteralPath $verificationRoot)) {
            try {
                Remove-ProductionVerificationRoot -VerificationRoot $verificationRoot
            }
            catch {
            }
        }
        for ($index = $leases.Count - 1; $index -ge 0; $index--) {
            $leases[$index].Dispose()
        }
    }
}

function Assert-ImportedProductionBundle {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)]$Import
    )

    $importRoot = Join-Path (Join-Path $Root 'imports') 'client-signing.v1'
    $signedRoot = Join-Path $importRoot 'signed'
    $importRootExpected = [ordered]@{
        'signing-response.v1.json' = $false
        'signed' = $true
    }
    [void](Assert-ExactProductionDirectoryInventory `
        -Path $importRoot `
        -Expected $importRootExpected `
        -Label 'Imported signing-response bundle')
    $signedExpected = [ordered]@{}
    foreach ($input in @($Plan.clientSigningInputs)) {
        $signedExpected[[string]$input.fileName] = $false
    }
    [void](Assert-ExactProductionDirectoryInventory `
        -Path $signedRoot `
        -Expected $signedExpected `
        -Label 'Imported signed-client payload')

    $responseSnapshot = Open-ProductionReleaseInput `
        -Path (Join-Path $importRoot 'signing-response.v1.json') `
        -Label 'Imported signing-response snapshot' `
        -MaximumBytes 4MB
    try {
        if ([int64]$responseSnapshot.SizeBytes -ne [int64]$Import.ResponseInput.Bytes.LongLength -or
            [string]$responseSnapshot.Sha256 -cne [string]$Import.ResponseInput.Sha256) {
            throw 'Imported signing-response snapshot differs from the authenticated response.'
        }
    }
    finally {
        $responseSnapshot.Stream.Dispose()
    }
    foreach ($snapshot in @($Import.SignedSnapshots)) {
        $published = Open-ProductionReleaseInput `
            -Path (Join-Path $signedRoot ([string]$snapshot.FileName)) `
            -Label "Imported signed client role $($snapshot.Role)" `
            -MaximumBytes 512MB
        try {
            if ([int64]$published.SizeBytes -ne [int64]$snapshot.SizeBytes -or
                [string]$published.Sha256 -cne [string]$snapshot.Sha256) {
                throw "Imported signed client role '$($snapshot.Role)' differs from the admitted snapshot."
            }
        }
        finally {
            $published.Stream.Dispose()
        }
    }
}

function Get-ImportReceiptData {
    param([Parameter(Mandatory = $true)]$Import)

    $files = [Collections.Generic.List[object]]::new()
    foreach ($snapshot in @($Import.SignedSnapshots)) {
        $files.Add([ordered]@{
            role = [string]$snapshot.Role
            fileName = [string]$snapshot.FileName
            sizeBytes = [int64]$snapshot.SizeBytes
            sha256 = [string]$snapshot.Sha256
            peContentSha256 = [string]$snapshot.PeContentSha256
            timestampProtocol = [string]$snapshot.TimestampProtocol
        })
    }
    $data = [ordered]@{
        responseRelativePath = 'imports/client-signing.v1/signing-response.v1.json'
        responseSha256 = [string]$Import.ResponseInput.Sha256
        completedAtUtc = [string]$Import.ResponseInput.Value.completedAtUtc
        authenticationKeyId = [string]$Import.ResponseInput.Value.authentication.keyId
        files = $files
    }
    $purposeProperty = $Import.ResponseInput.Value.authentication.PSObject.Properties['purpose']
    if ($null -ne $purposeProperty) {
        $data.Insert(4, 'authenticationPurpose', [string]$purposeProperty.Value)
        $data.Insert(5, 'authenticationPayloadType', [string]$Import.ResponseInput.Value.authentication.payloadType)
        $probes = [Collections.Generic.List[object]]::new()
        foreach ($probe in @($Import.ReleaseManifestTrustProbes)) {
            $probes.Add([ordered]@{
                role = [string]$probe.Role
                fileName = [string]$probe.FileName
                probeSha256 = [string]$probe.ProbeSha256
            })
        }
        $data.Insert(6, 'releaseManifestTrustProbeStatus', 'VERIFIED')
        $data.Insert(7, 'releaseManifestTrustProbes', $probes)
    }
    return $data
}

function Copy-ProductionLockedInputToCreateOnlyFile {
    param(
        [Parameter(Mandatory = $true)][Alias('Input')]$LockedInput,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $destinationFull = [IO.Path]::GetFullPath($DestinationPath)
    $destinationParent = [IO.Path]::GetDirectoryName($destinationFull)
    $parentItem = Get-Item -LiteralPath $destinationParent -Force -ErrorAction Stop
    if (-not $parentItem.PSIsContainer -or
        ($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        (Test-Path -LiteralPath $destinationFull)) {
        throw "$Label create-only destination is not one new child of an ordinary directory."
    }
    $writer = [IO.File]::Open(
        $destinationFull,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try {
        $LockedInput.Stream.Position = 0
        $LockedInput.Stream.CopyTo($writer)
        $writer.Flush($true)
        $LockedInput.Stream.Position = 0
    }
    finally {
        $writer.Dispose()
    }
    Assert-ProductionReleaseInputStillLocked -Descriptor $LockedInput -Label $Label
    $published = Open-ProductionReleaseInput `
        -Path $destinationFull `
        -Label "$Label staged copy" `
        -MaximumBytes ([int64]$LockedInput.SizeBytes)
    try {
        if ([int64]$published.SizeBytes -ne [int64]$LockedInput.SizeBytes -or
            [string]$published.Sha256 -cne [string]$LockedInput.Sha256) {
            throw "$Label staged copy differs from the locked external input."
        }
    }
    finally {
        $published.Stream.Dispose()
    }
}

function Assert-ProductionBundleTreesEqual {
    param(
        [Parameter(Mandatory = $true)][string]$ExpectedRoot,
        [Parameter(Mandatory = $true)][string]$ActualRoot,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $expected = [IO.Path]::GetFullPath($ExpectedRoot)
    $actual = [IO.Path]::GetFullPath($ActualRoot)
    $expectedEntries = @(Get-ChildItem -LiteralPath $expected -Force -Recurse | Sort-Object FullName)
    $actualEntries = @(Get-ChildItem -LiteralPath $actual -Force -Recurse | Sort-Object FullName)
    if ($expectedEntries.Count -ne $actualEntries.Count) {
        throw "$Label differs in entry count."
    }
    $actualByRelative = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal)
    foreach ($entry in $actualEntries) {
        $relative = [IO.Path]::GetRelativePath($actual, $entry.FullName).Replace(
            [IO.Path]::DirectorySeparatorChar,
            '/')
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not $actualByRelative.TryAdd($relative, $entry)) {
            throw "$Label actual tree contains a linked or repeated entry."
        }
    }
    foreach ($entry in $expectedEntries) {
        $relative = [IO.Path]::GetRelativePath($expected, $entry.FullName).Replace(
            [IO.Path]::DirectorySeparatorChar,
            '/')
        $matching = $null
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not $actualByRelative.TryGetValue($relative, [ref]$matching) -or
            [bool]$entry.PSIsContainer -ne [bool]$matching.PSIsContainer) {
            throw "$Label differs at '$relative'."
        }
        if (-not $entry.PSIsContainer) {
            $expectedInput = Open-ProductionReleaseInput `
                -Path $entry.FullName `
                -Label "$Label expected file $relative" `
                -MaximumBytes (8L * 1024 * 1024 * 1024)
            $actualInput = Open-ProductionReleaseInput `
                -Path $matching.FullName `
                -Label "$Label actual file $relative" `
                -MaximumBytes (8L * 1024 * 1024 * 1024)
            try {
                if ([int64]$expectedInput.SizeBytes -ne [int64]$actualInput.SizeBytes -or
                    [string]$expectedInput.Sha256 -cne [string]$actualInput.Sha256) {
                    throw "$Label file '$relative' differs in exact bytes."
                }
            }
            finally {
                $actualInput.Stream.Dispose()
                $expectedInput.Stream.Dispose()
            }
        }
    }
}

function New-PilotManifestPublishingRequestBundle {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$BaseHeadSha256,
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$ExistingRequestPath = ''
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'PrepareManifestSigning requires -PublisherInputPath.'
    }
    $descriptorInput = Read-StrictProductionJsonFile `
        -Path $Path `
        -Label 'External production Publisher input descriptor' `
        -SchemaPath $publisherInputSchemaPath
    [void](Assert-CanonicalProductionJsonInput `
        -Input $descriptorInput `
        -Label 'External production Publisher input descriptor')
    if ([IO.Path]::GetFileName($descriptorInput.Path) -cne 'publisher-input.v1.json') {
        throw 'External production Publisher input descriptor file name must be publisher-input.v1.json.'
    }
    $externalRoot = [IO.Path]::GetDirectoryName($descriptorInput.Path)
    [void](Assert-ExactProductionDirectoryInventory `
        -Path $externalRoot `
        -Expected ([ordered]@{
            'publisher-input.v1.json' = $false
            'payload' = $true
        }) `
        -Label 'External production Publisher input bundle')
    [void](Assert-ProductionPublisherInputFileSet `
        -Plan $Plan `
        -PlanSha256 ([string]$State.Identity.planSha256) `
        -PlanAdmissionReceipt $State.Receipts[0] `
        -ClientImportReceipt $State.Receipts[2] `
        -DescriptorInput $descriptorInput `
        -PayloadRoot (Join-Path $externalRoot 'payload'))

    $channelContract = Get-ProductionManifestChannelContract `
        -TargetChannel ([string]$Plan.targetChannel)
    $requestRoot = Join-Path `
        (Join-Path $Root 'requests') `
        ([string]$channelContract.RequestBundleName)
    $payloadRoot = Join-Path $requestRoot 'payload'
    [IO.Directory]::CreateDirectory($payloadRoot) | Out-Null
    Write-ProductionStateFile `
        -Path (Join-Path $requestRoot 'publisher-input.v1.json') `
        -Bytes $descriptorInput.Bytes
    foreach ($file in @($descriptorInput.Value.files)) {
        $source = Open-ProductionReleaseInput `
            -Path (Join-Path (Join-Path $externalRoot 'payload') ([string]$file.fileName)) `
            -Label "External production Publisher payload role $($file.role)" `
            -MaximumBytes (8L * 1024 * 1024 * 1024)
        try {
            Copy-ProductionLockedInputToCreateOnlyFile `
                -Input $source `
                -DestinationPath (Join-Path $payloadRoot ([string]$file.fileName)) `
                -Label "External production Publisher payload role $($file.role)"
        }
        finally {
            $source.Stream.Dispose()
        }
    }

    $requestPath = Join-Path $requestRoot 'manifest-publishing-request.v1.json'
    if ($ExistingRequestPath) {
        $existingRequest = Read-StrictProductionJsonFile `
            -Path $ExistingRequestPath `
            -Label 'Existing target-channel manifest-publishing request' `
            -SchemaPath $manifestRequestSchemaPath
        [void](Assert-CanonicalProductionJsonInput `
            -Input $existingRequest `
            -Label 'Existing target-channel manifest-publishing request')
        Write-ProductionStateFile -Path $requestPath -Bytes $existingRequest.Bytes
    }
    else {
        $nonceBytes = [byte[]]::new(32)
        [Security.Cryptography.RandomNumberGenerator]::Fill($nonceBytes)
        try {
            $requestNonce = [Convert]::ToBase64String($nonceBytes).
                TrimEnd('=').Replace('+', '-').Replace('/', '_')
        }
        finally {
            [Array]::Clear($nonceBytes, 0, $nonceBytes.Length)
        }
        $created = [DateTimeOffset]::UtcNow
        $expires = $created.AddMinutes(
            [int]$Plan.authenticodePolicy.maximumResponseAgeMinutes)
        $files = [Collections.Generic.List[object]]::new()
        foreach ($file in @($descriptorInput.Value.files)) {
            $files.Add([ordered]@{
                role = [string]$file.role
                fileName = [string]$file.fileName
                relativePath = [string]$file.relativePath
                sizeBytes = [int64]$file.sizeBytes
                sha256 = [string]$file.sha256
            })
        }
        $trust = $Plan.externalResponseTrusts.manifestPublishing
        $request = [ordered]@{
            schemaVersion = 1
            requestType = [string]$channelContract.RequestType
            orchestrationId = [string]$Plan.orchestrationId
            edition = [string]$Plan.edition
            releaseSetId = [string]$Plan.releaseSetId
            channel = [string]$channelContract.TargetChannel
            planSha256 = [string]$State.Identity.planSha256
            baseHeadSha256 = $BaseHeadSha256
            requestedRevision = 4
            requestNonce = $requestNonce
            createdAtUtc = ConvertTo-ProductionUtc -Value $created
            expiresAtUtc = ConvertTo-ProductionUtc -Value $expires
            publisherInput = [ordered]@{
                descriptorRelativePath = 'publisher-input.v1.json'
                descriptorSha256 = [string]$descriptorInput.Sha256
                files = $files
            }
            releaseManifestTrust = $Plan.releaseManifestTrust
            releaseCompatibility = $Plan.releaseCompatibility
            componentReleaseIds = $descriptorInput.Value.componentReleaseIds
            runtimeProvenance = $descriptorInput.Value.runtimeProvenance
            responseAuthentication = [ordered]@{
                algorithm = 'ES256'
                keyId = [string]$trust.keyId
                purpose = 'manifest-publishing-response'
                payloadType =
                    'ensou-dsh-launcher-manifest-publishing-response-authentication-v1'
            }
        }
        $runtimeSourceReleaseExpectation =
            ProductionReleaseState\Get-ProductionRuntimeSourceReleaseExpectation -Plan $Plan
        if ($null -ne $runtimeSourceReleaseExpectation) {
            $request.Insert(
                16,
                'runtimeSourceReleaseExpectation',
                [ordered]@{
                    repository = [string]$runtimeSourceReleaseExpectation.repository
                    tagName = [string]$runtimeSourceReleaseExpectation.tagName
                    targetCommit = [string]$runtimeSourceReleaseExpectation.targetCommit
                })
        }
        $requestBytes = ConvertTo-ProductionJsonBytes -Value $request
        [void](ConvertFrom-StrictProductionJsonBytes `
            -Bytes $requestBytes `
            -Label 'Generated target-channel manifest-publishing request' `
            -SchemaPath $manifestRequestSchemaPath)
        Write-ProductionStateFile -Path $requestPath -Bytes $requestBytes
    }
    $requestInput = Read-StrictProductionJsonFile `
        -Path $requestPath `
        -Label 'Staged target-channel manifest-publishing request' `
        -SchemaPath $manifestRequestSchemaPath
    [void](Assert-CanonicalProductionJsonInput `
        -Input $requestInput `
        -Label 'Staged target-channel manifest-publishing request')
    $request = $requestInput.Value
    $trust = $Plan.externalResponseTrusts.manifestPublishing
    [void](ProductionReleaseState\Assert-ProductionRuntimeSourceReleaseExpectation `
        -Plan $Plan -Value $request)
    if ([string]$request.orchestrationId -cne [string]$Plan.orchestrationId -or
        [string]$request.edition -cne [string]$Plan.edition -or
        [string]$request.releaseSetId -cne [string]$Plan.releaseSetId -or
        [string]$request.requestType -cne [string]$channelContract.RequestType -or
        [string]$request.channel -cne [string]$channelContract.TargetChannel -or
        [string]$request.planSha256 -cne [string]$State.Identity.planSha256 -or
        [string]$request.baseHeadSha256 -cne $BaseHeadSha256 -or
        [int]$request.requestedRevision -ne 4 -or
        [string]$request.publisherInput.descriptorSha256 -cne
            [string]$descriptorInput.Sha256 -or
        (Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $request.releaseManifestTrust)) -cne
            (Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $Plan.releaseManifestTrust)) -or
        (Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $request.releaseCompatibility)) -cne
            (Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $Plan.releaseCompatibility)) -or
        (Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $request.componentReleaseIds)) -cne
            (Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $descriptorInput.Value.componentReleaseIds)) -or
        (Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $request.runtimeProvenance)) -cne
            (Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $descriptorInput.Value.runtimeProvenance)) -or
        [string]$request.responseAuthentication.keyId -cne [string]$trust.keyId -or
        [string]$request.responseAuthentication.purpose -cne
            'manifest-publishing-response' -or
        [string]$request.responseAuthentication.payloadType -cne
            'ensou-dsh-launcher-manifest-publishing-response-authentication-v1') {
        throw 'Target-channel manifest-publishing request is not the exact plan/head/Publisher-input request.'
    }
    if (@($request.publisherInput.files).Count -ne @($descriptorInput.Value.files).Count) {
        throw 'Target-channel manifest-publishing request file count differs from its Publisher input.'
    }
    for ($index = 0; $index -lt @($request.publisherInput.files).Count; $index++) {
        $requested = ConvertTo-ProductionJsonBytes -Value $request.publisherInput.files[$index]
        $described = ConvertTo-ProductionJsonBytes -Value $descriptorInput.Value.files[$index]
        if ((Get-ProductionSha256Bytes -Bytes $requested) -cne
            (Get-ProductionSha256Bytes -Bytes $described)) {
            throw "Target-channel manifest-publishing request file index $index differs from its Publisher input."
        }
    }
    [void](Assert-ExactProductionDirectoryInventory `
        -Path $requestRoot `
        -Expected ([ordered]@{
            'manifest-publishing-request.v1.json' = $false
            'publisher-input.v1.json' = $false
            'payload' = $true
        }) `
        -Label 'Staged target-channel manifest-publishing request bundle')
    return [pscustomobject]@{
        RequestInput = $requestInput
        DescriptorInput = $descriptorInput
    }
}

function Get-PilotManifestRequestReceiptData {
    param([Parameter(Mandatory = $true)]$Bundle)

    $files = [Collections.Generic.List[object]]::new()
    foreach ($file in @($Bundle.RequestInput.Value.publisherInput.files)) {
        $files.Add([ordered]@{
            role = [string]$file.role
            fileName = [string]$file.fileName
            relativePath = [string]$file.relativePath
            sizeBytes = [int64]$file.sizeBytes
            sha256 = [string]$file.sha256
        })
    }
    $channelContract = Get-ProductionManifestChannelContract `
        -TargetChannel ([string]$Bundle.RequestInput.Value.channel)
    return [ordered]@{
        requestRelativePath = 'requests/' +
            [string]$channelContract.RequestBundleName +
            '/manifest-publishing-request.v1.json'
        requestSha256 = [string]$Bundle.RequestInput.Sha256
        publisherInputDescriptorSha256 = [string]$Bundle.DescriptorInput.Sha256
        baseHeadSha256 = [string]$Bundle.RequestInput.Value.baseHeadSha256
        requestNonce = [string]$Bundle.RequestInput.Value.requestNonce
        createdAtUtc = [string]$Bundle.RequestInput.Value.createdAtUtc
        expiresAtUtc = [string]$Bundle.RequestInput.Value.expiresAtUtc
        responseAuthenticationKeyId =
            [string]$Bundle.RequestInput.Value.responseAuthentication.keyId
        responseAuthenticationPurpose = 'manifest-publishing-response'
        responseAuthenticationPayloadType =
            'ensou-dsh-launcher-manifest-publishing-response-authentication-v1'
        releaseManifestTrustSha256 = Get-ProductionSha256Bytes -Bytes (
            ConvertTo-ProductionJsonBytes -Value $Bundle.RequestInput.Value.releaseManifestTrust)
        releaseCompatibilitySha256 = Get-ProductionSha256Bytes -Bytes (
            ConvertTo-ProductionJsonBytes -Value $Bundle.RequestInput.Value.releaseCompatibility)
        componentReleaseIdsSha256 = Get-ProductionSha256Bytes -Bytes (
            ConvertTo-ProductionJsonBytes -Value $Bundle.RequestInput.Value.componentReleaseIds)
        runtimeProvenanceSha256 = Get-ProductionSha256Bytes -Bytes (
            ConvertTo-ProductionJsonBytes -Value $Bundle.RequestInput.Value.runtimeProvenance)
        compiledReleaseTrustStatus = 'VERIFIED'
        files = $files
    }
}

function Import-PilotSignedCandidateResponse {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)]$RequestInput,
        [Parameter(Mandatory = $true)][string]$AdmissionHeadSha256,
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$EnforceCurrentLifetime
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'ImportSignedCandidate requires -ResponsePath.'
    }
    $channelContract = Get-ProductionManifestChannelContract `
        -TargetChannel ([string]$Plan.targetChannel)
    $responseInput = Read-StrictProductionJsonFile `
        -Path $Path `
        -Label 'External target-channel signed-candidate response' `
        -SchemaPath $manifestResponseSchemaPath
    [void](Assert-CanonicalProductionJsonInput `
        -Input $responseInput `
        -Label 'External target-channel signed-candidate response')
    if ([IO.Path]::GetFileName($responseInput.Path) -cne
        'manifest-publishing-response.v1.json') {
        throw 'Target-channel signed-candidate response file name must be manifest-publishing-response.v1.json.'
    }
    $externalRoot = [IO.Path]::GetDirectoryName($responseInput.Path)
    [void](Assert-ExactProductionDirectoryInventory `
        -Path $externalRoot `
        -Expected ([ordered]@{
            'manifest-publishing-response.v1.json' = $false
            'candidate' = $true
        }) `
        -Label 'External target-channel signed-candidate response bundle')
    $response = $responseInput.Value
    $expectedResponseMembers = @(
        'schemaVersion', 'responseType', 'orchestrationId', 'edition',
        'releaseSetId', 'channel', 'planSha256', 'requestSha256',
        'requestNonce', 'baseHeadSha256', 'admissionHeadSha256',
        'admissionRevision', 'requestExpiresAtUtc', 'completedAtUtc',
        'files', 'authentication')
    $runtimeSourceReleaseExpectation =
        ProductionReleaseState\Get-ProductionRuntimeSourceReleaseExpectation -Plan $Plan
    if ($null -ne $runtimeSourceReleaseExpectation) {
        $expectedResponseMembers += 'runtimeSourceReleaseAdmission'
    }
    Assert-ExactProductionJsonMembers `
        -Value $response `
        -Expected $expectedResponseMembers `
        -Label 'External target-channel signed-candidate response'
    Assert-ExactProductionJsonMembers `
        -Value $response.authentication `
        -Expected @('algorithm', 'keyId', 'purpose', 'payloadType', 'value') `
        -Label 'External target-channel signed-candidate response authentication'
    for ($index = 0; $index -lt @($response.files).Count; $index++) {
        Assert-ExactProductionJsonMembers `
            -Value $response.files[$index] `
            -Expected @('role', 'fileName', 'relativePath', 'sizeBytes', 'sha256') `
            -Label "External target-channel signed-candidate response file index $index"
    }
    $request = $RequestInput.Value
    if ([string]$response.responseType -cne [string]$channelContract.ResponseType -or
        [string]$response.channel -cne [string]$channelContract.TargetChannel -or
        [string]$response.orchestrationId -cne [string]$request.orchestrationId -or
        [string]$response.edition -cne [string]$request.edition -or
        [string]$response.releaseSetId -cne [string]$request.releaseSetId -or
        [string]$response.channel -cne [string]$request.channel -or
        [string]$response.planSha256 -cne [string]$request.planSha256 -or
        [string]$response.requestSha256 -cne [string]$RequestInput.Sha256 -or
        [string]$response.requestNonce -cne [string]$request.requestNonce -or
        [string]$response.baseHeadSha256 -cne [string]$request.baseHeadSha256 -or
        [string]$response.admissionHeadSha256 -cne $AdmissionHeadSha256 -or
        [int]$response.admissionRevision -ne 4 -or
        [string]$response.requestExpiresAtUtc -cne [string]$request.expiresAtUtc) {
        throw 'Target-channel signed-candidate response is not bound to the exact request nonce, plan, edition, revision, and state heads.'
    }
    $created = ConvertFrom-ProductionUtc `
        -Value ([string]$request.createdAtUtc) `
        -Label 'Target-channel manifest-publishing request creation time'
    $expires = ConvertFrom-ProductionUtc `
        -Value ([string]$request.expiresAtUtc) `
        -Label 'Target-channel manifest-publishing request expiry time'
    $completed = ConvertFrom-ProductionUtc `
        -Value ([string]$response.completedAtUtc) `
        -Label 'Target-channel signed-candidate response completion time'
    $now = [DateTimeOffset]::UtcNow
    if ($completed -lt $created -or
        $completed -gt $expires -or
        $completed -gt $now.AddMinutes(5) -or
        ($EnforceCurrentLifetime -and $now -gt $expires)) {
        throw 'Target-channel signed-candidate response is stale, future-dated, or outside its exact request lifetime.'
    }
    Assert-ProductionReleaseManifestPublishingResponseAuthentication `
        -Response $response `
        -Trust $Plan.externalResponseTrusts.manifestPublishing
    [void](ProductionReleaseState\Assert-ProductionRuntimeSourceReleaseResponseBinding `
        -Plan $Plan -Request $request -Response $response -StateRoot $StateRoot)

    $files = @($response.files)
    if ($files.Count -lt 1 -or
        [string]$files[0].role -cne 'release-manifest' -or
        [string]$files[0].fileName -cne 'release-set.v2.json' -or
        [string]$files[0].relativePath -cne 'candidate/release-set.v2.json') {
        throw 'Target-channel signed-candidate response must begin with candidate/release-set.v2.json.'
    }
    $roles = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $fileNames = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $candidateExpected = [ordered]@{}
    foreach ($file in $files) {
        if (-not $roles.Add([string]$file.role) -or
            -not $fileNames.Add([string]$file.fileName) -or
            [string]$file.relativePath -cne ('candidate/' + [string]$file.fileName)) {
            throw 'Target-channel signed-candidate response repeats a file identity or uses a noncanonical path.'
        }
        $candidateExpected[[string]$file.fileName] = $false
    }
    $externalCandidateRoot = Join-Path $externalRoot 'candidate'
    [void](Assert-ExactProductionDirectoryInventory `
        -Path $externalCandidateRoot `
        -Expected $candidateExpected `
        -Label 'External target-channel signed-candidate payload')

    $importRoot = Join-Path `
        (Join-Path $Root 'imports') `
        ([string]$channelContract.CandidateBundleName)
    $candidateRoot = Join-Path $importRoot 'candidate'
    [IO.Directory]::CreateDirectory($candidateRoot) | Out-Null
    Write-ProductionStateFile `
        -Path (Join-Path $importRoot 'manifest-publishing-response.v1.json') `
        -Bytes $responseInput.Bytes
    foreach ($file in $files) {
        $source = Open-ProductionReleaseInput `
            -Path (Join-Path $externalCandidateRoot ([string]$file.fileName)) `
            -Label "External target-channel signed-candidate role $($file.role)" `
            -MaximumBytes (8L * 1024 * 1024 * 1024)
        try {
            if ([int64]$source.SizeBytes -ne [int64]$file.sizeBytes -or
                [string]$source.Sha256 -cne [string]$file.sha256) {
                throw "External target-channel signed-candidate role '$($file.role)' differs from its authenticated descriptor."
            }
            Copy-ProductionLockedInputToCreateOnlyFile `
                -Input $source `
                -DestinationPath (Join-Path $candidateRoot ([string]$file.fileName)) `
                -Label "External target-channel signed-candidate role $($file.role)"
        }
        finally {
            $source.Stream.Dispose()
        }
    }
    $manifestInput = Read-StrictProductionJsonFile `
        -Path (Join-Path $candidateRoot 'release-set.v2.json') `
        -Label 'Staged target-channel signed release-set candidate'
    [void](Assert-CanonicalProductionJsonInput `
        -Input $manifestInput `
        -Label 'Staged target-channel signed release-set candidate')
    [void]@(Assert-ProductionReleaseManifestCandidate `
        -Plan $Plan `
        -ManifestInput $manifestInput `
        -CandidateRoot $candidateRoot `
        -Files $files `
        -ComponentReleaseIds $request.componentReleaseIds `
        -RuntimeProvenance $request.runtimeProvenance `
        -ValidationTimeUtc $completed)
    return [pscustomobject]@{
        ResponseInput = $responseInput
        ManifestInput = $manifestInput
        RequestInput = $RequestInput
    }
}

function Get-PilotSignedCandidateReceiptData {
    param([Parameter(Mandatory = $true)]$Import)

    $files = [Collections.Generic.List[object]]::new()
    foreach ($file in @($Import.ResponseInput.Value.files)) {
        $files.Add([ordered]@{
            role = [string]$file.role
            fileName = [string]$file.fileName
            relativePath = [string]$file.relativePath
            sizeBytes = [int64]$file.sizeBytes
            sha256 = [string]$file.sha256
        })
    }
    $channelContract = Get-ProductionManifestChannelContract `
        -TargetChannel ([string]$Import.ResponseInput.Value.channel)
    return [ordered]@{
        responseRelativePath = 'imports/' +
            [string]$channelContract.CandidateBundleName +
            '/manifest-publishing-response.v1.json'
        responseSha256 = [string]$Import.ResponseInput.Sha256
        requestSha256 = [string]$Import.ResponseInput.Value.requestSha256
        requestNonce = [string]$Import.ResponseInput.Value.requestNonce
        baseHeadSha256 = [string]$Import.ResponseInput.Value.baseHeadSha256
        admissionHeadSha256 = [string]$Import.ResponseInput.Value.admissionHeadSha256
        admissionRevision = 4
        requestExpiresAtUtc = [string]$Import.ResponseInput.Value.requestExpiresAtUtc
        completedAtUtc = [string]$Import.ResponseInput.Value.completedAtUtc
        authenticationKeyId = [string]$Import.ResponseInput.Value.authentication.keyId
        authenticationPurpose = 'manifest-publishing-response'
        authenticationPayloadType =
            'ensou-dsh-launcher-manifest-publishing-response-authentication-v1'
        manifestRelativePath = 'imports/' +
            [string]$channelContract.CandidateBundleName +
            '/candidate/release-set.v2.json'
        manifestSha256 = [string]$Import.ManifestInput.Sha256
        releaseManifestTrustSha256 = Get-ProductionSha256Bytes -Bytes (
            ConvertTo-ProductionJsonBytes -Value $Import.RequestInput.Value.releaseManifestTrust)
        releaseCompatibilitySha256 = Get-ProductionSha256Bytes -Bytes (
            ConvertTo-ProductionJsonBytes -Value $Import.RequestInput.Value.releaseCompatibility)
        componentReleaseIdsSha256 = Get-ProductionSha256Bytes -Bytes (
            ConvertTo-ProductionJsonBytes -Value $Import.RequestInput.Value.componentReleaseIds)
        runtimeProvenanceSha256 = Get-ProductionSha256Bytes -Bytes (
            ConvertTo-ProductionJsonBytes -Value $Import.RequestInput.Value.runtimeProvenance)
        compiledReleaseTrustStatus = 'VERIFIED'
        productionAdmission = 'NO_GO'
        files = $files
    }
}

function Get-InstallerSigningEvidenceFile {
    param(
        [Parameter(Mandatory = $true)][object[]]$Files,
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $matches = @($Files | Where-Object {
            $identity = if ($null -ne $_.PSObject.Properties['role']) {
                [string]$_.role
            }
            elseif ($null -ne $_.PSObject.Properties['component']) {
                [string]$_.component
            }
            else {
                ''
            }
            $identity -ceq $Role
        })
    if ($matches.Count -ne 1) {
        throw "$Label must contain exactly one role '$Role'."
    }
    return $matches[0]
}

function Get-InstallerSigningPayloadSelfCheckResultSha256 {
    param(
        [Parameter(Mandatory = $true)][psobject]$SelfCheck
    )

    $result = [ordered]@{
        schemaVersion = 1
        verificationType = 'ensou-dsh-launcher-installer-production-payload-self-check'
        command = [string]$SelfCheck.command
        status = [string]$SelfCheck.status
        exitCode = [int]$SelfCheck.exitCode
        inspectedInstallerSha256 = [string]$SelfCheck.inspectedInstallerSha256
        candidateSetSha256 = [string]$SelfCheck.candidateSetSha256
        payloadSetSha256 = [string]$SelfCheck.payloadSetSha256
        r3SignedClientSetSha256 = [string]$SelfCheck.r3SignedClientSetSha256
        releaseManifestTrustSha256 = [string]$SelfCheck.releaseManifestTrustSha256
        releaseManifestTrustProbeSetSha256 =
            [string]$SelfCheck.releaseManifestTrustProbeSetSha256
        completedAtUtc = [string]$SelfCheck.completedAtUtc
    }
    return Get-ProductionSha256Bytes -Bytes (
        ConvertTo-ProductionJsonBytes -Value $result)
}

function Assert-InstallerSigningPayloadSelfCheck {
    param(
        [Parameter(Mandatory = $true)][string]$InstallerPath,
        [Parameter(Mandatory = $true)][psobject]$Request,
        [Parameter(Mandatory = $true)][psobject]$SelfCheck,
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$ExecuteTrustedInstaller
    )

    if ([string]$SelfCheck.resultSha256 -cne
        (Get-InstallerSigningPayloadSelfCheckResultSha256 -SelfCheck $SelfCheck)) {
        throw "$Label result SHA-256 is not its canonical payload verification result."
    }
    $candidateRoot = Join-Path `
        (Join-Path $stateLock.StateRoot 'imports') `
        (([string]$Request.channel) + '-signed-candidate.v1\candidate')
    $manifestInput = Read-StrictProductionJsonFile `
        -Path (Join-Path $candidateRoot 'release-set.v2.json') `
        -Label "$Label Enterprise signed release manifest"
    [void](Assert-CanonicalProductionJsonInput `
        -Input $manifestInput `
        -Label "$Label Enterprise signed release manifest")
    if (-not $ExecuteTrustedInstaller) {
        return
    }
    $launcherArtifact = Get-InstallerSigningEvidenceFile `
        -Files @($manifestInput.Value.artifacts) `
        -Role launcher `
        -Label "$Label Enterprise manifest artifacts"
    $runtimeArtifact = Get-InstallerSigningEvidenceFile `
        -Files @($manifestInput.Value.artifacts) `
        -Role runtime `
        -Label "$Label Enterprise manifest artifacts"
    $manifestPayload = Get-InstallerSigningEvidenceFile `
        -Files @($Request.installerPayload.files) `
        -Role install-manifest `
        -Label "$Label Installer payload"
    $launcherPayload = Get-InstallerSigningEvidenceFile `
        -Files @($Request.installerPayload.files) `
        -Role launcher `
        -Label "$Label Installer payload"
    $runtimePayload = Get-InstallerSigningEvidenceFile `
        -Files @($Request.installerPayload.files) `
        -Role runtime `
        -Label "$Label Installer payload"
    $bootstrapperPayload = Get-InstallerSigningEvidenceFile `
        -Files @($Request.installerPayload.files) `
        -Role bootstrapper `
        -Label "$Label Installer payload"
    $arguments = @(
        '--production-payload-self-check',
        [string]$launcherArtifact.releaseId,
        [string]$runtimeArtifact.releaseId,
        [string]$manifestPayload.sha256,
        [string][int64]$manifestPayload.sizeBytes,
        [string]$launcherPayload.sha256,
        [string][int64]$launcherPayload.sizeBytes,
        [string]$runtimePayload.sha256,
        [string][int64]$runtimePayload.sizeBytes,
        [string]$bootstrapperPayload.sha256,
        [string][int64]$bootstrapperPayload.sizeBytes)
    $output = @(& $InstallerPath @arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code ${LASTEXITCODE}: $($output -join ' ')"
    }
    if ($output.Count -ne 1) {
        throw "$Label did not emit its one exact canonical JSON result."
    }
    $resultBytes = $utf8Strict.GetBytes([string]$output[0])
    $result = ConvertFrom-StrictProductionJsonBytes `
        -Bytes $resultBytes `
        -Label "$Label result"
    [void](Assert-ExactProductionJsonMembers `
        -Value $result `
        -Expected @(
            'schemaVersion',
            'resultType',
            'command',
            'status',
            'installerSha256',
            'launcherReleaseId',
            'runtimeReleaseId',
            'manifestSha256',
            'manifestSizeBytes',
            'launcherArchiveSha256',
            'launcherArchiveSizeBytes',
            'runtimeArchiveSha256',
            'runtimeArchiveSizeBytes',
            'bootstrapperSha256',
            'bootstrapperSizeBytes') `
        -Label "$Label result")
    $canonicalResultBytes = ConvertTo-ProductionJsonBytes -Value $result
    if ($canonicalResultBytes.Length -ne $resultBytes.Length -or
        (Get-ProductionSha256Bytes -Bytes $canonicalResultBytes) -cne
            (Get-ProductionSha256Bytes -Bytes $resultBytes) -or
        [int]$result.schemaVersion -ne 1 -or
        [string]$result.resultType -cne
            'ensou-dsh-enterprise-installer-production-payload-self-check' -or
        [string]$result.command -cne '--production-payload-self-check' -or
        [string]$result.status -cne 'VERIFIED' -or
        [string]$result.installerSha256 -cne
            [string]$SelfCheck.inspectedInstallerSha256 -or
        [string]$result.launcherReleaseId -cne
            [string]$launcherArtifact.releaseId -or
        [string]$result.runtimeReleaseId -cne
            [string]$runtimeArtifact.releaseId -or
        [string]$result.manifestSha256 -cne [string]$manifestPayload.sha256 -or
        [int64]$result.manifestSizeBytes -ne [int64]$manifestPayload.sizeBytes -or
        [string]$result.launcherArchiveSha256 -cne
            [string]$launcherPayload.sha256 -or
        [int64]$result.launcherArchiveSizeBytes -ne
            [int64]$launcherPayload.sizeBytes -or
        [string]$result.runtimeArchiveSha256 -cne [string]$runtimePayload.sha256 -or
        [int64]$result.runtimeArchiveSizeBytes -ne [int64]$runtimePayload.sizeBytes -or
        [string]$result.bootstrapperSha256 -cne [string]$bootstrapperPayload.sha256 -or
        [int64]$result.bootstrapperSizeBytes -ne [int64]$bootstrapperPayload.sizeBytes) {
        throw "$Label canonical result differs from the exact signed Installer and expected embedded payload."
    }
}

function Assert-EnterpriseInstallerSigningRequestStateClosure {
    param(
        [Parameter(Mandatory = $true)]$RequestInput,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][psobject]$State,
        [Parameter(Mandatory = $true)][string]$BaseHeadSha256,
        [Parameter(Mandatory = $true)][string]$BaseReceiptSha256,
        [Parameter(Mandatory = $true)][string]$SourceTree,
        [Parameter(Mandatory = $true)][string]$BundleRoot
    )

    $request = $RequestInput.Value
    if ([int]$request.schemaVersion -ne 2) {
        throw 'Enterprise Installer trusted build must produce signing request schema v2.'
    }
    [void](Assert-ExactProductionDirectoryInventory `
        -Path $BundleRoot `
        -Expected ([ordered]@{
            'installer-signing-request.v2.json' = $false
            'unsigned' = $true
            'payload' = $true
            'trusted-build' = $true
        }) `
        -Label 'Enterprise Installer trusted signing request bundle')
    $trustedBuildRoot = Join-Path $BundleRoot 'trusted-build'
    [void](Assert-ExactProductionDirectoryInventory `
        -Path $trustedBuildRoot `
        -Expected ([ordered]@{
            'trusted-build-evidence.v1.json' = $false
        }) `
        -Label 'Enterprise Installer trusted-build evidence bundle')
    $trustedBuildEvidenceInput = Read-StrictProductionJsonFile `
        -Path (Join-Path $trustedBuildRoot 'trusted-build-evidence.v1.json') `
        -SchemaPath $enterpriseInstallerTrustedBuildEvidenceSchemaPath `
        -Label 'Enterprise Installer trusted-build evidence'
    [void](Assert-CanonicalProductionJsonInput `
        -Input $trustedBuildEvidenceInput `
        -Label 'Enterprise Installer trusted-build evidence')
    $evidence = $trustedBuildEvidenceInput.Value
    if ([int64]$trustedBuildEvidenceInput.Bytes.LongLength -ne
            [int64]$request.trustedBuildEvidence.sizeBytes -or
        [string]$trustedBuildEvidenceInput.Sha256 -cne
            [string]$request.trustedBuildEvidence.sha256 -or
        [string]$evidence.sourceBuildInputs.inventorySha256 -cne
            [string]$request.sourceBuildInputSetSha256 -or
        [string]$evidence.buildExecution.targetBuildIdentitySha256 -cne
            [string]$request.buildExecution.targetBuildIdentitySha256 -or
        (Get-InstallerSigningObjectSha256 -Value $evidence.resourceBinding) -cne
            [string]$request.trustedBuildEvidence.resourceBindingSha256 -or
        [string]$evidence.toolchainLock.sdkFileClosureStatus -cne
            'VERIFIED' -or
        [string]$evidence.signingRequestEligibility.status -cne
            'ELIGIBLE_FOR_PILOT_SIGNING' -or
        [string]$evidence.signingRequestEligibility.productionAdmission -cne
            'NO_GO' -or
        [string]$evidence.signingRequestEligibility.blocker -cne
            'INSTALLER_SIGNING_RESPONSE_REQUIRED') {
        throw 'Enterprise Installer request does not carry its exact trusted-build evidence bytes and fail-closed closure.'
    }
    $expectedBasePhase = ([string]$Plan.targetChannel).ToUpperInvariant() +
        '_SIGNED_CANDIDATE_IMPORTED'
    if ([string]$request.planSha256 -cne [string]$State.Identity.planSha256 -or
        [string]$request.orchestrationId -cne [string]$Plan.orchestrationId -or
        [string]$request.edition -cne 'Enterprise' -or
        [string]$request.releaseSetId -cne [string]$Plan.releaseSetId -or
        [string]$request.channel -cne 'stable' -or
        [string]$request.sourceCommit -cne [string]$Plan.sourceCommit -or
        [string]$request.sourceTree -cne $SourceTree -or
        [int]$request.baseRevision -ne 5 -or
        [string]$request.basePhase -cne $expectedBasePhase -or
        [string]$request.baseHeadSha256 -cne $BaseHeadSha256 -or
        [string]$request.r5Evidence.headSha256 -cne $BaseHeadSha256 -or
        [string]$request.r5Evidence.receiptSha256 -cne
            $BaseReceiptSha256 -or
        [int]$request.responseAuthentication.maximumResponseAgeMinutes -ne
            [int]$Plan.authenticodePolicy.maximumResponseAgeMinutes) {
        throw 'Enterprise Installer-signing request differs from the exact plan, source tree, or r5 CAS head.'
    }

    [void](Assert-InstallerSigningRequestContract `
        -Request $request `
        -InstallerSigningTrust $Plan.externalResponseTrusts.installerSigning `
        -ReleaseManifestTrust $Plan.releaseManifestTrust)

    $r5Receipt = $State.Receipts[4]
    $r3Receipt = $State.Receipts[2]
    $candidateFiles = @($r5Receipt.data.files)
    if ((Get-InstallerSigningObjectSha256 -Value @($request.candidate.files)) -cne
            (Get-InstallerSigningObjectSha256 -Value $candidateFiles) -or
        [string]$request.r5Evidence.manifestPublishingRequestSha256 -cne
            [string]$State.Receipts[3].data.requestSha256 -or
        [string]$request.r5Evidence.manifestPublishingResponseSha256 -cne
            [string]$r5Receipt.data.responseSha256 -or
        [string]$request.r5Evidence.manifestSha256 -cne
            [string]$r5Receipt.data.manifestSha256 -or
        [string]$request.r5Evidence.releaseManifestTrustSha256 -cne
            [string]$r5Receipt.data.releaseManifestTrustSha256 -or
        [string]$request.r5Evidence.releaseCompatibilitySha256 -cne
            [string]$r5Receipt.data.releaseCompatibilitySha256) {
        throw 'Enterprise Installer-signing request does not preserve the exact r4/r5 candidate closure.'
    }

    $r3SignedClients = [Collections.Generic.List[object]]::new()
    foreach ($file in @($r3Receipt.data.files)) {
        $r3SignedClients.Add([ordered]@{
            role = [string]$file.role
            fileName = [string]$file.fileName
            relativePath = 'imports/client-signing.v1/signed/' +
                [string]$file.fileName
            sizeBytes = [int64]$file.sizeBytes
            sha256 = [string]$file.sha256
            peContentSha256 = [string]$file.peContentSha256
        })
    }
    $r3ReceiptPath = Join-Path `
        (Join-Path $State.StateRoot 'receipts') `
        '0003-client-signatures-imported.json'
    $r3ReceiptInput = Open-ProductionReleaseInput `
        -Path $r3ReceiptPath `
        -Label 'Enterprise r3 client-signature receipt' `
        -MaximumBytes 8MB
    try {
        if ([string]$request.r3Evidence.receiptSha256 -cne
                [string]$r3ReceiptInput.Sha256 -or
            (Get-InstallerSigningObjectSha256 -Value @($request.r3Evidence.signedClients)) -cne
                (Get-InstallerSigningObjectSha256 -Value @($r3SignedClients)) -or
            (Get-InstallerSigningObjectSha256 -Value @($request.r3Evidence.releaseManifestTrustProbes)) -cne
                (Get-InstallerSigningObjectSha256 -Value @($r3Receipt.data.releaseManifestTrustProbes))) {
            throw 'Enterprise Installer-signing request does not preserve the exact r3 signed-client closure.'
        }
    }
    finally {
        $r3ReceiptInput.Stream.Dispose()
    }

    $launcher = Get-InstallerSigningEvidenceFile `
        -Files $candidateFiles -Role launcher -Label 'Enterprise r5 candidate'
    $runtime = Get-InstallerSigningEvidenceFile `
        -Files $candidateFiles -Role runtime -Label 'Enterprise r5 candidate'
    $payloadRoot = Join-Path $BundleRoot 'payload'
    $payloadResult = EnterpriseProductionPayload\Test-EnterpriseProductionPayload `
        -PayloadDirectory $payloadRoot `
        -SignerSha256Thumbprint ([string]$Plan.authenticodePolicy.signerSha256Thumbprint) `
        -ExpectedLauncherArchiveSha256 ([string]$launcher.sha256) `
        -ExpectedRuntimeArchiveSha256 ([string]$runtime.sha256)
    $payloadByRole = @{}
    foreach ($file in @($request.installerPayload.files)) {
        $payloadByRole[[string]$file.role] = $file
        $payloadPath = Join-Path $payloadRoot ([string]$file.fileName)
        $payloadInput = Open-ProductionReleaseInput `
            -Path $payloadPath `
            -Label "Enterprise Installer payload role $($file.role)" `
            -MaximumBytes (8L * 1024 * 1024 * 1024)
        try {
            if ([int64]$payloadInput.SizeBytes -ne [int64]$file.sizeBytes -or
                [string]$payloadInput.Sha256 -cne [string]$file.sha256) {
                throw "Enterprise Installer payload role '$($file.role)' differs from the r6 request."
            }
        }
        finally {
            $payloadInput.Stream.Dispose()
        }
    }
    if ([string]$payloadByRole.launcher.sha256 -cne [string]$launcher.sha256 -or
        [string]$payloadByRole.runtime.sha256 -cne [string]$runtime.sha256 -or
        [string]$payloadResult.LauncherArchiveSha256 -cne [string]$launcher.sha256 -or
        [string]$payloadResult.RuntimeArchiveSha256 -cne [string]$runtime.sha256) {
        throw 'Enterprise Installer payload does not carry the exact r5 Launcher/runtime bytes.'
    }
    $installManifestInput = Read-StrictProductionJsonFile `
        -Path (Join-Path $payloadRoot 'enterprise-install-manifest.json') `
        -Label 'Enterprise Installer production payload manifest'
    [void](Assert-CanonicalProductionJsonInput `
        -Input $installManifestInput `
        -Label 'Enterprise Installer production payload manifest')
    if ([string]$installManifestInput.Value.publishedAtUtc -cne
        [string]$r5Receipt.data.completedAtUtc) {
        throw 'Enterprise Installer payload PublishedAtUtc must equal the authenticated r5 completion time.'
    }
}

function New-EnterpriseInstallerTrustedBuildForR6 {
    param(
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][psobject]$State,
        [Parameter(Mandatory = $true)][string]$BaseHeadSha256,
        [Parameter(Mandatory = $true)][string]$PayloadDirectory,
        [Parameter(Mandatory = $true)][string]$PackageDirectory,
        [Parameter(Mandatory = $true)][string]$DotNetSdkArchivePath,
        [Parameter(Mandatory = $true)][string]$OutputDirectory
    )

    $heldInputs = [Collections.Generic.List[object]]::new()
    try {
        $planInput = Open-ProductionReleaseInput `
            -Path (Join-Path $State.StateRoot 'plan.json') `
            -Label 'Trusted-build state plan' `
            -MaximumBytes 8MB
        Add-Member -InputObject $planInput -NotePropertyName Value `
            -NotePropertyValue $Plan
        $heldInputs.Add($planInput)
        if ([string]$planInput.Sha256 -cne [string]$State.Identity.planSha256) {
            throw 'Trusted-build state plan differs from the immutable state identity.'
        }

        $headInput = Open-ProductionReleaseInput `
            -Path (Join-Path $State.StateRoot 'head.json') `
            -Label 'Trusted-build r5 head' `
            -MaximumBytes 8MB
        Add-Member -InputObject $headInput -NotePropertyName Value `
            -NotePropertyValue $State.Head
        $heldInputs.Add($headInput)
        if ([string]$headInput.Sha256 -cne $BaseHeadSha256) {
            throw 'Trusted-build head changed after r5 CAS admission.'
        }

        $r5Input = Open-ProductionReleaseInput `
            -Path (Join-Path $State.StateRoot `
                'receipts\0005-stable-signed-candidate-imported.json') `
            -Label 'Trusted-build r5 receipt' `
            -MaximumBytes 8MB
        Add-Member -InputObject $r5Input -NotePropertyName Value `
            -NotePropertyValue $State.Receipts[4]
        $heldInputs.Add($r5Input)

        $r3Input = Open-ProductionReleaseInput `
            -Path (Join-Path $State.StateRoot `
                'receipts\0003-client-signatures-imported.json') `
            -Label 'Trusted-build r3 receipt' `
            -MaximumBytes 8MB
        Add-Member -InputObject $r3Input -NotePropertyName Value `
            -NotePropertyValue $State.Receipts[2]
        $heldInputs.Add($r3Input)

        $candidateFiles = @($State.Receipts[4].data.files)
        $launcher = Get-InstallerSigningEvidenceFile `
            -Files $candidateFiles `
            -Role launcher `
            -Label 'Trusted-build r5 candidate'
        $runtime = Get-InstallerSigningEvidenceFile `
            -Files $candidateFiles `
            -Role runtime `
            -Label 'Trusted-build r5 candidate'
        $payloadAdmission =
            EnterpriseProductionPayload\Test-EnterpriseProductionPayload `
                -PayloadDirectory $PayloadDirectory `
                -SignerSha256Thumbprint `
                    ([string]$Plan.authenticodePolicy.signerSha256Thumbprint) `
                -ExpectedLauncherArchiveSha256 ([string]$launcher.sha256) `
                -ExpectedRuntimeArchiveSha256 ([string]$runtime.sha256)

        $payloadInputs = [Collections.Generic.List[object]]::new()
        foreach ($definition in @(
                [pscustomobject]@{
                    Role = 'install-manifest'
                    FileName = 'enterprise-install-manifest.json'
                    MaximumBytes = 128KB
                },
                [pscustomobject]@{
                    Role = 'launcher'
                    FileName = 'launcher.zip'
                    MaximumBytes = 1GB
                },
                [pscustomobject]@{
                    Role = 'runtime'
                    FileName = 'runtime.zip'
                    MaximumBytes = 8GB
                },
                [pscustomobject]@{
                    Role = 'bootstrapper'
                    FileName = 'Ensou.Dsh.Enterprise.Bootstrapper.exe'
                    MaximumBytes = 512MB
                })) {
            $descriptor = Open-ProductionReleaseInput `
                -Path (Join-Path $PayloadDirectory $definition.FileName) `
                -Label "Trusted-build payload '$($definition.Role)'" `
                -MaximumBytes ([int64]$definition.MaximumBytes)
            $heldInputs.Add($descriptor)
            $payloadInputs.Add([pscustomobject]@{
                Role = [string]$definition.Role
                Descriptor = $descriptor
            })
        }

        $result =
            EnterpriseInstallerTrustedBuild\New-EnterpriseInstallerTrustedBuild `
                -PlanInput $planInput `
                -ProductionState $State `
                -BaseHeadInput $headInput `
                -R5ReceiptInput $r5Input `
                -R3ReceiptInput $r3Input `
                -PayloadInputs @($payloadInputs) `
                -PayloadAdmission $payloadAdmission `
                -PackageDirectory $PackageDirectory `
                -DotNetSdkArchivePath $DotNetSdkArchivePath `
                -OutputDirectory $OutputDirectory
        if ([string]$result.Status -cne 'SIGNING_REQUEST_READY_NO_GO' -or
            [string]$result.ProductionAdmission -cne 'NO_GO' -or
            [string]$result.Blocker -cne
                'INSTALLER_SIGNING_RESPONSE_REQUIRED') {
            $result.Dispose()
            throw 'Trusted builder returned an unsupported production admission state.'
        }
        return $result
    }
    finally {
        for ($index = $heldInputs.Count - 1; $index -ge 0; $index--) {
            $heldInputs[$index].Stream.Dispose()
        }
    }
}

function Get-InstallerSigningRequestReceiptData {
    param(
        [Parameter(Mandatory = $true)]$RequestInput,
        [Parameter(Mandatory = $true)][psobject]$State,
        [Parameter(Mandatory = $true)][string]$BaseReceiptSha256
    )

    $request = $RequestInput.Value
    $launcher = Get-InstallerSigningEvidenceFile `
        -Files @($State.Receipts[4].data.files) -Role launcher -Label 'Enterprise r5 candidate'
    $runtime = Get-InstallerSigningEvidenceFile `
        -Files @($State.Receipts[4].data.files) -Role runtime -Label 'Enterprise r5 candidate'
    return [ordered]@{
        evidenceType = 'INSTALLER_SIGNING_REQUESTED'
        requestSchemaVersion = 2
        requestRelativePath = 'requests/installer-signing.v2/installer-signing-request.v2.json'
        requestSha256 = [string]$RequestInput.Sha256
        baseHeadSha256 = [string]$request.baseHeadSha256
        baseReceiptSha256 = $BaseReceiptSha256
        sourceBuildInputSetSha256 = [string]$request.sourceBuildInputSetSha256
        targetBuildIdentitySha256 = [string]$request.buildExecution.targetBuildIdentitySha256
        payloadSetSha256 = [string]$request.installerPayload.inventorySha256
        r5LauncherSha256 = [string]$launcher.sha256
        r5RuntimeSha256 = [string]$runtime.sha256
        trustedBuildEvidenceRelativePath =
            'requests/installer-signing.v2/' +
            [string]$request.trustedBuildEvidence.relativePath
        trustedBuildEvidenceSha256 =
            [string]$request.trustedBuildEvidence.sha256
        resourceBindingSha256 =
            [string]$request.trustedBuildEvidence.resourceBindingSha256
        sdkFileClosureStatus =
            [string]$request.trustedBuildEvidence.sdkFileClosureStatus
        signingRequestEligibilityStatus = 'ELIGIBLE_FOR_PILOT_SIGNING'
        unsignedInstaller = [ordered]@{
            fileName = [string]$request.unsignedInstaller.fileName
            relativePath = 'requests/installer-signing.v2/' +
                [string]$request.unsignedInstaller.relativePath
            sizeBytes = [int64]$request.unsignedInstaller.sizeBytes
            sha256 = [string]$request.unsignedInstaller.sha256
            peContentSha256 = [string]$request.unsignedInstaller.peContentSha256
        }
        createdAtUtc = [string]$request.createdAtUtc
        expiresAtUtc = [string]$request.expiresAtUtc
        authenticationKeyId = [string]$request.responseAuthentication.keyId
        authenticationPurpose = 'installer-signing-response'
        admissionReason = 'INSTALLER_SIGNING_RESPONSE_REQUIRED'
        productionAdmission = 'NO_GO'
    }
}

function Get-InstallerSignatureImportReceiptData {
    param(
        [Parameter(Mandatory = $true)]$ResponseInput,
        [Parameter(Mandatory = $true)]$RequestInput,
        [Parameter(Mandatory = $true)][string]$R6HeadSha256,
        [Parameter(Mandatory = $true)][string]$R6ReceiptSha256,
        [Parameter(Mandatory = $true)][psobject]$R6ReceiptData
    )

    $response = $ResponseInput.Value
    $request = $RequestInput.Value
    $launcher = Get-InstallerSigningEvidenceFile `
        -Files @($request.candidate.files) -Role launcher -Label 'Enterprise r5 candidate'
    $runtime = Get-InstallerSigningEvidenceFile `
        -Files @($request.candidate.files) -Role runtime -Label 'Enterprise r5 candidate'
    $requestResourceBindingSha256 =
        [string]$request.trustedBuildEvidence.resourceBindingSha256
    if ([int]$R6ReceiptData.requestSchemaVersion -ne 2 -or
        [string]$R6ReceiptData.requestSha256 -cne [string]$RequestInput.Sha256 -or
        [string]$R6ReceiptData.r5LauncherSha256 -cne [string]$launcher.sha256 -or
        [string]$R6ReceiptData.r5RuntimeSha256 -cne [string]$runtime.sha256 -or
        [string]$R6ReceiptData.trustedBuildEvidenceSha256 -cne
            [string]$request.trustedBuildEvidence.sha256 -or
        [string]$R6ReceiptData.resourceBindingSha256 -cne
            $requestResourceBindingSha256 -or
        [string]$R6ReceiptData.sdkFileClosureStatus -cne
            'VERIFIED' -or
        [string]$R6ReceiptData.signingRequestEligibilityStatus -cne
            'ELIGIBLE_FOR_PILOT_SIGNING' -or
        [string]$R6ReceiptData.sourceBuildInputSetSha256 -cne
            [string]$request.sourceBuildInputSetSha256 -or
        [string]$R6ReceiptData.targetBuildIdentitySha256 -cne
            [string]$request.buildExecution.targetBuildIdentitySha256 -or
        [string]$R6ReceiptData.payloadSetSha256 -cne
            [string]$request.installerPayload.inventorySha256 -or
        [string]$R6ReceiptData.admissionReason -cne
            'INSTALLER_SIGNING_RESPONSE_REQUIRED' -or
        [string]$R6ReceiptData.productionAdmission -cne 'NO_GO') {
        throw 'Enterprise r7 cannot inherit a complete exact trusted-build source closure from r6.'
    }
    return [ordered]@{
        evidenceType = 'INSTALLER_SIGNATURE_IMPORTED'
        responseRelativePath = 'imports/installer-signing.v1/installer-signing-response.v1.json'
        responseSha256 = [string]$ResponseInput.Sha256
        requestSchemaVersion = 2
        requestSha256 = [string]$response.requestSha256
        admissionHeadSha256 = $R6HeadSha256
        r6ReceiptSha256 = $R6ReceiptSha256
        r5LauncherSha256 = [string]$launcher.sha256
        r5RuntimeSha256 = [string]$runtime.sha256
        trustedBuildEvidenceSha256 =
            [string]$R6ReceiptData.trustedBuildEvidenceSha256
        resourceBindingSha256 = [string]$R6ReceiptData.resourceBindingSha256
        sdkFileClosureStatus = [string]$R6ReceiptData.sdkFileClosureStatus
        signingRequestEligibilityStatus =
            [string]$R6ReceiptData.signingRequestEligibilityStatus
        sourceBuildInputSetSha256 =
            [string]$R6ReceiptData.sourceBuildInputSetSha256
        targetBuildIdentitySha256 =
            [string]$R6ReceiptData.targetBuildIdentitySha256
        payloadSetSha256 = [string]$R6ReceiptData.payloadSetSha256
        signedInstaller = [ordered]@{
            fileName = [string]$response.signedInstaller.fileName
            relativePath = 'imports/installer-signing.v1/' +
                [string]$response.signedInstaller.relativePath
            sizeBytes = [int64]$response.signedInstaller.sizeBytes
            sha256 = [string]$response.signedInstaller.sha256
            peContentSha256 = [string]$response.signedInstaller.peContentSha256
        }
        signerCertificateSha256 = [string]$response.authenticode.signerCertificateSha256
        timestampSignerCertificateSha256 =
            [string]$response.authenticode.timestampSignerCertificateSha256
        timestampProtocol = 'RFC3161'
        timestampUtc = [string]$response.authenticode.timestampUtc
        authenticationKeyId = [string]$response.authentication.keyId
        authenticationPurpose = 'installer-signing-response'
        completedAtUtc = [string]$response.completedAtUtc
        admissionReason = 'INSTALLER_SIGNING_RESPONSE_REQUIRED'
        productionAdmission = 'NO_GO'
    }
}

function Get-PersonalInstallerSigningRequestReceiptData {
    param(
        [Parameter(Mandatory = $true)]$RequestInput,
        [Parameter(Mandatory = $true)][psobject]$State,
        [Parameter(Mandatory = $true)][string]$BaseReceiptSha256
    )

    $request = $RequestInput.Value
    $bindings =
        PersonalInstallerSigningPipeline\Get-PersonalInstallerSigningRequestBindings `
            -Request $request
    $r5Files = @($State.Receipts[4].data.files)
    $r5 = [ordered]@{}
    foreach ($pair in @(
            [pscustomobject]@{ Name = 'r5ManifestSha256'; Role = 'release-manifest' },
            [pscustomobject]@{ Name = 'r5ClientBundleSha256'; Role = 'client-bundle' },
            [pscustomobject]@{ Name = 'r5RuntimeSha256'; Role = 'runtime' })) {
        $candidate = @(Get-InstallerSigningEvidenceFile `
            -Files $r5Files -Role $pair.Role -Label 'Personal r5 candidate')
        $payload = @(Get-InstallerSigningEvidenceFile `
            -Files @($request.payload.files) -Role $pair.Role `
            -Label 'Personal Installer payload')
        if ([string]$candidate.sha256 -cne [string]$payload.sha256) {
            throw "Personal r6 payload role '$($pair.Role)' differs from r5."
        }
        $r5[$pair.Name] = [string]$candidate.sha256
    }
    return [ordered]@{
        evidenceType = 'INSTALLER_SIGNING_REQUESTED'
        requestSchemaVersion = 2
        requestRelativePath =
            'requests/installer-signing.v2/installer-signing-request.v2.json'
        requestSha256 = [string]$RequestInput.Sha256
        baseHeadSha256 = [string]$request.baseHeadSha256
        baseReceiptSha256 = $BaseReceiptSha256
        sourceSha256 = [string]$bindings.sourceSha256
        payloadSha256 = [string]$bindings.payloadSha256
        compiledTrustSha256 = [string]$bindings.compiledTrustSha256
        toolchainSha256 = [string]$bindings.toolchainSha256
        buildExecutionSha256 = [string]$bindings.buildExecutionSha256
        resourceBindingSha256 = [string]$bindings.resourceBindingSha256
        trustedBuildEvidenceSha256 =
            [string]$bindings.trustedBuildEvidenceSha256
        admissionSha256 = [string]$bindings.admissionSha256
        r5ManifestSha256 = [string]$r5.r5ManifestSha256
        r5ClientBundleSha256 = [string]$r5.r5ClientBundleSha256
        r5RuntimeSha256 = [string]$r5.r5RuntimeSha256
        unsignedInstaller = [ordered]@{
            fileName = [string]$request.unsignedInstaller.fileName
            relativePath =
                'requests/installer-signing.v2/unsigned/' +
                    [string]$request.unsignedInstaller.fileName
            sizeBytes = [int64]$request.unsignedInstaller.sizeBytes
            sha256 = [string]$request.unsignedInstaller.sha256
            peContentSha256 = [string]$request.unsignedInstaller.peContentSha256
        }
        createdAtUtc = [string]$request.createdAtUtc
        expiresAtUtc = [string]$request.expiresAtUtc
        authenticationKeyId = [string]$request.responseAuthentication.keyId
        authenticationPurpose =
            'personal-installer-signing-response'
        authenticationPayloadType =
            'ensou-dsh-personal-installer-signing-response-authentication-v2'
        admissionReason = 'INSTALLER_SIGNING_RESPONSE_REQUIRED'
        productionAdmission = 'NO_GO'
    }
}

function Get-PersonalInstallerSignatureImportReceiptData {
    param(
        [Parameter(Mandatory = $true)]$ResponseInput,
        [Parameter(Mandatory = $true)]$RequestInput,
        [Parameter(Mandatory = $true)][string]$R6HeadSha256,
        [Parameter(Mandatory = $true)][string]$R6ReceiptSha256,
        [Parameter(Mandatory = $true)][psobject]$R6ReceiptData
    )

    $response = $ResponseInput.Value
    foreach ($bindingName in @(
            'sourceSha256', 'payloadSha256', 'compiledTrustSha256',
            'toolchainSha256', 'buildExecutionSha256',
            'resourceBindingSha256', 'trustedBuildEvidenceSha256',
            'admissionSha256')) {
        if ([string]$response.requestBindings.$bindingName -cne
            [string]$R6ReceiptData.$bindingName) {
            throw "Personal r7 response binding '$bindingName' differs from r6."
        }
    }
    return [ordered]@{
        evidenceType = 'INSTALLER_SIGNATURE_IMPORTED'
        responseRelativePath =
            'imports/installer-signing.v2/personal-installer-signing-response.v2.json'
        responseSha256 = [string]$ResponseInput.Sha256
        requestSchemaVersion = 2
        requestSha256 = [string]$RequestInput.Sha256
        admissionHeadSha256 = $R6HeadSha256
        r6ReceiptSha256 = $R6ReceiptSha256
        sourceSha256 = [string]$R6ReceiptData.sourceSha256
        payloadSha256 = [string]$R6ReceiptData.payloadSha256
        compiledTrustSha256 = [string]$R6ReceiptData.compiledTrustSha256
        toolchainSha256 = [string]$R6ReceiptData.toolchainSha256
        buildExecutionSha256 = [string]$R6ReceiptData.buildExecutionSha256
        resourceBindingSha256 = [string]$R6ReceiptData.resourceBindingSha256
        trustedBuildEvidenceSha256 =
            [string]$R6ReceiptData.trustedBuildEvidenceSha256
        admissionSha256 = [string]$R6ReceiptData.admissionSha256
        signedInstaller = [ordered]@{
            fileName = [string]$response.signedInstaller.fileName
            relativePath =
                'imports/installer-signing.v2/signed/' +
                    [string]$response.signedInstaller.fileName
            sizeBytes = [int64]$response.signedInstaller.sizeBytes
            sha256 = [string]$response.signedInstaller.sha256
            peContentSha256 = [string]$response.signedInstaller.peContentSha256
        }
        signerCertificateSha256 =
            [string]$response.authenticode.signerCertificateSha256
        timestampSignerCertificateSha256 =
            [string]$response.authenticode.timestampSignerCertificateSha256
        timestampProtocol = 'RFC3161'
        timestampUtc = [string]$response.authenticode.timestampUtc
        authenticationKeyId = [string]$response.authentication.keyId
        authenticationPurpose = 'personal-installer-signing-response'
        authenticationPayloadType =
            'ensou-dsh-personal-installer-signing-response-authentication-v2'
        payloadSelfCheckCanonicalJsonSha256 =
            [string]$response.payloadSelfCheck.canonicalJsonSha256
        completedAtUtc = [string]$response.completedAtUtc
        admissionReason = 'PERSONAL_SIGNED_WINDOWS_PILOT_REQUIRED'
        productionAdmission = 'NO_GO'
    }
}

function Invoke-PersonalPilotCompletedResultImport {
    param($Plan, $PlanInput, [string]$StateSchemaPath, $InitialState)
    if ([int]$InitialState.Head.revision -notin @(8,9)) { throw 'Personal completed result import requires r8 or an exact r9 retry.' }
    Assert-PersonalCompletedResultPathBoundary -ResultPath $PersonalFeedPromotionResultPath -CheckoutRoot $RepositoryRoot -StatePath $InitialState.StateRoot -PromotionPath $PromotionRoot
    $path = [IO.Path]::GetFullPath($PersonalFeedPromotionResultPath)
    if ([IO.Path]::GetFileName($path) -cne 'result.v1.json') { throw 'Personal result path must name result.v1.json in its complete evidence bundle.' }
    $root = [IO.Path]::GetDirectoryName($path)
    if ((Test-SameOrDescendantPath -Path $root -Root $InitialState.StateRoot) -or
        (Test-SameOrDescendantPath -Path $InitialState.StateRoot -Root $root)) { throw 'Personal external result and production state must be separate.' }
    $result = PersonalFeedPromotionResult\Open-PersonalFeedPromotionResult -BundleRoot $root
    $offline = $null; $writer = $null; $staging = $null; $stored = $null
    try {
        $r = $result.Result
        if ([int]$InitialState.Head.revision -eq 8) {
            if ($ExpectedHeadSha256 -cne $InitialState.HeadSha256 -or $r.sourceR8HeadSha256 -cne $ExpectedHeadSha256) { throw 'Personal result requires exact r8 CAS.' }
            $offline = ProductionFeedPromotion\Open-ProductionFeedPromotionBundleAdmission -PromotionRoot $PromotionRoot -ExpectedEdition Personal `
                -ExpectedPromotionHeadSha256 $r.promotionHeadSha256 -ExpectedBundleHeadSha256 $r.bundleHeadSha256 `
                -ExpectedSourceHeadSha256 $r.sourceR7HeadSha256 -ExpectedRequestSha256 $r.requestSha256 `
                -ExpectedResponseSha256 $r.authorizationSha256 -ExpectedBundleSetSha256 $r.bundleSetSha256
        }
        # External promotion lock precedes state writer lock, as in existing imports.
        $writer = Enter-ProductionReleaseStateLock -StateRoot $InitialState.StateRoot -PlanBytes $PlanInput.Bytes -Plan $Plan
        $state = Get-ProductionReleaseState -StateRoot $writer.StateRoot -StateSchemaPath $StateSchemaPath
        if ($state.HeadSha256 -cne $InitialState.HeadSha256) { throw 'Personal result source state changed before writer admission.' }
        $context = PersonalFeedPromotionResult\Get-PersonalFeedPromotionStateContext -StateRoot $state.StateRoot -Plan $Plan -Identity $state.Identity -IdentitySha256 $state.IdentitySha256 -Receipts $state.Receipts
        PersonalFeedPromotionResult\Assert-PersonalFeedPromotionResultBinding -Admission $result @context -Fresh:([int]$state.Head.revision -eq 8)
        if ([int]$state.Head.revision -eq 9) {
            if ($state.LastReceipt.data.sha256 -cne $result.Envelope.Sha256) { throw 'Personal result conflicts with the committed r9 replay.' }
            return Get-ProductionReleaseStateSummary -StateRoot $state.StateRoot -StateSchemaPath $StateSchemaPath
        }
        $staging = New-ProductionBundleStagingRoot -Root $state.StateRoot -Plan $Plan -Purpose 'pilot-feed-promotion'
        $bundle = Join-Path $staging.Root 'pilot-feed-result.v1'
        [void][IO.Directory]::CreateDirectory((Join-Path $bundle 'evidence'))
        Copy-ProductionLockedInputToCreateOnlyFile -LockedInput $result.Envelope -DestinationPath (Join-Path $bundle 'result.v1.json') -Label 'Authenticated Personal execution result'
        foreach ($role in $result.Files.Keys) {
            Copy-ProductionLockedInputToCreateOnlyFile -LockedInput $result.Files[$role] -DestinationPath (Join-Path (Join-Path $bundle 'evidence') $role) -Label "Completed Personal execution $role"
        }
        [void](Complete-ProductionBundleAfterCheckoutAdmission -Staging $staging -Plan $Plan -RelativeBundlePath 'pilot-feed-result.v1' -DestinationParent (Join-Path $state.StateRoot 'imports') -AllowExisting)
        $stored = PersonalFeedPromotionResult\Open-PersonalFeedPromotionResult -BundleRoot (Join-Path $state.StateRoot 'imports/pilot-feed-result.v1')
        if ($stored.Envelope.Sha256 -cne $result.Envelope.Sha256) { throw 'Stored Personal result conflicts with external result.' }
        $validate = {
            param([DateTimeOffset]$RecordedAtInstant)
            PersonalFeedPromotionResult\Assert-PersonalFeedPromotionResultBinding -Admission $result @context -Fresh
            PersonalFeedPromotionResult\Assert-PersonalFeedPromotionResultBinding -Admission $stored @context -Fresh
            foreach ($descriptor in $offline.HeldDescriptors) {
                ProductionReleaseState\Assert-ProductionReleaseInputStillLocked -Descriptor $descriptor -Label 'Authorized Personal offline bundle'
            }
        }.GetNewClosure()
        [void](ProductionReleaseState\Add-ProductionReleaseReceipt -StateRoot $state.StateRoot -StateSchemaPath $StateSchemaPath `
            -Phase 'PILOT_FEED_PROMOTED' -ExpectedPreviousPhase 'PILOT_PROMOTION_REQUESTED' -ExpectedHeadSha256 $ExpectedHeadSha256 `
            -Data ([ordered]@{evidenceType='PILOT_FEED_PROMOTED';relativePath='imports/pilot-feed-result.v1/result.v1.json';sha256=$stored.Envelope.Sha256}) -PreCommitValidation $validate)
        Get-ProductionReleaseStateSummary -StateRoot $state.StateRoot -StateSchemaPath $StateSchemaPath
    } finally {
        PersonalFeedPromotionResult\Close-PersonalFeedPromotionResult $stored
        if ($null -ne $staging) { Remove-ProductionBundleStagingRoot -Staging $staging }
        if ($null -ne $writer) { $writer.Stream.Dispose() }
        ProductionFeedPromotion\Close-ProductionFeedPromotionBundleAdmission $offline
        PersonalFeedPromotionResult\Close-PersonalFeedPromotionResult $result
    }
}

function Invoke-PersonalPilotFeedPromotionPhase {
    param(
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)]$PlanInput,
        [Parameter(Mandatory = $true)][string]$StateSchemaPath
    )

    $readLock = $null
    $initialState = $null
    try {
        $readLock = Enter-ProductionReleaseStateReadLock -StateRoot $StateRoot
        $initialState = Get-ProductionReleaseState `
            -StateRoot $readLock.StateRoot `
            -StateSchemaPath $StateSchemaPath
        $planSha256 = Get-ProductionSha256Bytes -Bytes $PlanInput.Bytes
        if ([int]$initialState.SchemaVersion -ne 2 -or
            [string]$initialState.Identity.edition -cne 'Personal' -or
            [string]$initialState.TargetChannel -cne 'pilot' -or
            [string]$initialState.Identity.planSha256 -cne $planSha256 -or
            [string]$initialState.Identity.orchestrationId -cne
                [string]$Plan.orchestrationId -or
            $null -eq $initialState.Head) {
            throw 'Personal Pilot promotion state conflicts with the supplied production plan.'
        }
        if ([int]$initialState.Head.revision -eq 9 -and
            [string]$initialState.Head.phase -ceq 'PILOT_FEED_PROMOTED' -and
            [string]::IsNullOrWhiteSpace($PersonalFeedPromotionResultPath)) {
            Get-ProductionReleaseStateSummary `
                -StateRoot $readLock.StateRoot -StateSchemaPath $StateSchemaPath
            return
        }
        if ([int]$initialState.Head.revision -notin @(7, 8, 9) -or
            [string]$initialState.Head.phase -notin @(
                'INSTALLER_SIGNATURE_IMPORTED',
                'PILOT_PROMOTION_REQUESTED', 'PILOT_FEED_PROMOTED')) {
            throw 'NO-GO: Personal Pilot Promote requires exact r7 Installer signature or its exact r8 promotion request.'
        }
    }
    finally {
        if ($null -ne $readLock) { $readLock.Stream.Dispose() }
    }

    if (-not [string]::IsNullOrWhiteSpace($PersonalFeedPromotionResultPath)) {
        Invoke-PersonalPilotCompletedResultImport -Plan $Plan -PlanInput $PlanInput -StateSchemaPath $StateSchemaPath -InitialState $initialState
        return
    }
    if ([string]::IsNullOrWhiteSpace($ExpectedHeadSha256) -or
        $ExpectedHeadSha256 -cne [string]$initialState.HeadSha256) {
        throw 'Personal Pilot Promote requires -ExpectedHeadSha256 for its exact current-state compare-and-swap.'
    }
    if ([string]::IsNullOrWhiteSpace($PromotionRoot) -or
        $ExpectedFeedIdentitySha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]::IsNullOrWhiteSpace($ExpectedChannelHead) -or
        [string]::IsNullOrWhiteSpace($ExpectedJournalHead)) {
        throw 'Personal Pilot Promote requires external PromotionRoot, feed identity, and both feed CAS expectations.'
    }
    $candidateRoot = Join-Path `
        (Join-Path (Join-Path $initialState.StateRoot 'imports') `
            'pilot-signed-candidate.v1') `
        'candidate'

    if ([int]$initialState.Head.revision -eq 8) {
        if ([string]::IsNullOrWhiteSpace($FeedPromotionResponsePath)) {
            throw 'NO-GO: Personal Pilot r8 has a sealed promotion request; import one authenticated external authorization response before execution.'
        }
        $promotionHeadInput = Open-ProductionReleaseInput `
            -Path (Join-Path ([IO.Path]::GetFullPath($PromotionRoot)) 'head.json') `
            -Label 'Personal Pilot external promotion CAS head' `
            -MaximumBytes 1MB
        try {
            $expectedPromotionHeadSha256 = [string]$promotionHeadInput.Sha256
        }
        finally {
            $promotionHeadInput.Stream.Dispose()
        }
        $import = ProductionFeedPromotion\Import-ProductionFeedPromotionResponse `
            -PromotionRoot $PromotionRoot `
            -SourceStateRoot $initialState.StateRoot `
            -CandidateRoot $candidateRoot `
            -ExposureRing pilot `
            -ResponsePath $FeedPromotionResponsePath `
            -ExpectedPromotionHeadSha256 $expectedPromotionHeadSha256 `
            -ExpectedSourcePlanSha256 ([string]$initialState.Identity.planSha256) `
            -ExpectedSourceIdentitySha256 ([string]$initialState.IdentitySha256) `
            -ExpectedSourceHeadSha256 ([string]$initialState.HeadSha256) `
            -AllowPersonalPilotPromotionRequestState
        return [pscustomobject]@{
            Phase = 'PILOT_PROMOTION_REQUESTED'
            ReleaseSetId = [string]$Plan.releaseSetId
            StateHeadSha256 = [string]$initialState.HeadSha256
            PromotionHeadSha256 = [string]$import.PromotionHeadSha256
            BundleHeadSha256 = [string]$import.BundleHeadSha256
            BundleSetSha256 = [string]$import.BundleSetSha256
            ProductionAdmission = 'NO_GO'
            NetworkPublishPerformed = $false
            NextAction = 'Execute the authorized Personal FeedPromoter operation and import its exact result receipt before r9.'
        }
    }

    $channelHead = ConvertFrom-StableFeedRawStateArgument `
        -Value $ExpectedChannelHead -Label 'Expected Personal Pilot channel head' `
        -MaximumBytes (512KB)
    $journalHead = ConvertFrom-StableFeedRawStateArgument `
        -Value $ExpectedJournalHead -Label 'Expected Personal Pilot journal head' `
        -MaximumBytes (128KB)
    $request = ProductionFeedPromotion\New-ProductionFeedPromotionRequest `
        -PromotionRoot $PromotionRoot `
        -SourceStateRoot $initialState.StateRoot `
        -CandidateRoot $candidateRoot `
        -ExposureRing pilot `
        -ExpectedChannelHead $channelHead `
        -ExpectedJournalHead $journalHead `
        -ExpectedFeedIdentitySha256 $ExpectedFeedIdentitySha256 `
        -ExpectedSourcePlanSha256 ([string]$initialState.Identity.planSha256) `
        -ExpectedSourceIdentitySha256 ([string]$initialState.IdentitySha256) `
        -ExpectedSourceHeadSha256 ([string]$initialState.HeadSha256)
    $requestInput = Open-ProductionReleaseInput `
        -Path ([string]$request.RequestPath) `
        -Label 'Personal Pilot external promotion request' `
        -MaximumBytes 1MB
    $stateLock = $null
    $staging = $null
    $stateRequestInput = $null
    try {
        if ([string]$requestInput.Sha256 -cne [string]$request.RequestSha256) {
            throw 'Personal Pilot external promotion request changed before state sealing.'
        }
        $stateLock = Enter-ProductionReleaseStateLock `
            -StateRoot $initialState.StateRoot `
            -PlanBytes $PlanInput.Bytes -Plan $Plan
        $writerState = Get-ProductionReleaseState `
            -StateRoot $stateLock.StateRoot -StateSchemaPath $StateSchemaPath
        if ($null -eq $writerState.Head -or
            [int]$writerState.Head.revision -ne 7 -or
            [string]$writerState.Head.phase -cne 'INSTALLER_SIGNATURE_IMPORTED' -or
            [string]$writerState.HeadSha256 -cne [string]$initialState.HeadSha256) {
            throw 'Personal Pilot r7 source changed before its promotion request could be sealed.'
        }
        $staging = New-ProductionBundleStagingRoot `
            -Root $writerState.StateRoot -Plan $Plan -Purpose 'pilot-feed-promotion'
        $stagedBundle = Join-Path $staging.Root 'pilot-feed-promotion.v1'
        [IO.Directory]::CreateDirectory($stagedBundle) | Out-Null
        Copy-ProductionLockedInputToCreateOnlyFile `
            -LockedInput $requestInput `
            -DestinationPath (Join-Path $stagedBundle 'request.v1.json') `
            -Label 'Personal Pilot promotion request'
        [void](Complete-ProductionBundleAfterCheckoutAdmission `
            -Staging $staging -Plan $Plan `
            -RelativeBundlePath 'pilot-feed-promotion.v1' `
            -DestinationParent (Join-Path $writerState.StateRoot 'requests') `
            -AllowExisting)
        $stateRequestInput = Open-ProductionReleaseInput `
            -Path (Join-Path (Join-Path $writerState.StateRoot `
                'requests\pilot-feed-promotion.v1') 'request.v1.json') `
            -Label 'Sealed Personal Pilot promotion request' `
            -MaximumBytes 1MB
        if ([string]$stateRequestInput.Sha256 -cne [string]$requestInput.Sha256 -or
            [int64]$stateRequestInput.SizeBytes -ne [int64]$requestInput.SizeBytes) {
            throw 'State-sealed Personal Pilot promotion request differs from its locked external request.'
        }
        $preCommitValidation = {
            param([DateTimeOffset]$RecordedAtInstant)
            Assert-ProductionReleaseInputStillLocked `
                -Descriptor $requestInput `
                -Label 'Personal Pilot external promotion request'
            Assert-ProductionReleaseInputStillLocked `
                -Descriptor $stateRequestInput `
                -Label 'Sealed Personal Pilot promotion request'
        }.GetNewClosure()
        [void](ProductionReleaseState\Add-ProductionReleaseReceipt `
            -StateRoot $writerState.StateRoot `
            -StateSchemaPath $StateSchemaPath `
            -Phase 'PILOT_PROMOTION_REQUESTED' `
            -ExpectedPreviousPhase 'INSTALLER_SIGNATURE_IMPORTED' `
            -ExpectedHeadSha256 ([string]$initialState.HeadSha256) `
            -Data ([ordered]@{
                evidenceType = 'PILOT_PROMOTION_REQUESTED'
                relativePath = 'requests/pilot-feed-promotion.v1/request.v1.json'
                sha256 = [string]$stateRequestInput.Sha256
            }) `
            -PreCommitValidation $preCommitValidation)
        Get-ProductionReleaseStateSummary `
            -StateRoot $writerState.StateRoot -StateSchemaPath $StateSchemaPath
    }
    finally {
        if ($null -ne $stateRequestInput) { $stateRequestInput.Stream.Dispose() }
        if ($null -ne $stateLock) { $stateLock.Stream.Dispose() }
        if ($null -ne $staging) { Remove-ProductionBundleStagingRoot -Staging $staging }
        $requestInput.Stream.Dispose()
    }
}

function Move-ExpiredEnterpriseStablePublication {
    param($Admission, $State, $Context, $Plan, [string]$StateSchemaPath)

    $expectedRoot = [IO.Path]::GetFullPath((Join-Path $State.StateRoot 'imports/stable-feed-result.v1'))
    if (-not $Admission.Root.Equals($expectedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Expired Stable publication does not name the exact canonical import.'
    }
    $current = Get-ProductionReleaseState -StateRoot $State.StateRoot -StateSchemaPath $StateSchemaPath
    if ($current.HeadSha256 -cne $State.HeadSha256 -or [int]$current.Head.revision -ne 9 -or
        $null -ne $current.OrphanReceipt) {
        throw 'Expired Stable publication cannot replace a committed or orphan transition.'
    }
    EnterpriseStablePublicationResult\Assert-EnterpriseStablePublicationBinding -Admission $Admission -ExpectedContext $Context -Plan $Plan
    $expires = ProductionReleaseState\ConvertFrom-ProductionUtc $Admission.Statement.expiresAtUtc 'Retained publication expiry'
    if ($expires -gt [DateTimeOffset]::UtcNow) { throw 'Only expired uncommitted publication evidence may be quarantined.' }
    $parent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($State.StateRoot))
    for ($item = Get-Item -LiteralPath $parent -Force; $null -ne $item; $item = $item.Parent) {
        if ($item -isnot [IO.DirectoryInfo] -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Expired publication quarantine parent crosses a filesystem link.'
        }
    }
    $destination = Join-Path $parent ('.ensou-launcher-production-expired-' +
        ([Guid]::Parse($Plan.orchestrationId)).ToString('N') + '-stable-feed-result-' + [Guid]::NewGuid().ToString('N'))
    $rootLease = @($Admission.DirectoryLeases | Where-Object { $_.Path.Equals($expectedRoot, [StringComparison]::OrdinalIgnoreCase) })
    if ($rootLease.Count -ne 1) { throw 'Expired publication requires one exact root-directory lease.' }
    $move = $null; $parentLease = $null; $parentAfter = $null
    try {
        $parentLease = Open-ProductionReleaseDirectoryLease -Path $parent -Label 'Expired publication quarantine parent'
        $move = Open-ProductionReleaseDirectoryMoveLease -Path $expectedRoot -Label 'Expired publication quarantine root'
        if ($move.VolumeSerialNumber -ne $rootLease[0].VolumeSerialNumber -or $move.FileIndex -ne $rootLease[0].FileIndex) {
            throw 'Expired publication quarantine handle changed identity.'
        }
        [void](Assert-LauncherSourceCheckout -Plan $Plan)
        EnterpriseStablePublicationResult\Assert-EnterpriseStablePublicationBinding -Admission $Admission -ExpectedContext $Context -Plan $Plan
        EnterpriseStablePublicationResult\Close-EnterpriseStablePublicationResult $Admission
        Assert-ProductionReleaseDirectoryStillLocked -Descriptor $parentLease -Label 'Expired publication quarantine parent'
        # A parent read lease denies share-write and blocks the child rename on
        # Windows. Retain the source move handle and recheck parent identity
        # immediately after this single create-only atomic operation.
        $parentLease.Handle.Dispose()
        [void](Move-ProductionReleaseDirectoryLease -Descriptor $move -DestinationPath $destination -Label 'Expired publication diagnostic quarantine')
        $parentAfter = Open-ProductionReleaseDirectoryLease -Path $parent -Label 'Expired publication quarantine parent recheck'
        if ($parentAfter.VolumeSerialNumber -ne $parentLease.VolumeSerialNumber -or $parentAfter.FileIndex -ne $parentLease.FileIndex) {
            throw 'Expired publication quarantine parent changed identity during the atomic move.'
        }
        Write-Warning "Expired uncommitted publication evidence retained for recovery at $destination"
    } finally {
        if ($null -ne $move) { $move.Handle.Dispose() }
        if ($null -ne $parentLease) { $parentLease.Handle.Dispose() }
        if ($null -ne $parentAfter) { $parentAfter.Handle.Dispose() }
    }
}

function Invoke-EnterpriseStableCompletedPublication {
    param($Plan, $PlanInput, [string]$StateSchemaPath, $InitialState)
    if (-not $EnterpriseStablePublicationResultBundlePath -and -not $EnterpriseStablePublicationContextPath) {
        Get-ProductionReleaseStateSummary -StateRoot $InitialState.StateRoot -StateSchemaPath $StateSchemaPath
        return
    }
    if ($ExpectedHeadSha256 -cne $InitialState.HeadSha256) { throw 'Stable publication requires exact current-state CAS.' }
    if ($EnterpriseStablePublicationContextPath) {
        if ([int]$InitialState.Head.revision -ne 9) { throw 'Publication context export requires the original r9 head.' }
        $read = Enter-ProductionReleaseStateReadLock -StateRoot $InitialState.StateRoot
        try {
            $state = Get-ProductionReleaseState -StateRoot $read.StateRoot -StateSchemaPath $StateSchemaPath
            if ($state.HeadSha256 -cne $ExpectedHeadSha256) { throw 'Publication context source state changed.' }
            $context = EnterpriseStablePublicationResult\Get-EnterpriseStablePublicationContext -StateRoot $state.StateRoot -Plan $Plan -Identity $state.Identity -IdentitySha256 $state.IdentitySha256 -Receipts $state.Receipts
            $destination = [IO.Path]::GetFullPath($EnterpriseStablePublicationContextPath)
            $parentLease = ProductionReleaseState\Open-ProductionReleaseDirectoryLease -Path ([IO.Path]::GetDirectoryName($destination)) -Label 'Publication context output parent'
            try {
                [byte[]]$bytes = ConvertTo-ProductionJsonBytes $context
                $stream = [IO.FileStream]::new($destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
                ProductionReleaseState\Assert-ProductionReleaseDirectoryStillLocked -Descriptor $parentLease -Label 'Publication context output parent'
            } finally { $parentLease.Handle.Dispose() }
            return [pscustomobject]@{Phase='STABLE_PROMOTION_REQUESTED';ContextPath=$destination;
                ContextSha256=(Get-ProductionSha256Bytes $bytes);ExpectedHeadSha256=$ExpectedHeadSha256;
                ProductionAdmission='NO_GO';NetworkPublishPerformed=$false;
                NextAction='After authorized Linux publication, run attest-publication using this exact context and import its authenticated result bundle.'}
        } finally { $read.Stream.Dispose() }
    }
    $result = EnterpriseStablePublicationResult\Open-EnterpriseStablePublicationResult -BundleRoot $EnterpriseStablePublicationResultBundlePath
    $writer = $null; $staging = $null; $stored = $null; $pilot = $null
    try {
        $writer = Enter-ProductionReleaseStateLock -StateRoot $InitialState.StateRoot -PlanBytes $PlanInput.Bytes -Plan $Plan
        $state = Get-ProductionReleaseState -StateRoot $writer.StateRoot -StateSchemaPath $StateSchemaPath
        if ($state.HeadSha256 -cne $ExpectedHeadSha256) { throw 'Stable publication source changed before writer admission.' }
        $context = EnterpriseStablePublicationResult\Get-EnterpriseStablePublicationContext -StateRoot $state.StateRoot -Plan $Plan -Identity $state.Identity -IdentitySha256 $state.IdentitySha256 -Receipts $state.Receipts
        $orphanRecordedAt = $null
        if ([int]$state.Head.revision -eq 9 -and $null -ne $state.OrphanReceipt) {
            $orphan = $state.OrphanReceipt
            if ([int]$orphan.revision -ne 10 -or $orphan.phase -cne 'STABLE_FEED_PROMOTED' -or
                $orphan.data.evidenceType -cne 'STABLE_FEED_PROMOTED' -or
                $orphan.data.relativePath -cne 'imports/stable-feed-result.v1/publication-result.v1.json' -or
                $orphan.data.sha256 -cne $result.Envelope.Sha256) {
                throw 'Stable publication result conflicts with its orphan r10 receipt.'
            }
            $orphanRecordedAt = ProductionReleaseState\ConvertFrom-ProductionUtc $orphan.recordedAtUtc 'Recovered Stable publication receipt time'
        }
        $admissionAt = if ($null -eq $orphanRecordedAt) { [DateTimeOffset]::UtcNow } else { $orphanRecordedAt }
        EnterpriseStablePublicationResult\Assert-EnterpriseStablePublicationBinding -Admission $result -ExpectedContext $context -Plan $Plan -Fresh:([int]$state.Head.revision -eq 9) -NowUtc $admissionAt
        if ([int]$state.Head.revision -eq 10) {
            if ($state.LastReceipt.data.sha256 -cne $result.Envelope.Sha256) { throw 'Stable publication result conflicts with the committed r10 replay.' }
            return Get-ProductionReleaseStateSummary -StateRoot $state.StateRoot -StateSchemaPath $StateSchemaPath
        }
        if ([int]$state.Head.revision -ne 9) { throw 'Stable publication can only advance exact r9.' }
        $pilot = Open-EnterprisePilotEvidenceBundleAdmission -BundleRoot (Join-Path $state.StateRoot 'imports/pilot-evidence.v1') -SchemaPath $enterprisePilotEvidenceInputSchemaPath -Plan $Plan -State $state -Label 'Stable publication Pilot evidence' -RequireCommittedR8Receipt -EnforceCurrentLifetime:($null -eq $orphanRecordedAt)
        $canonicalRoot = Join-Path $state.StateRoot 'imports/stable-feed-result.v1'
        if (Test-Path -LiteralPath $canonicalRoot) {
            $stored = EnterpriseStablePublicationResult\Open-EnterpriseStablePublicationResult -BundleRoot $canonicalRoot
            EnterpriseStablePublicationResult\Assert-EnterpriseStablePublicationBinding -Admission $stored -ExpectedContext $context -Plan $Plan
            if ($stored.Envelope.Sha256 -cne $result.Envelope.Sha256) {
                $oldExpiry = ProductionReleaseState\ConvertFrom-ProductionUtc $stored.Statement.expiresAtUtc 'Retained publication expiry'
                if ($null -ne $orphanRecordedAt -or $oldExpiry -gt [DateTimeOffset]::UtcNow) {
                    throw 'Fresh Stable publication result conflicts with retained evidence.'
                }
                Move-ExpiredEnterpriseStablePublication -Admission $stored -State $state -Context $context -Plan $Plan -StateSchemaPath $StateSchemaPath
            }
            EnterpriseStablePublicationResult\Close-EnterpriseStablePublicationResult $stored
            $stored = $null
        }
        $staging = New-ProductionBundleStagingRoot -Root $state.StateRoot -Plan $Plan -Purpose 'stable-feed-result'
        $bundle = Join-Path $staging.Root 'stable-feed-result.v1'
        [void][IO.Directory]::CreateDirectory((Join-Path $bundle 'evidence'))
        Copy-ProductionLockedInputToCreateOnlyFile -LockedInput $result.Envelope -DestinationPath (Join-Path $bundle 'publication-result.v1.json') -Label 'Authenticated Stable publication envelope'
        foreach ($role in $result.Files.Keys) {
            Copy-ProductionLockedInputToCreateOnlyFile -LockedInput $result.Files[$role] -DestinationPath (Join-Path (Join-Path $bundle 'evidence') $role) -Label "Stable publication $role"
        }
        $existingResult = Test-Path -LiteralPath (Join-Path $state.StateRoot 'imports/stable-feed-result.v1')
        [void](Complete-ProductionBundleAfterCheckoutAdmission -Staging $staging -Plan $Plan -RelativeBundlePath 'stable-feed-result.v1' -DestinationParent (Join-Path $state.StateRoot 'imports') -AllowExisting:$existingResult)
        $stored = EnterpriseStablePublicationResult\Open-EnterpriseStablePublicationResult -BundleRoot (Join-Path $state.StateRoot 'imports/stable-feed-result.v1')
        if ($stored.Envelope.Sha256 -cne $result.Envelope.Sha256) { throw 'Copied publication result conflicts with external evidence.' }
        if ($FaultPoint -ceq 'AfterStablePublicationBundle') { throw 'INJECTED-CRASH-AFTER-STABLE-PUBLICATION-BUNDLE' }
        $validate = {
            param([DateTimeOffset]$RecordedAtInstant)
            $effectiveAt = if ($null -eq $orphanRecordedAt) { $RecordedAtInstant } else { $orphanRecordedAt }
            EnterpriseStablePublicationResult\Assert-EnterpriseStablePublicationBinding -Admission $result -ExpectedContext $context -Plan $Plan -Fresh -NowUtc $effectiveAt
            EnterpriseStablePublicationResult\Assert-EnterpriseStablePublicationBinding -Admission $stored -ExpectedContext $context -Plan $Plan -Fresh -NowUtc $effectiveAt
            $current = Get-ProductionReleaseState -StateRoot $state.StateRoot -StateSchemaPath $StateSchemaPath
            if ($current.HeadSha256 -cne $ExpectedHeadSha256) { throw 'Stable publication lost its precommit CAS.' }
            $again = EnterpriseStablePublicationResult\Get-EnterpriseStablePublicationContext -StateRoot $current.StateRoot -Plan $Plan -Identity $current.Identity -IdentitySha256 $current.IdentitySha256 -Receipts $current.Receipts
            if ($null -ne $orphanRecordedAt -and ($null -eq $current.OrphanReceipt -or
                $current.OrphanReceipt.recordedAtUtc -cne $state.OrphanReceipt.recordedAtUtc -or
                $current.OrphanReceipt.transitionSha256 -cne $state.OrphanReceipt.transitionSha256)) {
                throw 'Stable publication orphan changed before recovery commit.'
            }
            EnterpriseStablePublicationResult\Assert-EnterpriseStablePublicationBinding -Admission $stored -ExpectedContext $again -Plan $Plan -Fresh -NowUtc $effectiveAt
            $freshPilot = Open-EnterprisePilotEvidenceBundleAdmission -BundleRoot (Join-Path $current.StateRoot 'imports/pilot-evidence.v1') -SchemaPath $enterprisePilotEvidenceInputSchemaPath -Plan $Plan -State $current -Label 'Stable publication precommit Pilot evidence' -RequireCommittedR8Receipt -EnforceCurrentLifetime:($null -eq $orphanRecordedAt)
            try {
                $pilotExpires = ProductionReleaseState\ConvertFrom-ProductionUtc $freshPilot.Input.Value.expiresAtUtc 'Stable publication Pilot expiry'
                $pilotCreated = ProductionReleaseState\ConvertFrom-ProductionUtc $freshPilot.Input.Value.createdAtUtc 'Stable publication Pilot creation'
                if ($effectiveAt -ge $pilotExpires -or $pilotCreated -gt $effectiveAt.AddMinutes(5)) {
                    throw 'Stable publication receipt falls outside its Pilot evidence lifetime.'
                }
            } finally { Close-ProductionBundleAdmission $freshPilot }
        }.GetNewClosure()
        [void](ProductionReleaseState\Add-ProductionReleaseReceipt -StateRoot $state.StateRoot -StateSchemaPath $StateSchemaPath -Phase 'STABLE_FEED_PROMOTED' -ExpectedPreviousPhase 'STABLE_PROMOTION_REQUESTED' -ExpectedHeadSha256 $ExpectedHeadSha256 `
            -Data ([ordered]@{evidenceType='STABLE_FEED_PROMOTED';relativePath='imports/stable-feed-result.v1/publication-result.v1.json';sha256=$stored.Envelope.Sha256}) -PreCommitValidation $validate -FaultAfterReceipt:($FaultPoint -ceq 'AfterStablePublicationReceipt'))
        Get-ProductionReleaseStateSummary -StateRoot $state.StateRoot -StateSchemaPath $StateSchemaPath
    } finally {
        Close-ProductionBundleAdmission $pilot
        EnterpriseStablePublicationResult\Close-EnterpriseStablePublicationResult $stored
        if ($null -ne $staging) { Remove-ProductionBundleStagingRoot -Staging $staging }
        if ($null -ne $writer) { $writer.Stream.Dispose() }
        EnterpriseStablePublicationResult\Close-EnterpriseStablePublicationResult $result
    }
}

function Invoke-EnterpriseStableFeedPromotionPhase {
    param(
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)]$PlanInput,
        [Parameter(Mandatory = $true)][string]$StateSchemaPath
    )

    $readLock = $null
    $initialPilotAdmission = $null
    $initialState = $null
    $stateBundleExists = $false
    $hadR9Orphan = $false
    try {
        $readLock = Enter-ProductionReleaseStateReadLock -StateRoot $StateRoot
        $initialState = Get-ProductionReleaseState `
            -StateRoot $readLock.StateRoot `
            -StateSchemaPath $StateSchemaPath
        $suppliedPlanSha256 = Get-ProductionSha256Bytes -Bytes $PlanInput.Bytes
        if ([int]$initialState.SchemaVersion -ne 2 -or
            [string]$initialState.Identity.edition -cne 'Enterprise' -or
            [string]$initialState.TargetChannel -cne 'stable' -or
            [string]$initialState.Identity.planSha256 -cne $suppliedPlanSha256 -or
            [string]$initialState.Identity.orchestrationId -cne
                [string]$Plan.orchestrationId) {
            throw 'Enterprise Stable promotion state conflicts with the supplied production plan.'
        }
        if ($null -eq $initialState.Head) {
            throw 'NO-GO: Enterprise Stable promotion requires committed r8 Pilot evidence.'
        }
        if (([int]$initialState.Head.revision -eq 9 -and $initialState.Head.phase -ceq 'STABLE_PROMOTION_REQUESTED') -or
            ([int]$initialState.Head.revision -eq 10 -and $initialState.Head.phase -ceq 'STABLE_FEED_PROMOTED')) {
            $readLock.Stream.Dispose(); $readLock = $null
            Invoke-EnterpriseStableCompletedPublication -Plan $Plan -PlanInput $PlanInput -StateSchemaPath $StateSchemaPath -InitialState $initialState
            return
        }
        if ([int]$initialState.Head.revision -ne 8 -or
            [string]$initialState.Head.phase -cne 'PILOT_EVIDENCE_BOUND') {
            throw 'NO-GO: Enterprise Stable promotion can only prepare the authenticated r9 offline bundle from exact r8 Pilot evidence.'
        }
        $hadR9Orphan = $null -ne $initialState.OrphanReceipt
        if ($hadR9Orphan -and
            ([int]$initialState.OrphanReceipt.revision -ne 9 -or
             [string]$initialState.OrphanReceipt.phase -cne
                'STABLE_PROMOTION_REQUESTED')) {
            throw 'Enterprise Stable promotion state contains a non-r9 orphan transition.'
        }
        $stateBundlePath = Join-Path `
            (Join-Path $readLock.StateRoot 'requests') `
            'stable-feed-promotion.v1'
        $stateBundleExists = Test-Path -LiteralPath $stateBundlePath
        $initialPilotAdmission = Open-EnterprisePilotEvidenceBundleAdmission `
            -BundleRoot (Join-Path $readLock.StateRoot `
                'imports\pilot-evidence.v1') `
            -SchemaPath $enterprisePilotEvidenceInputSchemaPath `
            -Plan $Plan `
            -State $initialState `
            -Label 'Enterprise Stable promotion Pilot-evidence admission' `
            -RequireCommittedR8Receipt `
            -EnforceCurrentLifetime:(-not $hadR9Orphan)
    }
    finally {
        Close-ProductionBundleAdmission -Admission $initialPilotAdmission
        if ($null -ne $readLock) { $readLock.Stream.Dispose() }
    }

    if ([string]::IsNullOrWhiteSpace($ExpectedHeadSha256)) {
        throw 'Enterprise Stable Promote requires -ExpectedHeadSha256 for its exact r8 compare-and-swap.'
    }
    if ($ExpectedHeadSha256 -cne [string]$initialState.HeadSha256) {
        throw 'Enterprise Stable Promote rejected a stale r8 production state head.'
    }

    $candidateRoot = Join-Path `
        (Join-Path (Join-Path $initialState.StateRoot 'imports') `
            'stable-signed-candidate.v1') `
        'candidate'
    $promotionRequest = $null
    $promotionImport = $null
    $externalAdmission = $null
    $localStateLock = $null
    $localStaging = $null
    $stagedAdmission = $null
    $canonicalAdmission = $null
    $pilotAdmission = $null
    try {
        if (-not $stateBundleExists) {
            if ([string]::IsNullOrWhiteSpace($PromotionRoot)) {
                throw 'Enterprise Stable Promote requires -PromotionRoot until its state-owned r9 bundle exists.'
            }
            if ($ExpectedFeedIdentitySha256 -cnotmatch '^[0-9a-f]{64}$') {
                throw 'Enterprise Stable Promote requires one exact -ExpectedFeedIdentitySha256.'
            }
            if ([string]::IsNullOrWhiteSpace($ExpectedChannelHead) -or
                [string]::IsNullOrWhiteSpace($ExpectedJournalHead)) {
                throw 'Enterprise Stable Promote requires both feed CAS arguments.'
            }
            $channelHead = ConvertFrom-StableFeedRawStateArgument `
                -Value $ExpectedChannelHead `
                -Label 'Expected Stable channel head' `
                -MaximumBytes (512KB)
            $journalHead = ConvertFrom-StableFeedRawStateArgument `
                -Value $ExpectedJournalHead `
                -Label 'Expected Stable journal head' `
                -MaximumBytes (128KB)

            $promotionRequest =
                ProductionFeedPromotion\New-ProductionFeedPromotionRequest `
                    -PromotionRoot $PromotionRoot `
                    -SourceStateRoot $initialState.StateRoot `
                    -CandidateRoot $candidateRoot `
                    -ExposureRing stable `
                    -ExpectedChannelHead $channelHead `
                    -ExpectedJournalHead $journalHead `
                    -ExpectedFeedIdentitySha256 $ExpectedFeedIdentitySha256 `
                    -ExpectedSourcePlanSha256 `
                        ([string]$initialState.Identity.planSha256) `
                    -ExpectedSourceIdentitySha256 `
                        ([string]$initialState.IdentitySha256) `
                    -ExpectedSourceHeadSha256 `
                        ([string]$initialState.HeadSha256)
            if ([string]::IsNullOrWhiteSpace($FeedPromotionResponsePath)) {
                $promotionRequest
                return
            }
            $promotionImport =
                ProductionFeedPromotion\Import-ProductionFeedPromotionResponse `
                    -PromotionRoot $PromotionRoot `
                    -SourceStateRoot $initialState.StateRoot `
                    -CandidateRoot $candidateRoot `
                    -ExposureRing stable `
                    -ResponsePath $FeedPromotionResponsePath `
                    -ExpectedPromotionHeadSha256 `
                        ([string]$promotionRequest.PromotionHeadSha256) `
                    -ExpectedSourcePlanSha256 `
                        ([string]$initialState.Identity.planSha256) `
                    -ExpectedSourceIdentitySha256 `
                        ([string]$initialState.IdentitySha256) `
                    -ExpectedSourceHeadSha256 `
                        ([string]$initialState.HeadSha256)
            $externalAdmission =
                ProductionFeedPromotion\Open-ProductionFeedPromotionBundleAdmission `
                    -PromotionRoot $PromotionRoot `
                    -ExpectedPromotionHeadSha256 `
                        ([string]$promotionImport.PromotionHeadSha256) `
                    -ExpectedBundleHeadSha256 `
                        ([string]$promotionImport.BundleHeadSha256) `
                    -ExpectedSourceHeadSha256 `
                        ([string]$initialState.HeadSha256) `
                    -ExpectedRequestSha256 `
                        ([string]$promotionRequest.RequestSha256) `
                    -ExpectedResponseSha256 `
                        ([string]$promotionImport.ResponseSha256) `
                    -ExpectedBundleSetSha256 `
                        ([string]$promotionImport.BundleSetSha256)

            $admissionValue = New-StableFeedPromotionStateAdmissionValue `
                -Plan $Plan `
                -SourceState $initialState `
                -ExternalAdmission $externalAdmission
            [byte[]]$admissionBytes = ConvertTo-ProductionJsonBytes `
                -Value $admissionValue
            [void](ConvertFrom-StrictProductionJsonBytes `
                -Bytes $admissionBytes `
                -Label 'Generated Stable feed-promotion state admission' `
                -SchemaPath $feedPromotionAdmissionSchemaPath)
            $admissionSha256 = Get-ProductionSha256Bytes -Bytes $admissionBytes

            $localStaging = New-ProductionBundleStagingRoot `
                -Root $initialState.StateRoot `
                -Plan $Plan `
                -Purpose 'stable-feed-promotion'
            $stagedBundleRoot = Join-Path `
                $localStaging.Root 'stable-feed-promotion.v1'
            [IO.Directory]::CreateDirectory($stagedBundleRoot) | Out-Null
            foreach ($copy in @(
                    [pscustomobject]@{
                        Name = 'request.v1.json'
                        Bytes = $externalAdmission.RequestInput.Bytes
                    },
                    [pscustomobject]@{
                        Name = 'response.v1.json'
                        Bytes = $externalAdmission.ResponseInput.Bytes
                    },
                    [pscustomobject]@{
                        Name = 'promotion-head.v1.json'
                        Bytes = $externalAdmission.PromotionHeadInput.Bytes
                    },
                    [pscustomobject]@{
                        Name = 'bundle-head.v1.json'
                        Bytes = $externalAdmission.BundleHeadInput.Bytes
                    },
                    [pscustomobject]@{
                        Name = 'promotion-admission.v1.json'
                        Bytes = $admissionBytes
                    })) {
                Write-ProductionStateFile `
                    -Path (Join-Path $stagedBundleRoot ([string]$copy.Name)) `
                    -Bytes ([byte[]]$copy.Bytes)
            }
            $stagedAdmission = Open-StableFeedPromotionStateBundleAdmission `
                -BundleRoot $stagedBundleRoot `
                -Plan $Plan `
                -ExpectedSourceHeadSha256 ([string]$initialState.HeadSha256) `
                -ExpectedAdmissionSha256 $admissionSha256 `
                -Label 'Staged Stable feed-promotion state bundle'
            $stagedPins = Get-ProductionBundleAdmissionPins `
                -Admission $stagedAdmission
            Wait-TestOnlyProductionCheckoutAdmission `
                -Staging $localStaging `
                -ExpectedFaultPoint `
                    'TestOnlyWaitBeforeStablePromotionCheckoutAdmission'
        }

        # The external promotion lock, when present, always precedes the state
        # writer. The external admission itself never reads or acquires state.
        $localStateLock = Enter-ProductionReleaseStateLock `
            -StateRoot $initialState.StateRoot `
            -PlanBytes $PlanInput.Bytes `
            -Plan $Plan
        $writerState = Get-ProductionReleaseState `
            -StateRoot $localStateLock.StateRoot `
            -StateSchemaPath $StateSchemaPath
        if ($null -eq $writerState.Head -or
            [int]$writerState.Head.revision -ne 8 -or
            [string]$writerState.Head.phase -cne 'PILOT_EVIDENCE_BOUND' -or
            [string]$writerState.HeadSha256 -cne
                [string]$initialState.HeadSha256) {
            throw 'Enterprise Stable r8 source changed before promotion-state commit.'
        }
        $writerHadR9Orphan = $null -ne $writerState.OrphanReceipt
        if ($writerHadR9Orphan -ne $hadR9Orphan) {
            throw 'Enterprise Stable r9 orphan state changed before promotion-state commit.'
        }
        $pilotAdmission = Open-EnterprisePilotEvidenceBundleAdmission `
            -BundleRoot (Join-Path $localStateLock.StateRoot `
                'imports\pilot-evidence.v1') `
            -SchemaPath $enterprisePilotEvidenceInputSchemaPath `
            -Plan $Plan `
            -State $writerState `
            -Label 'Enterprise Stable r9 Pilot-evidence admission' `
            -RequireCommittedR8Receipt `
            -EnforceCurrentLifetime:(-not $writerHadR9Orphan)

        if (-not $stateBundleExists) {
            $openFinalAdmission = {
                param($bundleRoot)
                Open-StableFeedPromotionStateBundleAdmission `
                    -BundleRoot $bundleRoot `
                    -Plan $Plan `
                    -ExpectedSourceHeadSha256 `
                        ([string]$initialState.HeadSha256) `
                    -ExpectedAdmissionSha256 $admissionSha256 `
                    -Label 'Canonical Stable feed-promotion state bundle'
            }.GetNewClosure()
            $publication = Complete-ValidatedProductionBundleAfterCheckoutAdmission `
                -Staging $localStaging `
                -Plan $Plan `
                -RelativeBundlePath 'stable-feed-promotion.v1' `
                -DestinationParent (Join-Path $localStateLock.StateRoot 'requests') `
                -PostWaitAdmission $stagedAdmission `
                -ExpectedPins $stagedPins `
                -OpenFinalAdmission $openFinalAdmission `
                -Label 'Stable feed-promotion state bundle' `
                -ExpectedPreMoveFaultPoint `
                    'TestOnlyWaitBeforeValidatedBundleAtomicMove'
            $stagedAdmission = $null
            $canonicalAdmission = $publication.Admission
            $stateBundleExists = $true
            if ($FaultPoint -ceq 'AfterStablePromotionStateBundle') {
                throw 'INJECTED-CRASH-AFTER-STABLE-PROMOTION-STATE-BUNDLE'
            }
            $writerState = Get-ProductionReleaseState `
                -StateRoot $localStateLock.StateRoot `
                -StateSchemaPath $StateSchemaPath
        }

        $admittedRevision = if ($null -eq $writerState.OrphanReceipt) { 8 } else { 9 }
        $admissionSummary =
            ProductionReleaseState\Assert-ProductionStableFeedPromotionAdmission `
                -StateRoot $localStateLock.StateRoot `
                -Plan $Plan `
                -Identity $writerState.Identity `
                -IdentitySha256 ([string]$writerState.IdentitySha256) `
                -Receipts $writerState.Receipts `
                -CommittedRevision 8 `
                -AdmittedRevision $admittedRevision
        if ($null -eq $canonicalAdmission) {
            $canonicalAdmission = Open-StableFeedPromotionStateBundleAdmission `
                -BundleRoot (Join-Path `
                    (Join-Path $localStateLock.StateRoot 'requests') `
                    'stable-feed-promotion.v1') `
                -Plan $Plan `
                -ExpectedSourceHeadSha256 `
                    ([string]$initialState.HeadSha256) `
                -ExpectedAdmissionSha256 ([string]$admissionSummary.Sha256) `
                -Label 'Recovered Stable feed-promotion state bundle'
        }

        $pilotExpiresAt = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$pilotAdmission.Input.Value.expiresAtUtc) `
            -Label 'Enterprise Stable r8 Pilot-evidence expiry'
        $pilotCreatedAt = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$pilotAdmission.Input.Value.createdAtUtc) `
            -Label 'Enterprise Stable r8 Pilot-evidence creation time'
        $responseCompletedAt = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$admissionSummary.Value.response.completedAtUtc) `
            -Label 'Enterprise Stable promotion authorization completion time'
        $requestExpiresAt = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$admissionSummary.Value.response.requestExpiresAtUtc) `
            -Label 'Enterprise Stable promotion authorization expiry'
        $orphanRecordedAt = $null
        if ($writerHadR9Orphan) {
            $orphanRecordedAt = ProductionReleaseState\ConvertFrom-ProductionUtc `
                -Value ([string]$writerState.OrphanReceipt.recordedAtUtc) `
                -Label 'Recovered Stable promotion r9 receipt time'
            if ($orphanRecordedAt -lt $responseCompletedAt -or
                $pilotCreatedAt -gt $orphanRecordedAt.AddMinutes(5) -or
                $orphanRecordedAt -ge $pilotExpiresAt -or
                $orphanRecordedAt -ge $requestExpiresAt) {
                throw 'Stable promotion r9 orphan was recorded after its authorization lifetime.'
            }
        }
        $receiptData = [ordered]@{
            evidenceType = 'STABLE_PROMOTION_REQUESTED'
            relativePath = [string]$admissionSummary.RelativePath
            sha256 = [string]$admissionSummary.Sha256
        }
        $preCommitValidation = {
            param([DateTimeOffset]$RecordedAtInstant)

            Assert-ProductionBundleAdmissionStillLocked `
                -Admission $canonicalAdmission `
                -Label 'Stable feed-promotion state bundle'
            Assert-ProductionBundleAdmissionStillLocked `
                -Admission $pilotAdmission `
                -Label 'Stable feed-promotion Pilot evidence'
            if ($null -ne $externalAdmission) {
                foreach ($descriptor in @($externalAdmission.HeldDescriptors)) {
                    ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                        -Descriptor $descriptor `
                        -Label 'External Stable feed-promotion bundle input'
                }
            }
            $effectiveRecordedAt = if ($null -ne $orphanRecordedAt) {
                $orphanRecordedAt
            }
            else {
                $RecordedAtInstant.ToUniversalTime()
            }
            if ($effectiveRecordedAt -lt $responseCompletedAt -or
                $pilotCreatedAt -gt $effectiveRecordedAt.AddMinutes(5) -or
                $effectiveRecordedAt -ge $pilotExpiresAt -or
                $effectiveRecordedAt -ge $requestExpiresAt) {
                throw 'Stable promotion r9 cannot be recorded after Pilot or authorization expiry.'
            }
        }.GetNewClosure()
        [void](ProductionReleaseState\Add-ProductionReleaseReceipt `
            -StateRoot $localStateLock.StateRoot `
            -StateSchemaPath $StateSchemaPath `
            -Phase 'STABLE_PROMOTION_REQUESTED' `
            -ExpectedPreviousPhase 'PILOT_EVIDENCE_BOUND' `
            -ExpectedHeadSha256 ([string]$initialState.HeadSha256) `
            -Data $receiptData `
            -PreCommitValidation $preCommitValidation `
            -FaultAfterReceipt:($FaultPoint -ceq
                'AfterStablePromotionReceipt'))
        Get-ProductionReleaseStateSummary `
            -StateRoot $localStateLock.StateRoot `
            -StateSchemaPath $StateSchemaPath
    }
    finally {
        Close-ProductionBundleAdmission -Admission $canonicalAdmission
        Close-ProductionBundleAdmission -Admission $stagedAdmission
        Close-ProductionBundleAdmission -Admission $pilotAdmission
        if ($null -ne $localStateLock) { $localStateLock.Stream.Dispose() }
        ProductionFeedPromotion\Close-ProductionFeedPromotionBundleAdmission `
            -Admission $externalAdmission
        if ($null -ne $localStaging) {
            Remove-ProductionBundleStagingRoot -Staging $localStaging
        }
    }
}

function New-StableFeedPromotionStateAdmissionValue {
    param(
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][psobject]$SourceState,
        [Parameter(Mandatory = $true)]$ExternalAdmission
    )

    $request = $ExternalAdmission.RequestInput.Value
    $response = $ExternalAdmission.ResponseInput.Value
    $bundleHead = $ExternalAdmission.BundleHeadInput.Value
    $files = [Collections.Generic.List[object]]::new()
    foreach ($file in @($ExternalAdmission.PayloadInputs)) {
        $files.Add([ordered]@{
            role = [string]$file.role
            fileName = [string]$file.fileName
            sizeBytes = [int64]$file.sizeBytes
            sha256 = [string]$file.sha256
        })
    }
    return [ordered]@{
        schemaVersion = 1
        evidenceType = 'STABLE_PROMOTION_REQUESTED'
        orchestrationId = [string]$Plan.orchestrationId
        edition = 'Enterprise'
        targetChannel = 'stable'
        exposureRing = 'stable'
        feedChannel = 'stable'
        publishScope = 'public-stable'
        releaseSetId = [string]$Plan.releaseSetId
        sourceState = [ordered]@{
            revision = 8
            phase = 'PILOT_EVIDENCE_BOUND'
            planSha256 = [string]$request.sourceState.planSha256
            identitySha256 = [string]$request.sourceState.identitySha256
            headSha256 = [string]$request.sourceState.headSha256
            r8ReceiptSha256 = [string]$SourceState.Head.receiptSha256
            receiptChainSha256 =
                [string]$request.sourceState.receiptChainSha256
            candidateReceiptSha256 =
                [string]$request.sourceState.candidateReceiptSha256
        }
        operationId = [string]$request.operationId
        feedFoundation = [ordered]@{
            expectedFeedIdentitySha256 =
                [string]$request.expectedFeedIdentitySha256
            expectedChannelHead = $request.feedCas.channelHead
            expectedJournalHead = $request.feedCas.journalHead
            feedCasSha256 = [string]$request.feedCasSha256
        }
        payloadSetSha256 = [string]$request.payloadSetSha256
        request = [ordered]@{
            fileName = 'request.v1.json'
            sizeBytes = [int64]$ExternalAdmission.RequestInput.Bytes.LongLength
            sha256 = [string]$ExternalAdmission.RequestInput.Sha256
        }
        response = [ordered]@{
            fileName = 'response.v1.json'
            sizeBytes = [int64]$ExternalAdmission.ResponseInput.Bytes.LongLength
            sha256 = [string]$ExternalAdmission.ResponseInput.Sha256
            keyId = [string]$response.authentication.keyId
            purpose = [string]$response.authentication.purpose
            payloadType = [string]$response.authentication.payloadType
            decision = [string]$response.decision
            completedAtUtc = [string]$response.completedAtUtc
            requestExpiresAtUtc = [string]$response.requestExpiresAtUtc
        }
        promotionHead = [ordered]@{
            fileName = 'promotion-head.v1.json'
            sizeBytes =
                [int64]$ExternalAdmission.PromotionHeadInput.Bytes.LongLength
            sha256 = [string]$ExternalAdmission.PromotionHeadInput.Sha256
        }
        bundleHead = [ordered]@{
            fileName = 'bundle-head.v1.json'
            sizeBytes = [int64]$ExternalAdmission.BundleHeadInput.Bytes.LongLength
            sha256 = [string]$ExternalAdmission.BundleHeadInput.Sha256
            bundleSetSha256 = [string]$bundleHead.bundleSetSha256
            status = [string]$bundleHead.status
        }
        files = @($files)
        productionAdmission = 'NO_GO'
        networkPublishPerformed = $false
    }
}

function Get-EnterpriseRevalidatedProductionStatus {
    param(
        [Parameter(Mandatory = $true)][psobject]$State,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][string]$ExpectedHeadSha256,
        [Parameter(Mandatory = $true)][string]$StateSchemaPath,
        [Parameter(Mandatory = $true)][string]$PilotAdapterPath,
        [Parameter(Mandatory = $true)][hashtable]$EvidencePaths,
        [ValidateSet(1, 2)][int]$WindowsPilotReadinessSchemaVersion = 1
    )

    # The caller retains the state read lock through this entire operation.
    # Component verification results never substitute for actual device rollout.
    if ([int]$State.SchemaVersion -ne 2 -or
        [string]$State.Identity.edition -cne 'Enterprise' -or
        [string]$State.TargetChannel -cne 'stable' -or
        $null -eq $State.Head -or [int]$State.Head.revision -notin @(8, 9, 10) -or
        $null -ne $State.OrphanReceipt -or
        $ExpectedHeadSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$State.HeadSha256 -cne $ExpectedHeadSha256) {
        throw 'ENTERPRISE_STATUS_REVALIDATION_STATE_REJECTED: Supply the exact committed Enterprise Stable r8, r9, or r10 head.'
    }
    $requiredPaths = @(
        'WindowsPilotEvidenceEnvelopePath', 'WindowsPilotEvidenceBodyPath',
        'WindowsPilotVerificationReportPath', 'WindowsPilotReadinessConfigPath',
        'WindowsPilotStoredReadinessReportPath', 'WindowsPilotReplayedReadinessReportPath',
        'LocalDataCertificationReceiptPath', 'StablePrivatePilotObservationPath',
        'PilotTrustPolicyPath')
    if ($EvidencePaths.Count -ne $requiredPaths.Count) {
        throw 'ENTERPRISE_STATUS_REVALIDATION_INPUTS_REQUIRED: Exactly nine original evidence paths are required.'
    }
    foreach ($name in $requiredPaths) {
        if (-not $EvidencePaths.ContainsKey($name) -or
            [string]::IsNullOrWhiteSpace([string]$EvidencePaths[$name])) {
            throw "ENTERPRISE_STATUS_REVALIDATION_INPUTS_REQUIRED: Missing '$name'."
        }
    }

    $clientResults = @(InstallerSigningContracts\Assert-ProductionClientSigningHistory `
        -State $State -Plan $Plan)
    if ($clientResults.Count -ne 1 -or
        [string]$clientResults[0].Status -cne 'CLIENT_SIGNING_HISTORY_REVALIDATED' -or
        [string]$clientResults[0].CurrentHeadSha256 -cne $ExpectedHeadSha256 -or
        [string]$clientResults[0].ResponseSha256 -cne [string]$State.Receipts[2].data.responseSha256 -or
        [int]$clientResults[0].VerifiedFileCount -ne 4) {
        throw 'ENTERPRISE_STATUS_CLIENT_REVALIDATION_REJECTED: Client-signing verification did not bind this exact state.'
    }
    $sourceResults = @(ProductionReleaseState\Assert-ProductionRuntimeSourceReleaseHistory `
        -State $State -Plan $Plan)
    if ($sourceResults.Count -ne 1 -or
        [string]$sourceResults[0].CurrentHeadSha256 -cne $ExpectedHeadSha256 -or
        [string]$sourceResults[0].Status -notin @(
            'RUNTIME_SOURCE_RELEASE_AUTHENTICATED',
            'IMMUTABLE_SOURCE_RELEASE_UNVERIFIED') -or
        $sourceResults[0].SourceReleaseVerified -isnot [bool] -or
        (([string]$sourceResults[0].Status -ceq
            'RUNTIME_SOURCE_RELEASE_AUTHENTICATED') -ne
            [bool]$sourceResults[0].SourceReleaseVerified)) {
        throw 'ENTERPRISE_STATUS_SOURCE_REVALIDATION_REJECTED: Runtime source-release history did not bind this exact state.'
    }
    $sourceReleaseVerified = [bool]$sourceResults[0].SourceReleaseVerified
    $pilotResults = @(& $PilotAdapterPath -StateRoot $State.StateRoot `
        -RevalidateOnly -ExpectedHeadSha256 $ExpectedHeadSha256 `
        -WindowsPilotReadinessSchemaVersion $WindowsPilotReadinessSchemaVersion @EvidencePaths)
    if ($pilotResults.Count -ne 1 -or
        [string]$pilotResults[0].Status -cne 'R8_EVIDENCE_REVALIDATED_NO_GO' -or
        [string]$pilotResults[0].ProductionAdmission -cne 'NO_GO' -or
        [string]$pilotResults[0].CurrentHeadSha256 -cne $ExpectedHeadSha256 -or
        [string]$pilotResults[0].PilotEvidenceInputSha256 -cne [string]$State.Receipts[7].data.sha256) {
        throw 'ENTERPRISE_STATUS_PILOT_REVALIDATION_REJECTED: Pilot verification did not bind this exact committed r8 evidence.'
    }
    $policyValidUntil = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$pilotResults[0].PolicyValidUntilUtc) -Label 'Revalidated Pilot policy deadline'

    # Replaying after both verifiers detects changed persisted bytes and also
    # reauthenticates any r9 authorization/r10 completed publication evidence.
    $summary = ProductionReleaseState\Get-ProductionReleaseStateSummary `
        -StateRoot $State.StateRoot -StateSchemaPath $StateSchemaPath
    if ([string]$summary.HeadSha256 -cne $ExpectedHeadSha256 -or
        [string]$summary.Edition -cne 'Enterprise' -or
        [string]$summary.TargetChannel -cne 'stable') {
        throw 'ENTERPRISE_STATUS_REVALIDATION_HEAD_CHANGED: Release state changed during revalidation.'
    }
    $completedAt = [DateTimeOffset]::UtcNow
    $expiry = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$summary.PilotEvidenceExpiresAtUtc) -Label 'Revalidated Pilot expiry'
    if ($completedAt -ge $expiry) {
        throw 'R8_BINDING_EXPIRED: Pilot evidence expired before the revalidated status could be returned.'
    }
    if ($completedAt -gt $policyValidUntil) {
        throw 'R8_EVIDENCE_POLICY_EXPIRED: Pilot evidence exceeded its maximum age or minimum remaining validity before status could be returned.'
    }
    $summary.PilotEvidenceStatus = 'REVALIDATED'
    $publicationRevalidated = [bool]$summary.LifecycleTerminal -and
        [int]$summary.Revision -eq 10 -and [string]$summary.Phase -ceq 'STABLE_FEED_PROMOTED'
    # The signed r5 response carries this only when its plan anchored the
    # immutable runtime source release. Local runtime hashes alone never count.
    $summary.StableReady = $publicationRevalidated -and $sourceReleaseVerified
    $summary | Add-Member -NotePropertyName ClientSigningEvidence -NotePropertyValue 'REVALIDATED'
    $summary | Add-Member -NotePropertyName RevalidatedReleaseEvidence -NotePropertyValue $true
    $summary | Add-Member -NotePropertyName RuntimeSourceAdmissionStatus -NotePropertyValue ([string]$sourceResults[0].Status)
    $summary | Add-Member -NotePropertyName ReadinessScope -NotePropertyValue 'AUTHENTICATED_RELEASE_STATE_ONLY'
    $summary | Add-Member -NotePropertyName EvidenceRevalidatedAtUtc -NotePropertyValue (
        ProductionReleaseState\ConvertTo-ProductionUtc -Value $completedAt)
    if ($publicationRevalidated) {
        $summary.FeedPublicationEvidence = 'AUTHENTICATED_COMPLETED_FEED_OPERATION_ONLY'
        $summary.NoGoCode = if ($sourceReleaseVerified) {
            # This is a read-only evidence scope, never a deployment decision
            # or a mutation of the committed productionAdmission=NO_GO state.
            'AUTHENTICATED_RELEASE_STATE_ONLY'
        }
        else { 'IMMUTABLE_SOURCE_RELEASE_UNVERIFIED' }
        $summary.NoGo = 'NO-GO: ' + $summary.NoGoCode
    }
    else {
        $summary.NoGoCode = if ([int]$summary.Revision -eq 8) {
            'STABLE_PROMOTION_REQUIRED'
        } else { 'STABLE_PUBLICATION_RESULT_REQUIRED' }
        $summary.NoGo = 'NO-GO: ' + $summary.NoGoCode
    }
    return $summary
}

if ($RevalidatePilotEvidence -and $Phase -cne 'Status') {
    throw 'ENTERPRISE_STATUS_REVALIDATION_PHASE_REJECTED: -RevalidatePilotEvidence is only valid with -Phase Status.'
}

Assert-ProductionCmdletBoundary
$codeBootstrap = Assert-LauncherCodeCheckoutBootstrap
$repositoryRootFull = [string]$codeBootstrap.Root
$stateModulePath = Join-Path $repositoryRootFull 'release\scripts\ProductionReleaseState.psm1'
$personalAdapterPath = Join-Path $repositoryRootFull 'release\scripts\PersonalProductionReleaseAdapter.psm1'
$enterpriseAdapterPath = Join-Path $repositoryRootFull 'release\scripts\EnterpriseProductionReleaseAdapter.psm1'
$enterprisePilotEvidenceAdapterPath = Join-Path `
    $repositoryRootFull `
    'release\scripts\New-EnterpriseProductionPilotEvidenceInput.ps1'
$installerSigningContractsPath = Join-Path $repositoryRootFull 'release\scripts\InstallerSigningContracts.psm1'
$personalInstallerTrustedBuildPath = Join-Path $repositoryRootFull 'release\scripts\PersonalInstallerTrustedBuild.psm1'
$personalInstallerSigningPipelinePath = Join-Path $repositoryRootFull 'release\scripts\PersonalInstallerSigningPipeline.psm1'
$enterpriseInstallerTrustedBuildPath = Join-Path $repositoryRootFull 'release\scripts\EnterpriseInstallerTrustedBuild.psm1'
$feedPromotionModulePath = Join-Path $repositoryRootFull 'release\scripts\ProductionFeedPromotion.psm1'
$enterpriseProductionPayloadPath = Join-Path $repositoryRootFull 'scripts\EnterpriseProductionPayload.psm1'
$metadataValidatorPath = Join-Path $repositoryRootFull 'release\scripts\Test-SourceRuntimeMetadata.ps1'
$schemaRoot = Join-Path $repositoryRootFull 'release\schemas'
$planSchemaV1Path = Join-Path $schemaRoot 'launcher-production-release-plan-v1.schema.json'
$planSchemaV2Path = Join-Path $schemaRoot 'launcher-production-release-plan-v2.schema.json'
$requestSchemaPath = Join-Path $schemaRoot 'launcher-external-signing-request-v1.schema.json'
$responseSchemaPath = Join-Path $schemaRoot 'launcher-external-signing-response-v1.schema.json'
$publisherInputSchemaPath = Join-Path $schemaRoot 'launcher-production-publisher-input-v1.schema.json'
$manifestRequestSchemaPath = Join-Path $schemaRoot 'launcher-manifest-publishing-request-v1.schema.json'
$manifestResponseSchemaPath = Join-Path $schemaRoot 'launcher-manifest-publishing-response-v1.schema.json'
$installerSigningRequestSchemaPath = Join-Path $schemaRoot 'launcher-installer-signing-request-v1.schema.json'
$installerSigningRequestSchemaV2Path = Join-Path $schemaRoot 'launcher-installer-signing-request-v2.schema.json'
$installerSigningResponseSchemaPath = Join-Path $schemaRoot 'launcher-installer-signing-response-v1.schema.json'
$personalInstallerSigningResponseSchemaPath = Join-Path `
    $schemaRoot 'personal-installer-signing-response-v2.schema.json'
$personalInstallerTrustedBuildEvidenceSchemaPath = Join-Path `
    $schemaRoot 'personal-installer-trusted-build-evidence-v1.schema.json'
$enterpriseInstallerTrustedBuildEvidenceSchemaPath = Join-Path $schemaRoot 'enterprise-installer-trusted-build-evidence-v1.schema.json'
$enterprisePilotEvidenceInputSchemaPath = Join-Path `
    $schemaRoot `
    'enterprise-production-pilot-evidence-input-v1.schema.json'
$releaseTrustProbeSchemaPath = Join-Path $schemaRoot 'launcher-release-manifest-trust-probe-v1.schema.json'
$feedPromotionRequestSchemaPath = Join-Path $schemaRoot 'launcher-feed-promotion-request-v1.schema.json'
$feedPromotionResponseSchemaPath = Join-Path $schemaRoot 'launcher-feed-promotion-response-v1.schema.json'
$feedPromotionStateSchemaPath = Join-Path $schemaRoot 'launcher-feed-promotion-state-v1.schema.json'
$feedPromotionAdmissionSchemaPath = Join-Path $schemaRoot 'launcher-feed-promotion-admission-v1.schema.json'
$stateSchemaV1Path = Join-Path $schemaRoot 'launcher-production-release-state-v1.schema.json'
$stateSchemaV2Path = Join-Path $schemaRoot 'launcher-production-release-state-v2.schema.json'
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force
Microsoft.PowerShell.Core\Import-Module $personalAdapterPath -Force
Microsoft.PowerShell.Core\Import-Module $enterpriseAdapterPath -Force
Microsoft.PowerShell.Core\Import-Module $installerSigningContractsPath -Force
Microsoft.PowerShell.Core\Import-Module $personalInstallerTrustedBuildPath -Force
Microsoft.PowerShell.Core\Import-Module $personalInstallerSigningPipelinePath -Force
Microsoft.PowerShell.Core\Import-Module $enterpriseProductionPayloadPath -Force
Microsoft.PowerShell.Core\Import-Module $enterpriseInstallerTrustedBuildPath -Force
Microsoft.PowerShell.Core\Import-Module $feedPromotionModulePath -Force
Microsoft.PowerShell.Core\Import-Module (Join-Path $repositoryRootFull 'release/scripts/PersonalFeedPromotionResult.psm1') -Force
Microsoft.PowerShell.Core\Import-Module (Join-Path $repositoryRootFull 'release/scripts/EnterpriseStablePublicationResult.psm1') -Force
# The Installer modules force-import both shared modules into private scopes.
# Re-import the contracts and then state last so the orchestrator's unqualified
# contract calls remain bound after PowerShell processes those nested imports.
Microsoft.PowerShell.Core\Import-Module $installerSigningContractsPath -Force
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force
$codeAdmission = ConvertTo-LauncherCodeLockedAdmission -Bootstrap $codeBootstrap

$admittedInputs = $null
$stateLock = $null
$bundleStaging = $null
$trustedBuildResult = $null
try {
    $planInput = Read-StrictProductionJsonFile -Path $PlanPath -Label 'Launcher production release plan'
    $schemaVersionProperty = $planInput.Value.PSObject.Properties['schemaVersion']
    if ($null -eq $schemaVersionProperty -or
        [int]$schemaVersionProperty.Value -notin @(1, 2)) {
        throw 'Launcher production release plan declares an unsupported schemaVersion.'
    }
    if ([int]$schemaVersionProperty.Value -eq 1 -and
        $Phase -cne 'Status') {
        throw 'NO-GO: launcher production release plan schemaVersion 1 is historical Status replay only; every mutating phase requires schemaVersion 2.'
    }
    $planSchemaPath = if ([int]$schemaVersionProperty.Value -eq 1) {
        $planSchemaV1Path
    }
    else {
        $planSchemaV2Path
    }
    $stateSchemaPath = if ([int]$schemaVersionProperty.Value -eq 1) {
        $stateSchemaV1Path
    }
    else {
        $stateSchemaV2Path
    }
    $plan = ConvertFrom-StrictProductionJsonBytes -Bytes $planInput.Bytes -Label 'Launcher production release plan' -SchemaPath $planSchemaPath
    $planInput.Value = $plan
    Assert-PlanSemanticContract -Plan $plan
    $sourceCheckout = $null
    if ($Phase -eq 'Status') {
        # Status is a read-only state replay. The currently admitted orchestrator
        # code must be clean and tracked, but an historical v1 plan necessarily
        # binds an older source commit. Every mutating phase still performs the
        # exact source-checkout admission below.
        Assert-ProductionExternalPathBoundary -Plan $plan -Root $repositoryRootFull
    }
    else {
        $sourceCheckout = Assert-LauncherSourceCheckout -Plan $plan
    }

    $newState = -not (Test-Path -LiteralPath ([IO.Path]::GetFullPath($StateRoot)))
    if ($newState -and $Phase -ne 'Prepare') {
        throw "NO-GO: phase '$Phase' cannot initialize a production state root; run Prepare first."
    }
    if ($Phase -eq 'Status') {
        $stateLock = Enter-ProductionReleaseStateReadLock -StateRoot $StateRoot
        $statusState = Get-ProductionReleaseState -StateRoot $stateLock.StateRoot -StateSchemaPath $stateSchemaPath
        $suppliedPlanSha256 = Get-ProductionSha256Bytes -Bytes $planInput.Bytes
        if ([string]$statusState.Identity.planSha256 -cne $suppliedPlanSha256 -or
            [string]$statusState.Identity.orchestrationId -cne [string]$plan.orchestrationId -or
            [string]$statusState.Identity.edition -cne [string]$plan.edition) {
            throw 'Existing production state identity conflicts with the supplied plan.'
        }
        if ($RevalidatePilotEvidence) {
            Get-EnterpriseRevalidatedProductionStatus -State $statusState -Plan $plan `
                -ExpectedHeadSha256 $ExpectedHeadSha256 -StateSchemaPath $stateSchemaPath `
                -WindowsPilotReadinessSchemaVersion $WindowsPilotReadinessSchemaVersion `
                -PilotAdapterPath $enterprisePilotEvidenceAdapterPath -EvidencePaths @{
                    WindowsPilotEvidenceEnvelopePath = $WindowsPilotEvidenceEnvelopePath
                    WindowsPilotEvidenceBodyPath = $WindowsPilotEvidenceBodyPath
                    WindowsPilotVerificationReportPath = $WindowsPilotVerificationReportPath
                    WindowsPilotReadinessConfigPath = $WindowsPilotReadinessConfigPath
                    WindowsPilotStoredReadinessReportPath = $WindowsPilotStoredReadinessReportPath
                    WindowsPilotReplayedReadinessReportPath = $WindowsPilotReplayedReadinessReportPath
                    LocalDataCertificationReceiptPath = $LocalDataCertificationReceiptPath
                    StablePrivatePilotObservationPath = $StablePrivatePilotObservationPath
                    PilotTrustPolicyPath = $PilotTrustPolicyPath
                }
        }
        else {
            Get-ProductionReleaseStateSummary -StateRoot $stateLock.StateRoot -StateSchemaPath $stateSchemaPath
        }
        return
    }

    if ($Phase -ceq 'Promote' -and
        [int]$plan.schemaVersion -eq 2 -and
        [string]$plan.edition -ceq 'Enterprise' -and
        [string]$plan.targetChannel -ceq 'stable') {
        Invoke-EnterpriseStableFeedPromotionPhase `
            -Plan $plan `
            -PlanInput $planInput `
            -StateSchemaPath $stateSchemaPath
        return
    }
    if ($Phase -ceq 'Promote' -and
        [int]$plan.schemaVersion -eq 2 -and
        [string]$plan.edition -ceq 'Personal' -and
        [string]$plan.targetChannel -ceq 'pilot') {
        Invoke-PersonalPilotFeedPromotionPhase `
            -Plan $plan `
            -PlanInput $planInput `
            -StateSchemaPath $stateSchemaPath
        return
    }

    $stateLock = Enter-ProductionReleaseStateLock `
        -StateRoot $StateRoot `
        -PlanBytes $planInput.Bytes `
        -Plan $plan
    if ($FaultPoint -ceq 'AfterInitializationRoot') {
        throw 'INJECTED-CRASH-AFTER-INITIALIZATION-ROOT'
    }
    if ($Phase -ne 'Prepare') {
        $completeInitialization =
            (Test-Path -LiteralPath (Join-Path $stateLock.StateRoot 'identity.json') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $stateLock.StateRoot 'plan.json') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $stateLock.StateRoot 'receipts') -PathType Container) -and
            (Test-Path -LiteralPath (Join-Path $stateLock.StateRoot 'requests') -PathType Container) -and
            (Test-Path -LiteralPath (Join-Path $stateLock.StateRoot 'imports') -PathType Container)
        if (-not $completeInitialization) {
            throw "NO-GO: phase '$Phase' cannot recover an incomplete production state root; run Prepare first."
        }
    }
    $initializationFaultPoint = if ($FaultPoint -in @(
            'AfterPlanPending',
            'AfterPlanSnapshot',
            'AfterIdentityPending',
            'AfterIdentity')) {
        $FaultPoint
    }
    else {
        ''
    }
    [void](Initialize-ProductionReleaseState `
        -Lock $stateLock `
        -PlanBytes $planInput.Bytes `
        -Plan $plan `
        -StateSchemaPath $stateSchemaPath `
        -FaultPoint $initializationFaultPoint)

    $state = Get-ProductionReleaseState -StateRoot $stateLock.StateRoot -StateSchemaPath $stateSchemaPath
    if ($Phase -eq 'Promote' -and
        [int]$state.SchemaVersion -eq 2 -and
        [string]$plan.edition -ceq 'Enterprise' -and
        [string]$plan.targetChannel -ceq 'stable' -and
        $null -ne $state.Head -and
        [int]$state.Head.revision -ge 8) {
        $promotionPilotAdmission = $null
        try {
            $promotionPilotRoot = Join-Path $stateLock.StateRoot `
                'imports\pilot-evidence.v1'
            $promotionPilotAdmission =
                Open-EnterprisePilotEvidenceBundleAdmission `
                    -BundleRoot $promotionPilotRoot `
                    -SchemaPath $enterprisePilotEvidenceInputSchemaPath `
                    -Plan $plan -State $state `
                    -Label 'Enterprise promotion Pilot-evidence bundle' `
                    -RequireCommittedR8Receipt `
                    -EnforceCurrentLifetime
        }
        finally {
            Close-ProductionBundleAdmission -Admission $promotionPilotAdmission
        }
    }
    if ($Phase -eq 'Promote' -or
        ($Phase -eq 'BindPilotEvidence' -and
         [string]$plan.edition -cne 'Enterprise') -or
        ($Phase -in @('PrepareInstallerSigning', 'ImportInstallerSignature') -and
         [int]$state.SchemaVersion -ne 2) -or
        ([int]$state.SchemaVersion -ne 2 -and
         $Phase -in @('PrepareManifestSigning', 'ImportSignedCandidate'))) {
        $allowedStageCodes = @(switch ($Phase) {
            'PrepareManifestSigning' { @('PILOT_MANIFEST_SIGNING_REQUESTED', 'STABLE_MANIFEST_SIGNING_REQUESTED') }
            'ImportSignedCandidate' { @('PILOT_SIGNED_CANDIDATE_IMPORTED', 'STABLE_SIGNED_CANDIDATE_IMPORTED') }
            'PrepareInstallerSigning' { @('INSTALLER_SIGNING_REQUESTED') }
            'ImportInstallerSignature' { @('INSTALLER_SIGNATURE_IMPORTED') }
            'BindPilotEvidence' { @('PILOT_EVIDENCE_BOUND') }
            'Promote' { @('PILOT_PROMOTION_REQUESTED', 'PILOT_FEED_PROMOTED', 'STABLE_PROMOTION_REQUESTED', 'STABLE_FEED_PROMOTED') }
        })
        $currentRevision = if ($null -eq $state.Head) { 0 } else { [int]$state.Head.revision }
        $nextLifecyclePhase = if ($currentRevision -lt [int]$state.Lifecycle.TerminalRevision) {
            [string]$state.Lifecycle.Transitions[$currentRevision].Phase
        }
        else {
            [string]$state.Lifecycle.TerminalPhase
        }
        $stageCode = if ($nextLifecyclePhase -in $allowedStageCodes) {
            $nextLifecyclePhase
        }
        elseif ([string]$state.TargetChannel -ceq 'stable' -and $currentRevision -ge 9) {
            [string]$allowedStageCodes[-1]
        }
        else {
            [string]$allowedStageCodes[0]
        }
        throw "NO-GO: PHASE_NOT_IMPLEMENTED_$stageCode; phase '$Phase' cannot mutate state until authenticated immutable external evidence and its purpose-specific adapter are bound."
    }
    if ($Phase -eq 'BindPilotEvidence') {
        if ([int]$state.SchemaVersion -ne 2 -or
            [string]$plan.edition -cne 'Enterprise' -or
            [string]$plan.targetChannel -cne 'stable' -or
            $null -eq $state.Head -or
            [int]$state.Head.revision -notin @(7, 8) -or
            [string]$state.Head.phase -notin @(
                'INSTALLER_SIGNATURE_IMPORTED',
                'PILOT_EVIDENCE_BOUND')) {
            throw 'NO-GO: Enterprise Pilot evidence can only be bound to one exact Stable r7 state.'
        }
        if ([int]$state.Head.revision -eq 8) {
            Get-ProductionReleaseStateSummary `
                -StateRoot $stateLock.StateRoot `
                -StateSchemaPath $stateSchemaPath
            return
        }
        if ([string]::IsNullOrWhiteSpace($ExpectedHeadSha256)) {
            throw 'BindPilotEvidence requires -ExpectedHeadSha256 for its exact r7 compare-and-swap.'
        }
        if ($ExpectedHeadSha256 -cne [string]$state.HeadSha256) {
            throw 'R8_BINDING_R7_HEAD_MISMATCH: BindPilotEvidence rejected a stale production state head before Pilot-evidence admission.'
        }

        $requiredPilotEvidencePaths = [ordered]@{
            WindowsPilotEvidenceEnvelopePath =
                $WindowsPilotEvidenceEnvelopePath
            WindowsPilotEvidenceBodyPath =
                $WindowsPilotEvidenceBodyPath
            WindowsPilotVerificationReportPath =
                $WindowsPilotVerificationReportPath
            WindowsPilotReadinessConfigPath =
                $WindowsPilotReadinessConfigPath
            WindowsPilotStoredReadinessReportPath =
                $WindowsPilotStoredReadinessReportPath
            WindowsPilotReplayedReadinessReportPath =
                $WindowsPilotReplayedReadinessReportPath
            LocalDataCertificationReceiptPath =
                $LocalDataCertificationReceiptPath
            StablePrivatePilotObservationPath =
                $StablePrivatePilotObservationPath
            PilotTrustPolicyPath = $PilotTrustPolicyPath
        }
        foreach ($entry in $requiredPilotEvidencePaths.GetEnumerator()) {
            if ([string]::IsNullOrWhiteSpace([string]$entry.Value)) {
                throw "BindPilotEvidence requires -$([string]$entry.Key)."
            }
        }

        $r7StateRoot = [string]$stateLock.StateRoot
        $stateLock.Stream.Dispose()
        $stateLock = $null
        $bundleStaging = New-ProductionBundleStagingRoot `
            -Root $r7StateRoot `
            -Plan $plan `
            -Purpose pilot-evidence-import
        $stagedPilotEvidenceRoot = Join-Path `
            (Join-Path ([string]$bundleStaging.Root) 'imports') `
            'pilot-evidence.v1'
        [IO.Directory]::CreateDirectory($stagedPilotEvidenceRoot) | Out-Null
        $stagedPilotEvidencePath = Join-Path `
            $stagedPilotEvidenceRoot `
            'pilot-evidence-input.v1.json'
        $adapterOutput = @(& $enterprisePilotEvidenceAdapterPath `
            -StateRoot $r7StateRoot `
            -ExpectedR7HeadSha256 $ExpectedHeadSha256 `
            -WindowsPilotReadinessSchemaVersion $WindowsPilotReadinessSchemaVersion `
            -WindowsPilotEvidenceEnvelopePath `
                $WindowsPilotEvidenceEnvelopePath `
            -WindowsPilotEvidenceBodyPath $WindowsPilotEvidenceBodyPath `
            -WindowsPilotVerificationReportPath `
                $WindowsPilotVerificationReportPath `
            -WindowsPilotReadinessConfigPath `
                $WindowsPilotReadinessConfigPath `
            -WindowsPilotStoredReadinessReportPath `
                $WindowsPilotStoredReadinessReportPath `
            -WindowsPilotReplayedReadinessReportPath `
                $WindowsPilotReplayedReadinessReportPath `
            -LocalDataCertificationReceiptPath `
                $LocalDataCertificationReceiptPath `
            -StablePrivatePilotObservationPath `
                $StablePrivatePilotObservationPath `
            -PilotTrustPolicyPath $PilotTrustPolicyPath `
            -OutputPath $stagedPilotEvidencePath)
        if ($adapterOutput.Count -ne 1 -or
            [string]$adapterOutput[0].Status -cne
                'PILOT_EVIDENCE_INPUT_READY_NO_GO' -or
            [string]$adapterOutput[0].ProductionAdmission -cne 'NO_GO' -or
            [string]$adapterOutput[0].NextRequiredGate -cne
                'PILOT_EVIDENCE_BOUND' -or
            -not [IO.Path]::GetFullPath(
                [string]$adapterOutput[0].OutputPath).Equals(
                    [IO.Path]::GetFullPath($stagedPilotEvidencePath),
                    [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Enterprise r8 adapter returned an unexpected result contract.'
        }

        $stagedPilotEvidenceInput = Read-StrictProductionJsonFile `
            -Path $stagedPilotEvidencePath `
            -Label 'Staged Enterprise Pilot-evidence input' `
            -SchemaPath $enterprisePilotEvidenceInputSchemaPath
        [void](Assert-CanonicalProductionJsonInput `
            -Input $stagedPilotEvidenceInput `
            -Label 'Staged Enterprise Pilot-evidence input')
        if ([string]$adapterOutput[0].OutputSha256 -cne
            [string]$stagedPilotEvidenceInput.Sha256) {
            throw 'Enterprise r8 adapter result digest differs from its staged output.'
        }

        $stateLock = Enter-ProductionReleaseStateLock `
            -StateRoot $r7StateRoot `
            -PlanBytes $planInput.Bytes `
            -Plan $plan
        $state = Get-ProductionReleaseState `
            -StateRoot $stateLock.StateRoot `
            -StateSchemaPath $stateSchemaPath
        $publishedPilotEvidenceRoot = Join-Path `
            (Join-Path $stateLock.StateRoot 'imports') `
            'pilot-evidence.v1'
        if ($null -ne $state.Head -and
            [int]$state.Head.revision -eq 8 -and
            [string]$state.Head.phase -ceq 'PILOT_EVIDENCE_BOUND') {
            Assert-ProductionBundleTreesEqual `
                -ExpectedRoot $stagedPilotEvidenceRoot `
                -ActualRoot $publishedPilotEvidenceRoot `
                -Label 'Exact Enterprise Pilot-evidence replay'
            $completedStaging = $bundleStaging
            $bundleStaging = $null
            Remove-ProductionBundleStagingRoot -Staging $completedStaging
            Get-ProductionReleaseStateSummary `
                -StateRoot $stateLock.StateRoot `
                -StateSchemaPath $stateSchemaPath
            return
        }
        if ($null -eq $state.Head -or
            [int]$state.Head.revision -ne 7 -or
            [string]$state.Head.phase -cne 'INSTALLER_SIGNATURE_IMPORTED' -or
            [string]$state.HeadSha256 -cne $ExpectedHeadSha256 -or
            ($null -ne $state.OrphanReceipt -and
             ([int]$state.OrphanReceipt.revision -ne 8 -or
              [string]$state.OrphanReceipt.phase -cne
                'PILOT_EVIDENCE_BOUND'))) {
            throw 'BindPilotEvidence lost its exact r7 compare-and-swap while the adapter was validating evidence.'
        }
        $pilotEvidenceAlreadyPublished =
            Test-Path -LiteralPath $publishedPilotEvidenceRoot
        $pendingHeadPath = Join-Path $stateLock.StateRoot 'head.json.pending'
        $hasUncommittedR8Ledger =
            $null -ne $state.OrphanReceipt -or
            (Test-Path -LiteralPath $pendingHeadPath)
        $pilotEvidenceData = [ordered]@{
            evidenceType = 'PILOT_EVIDENCE_BOUND'
            relativePath =
                'imports/pilot-evidence.v1/pilot-evidence-input.v1.json'
            sha256 = [string]$stagedPilotEvidenceInput.Sha256
        }
        $existingPilotAdmission = $null
        try {
            try {
                [void](ProductionReleaseState\Assert-EnterpriseProductionPilotEvidenceInputBinding `
                    -Input $stagedPilotEvidenceInput `
                    -Plan $plan `
                    -Identity $state.Identity `
                    -IdentitySha256 ([string]$state.IdentitySha256) `
                    -Receipts $state.Receipts `
                    -StateRoot $stateLock.StateRoot `
                    -ExpectedR7HeadSha256 $ExpectedHeadSha256 `
                    -EnforceCurrentLifetime)
            }
            catch {
                if ($_.Exception.Message.Contains(
                        'R8_BINDING_EXPIRED',
                        [StringComparison]::OrdinalIgnoreCase)) {
                    if ($hasUncommittedR8Ledger) {
                        throw 'NO-GO: R8_ORPHAN_LEDGER_RESTART_REQUIRED; retained r8 ledger evidence cannot be completed with expired Pilot evidence. Preserve this StateRoot and restart the release from its r7 baseline in a new StateRoot.'
                    }
                    if (-not $pilotEvidenceAlreadyPublished) {
                        throw
                    }
                    $existingPilotAdmission =
                        Open-EnterprisePilotEvidenceBundleAdmission `
                            -BundleRoot $publishedPilotEvidenceRoot `
                            -SchemaPath $enterprisePilotEvidenceInputSchemaPath `
                            -Plan $plan -State $state `
                            -ExpectedR7HeadSha256 $ExpectedHeadSha256 `
                            -Label 'Uncommitted Enterprise Pilot-evidence canonical bundle'
                    if ([string]$existingPilotAdmission.Input.Sha256 -ceq
                        [string]$stagedPilotEvidenceInput.Sha256) {
                        $quarantinePath =
                            Move-RejectedEnterprisePilotEvidenceCanonical `
                                -Admission $existingPilotAdmission `
                                -Plan $plan `
                                -StateRoot $stateLock.StateRoot `
                                -Label 'Expired Enterprise Pilot-evidence canonical'
                        $existingPilotAdmission = $null
                        throw "NO-GO: R8_BINDING_EXPIRED; the uncommitted canonical was identity-bound quarantined at '$quarantinePath'. Retry with nine fresh evidence inputs."
                    }
                }
                throw
            }
            if ($pilotEvidenceAlreadyPublished) {
                $existingPilotAdmission =
                    Open-EnterprisePilotEvidenceBundleAdmission `
                        -BundleRoot $publishedPilotEvidenceRoot `
                        -SchemaPath $enterprisePilotEvidenceInputSchemaPath `
                        -Plan $plan -State $state `
                        -ExpectedR7HeadSha256 $ExpectedHeadSha256 `
                        -Label 'Uncommitted Enterprise Pilot-evidence canonical bundle'
                if ([string]$existingPilotAdmission.Input.Sha256 -cne
                    [string]$stagedPilotEvidenceInput.Sha256) {
                    if ($hasUncommittedR8Ledger) {
                        throw 'NO-GO: R8_ORPHAN_LEDGER_RESTART_REQUIRED; the rebuilt nine-input Pilot evidence differs from the retained canonical and an uncommitted r8 receipt or pending head exists. Preserve this StateRoot and restart the release from its r7 baseline in a new StateRoot.'
                    }
                    $quarantinePath =
                        Move-RejectedEnterprisePilotEvidenceCanonical `
                            -Admission $existingPilotAdmission `
                            -Plan $plan `
                            -StateRoot $stateLock.StateRoot `
                            -Label 'Mismatched Enterprise Pilot-evidence canonical'
                    $existingPilotAdmission = $null
                    throw "NO-GO: R8_ORPHAN_CANONICAL_QUARANTINED; the rebuilt nine-input Pilot evidence differs from the uncommitted canonical. The retained diagnostic is '$quarantinePath'; retry with the same fresh inputs."
                }
            }
            if ($null -ne $state.OrphanReceipt -and
                ([int]$state.OrphanReceipt.revision -ne 8 -or
                 [string]$state.OrphanReceipt.phase -cne 'PILOT_EVIDENCE_BOUND' -or
                 (Get-InstallerSigningObjectSha256 `
                    -Value $state.OrphanReceipt.data) -cne
                 (Get-InstallerSigningObjectSha256 `
                    -Value $pilotEvidenceData))) {
                throw 'NO-GO: R8_ORPHAN_LEDGER_RESTART_REQUIRED; the rebuilt nine-input Pilot evidence differs from the uncommitted r8 receipt. Preserve this StateRoot and restart the release from its r7 baseline in a new StateRoot.'
            }
            if ($pilotEvidenceAlreadyPublished) {
                $existingPilotAdmission =
                    Add-ProductionBundlePublicationLease `
                        -Admission $existingPilotAdmission `
                        -Label 'Exact Enterprise Pilot-evidence crash-recovery canonical'
            }

            $preWaitAdmission = $null
            try {
                $preWaitAdmission = Open-EnterprisePilotEvidenceBundleAdmission `
                    -BundleRoot $stagedPilotEvidenceRoot `
                    -SchemaPath $enterprisePilotEvidenceInputSchemaPath `
                    -Plan $plan -State $state `
                    -ExpectedR7HeadSha256 $ExpectedHeadSha256 `
                    -Label 'Staged Enterprise Pilot-evidence bundle before wait' `
                    -EnforceCurrentLifetime
                if ([string]$preWaitAdmission.Input.Sha256 -cne
                    [string]$stagedPilotEvidenceInput.Sha256) {
                    throw 'Staged Enterprise Pilot evidence changed before checkout admission.'
                }
                $preWaitPins = Get-ProductionBundleAdmissionPins `
                    -Admission $preWaitAdmission
            }
            finally {
                Close-ProductionBundleAdmission -Admission $preWaitAdmission
            }
            Wait-TestOnlyProductionCheckoutAdmission `
                -Staging $bundleStaging `
                -ExpectedFaultPoint `
                    'TestOnlyWaitBeforePilotEvidenceCheckoutAdmission'
            $postWaitAdmission = Open-EnterprisePilotEvidenceBundleAdmission `
                -BundleRoot $stagedPilotEvidenceRoot `
                -SchemaPath $enterprisePilotEvidenceInputSchemaPath `
                -Plan $plan -State $state `
                -ExpectedR7HeadSha256 $ExpectedHeadSha256 `
                -Label 'Staged Enterprise Pilot-evidence bundle after wait' `
                -EnforceCurrentLifetime
            Assert-ProductionBundleAdmissionMatchesPins `
                -Admission $postWaitAdmission -Pins $preWaitPins `
                -Label 'Staged Enterprise Pilot-evidence bundle' `
                -RequireSameFileIdentity
            $postWaitPins = Get-ProductionBundleAdmissionPins `
                -Admission $postWaitAdmission
            $finalAdmission = $null
            try {
                if ($pilotEvidenceAlreadyPublished) {
                    Assert-ProductionBundleAdmissionStillLocked `
                        -Admission $existingPilotAdmission `
                        -Label 'Exact Enterprise Pilot-evidence crash-recovery canonical'
                    Assert-ProductionBundleAdmissionMatchesPins `
                        -Admission $postWaitAdmission `
                        -Pins (Get-ProductionBundleAdmissionPins `
                            -Admission $existingPilotAdmission) `
                        -Label 'Rebuilt Enterprise Pilot-evidence crash replay'
                    [void](ProductionReleaseState\Assert-EnterpriseProductionPilotEvidenceInputBinding `
                        -Input $existingPilotAdmission.Input `
                        -Plan $plan `
                        -Identity $state.Identity `
                        -IdentitySha256 ([string]$state.IdentitySha256) `
                        -Receipts $state.Receipts `
                        -StateRoot $stateLock.StateRoot `
                        -ExpectedR7HeadSha256 $ExpectedHeadSha256 `
                        -EnforceCurrentLifetime)
                    Close-ProductionBundleAdmission -Admission $postWaitAdmission
                    $postWaitAdmission = $null
                    $finalAdmission = $existingPilotAdmission
                    $existingPilotAdmission = $null
                }
                else {
                    $completion =
                        Complete-ValidatedProductionBundleAfterCheckoutAdmission `
                            -Staging $bundleStaging `
                            -Plan $plan `
                            -RelativeBundlePath 'imports\pilot-evidence.v1' `
                            -DestinationParent (Join-Path $stateLock.StateRoot 'imports') `
                            -PostWaitAdmission $postWaitAdmission `
                            -ExpectedPins $postWaitPins `
                            -Label 'Enterprise Pilot-evidence bundle' `
                            -ExpectedPreMoveFaultPoint `
                                'TestOnlyWaitBeforeValidatedBundleAtomicMove' `
                            -OpenFinalAdmission {
                                param($bundleRoot)
                                Open-EnterprisePilotEvidenceBundleAdmission `
                                    -BundleRoot $bundleRoot `
                                    -SchemaPath $enterprisePilotEvidenceInputSchemaPath `
                                    -Plan $plan -State $state `
                                    -ExpectedR7HeadSha256 $ExpectedHeadSha256 `
                                    -Label 'Final Enterprise Pilot-evidence bundle' `
                                    -EnforceCurrentLifetime
                            }
                    $postWaitAdmission = $null
                    $finalAdmission = $completion.Admission
                }
                $completedStaging = $bundleStaging
                $bundleStaging = $null
                Remove-ProductionBundleStagingRoot -Staging $completedStaging
                if ($FaultPoint -ceq 'AfterPilotEvidenceBundle') {
                    throw 'INJECTED-CRASH-AFTER-PILOT-EVIDENCE-BUNDLE'
                }
                Assert-ProductionBundleAdmissionStillLocked `
                    -Admission $finalAdmission `
                    -Label 'Final Enterprise Pilot-evidence bundle'
                [void](ProductionReleaseState\Assert-EnterpriseProductionPilotEvidenceInputBinding `
                    -Input $finalAdmission.Input `
                    -Plan $plan `
                    -Identity $state.Identity `
                    -IdentitySha256 ([string]$state.IdentitySha256) `
                    -Receipts $state.Receipts `
                    -StateRoot $stateLock.StateRoot `
                    -ExpectedR7HeadSha256 $ExpectedHeadSha256 `
                    -EnforceCurrentLifetime)
                if ($null -ne $state.OrphanReceipt -and
                    (Get-InstallerSigningObjectSha256 `
                        -Value $state.OrphanReceipt.data) -cne
                    (Get-InstallerSigningObjectSha256 `
                        -Value $pilotEvidenceData)) {
                    throw 'NO-GO: R8_ORPHAN_LEDGER_RESTART_REQUIRED; the uncommitted r8 receipt changed before final admission. Preserve this StateRoot and restart the release from its r7 baseline in a new StateRoot.'
                }
                $pilotPreCommitValidation = {
                    param([DateTimeOffset]$RecordedAtInstant)

                    Assert-ProductionBundleAdmissionStillLocked `
                        -Admission $finalAdmission `
                        -Label 'Final Enterprise Pilot-evidence precommit bundle'
                    [void](ProductionReleaseState\Assert-EnterpriseProductionPilotEvidenceInputBinding `
                        -Input $finalAdmission.Input `
                        -Plan $plan `
                        -Identity $state.Identity `
                        -IdentitySha256 ([string]$state.IdentitySha256) `
                        -Receipts $state.Receipts `
                        -StateRoot $stateLock.StateRoot `
                        -ExpectedR7HeadSha256 $ExpectedHeadSha256 `
                        -EnforceCurrentLifetime)
                    $preCommitCreatedAt =
                        ProductionReleaseState\ConvertFrom-ProductionUtc `
                            -Value ([string]$finalAdmission.Input.Value.createdAtUtc) `
                            -Label 'Enterprise r8 precommit creation time'
                    $preCommitExpiresAt =
                        ProductionReleaseState\ConvertFrom-ProductionUtc `
                            -Value ([string]$finalAdmission.Input.Value.expiresAtUtc) `
                            -Label 'Enterprise r8 precommit expiry time'
                    if ($preCommitCreatedAt -gt
                            $RecordedAtInstant.AddMinutes(5) -or
                        $preCommitExpiresAt -le $RecordedAtInstant) {
                        throw 'R8_BINDING_EXPIRED: Pilot evidence was not current at its exact receipt-recording instant.'
                    }
                }.GetNewClosure()
                $state = Add-ProductionReleaseReceipt `
                    -StateRoot $stateLock.StateRoot `
                    -StateSchemaPath $stateSchemaPath `
                    -Phase 'PILOT_EVIDENCE_BOUND' `
                    -ExpectedPreviousPhase 'INSTALLER_SIGNATURE_IMPORTED' `
                    -ExpectedHeadSha256 $ExpectedHeadSha256 `
                    -Data $pilotEvidenceData `
                    -PreCommitValidation $pilotPreCommitValidation `
                    -FaultAfterReceipt:($FaultPoint -ceq
                        'AfterPilotEvidenceReceipt')
                Assert-ProductionBundleAdmissionStillLocked `
                    -Admission $finalAdmission `
                    -Label 'Final Enterprise Pilot-evidence bundle'
                $summary = Get-ProductionReleaseStateSummary `
                    -StateRoot $stateLock.StateRoot `
                    -StateSchemaPath $stateSchemaPath
                Assert-ProductionBundleAdmissionStillLocked `
                    -Admission $finalAdmission `
                    -Label 'Final Enterprise Pilot-evidence bundle'
                $summary
                return
            }
            catch {
                if ($_.Exception.Message.Contains(
                        'R8_BINDING_EXPIRED',
                        [StringComparison]::OrdinalIgnoreCase)) {
                    if ($hasUncommittedR8Ledger) {
                        throw 'NO-GO: R8_ORPHAN_LEDGER_RESTART_REQUIRED; retained r8 ledger evidence expired during final admission. Preserve this StateRoot and restart the release from its r7 baseline in a new StateRoot.'
                    }
                    if ($null -ne $finalAdmission -and
                        [string]$finalAdmission.Input.Sha256 -ceq
                            [string]$stagedPilotEvidenceInput.Sha256) {
                        $quarantinePath =
                            Move-RejectedEnterprisePilotEvidenceCanonical `
                                -Admission $finalAdmission `
                                -Plan $plan `
                                -StateRoot $stateLock.StateRoot `
                                -Label 'Late-expired Enterprise Pilot-evidence canonical'
                        $finalAdmission = $null
                        throw "NO-GO: R8_BINDING_EXPIRED; the late-expired canonical was identity-bound quarantined at '$quarantinePath'. Retry with nine fresh evidence inputs."
                    }
                }
                throw
            }
            finally {
                Close-ProductionBundleAdmission -Admission $finalAdmission
                Close-ProductionBundleAdmission -Admission $postWaitAdmission
            }
        }
        catch {
            if ($_.Exception.Message.Contains(
                    'R8_BINDING_EXPIRED',
                    [StringComparison]::OrdinalIgnoreCase)) {
                if ($hasUncommittedR8Ledger) {
                    throw 'NO-GO: R8_ORPHAN_LEDGER_RESTART_REQUIRED; retained r8 ledger evidence expired during checkout admission. Preserve this StateRoot and restart the release from its r7 baseline in a new StateRoot.'
                }
                if ($null -ne $existingPilotAdmission -and
                    [string]$existingPilotAdmission.Input.Sha256 -ceq
                        [string]$stagedPilotEvidenceInput.Sha256) {
                    $quarantinePath =
                        Move-RejectedEnterprisePilotEvidenceCanonical `
                            -Admission $existingPilotAdmission `
                            -Plan $plan `
                            -StateRoot $stateLock.StateRoot `
                            -Label 'Checkout-expired Enterprise Pilot-evidence canonical'
                    $existingPilotAdmission = $null
                    throw "NO-GO: R8_BINDING_EXPIRED; the checkout-expired canonical was identity-bound quarantined at '$quarantinePath'. Retry with nine fresh evidence inputs."
                }
            }
            throw
        }
        finally {
            Close-ProductionBundleAdmission -Admission $existingPilotAdmission
        }
    }
    if ($Phase -eq 'Prepare') {
        if ($null -eq $state.Head) {
            if ($null -eq $admittedInputs) {
                $admittedInputs = Open-AndAdmitPlanInputs -Plan $plan -Root $stateLock.StateRoot
            }
            $sourceCheckout = Assert-LauncherSourceCheckout -Plan $plan
            $planData = Get-PlanAdmissionData `
                -Plan $plan `
                -SourceCheckout $sourceCheckout `
                -RuntimeMetadata $admittedInputs.RuntimeMetadata
            $state = Add-ProductionReleaseReceipt -StateRoot $stateLock.StateRoot -StateSchemaPath $stateSchemaPath -Phase 'PLAN_ADMITTED' -ExpectedPreviousPhase $null -ExpectedHeadSha256 '' -Data $planData -FaultAfterReceipt:($FaultPoint -ceq 'AfterPlanReceipt')
        }
        if ([string]$state.Head.phase -ceq 'PLAN_ADMITTED') {
            $requestBundlePath = Join-Path (Join-Path $stateLock.StateRoot 'requests') 'client-signing.v1'
            $requestPath = Join-Path $requestBundlePath 'signing-request.v1.json'
            $createRequest = -not (Test-Path -LiteralPath $requestPath)
            if ($null -eq $admittedInputs -and $createRequest) {
                $admittedInputs = Open-AndAdmitPlanInputs -Plan $plan -Root $stateLock.StateRoot
            }
            $snapshots = if ($null -eq $admittedInputs) { $null } else { $admittedInputs.ClientSnapshots }
            $requestRoot = $stateLock.StateRoot
            if ($createRequest) {
                $bundleStaging = New-ProductionBundleStagingRoot `
                    -Root $stateLock.StateRoot `
                    -Plan $plan `
                    -Purpose request
                $requestRoot = [string]$bundleStaging.Root
            }
            $requestInput = Get-RequestBundle -Root $requestRoot -Plan $plan -ClientSnapshots $snapshots
            $requestData = Get-RequestReceiptData -RequestInput $requestInput
            if ($null -ne $bundleStaging) {
                Wait-TestOnlyProductionCheckoutAdmission `
                    -Staging $bundleStaging `
                    -ExpectedFaultPoint 'TestOnlyWaitBeforeRequestCheckoutAdmission'
                # Re-read every generated byte after the optional test rendezvous.
                # This is the last potentially long bundle operation before the
                # exact checkout admission and same-volume atomic publication.
                $requestInput = Get-RequestBundle `
                    -Root ([string]$bundleStaging.Root) `
                    -Plan $plan `
                    -ClientSnapshots $null
                $requestData = Get-RequestReceiptData -RequestInput $requestInput
            }
            if ($null -ne $bundleStaging) {
                [void](Complete-ProductionBundleAfterCheckoutAdmission `
                    -Staging $bundleStaging `
                    -Plan $plan `
                    -RelativeBundlePath 'requests\client-signing.v1' `
                    -DestinationParent (Join-Path $stateLock.StateRoot 'requests'))
                $completedStaging = $bundleStaging
                $bundleStaging = $null
                Remove-ProductionBundleStagingRoot -Staging $completedStaging
                if ($FaultPoint -ceq 'AfterRequestFile') {
                    throw 'INJECTED-CRASH-AFTER-REQUEST-FILE'
                }
            }
            else {
                # Crash recovery reuses an already published exact request. It
                # still needs a last source admission before the receipt write.
                [void](Assert-LauncherSourceCheckout -Plan $plan)
            }
            $state = Add-ProductionReleaseReceipt -StateRoot $stateLock.StateRoot -StateSchemaPath $stateSchemaPath -Phase 'CLIENT_SIGNING_REQUESTED' -ExpectedPreviousPhase 'PLAN_ADMITTED' -ExpectedHeadSha256 ([string]$state.HeadSha256) -Data $requestData -FaultAfterReceipt:($FaultPoint -ceq 'AfterClientRequestReceipt')
        }
        elseif ([string]$state.Head.phase -notin @('CLIENT_SIGNING_REQUESTED', 'CLIENT_SIGNATURES_IMPORTED')) {
            throw "NO-GO: Prepare cannot continue from state phase '$($state.Head.phase)'."
        }
        Get-ProductionReleaseStateSummary -StateRoot $stateLock.StateRoot -StateSchemaPath $stateSchemaPath
        return
    }

    if ($Phase -eq 'ImportClientSignatures') {
        if ($null -eq $state.Head -or
            [string]$state.Head.phase -notin @('CLIENT_SIGNING_REQUESTED', 'CLIENT_SIGNATURES_IMPORTED')) {
            throw 'NO-GO: client signatures can only be imported after CLIENT_SIGNING_REQUESTED.'
        }
        if ([string]$state.Head.phase -ceq 'CLIENT_SIGNING_REQUESTED') {
            if ([string]::IsNullOrWhiteSpace($ExpectedHeadSha256)) {
                throw 'ImportClientSignatures requires -ExpectedHeadSha256 for state compare-and-swap.'
            }
            if ([string]$state.HeadSha256 -cne $ExpectedHeadSha256) {
                throw 'ImportClientSignatures rejected a stale production state head before external response admission.'
            }
        }
        $requestInput = Get-RequestBundle -Root $stateLock.StateRoot -Plan $plan -ClientSnapshots $null
        $bundleStaging = New-ProductionBundleStagingRoot `
            -Root $stateLock.StateRoot `
            -Plan $plan `
            -Purpose import
        $import = Import-ClientSigningResponse `
            -Root ([string]$bundleStaging.Root) `
            -Plan $plan `
            -RequestInput $requestInput `
            -Path $ResponsePath
        $importData = Get-ImportReceiptData -Import $import
        Wait-TestOnlyProductionCheckoutAdmission `
            -Staging $bundleStaging `
            -ExpectedFaultPoint 'TestOnlyWaitBeforeImportCheckoutAdmission'
        Assert-ImportedProductionBundle `
            -Root ([string]$bundleStaging.Root) `
            -Plan $plan `
            -Import $import
        $publishedImportPath = Join-Path (Join-Path $stateLock.StateRoot 'imports') 'client-signing.v1'
        $importAlreadyPublished = Test-Path -LiteralPath $publishedImportPath
        if ($importAlreadyPublished) {
            # A prior injected crash may have atomically published the complete
            # bundle before the receipt. Bind it to the exact revalidated bytes.
            Assert-ImportedProductionBundle `
                -Root $stateLock.StateRoot `
                -Plan $plan `
                -Import $import
        }
        [void](Complete-ProductionBundleAfterCheckoutAdmission `
            -Staging $bundleStaging `
            -Plan $plan `
            -RelativeBundlePath 'imports\client-signing.v1' `
            -DestinationParent (Join-Path $stateLock.StateRoot 'imports') `
            -AllowExisting:$importAlreadyPublished)
        $completedStaging = $bundleStaging
        $bundleStaging = $null
        Remove-ProductionBundleStagingRoot -Staging $completedStaging
        if ($FaultPoint -ceq 'AfterImportSnapshot') {
            throw 'INJECTED-CRASH-AFTER-IMPORT-SNAPSHOT'
        }
        if ([string]$state.Head.phase -ceq 'CLIENT_SIGNATURES_IMPORTED') {
            $state = Add-ProductionReleaseReceipt -StateRoot $stateLock.StateRoot -StateSchemaPath $stateSchemaPath -Phase 'CLIENT_SIGNATURES_IMPORTED' -ExpectedPreviousPhase 'CLIENT_SIGNING_REQUESTED' -ExpectedHeadSha256 $ExpectedHeadSha256 -Data $importData
        }
        else {
            $state = Add-ProductionReleaseReceipt -StateRoot $stateLock.StateRoot -StateSchemaPath $stateSchemaPath -Phase 'CLIENT_SIGNATURES_IMPORTED' -ExpectedPreviousPhase 'CLIENT_SIGNING_REQUESTED' -ExpectedHeadSha256 $ExpectedHeadSha256 -Data $importData -FaultAfterReceipt:($FaultPoint -ceq 'AfterImportReceipt')
        }
        Get-ProductionReleaseStateSummary -StateRoot $stateLock.StateRoot -StateSchemaPath $stateSchemaPath
        return
    }

    if ($Phase -eq 'PrepareManifestSigning') {
        $manifestChannelContract = Get-ProductionManifestChannelContract `
            -TargetChannel ([string]$plan.targetChannel)
        if ([int]$state.SchemaVersion -ne 2 -or
            $null -eq $state.Head -or
            [string]$state.Head.phase -notin @(
                'CLIENT_SIGNATURES_IMPORTED',
                [string]$manifestChannelContract.RequestPhase)) {
            throw 'NO-GO: target-channel manifest signing can only be requested after the typed v2 client-signature import.'
        }
        $baseHeadSha256 = if ([string]$state.Head.phase -ceq
            'CLIENT_SIGNATURES_IMPORTED') {
            [string]$state.HeadSha256
        }
        else {
            [string]$state.LastReceipt.data.baseHeadSha256
        }
        if ([string]::IsNullOrWhiteSpace($ExpectedHeadSha256)) {
            throw 'PrepareManifestSigning requires -ExpectedHeadSha256 for its exact r3 compare-and-swap.'
        }
        if ($ExpectedHeadSha256 -cne $baseHeadSha256) {
            throw 'PrepareManifestSigning rejected a stale production state head before Publisher-input admission.'
        }
        $publishedRequestRoot = Join-Path `
            (Join-Path $stateLock.StateRoot 'requests') `
            ([string]$manifestChannelContract.RequestBundleName)
        $publishedRequestPath = Join-Path `
            $publishedRequestRoot `
            'manifest-publishing-request.v1.json'
        $requestAlreadyPublished = Test-Path -LiteralPath $publishedRequestRoot
        $bundleStaging = New-ProductionBundleStagingRoot `
            -Root $stateLock.StateRoot `
            -Plan $plan `
            -Purpose manifest-request
        $manifestRequestBundle = New-PilotManifestPublishingRequestBundle `
            -Root ([string]$bundleStaging.Root) `
            -Plan $plan `
            -State $state `
            -BaseHeadSha256 $baseHeadSha256 `
            -Path $PublisherInputPath `
            -ExistingRequestPath $(if ($requestAlreadyPublished) {
                $publishedRequestPath
            } else { '' })
        $manifestRequestData = Get-PilotManifestRequestReceiptData `
            -Bundle $manifestRequestBundle
        Wait-TestOnlyProductionCheckoutAdmission `
            -Staging $bundleStaging `
            -ExpectedFaultPoint 'TestOnlyWaitBeforeManifestRequestCheckoutAdmission'
        $stagedRequestRoot = Join-Path `
            (Join-Path ([string]$bundleStaging.Root) 'requests') `
            ([string]$manifestChannelContract.RequestBundleName)
        $stagedRequestInput = Read-StrictProductionJsonFile `
            -Path (Join-Path $stagedRequestRoot 'manifest-publishing-request.v1.json') `
            -Label 'Staged target-channel manifest-publishing request before publication' `
            -SchemaPath $manifestRequestSchemaPath
        [void](Assert-CanonicalProductionJsonInput `
            -Input $stagedRequestInput `
            -Label 'Staged target-channel manifest-publishing request before publication')
        if ([string]$stagedRequestInput.Sha256 -cne
            [string]$manifestRequestBundle.RequestInput.Sha256) {
            throw 'Staged target-channel manifest-publishing request changed before atomic publication.'
        }
        $stagedDescriptorInput = Read-StrictProductionJsonFile `
            -Path (Join-Path $stagedRequestRoot 'publisher-input.v1.json') `
            -Label 'Staged production Publisher input before publication' `
            -SchemaPath $publisherInputSchemaPath
        $clientImportReceipt = if ([string]$state.Head.phase -ceq
            'CLIENT_SIGNATURES_IMPORTED') {
            $state.LastReceipt
        }
        else {
            $clientImportReceiptPath = Join-Path `
                (Join-Path $stateLock.StateRoot 'receipts') `
                '0003-client-signatures-imported.json'
            (Read-StrictProductionJsonFile `
                -Path $clientImportReceiptPath `
                -Label 'Admitted client-signature import receipt' `
                -SchemaPath $stateSchemaPath).Value
        }
        [void](Assert-ProductionPublisherInputFileSet `
            -Plan $plan `
            -PlanSha256 ([string]$state.Identity.planSha256) `
            -PlanAdmissionReceipt $state.Receipts[0] `
            -ClientImportReceipt $clientImportReceipt `
            -DescriptorInput $stagedDescriptorInput `
            -PayloadRoot (Join-Path $stagedRequestRoot 'payload'))
        if ($requestAlreadyPublished) {
            Assert-ProductionBundleTreesEqual `
                -ExpectedRoot $stagedRequestRoot `
                -ActualRoot $publishedRequestRoot `
                -Label 'Exact target-channel manifest-publishing request replay'
        }
        [void](Complete-ProductionBundleAfterCheckoutAdmission `
            -Staging $bundleStaging `
            -Plan $plan `
            -RelativeBundlePath ('requests\' + [string]$manifestChannelContract.RequestBundleName) `
            -DestinationParent (Join-Path $stateLock.StateRoot 'requests') `
            -AllowExisting:$requestAlreadyPublished)
        $completedStaging = $bundleStaging
        $bundleStaging = $null
        Remove-ProductionBundleStagingRoot -Staging $completedStaging
        if ($FaultPoint -ceq 'AfterManifestRequestBundle') {
            throw 'INJECTED-CRASH-AFTER-TARGET-CHANNEL-MANIFEST-REQUEST-BUNDLE'
        }
        $state = Add-ProductionReleaseReceipt `
            -StateRoot $stateLock.StateRoot `
            -StateSchemaPath $stateSchemaPath `
            -Phase ([string]$manifestChannelContract.RequestPhase) `
            -ExpectedPreviousPhase 'CLIENT_SIGNATURES_IMPORTED' `
            -ExpectedHeadSha256 $baseHeadSha256 `
            -Data $manifestRequestData `
            -FaultAfterReceipt:($FaultPoint -ceq 'AfterManifestRequestReceipt')
        Get-ProductionReleaseStateSummary `
            -StateRoot $stateLock.StateRoot `
            -StateSchemaPath $stateSchemaPath
        return
    }

    if ($Phase -eq 'ImportSignedCandidate') {
        $manifestChannelContract = Get-ProductionManifestChannelContract `
            -TargetChannel ([string]$plan.targetChannel)
        if ([int]$state.SchemaVersion -ne 2 -or
            $null -eq $state.Head -or
            [string]$state.Head.phase -notin @(
                [string]$manifestChannelContract.RequestPhase,
                [string]$manifestChannelContract.CandidatePhase)) {
            throw 'NO-GO: target-channel signed candidate can only be imported after its typed manifest-publishing request.'
        }
        $admissionHeadSha256 = if ([string]$state.Head.phase -ceq
            [string]$manifestChannelContract.RequestPhase) {
            [string]$state.HeadSha256
        }
        else {
            [string]$state.LastReceipt.data.admissionHeadSha256
        }
        if ([string]::IsNullOrWhiteSpace($ExpectedHeadSha256)) {
            throw 'ImportSignedCandidate requires -ExpectedHeadSha256 for its exact r4 compare-and-swap.'
        }
        if ($ExpectedHeadSha256 -cne $admissionHeadSha256) {
            throw 'ImportSignedCandidate rejected a stale production state head before signed-candidate admission.'
        }
        $manifestRequestRoot = Join-Path `
            (Join-Path $stateLock.StateRoot 'requests') `
            ([string]$manifestChannelContract.RequestBundleName)
        $manifestRequestPath = Join-Path `
            $manifestRequestRoot `
            'manifest-publishing-request.v1.json'
        $manifestRequestInput = Read-StrictProductionJsonFile `
            -Path $manifestRequestPath `
            -Label 'Admitted target-channel manifest-publishing request' `
            -SchemaPath $manifestRequestSchemaPath
        [void](Assert-CanonicalProductionJsonInput `
            -Input $manifestRequestInput `
            -Label 'Admitted target-channel manifest-publishing request')
        $publishedImportRoot = Join-Path `
            (Join-Path $stateLock.StateRoot 'imports') `
            ([string]$manifestChannelContract.CandidateBundleName)
        $importAlreadyPublished = Test-Path -LiteralPath $publishedImportRoot
        $bundleStaging = New-ProductionBundleStagingRoot `
            -Root $stateLock.StateRoot `
            -Plan $plan `
            -Purpose manifest-import
        $candidateImport = Import-PilotSignedCandidateResponse `
            -Root ([string]$bundleStaging.Root) `
            -StateRoot ([string]$stateLock.StateRoot) `
            -Plan $plan `
            -RequestInput $manifestRequestInput `
            -AdmissionHeadSha256 $admissionHeadSha256 `
            -Path $ResponsePath `
            -EnforceCurrentLifetime:([string]$state.Head.phase -ceq
                [string]$manifestChannelContract.RequestPhase)
        $candidateImportData = Get-PilotSignedCandidateReceiptData `
            -Import $candidateImport
        Wait-TestOnlyProductionCheckoutAdmission `
            -Staging $bundleStaging `
            -ExpectedFaultPoint 'TestOnlyWaitBeforeSignedCandidateCheckoutAdmission'
        $stagedImportRoot = Join-Path `
            (Join-Path ([string]$bundleStaging.Root) 'imports') `
            ([string]$manifestChannelContract.CandidateBundleName)
        $stagedResponseInput = Read-StrictProductionJsonFile `
            -Path (Join-Path $stagedImportRoot 'manifest-publishing-response.v1.json') `
            -Label 'Staged target-channel signed-candidate response before publication' `
            -SchemaPath $manifestResponseSchemaPath
        [void](Assert-CanonicalProductionJsonInput `
            -Input $stagedResponseInput `
            -Label 'Staged target-channel signed-candidate response before publication')
        Assert-ProductionReleaseManifestPublishingResponseAuthentication `
            -Response $stagedResponseInput.Value `
            -Trust $plan.externalResponseTrusts.manifestPublishing
        if ([string]$stagedResponseInput.Sha256 -cne
            [string]$candidateImport.ResponseInput.Sha256) {
            throw 'Staged target-channel signed-candidate response changed before atomic publication.'
        }
        foreach ($file in @($stagedResponseInput.Value.files)) {
            $stagedCandidateRoot = Join-Path $stagedImportRoot 'candidate'
            $stagedCandidate = Open-ProductionReleaseInput `
                -Path (Join-Path $stagedCandidateRoot ([string]$file.fileName)) `
                -Label "Staged target-channel signed-candidate role $($file.role)" `
                -MaximumBytes (8L * 1024 * 1024 * 1024)
            try {
                if ([int64]$stagedCandidate.SizeBytes -ne [int64]$file.sizeBytes -or
                    [string]$stagedCandidate.Sha256 -cne [string]$file.sha256) {
                    throw "Staged target-channel signed-candidate role '$($file.role)' changed before atomic publication."
                }
            }
            finally {
                $stagedCandidate.Stream.Dispose()
            }
        }
        $stagedManifestInput = Read-StrictProductionJsonFile `
            -Path (Join-Path (Join-Path $stagedImportRoot 'candidate') 'release-set.v2.json') `
            -Label 'Staged target-channel signed release manifest before publication'
        [void]@(Assert-ProductionReleaseManifestCandidate `
            -Plan $plan `
            -ManifestInput $stagedManifestInput `
            -CandidateRoot (Join-Path $stagedImportRoot 'candidate') `
            -Files @($stagedResponseInput.Value.files) `
            -ComponentReleaseIds $manifestRequestInput.Value.componentReleaseIds `
            -RuntimeProvenance $manifestRequestInput.Value.runtimeProvenance `
            -ValidationTimeUtc (ConvertFrom-ProductionUtc `
                -Value ([string]$candidateImport.ResponseInput.Value.completedAtUtc) `
                -Label 'Staged target-channel signed-candidate completion time'))
        if ($importAlreadyPublished) {
            Assert-ProductionBundleTreesEqual `
                -ExpectedRoot $stagedImportRoot `
                -ActualRoot $publishedImportRoot `
                -Label 'Exact target-channel signed-candidate response replay'
        }
        [void](Complete-ProductionBundleAfterCheckoutAdmission `
            -Staging $bundleStaging `
            -Plan $plan `
            -RelativeBundlePath ('imports\' + [string]$manifestChannelContract.CandidateBundleName) `
            -DestinationParent (Join-Path $stateLock.StateRoot 'imports') `
            -AllowExisting:$importAlreadyPublished)
        $completedStaging = $bundleStaging
        $bundleStaging = $null
        Remove-ProductionBundleStagingRoot -Staging $completedStaging
        if ($FaultPoint -ceq 'AfterSignedCandidateBundle') {
            throw 'INJECTED-CRASH-AFTER-TARGET-CHANNEL-SIGNED-CANDIDATE-BUNDLE'
        }
        $state = Add-ProductionReleaseReceipt `
            -StateRoot $stateLock.StateRoot `
            -StateSchemaPath $stateSchemaPath `
            -Phase ([string]$manifestChannelContract.CandidatePhase) `
            -ExpectedPreviousPhase ([string]$manifestChannelContract.RequestPhase) `
            -ExpectedHeadSha256 $admissionHeadSha256 `
            -Data $candidateImportData `
            -FaultAfterReceipt:($FaultPoint -ceq 'AfterSignedCandidateReceipt')
        Get-ProductionReleaseStateSummary `
            -StateRoot $stateLock.StateRoot `
            -StateSchemaPath $stateSchemaPath
        return
    }

    if ($Phase -eq 'PrepareInstallerSigning') {
        if ([int]$state.SchemaVersion -eq 2 -and
            [string]$plan.edition -ceq 'Personal') {
            if ([string]$plan.targetChannel -cne 'pilot' -or
                $null -eq $state.Head -or
                [string]$state.Head.phase -notin @(
                    'PILOT_SIGNED_CANDIDATE_IMPORTED',
                    'INSTALLER_SIGNING_REQUESTED')) {
                throw 'NO-GO: Personal Installer signing can only be prepared after its exact Pilot r5 signed candidate.'
            }
            $baseHeadSha256 = if ([string]$state.Head.phase -ceq
                'PILOT_SIGNED_CANDIDATE_IMPORTED') {
                [string]$state.HeadSha256
            }
            else {
                [string]$state.LastReceipt.data.baseHeadSha256
            }
            if ([string]::IsNullOrWhiteSpace($ExpectedHeadSha256) -or
                $ExpectedHeadSha256 -cne $baseHeadSha256) {
                throw 'PrepareInstallerSigning rejected a missing or stale Personal r5 compare-and-swap head.'
            }
            $r5ReceiptPath = Join-Path `
                (Join-Path $stateLock.StateRoot 'receipts') `
                '0005-pilot-signed-candidate-imported.json'
            $r5ReceiptInput = Open-ProductionReleaseInput `
                -Path $r5ReceiptPath `
                -Label 'Personal r5 signed-candidate receipt' `
                -MaximumBytes 8MB
            $planLease = $null
            $headLease = $null
            try {
                $baseReceiptSha256 = [string]$r5ReceiptInput.Sha256
                $publishedRequestRoot = Join-Path `
                    (Join-Path $stateLock.StateRoot 'requests') `
                    'installer-signing.v2'
                if (Test-Path -LiteralPath $publishedRequestRoot) {
                    $publishedAdmission = $null
                    try {
                        $publishedAdmission =
                            Open-PersonalInstallerRequestBundleAdmission `
                                -BundleRoot $publishedRequestRoot `
                                -Plan $plan `
                                -RequestSchemaPath `
                                    $installerSigningRequestSchemaV2Path `
                                -EvidenceSchemaPath `
                                    $personalInstallerTrustedBuildEvidenceSchemaPath `
                                -Label 'Published Personal Installer request bundle'
                        $publishedRequestInput =
                            $publishedAdmission.RequestInput
                        if ([string]$state.Head.phase -ceq
                            'PILOT_SIGNED_CANDIDATE_IMPORTED') {
                            $recoveredData = Get-PersonalInstallerSigningRequestReceiptData `
                                -RequestInput $publishedRequestInput `
                                -State $state `
                                -BaseReceiptSha256 $baseReceiptSha256
                            $state = Add-ProductionReleaseReceipt `
                                -StateRoot $stateLock.StateRoot `
                                -StateSchemaPath $stateSchemaPath `
                                -Phase 'INSTALLER_SIGNING_REQUESTED' `
                                -ExpectedPreviousPhase `
                                    'PILOT_SIGNED_CANDIDATE_IMPORTED' `
                                -ExpectedHeadSha256 $baseHeadSha256 `
                                -Data $recoveredData
                        }
                        elseif ([string]$state.LastReceipt.data.requestSha256 -cne
                            [string]$publishedRequestInput.Sha256) {
                            throw 'Published Personal Installer request differs from its admitted r6 receipt.'
                        }
                        Assert-ProductionBundleAdmissionStillLocked `
                            -Admission $publishedAdmission `
                            -Label 'Published Personal Installer request bundle'
                        $summary = Get-ProductionReleaseStateSummary `
                            -StateRoot $stateLock.StateRoot `
                            -StateSchemaPath $stateSchemaPath
                        Assert-ProductionBundleAdmissionStillLocked `
                            -Admission $publishedAdmission `
                            -Label 'Published Personal Installer request bundle'
                        $summary
                        return
                    }
                    finally {
                        Close-ProductionBundleAdmission `
                            -Admission $publishedAdmission
                    }
                }
                if ($InstallerSigningInputPath) {
                    throw 'PrepareInstallerSigning rejects operator-supplied Personal requests; request-v2 must be built in-process.'
                }
                if ([string]::IsNullOrWhiteSpace($PersonalInstallerPayloadPath) -or
                    [string]::IsNullOrWhiteSpace(
                        $PersonalInstallerPackageDirectory) -or
                    [string]::IsNullOrWhiteSpace(
                        $PersonalInstallerDotNetSdkArchivePath)) {
                    throw 'PrepareInstallerSigning requires -PersonalInstallerPayloadPath, -PersonalInstallerPackageDirectory, and -PersonalInstallerDotNetSdkArchivePath for its locked offline build.'
                }
                $bundleStaging = New-ProductionBundleStagingRoot `
                    -Root $stateLock.StateRoot `
                    -Plan $plan `
                    -Purpose installer-request
                $externalRequestRoot = Join-Path `
                    ([string]$bundleStaging.Root) `
                    'trusted-builder-output'
                $manifestOrigin = ([Uri]$plan.manifestUri).
                    GetLeftPart([UriPartial]::Authority) + '/'
                $artifactOrigin = ([Uri]$plan.artifactBaseUri).
                    GetLeftPart([UriPartial]::Authority) + '/'
                $buildContext = [ordered]@{
                    orchestrationId = [string]$plan.orchestrationId
                    channel = 'pilot'
                    expectedReleaseSetId = [string]$plan.releaseSetId
                    planSha256 = [string]$planInput.Sha256
                    baseHeadSha256 = $baseHeadSha256
                    maximumResponseAgeMinutes =
                        [int]$plan.authenticodePolicy.maximumResponseAgeMinutes
                }
                $compiledTrust = [ordered]@{
                    manifestOrigin = $manifestOrigin
                    artifactOrigin = $artifactOrigin
                    releaseKeyId = [string]$plan.releaseManifestTrust.keyId
                    releaseKeyX = [string]$plan.releaseManifestTrust.x
                    releaseKeyY = [string]$plan.releaseManifestTrust.y
                    startupStubVersion =
                        [string]$plan.releaseCompatibility.startupStubVersion
                    canonicalLowSFromSequence =
                        [int64]$plan.releaseCompatibility.canonicalLowSFromSequence
                    authenticodeSignerSha256Thumbprint =
                        [string]$plan.authenticodePolicy.signerSha256Thumbprint
                }
                $trustedBuildResult =
                    PersonalInstallerTrustedBuild\New-PersonalInstallerTrustedBuild `
                        -Context $buildContext `
                        -CompiledTrust $compiledTrust `
                        -InstallerSigningResponseTrust `
                            $plan.externalResponseTrusts.installerSigning `
                        -PayloadDirectory ([IO.Path]::GetFullPath(
                            $PersonalInstallerPayloadPath)) `
                        -PackageDirectory ([IO.Path]::GetFullPath(
                            $PersonalInstallerPackageDirectory)) `
                        -DotNetSdkArchivePath ([IO.Path]::GetFullPath(
                            $PersonalInstallerDotNetSdkArchivePath)) `
                        -OutputDirectory $externalRequestRoot `
                        -RepositoryRoot $repositoryRootFull
                $planLease = Open-ProductionReleaseInput `
                    -Path (Join-Path $stateLock.StateRoot 'plan.json') `
                    -Label 'Personal r6 plan' -MaximumBytes 8MB
                $headLease = Open-ProductionReleaseInput `
                    -Path (Join-Path $stateLock.StateRoot 'head.json') `
                    -Label 'Personal r5 head' -MaximumBytes 8MB
                $preparation =
                    PersonalInstallerSigningPipeline\Prepare-PersonalInstallerSigningPipeline `
                        -TrustedBuildResult $trustedBuildResult `
                        -PlanInput $planLease `
                        -R5HeadInput $headLease `
                        -R5ReceiptInput $r5ReceiptInput `
                        -ExpectedR5HeadSha256 $baseHeadSha256
                if (-not [bool]$preparation.ExternalSigningRequestEligible -or
                    [string]$preparation.Blocker -cne
                        'INSTALLER_SIGNING_RESPONSE_REQUIRED') {
                    throw "Personal trusted build did not produce one eligible r6 request: $($preparation.Blocker)"
                }
                $stagedRequestRoot = Join-Path `
                    (Join-Path ([string]$bundleStaging.Root) 'requests') `
                    'installer-signing.v2'
                $stagedUnsignedRoot = Join-Path $stagedRequestRoot 'unsigned'
                $stagedPayloadRoot = Join-Path $stagedRequestRoot 'payload'
                $stagedTrustedRoot = Join-Path $stagedRequestRoot 'trusted-build'
                [IO.Directory]::CreateDirectory($stagedUnsignedRoot) | Out-Null
                [IO.Directory]::CreateDirectory($stagedPayloadRoot) | Out-Null
                [IO.Directory]::CreateDirectory($stagedTrustedRoot) | Out-Null
                foreach ($copy in @(
                        [pscustomobject]@{
                            Input = $trustedBuildResult.RequestInput
                            Destination = Join-Path $stagedRequestRoot `
                                'installer-signing-request.v2.json'
                            Label = 'Personal Installer signing request v2'
                        },
                        [pscustomobject]@{
                            Input = $trustedBuildResult.UnsignedInstallerInput
                            Destination = Join-Path $stagedUnsignedRoot `
                                'Ensou.Dsh.Personal.Installer.exe'
                            Label = 'Unsigned Personal Installer'
                        },
                        [pscustomobject]@{
                            Input = $trustedBuildResult.EvidenceInput
                            Destination = Join-Path $stagedTrustedRoot `
                                'trusted-build-evidence.v1.json'
                            Label = 'Personal trusted-build evidence'
                        })) {
                    Copy-ProductionLockedInputToCreateOnlyFile `
                        -Input $copy.Input `
                        -DestinationPath $copy.Destination `
                        -Label $copy.Label
                }
                foreach ($payloadInput in @($trustedBuildResult.PayloadInputs)) {
                    Copy-ProductionLockedInputToCreateOnlyFile `
                        -Input $payloadInput `
                        -DestinationPath (Join-Path $stagedPayloadRoot `
                            ([string]$payloadInput.FileName)) `
                        -Label "Personal payload $($payloadInput.Role)"
                }
                $preWaitAdmission = $null
                try {
                    $preWaitAdmission =
                        Open-PersonalInstallerRequestBundleAdmission `
                            -BundleRoot $stagedRequestRoot `
                            -Plan $plan `
                            -RequestSchemaPath $installerSigningRequestSchemaV2Path `
                            -EvidenceSchemaPath `
                                $personalInstallerTrustedBuildEvidenceSchemaPath `
                            -Label 'Staged Personal Installer request bundle before wait' `
                            -EnforceCurrentLifetime
                    $preWaitPins = Get-ProductionBundleAdmissionPins `
                        -Admission $preWaitAdmission
                }
                finally {
                    Close-ProductionBundleAdmission -Admission $preWaitAdmission
                }
                foreach ($lockedOutput in @($trustedBuildResult.LockedOutputs)) {
                    [void](Assert-ProductionReleaseInputStillLocked `
                        -Descriptor $lockedOutput `
                        -Label "Personal trusted-build output '$($lockedOutput.FileName)'")
                }
                $trustedBuildResult.Dispose()
                $trustedBuildResult = $null
                Wait-TestOnlyProductionCheckoutAdmission `
                    -Staging $bundleStaging `
                    -ExpectedFaultPoint `
                        'TestOnlyWaitBeforeInstallerRequestCheckoutAdmission'
                $postWaitAdmission =
                    Open-PersonalInstallerRequestBundleAdmission `
                        -BundleRoot $stagedRequestRoot `
                        -Plan $plan `
                        -RequestSchemaPath $installerSigningRequestSchemaV2Path `
                        -EvidenceSchemaPath `
                            $personalInstallerTrustedBuildEvidenceSchemaPath `
                        -Label 'Staged Personal Installer request bundle after wait' `
                        -EnforceCurrentLifetime
                Assert-ProductionBundleAdmissionMatchesPins `
                    -Admission $postWaitAdmission -Pins $preWaitPins `
                    -Label 'Staged Personal Installer request bundle' `
                    -RequireSameFileIdentity
                $postWaitPins = Get-ProductionBundleAdmissionPins `
                    -Admission $postWaitAdmission
                $finalAdmission = $null
                try {
                    $completion =
                        Complete-ValidatedProductionBundleAfterCheckoutAdmission `
                            -Staging $bundleStaging `
                            -Plan $plan `
                            -RelativeBundlePath 'requests\installer-signing.v2' `
                            -DestinationParent (Join-Path $stateLock.StateRoot 'requests') `
                            -PostWaitAdmission $postWaitAdmission `
                            -ExpectedPins $postWaitPins `
                            -Label 'Personal Installer request bundle' `
                            -ExpectedPreMoveFaultPoint `
                                'TestOnlyWaitBeforeValidatedBundleAtomicMove' `
                            -OpenFinalAdmission {
                                param($bundleRoot)
                                Open-PersonalInstallerRequestBundleAdmission `
                                    -BundleRoot $bundleRoot `
                                    -Plan $plan `
                                    -RequestSchemaPath `
                                        $installerSigningRequestSchemaV2Path `
                                    -EvidenceSchemaPath `
                                        $personalInstallerTrustedBuildEvidenceSchemaPath `
                                    -Label 'Final Personal Installer request bundle' `
                                    -EnforceCurrentLifetime
                            }
                    $postWaitAdmission = $null
                    $publishedPath = [string]$completion.Path
                    $finalAdmission = $completion.Admission
                    $completedStaging = $bundleStaging
                    $bundleStaging = $null
                    Remove-ProductionBundleStagingRoot -Staging $completedStaging
                    if ($FaultPoint -ceq 'AfterInstallerRequestBundle') {
                        throw 'INJECTED-CRASH-AFTER-PERSONAL-INSTALLER-REQUEST-BUNDLE'
                    }
                    $requestData = Get-PersonalInstallerSigningRequestReceiptData `
                        -RequestInput $finalAdmission.RequestInput `
                        -State $state `
                        -BaseReceiptSha256 $baseReceiptSha256
                    Assert-ProductionBundleAdmissionStillLocked `
                        -Admission $finalAdmission `
                        -Label 'Final Personal Installer request bundle'
                    $state = Add-ProductionReleaseReceipt `
                        -StateRoot $stateLock.StateRoot `
                        -StateSchemaPath $stateSchemaPath `
                        -Phase 'INSTALLER_SIGNING_REQUESTED' `
                        -ExpectedPreviousPhase 'PILOT_SIGNED_CANDIDATE_IMPORTED' `
                        -ExpectedHeadSha256 $baseHeadSha256 `
                        -Data $requestData `
                        -FaultAfterReceipt:($FaultPoint -ceq
                            'AfterInstallerRequestReceipt')
                    Assert-ProductionBundleAdmissionStillLocked `
                        -Admission $finalAdmission `
                        -Label 'Final Personal Installer request bundle'
                    $summary = Get-ProductionReleaseStateSummary `
                        -StateRoot $stateLock.StateRoot `
                        -StateSchemaPath $stateSchemaPath
                    Assert-ProductionBundleAdmissionStillLocked `
                        -Admission $finalAdmission `
                        -Label 'Final Personal Installer request bundle'
                    $summary
                    return
                }
                finally {
                    Close-ProductionBundleAdmission -Admission $finalAdmission
                }
            }
            finally {
                if ($null -ne $headLease) { $headLease.Stream.Dispose() }
                if ($null -ne $planLease) { $planLease.Stream.Dispose() }
                $r5ReceiptInput.Stream.Dispose()
            }
        }
        if ([int]$state.SchemaVersion -ne 2 -or
            [string]$plan.edition -cne 'Enterprise' -or
            [string]$plan.targetChannel -cne 'stable' -or
            $null -eq $state.Head -or
            [string]$state.Head.phase -notin @(
                'STABLE_SIGNED_CANDIDATE_IMPORTED',
                'INSTALLER_SIGNING_REQUESTED')) {
            throw 'NO-GO: Enterprise Installer signing can only be prepared after its exact stable r5 signed candidate.'
        }
        $baseHeadSha256 = if ([string]$state.Head.phase -ceq
            'STABLE_SIGNED_CANDIDATE_IMPORTED') {
            [string]$state.HeadSha256
        }
        else {
            [string]$state.LastReceipt.data.baseHeadSha256
        }
        $r5ReceiptPath = Join-Path `
            (Join-Path $stateLock.StateRoot 'receipts') `
            '0005-stable-signed-candidate-imported.json'
        $r5ReceiptInput = Open-ProductionReleaseInput `
            -Path $r5ReceiptPath `
            -Label 'Enterprise r5 signed-candidate receipt' `
            -MaximumBytes 8MB
        try {
            $baseReceiptSha256 = [string]$r5ReceiptInput.Sha256
        }
        finally {
            $r5ReceiptInput.Stream.Dispose()
        }
        if ([string]::IsNullOrWhiteSpace($ExpectedHeadSha256)) {
            throw 'PrepareInstallerSigning requires -ExpectedHeadSha256 for its exact r5 compare-and-swap.'
        }
        if ($ExpectedHeadSha256 -cne $baseHeadSha256) {
            throw 'PrepareInstallerSigning rejected a stale production state head before Installer-build admission.'
        }
        $publishedRequestRoot = Join-Path `
            (Join-Path $stateLock.StateRoot 'requests') `
            'installer-signing.v2'
        if (Test-Path -LiteralPath $publishedRequestRoot) {
            $publishedAdmission = $null
            try {
                $publishedAdmission =
                    Open-EnterpriseInstallerRequestBundleAdmission `
                        -BundleRoot $publishedRequestRoot `
                        -Plan $plan -State $state `
                        -BaseHeadSha256 $baseHeadSha256 `
                        -BaseReceiptSha256 $baseReceiptSha256 `
                        -SourceTree ([string]$sourceCheckout.Tree) `
                        -RequestSchemaPath $installerSigningRequestSchemaV2Path `
                        -Label 'Published Enterprise Installer request bundle'
                $publishedRequestInput = $publishedAdmission.RequestInput
                if ([string]$state.Head.phase -ceq
                    'STABLE_SIGNED_CANDIDATE_IMPORTED') {
                    $recoveredRequestData = Get-InstallerSigningRequestReceiptData `
                        -RequestInput $publishedRequestInput `
                        -State $state `
                        -BaseReceiptSha256 $baseReceiptSha256
                    $state = Add-ProductionReleaseReceipt `
                        -StateRoot $stateLock.StateRoot `
                        -StateSchemaPath $stateSchemaPath `
                        -Phase 'INSTALLER_SIGNING_REQUESTED' `
                        -ExpectedPreviousPhase 'STABLE_SIGNED_CANDIDATE_IMPORTED' `
                        -ExpectedHeadSha256 $baseHeadSha256 `
                        -Data $recoveredRequestData
                }
                elseif ([string]$state.LastReceipt.data.requestSha256 -cne
                    [string]$publishedRequestInput.Sha256) {
                    throw 'Published Enterprise Installer request differs from its admitted r6 receipt.'
                }
                Assert-ProductionBundleAdmissionStillLocked `
                    -Admission $publishedAdmission `
                    -Label 'Published Enterprise Installer request bundle'
                $summary = Get-ProductionReleaseStateSummary `
                    -StateRoot $stateLock.StateRoot `
                    -StateSchemaPath $stateSchemaPath
                Assert-ProductionBundleAdmissionStillLocked `
                    -Admission $publishedAdmission `
                    -Label 'Published Enterprise Installer request bundle'
                $summary
                return
            }
            finally {
                Close-ProductionBundleAdmission -Admission $publishedAdmission
            }
        }
        if ($InstallerSigningInputPath) {
            throw 'PrepareInstallerSigning rejects operator-supplied Installer signing requests; request-v2 must be built in-process.'
        }
        if ([string]::IsNullOrWhiteSpace($EnterpriseInstallerPayloadPath) -or
            [string]::IsNullOrWhiteSpace(
                $EnterpriseInstallerPackageDirectory) -or
            [string]::IsNullOrWhiteSpace(
                $EnterpriseInstallerDotNetSdkArchivePath)) {
            throw 'PrepareInstallerSigning requires -EnterpriseInstallerPayloadPath, -EnterpriseInstallerPackageDirectory, and -EnterpriseInstallerDotNetSdkArchivePath for its locked offline build.'
        }
        $bundleStaging = New-ProductionBundleStagingRoot `
            -Root $stateLock.StateRoot `
            -Plan $plan `
            -Purpose installer-request
        $externalRequestRoot = Join-Path `
            ([string]$bundleStaging.Root) `
            'trusted-builder-output'
        if (Test-SameOrDescendantPath `
                -Path $EnterpriseInstallerDotNetSdkArchivePath `
                -Root ([string]$bundleStaging.Root)) {
            throw 'Enterprise portable .NET SDK archive must remain outside the trusted Builder output.'
        }
        $trustedBuildResult = New-EnterpriseInstallerTrustedBuildForR6 `
            -Plan $plan `
            -State $state `
            -BaseHeadSha256 $baseHeadSha256 `
            -PayloadDirectory ([IO.Path]::GetFullPath(
                $EnterpriseInstallerPayloadPath)) `
            -PackageDirectory ([IO.Path]::GetFullPath(
                $EnterpriseInstallerPackageDirectory)) `
            -DotNetSdkArchivePath ([IO.Path]::GetFullPath(
                $EnterpriseInstallerDotNetSdkArchivePath)) `
            -OutputDirectory $externalRequestRoot
        $externalRequestPath = Join-Path `
            $externalRequestRoot `
            'installer-signing-request.v2.json'
        if ([IO.Path]::GetFileName($externalRequestPath) -cne
            'installer-signing-request.v2.json') {
            throw 'Trusted builder produced a noncanonical Installer signing request path.'
        }
        [void](Assert-ExactProductionDirectoryInventory `
            -Path $externalRequestRoot `
            -Expected ([ordered]@{
                'installer-signing-request.v2.json' = $false
                'unsigned' = $true
                'payload' = $true
                'trusted-build' = $true
                'build-inputs' = $true
                'toolchain' = $true
            }) `
            -Label 'In-process Enterprise Installer trusted-build output')
        $externalRequestInput = Read-InstallerSigningContractInput `
            -Path $externalRequestPath `
            -SchemaPath $installerSigningRequestSchemaV2Path `
            -Label 'In-process Enterprise Installer signing request v2'
        $externalUnsignedRoot = Join-Path $externalRequestRoot 'unsigned'
        [void](Assert-ExactProductionDirectoryInventory `
            -Path $externalUnsignedRoot `
            -Expected ([ordered]@{
                'Ensou.Dsh.Enterprise.Installer.exe' = $false
            }) `
            -Label 'In-process Enterprise unsigned Installer bundle')
        $externalPayloadRoot = Join-Path $externalRequestRoot 'payload'
        [void](Assert-ExactProductionDirectoryInventory `
            -Path $externalPayloadRoot `
            -Expected ([ordered]@{
                'Ensou.Dsh.Enterprise.Bootstrapper.exe' = $false
                'enterprise-install-manifest.json' = $false
                'launcher.zip' = $false
                'runtime.zip' = $false
            }) `
            -Label 'In-process Enterprise Installer production payload')
        $sourceCheckout = Assert-LauncherSourceCheckout -Plan $plan
        Assert-EnterpriseInstallerSigningRequestStateClosure `
            -RequestInput $externalRequestInput `
            -Plan $plan `
            -State $state `
            -BaseHeadSha256 $baseHeadSha256 `
            -BaseReceiptSha256 $baseReceiptSha256 `
            -SourceTree ([string]$sourceCheckout.Tree) `
            -BundleRoot $externalRequestRoot
        $requestCreated = ConvertFrom-ProductionUtc `
            -Value ([string]$externalRequestInput.Value.createdAtUtc) `
            -Label 'Enterprise Installer-signing request creation time'
        $r5Completed = ConvertFrom-ProductionUtc `
            -Value ([string]$state.Receipts[4].data.completedAtUtc) `
            -Label 'Enterprise r5 signed-candidate completion time'
        if ($requestCreated -lt $r5Completed -or
            $requestCreated -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) {
            throw 'Enterprise Installer build/request time must follow the authenticated r5 candidate and cannot be future-dated.'
        }
        $externalUnsignedPath = Join-Path `
            $externalUnsignedRoot `
            'Ensou.Dsh.Enterprise.Installer.exe'
        [void](Assert-UnsignedInstallerSigningInput `
            -Path $externalUnsignedPath `
            -Descriptor $externalRequestInput.Value.unsignedInstaller)
        if ($null -ne
            $externalRequestInput.Value.PSObject.Properties['payloadSelfCheck']) {
            throw 'Installer signing request v2 must not claim or execute an unsigned payload self-check.'
        }
        $requestAlreadyPublished = $false
        $stagedRequestRoot = Join-Path `
            (Join-Path ([string]$bundleStaging.Root) 'requests') `
            'installer-signing.v2'
        $stagedUnsignedRoot = Join-Path $stagedRequestRoot 'unsigned'
        $stagedPayloadRoot = Join-Path $stagedRequestRoot 'payload'
        $stagedTrustedBuildRoot = Join-Path $stagedRequestRoot 'trusted-build'
        [IO.Directory]::CreateDirectory($stagedUnsignedRoot) | Out-Null
        [IO.Directory]::CreateDirectory($stagedPayloadRoot) | Out-Null
        [IO.Directory]::CreateDirectory($stagedTrustedBuildRoot) | Out-Null
        $requestLease = Open-ProductionReleaseInput `
            -Path $externalRequestPath `
            -Label 'External Enterprise Installer-signing request' `
            -MaximumBytes 8MB
        try {
            if ([string]$requestLease.Sha256 -cne
                [string]$externalRequestInput.Sha256) {
                throw 'External Enterprise Installer-signing request changed before staging.'
            }
            Copy-ProductionLockedInputToCreateOnlyFile `
                -Input $requestLease `
                -DestinationPath (Join-Path $stagedRequestRoot 'installer-signing-request.v2.json') `
                -Label 'Enterprise Installer-signing request'
        }
        finally {
            $requestLease.Stream.Dispose()
        }
        foreach ($copy in @(
                [pscustomobject]@{
                    Source = $externalUnsignedPath
                    Destination = Join-Path $stagedUnsignedRoot 'Ensou.Dsh.Enterprise.Installer.exe'
                    MaximumBytes = 1GB
                    Label = 'Unsigned Enterprise Installer'
                },
                [pscustomobject]@{
                    Source = Join-Path $externalRequestRoot `
                        'trusted-build\trusted-build-evidence.v1.json'
                    Destination = Join-Path $stagedTrustedBuildRoot `
                        'trusted-build-evidence.v1.json'
                    MaximumBytes = 64MB
                    Label = 'Enterprise Installer trusted-build evidence'
                },
                [pscustomobject]@{
                    Source = Join-Path $externalPayloadRoot 'Ensou.Dsh.Enterprise.Bootstrapper.exe'
                    Destination = Join-Path $stagedPayloadRoot 'Ensou.Dsh.Enterprise.Bootstrapper.exe'
                    MaximumBytes = 512MB
                    Label = 'Enterprise Installer Bootstrapper payload'
                },
                [pscustomobject]@{
                    Source = Join-Path $externalPayloadRoot 'enterprise-install-manifest.json'
                    Destination = Join-Path $stagedPayloadRoot 'enterprise-install-manifest.json'
                    MaximumBytes = 128KB
                    Label = 'Enterprise Installer manifest payload'
                },
                [pscustomobject]@{
                    Source = Join-Path $externalPayloadRoot 'launcher.zip'
                    Destination = Join-Path $stagedPayloadRoot 'launcher.zip'
                    MaximumBytes = 1GB
                    Label = 'Enterprise Installer Launcher payload'
                },
                [pscustomobject]@{
                    Source = Join-Path $externalPayloadRoot 'runtime.zip'
                    Destination = Join-Path $stagedPayloadRoot 'runtime.zip'
                    MaximumBytes = 8GB
                    Label = 'Enterprise Installer runtime payload'
                })) {
            $copyLease = Open-ProductionReleaseInput `
                -Path ([string]$copy.Source) `
                -Label ([string]$copy.Label) `
                -MaximumBytes ([int64]$copy.MaximumBytes)
            try {
                Copy-ProductionLockedInputToCreateOnlyFile `
                    -Input $copyLease `
                    -DestinationPath ([string]$copy.Destination) `
                    -Label ([string]$copy.Label)
            }
            finally {
                $copyLease.Stream.Dispose()
            }
        }
        $preWaitAdmission = $null
        try {
            $preWaitAdmission =
                Open-EnterpriseInstallerRequestBundleAdmission `
                    -BundleRoot $stagedRequestRoot `
                    -Plan $plan -State $state `
                    -BaseHeadSha256 $baseHeadSha256 `
                    -BaseReceiptSha256 $baseReceiptSha256 `
                    -SourceTree ([string]$sourceCheckout.Tree) `
                    -RequestSchemaPath $installerSigningRequestSchemaV2Path `
                    -Label 'Staged Enterprise Installer request bundle before wait' `
                    -EnforceCurrentLifetime
            $preWaitPins = Get-ProductionBundleAdmissionPins `
                -Admission $preWaitAdmission
        }
        finally {
            Close-ProductionBundleAdmission -Admission $preWaitAdmission
        }
        if ($requestAlreadyPublished) {
            Assert-ProductionBundleTreesEqual `
                -ExpectedRoot $stagedRequestRoot `
                -ActualRoot $publishedRequestRoot `
                -Label 'Exact Enterprise Installer-signing request replay'
        }
        foreach ($lockedOutput in @($trustedBuildResult.LockedOutputs)) {
            [void](Assert-ProductionReleaseInputStillLocked `
                -Descriptor $lockedOutput `
                -Label "Trusted-builder output '$($lockedOutput.FileName)'")
        }
        $trustedBuildResult.Dispose()
        $trustedBuildResult = $null
        Wait-TestOnlyProductionCheckoutAdmission `
            -Staging $bundleStaging `
            -ExpectedFaultPoint 'TestOnlyWaitBeforeInstallerRequestCheckoutAdmission'
        $postWaitAdmission =
            Open-EnterpriseInstallerRequestBundleAdmission `
                -BundleRoot $stagedRequestRoot `
                -Plan $plan -State $state `
                -BaseHeadSha256 $baseHeadSha256 `
                -BaseReceiptSha256 $baseReceiptSha256 `
                -SourceTree ([string]$sourceCheckout.Tree) `
                -RequestSchemaPath $installerSigningRequestSchemaV2Path `
                -Label 'Staged Enterprise Installer request bundle after wait' `
                -EnforceCurrentLifetime
        Assert-ProductionBundleAdmissionMatchesPins `
            -Admission $postWaitAdmission -Pins $preWaitPins `
            -Label 'Staged Enterprise Installer request bundle' `
            -RequireSameFileIdentity
        $postWaitPins = Get-ProductionBundleAdmissionPins `
            -Admission $postWaitAdmission
        $finalAdmission = $null
        try {
            $completion =
                Complete-ValidatedProductionBundleAfterCheckoutAdmission `
                    -Staging $bundleStaging `
                    -Plan $plan `
                    -RelativeBundlePath 'requests\installer-signing.v2' `
                    -DestinationParent (Join-Path $stateLock.StateRoot 'requests') `
                    -PostWaitAdmission $postWaitAdmission `
                    -ExpectedPins $postWaitPins `
                    -Label 'Enterprise Installer request bundle' `
                    -AllowExisting:$requestAlreadyPublished `
                    -ExpectedPreMoveFaultPoint `
                        'TestOnlyWaitBeforeValidatedBundleAtomicMove' `
                    -OpenFinalAdmission {
                        param($bundleRoot)
                        Open-EnterpriseInstallerRequestBundleAdmission `
                            -BundleRoot $bundleRoot `
                            -Plan $plan -State $state `
                            -BaseHeadSha256 $baseHeadSha256 `
                            -BaseReceiptSha256 $baseReceiptSha256 `
                            -SourceTree ([string]$sourceCheckout.Tree) `
                            -RequestSchemaPath `
                                $installerSigningRequestSchemaV2Path `
                            -Label 'Final Enterprise Installer request bundle' `
                            -EnforceCurrentLifetime:(-not $requestAlreadyPublished)
                    }
            $postWaitAdmission = $null
            $publishedPath = [string]$completion.Path
            $finalAdmission = $completion.Admission
            $completedStaging = $bundleStaging
            $bundleStaging = $null
            Remove-ProductionBundleStagingRoot -Staging $completedStaging
            if ($FaultPoint -ceq 'AfterInstallerRequestBundle') {
                throw 'INJECTED-CRASH-AFTER-INSTALLER-REQUEST-BUNDLE'
            }
            $requestData = Get-InstallerSigningRequestReceiptData `
                -RequestInput $finalAdmission.RequestInput `
                -State $state `
                -BaseReceiptSha256 $baseReceiptSha256
            Assert-ProductionBundleAdmissionStillLocked `
                -Admission $finalAdmission `
                -Label 'Final Enterprise Installer request bundle'
            $state = Add-ProductionReleaseReceipt `
                -StateRoot $stateLock.StateRoot `
                -StateSchemaPath $stateSchemaPath `
                -Phase 'INSTALLER_SIGNING_REQUESTED' `
                -ExpectedPreviousPhase 'STABLE_SIGNED_CANDIDATE_IMPORTED' `
                -ExpectedHeadSha256 $baseHeadSha256 `
                -Data $requestData `
                -FaultAfterReceipt:($FaultPoint -ceq 'AfterInstallerRequestReceipt')
            Assert-ProductionBundleAdmissionStillLocked `
                -Admission $finalAdmission `
                -Label 'Final Enterprise Installer request bundle'
            $summary = Get-ProductionReleaseStateSummary `
                -StateRoot $stateLock.StateRoot `
                -StateSchemaPath $stateSchemaPath
            Assert-ProductionBundleAdmissionStillLocked `
                -Admission $finalAdmission `
                -Label 'Final Enterprise Installer request bundle'
            $summary
            return
        }
        finally {
            Close-ProductionBundleAdmission -Admission $finalAdmission
        }
    }

    if ($Phase -eq 'ImportInstallerSignature') {
        if ([int]$state.SchemaVersion -eq 2 -and
            [string]$plan.edition -ceq 'Personal') {
            if ([string]$plan.targetChannel -cne 'pilot' -or
                $null -eq $state.Head -or
                [string]$state.Head.phase -notin @(
                    'INSTALLER_SIGNING_REQUESTED',
                    'INSTALLER_SIGNATURE_IMPORTED')) {
                throw 'NO-GO: Personal Installer signature can only be imported after its exact r6 request.'
            }
            $r6HeadSha256 = if ([string]$state.Head.phase -ceq
                'INSTALLER_SIGNING_REQUESTED') {
                [string]$state.HeadSha256
            }
            else {
                [string]$state.LastReceipt.data.admissionHeadSha256
            }
            if ([string]::IsNullOrWhiteSpace($ExpectedHeadSha256) -or
                $ExpectedHeadSha256 -cne $r6HeadSha256) {
                throw 'ImportInstallerSignature rejected a missing or stale Personal r6 compare-and-swap head.'
            }
            if ([string]::IsNullOrWhiteSpace($ResponsePath)) {
                throw 'ImportInstallerSignature requires -ResponsePath.'
            }

            $requestPath = Join-Path `
                (Join-Path (Join-Path $stateLock.StateRoot 'requests') `
                    'installer-signing.v2') `
                'installer-signing-request.v2.json'
            $requestInput = Read-InstallerSigningContractInput `
                -Path $requestPath `
                -SchemaPath $installerSigningRequestSchemaV2Path `
                -Label 'Admitted Personal Installer signing request v2'
            [void](Assert-InstallerSigningRequestContract `
                -Request $requestInput.Value `
                -InstallerSigningTrust `
                    $plan.externalResponseTrusts.installerSigning `
                -ReleaseManifestTrust $plan.releaseManifestTrust)
            $requestLease = Open-ProductionReleaseInput `
                -Path $requestPath `
                -Label 'Held Personal Installer signing request v2' `
                -MaximumBytes 8MB
            $r6ReceiptInput = Open-ProductionReleaseInput `
                -Path (Join-Path (Join-Path $stateLock.StateRoot 'receipts') `
                    '0006-installer-signing-requested.json') `
                -Label 'Personal r6 Installer-signing receipt' `
                -MaximumBytes 8MB
            $r5ReceiptInput = Open-ProductionReleaseInput `
                -Path (Join-Path (Join-Path $stateLock.StateRoot 'receipts') `
                    '0005-pilot-signed-candidate-imported.json') `
                -Label 'Personal r5 signed-candidate receipt' `
                -MaximumBytes 8MB
            $responseLease = $null
            $externalSignedInput = $null
            try {
                if ([string]$requestLease.Sha256 -cne
                    [string]$requestInput.Sha256) {
                    throw 'Personal r6 request changed while it was being held.'
                }
                $externalResponsePath = [IO.Path]::GetFullPath($ResponsePath)
                if ([IO.Path]::GetFileName($externalResponsePath) -cne
                    'personal-installer-signing-response.v2.json') {
                    throw 'Personal Installer response must name personal-installer-signing-response.v2.json.'
                }
                $externalResponseRoot =
                    [IO.Path]::GetDirectoryName($externalResponsePath)
                [void](Assert-ExactProductionDirectoryInventory `
                    -Path $externalResponseRoot `
                    -Expected ([ordered]@{
                        'personal-installer-signing-response.v2.json' = $false
                        'signed' = $true
                    }) `
                    -Label 'External Personal Installer signing response bundle')
                $externalSignedRoot = Join-Path $externalResponseRoot 'signed'
                [void](Assert-ExactProductionDirectoryInventory `
                    -Path $externalSignedRoot `
                    -Expected ([ordered]@{
                        'Ensou.Dsh.Personal.Installer.exe' = $false
                    }) `
                    -Label 'External signed Personal Installer bundle')
                $responseInput = Read-InstallerSigningContractInput `
                    -Path $externalResponsePath `
                    -SchemaPath $personalInstallerSigningResponseSchemaPath `
                    -Label 'External Personal Installer signing response v2'
                $responseLease = Open-ProductionReleaseInput `
                    -Path $externalResponsePath `
                    -Label 'Held external Personal Installer response v2' `
                    -MaximumBytes 8MB
                if ([string]$responseLease.Sha256 -cne
                    [string]$responseInput.Sha256) {
                    throw 'External Personal Installer response changed while it was being held.'
                }
                $externalSignedInput = Open-ProductionReleaseInput `
                    -Path (Join-Path $externalSignedRoot `
                        'Ensou.Dsh.Personal.Installer.exe') `
                    -Label 'Held external signed Personal Installer' `
                    -MaximumBytes 1GB
                $preparation = [pscustomobject][ordered]@{
                    Status = 'PERSONAL_SHARED_REQUEST_V2_VALIDATED_NO_GO'
                    Blocker = 'INSTALLER_SIGNING_RESPONSE_REQUIRED'
                    ProductionAdmission = 'NO_GO'
                    SharedRequestV2Status =
                        'VALIDATED_PERSONAL_PILOT_EXTERNAL_SIGNER_ELIGIBLE'
                    RequestDraftSha256 = [string]$requestInput.Sha256
                    R5HeadSha256 = [string]$requestInput.Value.baseHeadSha256
                    R5ReceiptSha256 =
                        [string]$state.Receipts[5].data.baseReceiptSha256
                    DependencyBlockers = @()
                    UnsignedArtifactExecution =
                        'FORBIDDEN_AND_NOT_PERFORMED'
                    SignedArtifactExecution = 'NOT_PERFORMED'
                    ExternalSigningRequestEligible = $true
                }
                $payloadExpectation =
                    PersonalInstallerSigningPipeline\Get-PersonalSigningPipelinePayloadExpectation `
                        -Request $requestInput.Value
                $publishedImportRoot = Join-Path `
                    (Join-Path $stateLock.StateRoot 'imports') `
                    'installer-signing.v2'
                $importAlreadyPublished =
                    Test-Path -LiteralPath $publishedImportRoot
                $enforceNewImportLifetime =
                    [string]$state.Head.phase -ceq 'INSTALLER_SIGNING_REQUESTED' -and
                    -not $importAlreadyPublished
                $importResult =
                    PersonalInstallerSigningPipeline\Import-PersonalInstallerSigningPipelineResponse `
                        -Preparation $preparation `
                        -RequestInput $requestLease `
                        -ResponseInput $responseLease `
                        -R6ReceiptInput $r6ReceiptInput `
                        -R5ReceiptInput $r5ReceiptInput `
                        -ExpectedR6HeadSha256 $r6HeadSha256 `
                        -InstallerSigningTrust `
                            $plan.externalResponseTrusts.installerSigning `
                        -ReleaseManifestTrust $plan.releaseManifestTrust `
                        -ExpectedSignerCertificateSha256 `
                            ([string]$plan.authenticodePolicy.signerSha256Thumbprint) `
                        -SignedInstallerInput $externalSignedInput `
                        -PayloadExpectation $payloadExpectation `
                        -EnforceCurrentLifetime:$enforceNewImportLifetime
                if ([string]$importResult.Status -cne
                        'PERSONAL_SIGNING_RESPONSE_VERIFIED_R7_READY_NO_GO' -or
                    [string]$importResult.ProductionAdmission -cne 'NO_GO') {
                    throw 'Personal signing pipeline did not return its exact r7-ready NO_GO result.'
                }

                $bundleStaging = New-ProductionBundleStagingRoot `
                    -Root $stateLock.StateRoot `
                    -Plan $plan `
                    -Purpose installer-import
                $stagedImportRoot = Join-Path `
                    (Join-Path ([string]$bundleStaging.Root) 'imports') `
                    'installer-signing.v2'
                $stagedSignedRoot = Join-Path $stagedImportRoot 'signed'
                [IO.Directory]::CreateDirectory($stagedSignedRoot) | Out-Null
                Copy-ProductionLockedInputToCreateOnlyFile `
                    -Input $responseLease `
                    -DestinationPath (Join-Path $stagedImportRoot `
                        'personal-installer-signing-response.v2.json') `
                    -Label 'Personal Installer signing response v2'
                Copy-ProductionLockedInputToCreateOnlyFile `
                    -Input $externalSignedInput `
                    -DestinationPath (Join-Path $stagedSignedRoot `
                        'Ensou.Dsh.Personal.Installer.exe') `
                    -Label 'Signed Personal Installer'
                $preWaitAdmission = $null
                try {
                    $preWaitAdmission =
                        Open-PersonalInstallerImportBundleAdmission `
                            -BundleRoot $stagedImportRoot `
                            -Plan $plan `
                            -ResponseSchemaPath `
                                $personalInstallerSigningResponseSchemaPath `
                            -RequestInput $requestInput `
                            -R6ReceiptInput $r6ReceiptInput `
                            -R6HeadSha256 $r6HeadSha256 `
                            -Label 'Staged Personal Installer import bundle before wait' `
                            -EnforceCurrentLifetime:$enforceNewImportLifetime
                    $preWaitPins = Get-ProductionBundleAdmissionPins `
                        -Admission $preWaitAdmission
                }
                finally {
                    Close-ProductionBundleAdmission -Admission $preWaitAdmission
                }
                foreach ($locked in @(
                        $requestLease, $responseLease, $externalSignedInput,
                        $r6ReceiptInput, $r5ReceiptInput)) {
                    [void](Assert-ProductionReleaseInputStillLocked `
                        -Descriptor $locked `
                        -Label "Personal r7 held input '$($locked.FileName)'")
                }
                if ($importAlreadyPublished) {
                    Assert-ProductionBundleTreesEqual `
                        -ExpectedRoot $stagedImportRoot `
                        -ActualRoot $publishedImportRoot `
                        -Label 'Exact Personal signed Installer response replay'
                }
                Wait-TestOnlyProductionCheckoutAdmission `
                    -Staging $bundleStaging `
                    -ExpectedFaultPoint `
                        'TestOnlyWaitBeforeInstallerImportCheckoutAdmission'
                $postWaitAdmission =
                    Open-PersonalInstallerImportBundleAdmission `
                        -BundleRoot $stagedImportRoot `
                        -Plan $plan `
                        -ResponseSchemaPath `
                            $personalInstallerSigningResponseSchemaPath `
                        -RequestInput $requestInput `
                        -R6ReceiptInput $r6ReceiptInput `
                        -R6HeadSha256 $r6HeadSha256 `
                        -Label 'Staged Personal Installer import bundle after wait' `
                        -EnforceCurrentLifetime:$enforceNewImportLifetime
                Assert-ProductionBundleAdmissionMatchesPins `
                    -Admission $postWaitAdmission -Pins $preWaitPins `
                    -Label 'Staged Personal Installer import bundle' `
                    -RequireSameFileIdentity
                $postWaitPins = Get-ProductionBundleAdmissionPins `
                    -Admission $postWaitAdmission
                $finalAdmission = $null
                try {
                    $completion =
                        Complete-ValidatedProductionBundleAfterCheckoutAdmission `
                            -Staging $bundleStaging `
                            -Plan $plan `
                            -RelativeBundlePath 'imports\installer-signing.v2' `
                            -DestinationParent (Join-Path $stateLock.StateRoot 'imports') `
                            -PostWaitAdmission $postWaitAdmission `
                            -ExpectedPins $postWaitPins `
                            -Label 'Personal Installer import bundle' `
                            -AllowExisting:$importAlreadyPublished `
                            -ExpectedPreMoveFaultPoint `
                                'TestOnlyWaitBeforeValidatedBundleAtomicMove' `
                            -OpenFinalAdmission {
                                param($bundleRoot)
                                Open-PersonalInstallerImportBundleAdmission `
                                    -BundleRoot $bundleRoot `
                                    -Plan $plan `
                                    -ResponseSchemaPath `
                                        $personalInstallerSigningResponseSchemaPath `
                                    -RequestInput $requestInput `
                                    -R6ReceiptInput $r6ReceiptInput `
                                    -R6HeadSha256 $r6HeadSha256 `
                                    -Label 'Final Personal Installer import bundle' `
                                    -EnforceCurrentLifetime:$enforceNewImportLifetime
                            }
                    $postWaitAdmission = $null
                    $publishedPath = [string]$completion.Path
                    $finalAdmission = $completion.Admission
                    $completedStaging = $bundleStaging
                    $bundleStaging = $null
                    Remove-ProductionBundleStagingRoot -Staging $completedStaging
                    if ($FaultPoint -ceq 'AfterInstallerImportBundle') {
                        throw 'INJECTED-CRASH-AFTER-PERSONAL-INSTALLER-IMPORT-BUNDLE'
                    }
                    $responseData = Get-PersonalInstallerSignatureImportReceiptData `
                        -ResponseInput $finalAdmission.ResponseInput `
                        -RequestInput $requestInput `
                        -R6HeadSha256 $r6HeadSha256 `
                        -R6ReceiptSha256 ([string]$r6ReceiptInput.Sha256) `
                        -R6ReceiptData $state.Receipts[5].data
                    Assert-ProductionBundleAdmissionStillLocked `
                        -Admission $finalAdmission `
                        -Label 'Final Personal Installer import bundle'
                    $state = Add-ProductionReleaseReceipt `
                        -StateRoot $stateLock.StateRoot `
                        -StateSchemaPath $stateSchemaPath `
                        -Phase 'INSTALLER_SIGNATURE_IMPORTED' `
                        -ExpectedPreviousPhase 'INSTALLER_SIGNING_REQUESTED' `
                        -ExpectedHeadSha256 $r6HeadSha256 `
                        -Data $responseData `
                        -FaultAfterReceipt:($FaultPoint -ceq
                            'AfterInstallerImportReceipt')
                    Assert-ProductionBundleAdmissionStillLocked `
                        -Admission $finalAdmission `
                        -Label 'Final Personal Installer import bundle'
                    $summary = Get-ProductionReleaseStateSummary `
                        -StateRoot $stateLock.StateRoot `
                        -StateSchemaPath $stateSchemaPath
                    Assert-ProductionBundleAdmissionStillLocked `
                        -Admission $finalAdmission `
                        -Label 'Final Personal Installer import bundle'
                    $summary
                    return
                }
                finally {
                    Close-ProductionBundleAdmission -Admission $finalAdmission
                }
            }
            finally {
                if ($null -ne $externalSignedInput) {
                    $externalSignedInput.Stream.Dispose()
                }
                if ($null -ne $responseLease) {
                    $responseLease.Stream.Dispose()
                }
                $r5ReceiptInput.Stream.Dispose()
                $r6ReceiptInput.Stream.Dispose()
                $requestLease.Stream.Dispose()
            }
        }
        if ([int]$state.SchemaVersion -ne 2 -or
            [string]$plan.edition -cne 'Enterprise' -or
            [string]$plan.targetChannel -cne 'stable' -or
            $null -eq $state.Head -or
            [string]$state.Head.phase -notin @(
                'INSTALLER_SIGNING_REQUESTED',
                'INSTALLER_SIGNATURE_IMPORTED')) {
            throw 'NO-GO: Enterprise Installer signature can only be imported after r6.'
        }
        $r6HeadSha256 = if ([string]$state.Head.phase -ceq
            'INSTALLER_SIGNING_REQUESTED') {
            [string]$state.HeadSha256
        }
        else {
            [string]$state.LastReceipt.data.admissionHeadSha256
        }
        if ([string]::IsNullOrWhiteSpace($ExpectedHeadSha256)) {
            throw 'ImportInstallerSignature requires -ExpectedHeadSha256 for its exact r6 compare-and-swap.'
        }
        if ($ExpectedHeadSha256 -cne $r6HeadSha256) {
            throw 'ImportInstallerSignature rejected a stale production state head before signed Installer admission.'
        }
        if ([string]::IsNullOrWhiteSpace($ResponsePath)) {
            throw 'ImportInstallerSignature requires -ResponsePath.'
        }
        $requestRoot = Join-Path `
            (Join-Path $stateLock.StateRoot 'requests') `
            'installer-signing.v2'
        $requestJsonLease = Open-CanonicalProductionJsonLease `
            -Path (Join-Path $requestRoot 'installer-signing-request.v2.json') `
            -SchemaPath $installerSigningRequestSchemaV2Path `
            -Label 'Admitted Enterprise Installer-signing request'
        $requestInput = $requestJsonLease.Input
        $requestLease = $requestJsonLease.Descriptor
        $r6ReceiptPath = Join-Path `
            (Join-Path $stateLock.StateRoot 'receipts') `
            '0006-installer-signing-requested.json'
        $r6ReceiptInput = $null
        $externalSignedInput = $null
        $installerVerificationRoot = $null
        $installerVerificationSnapshot = $null
        try {
            $r6ReceiptInput = Open-ProductionReleaseInput `
                -Path $r6ReceiptPath `
                -Label 'Enterprise r6 Installer-signing receipt' `
                -MaximumBytes 8MB
            Assert-ProductionReleaseInputStillLocked `
                -Descriptor $requestLease `
                -Label 'Admitted Enterprise Installer-signing request'
            $externalResponsePath = [IO.Path]::GetFullPath($ResponsePath)
            if ([IO.Path]::GetFileName($externalResponsePath) -cne
                'installer-signing-response.v1.json') {
                throw 'Enterprise Installer-signing response must name installer-signing-response.v1.json.'
            }
            $externalResponseRoot = [IO.Path]::GetDirectoryName($externalResponsePath)
            [void](Assert-ExactProductionDirectoryInventory `
                -Path $externalResponseRoot `
                -Expected ([ordered]@{
                    'installer-signing-response.v1.json' = $false
                    'signed' = $true
                }) `
                -Label 'External Enterprise Installer-signing response bundle')
            $externalSignedRoot = Join-Path $externalResponseRoot 'signed'
            [void](Assert-ExactProductionDirectoryInventory `
                -Path $externalSignedRoot `
                -Expected ([ordered]@{
                    'Ensou.Dsh.Enterprise.Installer.exe' = $false
                }) `
                -Label 'External signed Enterprise Installer bundle')
            $responseInput = Read-InstallerSigningContractInput `
                -Path $externalResponsePath `
                -SchemaPath $installerSigningResponseSchemaPath `
                -Label 'External Enterprise Installer-signing response'
            $publishedImportRoot = Join-Path `
                (Join-Path $stateLock.StateRoot 'imports') `
                'installer-signing.v1'
            $importAlreadyPublished = Test-Path -LiteralPath $publishedImportRoot
            $enforceNewImportLifetime =
                [string]$state.Head.phase -ceq 'INSTALLER_SIGNING_REQUESTED' -and
                -not $importAlreadyPublished
            [void](Assert-InstallerSigningResponseContract `
                -RequestInput $requestInput `
                -ResponseInput $responseInput `
                -R6HeadSha256 $r6HeadSha256 `
                -R6ReceiptSha256 ([string]$r6ReceiptInput.Sha256) `
                -InstallerSigningTrust $plan.externalResponseTrusts.installerSigning `
                -EnforceCurrentLifetime:$enforceNewImportLifetime)
            $externalSignedPath = Join-Path `
                $externalSignedRoot `
                'Ensou.Dsh.Enterprise.Installer.exe'
            $externalSignedInput = Open-ProductionReleaseInput `
                -Path $externalSignedPath `
                -Label 'External signed Enterprise Installer' `
                -MaximumBytes 1GB
            if ([int64]$externalSignedInput.SizeBytes -ne
                    [int64]$responseInput.Value.signedInstaller.sizeBytes -or
                [string]$externalSignedInput.Sha256 -cne
                    [string]$responseInput.Value.signedInstaller.sha256) {
                throw 'External signed Enterprise Installer differs from the authenticated response.'
            }
            $installerVerificationRoot = New-ProductionVerificationRoot `
                -Root $stateLock.StateRoot
            $installerVerificationSnapshot = New-ProductionVerificationSnapshot `
                -VerificationRoot $installerVerificationRoot `
                -Locked $externalSignedInput `
                -FileName 'Ensou.Dsh.Enterprise.Installer.exe' `
                -Label 'Signed Enterprise Installer'
            [void](Assert-SignedInstallerAuthenticode `
                -Path ([string]$installerVerificationSnapshot.Path) `
                -Response $responseInput.Value `
                -ExpectedSignerCertificateSha256 `
                    ([string]$plan.authenticodePolicy.signerSha256Thumbprint))
            Assert-InstallerSigningPayloadSelfCheck `
                -InstallerPath ([string]$installerVerificationSnapshot.Path) `
                -Request $requestInput.Value `
                -SelfCheck $responseInput.Value.payloadSelfCheck `
                -Label 'Signed Enterprise Installer payload self-check' `
                -ExecuteTrustedInstaller
            [void](Assert-ProductionReleaseInputStillLocked `
                -Descriptor $installerVerificationSnapshot `
                -Label 'Signed Enterprise Installer private verification snapshot')
            [void](Assert-ProductionReleaseInputStillLocked `
                -Descriptor $externalSignedInput `
                -Label 'External signed Enterprise Installer')

            $bundleStaging = New-ProductionBundleStagingRoot `
                -Root $stateLock.StateRoot `
                -Plan $plan `
                -Purpose installer-import
            $stagedImportRoot = Join-Path `
                (Join-Path ([string]$bundleStaging.Root) 'imports') `
                'installer-signing.v1'
            $stagedSignedRoot = Join-Path $stagedImportRoot 'signed'
            [IO.Directory]::CreateDirectory($stagedSignedRoot) | Out-Null
            $responseLease = Open-ProductionReleaseInput `
                -Path $externalResponsePath `
                -Label 'External Enterprise Installer-signing response' `
                -MaximumBytes 8MB
            try {
                if ([string]$responseLease.Sha256 -cne [string]$responseInput.Sha256) {
                    throw 'External Enterprise Installer-signing response changed before staging.'
                }
                Copy-ProductionLockedInputToCreateOnlyFile `
                    -Input $responseLease `
                    -DestinationPath (Join-Path $stagedImportRoot 'installer-signing-response.v1.json') `
                    -Label 'Enterprise Installer-signing response'
            }
            finally {
                $responseLease.Stream.Dispose()
            }
            Copy-ProductionLockedInputToCreateOnlyFile `
                -Input $externalSignedInput `
                -DestinationPath (Join-Path $stagedSignedRoot 'Ensou.Dsh.Enterprise.Installer.exe') `
                -Label 'Signed Enterprise Installer'
            $preWaitAdmission = $null
            try {
                $preWaitAdmission =
                    Open-EnterpriseInstallerImportBundleAdmission `
                        -BundleRoot $stagedImportRoot `
                        -Plan $plan -RequestInput $requestInput `
                        -R6ReceiptInput $r6ReceiptInput `
                        -R6HeadSha256 $r6HeadSha256 `
                        -ResponseSchemaPath $installerSigningResponseSchemaPath `
                        -Label 'Staged Enterprise Installer import bundle before wait' `
                        -EnforceCurrentLifetime:$enforceNewImportLifetime
                $preWaitPins = Get-ProductionBundleAdmissionPins `
                    -Admission $preWaitAdmission
            }
            finally {
                Close-ProductionBundleAdmission -Admission $preWaitAdmission
            }
            [void](Assert-ProductionReleaseInputStillLocked `
                -Descriptor $externalSignedInput `
                -Label 'External signed Enterprise Installer')
            Remove-ProductionVerificationSnapshot `
                -Snapshot $installerVerificationSnapshot `
                -Label 'Signed Enterprise Installer'
            $installerVerificationSnapshot = $null
            Remove-ProductionVerificationRoot `
                -VerificationRoot $installerVerificationRoot
            $installerVerificationRoot = $null
            if ($importAlreadyPublished) {
                Assert-ProductionBundleTreesEqual `
                    -ExpectedRoot $stagedImportRoot `
                    -ActualRoot $publishedImportRoot `
                    -Label 'Exact Enterprise signed Installer response replay'
            }
            Wait-TestOnlyProductionCheckoutAdmission `
                -Staging $bundleStaging `
                -ExpectedFaultPoint 'TestOnlyWaitBeforeInstallerImportCheckoutAdmission'
            $postWaitAdmission =
                Open-EnterpriseInstallerImportBundleAdmission `
                    -BundleRoot $stagedImportRoot `
                    -Plan $plan -RequestInput $requestInput `
                    -R6ReceiptInput $r6ReceiptInput `
                    -R6HeadSha256 $r6HeadSha256 `
                    -ResponseSchemaPath $installerSigningResponseSchemaPath `
                    -Label 'Staged Enterprise Installer import bundle after wait' `
                    -EnforceCurrentLifetime:$enforceNewImportLifetime
            Assert-ProductionBundleAdmissionMatchesPins `
                -Admission $postWaitAdmission -Pins $preWaitPins `
                -Label 'Staged Enterprise Installer import bundle' `
                -RequireSameFileIdentity
            $postWaitPins = Get-ProductionBundleAdmissionPins `
                -Admission $postWaitAdmission
            Assert-ProductionReleaseInputStillLocked `
                -Descriptor $requestLease `
                -Label 'Admitted Enterprise Installer-signing request'
            $finalAdmission = $null
            try {
                $completion =
                    Complete-ValidatedProductionBundleAfterCheckoutAdmission `
                        -Staging $bundleStaging `
                        -Plan $plan `
                        -RelativeBundlePath 'imports\installer-signing.v1' `
                        -DestinationParent (Join-Path $stateLock.StateRoot 'imports') `
                        -PostWaitAdmission $postWaitAdmission `
                        -ExpectedPins $postWaitPins `
                        -Label 'Enterprise Installer import bundle' `
                        -AllowExisting:$importAlreadyPublished `
                        -ExpectedPreMoveFaultPoint `
                            'TestOnlyWaitBeforeValidatedBundleAtomicMove' `
                        -OpenFinalAdmission {
                            param($bundleRoot)
                            Open-EnterpriseInstallerImportBundleAdmission `
                                -BundleRoot $bundleRoot `
                                -Plan $plan -RequestInput $requestInput `
                                -R6ReceiptInput $r6ReceiptInput `
                                -R6HeadSha256 $r6HeadSha256 `
                                -ResponseSchemaPath `
                                    $installerSigningResponseSchemaPath `
                                -Label 'Final Enterprise Installer import bundle' `
                                -EnforceCurrentLifetime:$enforceNewImportLifetime
                        }
                $postWaitAdmission = $null
                $publishedPath = [string]$completion.Path
                $finalAdmission = $completion.Admission
                $completedStaging = $bundleStaging
                $bundleStaging = $null
                Remove-ProductionBundleStagingRoot -Staging $completedStaging
                if ($FaultPoint -ceq 'AfterInstallerImportBundle') {
                    throw 'INJECTED-CRASH-AFTER-INSTALLER-IMPORT-BUNDLE'
                }
                $responseData = Get-InstallerSignatureImportReceiptData `
                    -ResponseInput $finalAdmission.ResponseInput `
                    -RequestInput $requestInput `
                    -R6HeadSha256 $r6HeadSha256 `
                    -R6ReceiptSha256 ([string]$r6ReceiptInput.Sha256) `
                    -R6ReceiptData $state.Receipts[5].data
                Assert-ProductionBundleAdmissionStillLocked `
                    -Admission $finalAdmission `
                    -Label 'Final Enterprise Installer import bundle'
                Assert-ProductionReleaseInputStillLocked `
                    -Descriptor $requestLease `
                    -Label 'Admitted Enterprise Installer-signing request'
                $state = Add-ProductionReleaseReceipt `
                    -StateRoot $stateLock.StateRoot `
                    -StateSchemaPath $stateSchemaPath `
                    -Phase 'INSTALLER_SIGNATURE_IMPORTED' `
                    -ExpectedPreviousPhase 'INSTALLER_SIGNING_REQUESTED' `
                    -ExpectedHeadSha256 $r6HeadSha256 `
                    -Data $responseData `
                    -FaultAfterReceipt:($FaultPoint -ceq 'AfterInstallerImportReceipt')
                Assert-ProductionBundleAdmissionStillLocked `
                    -Admission $finalAdmission `
                    -Label 'Final Enterprise Installer import bundle'
                Assert-ProductionReleaseInputStillLocked `
                    -Descriptor $requestLease `
                    -Label 'Admitted Enterprise Installer-signing request'
                $summary = Get-ProductionReleaseStateSummary `
                    -StateRoot $stateLock.StateRoot `
                    -StateSchemaPath $stateSchemaPath
                Assert-ProductionBundleAdmissionStillLocked `
                    -Admission $finalAdmission `
                    -Label 'Final Enterprise Installer import bundle'
                Assert-ProductionReleaseInputStillLocked `
                    -Descriptor $requestLease `
                    -Label 'Admitted Enterprise Installer-signing request'
                $summary
                return
            }
            finally {
                Close-ProductionBundleAdmission -Admission $finalAdmission
            }
        }
        finally {
            try {
                if ($null -ne $installerVerificationSnapshot) {
                    Remove-ProductionVerificationSnapshot `
                        -Snapshot $installerVerificationSnapshot `
                        -Label 'Signed Enterprise Installer'
                    $installerVerificationSnapshot = $null
                }
            }
            finally {
                try {
                    if ($null -ne $installerVerificationRoot) {
                        Remove-ProductionVerificationRoot `
                            -VerificationRoot $installerVerificationRoot
                        $installerVerificationRoot = $null
                    }
                }
                finally {
                    if ($null -ne $externalSignedInput) {
                        $externalSignedInput.Stream.Dispose()
                    }
                    if ($null -ne $r6ReceiptInput) {
                        $r6ReceiptInput.Stream.Dispose()
                    }
                    $requestLease.Stream.Dispose()
                }
            }
        }
    }
}
finally {
    if ($null -ne $trustedBuildResult) {
        $trustedBuildResult.Dispose()
    }
    if ($null -ne $bundleStaging) {
        Remove-ProductionBundleStagingRoot -Staging $bundleStaging
    }
    if ($null -ne $admittedInputs) {
        for ($index = $admittedInputs.Leases.Count - 1; $index -ge 0; $index--) {
            $admittedInputs.Leases[$index].Dispose()
        }
    }
    if ($null -ne $stateLock) {
        $stateLock.Stream.Dispose()
    }
    if ($null -ne $codeAdmission) {
        for ($index = $codeAdmission.Leases.Count - 1; $index -ge 0; $index--) {
            $codeAdmission.Leases[$index].Dispose()
        }
    }
}
