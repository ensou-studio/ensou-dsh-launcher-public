[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$schemaPath = Join-Path $RepositoryRoot 'release\schemas\channel-manifest.schema.json'
$examplesPath = Join-Path $RepositoryRoot 'release\examples'

if (-not (Test-Path -LiteralPath $schemaPath -PathType Leaf)) {
    throw "Manifest schema is missing: $schemaPath"
}

$schemaText = Get-Content -Raw -LiteralPath $schemaPath
if (-not (Test-Json -Json $schemaText -ErrorAction Stop)) {
    throw "Manifest schema is not valid JSON: $schemaPath"
}

$exampleFiles = @(Get-ChildItem -LiteralPath $examplesPath -Filter '*.manifest.json' -File | Sort-Object Name)
if ($exampleFiles.Count -ne 3) {
    throw "Expected exactly three channel examples; found $($exampleFiles.Count)."
}

$documentsByChannel = @{}
foreach ($file in $exampleFiles) {
    $json = Get-Content -Raw -LiteralPath $file.FullName
    if (-not (Test-Json -Json $json -SchemaFile $schemaPath -ErrorAction Stop)) {
        throw "Manifest does not satisfy the schema: $($file.FullName)"
    }

    $document = $json | ConvertFrom-Json -Depth 20
    $expectedChannel = $file.BaseName.Split('.')[0]
    if ($document.channel -cne $expectedChannel) {
        throw "File $($file.Name) must declare channel '$expectedChannel'."
    }
    if ($document.signature.keyId -cne 'example-key-not-for-production') {
        throw 'Example manifests must use the explicit non-production key id.'
    }

    $documentsByChannel[$expectedChannel] = $document
}

$ordered = @(
    $documentsByChannel['lab'],
    $documentsByChannel['pilot'],
    $documentsByChannel['stable']
)
$first = $ordered[0]
foreach ($document in $ordered) {
    if ($document.releaseId -cne $first.releaseId -or
        $document.launcherVersion -cne $first.launcherVersion -or
        $document.minimumBootstrapperVersion -cne $first.minimumBootstrapperVersion -or
        $document.dshVersion -cne $first.dshVersion -or
        $document.artifact.fileName -cne $first.artifact.fileName -or
        $document.artifact.sha256 -cne $first.artifact.sha256 -or
        [int64]$document.artifact.sizeBytes -ne [int64]$first.artifact.sizeBytes) {
        throw 'Lab, Pilot, and Stable examples must demonstrate build-once/promote-many with identical release and artifact identity.'
    }
}

for ($index = 1; $index -lt $ordered.Count; $index++) {
    $previous = [DateTimeOffset]::Parse($ordered[$index - 1].publishedAtUtc)
    $current = [DateTimeOffset]::Parse($ordered[$index].publishedAtUtc)
    if ($current -lt $previous) {
        throw 'Example publication times must not move backwards from Lab to Pilot to Stable.'
    }
}

$sourceMetadataFixture = Join-Path $examplesPath 'source-runtime.metadata.json'
$versionsLockPath = Join-Path $RepositoryRoot 'versions\locked.json'
$versionsLock = Get-Content -Raw -LiteralPath $versionsLockPath |
    ConvertFrom-Json -Depth 100 -DateKind String
$lockedManagedPatchManifestSha256 =
    [string]$versionsLock.managedPatch.manifestSha256
$managedPatchManifestCandidates = @(Get-ChildItem `
    -LiteralPath (Join-Path $RepositoryRoot 'upstream-patches') `
    -Filter 'manifest.json' `
    -File `
    -Recurse |
    Where-Object {
        (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).
            Hash.ToLowerInvariant() -ceq $lockedManagedPatchManifestSha256
    })
if ($managedPatchManifestCandidates.Count -ne 1) {
    throw 'Active versions lock must select exactly one managed patch manifest by SHA-256.'
}
$managedPatchManifestPath = $managedPatchManifestCandidates[0].FullName
$managedPatchRoot = $managedPatchManifestCandidates[0].DirectoryName
$managedPatchManifestBytes = [IO.File]::ReadAllBytes(
    $managedPatchManifestPath)
$managedPatchManifestSha256 = ([Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData(
        $managedPatchManifestBytes))).ToLowerInvariant()
$managedPatchManifest = [Text.UTF8Encoding]::new($false, $true).
    GetString($managedPatchManifestBytes) |
    ConvertFrom-Json -Depth 100 -DateKind String
$managedPatchFilePath = Join-Path `
    $managedPatchRoot `
    ([string]$managedPatchManifest.patch.file)
$managedPatchFile = Get-Item -LiteralPath $managedPatchFilePath
$managedPatchFileSha256 = (Get-FileHash `
    -Algorithm SHA256 `
    -LiteralPath $managedPatchFilePath).Hash.ToLowerInvariant()
if ($managedPatchManifestSha256 -cne $lockedManagedPatchManifestSha256 -or
    [string]$versionsLock.managedPatch.id -cne
        ([string]$managedPatchManifest.base.tag + '-enterprise-managed-v1') -or
    [string]$versionsLock.managedPatch.patchSha256 -cne
        [string]$managedPatchManifest.patch.sha256 -or
    [string]$versionsLock.officialTag -cne
        [string]$managedPatchManifest.base.tag -or
    [string]$versionsLock.officialCommit -cne
        [string]$managedPatchManifest.base.commit -or
    [string]$versionsLock.officialTree -cne
        [string]$managedPatchManifest.base.tree -or
    [int64]$managedPatchManifest.patch.bytes -ne
        [int64]$managedPatchFile.Length -or
    [string]$managedPatchManifest.patch.sha256 -cne
        $managedPatchFileSha256 -or
    [int]$managedPatchManifest.counts.modifiedFiles -ne
        @($managedPatchManifest.base.modifiedPreimages.PSObject.Properties).Count) {
    throw 'Active versions lock, managed patch manifest, and exact patch bytes are not closed over one identity.'
}
$sourceMetadata = & (Join-Path $PSScriptRoot 'Test-SourceRuntimeMetadata.ps1') `
    -MetadataPath $sourceMetadataFixture `
    -ExpectedReleaseId 'managed-v2026.08.25.3' `
    -ExpectedArtifactFileName 'EnsouDshRuntime-managed-v2026.08.25.3-win-x64.zip' `
    -ExpectedArtifactSha256 'ebb4f366dc007da78a1d9168324afd2c0bd4a4da7fcd46e3d0f7d3cb13e22a73'
if ($sourceMetadata.verification.runtimeClosureAgainstPinnedSourceAndLock -ne $true) {
    throw 'Source-runtime metadata fixture did not preserve the pinned source-and-lock closure proof.'
}
if ([int]$sourceMetadata.schemaVersion -ne 2 -or
    $sourceMetadata.promotionEligible -ne $true -or
    $sourceMetadata.artifactType -cne 'ensou-dsh-enterprise-managed-source-runtime' -or
    $sourceMetadata.sourceRepository -cne
        [string]$managedPatchManifest.base.repository -or
    $sourceMetadata.sourceTag -cne
        [string]$managedPatchManifest.base.tag -or
    $sourceMetadata.sourceCommit -cne
        [string]$managedPatchManifest.base.commit -or
    $sourceMetadata.sourceTree -cne
        [string]$managedPatchManifest.base.tree -or
    $sourceMetadata.dshVersion -cne [string]$versionsLock.dshVersion -or
    $sourceMetadata.baseLockfileSha256 -cne
        [string]$versionsLock.baseLockfileSha256 -or
    $sourceMetadata.lockfileSha256 -cne
        [string]$versionsLock.lockfileSha256 -or
    $sourceMetadata.runtimeWebAuthProtocol -cne
        [string]$versionsLock.runtimeWebAuthProtocol -or
    $sourceMetadata.managedPatch.id -cne
        [string]$versionsLock.managedPatch.id -or
    $sourceMetadata.managedPatch.manifestSchema -cne
        [string]$managedPatchManifest.schema -or
    $sourceMetadata.managedPatch.manifestSha256 -cne
        $managedPatchManifestSha256 -or
    $sourceMetadata.managedPatch.patchSha256 -cne
        [string]$managedPatchManifest.patch.sha256 -or
    [int64]$sourceMetadata.managedPatch.patchBytes -ne
        [int64]$managedPatchManifest.patch.bytes -or
    [int]$sourceMetadata.managedPatch.changedFileCount -ne
        [int]$managedPatchManifest.counts.changedFiles -or
    [int]$sourceMetadata.managedPatch.modifiedPreimageCount -ne
        [int]$managedPatchManifest.counts.modifiedFiles -or
    $sourceMetadata.managedPolicy.managedSkillsRootEnvironment -cne 'ENSOU_DSH_ENTERPRISE_SKILLS_ROOT' -or
    $sourceMetadata.managedPolicy.pluginResolutionPolicy -cne 'frozen exact installation map from managed base/web bundles; no ambient fallback' -or
    $sourceMetadata.managedPolicy.sandboxMaximumMode -cne 'workspace-write' -or
    $sourceMetadata.managedPolicy.workspaceRootSource -cne 'process.cwd()' -or
    $sourceMetadata.managedPolicy.restoredSessionCwdPolicy -cne 'must-equal-workspace-root' -or
    $sourceMetadata.managedPolicy.hostCompositionCanonicalSha256 -cne
        [string]$managedPatchManifest.managedPolicy.hostCompositionCanonicalSha256 -or
    $sourceMetadata.managedPolicy.presetCompositionCanonicalSha256 -cne '22044243781ab948f0c649843181835ab2b0b676246583ef675db4ad0f51b3b9' -or
    $sourceMetadata.managedPolicy.presetMetadataCanonicalSha256 -cne '4cb4661afe8d79f3687d1c58b401a2c072131dfd83a4c7389cec9e948f3d5eea' -or
    $sourceMetadata.managedPolicy.loaderRootCanonicalSha256 -cne '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945' -or
    $sourceMetadata.toolchain.nodeVersion -cne '24.19.0' -or
    $sourceMetadata.toolchain.pnpmVersion -cne '11.7.0') {
    throw 'Source-runtime metadata fixture did not preserve the reviewed managed patch and policy identity.'
}

$sourceMetadataText = Get-Content -Raw -LiteralPath $sourceMetadataFixture
$sourceMetadataSchemaPath = Join-Path $RepositoryRoot `
    'release\schemas\source-runtime-metadata.schema.json'
$developmentSourceMetadataSchemaPath = Join-Path $RepositoryRoot `
    'release\schemas\enterprise-development-runtime-metadata.schema.json'
$sourceMetadataSchema = Get-Content `
    -Raw `
    -LiteralPath $sourceMetadataSchemaPath |
    ConvertFrom-Json -Depth 100 -DateKind String
if ([int64]$sourceMetadataSchema.properties.managedPatch.properties.patchBytes.const -ne
        [int64]$managedPatchManifest.patch.bytes -or
    [string]$sourceMetadataSchema.properties.managedPatch.properties.manifestSha256.const -cne
        $managedPatchManifestSha256 -or
    [string]$sourceMetadataSchema.properties.managedPatch.properties.patchSha256.const -cne
        [string]$managedPatchManifest.patch.sha256 -or
    [string]$sourceMetadataSchema.properties.managedPolicy.properties.hostCompositionCanonicalSha256.const -cne
        [string]$managedPatchManifest.managedPolicy.hostCompositionCanonicalSha256) {
    throw 'Production source-runtime schema drifted from the generator-owned alpha.3 patch manifest.'
}
$formerPatchBytesMetadata = $sourceMetadataText |
    ConvertFrom-Json -Depth 64 -DateKind String
$formerPatchBytesMetadata.managedPatch.patchBytes = 247300
if (Test-Json `
        -Json ($formerPatchBytesMetadata | ConvertTo-Json -Depth 64) `
        -SchemaFile $sourceMetadataSchemaPath `
        -ErrorAction SilentlyContinue) {
    throw 'Production source-runtime schema accepted the former stale patch byte count.'
}
$formerHostCompositionMetadata = $sourceMetadataText |
    ConvertFrom-Json -Depth 64 -DateKind String
$formerHostCompositionMetadata.managedPolicy.hostCompositionCanonicalSha256 =
    '8d21f27c58de780ecd9a4cd312cd8af3a9536c9eee423f016e2e8f7ce49ebee1'
if (Test-Json `
        -Json ($formerHostCompositionMetadata | ConvertTo-Json -Depth 64) `
        -SchemaFile $sourceMetadataSchemaPath `
        -ErrorAction SilentlyContinue) {
    throw 'Production source-runtime schema accepted the former stale host composition digest.'
}
if (-not (Test-Json `
        -Json $sourceMetadataText `
        -SchemaFile $developmentSourceMetadataSchemaPath `
        -ErrorAction Stop)) {
    throw 'The production source-runtime fixture must also satisfy the development admission schema.'
}
$metadataContractRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'ensou-source-metadata-contract-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($metadataContractRoot) | Out-Null
try {
    $labMetadata = $sourceMetadataText | ConvertFrom-Json -Depth 64
    $labMetadata.releaseId = 'lab-contract-20260830'
    $labMetadata.promotionEligible = $false
    $labMetadata.artifact.fileName =
        'EnsouDshRuntime-lab-contract-20260830-win-x64.zip'
    $labMetadataPath = Join-Path $metadataContractRoot 'lab.metadata.json'
    $labMetadataJson = $labMetadata | ConvertTo-Json -Depth 64
    [IO.File]::WriteAllText(
        $labMetadataPath,
        $labMetadataJson,
        [Text.UTF8Encoding]::new($false))
    if (-not (Test-Json -Json $labMetadataJson `
            -SchemaFile $sourceMetadataSchemaPath -ErrorAction Stop) -or
        -not (Test-Json -Json $labMetadataJson `
            -SchemaFile $developmentSourceMetadataSchemaPath -ErrorAction Stop)) {
        throw 'Explicit local Lab metadata did not satisfy the release-id identity schemas.'
    }
    $defaultLabRejected = $false
    try {
        & (Join-Path $PSScriptRoot 'Test-SourceRuntimeMetadata.ps1') `
            -MetadataPath $labMetadataPath `
            -ExpectedReleaseId 'lab-contract-20260830' | Out-Null
    }
    catch {
        $defaultLabRejected = $true
    }
    if (-not $defaultLabRejected) {
        throw 'Production metadata admission accepted local Lab metadata by default.'
    }
    $admittedLabMetadata = & (Join-Path $PSScriptRoot `
        'Test-SourceRuntimeMetadata.ps1') `
        -MetadataPath $labMetadataPath `
        -ExpectedReleaseId 'lab-contract-20260830' `
        -AllowLocalLab
    if ($admittedLabMetadata.promotionEligible -ne $false) {
        throw 'Explicit local Lab metadata admission lost promotion eligibility identity.'
    }

    $falseManagedMetadata = $sourceMetadataText | ConvertFrom-Json -Depth 64
    $falseManagedMetadata.promotionEligible = $false
    if (Test-Json `
            -Json ($falseManagedMetadata | ConvertTo-Json -Depth 64) `
            -SchemaFile $sourceMetadataSchemaPath `
            -ErrorAction SilentlyContinue) {
        throw 'Source-runtime schema accepted promotionEligible=false with a managed releaseId.'
    }
    $trueLabMetadata = $labMetadataJson | ConvertFrom-Json -Depth 64
    $trueLabMetadata.promotionEligible = $true
    if (Test-Json `
            -Json ($trueLabMetadata | ConvertTo-Json -Depth 64) `
            -SchemaFile $sourceMetadataSchemaPath `
            -ErrorAction SilentlyContinue) {
        throw 'Source-runtime schema accepted promotionEligible=true with a lab releaseId.'
    }
    $missingEligibilityMetadata = $sourceMetadataText | ConvertFrom-Json -Depth 64
    $missingEligibilityMetadata.PSObject.Properties.Remove('promotionEligible')
    if (Test-Json `
            -Json ($missingEligibilityMetadata | ConvertTo-Json -Depth 64) `
            -SchemaFile $sourceMetadataSchemaPath `
            -ErrorAction SilentlyContinue) {
        throw 'Source-runtime schema accepted metadata with no promotionEligible identity.'
    }
}
finally {
    if (Test-Path -LiteralPath $metadataContractRoot) {
        [IO.Directory]::Delete($metadataContractRoot, $true)
    }
}
$mismatchedRuntimeWebAuthMetadata = $sourceMetadataText.Replace(
    '"runtimeWebAuthProtocol": "browser-launch-cookie-v1"',
    '"runtimeWebAuthProtocol": "legacy-clean-root-v1"',
    [StringComparison]::Ordinal)
if ($mismatchedRuntimeWebAuthMetadata -ceq $sourceMetadataText) {
    throw 'The runtime Web auth protocol mismatch fixture could not be constructed.'
}
if (Test-Json `
        -Json $mismatchedRuntimeWebAuthMetadata `
        -SchemaFile $sourceMetadataSchemaPath `
        -ErrorAction SilentlyContinue) {
    throw 'Production source-runtime metadata accepted the wrong Web auth protocol.'
}
if (Test-Json `
        -Json $mismatchedRuntimeWebAuthMetadata `
        -SchemaFile $developmentSourceMetadataSchemaPath `
        -ErrorAction SilentlyContinue) {
    throw 'Development source-runtime metadata accepted an unreviewed tag/protocol pair.'
}
$mixedRc2RuntimeMetadata = $sourceMetadataText.Replace(
    '"sourceTag": "dsh-v0.1.2-rc.1"',
    '"sourceTag": "dsh-v0.1.1-rc.2"',
    [StringComparison]::Ordinal).Replace(
    '"runtimeWebAuthProtocol": "browser-launch-cookie-v1"',
    '"runtimeWebAuthProtocol": "legacy-clean-root-v1"',
    [StringComparison]::Ordinal)
if ($mixedRc2RuntimeMetadata -ceq $sourceMetadataText -or
    (Test-Json `
        -Json $mixedRc2RuntimeMetadata `
        -SchemaFile $developmentSourceMetadataSchemaPath `
        -ErrorAction SilentlyContinue)) {
    throw 'Development source-runtime metadata accepted an rc.2 label over an alpha source tuple.'
}

$builderPath = Join-Path $RepositoryRoot 'scripts\build-source-runtime.ps1'
$builderText = Get-Content -Raw -LiteralPath $builderPath
$promotionText = Get-Content -Raw -LiteralPath (Join-Path $RepositoryRoot '.github\workflows\promote.yml')
$buildCandidateText = Get-Content -Raw -LiteralPath (Join-Path $RepositoryRoot '.github\workflows\build-candidate.yml')
$publisherText = Get-Content -Raw -LiteralPath (Join-Path $RepositoryRoot 'release\scripts\Publish-SourceRuntimeCandidate.ps1')
if ($builderText -notmatch 'runtimeClosureAgainstPinnedSourceAndLock\s*=\s*\$true') {
    throw 'Source builder does not emit the required runtime-closure proof field.'
}
if ($builderText -notmatch 'ManagedSourcePatch\.psm1' -or
    $builderText -notmatch 'Copy-Item -LiteralPath \$officialGitDirectory' -or
    $builderText -notmatch 'Join-Path \$officialGitDirectory ''commondir''' -or
    $builderText -notmatch 'Official checkout is a linked Git worktree' -or
    $builderText -notmatch 'Invoke-OfficialGitCaptured @\(''ls-files''\)' -or
    $builderText -notmatch 'Apply-ManagedSourcePatch' -or
    $builderText -notmatch 'Assert-ManagedSourcePostimages' -or
    $builderText -notmatch 'Get-CheckoutFilesystemInventorySha256' -or
    $builderText -notmatch 'function Assert-CheckoutFilesystemInventoryUnchanged' -or
    $builderText -notmatch 'Collections\.Generic\.SortedSet\[string\]' -or
    $builderText -notmatch 'Get-CheckoutFilesystemInventoryPathUnion' -or
    $builderText -notmatch '\[StringComparer\]::Ordinal' -or
    $builderText -notmatch 'officialFilesystemInventoryRecords' -or
    $builderText -notmatch 'expected sha256=\$officialFilesystemInventorySha256 records=\$\(\$officialFilesystemInventoryRecords\.Count\)' -or
    $builderText -notmatch 'current sha256=\$currentSha256 records=\$\(\$currentRecords\.Count\)' -or
    $builderText -notmatch 'function Invoke-ReviewedMaterializedCordisConfigGate' -or
    $builderText -notmatch 'apps/cli/tests/profiles/acp/cordis\.yml' -or
    $builderText -notmatch 'snapshots/acp/escalation-approved/cordis\.yml' -or
    $builderText -notmatch '''ls-files'', ''-s'', ''--'', \$linkRelative' -or
    $builderText -notmatch '''hash-object'', ''--no-filters'', ''--'', \$linkPath' -or
    $builderText -notmatch 'function Get-GitBlobObjectId' -or
    $builderText -notmatch 'Get-GitBlobObjectId \$targetBytes' -or
    $builderText -notmatch '8a6e191c8e97ad8f581569c74f922c60aa5797c0' -or
    $builderText -notmatch 'cc8f9609f9ee1ddd230582e1c809ccd2a61018a7' -or
    $builderText -notmatch 'byte-bound to the exact official commit and Git index blobs' -or
    $builderText -notmatch 'Materialized and restored 1 reviewed Git source link' -or
    $builderText -notmatch 'Assert-NoBuildToolingInRuntime' -or
    $builderText.IndexOf('Apply-ManagedSourcePatch', [StringComparison]::Ordinal) -gt
        $builderText.IndexOf("@('install', '--frozen-lockfile')", [StringComparison]::Ordinal) -or
    $builderText -match 'Push-Location\s+\$officialCheckout') {
    throw 'Source builder must apply the indexed managed patch in an isolated tracked-file copy before any package-manager operation.'
}
if ($builderText -notmatch '\[switch\]\$LocalLab' -or
    $builderText -notmatch 'LocalLab mode requires a canonical lab-\* releaseId' -or
    $builderText -notmatch 'Production-candidate mode requires a canonical managed-vYYYY\.MM\.DD\.N releaseId' -or
    $builderText -notmatch '\$promotionEligible\s*=\s*-not \[bool\]\$LocalLab' -or
    $builderText -notmatch 'promotionEligible\s*=\s*\$promotionEligible') {
    throw 'Source builder does not bind explicit LocalLab mode to promotionEligible and the release-id class.'
}
if ($builderText -notmatch '\$MaximumNativeToolPathLengthExclusive\s*=\s*240' -or
    $builderText -notmatch '\$ReviewedLongestNativeToolRelativePath\s*=\s*''node_modules\\\.pnpm\\@oxlint-tsgolint\+win32-x64@7\.0\.2001' -or
    $builderText -notmatch 'function New-ShortSourceStagingRoot' -or
    $builderText -notmatch '\[IO\.Path\]::GetTempPath\(\)' -or
    $builderText -notmatch '''edsh-'' \+ \[guid\]::NewGuid\(\)\.ToString\(''N''\)' -or
    $builderText -notmatch 'Assert-NoReparsePointInPath \$tempParent' -or
    $builderText -notmatch '\$checkout = Join-Path \$stagingRoot ''s''' -or
    $builderText -notmatch '\$productsRoot = Join-Path \$out' -or
    $builderText -notmatch 'Assert-InstalledNativeToolPathBudget \$checkout' -or
    $builderText -notmatch 'Remove-OwnedBuildDirectory' -or
    $builderText -notmatch '\[IO\.FileMode\]::CreateNew' -or
    $builderText -notmatch '\[IO\.Directory\]::Move\(\$productsRoot, \$releaseDirectory\)' -or
    $builderText -match '\$stagingRoot\s*=\s*Join-Path\s+\$out' -or
    $builderText -match 'Join-Path \$stagingRoot ''patched-source''' -or
    $builderText -match 'subst(?:\.exe)?\s' -or
    $builderText -match 'Copy-Item[^\r\n]+tsgolint') {
    throw 'Source builder must use unique link-free short Windows-temp source staging, retain same-volume immutable publication, and enforce the sub-240 native-tool path budget.'
}
if ($builderText.IndexOf('Assert-InstalledNativeToolPathBudget $checkout', [StringComparison]::Ordinal) -gt
        $builderText.IndexOf('managed changed TypeScript lint', [StringComparison]::Ordinal)) {
    throw 'Source builder must validate installed native executable paths before changed-TypeScript lint.'
}
if ($builderText -notmatch '@\(''run'', ''--testTimeout=15000''\) \+ \$managedFocusedTestFiles') {
    throw 'Source builder must give the complete managed composition test a reviewed Windows-clean-build timeout budget.'
}
if ($builderText -notmatch 'windowsExcludedExpectedTests' -or
    $builderText -notmatch 'confines a terminal to the deployment maximum despite a durable danger mode' -or
    $builderText -notmatch 'never executes above a deployment maximum after session restore or per-call approval' -or
    $builderText -notmatch 'rejects a real JSONL-restored outside cwd before bash reaches the executor' -or
    $builderText -notmatch 'Tests\\s\+3 passed') {
    throw 'Source builder must bind the Windows-excluded lane to the exact three reviewed passing tests without a brittle upstream skip count.'
}
if ($builderText -notmatch 'ensou-dsh-toolchain-probe-' -or
    $builderText -match '--dir.+\$checkout.+exec.+node') {
    throw 'Source builder toolchain validation must not let pnpm reconcile the Harness workspace.'
}
if ($builderText -notmatch 'strict-dep-builds=false' -or
    $builderText -notmatch 'expectedIgnoredBuild' -or
    $builderText -notmatch 'reviewed workspace postinstall' -or
    $builderText -notmatch '\.pnpm-workspace-state-v1\.json' -or
    $builderText -notmatch "'pnpm-lock\.yaml', 'pnpm-workspace\.yaml'") {
    throw 'Source builder must fail closed around pnpm deploy build scripts and remove staging-only metadata.'
}
if ($builderText -notmatch 'Restore-RequiredWorkspacePeers' -or
    $builderText -notmatch "peerDependenciesMeta" -or
    $builderText -notmatch "'pack'" -or
    $builderText -notmatch "--dry-run" -or
    $builderText -notmatch "--ignore-workspace" -or
    $builderText -notmatch "--config.ignore-scripts=true" -or
    $builderText -notmatch "'prepack'.+'prepare'.+'postpack'" -or
    $builderText -notmatch 'unreviewed.+lifecycle script' -or
    $builderText.IndexOf('unreviewed $lifecycleName lifecycle script', [StringComparison]::Ordinal) -gt
        $builderText.IndexOf('$packJson = Invoke-Captured', [StringComparison]::Ordinal) -or
    $builderText.IndexOf('$restoredWorkspacePeers = @(Restore-RequiredWorkspacePeers', [StringComparison]::Ordinal) -gt
        $builderText.IndexOf('Materialize-StagedLinks $deployedNodeModules', [StringComparison]::Ordinal)) {
    throw 'Source builder must restore non-optional workspace peers from exact publish files before materializing the deploy tree.'
}
if ($builderText -notmatch 'Normalize-SourceBuildRegionComments' -or
    $builderText -notmatch 'Normalize-GeneratedBinShimTargetComments' -or
    $builderText -notmatch 'Assert-NoEmbeddedBuildRoot' -or
    $builderText -notmatch '<dsh-source>' -or
    $builderText -notmatch '<runtime>/node_modules/' -or
    $builderText -notmatch 'Encoding\]::UTF8' -or
    $builderText -notmatch 'Encoding\]::Unicode' -or
    $builderText -notmatch 'Encoding\]::BigEndianUnicode' -or
    $builderText -notmatch 'GetMaxByteCount' -or
    $builderText -notmatch 'Get-ChildItem -LiteralPath \$Root -File -Recurse -Force' -or
    $builderText -notmatch 'Get-ChildItem -LiteralPath \$runtimeFull -File -Recurse -Force' -or
    $builderText -notmatch 'Get-ChildItem -LiteralPath \$runtimeRoot -File -Recurse -Force' -or
    $builderText -match '\$textExtensions' -or
    $builderText -notmatch 'normalizedBinShimTargetCommentCount' -or
    $builderText.IndexOf('Normalize-GeneratedBinShimTargetComments', [StringComparison]::Ordinal) -gt
        $builderText.IndexOf('Assert-PortableBinShims $deployedNodeModules', [StringComparison]::Ordinal) -or
    $builderText.IndexOf(
        'Assert-NoEmbeddedBuildRoot $runtimeRoot @(',
        [StringComparison]::Ordinal) -lt
        $builderText.IndexOf("Set-Content -LiteralPath (Join-Path `$runtimeRoot 'source-build.json')", [StringComparison]::Ordinal) -or
    $builderText.IndexOf(
        'Assert-NoEmbeddedBuildRoot $runtimeRoot @(',
        [StringComparison]::Ordinal) -gt
        $builderText.IndexOf("`$hashManifest = Join-Path `$runtimeRoot 'runtime-files.sha256'", [StringComparison]::Ordinal)) {
    throw 'Source builder must normalize reviewed source-only comments and raw-scan every final runtime file for checkout or staging roots.'
}
if ($builderText -notmatch "reviewed workspace postinstall'\s*\r?\n\s*Assert-CheckoutInputsUnchanged" -or
    $builderText.LastIndexOf('Assert-CheckoutInputsUnchanged', [StringComparison]::Ordinal) -lt
        $builderText.IndexOf("Write-Step '7/10 smoke-test", [StringComparison]::Ordinal)) {
    throw 'Source builder must recheck the official checkout after reviewed scripts and final runtime smoke.'
}

$patchRoot = Join-Path $RepositoryRoot 'upstream-patches'
$patchIndexPath = Join-Path $patchRoot 'index.json'
$patchIndex = Get-Content -Raw -LiteralPath $patchIndexPath | ConvertFrom-Json -Depth 20
$patchEntries = @($patchIndex.entries)
$expectedPatchIds = @(
    'dsh-v0.1.1-rc.2-enterprise-managed-v1',
    'dsh-v0.1.2-alpha.1-enterprise-managed-v1',
    'dsh-v0.1.2-alpha.3-enterprise-managed-v1',
    'dsh-v0.1.2-rc.1-enterprise-managed-v1'
)
if ($patchIndex.schema -cne 'ensou.dsh.upstream-patch-index.v1' -or
    $patchEntries.Count -ne $expectedPatchIds.Count -or
    (@($patchEntries.id) -join "`n") -cne ($expectedPatchIds -join "`n")) {
    throw 'Installation-owned managed patch index must contain reviewed rc.2/alpha history and current rc.1 bundle in canonical order.'
}
foreach ($patchEntry in $patchEntries) {
    $patchDirectory = Join-Path $patchRoot (([string]$patchEntry.directory) -replace '/', '\')
    $patchManifestPath = Join-Path $patchDirectory 'manifest.json'
    $patchFilePath = Join-Path $patchDirectory '0001-ensou-enterprise-managed-boot.patch'
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $patchManifestPath).Hash.ToLowerInvariant() -cne
            [string]$patchEntry.manifestSha256 -or
        (Get-FileHash -Algorithm SHA256 -LiteralPath $patchFilePath).Hash.ToLowerInvariant() -cne
            [string]$patchEntry.patchSha256) {
        throw "Installation-owned managed patch bytes do not match the indexed digests for $($patchEntry.id)."
    }
}
$currentPatchEntry = @($patchEntries | Where-Object {
    [string]$_.id -ceq [string]$sourceMetadata.managedPatch.id
})
if ($currentPatchEntry.Count -ne 1 -or
    [string]$currentPatchEntry[0].tag -cne [string]$sourceMetadata.sourceTag -or
    [string]$currentPatchEntry[0].commit -cne [string]$sourceMetadata.sourceCommit -or
    [string]$currentPatchEntry[0].tree -cne [string]$sourceMetadata.sourceTree -or
    [string]$currentPatchEntry[0].manifestSha256 -cne
        [string]$sourceMetadata.managedPatch.manifestSha256 -or
    [string]$currentPatchEntry[0].patchSha256 -cne
        [string]$sourceMetadata.managedPatch.patchSha256) {
    throw 'Current source-runtime metadata is not bound to exactly one indexed alpha patch bundle.'
}

# Execute only the scanner and its path helper from the builder AST. These
# behavior probes prove hidden/extensionless, uncommon-extension, Unicode,
# binary UTF-16, and cross-buffer detection without running the builder body.
$tokens = $null
$parseErrors = $null
$builderAst = [Management.Automation.Language.Parser]::ParseFile(
    $builderPath,
    [ref]$tokens,
    [ref]$parseErrors)
if ($parseErrors.Count -ne 0) {
    throw "Source builder has parse errors: $($parseErrors[0].Message)"
}
foreach ($functionName in @(
    'Get-FullProviderPath',
    'Test-SamePath',
    'Test-IsWithin',
    'Assert-NoReparsePointInPath',
    'Assert-NativeToolPathBudget',
    'New-ShortSourceStagingRoot',
    'Remove-OwnedBuildDirectory',
    'Assert-NoEmbeddedBuildRoot',
    'Get-CheckoutFilesystemInventoryPathUnion')) {
    $definitions = @($builderAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $functionName
    }, $true))
    if ($definitions.Count -ne 1) {
        throw "Expected one $functionName definition in the source builder."
    }
    . ([scriptblock]::Create($definitions[0].Extent.Text))
}

$inventoryExpected = [Collections.Generic.Dictionary[string, string]]::new(
    [StringComparer]::Ordinal)
$inventoryCurrent = [Collections.Generic.Dictionary[string, string]]::new(
    [StringComparer]::Ordinal)
$inventoryExpected.Add('removed.txt', 'expected removed')
$inventoryExpected.Add('Case.txt', 'expected upper case')
$inventoryCurrent.Add('added.txt', 'current added')
$inventoryCurrent.Add('case.txt', 'current lower case')
$inventoryUnion = @(Get-CheckoutFilesystemInventoryPathUnion `
    $inventoryExpected $inventoryCurrent)
$expectedInventoryUnion = [string[]]@(
    'removed.txt', 'Case.txt', 'added.txt', 'case.txt')
[Array]::Sort($expectedInventoryUnion, [StringComparer]::Ordinal)
if ($inventoryUnion.Count -ne $expectedInventoryUnion.Count -or
    [string]::Join("`n", $inventoryUnion) -cne
        [string]::Join("`n", $expectedInventoryUnion) -or
    $inventoryUnion -cnotcontains 'Case.txt' -or
    $inventoryUnion -cnotcontains 'case.txt') {
    throw 'Checkout inventory union lost an added, removed, or case-sensitive path.'
}

$MaximumNativeToolPathLengthExclusive = 240
$ReviewedLongestNativeToolRelativePath = 'node_modules\.pnpm\@oxlint-tsgolint+win32-x64@7.0.2001\node_modules\@oxlint-tsgolint\win32-x64\tsgolint.exe'
$shortStagingProbes = @()
$cleanupControl = $null
try {
    foreach ($probeIndex in 1..2) {
        $probe = New-ShortSourceStagingRoot `
            (Join-Path $RepositoryRoot 'out\contract-staging-probe') `
            'C:\Agents\deepseek' `
            $RepositoryRoot
        $shortStagingProbes += $probe
    }
    if (Test-SamePath $shortStagingProbes[0].Root $shortStagingProbes[1].Root) {
        throw 'Short staging reservations were not unique.'
    }

    $expectedTempParent = Get-FullProviderPath ([IO.Path]::GetTempPath()) -MustExist
    foreach ($probe in $shortStagingProbes) {
        $probeRoot = Get-FullProviderPath ([string]$probe.Root) -MustExist
        $probeItem = Get-Item -LiteralPath $probeRoot -Force
        $plannedTsgolint = Get-FullProviderPath (
            Join-Path (Join-Path $probeRoot 's') $ReviewedLongestNativeToolRelativePath)
        if (-not (Test-SamePath ([string]$probe.Parent) $expectedTempParent) -or
            -not (Test-SamePath (Split-Path -Parent $probeRoot) $expectedTempParent) -or
            (Split-Path -Leaf $probeRoot) -cnotmatch '^edsh-[0-9a-f]{32}$' -or
            ($probeItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $plannedTsgolint.Length -ge $MaximumNativeToolPathLengthExclusive) {
            throw "Short staging probe violated temp-parent, identity, link, or native-path budget: $probeRoot"
        }
    }

    $driveRoot = [IO.Path]::GetPathRoot($expectedTempParent)
    $passSourceLength = ($MaximumNativeToolPathLengthExclusive - 1) - 1 -
        $ReviewedLongestNativeToolRelativePath.Length
    $rejectSourceLength = $MaximumNativeToolPathLengthExclusive - 1 -
        $ReviewedLongestNativeToolRelativePath.Length
    if ($passSourceLength -le $driveRoot.Length) {
        throw 'Native-tool boundary probe cannot construct a rooted source path.'
    }
    $passSource = $driveRoot + ('x' * ($passSourceLength - $driveRoot.Length))
    $rejectSource = $driveRoot + ('x' * ($rejectSourceLength - $driveRoot.Length))
    Assert-NativeToolPathBudget $passSource @($ReviewedLongestNativeToolRelativePath)
    $budgetRejected = $false
    try {
        Assert-NativeToolPathBudget $rejectSource @($ReviewedLongestNativeToolRelativePath)
    } catch {
        if ($_.Exception.Message -notlike 'Staged native-tool path is 240 characters*') {
            throw
        }
        $budgetRejected = $true
    }
    if (-not $budgetRejected) {
        throw 'Native-tool path budget accepted a 240-character executable path.'
    }

    $cleanupControl = Join-Path $expectedTempParent (
        'ensou-cleanup-control-' + [guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($cleanupControl) | Out-Null
    $unsafeCleanupRejected = $false
    try {
        Remove-OwnedBuildDirectory `
            $cleanupControl $expectedTempParent '^edsh-[0-9a-f]{32}$'
    } catch {
        if ($_.Exception.Message -notlike 'Refusing unsafe owned-build cleanup:*') {
            throw
        }
        $unsafeCleanupRejected = $true
    }
    if (-not $unsafeCleanupRejected -or -not (Test-Path -LiteralPath $cleanupControl)) {
        throw 'Owned-build cleanup did not fail closed for an unowned temp directory.'
    }
} finally {
    if ($cleanupControl -and (Test-Path -LiteralPath $cleanupControl)) {
        [IO.Directory]::Delete($cleanupControl, $true)
    }
    foreach ($probe in $shortStagingProbes) {
        if ($probe.Root -and (Test-Path -LiteralPath $probe.Root)) {
            Remove-OwnedBuildDirectory `
                ([string]$probe.Root) ([string]$probe.Parent) '^edsh-[0-9a-f]{32}$'
        }
    }
}

$scannerProbeRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'ensou-dsh-build-path-scanner-' + [guid]::NewGuid().ToString('N'))
$scannerBuildRoot = Join-Path $scannerProbeRoot 'checkout-root'
[IO.Directory]::CreateDirectory($scannerBuildRoot) | Out-Null
try {
    function Assert-ScannerRejects(
        [string]$Name,
        [byte[]]$Payload,
        [string]$BuildRoot = $scannerBuildRoot,
        [IO.FileAttributes]$Attributes = [IO.FileAttributes]::Normal
    ) {
        $caseRoot = Join-Path $scannerProbeRoot $Name
        [IO.Directory]::CreateDirectory($caseRoot) | Out-Null
        $probePath = Join-Path $caseRoot $Name
        [IO.File]::WriteAllBytes($probePath, $Payload)
        if ($Attributes -ne [IO.FileAttributes]::Normal) {
            [IO.File]::SetAttributes($probePath, $Attributes)
        }
        try {
            $rejected = $false
            try {
                Assert-NoEmbeddedBuildRoot $caseRoot @($BuildRoot)
            } catch {
                if ($_.Exception.Message -notlike 'Runtime file contains an embedded build root*') {
                    throw
                }
                $rejected = $true
            }
            if (-not $rejected) {
                throw "Raw build-path scanner did not reject probe: $Name"
            }
        } finally {
            if (Test-Path -LiteralPath $probePath) {
                [IO.File]::SetAttributes($probePath, [IO.FileAttributes]::Normal)
            }
        }
    }

    $forwardSlashRoot = $scannerBuildRoot.Replace('\', '/')
    Assert-ScannerRejects 'uncommon-extension.mts' (
        [Text.Encoding]::UTF8.GetBytes("export const path = '$forwardSlashRoot/lib'"))
    Assert-ScannerRejects 'extensionless' (
        [Text.Encoding]::UTF8.GetBytes($scannerBuildRoot.Replace('\', '\\')))
    Assert-ScannerRejects 'hidden-system-extensionless' (
        [Text.Encoding]::UTF8.GetBytes($forwardSlashRoot)) `
        $scannerBuildRoot `
        ([IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System)
    $hiddenContainer = Join-Path $scannerProbeRoot 'hidden-directory-container'
    $hiddenDirectory = Join-Path $hiddenContainer 'hidden-child'
    [IO.Directory]::CreateDirectory($hiddenDirectory) | Out-Null
    [IO.File]::WriteAllBytes(
        (Join-Path $hiddenDirectory 'payload'),
        [Text.Encoding]::UTF8.GetBytes($forwardSlashRoot))
    [IO.File]::SetAttributes(
        $hiddenDirectory,
        [IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System -bor
            [IO.FileAttributes]::Directory)
    try {
        $hiddenDirectoryRejected = $false
        try {
            Assert-NoEmbeddedBuildRoot $hiddenContainer @($scannerBuildRoot)
        } catch {
            if ($_.Exception.Message -notlike 'Runtime file contains an embedded build root*') {
                throw
            }
            $hiddenDirectoryRejected = $true
        }
        if (-not $hiddenDirectoryRejected) {
            throw 'Raw build-path scanner did not inspect a hidden directory.'
        }
    } finally {
        [IO.File]::SetAttributes($hiddenDirectory, [IO.FileAttributes]::Directory)
    }
    Assert-ScannerRejects 'utf16le.bin' (
        [Text.Encoding]::Unicode.GetBytes("prefix $scannerBuildRoot suffix"))

    $unicodeScannerBuildRoot = Join-Path $scannerProbeRoot 'Café-BuildRoot'
    [IO.Directory]::CreateDirectory($unicodeScannerBuildRoot) | Out-Null
    $unicodeCaseVariant = $unicodeScannerBuildRoot.ToUpperInvariant()
    Assert-ScannerRejects 'unicode-case-utf8.data' (
        [Text.Encoding]::UTF8.GetBytes("prefix $unicodeCaseVariant suffix")) `
        $unicodeScannerBuildRoot
    Assert-ScannerRejects 'unicode-case-utf16le.data' (
        [Text.Encoding]::Unicode.GetBytes("prefix $unicodeCaseVariant suffix")) `
        $unicodeScannerBuildRoot
    Assert-ScannerRejects 'unicode-case-utf16be.data' (
        [Text.Encoding]::BigEndianUnicode.GetBytes("prefix $unicodeCaseVariant suffix")) `
        $unicodeScannerBuildRoot

    $boundaryPrefix = [byte[]]::new((1024 * 1024) - 5)
    [Array]::Fill[byte]($boundaryPrefix, 0x41)
    $boundaryNeedle = [Text.Encoding]::UTF8.GetBytes($forwardSlashRoot)
    $boundaryPayload = [byte[]]::new($boundaryPrefix.Length + $boundaryNeedle.Length)
    [Buffer]::BlockCopy($boundaryPrefix, 0, $boundaryPayload, 0, $boundaryPrefix.Length)
    [Buffer]::BlockCopy(
        $boundaryNeedle,
        0,
        $boundaryPayload,
        $boundaryPrefix.Length,
        $boundaryNeedle.Length)
    Assert-ScannerRejects 'cross-buffer.dat' $boundaryPayload

    function New-CrossBufferPayload([byte[]]$Needle, [int]$SplitOffset) {
        if ($SplitOffset -le 0 -or $SplitOffset -ge $Needle.Length) {
            throw 'Cross-buffer split must be inside the encoded needle.'
        }
        $prefixLength = (1024 * 1024) - $SplitOffset
        $payload = [byte[]]::new($prefixLength + $Needle.Length)
        [Array]::Fill[byte]($payload, 0x41, 0, $prefixLength)
        [Buffer]::BlockCopy($Needle, 0, $payload, $prefixLength, $Needle.Length)
        return $payload
    }

    $accentIndex = $unicodeCaseVariant.IndexOf('É', [StringComparison]::Ordinal)
    if ($accentIndex -lt 0) { throw 'Unicode scanner probe has no case-variant accent.' }
    $unicodeUtf8Needle = [Text.Encoding]::UTF8.GetBytes($unicodeCaseVariant)
    $unicodeUtf8Split = [Text.Encoding]::UTF8.GetByteCount(
        $unicodeCaseVariant.Substring(0, $accentIndex)) + 1
    Assert-ScannerRejects 'unicode-case-cross-buffer-utf8.data' (
        New-CrossBufferPayload $unicodeUtf8Needle $unicodeUtf8Split) `
        $unicodeScannerBuildRoot

    $unicodeUtf16Needle = [Text.Encoding]::Unicode.GetBytes($unicodeCaseVariant)
    $unicodeUtf16Split = [Text.Encoding]::Unicode.GetByteCount(
        $unicodeCaseVariant.Substring(0, $accentIndex)) + 1
    Assert-ScannerRejects 'unicode-case-cross-buffer-utf16le.data' (
        New-CrossBufferPayload $unicodeUtf16Needle $unicodeUtf16Split) `
        $unicodeScannerBuildRoot

    $unicodeUtf16BeNeedle = [Text.Encoding]::BigEndianUnicode.GetBytes($unicodeCaseVariant)
    $unicodeUtf16BeSplit = [Text.Encoding]::BigEndianUnicode.GetByteCount(
        $unicodeCaseVariant.Substring(0, $accentIndex)) + 1
    Assert-ScannerRejects 'unicode-case-cross-buffer-utf16be.data' (
        New-CrossBufferPayload $unicodeUtf16BeNeedle $unicodeUtf16BeSplit) `
        $unicodeScannerBuildRoot

    $lengthChangingUpper = [string]::new([char]0x023A, 128)
    $lengthChangingLower = [string]::new([char]0x2C65, 128)
    if (-not [string]::Equals(
            $lengthChangingUpper,
            $lengthChangingLower,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Runtime does not expose the expected length-changing Unicode case pair.'
    }
    $lengthChangingBuildRoot = Join-Path $scannerProbeRoot $lengthChangingUpper
    [IO.Directory]::CreateDirectory($lengthChangingBuildRoot) | Out-Null
    $lengthChangingVariant = $lengthChangingBuildRoot.ToLowerInvariant()
    $lengthChangingUtf8Needle = [Text.Encoding]::UTF8.GetBytes($lengthChangingVariant)
    Assert-ScannerRejects 'unicode-length-changing-cross-buffer-utf8.data' (
        New-CrossBufferPayload `
            $lengthChangingUtf8Needle `
            ($lengthChangingUtf8Needle.Length - 1)) `
        $lengthChangingBuildRoot

    $splitFilesRoot = Join-Path $scannerProbeRoot 'cross-file-control'
    [IO.Directory]::CreateDirectory($splitFilesRoot) | Out-Null
    $splitPoint = [int]($boundaryNeedle.Length / 2)
    [IO.File]::WriteAllBytes(
        (Join-Path $splitFilesRoot 'first-half'),
        $boundaryNeedle[0..($splitPoint - 1)])
    [IO.File]::WriteAllBytes(
        (Join-Path $splitFilesRoot 'second-half'),
        $boundaryNeedle[$splitPoint..($boundaryNeedle.Length - 1)])
    Assert-NoEmbeddedBuildRoot $splitFilesRoot @($scannerBuildRoot)

    $cleanRoot = Join-Path $scannerProbeRoot 'clean'
    [IO.Directory]::CreateDirectory($cleanRoot) | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $cleanRoot 'clean.svg'),
        '<svg><!-- C:/unrelated/build/path --></svg>')
    Assert-NoEmbeddedBuildRoot $cleanRoot @($scannerBuildRoot)
} finally {
    if (Test-Path -LiteralPath $scannerProbeRoot) {
        [IO.Directory]::Delete($scannerProbeRoot, $true)
    }
}

$enterpriseSchemaNames = @(
    'enterprise-release-set-v2.schema.json',
    'certified-distribution-receipt-v1.schema.json',
    'certified-distribution-receipt-authentication-v1.schema.json',
    'enterprise-stable-promotion-authorization-v1.schema.json',
    'enterprise-release-policy-handoff-v1.schema.json',
    'enterprise-local-data-compatibility-certification-receipt-v1.schema.json',
    'enterprise-local-data-compatibility-evidence-v1.schema.json',
    'enterprise-local-data-forward-result-v1.schema.json',
    'enterprise-local-data-rollback-result-v1.schema.json',
    'enterprise-local-data-api-lane-result-v1.schema.json',
    'managed-plugin-harness-compatibility-receipt-v1.schema.json',
    'managed-plugin-execution-admission-receipt-v1.schema.json',
    'enterprise-plugin-promotion-journal-authorization-v1.schema.json',
    'enterprise-pilot-readiness-v1.schema.json',
    'enterprise-pilot-readiness-report-v1.schema.json',
    'enterprise-windows-pilot-evidence-envelope-v2.schema.json',
    'enterprise-windows-pilot-evidence-body-v2.schema.json',
    'enterprise-windows-pilot-evidence-collection-v1.schema.json',
    'enterprise-windows-pilot-attestation-request-v1.schema.json',
    'enterprise-windows-pilot-gate-contract-v2.schema.json',
    'enterprise-windows-pilot-gate-receipt-v2.schema.json',
    'enterprise-windows-pilot-verification-report-v2.schema.json'
)
$enterpriseSchemas = @{}
foreach ($schemaName in $enterpriseSchemaNames) {
    $path = Join-Path $RepositoryRoot "release\schemas\$schemaName"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Enterprise release schema is missing: $path"
    }
    $json = Get-Content -Raw -LiteralPath $path
    if (-not (Test-Json -Json $json -ErrorAction Stop)) {
        throw "Enterprise release schema is invalid JSON: $path"
    }
    $enterpriseSchemas[$schemaName] = $path
}
if ($builderText -notmatch 'function Read-RuntimeWebAuthProtocolMetadata' -or
    $builderText -notmatch 'assembledRuntimeWebAuthProtocol' -or
    $builderText -notmatch 'extractedRuntimeWebAuthProtocol' -or
    $builderText -notmatch 'runtimeWebAuthProtocol\s*=\s*\$extractedRuntimeWebAuthProtocol') {
    throw 'Source builder does not bind the runtime Web authentication protocol through assembled, extracted, and external immutable metadata.'
}

$pilotGateContractPath = Join-Path $RepositoryRoot 'release\enterprise-windows-pilot-gate-contract-v2.json'
if (-not (Test-Path -LiteralPath $pilotGateContractPath -PathType Leaf) -or
    -not (Test-Json `
        -Json (Get-Content -Raw -LiteralPath $pilotGateContractPath) `
        -SchemaFile $enterpriseSchemas['enterprise-windows-pilot-gate-contract-v2.schema.json'] `
        -ErrorAction Stop)) {
    throw 'Enterprise Windows Pilot gate contract does not satisfy its exact schema.'
}
$pilotGateContract = Get-Content -Raw -LiteralPath $pilotGateContractPath |
    ConvertFrom-Json -Depth 16
$pilotGateContractCanonicalBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
    ($pilotGateContract | ConvertTo-Json -Depth 16 -Compress))
$pilotGateContractCanonicalSha256 = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData($pilotGateContractCanonicalBytes)).ToLowerInvariant()
if ($pilotGateContractCanonicalSha256 -cne
    'a7fff40aad6690d12042d62ba1a8deb80e36431abdd62bc4874fa04388d26331') {
    throw 'Enterprise Windows Pilot gate contract does not match its pinned canonical digest.'
}

$personalSchemaNames = @(
    'personal-lifecycle-evidence-receipt-v1.schema.json',
    'personal-certified-distribution-receipt-v1.schema.json',
    'personal-certified-distribution-receipt-v2.schema.json'
)
$personalSchemas = @{}
foreach ($schemaName in $personalSchemaNames) {
    $path = Join-Path $RepositoryRoot "release\schemas\$schemaName"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Personal release schema is missing: $path"
    }
    $json = Get-Content -Raw -LiteralPath $path
    if (-not (Test-Json -Json $json -ErrorAction Stop)) {
        throw "Personal release schema is invalid JSON: $path"
    }
    $personalSchemas[$schemaName] = $path
}

$personalLifecycleSchema = Get-Content -Raw -LiteralPath `
    $personalSchemas['personal-lifecycle-evidence-receipt-v1.schema.json'] |
    ConvertFrom-Json -Depth 64
if ($personalLifecycleSchema.properties.receiptType.const -cne `
        'ensou-dsh-personal-certified-lifecycle-evidence' -or
    $personalLifecycleSchema.properties.channel.const -cne 'pilot' -or
    @($personalLifecycleSchema.properties.kind.enum).Count -ne 3) {
    throw 'Personal lifecycle schema no longer fixes the receipt identity and three evidence kinds.'
}

$personalDistributionSchema = Get-Content -Raw -LiteralPath `
    $personalSchemas['personal-certified-distribution-receipt-v2.schema.json'] |
    ConvertFrom-Json -Depth 64
$personalDistributionRequired = @($personalDistributionSchema.required)
$personalInstallerRequired = @($personalDistributionSchema.'$defs'.installer.required)
$personalGateRequired = @(
    $personalDistributionSchema.'$defs'.productionGateEvidence.required)
if ($personalDistributionSchema.properties.schemaVersion.const -ne 2 -or
    -not $personalDistributionRequired.Contains('productionGateEvidence') -or
    -not $personalInstallerRequired.Contains('signatureType') -or
    $personalDistributionSchema.'$defs'.installer.properties.fileName.const -cne
        'Ensou.Dsh.Personal.Installer.exe' -or
    $personalDistributionSchema.'$defs'.installer.properties.authenticodeStatus.const -cne
        'Valid' -or
    $personalDistributionSchema.'$defs'.installer.properties.signatureType.const -cne
        'Authenticode' -or
    $personalDistributionSchema.'$defs'.installer.properties.timestamped.const -ne $true -or
    $personalDistributionSchema.'$defs'.installer.properties.signerSha256Thumbprint.'$ref' -cne
        '#/$defs/sha256' -or
    $personalDistributionSchema.'$defs'.productionGateEvidence.properties.evidenceType.const -cne
        'ensou-dsh-personal-production-artifact-gate') {
    throw 'Personal distribution receipt v2 no longer fixes the production gate and official signed Installer identity.'
}
foreach ($required in @(
    'evidenceType',
    'releaseSetId',
    'evidenceSizeBytes',
    'evidenceSha256',
    'compiledTrustSha256',
    'validatedAtUtc')) {
    if (-not $personalGateRequired.Contains($required)) {
        throw "Personal distribution receipt v2 no longer requires production gate field $required."
    }
}
$personalCertificationRequired = @(
    $personalDistributionSchema.properties.certification.required)
foreach ($required in @(
    'cleanDeviceLifecycle',
    'twoUpdateUpgradeLifecycle',
    'failureRecoveryLifecycle')) {
    if (-not $personalCertificationRequired.Contains($required)) {
        throw "Personal distribution schema no longer requires $required."
    }
}

$personalReceiptContractProject = Join-Path `
    $RepositoryRoot `
    'tests\Ensou.Dsh.Personal.FeedPromoterTests\Ensou.Dsh.Personal.FeedPromoterTests.csproj'
$personalReceiptContractOutput = @(& dotnet run `
    --project $personalReceiptContractProject `
    --configuration Release `
    -- `
    --distribution-receipt-schema-contract 2>&1)
$personalReceiptContractExitCode = $LASTEXITCODE
$personalReceiptContractPass = `
    $personalReceiptContractOutput -contains `
    'PERSONAL-DISTRIBUTION-RECEIPT-SCHEMA-CONTRACT-PASS'
if ($personalReceiptContractExitCode -ne 0 -or -not $personalReceiptContractPass) {
    $personalReceiptContractDetails = `
        ($personalReceiptContractOutput | Out-String).Trim()
    throw "Personal distribution receipt producer-to-v2-schema contract failed. " +
        "Exit code: $personalReceiptContractExitCode. $personalReceiptContractDetails"
}

$personalLifecycleContractText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Personal.FeedPromoter\PersonalLifecycleEvidenceContracts.cs')
$personalFeedContractText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Personal.FeedPromoter\PersonalFeedContracts.cs')
$personalPromoterText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Personal.FeedPromoter\PersonalFeedPromoter.cs')
$personalPromoterProgramText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Personal.FeedPromoter\Program.cs')
foreach ($required in @(
    'CleanDeviceLifecycle',
    'TwoUpdateUpgradeLifecycle',
    'FailureRecoveryLifecycle',
    'ReceiptSizeBytes',
    'ReceiptSha256',
    'LocalDataWitnessSha256',
    'ObservedProcessExecutableSha256',
    'previous-runtime',
    'repair-offline',
    'second-consecutive-update',
    'RequireCanonicalTestRunId',
    'SerializeCanonical',
    'PersonalFeedJson.RequireNoDuplicateMembers',
    'json.SequenceEqual(canonical)')) {
    if (-not $personalLifecycleContractText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal lifecycle evidence contract is missing: $required"
    }
}
foreach ($required in @(
    'PersonalLifecycleEvidenceSet',
    'Certification.Verify',
    'snapshot.RawSha256')) {
    if (-not $personalFeedContractText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal distribution receipt binding is missing: $required"
    }
}
foreach ($required in @(
    'PersonalLifecycleEvidenceSnapshot.Read',
    'RequireCertificationArgumentSet',
    'CleanDeviceLifecyclePath',
    'TwoUpdateUpgradeLifecyclePath',
    'FailureRecoveryLifecyclePath')) {
    if (-not $personalPromoterText.Contains($required, [StringComparison]::Ordinal)) {
        throw "Personal FeedPromoter evidence admission is missing: $required"
    }
}
foreach ($required in @(
    '--clean-device-lifecycle',
    '--two-update-upgrade-lifecycle',
    '--failure-recovery-lifecycle',
    '--production-gate-evidence',
    'certify-distribution')) {
    if (-not $personalPromoterProgramText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal FeedPromoter CLI is missing: $required"
    }
}

$releaseReadmeText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'release\README.md')
foreach ($required in @(
    'personal-certified-distribution-receipt-v2.schema.json',
    '-ProductionGateEvidencePath',
    '--production-gate-evidence',
    'certified-distribution-receipt-authentication-v1.schema.json',
    '-ExpectedInstallerSignerSha256Thumbprint',
    '-ReceiptAuthenticationKeyId',
    '-ProtectedSnapshotBasePath')) {
    if (-not $releaseReadmeText.Contains($required, [StringComparison]::Ordinal)) {
        throw "Stable release runbook is missing: $required"
    }
}
if ($releaseReadmeText.Contains(
        'personal-certified-distribution-receipt-v1.schema.json',
        [StringComparison]::Ordinal)) {
    throw 'Personal Stable release runbook still points to the superseded v1 distribution receipt schema.'
}

$distributionGatePath = Join-Path $RepositoryRoot `
    'release\scripts\Test-CertifiedDistributionReceipt.ps1'
$distributionGateText = Get-Content -Raw -LiteralPath $distributionGatePath
if ($distributionGateText -notmatch 'CERTIFIED-DISTRIBUTION-PASS' -or
    $distributionGateText -notmatch 'Get-AuthenticodeSignature' -or
    $distributionGateText -notmatch 'ReceiptAuthenticationPath' -or
    $distributionGateText -notmatch 'ExpectedInstallerSignerSha256Thumbprint' -or
    $distributionGateText -notmatch 'Open-CertifiedDistributionLockedInput' -or
    $distributionGateText -notmatch 'Open-CertifiedDistributionLockedDirectory' -or
    $distributionGateText -notmatch 'Copy-CertifiedDistributionLockedSnapshot' -or
    $distributionGateText -notmatch 'MaximumReceiptAgeHours' -or
    $distributionGateText -notmatch 'IeeeP1363FixedFieldConcatenation' -or
    $distributionGateText -notmatch 'externalManifestSha256' -or
    $distributionGateText -notmatch 'enterprisePluginLoaded') {
    throw 'Certified distribution gate no longer authenticates the receipt, independently pins the Installer signer, and retains exact-input handle continuity.'
}

$stableAuthorizationPath = Join-Path $RepositoryRoot `
    'release\scripts\New-EnterpriseStablePromotionAuthorization.ps1'
$stableAuthorizationText = Get-Content -Raw -LiteralPath $stableAuthorizationPath
if ($stableAuthorizationText -notmatch 'Test-CertifiedDistributionReceipt[.]ps1' -or
    $stableAuthorizationText -notmatch 'ReceiptAuthenticationKeyId' -or
    $stableAuthorizationText -notmatch 'ExpectedInstallerSignerSha256Thumbprint' -or
    $stableAuthorizationText -notmatch 'Open-CertifiedDistributionLockedInput' -or
    $stableAuthorizationText -notmatch 'MaximumReceiptAgeHours' -or
    $stableAuthorizationText -notmatch 'PassThru' -or
    $stableAuthorizationText -match 'Get-Content\s+-Raw\s+-LiteralPath\s+\$ReceiptPath' -or
    $stableAuthorizationText -notmatch 'ImportPkcs8PrivateKey' -or
    $stableAuthorizationText -notmatch 'IeeeP1363FixedFieldConcatenation' -or
    $stableAuthorizationText -notmatch 'STABLE-PROMOTION-AUTHORIZATION-PASS') {
    throw 'Stable promotion authorization no longer consumes one authenticated exact-byte admission snapshot.'
}
foreach ($inputParameter in @(
    'ReceiptPath',
    'ReceiptAuthenticationPath',
    'InstallerPath',
    'ManifestPath')) {
    $inputReferences = [regex]::Matches(
        $stableAuthorizationText,
        '\$' + [regex]::Escape($inputParameter) + '\b')
    if ($inputReferences.Count -ne 2) {
        throw "Stable promotion authorization must name $inputParameter only as its parameter and one gate argument; any later reference would reopen the admitted path."
    }
}

$receiptAuthenticationExample = Join-Path $examplesPath `
    'certified-distribution-receipt-authentication-v1.example.json'
if (-not (Test-Path -LiteralPath $receiptAuthenticationExample -PathType Leaf) -or
    -not (Test-Json `
        -Json (Get-Content -Raw -LiteralPath $receiptAuthenticationExample) `
        -SchemaFile $enterpriseSchemas['certified-distribution-receipt-authentication-v1.schema.json'] `
        -ErrorAction Stop)) {
    throw 'Certified distribution receipt authentication example does not satisfy its strict schema.'
}

$stableAuthorizationContract = Join-Path $RepositoryRoot `
    'release\scripts\Test-EnterpriseStablePromotionAuthorization.ps1'
if (-not (Test-Path -LiteralPath $stableAuthorizationContract -PathType Leaf)) {
    throw 'Enterprise Stable promotion authorization direct contract test is missing.'
}
$stableAuthorizationContractOutput = @(& $stableAuthorizationContract `
    -RepositoryRoot $RepositoryRoot)
if ($stableAuthorizationContractOutput -notcontains `
        'ENTERPRISE-STABLE-PROMOTION-AUTHORIZATION-CONTRACT-PASS') {
    throw 'Enterprise Stable promotion authorization direct contract test did not pass.'
}

$pilotReadinessExample = Join-Path $examplesPath 'enterprise-pilot-readiness.config.example.json'
if (-not (Test-Path -LiteralPath $pilotReadinessExample -PathType Leaf) -or
    -not (Test-Json `
        -Json (Get-Content -Raw -LiteralPath $pilotReadinessExample) `
        -SchemaFile $enterpriseSchemas['enterprise-pilot-readiness-v1.schema.json'] `
        -ErrorAction Stop)) {
    throw 'Enterprise Pilot readiness example does not satisfy the strict input schema.'
}
$pilotReadinessSchema = Get-Content -Raw -LiteralPath `
    $enterpriseSchemas['enterprise-pilot-readiness-v1.schema.json'] |
    ConvertFrom-Json -Depth 64
foreach ($requiredClientBinaryPath in @(
    'launcherExecutablePath',
    'clientBootstrapperExecutablePath',
    'maintenanceExecutablePath')) {
    if (-not @($pilotReadinessSchema.required).Contains($requiredClientBinaryPath)) {
        throw "Enterprise Pilot readiness schema does not require $requiredClientBinaryPath."
    }
}

$localDataSampleRoots = @(
    (Join-Path $RepositoryRoot `
        'out\local-data-compatibility\rc7-to-rc2-full-api-dev-20260825-11'),
    (Join-Path $RepositoryRoot `
        'out\local-data-compatibility\rc7-to-rc2-text-only-v1-20260825-01')
)
foreach ($run11Root in $localDataSampleRoots) {
if (Test-Path -LiteralPath $run11Root -PathType Container) {
    $run11Contracts = @(
        @('local-data-compatibility-evidence.json',
            'enterprise-local-data-compatibility-evidence-v1.schema.json'),
        @('results\forward-result.json',
            'enterprise-local-data-forward-result-v1.schema.json'),
        @('results\rollback-result.json',
            'enterprise-local-data-rollback-result-v1.schema.json'),
        @('results\source-seed-api-lane.json',
            'enterprise-local-data-api-lane-result-v1.schema.json'),
        @('results\target-forward-api-lane.json',
            'enterprise-local-data-api-lane-result-v1.schema.json'),
        @('results\source-restored-api-lane.json',
            'enterprise-local-data-api-lane-result-v1.schema.json')
    )
    foreach ($contract in $run11Contracts) {
        $samplePath = Join-Path $run11Root $contract[0]
        if (-not (Test-Path -LiteralPath $samplePath -PathType Leaf) -or
            -not (Test-Json `
                -Json (Get-Content -Raw -LiteralPath $samplePath) `
                -SchemaFile $enterpriseSchemas[$contract[1]] `
                -ErrorAction Stop)) {
            throw "Run11 local-data sample does not satisfy $($contract[1]): $samplePath"
        }
    }

    $expectedRefusals = @{
        'source-seed' = @('select-model', 'model-unavailable',
            'managed-text-only-model-selection-refusal')
        'target-forward' = @('image-prompt', 'attachment-error',
            'managed-text-only-image-prompt-refusal')
        'source-restored' = @('select-model', 'model-unavailable',
            'managed-text-only-model-selection-refusal')
    }
    foreach ($phase in $expectedRefusals.Keys) {
        $lane = Get-Content -Raw -LiteralPath (
            Join-Path $run11Root "results\$phase-api-lane.json") |
            ConvertFrom-Json -Depth 64
        $normalization = $lane.attachment.requestImageNormalization
        $expected = $expectedRefusals[$phase]
        if ($normalization.status -cne 'not-applicable-managed-text-only-policy' -or
            @($normalization.requestImageFiles).Count -ne 0 -or
            $normalization.publicPolicyRefusal.stage -cne $expected[0] -or
            $normalization.publicPolicyRefusal.code -cne $expected[1] -or
            $normalization.publicPolicyRefusal.diagnosticClass -cne $expected[2]) {
            throw "Run11 $phase does not prove the exact managed text-only refusal tuple."
        }
    }
}
}

$publisherProjectPath = Join-Path $RepositoryRoot `
    'src\Ensou.Dsh.Enterprise.ReleasePublisher\Ensou.Dsh.Enterprise.ReleasePublisher.csproj'
$publisherProjectText = Get-Content -Raw -LiteralPath $publisherProjectPath
if ($publisherProjectText -notmatch 'PublishSingleFile' -or
    $publisherProjectText -notmatch 'self-contained single-file executable') {
    throw 'ReleasePublisher publish no longer enforces a self-contained single-file executable.'
}
foreach ($required in @(
    'EnterprisePluginPromotionJournalKeyId',
    'EnterprisePluginPromotionJournalKeyX',
    'EnterprisePluginPromotionJournalKeyY',
    'independent compiled plugin-promotion journal authorization public key'
)) {
    if (-not $publisherProjectText.Contains($required, [StringComparison]::Ordinal)) {
        throw "ReleasePublisher production journal trust metadata is missing: $required"
    }
}
foreach ($required in @(
    'EnterprisePilotEvidenceKeyId',
    'EnterprisePilotEvidenceKeyX',
    'EnterprisePilotEvidenceKeyY',
    'independent compiled Windows Pilot evidence attestation public key'
)) {
    if (-not $publisherProjectText.Contains($required, [StringComparison]::Ordinal)) {
        throw "ReleasePublisher Windows Pilot evidence trust metadata is missing: $required"
    }
}
$windowsPilotPublisherText = Get-Content -Raw -LiteralPath (Join-Path $RepositoryRoot `
    'src\Ensou.Dsh.Enterprise.ReleasePublisher\PublisherWindowsPilotEvidence.cs')
foreach ($required in @(
    '--windows-pilot-trust',
    '--verify-windows-pilot-attestation',
    '--verify-windows-pilot-manifest',
    '--verify-windows-pilot-live-head',
    'RequireIndependentTrust('
)) {
    if (-not $windowsPilotPublisherText.Contains($required, [StringComparison]::Ordinal)) {
        throw "ReleasePublisher Windows Pilot verification wiring is missing: $required"
    }
}
$publisherProgramText = Get-Content -Raw -LiteralPath (Join-Path $RepositoryRoot `
    'src\Ensou.Dsh.Enterprise.ReleasePublisher\Program.cs')
foreach ($required in @(
    'PublisherPluginPromotionJournal.Consume(',
    '--initialize-plugin-promotion-journal',
    '--plugin-promotion-journal-challenge',
    '--plugin-promotion-journal-intent',
    'PublisherInputSnapshot.CaptureIntent(',
    'PluginPromotionJournalAuthorizationPath'
)) {
    if (-not $publisherProgramText.Contains($required, [StringComparison]::Ordinal)) {
        throw "ReleasePublisher production journal wiring is missing: $required"
    }
}
$publisherInputSnapshotText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Enterprise.ReleasePublisher\PublisherInputSnapshot.cs')
foreach ($required in @(
    'PublisherPrivateKeyLease.Open(privateKeyPath)',
    'PublisherSafeFile.OpenLockedRead(fullPath)',
    'PublisherSafeFile.RequireExpectedPathAndRegularFile(',
    'PublisherSafeFile.GetIdentity(stream) != _identity',
    'Interlocked.Exchange(ref _privateKey, null)?.Dispose();',
    'CryptographicOperations.ZeroMemory(bytes);',
    'FileShare.Read'
)) {
    if (-not $publisherInputSnapshotText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "ReleasePublisher source private-key lease is missing: $required"
    }
}
if ($publisherInputSnapshotText.Contains(
        'staging.Capture(privateKeyPath)',
        [StringComparison]::Ordinal) -or
    $publisherProgramText.Contains(
        'DeletePrivateKeyCopy',
        [StringComparison]::Ordinal)) {
    throw 'ReleasePublisher may not copy or early-delete a private key in staging/temp.'
}
$publisherTestsText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'tests\Ensou.Dsh.Enterprise.ReleasePublisherTests\Program.cs')
foreach ($required in @(
    'publisher holds the source private key and never stages its bytes',
    'publisher releases the source private key after capture failure',
    'publisher crash leaves the source key but no staged key bytes',
    'AssertPrivateKeyMutationsDenied(',
    'AssertPrivateKeyMutationsAllowed(',
    'AssertNoPublisherStagingContains(',
    'FileAccess.Write',
    'File.Move(replacement, keyPath, overwrite: true)',
    'File.Move(keyPath, renamed)',
    'File.Delete(keyPath)',
    'Environment.Exit(37);'
)) {
    if (-not $publisherTestsText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "ReleasePublisher private-key executable regression is missing: $required"
    }
}
$journalAuthorizationContract = Join-Path $RepositoryRoot `
    'release\scripts\Test-EnterprisePluginPromotionJournalAuthorization.ps1'
if (-not (Test-Path -LiteralPath $journalAuthorizationContract -PathType Leaf)) {
    throw 'Enterprise plugin promotion journal authorization contract test is missing.'
}
$journalAuthorizationOutput = @(& $journalAuthorizationContract -RepositoryRoot $RepositoryRoot)
if ($journalAuthorizationOutput.Count -ne 1 -or
    $journalAuthorizationOutput[0] -cne
        'ENTERPRISE-PLUGIN-PROMOTION-JOURNAL-AUTHORIZATION-CONTRACT-PASS') {
    throw 'Enterprise plugin promotion journal authorization contract test did not pass.'
}
$policyHandoffText = Get-Content -Raw -LiteralPath (Join-Path $RepositoryRoot 'src\Ensou.Dsh.Enterprise.ReleasePublisher\EnterprisePolicyHandoffCommand.cs')
$policyHandoffSchema = Get-Content -Raw -LiteralPath `
    $enterpriseSchemas['enterprise-release-policy-handoff-v1.schema.json'] |
    ConvertFrom-Json -Depth 32
if (-not @($policyHandoffSchema.required).Contains('promotionResultSha256') -or
    $null -eq $policyHandoffSchema.properties.promotionResultSha256) {
    throw 'Release-policy handoff schema no longer requires the FeedPromoter result digest.'
}
foreach ($required in @(
    'EnterpriseReleasePolicyHandoffContract',
    'PromotionResultSha256',
    'PromotionJournalSha256',
    '--promotion-result-receipt',
    'RequireExactPromotion',
    '/srv/ensou-dsh-enterprise-feed/public/channels/',
    '/srv/ensou-dsh-enterprise-feed/journal/',
    'RequireExactManifest',
    'EnterpriseReleaseSetValidator.Verify',
    'PublisherSafeFile.OpenLockedRead',
    'RequireExpectedPathAndRegularFile',
    'ReadLockedInput',
    'IeeeP1363FixedFieldConcatenation'
)) {
    if (-not $policyHandoffText.Contains($required, [StringComparison]::Ordinal)) {
        throw "Release-policy handoff signer is missing: $required"
    }
}

$pilotWrapperPath = Join-Path $RepositoryRoot 'scripts\Test-EnterprisePilotReadiness.ps1'
$pilotWrapperText = Get-Content -Raw -LiteralPath $pilotWrapperPath
$publisherLockIndex = $pilotWrapperText.IndexOf(
    '$publisherLock = [IO.FileStream]::new',
    [StringComparison]::Ordinal)
$publisherSignatureIndex = $pilotWrapperText.IndexOf(
    'Get-AuthenticodeSignature',
    [StringComparison]::Ordinal)
$publisherEmbeddedSignatureIndex = $pilotWrapperText.IndexOf(
    '$signature.SignatureType',
    [StringComparison]::Ordinal)
$publisherTimestampIndex = $pilotWrapperText.IndexOf(
    '$signature.TimeStamperCertificate',
    [StringComparison]::Ordinal)
$publisherLaunchIndex = $pilotWrapperText.IndexOf(
    '[Diagnostics.Process]::Start',
    [StringComparison]::Ordinal)
$publisherUnlockIndex = $pilotWrapperText.LastIndexOf(
    '$publisherLock.Dispose()',
    [StringComparison]::Ordinal)
if ($pilotWrapperText -notmatch 'PublisherExecutableSha256' -or
    $pilotWrapperText -notmatch '\[IO\.FileShare\]::Read' -or
    $pilotWrapperText -notmatch 'Get-LowerSha256FromLockedStream' -or
    $publisherLockIndex -lt 0 -or
    $publisherSignatureIndex -le $publisherLockIndex -or
    $publisherEmbeddedSignatureIndex -le $publisherSignatureIndex -or
    $publisherTimestampIndex -le $publisherEmbeddedSignatureIndex -or
    $publisherTimestampIndex -le $publisherSignatureIndex -or
    $publisherLaunchIndex -le $publisherTimestampIndex -or
    $publisherLaunchIndex -le $publisherSignatureIndex -or
    $publisherUnlockIndex -le $publisherLaunchIndex) {
    throw 'Pilot wrapper no longer locks and hash-binds one Publisher EXE across verification and launch.'
}

$publishedArtifactsPath = Join-Path `
    $RepositoryRoot `
    'scripts\Test-EnterprisePublishedArtifacts.ps1'
$publishedArtifactsText = Get-Content -Raw -LiteralPath $publishedArtifactsPath
$enterprisePublishedTokens = $null
$enterprisePublishedParseErrors = $null
$enterprisePublishedAst =
    [Management.Automation.Language.Parser]::ParseFile(
        $publishedArtifactsPath,
        [ref]$enterprisePublishedTokens,
        [ref]$enterprisePublishedParseErrors)
if ($enterprisePublishedParseErrors.Count -ne 0) {
    throw 'Enterprise published-artifact RFC3161 gate no longer parses.'
}
$enterpriseAuthenticodeFunctions = @($enterprisePublishedAst.FindAll(
    {
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Assert-Authenticode'
    },
    $true))
$enterpriseLockedReadFunctions = @($enterprisePublishedAst.FindAll(
    {
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Read-LockedArtifactBytes'
    },
    $true))
if ($enterpriseAuthenticodeFunctions.Count -ne 1 -or
    $enterpriseLockedReadFunctions.Count -ne 1) {
    throw 'Enterprise published-artifact RFC3161 gate lost its unique verifier or locked-byte reader.'
}
$enterpriseAuthenticodeFunctionText =
    $enterpriseAuthenticodeFunctions[0].Extent.Text
$enterpriseLockedReadFunctionText =
    $enterpriseLockedReadFunctions[0].Extent.Text
foreach ($required in @(
    '$signature = Get-AuthenticodeSignature -LiteralPath $Executable',
    '[byte[]]$lockedBytes = Read-LockedArtifactBytes',
    '$timestampAdmission = ProductionReleaseState\Assert-PeRfc3161Timestamp',
    '-Bytes $lockedBytes',
    '-SignerCertificate $signature.SignerCertificate',
    '-TimeStamperCertificate $signature.TimeStamperCertificate',
    '$timestampAdmission.TimestampProtocol -cne ''RFC3161''',
    '$timestamped = $true',
    'timestamped = $timestamped'
)) {
    if (-not $enterpriseAuthenticodeFunctionText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Enterprise published-artifact RFC3161 admission is missing: $required"
    }
}
foreach ($required in @(
    '$Stream.Length -ne $Expected.SizeBytes',
    '$Stream.Position = 0',
    '$Stream.Read(',
    '$Stream.ReadByte() -ne -1',
    '[Security.Cryptography.SHA256]::HashData($bytes)',
    '$sha256 -cne $Expected.Sha256'
)) {
    if (-not $enterpriseLockedReadFunctionText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Enterprise published-artifact RFC3161 locked-byte reader is missing: $required"
    }
}
$enterpriseLockedReadIndex = $enterpriseAuthenticodeFunctionText.IndexOf(
    '[byte[]]$lockedBytes = Read-LockedArtifactBytes',
    [StringComparison]::Ordinal)
$enterpriseCanonicalTimestampIndex = $enterpriseAuthenticodeFunctionText.IndexOf(
    '$timestampAdmission = ProductionReleaseState\Assert-PeRfc3161Timestamp',
    [StringComparison]::Ordinal)
$enterpriseTimestampProtocolIndex = $enterpriseAuthenticodeFunctionText.IndexOf(
    '$timestampAdmission.TimestampProtocol -cne ''RFC3161''',
    [StringComparison]::Ordinal)
$enterpriseAdmittedEvidenceIndex = $enterpriseAuthenticodeFunctionText.IndexOf(
    '$timestamped = $true',
    [StringComparison]::Ordinal)
if ($enterpriseLockedReadIndex -lt 0 -or
    $enterpriseCanonicalTimestampIndex -le $enterpriseLockedReadIndex -or
    $enterpriseTimestampProtocolIndex -le $enterpriseCanonicalTimestampIndex -or
    $enterpriseAdmittedEvidenceIndex -le $enterpriseTimestampProtocolIndex -or
    [regex]::Matches(
        $enterpriseAuthenticodeFunctionText,
        '(?m)^[ \t]*\$timestampAdmission = ProductionReleaseState\\Assert-PeRfc3161Timestamp[ \t]*`?[ \t]*\r?$').Count -ne 1) {
    throw 'Enterprise published-artifact timestamp evidence is no longer ordered after one canonical RFC3161 admission.'
}
foreach ($required in @(
    'Enterprise production published artifacts require Authenticode verification.',
    "'..\release\scripts\ProductionReleaseState.psm1'",
    '[IO.FileShare]::Read',
    'RequireOrdinarySingleLink(',
    'Get-ExactRootArchiveEntry',
    'Get-LockedArtifactDescriptor',
    'Assert-LockedArtifactUnchanged',
    "Name = 'Installer'",
    "Name = 'Bootstrapper'",
    "Name = 'Launcher'",
    "Name = 'ClientBootstrapper'",
    "Name = 'Maintenance'",
    'Path = $installer',
    'Stream = $installerLock',
    'Descriptor = $installerDescriptor',
    'Path = $bootstrapper',
    'Stream = $bootstrapperLock',
    'Descriptor = $bootstrapperDescriptor',
    'Path = $launcher',
    'Stream = $launcherLock',
    'Descriptor = $launcherDescriptor',
    'Path = $clientBootstrapper',
    'Stream = $clientBootstrapperLock',
    'Descriptor = $clientBootstrapperDescriptor',
    'Path = $maintenance',
    'Stream = $maintenanceLock',
    'Descriptor = $maintenanceDescriptor',
    '-Executable $productionPe.Path',
    '-Stream $productionPe.Stream',
    '-Descriptor $productionPe.Descriptor',
    'AuthenticodeEvidence = [pscustomobject]$authenticodeEvidence'
)) {
    if (-not $publishedArtifactsText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Enterprise published-artifact RFC3161 descriptor binding is missing: $required"
    }
}
if ([regex]::Matches(
        $publishedArtifactsText,
        '(?m)^\s*Assert-ArchiveEntryBinding\s').Count -ne 4 -or
    [regex]::Matches(
        $publishedArtifactsText,
        '(?m)^[ \t]*\$authenticodeEvidence\[\$productionPe\.Name\] = Assert-Authenticode[ \t]*`?[ \t]*\r?$').Count -ne 1) {
    throw 'Enterprise published-artifact RFC3161 admission no longer covers its five unique production PE entrypoints through one locked-descriptor loop.'
}
$enterprisePublishedMainIndex = $publishedArtifactsText.IndexOf(
    '$installerRoot = Resolve-SafeDirectory',
    [StringComparison]::Ordinal)
if ($enterprisePublishedMainIndex -lt 0) {
    throw 'Enterprise published-artifact executable-order contract lost its main gate body.'
}
$enterprisePublishedMain = $publishedArtifactsText.Substring(
    $enterprisePublishedMainIndex)
$enterpriseAdmissionIndex = $enterprisePublishedMain.IndexOf(
    '$authenticodeEvidence[$productionPe.Name] = Assert-Authenticode',
    [StringComparison]::Ordinal)
foreach ($executionSink in @(
    'Invoke-WithoutSystemDotNet',
    'Assert-NonInteractiveInstallerFailure',
    'Assert-NonInteractiveBootstrapperFailure',
    'Assert-NonInteractiveClientBootstrapperHealthFailure',
    'Invoke-InstallerPayloadSelfCheckWithoutSystemDotNet')) {
    $executionIndex = $enterprisePublishedMain.IndexOf(
        $executionSink,
        [StringComparison]::Ordinal)
    if ($enterpriseAdmissionIndex -lt 0 -or
        $executionIndex -le $enterpriseAdmissionIndex) {
        throw "Enterprise published-artifact gate can execute '$executionSink' before Authenticode/RFC3161 admission."
    }
}
if ([regex]::Matches(
        $enterprisePublishedMain,
        '(?m)^\s*Invoke-WithoutSystemDotNet\s').Count -ne 5) {
    throw 'Enterprise published-artifact executable-order contract no longer covers exactly five primary EXE self-checks.'
}
$executionFunctions = @(
    'Invoke-WithoutSystemDotNet',
    'Assert-NonInteractiveInstallerFailure',
    'Invoke-InstallerPayloadSelfCheckWithoutSystemDotNet',
    'Assert-NonInteractiveBootstrapperFailure',
    'Assert-NonInteractiveClientBootstrapperHealthFailure')
foreach ($executionFunction in $executionFunctions) {
    $functionNodes = @($enterprisePublishedAst.FindAll(
        {
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq $executionFunction
        },
        $true))
    if ($functionNodes.Count -ne 1) {
        throw "Enterprise published-artifact execution function is not unique: $executionFunction"
    }
    $functionText = $functionNodes[0].Extent.Text
    $identityIndex = $functionText.IndexOf(
        'Assert-LockedArtifactUnchanged',
        [StringComparison]::Ordinal)
    $staticStartIndex = $functionText.IndexOf(
        '[Diagnostics.Process]::Start($start)',
        [StringComparison]::Ordinal)
    $instanceStartIndex = $functionText.IndexOf(
        '$process.Start()',
        [StringComparison]::Ordinal)
    $startIndex = if ($staticStartIndex -ge 0) {
        $staticStartIndex
    }
    else {
        $instanceStartIndex
    }
    if ($identityIndex -lt 0 -or
        $startIndex -lt 0 -or
        $identityIndex -gt $startIndex) {
        throw "Enterprise published-artifact execution function lost its launch-adjacent locked identity/hash check: $executionFunction"
    }
}
$enterpriseRfc3161PolicyPath = Join-Path `
    $RepositoryRoot `
    'scripts\Test-EnterprisePublishedArtifactsRfc3161Policy.ps1'
$enterpriseRfc3161PolicyText = Get-Content -Raw -LiteralPath `
    $enterpriseRfc3161PolicyPath
foreach ($required in @(
    'New-TestPeWithCms',
    'wrong-primary-SignerInfo RFC3161 token regression',
    'truncated WIN_CERTIFICATE alignment regression',
    'invalid primary CMS with bound RFC3161 token regression',
    'invalid auxiliary CMS RFC3161 regression',
    'Authenticode locked-PE digest regression',
    'non-Authenticode CMS content-type regression',
    'legacy counterSignature regression',
    'ProductionReleaseState\Assert-PeRfc3161Timestamp',
    'ENTERPRISE-RFC3161-REAL-FIXTURE-PENDING',
    'ENTERPRISE-RFC3161-REAL-FIXTURE-PASS'
)) {
    if (-not $enterpriseRfc3161PolicyText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Enterprise published-artifact RFC3161 semantic regression is missing: $required"
    }
}
$enterpriseRfc3161PolicyOutput = @(& $enterpriseRfc3161PolicyPath)
if ($enterpriseRfc3161PolicyOutput.Count -ne 3 -or
    $enterpriseRfc3161PolicyOutput[0] -cne
        'ENTERPRISE-RFC3161-NEGATIVE-CONTRACTS-PASS' -or
    $enterpriseRfc3161PolicyOutput[2] -cne
        'ENTERPRISE-RFC3161-POLICY-CONTRACT-PASS' -or
    ($enterpriseRfc3161PolicyOutput[1] -notlike
        'ENTERPRISE-RFC3161-REAL-FIXTURE-PASS:*' -and
     $enterpriseRfc3161PolicyOutput[1] -notlike
        'ENTERPRISE-RFC3161-REAL-FIXTURE-PENDING:*')) {
    throw 'Enterprise published-artifact RFC3161 semantic regression did not pass with an explicit real-fixture outcome.'
}
$enterpriseInstallerPayloadBindingPath = Join-Path `
    $RepositoryRoot `
    'scripts\Test-EnterpriseInstallerPayloadBinding.ps1'
$enterpriseInstallerPayloadBindingText = Get-Content -Raw -LiteralPath `
    $enterpriseInstallerPayloadBindingPath
foreach ($requiredPayloadBindingControl in @(
    "'restore'",
    '--locked-mode',
    '--production-payload-self-check',
    '--development-production-payload-self-check',
    'if (!developmentSelfCheck && DevelopmentE2EEnabled)',
    'ENTERPRISE-INSTALLER-PAYLOAD-BINDING-PASS')) {
    if (-not $enterpriseInstallerPayloadBindingText.Contains(
            $requiredPayloadBindingControl,
            [StringComparison]::Ordinal)) {
        throw "Enterprise Installer payload-binding regression is missing: $requiredPayloadBindingControl"
    }
}
$enterpriseInstallerPayloadBindingOutput = @(
    & $enterpriseInstallerPayloadBindingPath)
if ($enterpriseInstallerPayloadBindingOutput.Count -ne 1 -or
    $enterpriseInstallerPayloadBindingOutput[0] -cne
        'ENTERPRISE-INSTALLER-PAYLOAD-BINDING-PASS') {
    throw 'Enterprise Installer payload-binding regression did not execute with its unique PASS marker.'
}
$pilotReadinessText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Enterprise.ReleasePublisher\EnterprisePilotReadiness.cs')
foreach ($requiredClientBindingControl in @(
    'ClientBootstrapperExecutablePath',
    'MaintenanceExecutablePath',
    'LauncherBuildProfilePath',
    'RequireArchiveExecutableBinding')) {
    if (-not $pilotReadinessText.Contains(
            $requiredClientBindingControl,
            [StringComparison]::Ordinal)) {
        throw "Enterprise Pilot client binding is missing: $requiredClientBindingControl"
    }
}
$authenticodeVerifierText = Get-Content -Raw -LiteralPath (
    Join-Path $RepositoryRoot 'src\Ensou.Dsh.Enterprise.Installation\EnterpriseAuthenticodeVerifier.cs')
foreach ($requiredTimestampControl in @(
    'HasTrustedTimestamp',
    'WtdStateActionVerify',
    'WtdStateActionClose',
    'SgnrTypeTimestamp',
    'WTHelperGetProvCertFromChain',
    'X509CertificateLoader.LoadCertificate',
    'has no trusted Authenticode timestamp')) {
    if (-not $authenticodeVerifierText.Contains(
            $requiredTimestampControl,
            [StringComparison]::Ordinal)) {
        throw "Shared Enterprise Authenticode verifier lost trusted timestamp control: $requiredTimestampControl"
    }
}
if ($authenticodeVerifierText.Contains(
        'CreateFromSignedFile',
        [StringComparison]::Ordinal)) {
    throw 'Shared Enterprise Authenticode verifier reopened the executable by path after locked-handle WinVerifyTrust.'
}

$localDataRunnerText = Get-Content -Raw -LiteralPath (
    Join-Path $RepositoryRoot 'scripts\Test-EnterpriseLocalDataCompatibility.ps1')
$localDataDriverText = Get-Content -Raw -LiteralPath (
    Join-Path $RepositoryRoot 'scripts\local-data-compatibility-api-lane.mjs')
if ($localDataRunnerText -match 'covered-public-vision-conversation' -or
    $localDataDriverText -match 'covered-public-vision-conversation' -or
    $localDataRunnerText -notmatch 'not-applicable-managed-text-only-policy-public-refusal-proven' -or
    $localDataDriverText -notmatch 'not-applicable-managed-text-only-policy') {
    throw 'Local-data v1 producer reintroduced vision success or lost managed text-only refusal evidence.'
}

$personalRuntimeBuilderPath = Join-Path $RepositoryRoot `
    'scripts\New-PersonalSourceRuntimeArtifact.ps1'
$personalRuntimePayloadPath = Join-Path $RepositoryRoot `
    'scripts\New-PersonalDevelopmentInstallerPayload.ps1'
$personalRuntimeBuilderTestPath = Join-Path $RepositoryRoot `
    'scripts\Test-PersonalSourceRuntimeArtifact.ps1'
$personalRuntimePayloadTestPath = Join-Path $RepositoryRoot `
    'scripts\Test-PersonalDevelopmentRuntimeArtifactPayload.ps1'
foreach ($requiredPath in @(
    $personalRuntimeBuilderPath,
    $personalRuntimePayloadPath,
    $personalRuntimeBuilderTestPath,
    $personalRuntimePayloadTestPath
)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Personal source-runtime artifact chain is missing: $requiredPath"
    }
}
$personalRuntimeBuilderText = Get-Content -Raw -LiteralPath `
    $personalRuntimeBuilderPath
foreach ($required in @(
    'EnsouPersonalSourceRuntime.NativeFileIdentity',
    'Open-ExactLockedInput',
    'SourceEvidenceLockedObserver',
    'ensou-dsh-personal-source-runtime-artifact',
    'source-build.json',
    'ArtifactDescriptorPath'
)) {
    if (-not $personalRuntimeBuilderText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal source-runtime builder lost its exact provenance contract: $required"
    }
}
$personalRuntimePayloadText = Get-Content -Raw -LiteralPath `
    $personalRuntimePayloadPath
foreach ($required in @(
    'RuntimeArtifactDescriptorPath',
    'Open-ExactLockedFile',
    'Copy-ExactLockedFile',
    'RequireOrdinarySingleLink',
    'runtimeArtifactDescriptorSha256',
    'archive differs from its complete-tree',
    'verified-source-runtime-artifact',
    'runtimeArtifactAuthenticity',
    'not-asserted',
    'developmentInstallDefault',
    '--allow-unsigned-development-install'
)) {
    if (-not $personalRuntimePayloadText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal development payload lost its exact runtime artifact gate: $required"
    }
}
$personalRuntimeBuilderTestText = Get-Content -Raw -LiteralPath `
    $personalRuntimeBuilderTestPath
$personalRuntimePayloadTestText = Get-Content -Raw -LiteralPath `
    $personalRuntimePayloadTestPath
foreach ($required in @(
    'SourceEvidenceLockedObserver',
    'locked source evidence stayed on admitted bytes'
)) {
    if (-not $personalRuntimeBuilderTestText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal source-runtime builder regression is missing: $required"
    }
}
foreach ($required in @(
    'New-SourceRuntimeArtifact',
    'ItemType HardLink',
    'ItemType Junction',
    'self-consistent descriptor with archive content mismatch',
    'locked replacement either failed or copied the admitted A bytes'
)) {
    if (-not $personalRuntimePayloadTestText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal runtime payload regression is missing: $required"
    }
}
$personalCiText = Get-Content -Raw -LiteralPath (
    Join-Path $RepositoryRoot '.github\workflows\personal-managed-update-v2.yml')
$primaryCiText = Get-Content -Raw -LiteralPath (
    Join-Path $RepositoryRoot '.github\workflows\ci.yml')
$primaryCoreContractsJob = [regex]::Match(
    $primaryCiText,
    '(?ms)^  core-contracts:\s*\r?\n(?<body>.*?)(?=^  [A-Za-z0-9_-]+:\s*$|\z)')
$primaryCoreContractsTimeout = if ($primaryCoreContractsJob.Success) {
    [regex]::Match(
        $primaryCoreContractsJob.Groups['body'].Value,
        '(?m)^    timeout-minutes:\s*(?<minutes>[0-9]+)\s*$')
}
if (-not $primaryCoreContractsTimeout.Success -or
    [int]$primaryCoreContractsTimeout.Groups['minutes'].Value -lt 45) {
    throw 'CI core contracts must retain its existing minimum time allowance.'
}
$primaryOrchestrationJob = [regex]::Match(
    $primaryCiText,
    '(?ms)^  orchestration:\s*\r?\n(?<body>.*?)(?=^  [A-Za-z0-9_-]+:\s*$|\z)')
if (-not $primaryOrchestrationJob.Success -or
    $primaryOrchestrationJob.Groups['body'].Value -notmatch '(?m)^    timeout-minutes:\s*75\s*$' -or
    $primaryOrchestrationJob.Groups['body'].Value -notmatch '(?m)^      fail-fast:\s*false\s*$' -or
    $primaryOrchestrationJob.Groups['body'].Value -notmatch '(?m)^        shard:\s*\[FoundationR8, ImportAndPersonal\]\s*$' -or
    $primaryOrchestrationJob.Groups['body'].Value -notmatch [regex]::Escape('.\release\scripts\Test-LauncherProductionReleaseOrchestration.ps1 -Shard ${{ matrix.shard }}')) {
    throw 'CI must run both fail-closed production orchestration shards in a fail-fast-disabled matrix.'
}
$primaryAggregateJob = [regex]::Match(
    $primaryCiText,
    '(?ms)^  contracts:\s*\r?\n(?<body>.*?)(?=^  [A-Za-z0-9_-]+:\s*$|\z)')
$primaryAggregateBody = $primaryAggregateJob.Groups['body'].Value
$primaryAggregateStep = [regex]::Match(
    $primaryAggregateBody,
    '(?ms)^      - name: Require all release and workflow contract jobs\r?\n(?<body>.*?)(?=^      - name:|\z)')
$expectedPrimaryAggregateStepBody = [string]::Join(
    "`n",
    @(
        '        shell: bash',
        '        run: |',
        '          if [[ "${{ needs.core-contracts.result }}" != "success" || "${{ needs.orchestration.result }}" != "success" ]]; then',
        '            echo "core-contracts=${{ needs.core-contracts.result }} orchestration=${{ needs.orchestration.result }}"',
        '            exit 1',
        '          fi',
        ''))
if (-not $primaryAggregateJob.Success -or
    $primaryAggregateBody -notmatch '(?m)^    name:\s*Release and workflow contracts\s*$' -or
    $primaryAggregateBody -notmatch '(?m)^    if:\s*\$\{\{ always\(\) \}\}\s*$' -or
    $primaryAggregateBody -notmatch '(?m)^    needs:\s*\[core-contracts, orchestration\]\s*$' -or
    $primaryAggregateBody.Contains('continue-on-error:', [StringComparison]::OrdinalIgnoreCase) -or
    -not $primaryAggregateStep.Success -or
    $primaryAggregateStep.Groups['body'].Value.Replace("`r`n", "`n") -cne $expectedPrimaryAggregateStepBody) {
    throw 'CI must preserve the Release and workflow contracts aggregate and require both core and orchestration success.'
}
$personalReleaseFreezeText = Get-Content -Raw -LiteralPath (
    Join-Path $RepositoryRoot '.github\workflows\personal-release-freeze.yml')
if ($personalReleaseFreezeText -match '(?m)^\s*\.\\release\\scripts\\Test-LauncherProductionReleaseOrchestration\.ps1(?:\s|$)') {
    throw 'Personal release freeze must not duplicate the main CI-owned production orchestration shards.'
}
$personalBuilderTestIndex = $personalCiText.IndexOf(
    '.\scripts\Test-PersonalSourceRuntimeArtifact.ps1',
    [StringComparison]::Ordinal)
$personalPayloadTestIndex = $personalCiText.IndexOf(
    '.\scripts\Test-PersonalDevelopmentRuntimeArtifactPayload.ps1',
    [StringComparison]::Ordinal)
$solutionBuildIndex = $personalCiText.IndexOf(
    'dotnet build .\Ensou.Dsh.slnx --configuration Release',
    [StringComparison]::Ordinal)
if ($solutionBuildIndex -lt 0 -or
    $personalBuilderTestIndex -le $solutionBuildIndex -or
    $personalPayloadTestIndex -le $solutionBuildIndex) {
    throw 'CI must run the Personal source-runtime artifact chain after the Release solution build.'
}
$personalNoRestorePublishCount = [regex]::Matches(
    $personalCiText,
    '(?m)^\s+--no-restore\s+`\s*$').Count
if ($personalNoRestorePublishCount -ne 2) {
    throw 'CI must reuse the locked solution restore for both Personal publish phases.'
}

function Assert-PersonalCiAccountOriginBinding {
    param([Parameter(Mandatory = $true)][string]$WorkflowText)

    $step = [regex]::Match($WorkflowText,
        '(?ms)^      - name: Publish and validate single-file client artifacts\r?\n(?<body>.*?)(?=^      - name:|\z)')
    $run = [regex]::Match($step.Groups['body'].Value,
        '(?m)^        run: \|\r?\n(?<script>(?:(?:^[ \t]{10,}.*|^[ \t]*)(?:\r?\n|\z))*)')
    $scriptText = [regex]::Replace($run.Groups['script'].Value, '(?m)^ {10}', '')
    $parseErrors = $null
    $tokens = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput(
        $scriptText, [ref]$tokens, [ref]$parseErrors)
    $clientPublishes = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -ceq 'dotnet' -and
        $node.CommandElements.Count -gt 2 -and
        $node.CommandElements[1].Extent.Text -ceq 'publish' -and
        $node.CommandElements[2].Extent.Text -ceq '$publish[0]'
    }, $true))
    if (-not $step.Success -or -not $run.Success -or
        $parseErrors.Count -ne 0 -or $clientPublishes.Count -ne 1) {
        throw 'Personal CI must expose one parseable shared client publish command.'
    }
    $literalArguments = @($clientPublishes[0].CommandElements |
        Where-Object { $_ -is [Management.Automation.Language.StringConstantExpressionAst] } |
        ForEach-Object Value)
    $accountArguments = @($literalArguments |
        Where-Object { $_.StartsWith('-p:PersonalAccountOrigin=', [StringComparison]::Ordinal) })
    $publishTokens = @($clientPublishes[0].CommandElements | ForEach-Object { $_.Extent.Text })
    if ($accountArguments.Count -ne 1 -or
        $accountArguments[0] -cne '-p:PersonalAccountOrigin=https://accounts.example.invalid/' -or
        $publishTokens -cnotcontains '-p:PersonalDevelopmentPublish=true') {
        throw 'Personal development CI must bind the immutable test account origin on its actual shared client publish command.'
    }
}
Assert-PersonalCiAccountOriginBinding -WorkflowText $personalCiText

$personalInstallerCommandPath = Join-Path $RepositoryRoot `
    'src\Ensou.Dsh.UpdateEngine\PersonalInstallerCommandLine.cs'
$personalInstallerProgramPath = Join-Path $RepositoryRoot `
    'src\Ensou.Dsh.Personal.Installer\Program.cs'
$personalInstallerTestsPath = Join-Path $RepositoryRoot `
    'tests\Ensou.Dsh.Personal.InstallerTests\Program.cs'
foreach ($requiredPath in @(
    $personalInstallerCommandPath,
    $personalInstallerProgramPath,
    $personalInstallerTestsPath
)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Personal development Installer admission contract is missing: $requiredPath"
    }
}
$personalInstallerCommandText = Get-Content -Raw -LiteralPath `
    $personalInstallerCommandPath
foreach ($required in @(
    '--allow-unsigned-development-install',
    'PersonalInstallerInstallAdmissionException',
    'productionBuild && command.AllowUnsignedDevelopmentInstall',
    '!productionBuild && !command.AllowUnsignedDevelopmentInstall',
    'Machine self-check commands cannot enter Personal installation'
)) {
    if (-not $personalInstallerCommandText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal Installer command admission lost its fail-closed rule: $required"
    }
}
$personalInstallerProgramText = Get-Content -Raw -LiteralPath `
    $personalInstallerProgramPath
$runAsyncIndex = $personalInstallerProgramText.IndexOf(
    'private static async Task<int> RunAsync',
    [StringComparison]::Ordinal)
if ($runAsyncIndex -lt 0) {
    throw 'Personal Installer has no ordinary installation entrypoint.'
}
$installAdmissionIndex = $personalInstallerProgramText.IndexOf(
    'PersonalInstallerCommandLine.RequireInstallAllowed',
    $runAsyncIndex,
    [StringComparison]::Ordinal)
$payloadConstructionIndex = $personalInstallerProgramText.IndexOf(
    'var payload = new PersonalEmbeddedInstallerPayloadSource',
    $runAsyncIndex,
    [StringComparison]::Ordinal)
$layoutConstructionIndex = $personalInstallerProgramText.IndexOf(
    'PersonalInstallationLayout.CreateDefault',
    $runAsyncIndex,
    [StringComparison]::Ordinal)
if ($installAdmissionIndex -le $runAsyncIndex -or
    $payloadConstructionIndex -le $installAdmissionIndex -or
    $layoutConstructionIndex -le $installAdmissionIndex -or
    -not $personalInstallerProgramText.Contains(
        'exception is not PersonalInstallerInstallAdmissionException',
        [StringComparison]::Ordinal)) {
    throw 'Personal Installer must refuse unsigned-development install before payload/layout mutation and without a refusal log write.'
}
$personalInstallerTestsText = Get-Content -Raw -LiteralPath `
    $personalInstallerTestsPath
foreach ($required in @(
    'Installer command line fails closed for unsigned development',
    'productionBuild: false',
    'productionBuild: true',
    '--allow-unsigned-development-Install',
    'PersonalInstallerCommandLine.DevelopmentOverrideArgument',
    'PersonalInstallerCommandLine.BinarySelfCheckArgument'
)) {
    if (-not $personalInstallerTestsText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal Installer command admission regression is missing: $required"
    }
}
if (-not $personalCiText.Contains(
        '.\tests\Ensou.Dsh.Personal.InstallerTests\Ensou.Dsh.Personal.InstallerTests.csproj',
        [StringComparison]::Ordinal)) {
    throw 'CI no longer runs the Personal Installer admission regression.'
}

if ($promotionText -notmatch 'Test-SourceRuntimeMetadata\.ps1' -or
    $promotionText -notmatch '\$metadata\.promotionEligible -ne \$true' -or
    $promotionText -notmatch '@\(\$release\.assets\)\.Count -ne 3' -or
    $promotionText -notmatch 'ensou-dsh-source-candidate/\$env:RELEASE_ID' -or
    $promotionText -notmatch 'releases/tags/\$reservationTag' -or
    $promotionText -notmatch '@\(\$reservationRelease\.assets\)\.Count -ne 0' -or
    $promotionText -notmatch 'reservationRelease\.target_commitish -cne' -or
    $publisherText -notmatch 'reservation\.target_commitish -cne \$LauncherSourceCommit' -or
    $promotionText -match 'runtimeClosureAgainstPinnedLock' -or
    $promotionText -match 'versions\\locked\.json') {
    throw 'Promotion must validate immutable candidate metadata without coupling it to the current source lock.'
}
if ($buildCandidateText -notmatch '(?ms)^  build:.*?permissions:\s*\r?\n\s*contents: read.*?^  publish:' -or
    $buildCandidateText -notmatch '(?ms)^  publish:.*?permissions:\s*\r?\n\s*contents: write' -or
    $buildCandidateText -notmatch 'foreach \(\$attempt in 1\.\.30\)' -or
    $buildCandidateText -notmatch 'confirmedReservation\.id -ne \$reservationId' -or
    $buildCandidateText -notmatch '@\(\$confirmedReservation\.assets\)\.Count -ne 0' -or
    $buildCandidateText -notmatch '\$byTag\.id -ne \$reservationId' -or
    $buildCandidateText -notmatch 'git/ref/tags/\$encodedTagName' -or
    $buildCandidateText -notmatch 'actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c' -or
    $buildCandidateText -notmatch 'artifact-ids:\s*\$\{\{ needs\.build\.outputs\.actions_artifact_id \}\}' -or
    $buildCandidateText -notmatch 'Publish-SourceRuntimeCandidate\.ps1' -or
    $buildCandidateText -match '-LocalLab') {
    throw 'Candidate workflow must isolate read-only source build from exact-artifact immutable publication and must never enable LocalLab.'
}
if ($publisherText.Contains(
        '-InFile $input.File.FullName',
        [StringComparison]::Ordinal)) {
    throw 'Candidate publisher must never reopen a verified asset path for upload.'
}
if ($publisherText -notmatch 'FileShare\]::Read' -or
    $publisherText -notmatch 'Read-LockedReleaseInputBytes' -or
    $publisherText -notmatch 'Read-StrictJsonObject `?\r?\n?\s*\$metadataFile' -or
    $publisherText -notmatch 'Read-LockedAsciiText `?\r?\n?\s*\$hashFile' -or
    $publisherText -notmatch 'Assert-LockedReleaseInputUnchanged' -or
    $publisherText -notmatch 'function Send-LockedReleaseAsset' -or
    $publisherText -notmatch '\$uploaded\s*=\s*Send-LockedReleaseAsset' -or
    $publisherText -notmatch 'Net\.Http\.StreamContent' -or
    $publisherText -notmatch 'Headers\.ContentLength\s*=\s*\[int64\]\$Descriptor\.Length' -or
    $publisherText -notmatch '\$Leases\.Add\(\$request\)' -or
    $publisherText -notmatch 'uploadHttpClient\.Timeout\s*=\s*\[Threading\.Timeout\]::InfiniteTimeSpan' -or
    $publisherText -notmatch 'draft\s*=\s*\$true' -or
    $publisherText -notmatch 'application/octet-stream' -or
    $publisherText -notmatch 'draft\s*=\s*\$false' -or
    $publisherText -notmatch 'foreach \(\$attempt in 1\.\.30\)' -or
    $publisherText -notmatch 'immutableRelease\.immutable' -or
    $publisherText -notmatch 'Final artifact-bearing Release tag' -or
    $publisherText -match 'Expand-Archive|ZipArchive|node\.exe|Start-Process') {
    throw 'Candidate publisher must hold exact opaque inputs, re-download three draft assets, and confirm an immutable lightweight final tag.'
}

# Execute the exact publication lease/parser/upload helpers without running the
# networked publisher body. Direct file mutations must remain denied, and a
# parent-directory namespace swap must not change the bytes sent by the locked
# stream upload.
$publisherPath = Join-Path $RepositoryRoot `
    'release/scripts/Publish-SourceRuntimeCandidate.ps1'
$publisherTokens = $null
$publisherParseErrors = $null
$publisherAst = [Management.Automation.Language.Parser]::ParseFile(
    $publisherPath,
    [ref]$publisherTokens,
    [ref]$publisherParseErrors)
if ($publisherParseErrors.Count -ne 0) {
    throw "Candidate publisher has parse errors: $($publisherParseErrors[0].Message)"
}
foreach ($functionName in @(
    'Get-OrdinaryReleaseInput',
    'Get-LockedReleaseInputSha256',
    'Read-LockedReleaseInputBytes',
    'Assert-LockedReleaseInputUnchanged',
    'Send-LockedReleaseAsset',
    'Assert-NoDuplicateJsonMembers',
    'Read-StrictJsonObject')) {
    $definitions = @($publisherAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $functionName
    }, $true))
    if ($definitions.Count -ne 1) {
        throw "Expected one $functionName definition in the candidate publisher."
    }
    . ([scriptblock]::Create($definitions[0].Extent.Text))
}

if ($null -eq ('CandidateUploadCaptureHandler' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public sealed class CandidateUploadCaptureHandler : HttpMessageHandler
{
    public byte[] CapturedBytes { get; private set; }
    public long? CapturedContentLength { get; private set; }
    public string CapturedContentType { get; private set; }
    public string CapturedMethod { get; private set; }
    public Uri CapturedRequestUri { get; private set; }
    public Dictionary<string, string[]> CapturedHeaders { get; private set; }
    public HttpStatusCode ResponseStatusCode { get; set; }
    public string ResponseJson { get; set; }

    public CandidateUploadCaptureHandler()
    {
        CapturedBytes = new byte[0];
        CapturedContentType = string.Empty;
        CapturedMethod = string.Empty;
        CapturedHeaders = new Dictionary<string, string[]>(
            StringComparer.OrdinalIgnoreCase);
        ResponseStatusCode = HttpStatusCode.Created;
        ResponseJson = "{}";
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        CapturedMethod = request.Method.Method;
        CapturedRequestUri = request.RequestUri;
        CapturedContentLength = request.Content.Headers.ContentLength;
        CapturedContentType = request.Content.Headers.ContentType == null
            ? string.Empty
            : request.Content.Headers.ContentType.MediaType;
        CapturedHeaders.Clear();
        foreach (var header in request.Headers)
        {
            CapturedHeaders.Add(header.Key, header.Value.ToArray());
        }
        CapturedBytes = await request.Content.ReadAsByteArrayAsync()
            .ConfigureAwait(false);
        return new HttpResponseMessage(ResponseStatusCode)
        {
            Content = new StringContent(
                ResponseJson,
                Encoding.UTF8,
                "application/json")
        };
    }
}
'@
}

$publicationLeaseRoot = Join-Path ([IO.Path]::GetTempPath()) (
        'ensou-candidate-publication-lease-' + [guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($publicationLeaseRoot) | Out-Null
    $publicationLeases = [Collections.Generic.List[IDisposable]]::new()
    try {
        $leaseInputRoot = Join-Path $publicationLeaseRoot 'admitted'
        [IO.Directory]::CreateDirectory($leaseInputRoot) | Out-Null
        $leaseInputPath = Join-Path $leaseInputRoot `
            'candidate.metadata.json'
        $replacementPath = Join-Path $leaseInputRoot 'replacement.json'
        $renamedPath = Join-Path $leaseInputRoot 'renamed.json'
        $backupPath = Join-Path $leaseInputRoot 'backup.json'
        $expectedLeaseBytes = [Text.UTF8Encoding]::new($false).GetBytes(
            '{"identity":"locked-production-bytes","ordinal":1}')
        [IO.File]::WriteAllBytes($leaseInputPath, $expectedLeaseBytes)
        [IO.File]::WriteAllText(
            $replacementPath,
            '{"identity":"replacement-bytes","ordinal":2}',
            [Text.UTF8Encoding]::new($false))
        $lockedDescriptor = Get-OrdinaryReleaseInput `
            $leaseInputPath 'candidate.metadata.json' (4KB) `
            $publicationLeases
        $expectedLeaseSha256 = Get-LockedReleaseInputSha256 `
            $lockedDescriptor
        $parsedLockedInput = Read-StrictJsonObject `
            $lockedDescriptor 'Candidate publication lease fixture'
        if ($parsedLockedInput.identity -cne 'locked-production-bytes' -or
            [int]$parsedLockedInput.ordinal -ne 1) {
            throw 'Candidate publisher parser did not read the locked descriptor bytes.'
        }

        if ($IsWindows) {
            $mutationAttempts = [ordered]@{
                overwrite = {
                    [IO.File]::WriteAllText(
                        $leaseInputPath,
                        '{"identity":"overwritten","ordinal":3}',
                        [Text.UTF8Encoding]::new($false))
                }
                replace = {
                    [IO.File]::Replace(
                        $replacementPath,
                        $leaseInputPath,
                        $backupPath)
                }
                rename = {
                    [IO.File]::Move($leaseInputPath, $renamedPath)
                }
                delete = {
                    [IO.File]::Delete($leaseInputPath)
                }
            }
            foreach ($attempt in $mutationAttempts.GetEnumerator()) {
                $denied = $false
                try {
                    & $attempt.Value
                }
                catch {
                    $failure = $_.Exception
                    while ($null -ne $failure.InnerException) {
                        $failure = $failure.InnerException
                    }
                    if ($failure -isnot [IO.IOException] -and
                        $failure -isnot [UnauthorizedAccessException]) {
                        throw
                    }
                    $denied = $true
                }
                if (-not $denied) {
                    throw "Candidate publication lease allowed $($attempt.Key)."
                }
                $uploadBytes = [IO.File]::ReadAllBytes($leaseInputPath)
                try {
                    if ([Convert]::ToHexString($uploadBytes) -cne
                        [Convert]::ToHexString($expectedLeaseBytes)) {
                        throw "Candidate publication $($attempt.Key) attempt split verified and upload bytes."
                    }
                }
                finally {
                    [Array]::Clear($uploadBytes, 0, $uploadBytes.Length)
                }
            }
            $parsedLockedInputAgain = Read-StrictJsonObject `
                $lockedDescriptor `
                'Candidate publication lease fixture after mutation attempts'
            if ($parsedLockedInputAgain.identity -cne
                    'locked-production-bytes' -or
                [int]$parsedLockedInputAgain.ordinal -ne 1) {
                throw 'Candidate publisher locked parser bytes changed after denied mutations.'
            }
            Write-Host 'PASS  Candidate publisher locked-stream parser and overwrite/replace/rename/delete lease behavior.'
        }

        # Unix permits a leased child's parent namespace to move; Windows may
        # deny that move because FileShare.Read omits delete sharing. Exercise
        # the real swap where supported and use an independent same-name,
        # same-length malicious path fixture when the platform already denied
        # the namespace mutation. Either way, only the locked stream may upload.
        $movedInputRoot = Join-Path $publicationLeaseRoot 'admitted-moved'
        $maliciousPathBytes = [Text.Encoding]::ASCII.GetBytes(
            'X' * $expectedLeaseBytes.Length)
        $namespaceSwapSucceeded = $false
        $namespaceMoveDenied = $false
        try {
            [IO.Directory]::Move($leaseInputRoot, $movedInputRoot)
            $namespaceSwapSucceeded = $true
        }
        catch {
            $failure = $_.Exception
            while ($null -ne $failure.InnerException) {
                $failure = $failure.InnerException
            }
            if (-not $IsWindows -or
                ($failure -isnot [IO.IOException] -and
                    $failure -isnot [UnauthorizedAccessException])) {
                throw
            }
            $namespaceMoveDenied = $true
        }
        if ($namespaceSwapSucceeded) {
            [IO.Directory]::CreateDirectory($leaseInputRoot) | Out-Null
            $maliciousFixturePath = $leaseInputPath
        }
        else {
            if (-not $namespaceMoveDenied) {
                throw 'Parent namespace mutation produced no explicit platform result.'
            }
            $maliciousFixtureRoot = Join-Path `
                $publicationLeaseRoot `
                'same-name-malicious-fixture'
            [IO.Directory]::CreateDirectory($maliciousFixtureRoot) |
                Out-Null
            $maliciousFixturePath = Join-Path `
                $maliciousFixtureRoot `
                $lockedDescriptor.Name
        }
        [IO.File]::WriteAllBytes(
            $maliciousFixturePath,
            $maliciousPathBytes)
        if ([IO.Path]::GetFileName($maliciousFixturePath) -cne
                $lockedDescriptor.Name) {
            throw 'Malicious upload comparison fixture lost the locked file name.'
        }

        $captureHandler = [CandidateUploadCaptureHandler]::new()
        $captureHandler.ResponseJson = @{
            name = 'candidate.metadata.json'
            state = 'uploaded'
            size = $expectedLeaseBytes.Length
            id = 4242
            url = 'https://api.example.invalid/assets/4242'
        } | ConvertTo-Json -Compress
        $captureClient = [Net.Http.HttpClient]::new($captureHandler, $true)
        $publicationLeases.Add($captureClient)
        $uploadHeaders = @{
            Authorization = 'Bearer fixture-token'
            Accept = 'application/vnd.github+json'
            'X-GitHub-Api-Version' = '2026-03-10'
            'User-Agent' = 'ensou-dsh-source-candidate-publisher'
        }
        $captureUri = [Uri](
            'https://uploads.example.invalid/releases/7/assets' +
            '?name=candidate.metadata.json')
        $uploadResponse = Send-LockedReleaseAsset `
            $captureClient `
            $captureUri `
            $uploadHeaders `
            $lockedDescriptor `
            $publicationLeases

        $capturedAuthorization = [string]::Join(
            ',',
            [string[]]$captureHandler.CapturedHeaders['Authorization'])
        $capturedAccept = [string]::Join(
            ',',
            [string[]]$captureHandler.CapturedHeaders['Accept'])
        $capturedApiVersion = [string]::Join(
            ',',
            [string[]]$captureHandler.CapturedHeaders[
                'X-GitHub-Api-Version'])
        $capturedUserAgent = [string]::Join(
            ',',
            [string[]]$captureHandler.CapturedHeaders['User-Agent'])
        if ([Convert]::ToHexString($captureHandler.CapturedBytes) -cne
                [Convert]::ToHexString($expectedLeaseBytes) -or
            [Convert]::ToHexString($captureHandler.CapturedBytes) -ceq
                [Convert]::ToHexString($maliciousPathBytes) -or
            [int64]$captureHandler.CapturedContentLength -ne
                [int64]$expectedLeaseBytes.Length -or
            $captureHandler.CapturedContentType -cne
                'application/octet-stream' -or
            $captureHandler.CapturedMethod -cne 'POST' -or
            $captureHandler.CapturedRequestUri.AbsoluteUri -cne
                $captureUri.AbsoluteUri -or
            $capturedAuthorization -cne 'Bearer fixture-token' -or
            $capturedAccept -cne 'application/vnd.github+json' -or
            $capturedApiVersion -cne '2026-03-10' -or
            $capturedUserAgent -cne
                'ensou-dsh-source-candidate-publisher') {
            throw 'Locked-stream asset upload lost its exact bytes, length, URI, content type, method, or token headers.'
        }
        if ([string]$uploadResponse.name -cne 'candidate.metadata.json' -or
            [string]$uploadResponse.state -cne 'uploaded' -or
            [int64]$uploadResponse.size -ne $expectedLeaseBytes.Length -or
            [int64]$uploadResponse.id -ne 4242 -or
            -not $lockedDescriptor.Stream.CanRead -or
            $lockedDescriptor.Stream.Position -ne 0) {
            throw 'Locked-stream asset upload lost its 201 JSON response or reusable stream state.'
        }

        Assert-LockedReleaseInputUnchanged `
            $lockedDescriptor `
            $expectedLeaseBytes.Length `
            $expectedLeaseSha256
        $parsedAfterUpload = Read-StrictJsonObject `
            $lockedDescriptor `
            'Candidate publication lease fixture after stream upload'
        if ($parsedAfterUpload.identity -cne 'locked-production-bytes' -or
            [int]$parsedAfterUpload.ordinal -ne 1 -or
            $lockedDescriptor.Stream.Position -ne 0) {
            throw 'Upload request/content lifetime closed or moved the locked stream before later checks.'
        }

        $unexpectedStatusHandler = [CandidateUploadCaptureHandler]::new()
        $unexpectedStatusHandler.ResponseStatusCode =
            [Net.HttpStatusCode]::OK
        $unexpectedStatusClient = [Net.Http.HttpClient]::new(
            $unexpectedStatusHandler,
            $true)
        $publicationLeases.Add($unexpectedStatusClient)
        $unexpectedStatusRejected = $false
        try {
            Send-LockedReleaseAsset `
                $unexpectedStatusClient `
                $captureUri `
                $uploadHeaders `
                $lockedDescriptor `
                $publicationLeases | Out-Null
        }
        catch {
            if ($_.Exception.Message -cnotmatch
                'unexpected HTTP status: 200') {
                throw
            }
            $unexpectedStatusRejected = $true
        }
        if (-not $unexpectedStatusRejected -or
            $lockedDescriptor.Stream.Position -ne 0) {
            throw 'Locked-stream asset upload accepted a non-201 status or lost stream position on failure.'
        }

        $namespaceResult = if ($namespaceSwapSucceeded) {
            'real parent namespace replacement'
        }
        else {
            'Windows FileShare parent-move denial plus same-name fixture'
        }
        Write-Host "PASS  Candidate publisher uploads locked bytes with exact HTTP identity and lifetime: $namespaceResult."
    }
    finally {
        for ($leaseIndex = $publicationLeases.Count - 1;
            $leaseIndex -ge 0;
            $leaseIndex--) {
            $publicationLeases[$leaseIndex].Dispose()
        }
        if (Test-Path -LiteralPath $publicationLeaseRoot) {
            [IO.Directory]::Delete($publicationLeaseRoot, $true)
        }
    }

function Assert-ClientBootstrapperMachineFailureContract {
    param(
        [Parameter(Mandatory)]
        [string]$SourceText,
        [Parameter(Mandatory)]
        [pscustomobject]$Contract,
        [Parameter(Mandatory)]
        [string]$Label
    )

    $mainStart = $SourceText.IndexOf(
        'private static int Main(string[] args)',
        [StringComparison]::Ordinal)
    $mainEnd = $SourceText.IndexOf(
        'private static bool IsMachineCommandIntent',
        [StringComparison]::Ordinal)
    if ($mainStart -lt 0 -or $mainEnd -le $mainStart) {
        throw "ClientBootstrapper Main boundary is missing: $Label"
    }

    $mainText = $SourceText.Substring($mainStart, $mainEnd - $mainStart)
    $tryIndex = $mainText.IndexOf('try', [StringComparison]::Ordinal)
    $applicationIndex = $mainText.IndexOf(
        'ApplicationConfiguration.Initialize();',
        [StringComparison]::Ordinal)
    $catchStart = $mainText.IndexOf(
        'catch (Exception exception)',
        [StringComparison]::Ordinal)
    if ($tryIndex -lt 0 -or
        $applicationIndex -le $tryIndex -or
        $catchStart -le $applicationIndex) {
        throw "ClientBootstrapper Main must protect ApplicationConfiguration.Initialize with its exception boundary: $Label"
    }
    if ($catchStart -lt 0) {
        throw "ClientBootstrapper machine-command catch boundary is missing: $Label"
    }

    $catchText = $mainText.Substring($catchStart)
    $guardIndex = $catchText.IndexOf(
        $Contract.MachineFailureGuard,
        [StringComparison]::Ordinal)
    $writeIndex = $catchText.IndexOf(
        'WriteMachineCommandFailure();',
        [StringComparison]::Ordinal)
    if ($guardIndex -lt 0) {
        throw "ClientBootstrapper machine failure guard is missing: $Label"
    }
    if ($writeIndex -lt 0) {
        throw "ClientBootstrapper machine failure writer is missing: $Label"
    }
    $elseIndex = $catchText.IndexOf(
        'else', $writeIndex, [StringComparison]::Ordinal)
    $messageBoxIndex = $catchText.IndexOf(
        'MessageBox.Show(', [StringComparison]::Ordinal)
    if ($writeIndex -le $guardIndex -or
        $elseIndex -le $writeIndex -or
        $messageBoxIndex -le $elseIndex) {
        throw "ClientBootstrapper machine command can enter interactive failure UI: $Label"
    }
}

function Assert-ExpectedContractFailure {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Action,
        [Parameter(Mandatory)]
        [string]$ExpectedMessage,
        [Parameter(Mandatory)]
        [string]$Label
    )

    try {
        & $Action
    }
    catch {
        if ($_.Exception.Message -ceq $ExpectedMessage) {
            return
        }
        throw "Contract negative $Label threw an unexpected failure: $($_.Exception.Message)"
    }
    throw "Contract negative $Label unexpectedly passed."
}

$clientBootstrapperMachineContracts = @(
    [pscustomobject]@{
        Source = Join-Path $RepositoryRoot `
            'src\Ensou.Dsh.ClientBootstrapper\Program.cs'
        ArtifactTest = Join-Path $RepositoryRoot `
            'scripts\Test-PersonalPublishedArtifacts.ps1'
        Failure =
            'Ensou DSH Personal ClientBootstrapper machine command failed.'
        RequiredArguments = @(
            '["--binary-self-check"]'
        )
        HealthCommandPattern =
            '(?ms)\[\s*"--release-health-token",\s*var token,\s*PersonalHealthBudgetV1\.ActiveDeadlineArgument,\s*var deadlineValue\]\s*=>'
        RequiredIntent = @(
            'IsMachineCommandIntent(IReadOnlyList<string> args)',
            '&& args[0] is "--binary-self-check"',
            'or "--release-health-token"',
            'or PersonalLauncherRestartHandoffCommand.CommandSwitch'
        )
        RequiredHealthDeadline = @(
            'PersonalHealthBudgetV1.ParseDeadlineTickCount64(',
            'PersonalHealthBudgetV1.CreateCancellationUntil(',
            'healthCommand.Deadline!.Value'
        )
        MachineFailureGuard = 'if (isMachineCommand || developmentE2ECompiled)'
        RequiredArtifactCases = @(
            "Name = 'missing-token'",
            "Name = 'extra-token-argument'",
            "Name = 'extra-self-check-argument'"
        )
    },
    [pscustomobject]@{
        Source = Join-Path $RepositoryRoot `
            'src\Ensou.Dsh.Enterprise.ClientBootstrapper\Program.cs'
        ArtifactTest = Join-Path $RepositoryRoot `
            'scripts\Test-EnterprisePublishedArtifacts.ps1'
        Failure =
            'Ensou DSH Enterprise ClientBootstrapper machine command failed.'
        RequiredArguments = @(
            '["--binary-self-check"]',
            '["--installation-self-check"]',
            '["--release-health-token", var token]'
        )
        RequiredIntent = @(
            'IsMachineCommandIntent(IReadOnlyList<string> args)',
            '&& args[0] is "--binary-self-check"',
            'or "--installation-self-check"',
            'or "--release-health-token"'
        )
        HealthCommandPattern = $null
        RequiredHealthDeadline = @()
        MachineFailureGuard = 'else if (isMachineCommand)'
        RequiredArtifactCases = @(
            "Name = 'missing-token'",
            "Name = 'extra-token-argument'",
            "Name = 'extra-self-check-argument'",
            "Name = 'extra-installation-check-argument'"
        )
    }
)
foreach ($contract in $clientBootstrapperMachineContracts) {
    $sourceText = Get-Content -Raw -LiteralPath $contract.Source
    Assert-ClientBootstrapperMachineFailureContract `
        -SourceText $sourceText `
        -Contract $contract `
        -Label $contract.Source
    if (-not $sourceText.Contains(
            'WriteMachineCommandFailure();',
            [StringComparison]::Ordinal) -or
        -not $sourceText.Contains(
            $contract.Failure,
            [StringComparison]::Ordinal)) {
        throw "ClientBootstrapper machine command can enter interactive failure UI: $($contract.Source)"
    }
    foreach ($argumentContract in $contract.RequiredArguments) {
        if (-not $sourceText.Contains(
                $argumentContract,
                [StringComparison]::Ordinal)) {
            throw "ClientBootstrapper machine command classification is missing: $argumentContract"
        }
    }
    if ($null -ne $contract.HealthCommandPattern -and
        -not [regex]::IsMatch(
            $sourceText,
            $contract.HealthCommandPattern,
            [Text.RegularExpressions.RegexOptions]::CultureInvariant)) {
        throw 'ClientBootstrapper health command no longer requires the versioned token/deadline argument tuple.'
    }
    foreach ($intentContract in $contract.RequiredIntent) {
        if (-not $sourceText.Contains(
                $intentContract,
                [StringComparison]::Ordinal)) {
            throw "ClientBootstrapper machine command intent classification is missing: $intentContract"
        }
    }
    foreach ($healthDeadlineContract in $contract.RequiredHealthDeadline) {
        if (-not $sourceText.Contains(
                $healthDeadlineContract,
                [StringComparison]::Ordinal)) {
            throw "ClientBootstrapper health deadline contract is missing: $healthDeadlineContract"
        }
    }
    $artifactTestText = Get-Content -Raw -LiteralPath $contract.ArtifactTest
    foreach ($required in @(
        'Assert-NonInteractiveClientBootstrapperHealthFailure',
        '--release-health-token',
        'blocked on interactive UI',
        $contract.Failure
    )) {
        if (-not $artifactTestText.Contains(
                $required,
                [StringComparison]::Ordinal)) {
            throw "Published ClientBootstrapper real failure regression is missing: $required"
        }
    }
    foreach ($requiredCase in $contract.RequiredArtifactCases) {
        if (-not $artifactTestText.Contains(
                $requiredCase,
                [StringComparison]::Ordinal)) {
            throw "Published ClientBootstrapper malformed-command regression is missing: $requiredCase"
        }
    }
}

# Exercise the exact Personal branch contract against the current source and
# two focused regressions: the obsolete strict-only guard and a UI mutation.
$personalMachineContract = $clientBootstrapperMachineContracts[0]
$personalMachineSource = Get-Content -Raw -LiteralPath $personalMachineContract.Source
Assert-ClientBootstrapperMachineFailureContract `
    -SourceText $personalMachineSource `
    -Contract $personalMachineContract `
    -Label 'current Personal ClientBootstrapper source'
Assert-ExpectedContractFailure `
    -Action {
    Assert-ClientBootstrapperMachineFailureContract `
        -SourceText $personalMachineSource.Replace(
            'if (isMachineCommand || developmentE2ECompiled)',
            'if (isMachineCommand)') `
        -Contract $personalMachineContract `
        -Label 'obsolete Personal strict-only machine guard'
    } `
    -ExpectedMessage 'ClientBootstrapper machine failure guard is missing: obsolete Personal strict-only machine guard' `
    -Label 'obsolete Personal strict-only machine guard'
Assert-ExpectedContractFailure `
    -Action {
    Assert-ClientBootstrapperMachineFailureContract `
        -SourceText $personalMachineSource.Replace(
            'WriteMachineCommandFailure();',
            'MessageBox.Show(exception.Message);') `
        -Contract $personalMachineContract `
        -Label 'Personal interactive machine-failure mutation'
    } `
    -ExpectedMessage 'ClientBootstrapper machine failure writer is missing: Personal interactive machine-failure mutation' `
    -Label 'Personal interactive machine-failure mutation'
$initializeCall = 'ApplicationConfiguration.Initialize();'
$initializeCallIndex = $personalMachineSource.IndexOf(
    $initializeCall, [StringComparison]::Ordinal)
$initializeTryIndex = $personalMachineSource.LastIndexOf(
    '        try', $initializeCallIndex, [StringComparison]::Ordinal)
if ($initializeCallIndex -lt 0 -or $initializeTryIndex -lt 0) {
    throw 'ClientBootstrapper machine-command contract could not locate its initialization sample.'
}
$initializeBeforeTry = $personalMachineSource.Remove(
    $initializeTryIndex,
    ($initializeCallIndex + $initializeCall.Length) - $initializeTryIndex).Insert(
        $initializeTryIndex,
        "        ApplicationConfiguration.Initialize();`n        try`n        {")
if ($initializeBeforeTry -ceq $personalMachineSource) {
    throw 'ClientBootstrapper machine-command contract could not construct its initialization-boundary negative sample.'
}
Assert-ExpectedContractFailure `
    -Action {
    Assert-ClientBootstrapperMachineFailureContract `
        -SourceText $initializeBeforeTry `
        -Contract $personalMachineContract `
        -Label 'Personal initialization-before-try mutation'
    } `
    -ExpectedMessage 'ClientBootstrapper Main must protect ApplicationConfiguration.Initialize with its exception boundary: Personal initialization-before-try mutation' `
    -Label 'Personal initialization-before-try mutation'
$healthDeadlineMutation = $personalMachineSource.Replace(
    'PersonalHealthBudgetV1.ActiveDeadlineArgument',
    '"--obsolete-health-deadline"')
if ([regex]::IsMatch(
        $healthDeadlineMutation,
        $personalMachineContract.HealthCommandPattern,
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)) {
    throw 'ClientBootstrapper machine-command contract accepted a malformed health deadline tuple.'
}

$enterpriseClientPublishedCiGate = Join-Path $RepositoryRoot `
    'scripts\Test-EnterpriseClientBootstrapperPublishedMachineCommands.ps1'
$enterpriseClientPublishedCiGateText = Get-Content -Raw -LiteralPath `
    $enterpriseClientPublishedCiGate
$enterpriseManagedWorkflowText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    '.github\workflows\enterprise-managed-release-v2.yml')
$enterpriseInstallerTrustedBuildPath = Join-Path $RepositoryRoot `
    'release\scripts\EnterpriseInstallerTrustedBuild.psm1'
$enterpriseInstallerTrustedBuildText = Get-Content -Raw -LiteralPath `
    $enterpriseInstallerTrustedBuildPath
$portableDotNetSdkReviewedLockPath = Join-Path $RepositoryRoot `
    'release\locks\dotnet-sdk-10.0.302-win-x64.files.lock.json'
if (-not (Test-Path -LiteralPath $portableDotNetSdkReviewedLockPath -PathType Leaf)) {
    throw 'Enterprise trusted build reviewed portable .NET SDK lock is missing.'
}
foreach ($required in @(
        '[Parameter(Mandatory = $true)][string]$DotNetSdkArchivePath',
        'PortableDotNetSdkClosure\Open-PortableDotNetSdkArchiveClosure',
        'PortableDotNetSdkClosure\New-PortableDotNetSdkPrivateCopy',
        'PortableDotNetSdkClosure\Get-PortableDotNetSdkPrivateToolchain',
        "DOTNET_MULTILEVEL_LOOKUP = '0'",
        'DOTNET_ROOT = $privateDotNetRoot',
        'DOTNET_ROOT_X64 = $privateDotNetRoot',
        'release/locks/dotnet-sdk-10.0.302-win-x64.files.lock.json',
        'launcher-enterprise-installer-signing-request-v2.schema.json',
        "sdkFileClosureStatus = 'VERIFIED'",
        "Blocker = 'INSTALLER_SIGNING_RESPONSE_REQUIRED'")) {
    if (-not $enterpriseInstallerTrustedBuildText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Enterprise trusted build private SDK closure is missing: $required"
    }
}
if ($enterpriseInstallerTrustedBuildText.Contains(
        "Join-Path `$programFiles 'dotnet\dotnet.exe'",
        [StringComparison]::Ordinal)) {
    throw 'Enterprise trusted build contains a forbidden Program Files dotnet fallback.'
}
foreach ($required in @(
    'Ensou.Dsh.Enterprise.ClientBootstrapper.exe',
    "Name = 'health-missing-token'",
    "Name = 'health-extra-argument'",
    "Name = 'binary-extra-argument'",
    "Name = 'installation-extra-argument'",
    'WaitForExit(30000)',
    'blocked on UI',
    'Enterprise ClientBootstrapper published machine-command gate passed.'
)) {
    if (-not $enterpriseClientPublishedCiGateText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Enterprise ClientBootstrapper CI artifact execution gate is missing: $required"
    }
}
foreach ($required in @(
    'dotnet publish',
    'Ensou.Dsh.Enterprise.ClientBootstrapper.csproj',
    '--self-contained true',
    '--no-restore',
    '-p:PublishSingleFile=true',
    '-p:EnterpriseDevelopmentE2E=true',
    'Test-EnterpriseClientBootstrapperPublishedMachineCommands.ps1'
)) {
    if (-not $enterpriseManagedWorkflowText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Enterprise workflow does not publish and execute the real ClientBootstrapper gate: $required"
    }
}
foreach ($required in @(
    '.\scripts\Test-EnterpriseProductionPayloadContract.ps1',
    '.\release\scripts\Test-EnterpriseProductionPublisherAdapter.ps1',
    '.\release\scripts\Test-SourceRuntimeReviewHandoff.ps1',
    '.\release\scripts\Test-ProductionRuntimeSourceReleaseAdmission.ps1',
    '.\release\scripts\Test-EnterpriseSourceAdmissionImportRouting.ps1',
    '.\release\scripts\Test-EnterpriseManifestPublishingResponse.ps1',
    '.\scripts\Test-EnterprisePublishedArtifactsRfc3161Policy.ps1',
    '.\release\scripts\Test-EnterpriseProductionPilotEvidenceAdapter.ps1',
    '.\release\scripts\Test-EnterpriseProductionPilotEvidenceRevalidation.ps1',
    '.\release\scripts\Test-ProductionClientSigningHistory.ps1',
    '.\release\scripts\Test-ProductionClientSigningResponse.ps1',
    '.\release\scripts\Test-EnterpriseInstallerProductionPayloadSelfCheck.ps1',
    '.\release\scripts\Test-ProductionInstallerSigningResponse.ps1',
    '.\release\scripts\Test-EnterpriseProductionReleaseReadiness.ps1',
    '.\release\scripts\Test-InstallerSigningContracts.ps1',
    '.\release\scripts\Test-EnterpriseInstallerTrustedBuild.ps1',
    '-DotNetSdkArchivePath $sdkArchive',
    'https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.302/dotnet-sdk-10.0.302-win-x64.zip',
    'INSTALLER_SIGNING_RESPONSE_REQUIRED'
)) {
    if (-not $enterpriseManagedWorkflowText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Enterprise workflow does not execute a production packaging contract: $required"
    }
}
foreach ($relativePath in @(
    'scripts\EnterpriseProductionPayload.psm1',
    'scripts\New-EnterpriseProductionPayload.ps1',
    'scripts\Test-EnterpriseProductionPayload.ps1',
    'scripts\Test-EnterpriseProductionPayloadContract.ps1',
    'release\scripts\New-EnterpriseProductionPublisherInput.ps1',
    'release\scripts\Test-EnterpriseProductionPublisherAdapter.ps1',
    'release\scripts\Test-SourceRuntimeReviewHandoff.ps1',
    'release\scripts\Test-ProductionRuntimeSourceReleaseAdmission.ps1',
    'release\scripts\Test-EnterpriseSourceAdmissionImportRouting.ps1',
    'release\scripts\New-EnterpriseManifestPublishingResponse.ps1',
    'release\scripts\Test-EnterpriseManifestPublishingResponse.ps1',
    'docs\adr\008-runtime-source-release-admission.md',
    'release\schemas\enterprise-production-publisher-policy-v1.schema.json',
    'release\scripts\EnterpriseProductionPilotEvidence.psm1',
    'release\scripts\New-EnterpriseProductionPilotEvidenceInput.ps1',
    'release\scripts\Test-EnterpriseProductionPilotEvidenceAdapter.ps1',
    'release\scripts\Test-EnterpriseProductionPilotEvidenceRevalidation.ps1',
    'release\scripts\Test-ProductionClientSigningHistory.ps1',
    'release\scripts\New-ProductionClientSigningResponse.ps1',
    'release\scripts\Test-ProductionClientSigningResponse.ps1',
    'release\scripts\EnterpriseInstallerProductionPayloadSelfCheck.psm1',
    'release\scripts\Test-EnterpriseInstallerProductionPayloadSelfCheck.ps1',
    'release\scripts\New-ProductionInstallerSigningResponse.ps1',
    'release\scripts\Test-ProductionInstallerSigningResponse.ps1',
    'release\scripts\Test-EnterpriseProductionReleaseReadiness.ps1',
    'release\scripts\Test-EnterpriseProductionPilotEvidenceCryptography.ps1',
    'release\schemas\enterprise-production-pilot-evidence-input-v1.schema.json',
    'release\schemas\enterprise-production-pilot-evidence-trust-v1.schema.json',
    'release\schemas\enterprise-production-stable-private-pilot-observation-v1.schema.json'
)) {
    $contractPath = Join-Path $RepositoryRoot $relativePath
    if (-not (Test-Path -LiteralPath $contractPath -PathType Leaf)) {
        throw "Enterprise production packaging contract is missing: $relativePath"
    }
}

$sourceAdmissionImportRoutingText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'release\scripts\Test-EnterpriseSourceAdmissionImportRouting.ps1')
foreach ($required in @(
    'Focused routing regression, not a production publisher or device acceptance',
    'GREEN-real-state-source-before-staging-write',
    'TEST_IMPORT_WRITE_BOUNDARY',
    'RUNTIME_SOURCE_RECEIPT_MISMATCH',
    'actual import AST routing'
)) {
    if (-not $sourceAdmissionImportRoutingText.Contains($required, [StringComparison]::Ordinal)) {
        throw "Enterprise source-admission import-routing self-check is missing: $required"
    }
}

$sourceRuntimeReviewHandoffText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'release\scripts\Test-SourceRuntimeReviewHandoff.ps1')
foreach ($required in @(
    'UNSIGNED_REVIEW_INPUT_ONLY',
    'New-SourceRuntimeReviewEvidence',
    'Assert-HandoffRejected',
    'unsigned fact-preservation only, no GitHub calls or admission'
)) {
    if (-not $sourceRuntimeReviewHandoffText.Contains($required, [StringComparison]::Ordinal)) {
        throw "Source-runtime review handoff self-check is missing: $required"
    }
}

$runtimeSourceReleaseTestText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'release\scripts\Test-ProductionRuntimeSourceReleaseAdmission.ps1')
foreach ($required in @(
    'Assert-ProductionRuntimeSourceReleaseHistory',
    '--runtime-source-release-checks',
    'Historical plan without an original source anchor remains explicitly unverified',
    'Historical replay rejects changed raw organization receipt bytes',
    'Historical replay rejects a forged typed r4 receipt binding',
    'Historical replay rejects a forged typed r5 receipt binding',
    'Historical replay rejects a changed current state head'
)) {
    if (-not $runtimeSourceReleaseTestText.Contains($required, [StringComparison]::Ordinal)) {
        throw "Runtime source-release focused self-check is missing: $required"
    }
}

$enterprisePilotAdapterText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'release\scripts\New-EnterpriseProductionPilotEvidenceInput.ps1')
foreach ($required in @(
    'Enter-ProductionReleaseStateReadLock',
    'Get-ProductionReleaseState',
    'ExpectedR7HeadSha256',
    'Get-PeContentSha256',
    'R7_TRUSTED_BUILD_SOURCE_MISSING',
    'R7_PRODUCTION_ADMISSION_REASON_REJECTED',
    'INSTALLER_SIGNING_RESPONSE_REQUIRED',
    'Assert-InstallerSigningResponseContract',
    'Assert-SignedInstallerAuthenticode',
    'Assert-EnterpriseProductionPilotEvidence',
    'plan.pilotEvidenceTrustPolicySha256',
    'R8_TRUST_POLICY_PLAN_ANCHOR_MISMATCH',
    'Open-CertifiedDistributionLockedDirectory',
    'Assert-CertifiedDistributionLockedDirectoryUnchanged',
    'windowsBodyInput.Value.completedAtUtc',
    'Write-R8CreateNewOutput',
    'PILOT_EVIDENCE_INPUT_READY_NO_GO'
)) {
    if (-not $enterprisePilotAdapterText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Enterprise r8 Pilot adapter is not fail-closed: $required"
    }
}
foreach ($forbidden in @(
    'ExpectedPilotTrustPolicySha256',
    'SDK_FILE_CLOSURE_EXTERNAL_HOST_PREREQUISITE',
    'EXTERNAL_HOST_PREREQUISITE_NOT_SNAPSHOTTED',
    'BindPilotEvidence',
    'productionAdmission = ''GO''',
    'productionAdmission = ''ADMITTED'''
)) {
    if ($enterprisePilotAdapterText.Contains(
            $forbidden,
            [StringComparison]::Ordinal)) {
        throw "Enterprise r8 Pilot adapter contains a forbidden admission path: $forbidden"
    }
}

$enterpriseInstallerProgramText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Enterprise.Installer\Program.cs')
$enterpriseLegacyMigrationTestsText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'tests\Ensou.Dsh.Enterprise.LegacyMigrationTests\Program.cs')
foreach ($required in @(
    'private static int Main(string[] args)',
    'RunWithApplicationInitializer(',
    'IsMachineCommand(args)',
    'WriteMachineCommandFailure();',
    'Console.Error.WriteLine(MachineCommandFailureMessage);',
    'Ensou DSH Enterprise Installer machine command failed.'
)) {
    if (-not $enterpriseInstallerProgramText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Enterprise Installer outer machine-failure boundary is missing: $required"
    }
}
foreach ($required in @(
    'InstallerMachineSelfCheckFailuresAreBoundedAsync',
    'Unable to start unsigned Enterprise Installer',
    'process.ExitCode != 1',
    'failure escaped its noninteractive boundary',
    'InstallerApplicationInitializationFailureUsesMachineBoundaryAsync'
)) {
    if (-not $enterpriseLegacyMigrationTestsText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Enterprise Installer unsigned process regression is missing: $required"
    }
}

$enterpriseTrustedStartText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Enterprise.Installation\EnterpriseAuthenticodeVerifier.cs')
$enterpriseBootstrapperStartText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Enterprise.Bootstrapper\Program.cs')
$enterpriseClientBootstrapperStartText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Enterprise.ClientBootstrapper\Program.cs')
$enterpriseInstallationTestsText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'tests\Ensou.Dsh.Enterprise.InstallationTests\Program.cs')
foreach ($required in @(
    'internal sealed class EnterpriseTrustedExecutableLaunchLease',
    'QueryFullProcessImageName(',
    'EnterpriseManagedGcPathSafety.RequireSingleLinkHandle(',
    'EnterpriseManagedGcPathSafety.GetFileIdentity(',
    'FileShare.Read',
    'process.Kill(entireProcessTree: true);',
    'process.WaitForExit(FailedProcessExitWaitMilliseconds)',
    'JobObjectLimitKillOnJobClose',
    'CreateSuspended | CreateUnicodeEnvironment | CreateNoWindow',
    'AssignProcessToJobObject(job, processInformation.ProcessHandle)',
    'ResumeThread(processInformation.ThreadHandle)',
    'TerminateJobObject(job, ContainmentExitCode)',
    'ReadActiveProcessCount(job) == 0',
    'internal EnterpriseTrustedStartedProcess StartContained(',
    'internal static ProcessStartInfo CreateStartInfo(',
    'UseShellExecute = false',
    'CreateNoWindow = true'
)) {
    if (-not $enterpriseTrustedStartText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Enterprise trusted executable start is missing: $required"
    }
}
$enterpriseCreateSuspendedIndex = $enterpriseTrustedStartText.IndexOf(
    'if (!CreateProcess(',
    [StringComparison]::Ordinal)
$enterpriseAssignJobIndex = $enterpriseTrustedStartText.IndexOf(
    'if (!AssignProcessToJobObject(job, processInformation.ProcessHandle))',
    [StringComparison]::Ordinal)
$enterpriseResumeThreadIndex = $enterpriseTrustedStartText.IndexOf(
    'var previousSuspendCount = ResumeThread(processInformation.ThreadHandle);',
    [StringComparison]::Ordinal)
if ($enterpriseCreateSuspendedIndex -lt 0 -or
    $enterpriseAssignJobIndex -le $enterpriseCreateSuspendedIndex -or
    $enterpriseResumeThreadIndex -le $enterpriseAssignJobIndex -or
    $enterpriseTrustedStartText.Contains(
        'CreateBreakawayFromJob',
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Enterprise trusted child must be assigned to a kill-on-close Job before its suspended primary thread resumes, without breakaway.'
}
foreach ($required in @(
    '.OpenTrustedExecutableForLaunch(',
    'using var process = executable.Start(startInfo);',
    'UseShellExecute = false',
    'CreateNoWindow = true'
)) {
    if (-not $enterpriseBootstrapperStartText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Enterprise Bootstrapper trusted child start is missing: $required"
    }
}
foreach ($childStart in @(
    [pscustomobject]@{
        Name = 'Enterprise Bootstrapper'
        Text = $enterpriseBootstrapperStartText
    },
    [pscustomobject]@{
        Name = 'Enterprise ClientBootstrapper'
        Text = $enterpriseClientBootstrapperStartText
    }
)) {
    foreach ($required in @(
        'StartContained(',
        'started.TerminateRequired();',
        'started.CompleteRequired();'
    )) {
        if ($childStart.Text.Contains($required, [StringComparison]::Ordinal)) {
            continue
        }
        throw "$($childStart.Name) health timeout lacks fail-closed process-tree containment."
    }
}
if ($enterpriseBootstrapperStartText.Contains(
        'UseShellExecute = true',
        [StringComparison]::Ordinal) -or
    $enterpriseTrustedStartText.Contains(
        'startVerifiedProcessForTest',
        [StringComparison]::Ordinal)) {
    throw 'Enterprise trusted child start contains a shell/path or test-bypass admission path.'
}
foreach ($required in @(
    'trusted executable launch lease binds the real process image through mutation races',
    'CreateHardLink(',
    'TryCreateDirectoryJunction(linkedRoot, root)',
    'File.Move(executable, renamed)',
    'File.Move(replacement, executable, overwrite: true)',
    'File.Delete(executable)',
    'lease.InspectProcessImageIdentityForTests(process)',
    'enterprise-untrusted-containment-',
    'actualMismatchStart',
    'beforeResumeObserved',
    'AssertEqual(1u, activeProcessesBeforeResume)',
    'AssertFalse(File.Exists(containmentMarker))',
    'WaitForProcessExit(mismatchedForwarderProcessId)',
    'AssertEqual(0, mismatchedFinalProcessId)',
    'DeleteFileWithRetry(mismatchedAppHostPath)',
    'Enterprise containment fixture remained locked after its process tree exited.',
    'new DirectoryInfo(AppContext.BaseDirectory)',
    'configuration is not "Debug" and not "Release"',
    'configurationSegment',
    'TrustedLauncherProbeMarkerEnvironment',
    'EnterpriseTrustedLauncherProcessStarter.Start(',
    'EnterpriseTrustedLauncherProcessStarter.StartContained(',
    'EnterpriseTrustedLauncherProcessStarter.CreateStartInfo('
)) {
    if (-not $enterpriseInstallationTestsText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Enterprise trusted child real-process regression is missing: $required"
    }
}

$personalPublisherProgramText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Personal.ReleasePublisher\Program.cs')
$personalPublisherLedgerText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Personal.ReleasePublisher\PersonalPublisherSigningLedger.cs')
$personalReleasePublisherText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Personal.ReleasePublisher\PersonalReleasePublisher.cs')
if (-not $personalPublisherProgramText.Contains(
        '--check-signing-ledger-upgrade-ready',
        [StringComparison]::Ordinal)) {
    throw 'Personal Publisher read-only signing-ledger upgrade command is missing.'
}
foreach ($required in @(
    '.pending.v2',
    '.pending',
    '.publication.v2',
    'CurrentAnchorSchemaVersion = 2',
    'EnsureCurrentSchemaFence',
    'allowLegacyAnchorSchema: true',
    'CommitPendingPublicationReceipt',
    'TryDeleteCommittedPending',
    'Exact retry is allowed, but a new sequence cannot be signed',
    'conflicting legacy and v2 pending markers',
    'current publisher will not parse, rename, or delete it',
    'publication destination conflicts with the authenticated pending manifest'
)) {
    if (-not $personalPublisherLedgerText.Contains(
            $required,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Personal Publisher v2/legacy recovery contract is missing: $required"
    }
}
foreach ($required in @(
    'cancellationToken.ThrowIfCancellationRequested()',
    'CancellationToken.None',
    'RequireConfiguredSigningKey(verifiedCommitted, config.SigningKeyId)',
    '_beforeFinalCancellationCheckpoint?.Invoke()',
    'RequireCandidateFileIdentity(',
    'information.NumberOfLinks != 1',
    'GetFinalPathNameByHandle(',
    'RequireAllPathsMatchAsync(',
    'probeDescriptor'
)) {
    if (-not $personalReleasePublisherText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal Publisher final commit cancellation boundary is missing: $required"
    }
}
$publisherFinalIdentityCheckpointIndex = $personalReleasePublisherText.IndexOf(
    '_beforeFinalCancellationCheckpoint?.Invoke()',
    [StringComparison]::Ordinal)
$publisherFinalIdentityRecheckIndex = $personalReleasePublisherText.IndexOf(
    'await candidateInputs.RequireAllPathsMatchAsync(CancellationToken.None)',
    [StringComparison]::Ordinal)
$publisherFinalCancellationIndex = $personalReleasePublisherText.IndexOf(
    'cancellationToken.ThrowIfCancellationRequested()',
    [StringComparison]::Ordinal)
$publisherCommitIndex = $personalReleasePublisherText.IndexOf(
    'signingLedger.Commit(',
    [StringComparison]::Ordinal)
$publisherReadbackIndex = $personalReleasePublisherText.IndexOf(
    'var persistedBytes = await File.ReadAllBytesAsync(',
    [StringComparison]::Ordinal)
if ($publisherFinalIdentityCheckpointIndex -lt 0 -or
    $publisherFinalIdentityRecheckIndex -le $publisherFinalIdentityCheckpointIndex -or
    $publisherFinalCancellationIndex -le $publisherFinalIdentityRecheckIndex -or
    $publisherCommitIndex -le $publisherFinalCancellationIndex -or
    $publisherReadbackIndex -le $publisherCommitIndex) {
    throw 'Personal Publisher final identity recheck, cancellation, protected commit, and non-cancellable readback order is invalid.'
}
foreach ($forbidden in @(
    'DeleteTemporaryBeforeCommitAsync',
    'temporaryPath',
    'FileMode.CreateNew',
    'FileAccess.Write',
    'File.WriteAllBytes',
    'File.Move(',
    'File.Delete('
)) {
    if ($personalReleasePublisherText.Contains(
            $forbidden,
            [StringComparison]::Ordinal)) {
        throw "Personal Publisher persists or mutates a plaintext manifest before its protected ledger commit: $forbidden"
    }
}
$publisherProtectedPendingIndex = $personalPublisherLedgerText.IndexOf(
    'WriteProtectedAtomically(_pendingPath, intent, overwrite: false)',
    [StringComparison]::Ordinal)
$publisherPendingCallIndex = $personalPublisherLedgerText.IndexOf(
    '_anchorStore.WritePending(',
    [StringComparison]::Ordinal)
$publisherEntryWriteIndex = $personalPublisherLedgerText.IndexOf(
    'WriteCreateOnlyDurable(Path.Combine(_channelRoot, entryName), entryBytes)',
    [StringComparison]::Ordinal)
if ($publisherProtectedPendingIndex -lt 0 -or
    $publisherPendingCallIndex -lt 0 -or
    $publisherEntryWriteIndex -le $publisherPendingCallIndex) {
    throw 'Personal Publisher does not make the DPAPI pending intent its first transaction write.'
}
$personalPublisherUpdateTestsText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'tests\Ensou.Dsh.Personal.UpdateTests\Program.cs')
foreach ($required in @(
    'personal publisher binds every candidate to one locked file identity',
    'CreateHardLinkForTest(racedHardLink, clientSource)',
    'File.Move(clientSource, renamed)',
    'File.Move(replacement, clientSource, overwrite: true)',
    'personal publisher never persists a pre-commit plaintext manifest',
    'temporaryFilesObserved',
    '--legacy-v1-anchor-admission-probe',
    'c2507cab5d74bb36d64d855a46bffbb66a521f6e',
    'legacy-v1-would-mutate-n-plus-one.txt',
    'publisher-schema-v1-pending-v2-compatibility',
    'personal publisher committed cleanup failure allows exact retry only',
    'PersonalPublisherSigningLedgerCommitStage.PublicationReceiptCommitted',
    'missing-private-key-for-read-only-upgrade-check.pk8'
)) {
    if (-not $personalPublisherUpdateTestsText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal Publisher locked-input/protected-commit regression is missing: $required"
    }
}
foreach ($required in @(
    'The current Publisher never parses, renames, deletes, or converts it',
    'copy `.pending` to `.pending.v2`',
    'never delete either marker to make the',
    'ordinary single-link Windows file handle',
    'manifest signature key ID equals the config signing key ID',
    'schema v2 as a durable downgrade fence',
    'signed manifest exists only in memory',
    'authenticated receipt plus immutable manifest readback',
    'every N+1 or otherwise different publication is',
    'rejected before signing',
    'Do not manually rename, replace, or delete a',
    'cleanup-blocked marker'
)) {
    if (-not $releaseReadmeText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal Publisher controlled legacy recovery runbook is missing: $required"
    }
}

$personalRestartHandoffContractText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Contracts\PersonalLauncherRestartHandoff.cs')
$personalRestartCoordinatorText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Host\LauncherRestartCoordinator.cs')
$personalLauncherAppText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Launcher\App.xaml.cs')
$personalLauncherSettingsText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Launcher\LauncherSettings.cs')
$personalLauncherWindowText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Launcher\MainWindow.xaml.cs')
$personalStartupStubText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Bootstrapper\Program.cs')
$personalClientBootstrapperText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.ClientBootstrapper\Program.cs')
$personalAuthenticodeText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.UpdateEngine\PersonalAuthenticodeVerifier.cs')
$personalCompiledTrustText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.UpdateEngine\PersonalCompiledTrustFingerprint.cs')
$personalMaintenanceIntegrityText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.UpdateEngine\PersonalMaintenanceOperations.cs')
$personalUpdateTestsText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'tests\Ensou.Dsh.Personal.UpdateTests\Program.cs')
$coreTestsText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'tests\Ensou.Dsh.CoreTests\Program.cs')
$dshHostServiceText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Host\DshHostService.cs')
$dshWindowsJobObjectText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Host\WindowsJobObject.cs')
$dshRuntimeLaunchLeaseText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Host\DshRuntimeLaunchLease.cs')
$dshUnassignedContainmentText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Host\DshUnassignedProcessContainment.cs')
$dshLoopbackListenerText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Host\DshLoopbackListenerOwnership.cs')
$dshRuntimeAdmissionTestsText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'tests\Ensou.Dsh.CoreTests\DshRuntimeAdmissionTests.cs')
$dshUnassignedContainmentTestsText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'tests\Ensou.Dsh.CoreTests\DshUnassignedProcessContainmentTests.cs')
$dshLoopbackListenerTestsText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'tests\Ensou.Dsh.CoreTests\DshLoopbackListenerOwnershipTests.cs')
$launcherRestartReceiverRetentionTestsText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'tests\Ensou.Dsh.CoreTests\LauncherRestartReceiverRetentionTests.cs')
$enterpriseLauncherAppText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Enterprise.Launcher\App.xaml.cs')
$enterpriseHostAdapterText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Enterprise.Launcher\DshHostAdapter.cs')
$enterpriseCompatibilityProbeText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.EnterprisePluginCompatibilityRunner\InternalCompatibilityProbe.cs')
function Assert-DshHostPublicConstructorContract {
    param(
        [Parameter(Mandatory)]
        [string]$SourceText,
        [Parameter(Mandatory)]
        [string]$Label
    )

    $firstPublicStart = $SourceText.IndexOf(
        '    public DshHostService(',
        [StringComparison]::Ordinal)
    $secondPublicStart = $SourceText.IndexOf(
        '    public DshHostService(',
        $firstPublicStart + 1,
        [StringComparison]::Ordinal)
    $internalStart = $SourceText.IndexOf(
        '    internal DshHostService(',
        $secondPublicStart + 1,
        [StringComparison]::Ordinal)
    if ($firstPublicStart -lt 0 -or
        $secondPublicStart -le $firstPublicStart -or
        $internalStart -le $secondPublicStart) {
        throw "DSH Host public production constructor boundary is missing: $Label"
    }

    $legacyPublic = $SourceText.Substring(
        $firstPublicStart, $secondPublicStart - $firstPublicStart)
    $diagnosticPublic = $SourceText.Substring(
        $secondPublicStart, $internalStart - $secondPublicStart)
    foreach ($required in @(
        'Action validateBeforeProcessStart',
        'Func<IDshHomeWriterSession>? acquireHomeWriterSession = null)',
        'diagnostic: null)'
    )) {
        if (-not $legacyPublic.Contains(
                $required, [StringComparison]::Ordinal)) {
            throw "DSH Host legacy public constructor no longer delegates to the admitted diagnostic overload: $required ($Label)"
        }
    }
    foreach ($required in @(
        'Action validateBeforeProcessStart',
        'Action<string, Exception?>? diagnostic)',
        'validateBeforeProcessStart',
        '?? throw new ArgumentNullException(',
        'DshLoopbackListenerOwnership',
        '.IsExactProcessListeningOnIpv4Loopback',
        'allowUnleasedRuntimeAdmissionForTests: false',
        'acquireHomeWriterSession,',
        'diagnostic)'
    )) {
        if (-not $diagnosticPublic.Contains(
                $required, [StringComparison]::Ordinal)) {
            throw "DSH Host diagnostic public constructor lost production admission: $required ($Label)"
        }
    }
    if ($legacyPublic.Contains(
            'Action? validateBeforeProcessStart',
            [StringComparison]::Ordinal) -or
        $diagnosticPublic.Contains(
            'Action? validateBeforeProcessStart',
            [StringComparison]::Ordinal)) {
        throw "DSH Host public production constructor may not allow a null complete-tree validator: $Label"
    }

    $publicCount = [regex]::Matches(
        $SourceText,
        [regex]::Escape('public DshHostService('),
        [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
    $internalCount = [regex]::Matches(
        $SourceText,
        [regex]::Escape('internal DshHostService('),
        [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
    $privateCount = [regex]::Matches(
        $SourceText,
        [regex]::Escape('private DshHostService('),
        [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
    if ($publicCount -ne 2 -or $internalCount -ne 3 -or $privateCount -ne 1) {
        throw "DSH Host constructor visibility boundary changed: public=$publicCount internal=$internalCount private=$privateCount ($Label)."
    }
}

Assert-DshHostPublicConstructorContract `
    -SourceText $dshHostServiceText `
    -Label 'current DshHostService source'
$hostPublicValidatorMutation = $dshHostServiceText.Replace(
    'Action validateBeforeProcessStart,',
    'Action? validateBeforeProcessStart,')
$hostPublicValidatorRejected = $false
try {
    Assert-DshHostPublicConstructorContract `
        -SourceText $hostPublicValidatorMutation `
        -Label 'nullable public validator mutation'
}
catch {
    $hostPublicValidatorRejected = $true
}
if (-not $hostPublicValidatorRejected) {
    throw 'DSH Host public constructor contract accepted a nullable validator mutation.'
}
$hostPublicDelegateMutation = $dshHostServiceText.Replace(
    'diagnostic: null)',
    'diagnostic: diagnostic)')
$hostPublicDelegateRejected = $false
try {
    Assert-DshHostPublicConstructorContract `
        -SourceText $hostPublicDelegateMutation `
        -Label 'legacy public delegation mutation'
}
catch {
    $hostPublicDelegateRejected = $true
}
if (-not $hostPublicDelegateRejected) {
    throw 'DSH Host public constructor contract accepted a legacy delegation mutation.'
}
$hostPublicAdmissionMutation = $dshHostServiceText.Replace(
    'allowUnleasedRuntimeAdmissionForTests: false,',
    'allowUnleasedRuntimeAdmissionForTests: true,')
$hostPublicAdmissionRejected = $false
try {
    Assert-DshHostPublicConstructorContract `
        -SourceText $hostPublicAdmissionMutation `
        -Label 'public unleased-admission mutation'
}
catch {
    $hostPublicAdmissionRejected = $true
}
if (-not $hostPublicAdmissionRejected) {
    throw 'DSH Host public constructor contract accepted an unleased-admission mutation.'
}
$productionHostCallsites = @(
    [pscustomobject]@{
        Name = 'Personal Launcher active runtime'
        Text = $personalLauncherAppText
        Start = '_hostService = new DshHostService('
        End = '_launcherWindow = new MainWindow('
        Required = @(
            'validateBeforeProcessStart: () =>',
            'RequireSamePersonalRuntimeForLaunch('
        )
    },
    [pscustomobject]@{
        Name = 'Personal Launcher candidate runtime'
        Text = $personalLauncherAppText
        Start = 'await using var host = new DshHostService('
        End = 'var launched = await host.EnsureStartedAsync(cancellationToken).ConfigureAwait(false);'
        Required = @(
            'validateBeforeProcessStart: () =>',
            'PersonalHarnessWriterGuard.RequireAvailableLoopbackPort(healthPort)',
            'current.Current.HealthState != PersonalReleaseHealthStates.Pending',
            'diagnostic: (phase, exception) => diagnostic.Mark(phase, exception)'
        )
    },
    [pscustomobject]@{
        Name = 'Enterprise Launcher candidate runtime'
        Text = $enterpriseLauncherAppText
        Start = 'await using var host = new DshHostService('
        End = 'var launchResult = await host.EnsureStartedAsync().ConfigureAwait(false);'
        Required = @(
            'validateBeforeProcessStart: () =>',
            'EnterpriseHarnessWriterGuard.RequireQuiescentLoopbackPort(',
            'current.Current.HealthState != EnterpriseReleaseHealthStates.Pending'
        )
    },
    [pscustomobject]@{
        Name = 'Enterprise Host adapter'
        Text = $enterpriseHostAdapterText
        Start = 'return _hostService ??= new DshHostService('
        End = 'private DshHostService? GetExistingHostService()'
        Required = @('validateBeforeProcessStart: _validateRuntime')
    },
    [pscustomobject]@{
        Name = 'Enterprise compatibility runner'
        Text = $enterpriseCompatibilityProbeText
        Start = 'await using var host = new DshHostService('
        End = 'var launched = await host.EnsureStartedAsync('
        Required = @(
            'validateBeforeProcessStart: () =>',
            'EnterpriseRuntimeFileManifest.ValidateCompleteTree(',
            'options.RuntimeDirectory'
        )
    }
)

function Get-RequiredSourceRange {
    param(
        [Parameter(Mandatory)]
        [string]$SourceText,
        [Parameter(Mandatory)]
        [string]$Start,
        [Parameter(Mandatory)]
        [string]$End,
        [Parameter(Mandatory)]
        [string]$Label
    )

    $startIndex = $SourceText.IndexOf($Start, [StringComparison]::Ordinal)
    if ($startIndex -lt 0) {
        throw "Required source range start is missing: $Label"
    }
    $endIndex = $SourceText.IndexOf(
        $End, $startIndex, [StringComparison]::Ordinal)
    if ($endIndex -le $startIndex) {
        throw "Required source range end is missing: $Label"
    }
    return $SourceText.Substring($startIndex, $endIndex - $startIndex)
}

$sourceRangeMissingStartRejected = $false
try {
    Get-RequiredSourceRange `
        -SourceText 'known-end' `
        -Start 'missing-start' `
        -End 'known-end' `
        -Label 'negative missing-start sample' | Out-Null
}
catch {
    if ($_.Exception.Message -ceq
        'Required source range start is missing: negative missing-start sample') {
        $sourceRangeMissingStartRejected = $true
    }
    else {
        throw
    }
}
if (-not $sourceRangeMissingStartRejected) {
    throw 'Required source-range helper accepted a missing start marker.'
}
$sourceRangeMissingEndRejected = $false
try {
    Get-RequiredSourceRange `
        -SourceText 'known-start' `
        -Start 'known-start' `
        -End 'missing-end' `
        -Label 'negative missing-end sample' | Out-Null
}
catch {
    if ($_.Exception.Message -ceq
        'Required source range end is missing: negative missing-end sample') {
        $sourceRangeMissingEndRejected = $true
    }
    else {
        throw
    }
}
if (-not $sourceRangeMissingEndRejected) {
    throw 'Required source-range helper accepted a missing end marker.'
}

foreach ($productionHost in $productionHostCallsites) {
    $callsiteText = Get-RequiredSourceRange `
        -SourceText $productionHost.Text `
        -Start $productionHost.Start `
        -End $productionHost.End `
        -Label "DSH production Host callsite $($productionHost.Name)"
    foreach ($required in $productionHost.Required) {
        if (-not $callsiteText.Contains(
                $required,
                [StringComparison]::Ordinal)) {
            throw "DSH production Host validator is missing from $($productionHost.Name): $required"
        }
    }
}
$personalHomeAdmissionStart = $personalLauncherAppText.IndexOf(
    'using var homeLease = new PersonalHarnessHomeCoordinator(layout.HarnessHome)',
    [StringComparison]::Ordinal)
$personalCandidateHostStart = $personalLauncherAppText.IndexOf(
    'await using var host = new DshHostService(',
    $personalHomeAdmissionStart,
    [StringComparison]::Ordinal)
if ($personalHomeAdmissionStart -lt 0 -or
    $personalCandidateHostStart -le $personalHomeAdmissionStart) {
    throw 'Personal candidate Runtime home-admission boundary is missing.'
}
$personalHomeAdmissionText = $personalLauncherAppText.Substring(
    $personalHomeAdmissionStart,
    $personalCandidateHostStart - $personalHomeAdmissionStart)
function Assert-PersonalOuterHomeAdmissionContract {
    param(
        [Parameter(Mandatory)]
        [string]$SourceText,
        [Parameter(Mandatory)]
        [string]$Label
    )

    foreach ($required in @(
        '.AcquireLease(() =>',
        'PersonalHarnessWriterGuard.RequireQuiescentLoopbackPort(healthPort)',
        'homeLease.RequireMutationAdmission(layout.HarnessHome);'
    )) {
        if (-not $SourceText.Contains(
                $required, [StringComparison]::Ordinal)) {
            throw "Personal outer home admission is missing ${required}: $Label"
        }
    }
}
Assert-PersonalOuterHomeAdmissionContract `
    -SourceText $personalHomeAdmissionText `
    -Label 'current Personal candidate runtime admission'
$personalHomeAdmissionMutation = $personalHomeAdmissionText.Replace(
    'homeLease.RequireMutationAdmission(layout.HarnessHome);',
    'homeLease.RequireAvailableLoopbackPort(healthPort);',
    [StringComparison]::Ordinal)
Assert-ExpectedContractFailure `
    -Action {
        Assert-PersonalOuterHomeAdmissionContract `
            -SourceText $personalHomeAdmissionMutation `
            -Label 'Personal candidate mutation-admission regression'
    } `
    -ExpectedMessage 'Personal outer home admission is missing homeLease.RequireMutationAdmission(layout.HarnessHome);: Personal candidate mutation-admission regression' `
    -Label 'Personal candidate mutation-admission regression'
$productionHostConstructorCount =
    [regex]::Matches(
        $personalLauncherAppText,
        [regex]::Escape('new DshHostService('),
        [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count +
    [regex]::Matches(
        $enterpriseLauncherAppText,
        [regex]::Escape('new DshHostService('),
        [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count +
    [regex]::Matches(
        $enterpriseHostAdapterText,
        [regex]::Escape('new DshHostService('),
        [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count +
    [regex]::Matches(
        $enterpriseCompatibilityProbeText,
        [regex]::Escape('new DshHostService('),
        [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
if ($productionHostConstructorCount -ne 5) {
    throw "Expected exactly five production DshHostService callsites; found $productionHostConstructorCount."
}
$allSourceHostConstructorCount = 0
foreach ($sourceFile in @(Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot 'src') `
        -Filter '*.cs' -File -Recurse | Where-Object {
            $_.FullName -notmatch '[\\](bin|obj)[\\]'
        })) {
    $sourceFileText = Get-Content -Raw -LiteralPath $sourceFile.FullName
    $allSourceHostConstructorCount += [regex]::Matches(
        $sourceFileText,
        [regex]::Escape('new DshHostService('),
        [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
}
if ($allSourceHostConstructorCount -ne 5) {
    throw "Every production DshHostService callsite under src must be reviewed; found $allSourceHostConstructorCount instead of five."
}
$enterpriseAdapterConstructorStart = $enterpriseHostAdapterText.IndexOf(
    '    public DshHostAdapter(',
    [StringComparison]::Ordinal)
$enterpriseAdapterConstructorEnd = $enterpriseHostAdapterText.IndexOf(
    '    public Uri WebUiUri',
    $enterpriseAdapterConstructorStart,
    [StringComparison]::Ordinal)
$enterpriseAdapterConstructorText = $enterpriseHostAdapterText.Substring(
    $enterpriseAdapterConstructorStart,
    $enterpriseAdapterConstructorEnd - $enterpriseAdapterConstructorStart)
foreach ($required in @(
    'Action validateRuntime',
    'throw new ArgumentNullException(nameof(validateRuntime))'
)) {
    if (-not $enterpriseAdapterConstructorText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Enterprise Host adapter constructor lost its mandatory runtime validator: $required"
    }
}
foreach ($forbidden in @(
    'Action? validateRuntime',
    'validateRuntime = null',
    'validateRuntime ?? (() => { })'
)) {
    if ($enterpriseAdapterConstructorText.Contains(
            $forbidden,
            [StringComparison]::Ordinal)) {
        throw "Enterprise Host adapter may not silently replace its runtime validator: $forbidden"
    }
}
$enterpriseAdapterCallStart = $enterpriseLauncherAppText.IndexOf(
    'var host = new DshHostAdapter(',
    [StringComparison]::Ordinal)
$enterpriseAdapterCallEnd = $enterpriseLauncherAppText.IndexOf(
    'var deviceKeyStore =',
    $enterpriseAdapterCallStart,
    [StringComparison]::Ordinal)
$enterpriseAdapterCallText = $enterpriseLauncherAppText.Substring(
    $enterpriseAdapterCallStart,
    $enterpriseAdapterCallEnd - $enterpriseAdapterCallStart)
foreach ($required in @(
    'runtimeOptions,',
    '() => ValidateActiveReleaseSet('
)) {
    if (-not $enterpriseAdapterCallText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Enterprise active Host adapter lost its captured release-set validator: $required"
    }
}
$allSourceAdapterConstructorCount = 0
foreach ($sourceFile in @(Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot 'src') `
        -Filter '*.cs' -File -Recurse | Where-Object {
            $_.FullName -notmatch '[\\](bin|obj)[\\]'
        })) {
    $sourceFileText = Get-Content -Raw -LiteralPath $sourceFile.FullName
    $allSourceAdapterConstructorCount += [regex]::Matches(
        $sourceFileText,
        [regex]::Escape('new DshHostAdapter('),
        [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
}
if ($allSourceAdapterConstructorCount -ne 1) {
    throw "Every production DshHostAdapter callsite under src must be reviewed; found $allSourceAdapterConstructorCount instead of one."
}

$hostEnsureStart = $dshHostServiceText.IndexOf(
    '    public async Task<DshLaunchResult> EnsureStartedAsync',
    [StringComparison]::Ordinal)
$hostEnsureEnd = $dshHostServiceText.IndexOf(
    '    public async Task<bool> IsHealthyAsync',
    $hostEnsureStart,
    [StringComparison]::Ordinal)
if ($hostEnsureStart -lt 0 -or $hostEnsureEnd -le $hostEnsureStart) {
    throw 'DSH Host exact launch method boundary is missing.'
}
$hostEnsureText = $dshHostServiceText.Substring(
    $hostEnsureStart,
    $hostEnsureEnd - $hostEnsureStart)
$hostEnsureRetry = $hostEnsureText.IndexOf(
    '_unassignedProcessContainment.RetryTerminationOrThrow();',
    [StringComparison]::Ordinal)
$hostEnsureExitedBranch = $hostEnsureText.IndexOf(
    'if (_ownedProcess is { HasExited: true } exitedProcess)',
    $hostEnsureRetry,
    [StringComparison]::Ordinal)
$hostEnsureHealthBranch = $hostEnsureText.IndexOf(
    'if (await IsHealthyAsync(cancellationToken).ConfigureAwait(false))',
    $hostEnsureExitedBranch,
    [StringComparison]::Ordinal)
$hostEnsureFirstReturn = $hostEnsureText.IndexOf(
    'return ',
    [StringComparison]::Ordinal)
$hostJobCreate = $hostEnsureText.IndexOf(
    'jobObject = WindowsJobObject.CreateKillOnClose(',
    [StringComparison]::Ordinal)
$hostRuntimeLease = $hostEnsureText.IndexOf(
    'runtimeLaunchLease = DshRuntimeLaunchLease.Acquire(',
    $hostJobCreate,
    [StringComparison]::Ordinal)
$hostFullBarrierBeforeStart = $hostEnsureText.IndexOf(
    'runtimeLaunchLease.RequireCompleteInventoryStillCurrent();',
    $hostJobCreate,
    [StringComparison]::Ordinal)
$hostTestBranch = $hostEnsureText.IndexOf(
    'if (_allowUnleasedRuntimeAdmissionForTests)',
    $hostFullBarrierBeforeStart,
    [StringComparison]::Ordinal)
$hostTestProcessStart = $hostEnsureText.IndexOf(
    'process = Process.Start(startInfo)',
    $hostTestBranch,
    [StringComparison]::Ordinal)
$hostTestJobAssign = $hostEnsureText.IndexOf(
    'jobObject.Assign(process);',
    $hostTestProcessStart,
    [StringComparison]::Ordinal)
$hostTestProcessImage = $hostEnsureText.IndexOf(
    'runtimeLaunchLease.RequireProcessImage(process);',
    $hostTestJobAssign,
    [StringComparison]::Ordinal)
$hostTestFullBarrier = $hostEnsureText.IndexOf(
    'runtimeLaunchLease.RequireCompleteInventoryStillCurrent();',
    $hostTestProcessImage,
    [StringComparison]::Ordinal)
$hostProductionElse = $hostEnsureText.IndexOf(
    '                else',
    $hostTestFullBarrier,
    [StringComparison]::Ordinal)
$hostSuspendedValidator = $hostEnsureText.IndexOf(
    'Action<Process> validateSuspendedProcess = suspendedProcess =>',
    $hostProductionElse,
    [StringComparison]::Ordinal)
$hostSuspendedImageBeforeGate = $hostEnsureText.IndexOf(
    'runtimeLaunchLease.RequireProcessImage(suspendedProcess);',
    $hostSuspendedValidator,
    [StringComparison]::Ordinal)
$hostSuspendedBarrierBeforeGate = $hostEnsureText.IndexOf(
    'runtimeLaunchLease.RequireCompleteInventoryStillCurrent();',
    $hostSuspendedImageBeforeGate,
    [StringComparison]::Ordinal)
$hostValidateBeforeResume = $hostEnsureText.IndexOf(
    '_validateBeforeResume(suspendedProcess);',
    $hostSuspendedBarrierBeforeGate,
    [StringComparison]::Ordinal)
$hostSuspendedImageAfterGate = $hostEnsureText.IndexOf(
    'runtimeLaunchLease.RequireProcessImage(suspendedProcess);',
    $hostValidateBeforeResume,
    [StringComparison]::Ordinal)
$hostSuspendedBarrierAfterGate = $hostEnsureText.IndexOf(
    'runtimeLaunchLease.RequireCompleteInventoryStillCurrent();',
    $hostSuspendedImageAfterGate,
    [StringComparison]::Ordinal)
$hostAtomicSuspendedStart = $hostEnsureText.IndexOf(
    'jobObject.StartAtomicSuspended(startInfo, validateSuspendedProcess)',
    $hostSuspendedBarrierAfterGate,
    [StringComparison]::Ordinal)
$hostTraditionalSuspendedStart = $hostEnsureText.IndexOf(
    'jobObject.StartSuspended(startInfo, validateSuspendedProcess)',
    $hostAtomicSuspendedStart,
    [StringComparison]::Ordinal)
$hostAtomicSelection = $hostEnsureText.IndexOf(
    'suspendedStart = homeWriterSession is IDshAtomicHomeWriterSession',
    $hostSuspendedBarrierAfterGate,
    [StringComparison]::Ordinal)
$hostSuspendedProcess = $hostEnsureText.IndexOf(
    'process = suspendedStart.Process;',
    $hostTraditionalSuspendedStart,
    [StringComparison]::Ordinal)
$hostPostSuspendedImage = $hostEnsureText.IndexOf(
    'runtimeLaunchLease.RequireProcessImage(process);',
    $hostSuspendedProcess,
    [StringComparison]::Ordinal)
$hostPostSuspendedBarrier = $hostEnsureText.IndexOf(
    'runtimeLaunchLease.RequireCompleteInventoryStillCurrent();',
    $hostPostSuspendedImage,
    [StringComparison]::Ordinal)
$hostLaunchCatch = $hostEnsureText.IndexOf(
    'catch (Exception launchFailure)',
    $hostPostSuspendedBarrier,
    [StringComparison]::Ordinal)
$hostSuspendedCleanup = $hostEnsureText.IndexOf(
    'suspendedStart?.Dispose();',
    $hostLaunchCatch,
    [StringComparison]::Ordinal)
$hostContainmentTransfer = $hostEnsureText.IndexOf(
    '_unassignedProcessContainment.ThrowAfterLaunchFailure(',
    $hostSuspendedCleanup,
    [StringComparison]::Ordinal)
$hostContainmentProcess = $hostEnsureText.IndexOf(
    'process,',
    $hostContainmentTransfer,
    [StringComparison]::Ordinal)
$hostContainmentFailure = $hostEnsureText.IndexOf(
    'effectiveLaunchFailure,',
    $hostContainmentProcess,
    [StringComparison]::Ordinal)
$hostContainmentJob = $hostEnsureText.IndexOf(
    'jobObject,',
    $hostContainmentFailure,
    [StringComparison]::Ordinal)
$hostContainmentLease = $hostEnsureText.IndexOf(
    'new HomeRuntimeAdmissionResources(runtimeLaunchLease, homeWriterSession));',
    $hostContainmentJob,
    [StringComparison]::Ordinal)
$hostDetachReaders = $hostEnsureText.IndexOf(
    'suspendedStart.DetachReaders();',
    $hostContainmentLease,
    [StringComparison]::Ordinal)
$hostPublishJob = $hostEnsureText.IndexOf(
    '_jobObject = jobObject;',
    $hostDetachReaders,
    [StringComparison]::Ordinal)
$hostPublishLease = $hostEnsureText.IndexOf(
    '_runtimeLaunchLease = runtimeLaunchLease;',
    $hostPublishJob,
    [StringComparison]::Ordinal)
$hostPublishProcess = $hostEnsureText.IndexOf(
    'Volatile.Write(ref _ownedProcess, process);',
    $hostPublishLease,
    [StringComparison]::Ordinal)
$hostEnsureFullBarrierCount = [regex]::Matches(
    $hostEnsureText,
    [regex]::Escape('runtimeLaunchLease.RequireCompleteInventoryStillCurrent();'),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$hostEnsureJobAssignCount = [regex]::Matches(
    $hostEnsureText,
    [regex]::Escape('jobObject.Assign(process);'),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$hostEnsureProcessStartCount = [regex]::Matches(
    $hostEnsureText,
    [regex]::Escape('Process.Start('),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$hostEnsureSuspendedStartCount = [regex]::Matches(
    $hostEnsureText,
    [regex]::Escape('jobObject.StartSuspended('),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$hostEnsureAtomicSuspendedStartCount = [regex]::Matches(
    $hostEnsureText,
    [regex]::Escape('jobObject.StartAtomicSuspended('),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$hostEnsureProcessImageCount = [regex]::Matches(
    $hostEnsureText,
    [regex]::Escape('runtimeLaunchLease.RequireProcessImage('),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$hostEnsureResumeGateCount = [regex]::Matches(
    $hostEnsureText,
    [regex]::Escape('_validateBeforeResume(suspendedProcess);'),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$hostEnsureRuntimeLeaseCount = [regex]::Matches(
    $hostEnsureText,
    [regex]::Escape('DshRuntimeLaunchLease.Acquire('),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$hostEnsureJobCreateCount = [regex]::Matches(
    $hostEnsureText,
    [regex]::Escape('WindowsJobObject.CreateKillOnClose('),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
if ($hostEnsureRetry -lt 0 -or
    $hostEnsureFirstReturn -le $hostEnsureRetry -or
    $hostEnsureExitedBranch -le $hostEnsureRetry -or
    $hostEnsureHealthBranch -le $hostEnsureExitedBranch -or
    $hostJobCreate -le $hostEnsureHealthBranch -or
    $hostRuntimeLease -le $hostJobCreate -or
    $hostFullBarrierBeforeStart -le $hostRuntimeLease -or
    $hostTestBranch -le $hostFullBarrierBeforeStart -or
    $hostTestProcessStart -le $hostTestBranch -or
    $hostTestJobAssign -le $hostTestProcessStart -or
    $hostTestProcessImage -le $hostTestJobAssign -or
    $hostTestFullBarrier -le $hostTestProcessImage -or
    $hostProductionElse -le $hostTestFullBarrier -or
    $hostSuspendedValidator -le $hostProductionElse -or
    $hostSuspendedImageBeforeGate -le $hostSuspendedValidator -or
    $hostSuspendedBarrierBeforeGate -le $hostSuspendedImageBeforeGate -or
    $hostValidateBeforeResume -le $hostSuspendedBarrierBeforeGate -or
    $hostSuspendedImageAfterGate -le $hostValidateBeforeResume -or
    $hostSuspendedBarrierAfterGate -le $hostSuspendedImageAfterGate -or
    $hostAtomicSuspendedStart -le $hostSuspendedBarrierAfterGate -or
    $hostAtomicSelection -le $hostSuspendedBarrierAfterGate -or
    $hostAtomicSelection -ge $hostAtomicSuspendedStart -or
    $hostTraditionalSuspendedStart -le $hostAtomicSuspendedStart -or
    $hostSuspendedProcess -le $hostTraditionalSuspendedStart -or
    $hostPostSuspendedImage -le $hostSuspendedProcess -or
    $hostPostSuspendedBarrier -le $hostPostSuspendedImage -or
    $hostLaunchCatch -le $hostPostSuspendedBarrier -or
    $hostSuspendedCleanup -le $hostLaunchCatch -or
    $hostContainmentTransfer -le $hostLaunchCatch -or
    $hostContainmentProcess -le $hostContainmentTransfer -or
    $hostContainmentFailure -le $hostContainmentProcess -or
    $hostContainmentJob -le $hostContainmentFailure -or
    $hostContainmentLease -le $hostContainmentJob -or
    $hostDetachReaders -le $hostContainmentLease -or
    $hostPublishJob -le $hostDetachReaders -or
    $hostPublishLease -le $hostPublishJob -or
    $hostPublishProcess -le $hostPublishLease -or
    $hostEnsureFullBarrierCount -ne 5 -or
    $hostEnsureJobAssignCount -ne 1 -or
    $hostEnsureProcessStartCount -ne 1 -or
    $hostEnsureSuspendedStartCount -ne 1 -or
    $hostEnsureAtomicSuspendedStartCount -ne 1 -or
    $hostEnsureProcessImageCount -ne 4 -or
    $hostEnsureResumeGateCount -ne 1 -or
    $hostEnsureRuntimeLeaseCount -ne 1 -or
    $hostEnsureJobCreateCount -ne 1 -or
    $hostEnsureText.Contains(
        'using var runtimeLaunchLease',
        [StringComparison]::Ordinal)) {
    throw 'DSH Host production launch must validate a Job-contained suspended process before resume, retain the exact full-tree lease through publication, and transfer every failed launch resource.'
}
$hostTestBranchText = $hostEnsureText.Substring(
    $hostTestBranch,
    $hostProductionElse - $hostTestBranch)
$hostProductionBranchText = $hostEnsureText.Substring(
    $hostProductionElse,
    $hostLaunchCatch - $hostProductionElse)
foreach ($branchContract in @(
        [pscustomobject]@{
            Label = 'test-only'
            Text = $hostTestBranchText
            FullBarriers = 1
            ProcessImages = 1
            RawStarts = 1
            RawAssigns = 1
            SuspendedStarts = 0
            ResumeGates = 0
        },
        [pscustomobject]@{
            Label = 'production'
            Text = $hostProductionBranchText
            FullBarriers = 3
            ProcessImages = 3
            RawStarts = 0
            RawAssigns = 0
            SuspendedStarts = 1
            ResumeGates = 1
        })) {
    $branchFullBarriers = [regex]::Matches(
        $branchContract.Text,
        [regex]::Escape('runtimeLaunchLease.RequireCompleteInventoryStillCurrent();'),
        [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
    $branchProcessImages = [regex]::Matches(
        $branchContract.Text,
        [regex]::Escape('runtimeLaunchLease.RequireProcessImage('),
        [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
    $branchRawStarts = [regex]::Matches(
        $branchContract.Text,
        [regex]::Escape('Process.Start('),
        [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
    $branchRawAssigns = [regex]::Matches(
        $branchContract.Text,
        [regex]::Escape('jobObject.Assign(process);'),
        [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
    $branchSuspendedStarts = [regex]::Matches(
        $branchContract.Text,
        [regex]::Escape('jobObject.StartSuspended('),
        [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
    $branchResumeGates = [regex]::Matches(
        $branchContract.Text,
        [regex]::Escape('_validateBeforeResume(suspendedProcess);'),
        [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
    if ($branchFullBarriers -ne $branchContract.FullBarriers -or
        $branchProcessImages -ne $branchContract.ProcessImages -or
        $branchRawStarts -ne $branchContract.RawStarts -or
        $branchRawAssigns -ne $branchContract.RawAssigns -or
        $branchSuspendedStarts -ne $branchContract.SuspendedStarts -or
        $branchResumeGates -ne $branchContract.ResumeGates) {
        throw "DSH Host $($branchContract.Label) launch branch does not match its exact reviewed admission shape."
    }
}

$windowsJobSuspendedStart = $dshWindowsJobObjectText.IndexOf(
    '    public WindowsJobStartedProcess StartSuspended(',
    [StringComparison]::Ordinal)
$windowsJobSuspendedEnd = $dshWindowsJobObjectText.IndexOf(
    '    public void Dispose()',
    $windowsJobSuspendedStart,
    [StringComparison]::Ordinal)
if ($windowsJobSuspendedStart -lt 0 -or
    $windowsJobSuspendedEnd -le $windowsJobSuspendedStart) {
    throw 'Windows Job suspended-start method boundary is missing.'
}
$windowsJobSuspendedText = $dshWindowsJobObjectText.Substring(
    $windowsJobSuspendedStart,
    $windowsJobSuspendedEnd - $windowsJobSuspendedStart)
$windowsJobCreate = $windowsJobSuspendedText.IndexOf(
    'if (!CreateProcess(',
    [StringComparison]::Ordinal)
$windowsJobProcessLookup = $windowsJobSuspendedText.IndexOf(
    'process = Process.GetProcessById(',
    $windowsJobCreate,
    [StringComparison]::Ordinal)
$windowsJobProcessPin = $windowsJobSuspendedText.IndexOf(
    '_ = process.Handle;',
    $windowsJobProcessLookup,
    [StringComparison]::Ordinal)
$windowsJobAtomicAssigned = $windowsJobSuspendedText.IndexOf(
    'assigned = atomicJob;',
    $windowsJobCreate,
    [StringComparison]::Ordinal)
$windowsJobAtomicCreateCallback = $windowsJobSuspendedText.IndexOf(
    'afterNativeCreate?.Invoke(',
    $windowsJobAtomicAssigned,
    [StringComparison]::Ordinal)
$windowsJobAssign = $windowsJobSuspendedText.IndexOf(
    'if (!atomicJob && !AssignProcessToJobObject(_handle, processInformation.ProcessHandle))',
    $windowsJobProcessPin,
    [StringComparison]::Ordinal)
$windowsJobAssigned = $windowsJobSuspendedText.IndexOf(
    'assigned = true;',
    $windowsJobAssign,
    [StringComparison]::Ordinal)
$windowsJobAtomicExact = $windowsJobSuspendedText.IndexOf(
    'if (atomicJob',
    $windowsJobAssigned,
    [StringComparison]::Ordinal)
$windowsJobActiveOne = $windowsJobSuspendedText.IndexOf(
    'if (ReadActiveProcessCount() != 1)',
    $windowsJobAtomicExact,
    [StringComparison]::Ordinal)
$windowsJobValidate = $windowsJobSuspendedText.IndexOf(
    'validateBeforeResume(process);',
    $windowsJobActiveOne,
    [StringComparison]::Ordinal)
$windowsJobResume = $windowsJobSuspendedText.IndexOf(
    'ResumeThread(processInformation.ThreadHandle)',
    $windowsJobValidate,
    [StringComparison]::Ordinal)
$windowsJobResumeOnce = $windowsJobSuspendedText.IndexOf(
    'previousSuspendCount != 1',
    $windowsJobResume,
    [StringComparison]::Ordinal)
$windowsJobFailureCatch = $windowsJobSuspendedText.IndexOf(
    'catch (Exception launchFailure)',
    $windowsJobResumeOnce,
    [StringComparison]::Ordinal)
$windowsJobAssignedFailure = $windowsJobSuspendedText.IndexOf(
    'if (assigned)',
    $windowsJobFailureCatch,
    [StringComparison]::Ordinal)
$windowsJobTerminate = $windowsJobSuspendedText.IndexOf(
    'TerminateJobObject(_handle, ContainmentExitCode)',
    $windowsJobAssignedFailure,
    [StringComparison]::Ordinal)
$windowsJobWaitRoot = $windowsJobSuspendedText.IndexOf(
    'if (WaitForSingleObject(',
    $windowsJobTerminate,
    [StringComparison]::Ordinal)
$windowsJobWaitEmpty = $windowsJobSuspendedText.IndexOf(
    'WaitForJobEmpty();',
    $windowsJobWaitRoot,
    [StringComparison]::Ordinal)
if ($windowsJobCreate -lt 0 -or
    $windowsJobProcessLookup -le $windowsJobCreate -or
    $windowsJobProcessPin -le $windowsJobProcessLookup -or
    $windowsJobAtomicAssigned -le $windowsJobCreate -or
    $windowsJobAtomicCreateCallback -le $windowsJobAtomicAssigned -or
    $windowsJobProcessLookup -le $windowsJobAtomicCreateCallback -or
    $windowsJobAssign -le $windowsJobProcessPin -or
    $windowsJobAssigned -le $windowsJobAssign -or
    $windowsJobAtomicExact -le $windowsJobAssigned -or
    $windowsJobActiveOne -le $windowsJobAtomicExact -or
    $windowsJobValidate -le $windowsJobActiveOne -or
    $windowsJobResume -le $windowsJobValidate -or
    $windowsJobResumeOnce -le $windowsJobResume -or
    $windowsJobFailureCatch -le $windowsJobResumeOnce -or
    $windowsJobAssignedFailure -le $windowsJobFailureCatch -or
    $windowsJobTerminate -le $windowsJobAssignedFailure -or
    $windowsJobWaitRoot -le $windowsJobTerminate -or
    $windowsJobWaitEmpty -le $windowsJobWaitRoot -or
    $windowsJobSuspendedText.Contains(
        'Process.Start(',
        [StringComparison]::Ordinal) -or
    $windowsJobSuspendedText.Contains(
        'CreateBreakawayFromJob',
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Windows Job native start must contain one exact suspended root, validate it while Job-contained, resume exactly once, and synchronously empty the assigned Job on rejection.'
}
foreach ($exactNativeMarker in @(
        'CreateSuspended',
        'AssignProcessToJobObject(_handle, processInformation.ProcessHandle)',
        'ReadActiveProcessCount() != 1',
        'validateBeforeResume(process);',
        'ResumeThread(processInformation.ThreadHandle)',
        'previousSuspendCount != 1',
        'TerminateJobObject(_handle, ContainmentExitCode)',
        'WaitForJobEmpty();')) {
    $nativeMarkerCount = [regex]::Matches(
        $windowsJobSuspendedText,
        [regex]::Escape($exactNativeMarker),
        [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
    if ($nativeMarkerCount -ne 1) {
        throw "Windows Job suspended-start marker must occur exactly once: $exactNativeMarker; found $nativeMarkerCount."
    }
}
$hostDirectFullBarrierCount = [regex]::Matches(
    $dshHostServiceText,
    [regex]::Escape('runtimeLaunchLease.RequireCompleteInventoryStillCurrent();'),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$hostDirectFastBarrierCount = [regex]::Matches(
    $dshHostServiceText,
    [regex]::Escape('runtimeLaunchLease.RequireFilesStillCurrent();'),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
if ($hostDirectFullBarrierCount -ne 6 -or
    $hostDirectFastBarrierCount -ne 1) {
    throw "DSH Host must contain exactly six direct full barriers and one direct fast barrier; found full=$hostDirectFullBarrierCount fast=$hostDirectFastBarrierCount."
}

$hostHealthStart = $hostEnsureEnd
$hostHealthEnd = $dshHostServiceText.IndexOf(
    '    private Process? TryGetOwnedProcessForHealth()',
    $hostHealthStart,
    [StringComparison]::Ordinal)
$hostHealthText = $dshHostServiceText.Substring(
    $hostHealthStart,
    $hostHealthEnd - $hostHealthStart)
$hostHealthFastCount = [regex]::Matches(
    $hostHealthText,
    [regex]::Escape('RequireRuntimeLaunchLeaseForHealth(expectedRuntimeLaunchLease);'),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$hostHealthListenerCount = [regex]::Matches(
    $hostHealthText,
    [regex]::Escape('_ownsLoopbackListener(expectedProcess, _options.Port)'),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$hostHealthFast1 = $hostHealthText.IndexOf(
    'RequireRuntimeLaunchLeaseForHealth(expectedRuntimeLaunchLease);',
    [StringComparison]::Ordinal)
$hostHealthListener1 = $hostHealthText.IndexOf(
    '_ownsLoopbackListener(expectedProcess, _options.Port)',
    $hostHealthFast1,
    [StringComparison]::Ordinal)
$hostHealthRequest = $hostHealthText.IndexOf(
    '_httpClient.SendAsync(',
    $hostHealthListener1,
    [StringComparison]::Ordinal)
$hostHealthResponseRead = $hostHealthText.IndexOf(
    'var html = await ReadHealthPageAsync(',
    $hostHealthRequest,
    [StringComparison]::Ordinal)
$hostHealthFast2 = $hostHealthText.IndexOf(
    'RequireRuntimeLaunchLeaseForHealth(expectedRuntimeLaunchLease);',
    $hostHealthResponseRead,
    [StringComparison]::Ordinal)
$hostHealthListener2 = $hostHealthText.IndexOf(
    '_ownsLoopbackListener(expectedProcess, _options.Port)',
    $hostHealthFast2,
    [StringComparison]::Ordinal)
if ($hostHealthStart -lt 0 -or
    $hostHealthEnd -le $hostHealthStart -or
    $hostHealthFastCount -ne 2 -or
    $hostHealthListenerCount -ne 2 -or
    $hostHealthFast1 -lt 0 -or
    $hostHealthListener1 -le $hostHealthFast1 -or
    $hostHealthRequest -le $hostHealthListener1 -or
    $hostHealthResponseRead -le $hostHealthRequest -or
    $hostHealthFast2 -le $hostHealthResponseRead -or
    $hostHealthListener2 -le $hostHealthFast2) {
    throw 'DSH ordinary health must bind the same process, runtime lease, and exact listener before and after its request.'
}

$hostEndpointStart = $dshHostServiceText.IndexOf(
    '    private bool IsSameOwnedRuntimeEndpoint(',
    [StringComparison]::Ordinal)
$hostEndpointEnd = $dshHostServiceText.IndexOf(
    '    public async Task OpenWebUiAsync(',
    $hostEndpointStart,
    [StringComparison]::Ordinal)
$hostEndpointText = $dshHostServiceText.Substring(
    $hostEndpointStart,
    $hostEndpointEnd - $hostEndpointStart)
foreach ($required in @(
    'IsSameOwnedProcessHealthy(expectedProcess)',
    'ReferenceEquals(',
    'Volatile.Read(ref _runtimeLaunchLease)',
    'RequireRuntimeLaunchLeaseForHealth(expectedRuntimeLaunchLease);',
    '_ownsLoopbackListener(expectedProcess, _options.Port)'
)) {
    if (-not $hostEndpointText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "DSH exact runtime endpoint helper lost a process, lease, or listener check: $required"
    }
}

$hostBrowserAuthStart = $dshHostServiceText.IndexOf(
    '    private async Task EstablishBrowserSessionAsync(',
    [StringComparison]::Ordinal)
$hostBrowserAuthEnd = $dshHostServiceText.IndexOf(
    '    private void InitializeBrowserAuthState(',
    $hostBrowserAuthStart,
    [StringComparison]::Ordinal)
$hostBrowserAuthText = $dshHostServiceText.Substring(
    $hostBrowserAuthStart,
    $hostBrowserAuthEnd - $hostBrowserAuthStart)
$browserAuthCapturedLease = $hostBrowserAuthText.IndexOf(
    'var expectedRuntimeLaunchLease = Volatile.Read(',
    [StringComparison]::Ordinal)
$browserAuthEndpointPre = $hostBrowserAuthText.IndexOf(
    'IsSameOwnedRuntimeEndpoint(',
    $browserAuthCapturedLease,
    [StringComparison]::Ordinal)
$browserAuthExchange = $hostBrowserAuthText.IndexOf(
    'DshBrowserAuthentication.ExchangeAsync(',
    $browserAuthEndpointPre,
    [StringComparison]::Ordinal)
$browserAuthEndpointPost = $hostBrowserAuthText.IndexOf(
    'IsSameOwnedRuntimeEndpoint(',
    $browserAuthExchange,
    [StringComparison]::Ordinal)
$browserAuthCommitLock = $hostBrowserAuthText.IndexOf(
    'lock (_browserAuthGate)',
    $browserAuthEndpointPost,
    [StringComparison]::Ordinal)
$browserAuthCommitIdentity = $hostBrowserAuthText.IndexOf(
    'ReferenceEquals(_browserAuthProcess, process)',
    $browserAuthCommitLock,
    [StringComparison]::Ordinal)
$browserAuthCommitSession = $hostBrowserAuthText.IndexOf(
    '_browserSession = session;',
    $browserAuthCommitIdentity,
    [StringComparison]::Ordinal)
$browserAuthEndpointCount = [regex]::Matches(
    $hostBrowserAuthText,
    [regex]::Escape('IsSameOwnedRuntimeEndpoint('),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$browserAuthFailClosedCount = [regex]::Matches(
    $hostBrowserAuthText,
    [regex]::Escape('if (!IsSameOwnedRuntimeEndpoint('),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$browserAuthCommitOpenBrace = $hostBrowserAuthText.IndexOf(
    '{',
    $browserAuthCommitLock)
$browserAuthCommitCloseBrace = -1
$browserAuthCommitBraceDepth = 0
for ($index = $browserAuthCommitOpenBrace;
    $index -ge 0 -and $index -lt $hostBrowserAuthText.Length;
    $index++) {
    if ($hostBrowserAuthText[$index] -eq '{') {
        $browserAuthCommitBraceDepth++
    }
    elseif ($hostBrowserAuthText[$index] -eq '}') {
        $browserAuthCommitBraceDepth--
        if ($browserAuthCommitBraceDepth -eq 0) {
            $browserAuthCommitCloseBrace = $index
            break
        }
    }
}
if ($hostBrowserAuthStart -lt 0 -or
    $hostBrowserAuthEnd -le $hostBrowserAuthStart -or
    $browserAuthCapturedLease -lt 0 -or
    $browserAuthEndpointPre -le $browserAuthCapturedLease -or
    $browserAuthExchange -le $browserAuthEndpointPre -or
    $browserAuthEndpointPost -le $browserAuthExchange -or
    $browserAuthCommitLock -le $browserAuthEndpointPost -or
    $browserAuthCommitIdentity -le $browserAuthCommitLock -or
    $browserAuthCommitSession -le $browserAuthCommitIdentity -or
    $browserAuthCommitOpenBrace -le $browserAuthCommitLock -or
    $browserAuthCommitCloseBrace -le $browserAuthCommitSession -or
    $browserAuthEndpointCount -ne 2 -or
    $browserAuthFailClosedCount -ne 2) {
    throw 'DSH browser authentication must bind the captured process, lease, and listener before and after token exchange and before session commit.'
}

$hostCandidateProbeStart = $dshHostServiceText.IndexOf(
    '    private async Task<bool> ProbeCandidateInstallHealthOnceAsync(',
    [StringComparison]::Ordinal)
$hostCandidateProbeEnd = $dshHostServiceText.IndexOf(
    '    public async Task<bool> CompleteCandidateInstallHealthAsync(',
    $hostCandidateProbeStart,
    [StringComparison]::Ordinal)
$hostCandidateProbeText = $dshHostServiceText.Substring(
    $hostCandidateProbeStart,
    $hostCandidateProbeEnd - $hostCandidateProbeStart)
$candidateEndpoint1 = $hostCandidateProbeText.IndexOf(
    'IsSameOwnedRuntimeEndpoint(',
    [StringComparison]::Ordinal)
$candidateRequest = $hostCandidateProbeText.IndexOf(
    '_httpClient.SendAsync(',
    $candidateEndpoint1,
    [StringComparison]::Ordinal)
$candidateResponseRead = $hostCandidateProbeText.IndexOf(
    'ReadBoundedHealthResponseAsync(',
    $candidateRequest,
    [StringComparison]::Ordinal)
$candidateParse = $hostCandidateProbeText.IndexOf(
    'JsonDocument.Parse(',
    $candidateResponseRead,
    [StringComparison]::Ordinal)
$candidateValidation = $hostCandidateProbeText.IndexOf(
    'IsValidCandidateSessionListResponse(',
    $candidateParse,
    [StringComparison]::Ordinal)
$candidateEndpoint2 = $hostCandidateProbeText.IndexOf(
    'IsSameOwnedRuntimeEndpoint(',
    $candidateValidation,
    [StringComparison]::Ordinal)
$candidateFullBarrier = $hostCandidateProbeText.IndexOf(
    'RequireCompleteRuntimeInventoryForCandidate(',
    $candidateEndpoint2,
    [StringComparison]::Ordinal)
$candidateEndpoint3 = $hostCandidateProbeText.IndexOf(
    'return IsSameOwnedRuntimeEndpoint(',
    $candidateFullBarrier,
    [StringComparison]::Ordinal)
$candidateEndpointCount = [regex]::Matches(
    $hostCandidateProbeText,
    [regex]::Escape('IsSameOwnedRuntimeEndpoint('),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$candidateFullBarrierCount = [regex]::Matches(
    $hostCandidateProbeText,
    [regex]::Escape('RequireCompleteRuntimeInventoryForCandidate('),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
if ($hostCandidateProbeStart -lt 0 -or
    $hostCandidateProbeEnd -le $hostCandidateProbeStart -or
    $candidateEndpoint1 -lt 0 -or
    $candidateRequest -le $candidateEndpoint1 -or
    $candidateResponseRead -le $candidateRequest -or
    $candidateParse -le $candidateResponseRead -or
    $candidateValidation -le $candidateParse -or
    $candidateEndpoint2 -le $candidateValidation -or
    $candidateFullBarrier -le $candidateEndpoint2 -or
    $candidateEndpoint3 -le $candidateFullBarrier -or
    $candidateEndpointCount -ne 3 -or
    $candidateFullBarrierCount -ne 1) {
    throw 'DSH candidate probe must bind endpoint before the request and perform endpoint-full-endpoint checks after the response.'
}

$hostCandidateCompleteStart = $hostCandidateProbeEnd
$hostCandidateCompleteEnd = $dshHostServiceText.IndexOf(
    '    public async Task StopOwnedProcessAsync(',
    $hostCandidateCompleteStart,
    [StringComparison]::Ordinal)
$hostCandidateCompleteText = $dshHostServiceText.Substring(
    $hostCandidateCompleteStart,
    $hostCandidateCompleteEnd - $hostCandidateCompleteStart)
$completeRetry = $hostCandidateCompleteText.IndexOf(
    '_unassignedProcessContainment.RetryTerminationOrThrow();',
    [StringComparison]::Ordinal)
$completeFirstReturn = $hostCandidateCompleteText.IndexOf(
    'return ',
    [StringComparison]::Ordinal)
$completeCapturedProcess = $hostCandidateCompleteText.IndexOf(
    'var process = _ownedProcess;',
    $completeRetry,
    [StringComparison]::Ordinal)
$completeCapturedLease = $hostCandidateCompleteText.IndexOf(
    'var expectedRuntimeLaunchLease = Volatile.Read(',
    $completeCapturedProcess,
    [StringComparison]::Ordinal)
$completeInitialProcessId = $hostCandidateCompleteText.IndexOf(
    'process.Id != expectedProcessId',
    $completeCapturedLease,
    [StringComparison]::Ordinal)
$completeInitialEndpoint = $hostCandidateCompleteText.IndexOf(
    'IsSameOwnedRuntimeEndpoint(',
    $completeInitialProcessId,
    [StringComparison]::Ordinal)
$completeProbe = $hostCandidateCompleteText.IndexOf(
    'IsCandidateInstallHealthyAsync(',
    $completeInitialEndpoint,
    [StringComparison]::Ordinal)
$completeReference = $hostCandidateCompleteText.IndexOf(
    'ReferenceEquals(_ownedProcess, process)',
    $completeProbe,
    [StringComparison]::Ordinal)
$completeFinalProcessId = $hostCandidateCompleteText.IndexOf(
    'process.Id != expectedProcessId',
    $completeReference,
    [StringComparison]::Ordinal)
$completeFinalEndpoint = $hostCandidateCompleteText.IndexOf(
    'IsSameOwnedRuntimeEndpoint(',
    $completeFinalProcessId,
    [StringComparison]::Ordinal)
$completeClear = $hostCandidateCompleteText.IndexOf(
    'ClearBrowserAuthState(process);',
    $completeFinalEndpoint,
    [StringComparison]::Ordinal)
$completeKill = $hostCandidateCompleteText.IndexOf(
    'process.Kill(entireProcessTree: true);',
    $completeClear,
    [StringComparison]::Ordinal)
$completeEndpointCount = [regex]::Matches(
    $hostCandidateCompleteText,
    [regex]::Escape('IsSameOwnedRuntimeEndpoint('),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$completeProcessIdCount = [regex]::Matches(
    $hostCandidateCompleteText,
    [regex]::Escape('process.Id != expectedProcessId'),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
if ($hostCandidateCompleteStart -lt 0 -or
    $hostCandidateCompleteEnd -le $hostCandidateCompleteStart -or
    $completeRetry -lt 0 -or
    $completeFirstReturn -le $completeRetry -or
    $completeCapturedProcess -le $completeRetry -or
    $completeCapturedLease -le $completeCapturedProcess -or
    $completeInitialProcessId -le $completeCapturedLease -or
    $completeInitialEndpoint -le $completeInitialProcessId -or
    $completeProbe -le $completeInitialEndpoint -or
    $completeReference -le $completeProbe -or
    $completeFinalProcessId -le $completeReference -or
    $completeFinalEndpoint -le $completeFinalProcessId -or
    $completeClear -le $completeFinalEndpoint -or
    $completeKill -le $completeClear -or
    $completeEndpointCount -ne 2 -or
    $completeProcessIdCount -ne 2) {
    throw 'DSH candidate commit must rebind the captured process, lease, and listener immediately before controlled stop.'
}
$hostStopStart = $dshHostServiceText.IndexOf(
    '    public async Task StopOwnedProcessAsync',
    [StringComparison]::Ordinal)
$hostDisposeStart = $dshHostServiceText.IndexOf(
    '    public async ValueTask DisposeAsync',
    $hostStopStart,
    [StringComparison]::Ordinal)
$hostStopText = $dshHostServiceText.Substring(
    $hostStopStart,
    $hostDisposeStart - $hostStopStart)
if (-not $hostStopText.Contains(
        '_unassignedProcessContainment.RetryTerminationOrThrow();',
        [StringComparison]::Ordinal)) {
    throw 'DSH Host stop must retry every process-wide unassigned launch bundle before returning.'
}
$hostStopRetry = $hostStopText.IndexOf(
    '_unassignedProcessContainment.RetryTerminationOrThrow();',
    [StringComparison]::Ordinal)
$hostStopFirstReturn = $hostStopText.IndexOf(
    'return;',
    [StringComparison]::Ordinal)
$hostStopOwnedProcess = $hostStopText.IndexOf(
    'var process = _ownedProcess;',
    $hostStopRetry,
    [StringComparison]::Ordinal)
if ($hostStopRetry -lt 0 -or
    $hostStopFirstReturn -le $hostStopRetry -or
    $hostStopOwnedProcess -le $hostStopRetry) {
    throw 'DSH Host stop must retry process-wide launch bundles before any null-owned-process early return.'
}
foreach ($forbidden in @(
    'TerminateUnassignedProcess(',
    'jobCleanupFailure',
    'using var runtimeLaunchLease'
)) {
    if ($dshHostServiceText.Contains(
            $forbidden,
            [StringComparison]::Ordinal)) {
        throw "DSH Host contains a legacy handle-losing launch path: $forbidden"
    }
}

foreach ($required in @(
    'internal sealed class DshRuntimeLaunchLease',
    'private const int MaximumParallelFileOpens = 16;',
    'private const uint GenericRead = 0x80000000;',
    'SafeFileHandle',
    'LockedRuntimeInventory',
    'Parallel.For(',
    'MaxDegreeOfParallelism = MaximumParallelFileOpens',
    'GenericRead,',
    '(uint)FileShare.Read,',
    'information.NumberOfLinks != 1',
    'internal void RequireProcessImage(Process process)',
    'QueryFullProcessImageName(',
    'Filter = "*"',
    'IncludeSubdirectories = true',
    'directories must also be ACL-isolated'
)) {
    if (-not $dshRuntimeLaunchLeaseText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "DSH runtime launch lease lost a complete-tree handle or supported-boundary requirement: $required"
    }
}
$runtimeFastStart = $dshRuntimeLaunchLeaseText.IndexOf(
    '    internal void RequireFilesStillCurrent()',
    [StringComparison]::Ordinal)
$runtimeFastEnd = $dshRuntimeLaunchLeaseText.IndexOf(
    '    internal void RequireCompleteInventoryStillCurrent()',
    $runtimeFastStart,
    [StringComparison]::Ordinal)
$runtimeFastText = $dshRuntimeLaunchLeaseText.Substring(
    $runtimeFastStart,
    $runtimeFastEnd - $runtimeFastStart)
foreach ($required in @(
    'runtimeTreeChangeMonitor.RequireUnchanged();',
    'GetFileIdentity(lockedNode.SafeFileHandle',
    'GetFileIdentity(',
    'lockedEntryPoint.SafeFileHandle',
    'RequirePathIdentity(NodePath',
    'RequireTrustMetadataStillCurrent(lockedTrustMetadata);'
)) {
    if (-not $runtimeFastText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "DSH runtime fast health lease lost a critical identity check: $required"
    }
}
foreach ($forbidden in @(
    'EnumerateRuntimeInventory(',
    'RequireRuntimeInventoryStillCurrent(',
    'FullInventoryScanCountForTests'
)) {
    if ($runtimeFastText.Contains(
            $forbidden,
            [StringComparison]::Ordinal)) {
        throw "DSH runtime fast health lease may not scan all runtime files: $forbidden"
    }
}
$runtimeFastWatcherCount = [regex]::Matches(
    $runtimeFastText,
    [regex]::Escape('runtimeTreeChangeMonitor.RequireUnchanged();'),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
if ($runtimeFastWatcherCount -ne 2) {
    throw "DSH runtime fast health lease must check its watcher twice; found $runtimeFastWatcherCount."
}
$runtimeFullStart = $runtimeFastEnd
$runtimeFullEnd = $dshRuntimeLaunchLeaseText.IndexOf(
    '    internal void RequireProcessImage(Process process)',
    $runtimeFullStart,
    [StringComparison]::Ordinal)
$runtimeFullText = $dshRuntimeLaunchLeaseText.Substring(
    $runtimeFullStart,
    $runtimeFullEnd - $runtimeFullStart)
$runtimeFullFastPre = $runtimeFullText.IndexOf(
    'RequireFilesStillCurrent();',
    [StringComparison]::Ordinal)
$runtimeFullDrain = $runtimeFullText.IndexOf(
    'Thread.Sleep(RuntimeWatcherEventDrain);',
    $runtimeFullFastPre,
    [StringComparison]::Ordinal)
$runtimeFullWatcherPre = $runtimeFullText.IndexOf(
    'runtimeTreeChangeMonitor.RequireUnchanged();',
    $runtimeFullDrain,
    [StringComparison]::Ordinal)
$runtimeFullHook = $runtimeFullText.IndexOf(
    'BeforeCompleteInventoryScanForTests?.Invoke();',
    $runtimeFullWatcherPre,
    [StringComparison]::Ordinal)
$runtimeFullScanCount = $runtimeFullText.IndexOf(
    'Interlocked.Increment(ref _fullInventoryScanCount);',
    $runtimeFullHook,
    [StringComparison]::Ordinal)
$runtimeFullNames = $runtimeFullText.IndexOf(
    'RequireRuntimeInventoryStillCurrent(',
    $runtimeFullScanCount,
    [StringComparison]::Ordinal)
$runtimeFullNamesOnly = $runtimeFullText.IndexOf(
    'requireLockedFileIdentities: false',
    $runtimeFullNames,
    [StringComparison]::Ordinal)
$runtimeFullWatcherPost = $runtimeFullText.IndexOf(
    'runtimeTreeChangeMonitor.RequireUnchanged();',
    $runtimeFullNamesOnly,
    [StringComparison]::Ordinal)
$runtimeFullFastPost = $runtimeFullText.IndexOf(
    'RequireFilesStillCurrent();',
    $runtimeFullWatcherPost,
    [StringComparison]::Ordinal)
$runtimeFullFastCount = [regex]::Matches(
    $runtimeFullText,
    [regex]::Escape('RequireFilesStillCurrent();'),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$runtimeFullInventoryCount = [regex]::Matches(
    $runtimeFullText,
    [regex]::Escape('RequireRuntimeInventoryStillCurrent('),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$runtimeFullCounterCount = [regex]::Matches(
    $runtimeFullText,
    [regex]::Escape('Interlocked.Increment(ref _fullInventoryScanCount);'),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
if ($runtimeFullFastPre -lt 0 -or
    $runtimeFullDrain -le $runtimeFullFastPre -or
    $runtimeFullWatcherPre -le $runtimeFullDrain -or
    $runtimeFullHook -le $runtimeFullWatcherPre -or
    $runtimeFullScanCount -le $runtimeFullHook -or
    $runtimeFullNames -le $runtimeFullScanCount -or
    $runtimeFullNamesOnly -le $runtimeFullNames -or
    $runtimeFullWatcherPost -le $runtimeFullNamesOnly -or
    $runtimeFullFastPost -le $runtimeFullWatcherPost -or
    $runtimeFullFastCount -ne 2 -or
    $runtimeFullInventoryCount -ne 1 -or
    $runtimeFullCounterCount -ne 1) {
    throw 'DSH complete inventory barrier must drain the watcher and compare exact names between fast checks.'
}
$runtimeAcquireStart = $dshRuntimeLaunchLeaseText.IndexOf(
    '    internal static DshRuntimeLaunchLease Acquire(',
    [StringComparison]::Ordinal)
$runtimeAcquireEnd = $runtimeFastStart
$runtimeAcquireText = $dshRuntimeLaunchLeaseText.Substring(
    $runtimeAcquireStart,
    $runtimeAcquireEnd - $runtimeAcquireStart)
$runtimeAcquireInventoryLock = $runtimeAcquireText.IndexOf(
    'lockedRuntimeInventory = LockRuntimeInventory(runtimeRoot);',
    [StringComparison]::Ordinal)
$runtimeAcquireValidator = $runtimeAcquireText.IndexOf(
    'validateBeforeProcessStart();',
    $runtimeAcquireInventoryLock,
    [StringComparison]::Ordinal)
$runtimeAcquireNames = $runtimeAcquireText.IndexOf(
    'RequireRuntimeInventoryStillCurrent(',
    $runtimeAcquireValidator,
    [StringComparison]::Ordinal)
$runtimeAcquireNamesOnly = $runtimeAcquireText.IndexOf(
    'requireLockedFileIdentities: false',
    $runtimeAcquireNames,
    [StringComparison]::Ordinal)
if ($runtimeAcquireInventoryLock -lt 0 -or
    $runtimeAcquireValidator -le $runtimeAcquireInventoryLock -or
    $runtimeAcquireNames -le $runtimeAcquireValidator -or
    $runtimeAcquireNamesOnly -le $runtimeAcquireNames) {
    throw 'DSH runtime acquisition must lock the full file inventory before the edition validator and then run a names-only full barrier.'
}

$runtimeInventoryLockStart = $dshRuntimeLaunchLeaseText.IndexOf(
    '    private static LockedRuntimeInventory LockRuntimeInventory(',
    [StringComparison]::Ordinal)
$runtimeInventoryLockEnd = $dshRuntimeLaunchLeaseText.IndexOf(
    '    private static void RequireRuntimeInventoryStillCurrent(',
    $runtimeInventoryLockStart,
    [StringComparison]::Ordinal)
$runtimeInventoryLockText = $dshRuntimeLaunchLeaseText.Substring(
    $runtimeInventoryLockStart,
    $runtimeInventoryLockEnd - $runtimeInventoryLockStart)
foreach ($required in @(
    'Parallel.For(',
    'MaxDegreeOfParallelism = MaximumParallelFileOpens',
    'SafeFileHandle? handle = OpenLockedRuntimeFileHandle(',
    'lockedFiles[index] = new LockedRuntimeFile(',
    'GetFileIdentity(',
    'TryDispose(lockedFiles[index]?.Handle, cleanupFailures);'
)) {
    if (-not $runtimeInventoryLockText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "DSH runtime inventory lock lost its bounded native-handle admission: $required"
    }
}
$runtimeInventoryRecordStart = $dshRuntimeLaunchLeaseText.IndexOf(
    '    private sealed record LockedRuntimeFile(',
    [StringComparison]::Ordinal)
$runtimeInventoryRecordEnd = $dshRuntimeLaunchLeaseText.IndexOf(
    '    private sealed record RuntimeFileCandidate(',
    $runtimeInventoryRecordStart,
    [StringComparison]::Ordinal)
$runtimeInventoryRecordText = $dshRuntimeLaunchLeaseText.Substring(
    $runtimeInventoryRecordStart,
    $runtimeInventoryRecordEnd - $runtimeInventoryRecordStart)
if (-not $runtimeInventoryRecordText.Contains(
        'SafeFileHandle Handle',
        [StringComparison]::Ordinal)) {
    throw 'DSH locked runtime inventory must retain the exact native file handle in every file record.'
}
$runtimeInventoryDisposeStart = $dshRuntimeLaunchLeaseText.IndexOf(
    '    private sealed class LockedRuntimeInventory(',
    [StringComparison]::Ordinal)
$runtimeInventoryDisposeEnd = $dshRuntimeLaunchLeaseText.IndexOf(
    '    private sealed record RuntimeInventoryPaths(',
    $runtimeInventoryDisposeStart,
    [StringComparison]::Ordinal)
$runtimeInventoryDisposeText = $dshRuntimeLaunchLeaseText.Substring(
    $runtimeInventoryDisposeStart,
    $runtimeInventoryDisposeEnd - $runtimeInventoryDisposeStart)
foreach ($required in @(
    'for (var index = lockedFiles.Count - 1; index >= 0; index--)',
    'TryDispose(lockedFiles[index].Handle, failures);'
)) {
    if (-not $runtimeInventoryDisposeText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "DSH runtime inventory disposal lost reverse exact-handle release: $required"
    }
}

foreach ($required in @(
    'private static readonly object RegistrySync = new();',
    'private static readonly List<RetainedLaunch> RetainedLaunches = [];',
    'lock (RegistrySync)',
    'RetainExactLaunch(retained);',
    'cleanupFailures = AdvanceCleanup(retained);',
    'if (retained.IsFullyReleased)',
    'RemoveExactLaunchAfterCleanup(retained);',
    'foreach (var retained in RetainedLaunches.ToArray())',
    'Process? process',
    'IDisposable? JobObject',
    'IDisposable? RuntimeLaunchLease',
    'Func<Process, TimeSpan, bool> TerminateAndConfirm',
    'Action<Process> DisposeProcess',
    'Func<Process, bool> ConfirmExited',
    'JobClosed',
    'ExitConfirmed',
    'RuntimeLeaseDisposed',
    'ProcessDisposed'
)) {
    if (-not $dshUnassignedContainmentText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "DSH process-wide launch containment lost an exact resource bundle boundary: $required"
    }
}
$containmentThrowStart = $dshUnassignedContainmentText.IndexOf(
    '    internal void ThrowAfterLaunchFailure(',
    [StringComparison]::Ordinal)
$containmentThrowEnd = $dshUnassignedContainmentText.IndexOf(
    '    internal void RetryTerminationOrThrow()',
    $containmentThrowStart,
    [StringComparison]::Ordinal)
$containmentThrowText = $dshUnassignedContainmentText.Substring(
    $containmentThrowStart,
    $containmentThrowEnd - $containmentThrowStart)
$containmentThrowLock = $containmentThrowText.IndexOf(
    'lock (RegistrySync)',
    [StringComparison]::Ordinal)
$containmentThrowRetain = $containmentThrowText.IndexOf(
    'RetainExactLaunch(retained);',
    $containmentThrowLock,
    [StringComparison]::Ordinal)
$containmentThrowAdvance = $containmentThrowText.IndexOf(
    'cleanupFailures = AdvanceCleanup(retained);',
    $containmentThrowRetain,
    [StringComparison]::Ordinal)
$containmentThrowReleased = $containmentThrowText.IndexOf(
    'if (retained.IsFullyReleased)',
    $containmentThrowAdvance,
    [StringComparison]::Ordinal)
$containmentThrowRemove = $containmentThrowText.IndexOf(
    'RemoveExactLaunchAfterCleanup(retained);',
    $containmentThrowReleased,
    [StringComparison]::Ordinal)
$containmentThrowLockCount = [regex]::Matches(
    $containmentThrowText,
    [regex]::Escape('lock (RegistrySync)'),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$containmentThrowOpenBrace = $containmentThrowText.IndexOf(
    '{',
    $containmentThrowLock)
$containmentThrowCloseBrace = -1
$containmentThrowBraceDepth = 0
for ($index = $containmentThrowOpenBrace;
    $index -ge 0 -and $index -lt $containmentThrowText.Length;
    $index++) {
    if ($containmentThrowText[$index] -eq '{') {
        $containmentThrowBraceDepth++
    }
    elseif ($containmentThrowText[$index] -eq '}') {
        $containmentThrowBraceDepth--
        if ($containmentThrowBraceDepth -eq 0) {
            $containmentThrowCloseBrace = $index
            break
        }
    }
}
if ($containmentThrowStart -lt 0 -or
    $containmentThrowEnd -le $containmentThrowStart -or
    $containmentThrowLock -lt 0 -or
    $containmentThrowRetain -le $containmentThrowLock -or
    $containmentThrowAdvance -le $containmentThrowRetain -or
    $containmentThrowReleased -le $containmentThrowAdvance -or
    $containmentThrowRemove -le $containmentThrowReleased -or
    $containmentThrowOpenBrace -le $containmentThrowLock -or
    $containmentThrowCloseBrace -le $containmentThrowRemove -or
    $containmentThrowLockCount -ne 1) {
    throw 'DSH failed-launch containment must retain, advance, and conditionally remove the exact bundle inside one registry lock.'
}
$containmentRetryStart = $containmentThrowEnd
$containmentRetryEnd = $dshUnassignedContainmentText.IndexOf(
    '    private static void RetainExactLaunch(',
    $containmentRetryStart,
    [StringComparison]::Ordinal)
$containmentRetryText = $dshUnassignedContainmentText.Substring(
    $containmentRetryStart,
    $containmentRetryEnd - $containmentRetryStart)
$containmentRetryLock = $containmentRetryText.IndexOf(
    'lock (RegistrySync)',
    [StringComparison]::Ordinal)
$containmentRetrySnapshot = $containmentRetryText.IndexOf(
    'foreach (var retained in RetainedLaunches.ToArray())',
    $containmentRetryLock,
    [StringComparison]::Ordinal)
$containmentRetryAdvance = $containmentRetryText.IndexOf(
    'failures.AddRange(AdvanceCleanup(retained));',
    $containmentRetrySnapshot,
    [StringComparison]::Ordinal)
$containmentRetryReleased = $containmentRetryText.IndexOf(
    'if (retained.IsFullyReleased)',
    $containmentRetryAdvance,
    [StringComparison]::Ordinal)
$containmentRetryRemove = $containmentRetryText.IndexOf(
    'RemoveExactLaunchAfterCleanup(retained);',
    $containmentRetryReleased,
    [StringComparison]::Ordinal)
$containmentRetryLockCount = [regex]::Matches(
    $containmentRetryText,
    [regex]::Escape('lock (RegistrySync)'),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$containmentRetryOpenBrace = $containmentRetryText.IndexOf(
    '{',
    $containmentRetryLock)
$containmentRetryCloseBrace = -1
$containmentRetryBraceDepth = 0
for ($index = $containmentRetryOpenBrace;
    $index -ge 0 -and $index -lt $containmentRetryText.Length;
    $index++) {
    if ($containmentRetryText[$index] -eq '{') {
        $containmentRetryBraceDepth++
    }
    elseif ($containmentRetryText[$index] -eq '}') {
        $containmentRetryBraceDepth--
        if ($containmentRetryBraceDepth -eq 0) {
            $containmentRetryCloseBrace = $index
            break
        }
    }
}
if ($containmentRetryStart -lt 0 -or
    $containmentRetryEnd -le $containmentRetryStart -or
    $containmentRetryLock -lt 0 -or
    $containmentRetrySnapshot -le $containmentRetryLock -or
    $containmentRetryAdvance -le $containmentRetrySnapshot -or
    $containmentRetryReleased -le $containmentRetryAdvance -or
    $containmentRetryRemove -le $containmentRetryReleased -or
    $containmentRetryOpenBrace -le $containmentRetryLock -or
    $containmentRetryCloseBrace -le $containmentRetryRemove -or
    $containmentRetryLockCount -ne 1) {
    throw 'DSH process-wide retry must snapshot, advance, and conditionally remove every retained bundle inside one registry lock.'
}
$containmentRetainedStart = $dshUnassignedContainmentText.IndexOf(
    '    private sealed class RetainedLaunch(',
    [StringComparison]::Ordinal)
$containmentRetainedText = $dshUnassignedContainmentText.Substring(
    $containmentRetainedStart)
foreach ($required in @(
    'internal Process? Process { get; } = process;',
    'internal IDisposable? JobObject { get; } = jobObject;',
    'internal IDisposable? RuntimeLaunchLease { get; } = runtimeLaunchLease;',
    'internal Func<Process, TimeSpan, bool> TerminateAndConfirm { get; }',
    'internal Action<Process> DisposeProcess { get; } = disposeProcess;',
    'internal Func<Process, bool> ConfirmExited { get; } = confirmExited;',
    'JobClosed',
    'ExitConfirmed',
    'RuntimeLeaseDisposed',
    'ProcessDisposed'
)) {
    if (-not $containmentRetainedText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "DSH retained launch record lost one exact resource or cleanup policy: $required"
    }
}
$containmentReleasedExpression = $containmentRetainedText.IndexOf(
    'internal bool IsFullyReleased =>',
    [StringComparison]::Ordinal)
$containmentReleasedJob = $containmentRetainedText.IndexOf(
    'JobClosed',
    $containmentReleasedExpression,
    [StringComparison]::Ordinal)
$containmentReleasedExit = $containmentRetainedText.IndexOf(
    'ExitConfirmed',
    $containmentReleasedJob,
    [StringComparison]::Ordinal)
$containmentReleasedLease = $containmentRetainedText.IndexOf(
    'RuntimeLeaseDisposed',
    $containmentReleasedExit,
    [StringComparison]::Ordinal)
$containmentReleasedProcess = $containmentRetainedText.IndexOf(
    'ProcessDisposed',
    $containmentReleasedLease,
    [StringComparison]::Ordinal)
if ($containmentReleasedExpression -lt 0 -or
    $containmentReleasedJob -le $containmentReleasedExpression -or
    $containmentReleasedExit -le $containmentReleasedJob -or
    $containmentReleasedLease -le $containmentReleasedExit -or
    $containmentReleasedProcess -le $containmentReleasedLease) {
    throw 'DSH retained launch may be removed only after job, exit, runtime lease, and Process wrapper release all complete.'
}
$containmentAdvanceStart = $dshUnassignedContainmentText.IndexOf(
    '    private static List<Exception> AdvanceCleanup(',
    [StringComparison]::Ordinal)
$containmentAdvanceEnd = $dshUnassignedContainmentText.IndexOf(
    '    private static bool TerminateAndConfirm(',
    $containmentAdvanceStart,
    [StringComparison]::Ordinal)
$containmentAdvanceText = $dshUnassignedContainmentText.Substring(
    $containmentAdvanceStart,
    $containmentAdvanceEnd - $containmentAdvanceStart)
$containmentJobDispose = $containmentAdvanceText.IndexOf(
    'retained.JobObject?.Dispose();',
    [StringComparison]::Ordinal)
$containmentJobFailure = $containmentAdvanceText.IndexOf(
    'failures.Add(exception);',
    $containmentJobDispose,
    [StringComparison]::Ordinal)
$containmentTerminate = $containmentAdvanceText.IndexOf(
    'retained.TerminateAndConfirm(',
    $containmentJobFailure,
    [StringComparison]::Ordinal)
$containmentConfirm = $containmentAdvanceText.IndexOf(
    'retained.ConfirmExited(process);',
    $containmentTerminate,
    [StringComparison]::Ordinal)
$containmentLeaseDispose = $containmentAdvanceText.IndexOf(
    'retained.RuntimeLaunchLease?.Dispose();',
    $containmentConfirm,
    [StringComparison]::Ordinal)
$containmentProcessDispose = $containmentAdvanceText.IndexOf(
    'retained.DisposeProcess(retained.Process);',
    $containmentLeaseDispose,
    [StringComparison]::Ordinal)
if ($containmentJobDispose -lt 0 -or
    $containmentJobFailure -le $containmentJobDispose -or
    $containmentTerminate -le $containmentJobFailure -or
    $containmentConfirm -le $containmentTerminate -or
    $containmentLeaseDispose -le $containmentConfirm -or
    $containmentProcessDispose -le $containmentLeaseDispose) {
    throw 'DSH failed launch cleanup must retain job ownership while continuing exact process termination before lease release.'
}

$hostDisposeText = $dshHostServiceText.Substring($hostDisposeStart)
$hostDisposeStop = $hostDisposeText.IndexOf(
    'await StopOwnedProcessAsync().ConfigureAwait(false);',
    [StringComparison]::Ordinal)
$hostDisposeFlag = $hostDisposeText.IndexOf(
    '_disposed = true;',
    $hostDisposeStop,
    [StringComparison]::Ordinal)
if ($hostDisposeStop -lt 0 -or $hostDisposeFlag -le $hostDisposeStop) {
    throw 'DSH Host may mark itself disposed only after exact owned and process-wide launch cleanup succeeds.'
}

foreach ($required in @(
    'GetExtendedTcpTable(',
    'TcpTableOwnerPidListener',
    'TcpStateListen',
    'Ipv4LoopbackMibValue = 0x0100007f',
    'NetworkToHostPort(localPort) == port',
    'owningProcessId == processId',
    'TryGetActiveProcessId(process, out var processId)',
    'TryGetActiveProcessId(process, out var confirmedProcessId)',
    'confirmedProcessId == processId',
    'process.HasExited',
    'MaximumTableBytes',
    'returnedBytes > tableBytes',
    'rowCount > maximumRows'
)) {
    if (-not $dshLoopbackListenerText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "DSH loopback health lost an exact listener-owner boundary: $required"
    }
}
foreach ($required in @(
    'ExactChildListenerOwnsItsLoopbackSocketAsync',
    'UnrelatedOwnedProcessCannotClaimListenerAsync',
    'WildcardListenerIsNotExactLoopbackAsync',
    'await WaitForOwnershipAsync(listener.Process, listener.Port)',
    'await listener.StopGracefullyAsync()',
    'new TcpClient(AddressFamily.InterNetwork)',
    'IPAddress.Loopback',
    'addressProperty is not ("Loopback" or "Any")',
    'unrelatedOwnedProcess',
    'IsExactProcessListeningOnIpv4Loopback('
)) {
    if (-not $dshLoopbackListenerTestsText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "DSH loopback listener ownership regression is missing: $required"
    }
}
foreach ($required in @(
    'HealthRejectsListenerLossDuringRequestAsync',
    'BrowserAuthenticationRejectsListenerLossAsync',
    'OrdinaryHealthUsesOnlyFastRuntimeChecksAsync',
    'CandidateFullBarrierRejectsProcessFlipAsync',
    'RunCompleteInventoryAdditionCase',
    'lease.DisableWatcherNotificationsForTests();',
    'AssertEqual(0, lease.FullInventoryScanCountForTests);',
    'AssertEqual(1, lease.FullInventoryScanCountForTests);',
    'lease.BeforeCompleteInventoryScanForTests = () =>',
    'AttachOwnedProcess(service, replacementProcess);',
    'AssertFalse(await InvokeCandidateHealthProbeOnceAsync(service));',
    'AssertFalse(originalObserver.HasExited);',
    'AssertFalse(replacementObserver.HasExited);',
    'AssertEqual(2, listenerChecks);'
)) {
    if (-not $dshRuntimeAdmissionTestsText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "DSH runtime split-barrier regression is missing: $required"
    }
}
$browserAuthRegressionStart = $dshRuntimeAdmissionTestsText.IndexOf(
    '    private static async Task BrowserAuthenticationRejectsListenerLossAsync()',
    [StringComparison]::Ordinal)
$browserAuthRegressionEnd = $dshRuntimeAdmissionTestsText.IndexOf(
    '    private static async Task OrdinaryHealthUsesOnlyFastRuntimeChecksAsync()',
    $browserAuthRegressionStart,
    [StringComparison]::Ordinal)
$browserAuthRegressionText = $dshRuntimeAdmissionTestsText.Substring(
    $browserAuthRegressionStart,
    $browserAuthRegressionEnd - $browserAuthRegressionStart)
foreach ($required in @(
    'DshRuntimeMetadata.FileName',
    'browser-launch-cookie-v1',
    'HttpStatusCode.SeeOther',
    '"Set-Cookie"',
    'ownsLoopbackListener: (_, _) =>',
    'Interlocked.Increment(ref listenerChecks) == 1',
    'InitializeBrowserAuthState(service, ownedProcess);',
    'AssertEqual(2, listenerChecks);',
    'AssertEqual(3, listenerChecks);',
    'AssertTrue(ReadBrowserSession(service) is null);',
    'AssertFalse(ownedProcess.HasExited);'
)) {
    if (-not $browserAuthRegressionText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "DSH browser-auth listener-loss regression is missing: $required"
    }
}
$browserAuthRegressionInvokeCount = [regex]::Matches(
    $browserAuthRegressionText,
    [regex]::Escape('InvokeEstablishBrowserSessionAsync('),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$browserAuthRegressionRequestCount = [regex]::Matches(
    $browserAuthRegressionText,
    [regex]::Escape('AssertEqual(1, requestCount);'),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$browserAuthRegressionNoSessionCount = [regex]::Matches(
    $browserAuthRegressionText,
    [regex]::Escape('AssertTrue(ReadBrowserSession(service) is null);'),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
$browserAuthRegressionAliveCount = [regex]::Matches(
    $browserAuthRegressionText,
    [regex]::Escape('AssertFalse(ownedProcess.HasExited);'),
    [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
if ($browserAuthRegressionStart -lt 0 -or
    $browserAuthRegressionEnd -le $browserAuthRegressionStart -or
    $browserAuthRegressionInvokeCount -ne 2 -or
    $browserAuthRegressionRequestCount -ne 2 -or
    $browserAuthRegressionNoSessionCount -ne 2 -or
    $browserAuthRegressionAliveCount -ne 2) {
    throw 'DSH browser-auth listener-loss regression must prove one post-exchange rejection, one pre-exchange rejection, no session publish, and a live exact process.'
}
foreach ($required in @(
    'RealRuntimeLeaseRemainsLockedUntilExitConfirmedAsync',
    'CleanupFailuresRetainExactBundleAsync',
    'ExitInspectionFailuresRemainRetainedAsync',
    'var independentContainment = new DshUnassignedProcessContainment(',
    'independentContainment.RetryTerminationOrThrow();',
    'AssertEqual(2, jobObject.DisposeAttempts);',
    'AssertEqual(2, runtimeLaunchLease.DisposeAttempts);',
    'AssertEqual(2, processDisposeAttempts);',
    'AssertEqual(2, confirmationAttempts);'
)) {
    if (-not $dshUnassignedContainmentTestsText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "DSH process-wide exact-bundle regression is missing: $required"
    }
}
$runtimeAdmissionRunStart = $dshRuntimeAdmissionTestsText.IndexOf(
    '    internal static async Task RunAsync()',
    [StringComparison]::Ordinal)
$runtimeAdmissionRunEnd = $dshRuntimeAdmissionTestsText.IndexOf(
    '    private static async Task RuntimeFilesRemainBoundThroughProcessAdmissionAsync()',
    $runtimeAdmissionRunStart,
    [StringComparison]::Ordinal)
$runtimeAdmissionRunText = $dshRuntimeAdmissionTestsText.Substring(
    $runtimeAdmissionRunStart,
    $runtimeAdmissionRunEnd - $runtimeAdmissionRunStart)
foreach ($required in @(
    'await RuntimeFilesRemainBoundThroughProcessAdmissionAsync();',
    'RuntimeWatcherRejectsNoncriticalTreeChanges();',
    'await HealthRequiresTheSameOwnedProcessAsync();',
    'await HealthRejectsListenerLossDuringRequestAsync();',
    'await BrowserAuthenticationRejectsListenerLossAsync();',
    'await OrdinaryHealthUsesOnlyFastRuntimeChecksAsync();',
    'await CandidateFullBarrierRejectsProcessFlipAsync();'
)) {
    if (-not $runtimeAdmissionRunText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "DSH runtime admission regression is defined but not executed by RunAsync: $required"
    }
}
$containmentRunStart = $dshUnassignedContainmentTestsText.IndexOf(
    '    internal static async Task RunAsync()',
    [StringComparison]::Ordinal)
$containmentRunEnd = $dshUnassignedContainmentTestsText.IndexOf(
    '    private static async Task RealRuntimeLeaseRemainsLockedUntilExitConfirmedAsync()',
    $containmentRunStart,
    [StringComparison]::Ordinal)
$containmentRunText = $dshUnassignedContainmentTestsText.Substring(
    $containmentRunStart,
    $containmentRunEnd - $containmentRunStart)
foreach ($required in @(
    'await RealRuntimeLeaseRemainsLockedUntilExitConfirmedAsync();',
    'await CleanupFailuresRetainExactBundleAsync();',
    'await ExitInspectionFailuresRemainRetainedAsync();'
)) {
    if (-not $containmentRunText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "DSH process-wide containment regression is defined but not executed by RunAsync: $required"
    }
}
$listenerRunStart = $dshLoopbackListenerTestsText.IndexOf(
    '    internal static async Task RunAsync()',
    [StringComparison]::Ordinal)
$listenerRunEnd = $dshLoopbackListenerTestsText.IndexOf(
    '    private static async Task ExactChildListenerOwnsItsLoopbackSocketAsync()',
    $listenerRunStart,
    [StringComparison]::Ordinal)
$listenerRunText = $dshLoopbackListenerTestsText.Substring(
    $listenerRunStart,
    $listenerRunEnd - $listenerRunStart)
foreach ($required in @(
    'await ExactChildListenerOwnsItsLoopbackSocketAsync();',
    'await UnrelatedOwnedProcessCannotClaimListenerAsync();',
    'await WildcardListenerIsNotExactLoopbackAsync();'
)) {
    if (-not $listenerRunText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "DSH loopback listener regression is defined but not executed by RunAsync: $required"
    }
}
foreach ($registration in @(
    '("DSH unassigned process containment retains exact handle until exit is confirmed", DshUnassignedProcessContainmentTests.RunAsync),',
    '("DSH runtime launch admission binds files process image and owned health", DshRuntimeAdmissionTests.RunAsync),',
    '("DSH health binds exact IPv4 loopback listener owner", DshLoopbackListenerOwnershipTests.RunAsync),'
)) {
    if (-not $coreTestsText.Contains(
            $registration,
            [StringComparison]::Ordinal)) {
        throw "DSH Host security regression is not registered in CoreTests: $registration"
    }
}
$resolveRuntimeStart = $personalLauncherSettingsText.IndexOf(
    '    public string ResolveRuntimeDirectory()',
    [StringComparison]::Ordinal)
$resolveRuntimeEnd = $personalLauncherSettingsText.IndexOf(
    '    public string GetRuntimeRootDirectory()',
    $resolveRuntimeStart,
    [StringComparison]::Ordinal)
if ($resolveRuntimeStart -lt 0 -or $resolveRuntimeEnd -le $resolveRuntimeStart) {
    throw 'Personal Launcher runtime resolver boundary is missing.'
}
$resolveRuntimeText = $personalLauncherSettingsText.Substring(
    $resolveRuntimeStart,
    $resolveRuntimeEnd - $resolveRuntimeStart)
$resolveV3Pointer = $resolveRuntimeText.IndexOf(
    'new PersonalReleaseSetPointerStore(personalLayout).TryRead()',
    [StringComparison]::Ordinal)
$resolveV3Branch = $resolveRuntimeText.IndexOf(
    'if (releaseSet is not null)',
    $resolveV3Pointer,
    [StringComparison]::Ordinal)
$resolveV3Health = $resolveRuntimeText.IndexOf(
    'releaseSet.Current.HealthState != PersonalReleaseHealthStates.Healthy',
    [StringComparison]::Ordinal)
$resolveV3Return = $resolveRuntimeText.IndexOf(
    'return releaseSet.Current.Runtime.Directory;',
    [StringComparison]::Ordinal)
$resolveDevelopmentFlag = $resolveRuntimeText.IndexOf(
    'Environment.GetEnvironmentVariable("ENSOU_DSH_ALLOW_DEVELOPMENT_RUNTIME")',
    [StringComparison]::Ordinal)
$resolveDevelopmentBranch = $resolveRuntimeText.LastIndexOf(
    'if (string.Equals(',
    $resolveDevelopmentFlag,
    [StringComparison]::Ordinal)
$resolveDevelopmentExactOne = $resolveRuntimeText.IndexOf(
    '"1",',
    $resolveDevelopmentFlag,
    [StringComparison]::Ordinal)
$resolveDevelopmentComparison = $resolveRuntimeText.IndexOf(
    'StringComparison.Ordinal',
    $resolveDevelopmentExactOne,
    [StringComparison]::Ordinal)
$resolveDevelopmentReturn = $resolveRuntimeText.IndexOf(
    'return Path.GetFullPath(RuntimeDirectory);',
    [StringComparison]::Ordinal)
$resolveLegacyPointer = $resolveRuntimeText.IndexOf(
    'RuntimePointer.TryRead(RuntimePointer.StatePath())',
    [StringComparison]::Ordinal)
$resolveUninstalled = $resolveRuntimeText.IndexOf(
    'return Path.Combine(GetRuntimeRootDirectory(), "uninstalled");',
    [StringComparison]::Ordinal)
if ($resolveV3Pointer -lt 0 -or
    $resolveV3Branch -le $resolveV3Pointer -or
    $resolveV3Health -le $resolveV3Branch -or
    $resolveV3Return -le $resolveV3Health -or
    $resolveDevelopmentBranch -le $resolveV3Return -or
    $resolveDevelopmentFlag -le $resolveDevelopmentBranch -or
    $resolveDevelopmentExactOne -le $resolveDevelopmentFlag -or
    $resolveDevelopmentComparison -le $resolveDevelopmentExactOne -or
    $resolveDevelopmentReturn -le $resolveDevelopmentComparison -or
    $resolveLegacyPointer -le $resolveDevelopmentReturn -or
    $resolveUninstalled -le $resolveLegacyPointer) {
    throw 'Personal Launcher runtime selection must remain production-v3, explicit development, legacy, then uninstalled.'
}

$personalRuntimeGuardStart = $personalLauncherAppText.IndexOf(
    '    private static bool RequireSamePersonalRuntimeForLaunch(',
    [StringComparison]::Ordinal)
$personalRuntimeGuardEnd = $personalLauncherAppText.IndexOf(
    '    protected override void OnExit',
    $personalRuntimeGuardStart,
    [StringComparison]::Ordinal)
if ($personalRuntimeGuardStart -lt 0 -or
    $personalRuntimeGuardEnd -le $personalRuntimeGuardStart) {
    throw 'Personal Launcher locked runtime guard boundary is missing.'
}
$personalRuntimeGuardText = $personalLauncherAppText.Substring(
    $personalRuntimeGuardStart,
    $personalRuntimeGuardEnd - $personalRuntimeGuardStart)
$guardDevelopmentFlag = $personalRuntimeGuardText.IndexOf(
    'ENSOU_DSH_ALLOW_DEVELOPMENT_RUNTIME',
    [StringComparison]::Ordinal)
$guardDevelopmentExactOne = $personalRuntimeGuardText.IndexOf(
    '"1",',
    $guardDevelopmentFlag,
    [StringComparison]::Ordinal)
$guardDevelopmentComparison = $personalRuntimeGuardText.IndexOf(
    'StringComparison.Ordinal',
    $guardDevelopmentExactOne,
    [StringComparison]::Ordinal)
$guardV3Pointer = $personalRuntimeGuardText.IndexOf(
    'new PersonalReleaseSetPointerStore(layout).TryRead()',
    [StringComparison]::Ordinal)
$guardDevelopmentBranch = $personalRuntimeGuardText.IndexOf(
    'if (unmanagedDevelopmentRuntime)',
    $guardV3Pointer,
    [StringComparison]::Ordinal)
$guardDevelopmentResolver = $personalRuntimeGuardText.IndexOf(
    'currentRuntimeDirectory = settings.ResolveRuntimeDirectory();',
    [StringComparison]::Ordinal)
$guardProductionElse = $personalRuntimeGuardText.IndexOf(
    'else',
    $guardDevelopmentResolver,
    [StringComparison]::Ordinal)
$guardV3Health = $personalRuntimeGuardText.IndexOf(
    'PersonalReleaseHealthStates.Healthy',
    $guardV3Pointer,
    [StringComparison]::Ordinal)
$guardV3Runtime = $personalRuntimeGuardText.IndexOf(
    'currentRuntimeDirectory = releaseSet.Current.Runtime.Directory;',
    [StringComparison]::Ordinal)
$guardPathComparison = $personalRuntimeGuardText.IndexOf(
    'Path.TrimEndingDirectorySeparator(',
    $guardV3Runtime,
    [StringComparison]::Ordinal)
if ($guardDevelopmentFlag -lt 0 -or
    $guardDevelopmentExactOne -le $guardDevelopmentFlag -or
    $guardDevelopmentComparison -le $guardDevelopmentExactOne -or
    $guardDevelopmentBranch -le $guardV3Pointer -or
    $guardDevelopmentResolver -le $guardDevelopmentBranch -or
    $guardProductionElse -le $guardDevelopmentResolver -or
    $guardV3Pointer -le $guardDevelopmentComparison -or
    $guardV3Health -le $guardV3Pointer -or
    $guardV3Runtime -le $guardV3Health -or
    $guardPathComparison -le $guardV3Runtime -or
    -not $personalRuntimeGuardText.Contains(
        '最新的已签名 Ensou DSH Personal Installer',
        [StringComparison]::Ordinal) -or
    -not $personalRuntimeGuardText.Contains(
        'var unmanagedDevelopmentRuntime = allowDevelopmentRuntime && releaseSet is null;',
        [StringComparison]::Ordinal) -or
    $personalRuntimeGuardText.Contains(
        'if (allowDevelopmentRuntime)',
        [StringComparison]::Ordinal) -or
    $personalRuntimeGuardText.Contains(
        'RuntimePointer.TryRead(',
        [StringComparison]::Ordinal)) {
    throw 'Personal production runtime guard may not admit legacy runtime state without the explicit development override.'
}

$personalHostWiringStart = $personalLauncherAppText.IndexOf(
    '            var admittedRuntimeDirectory = settings.ResolveRuntimeDirectory();',
    [StringComparison]::Ordinal)
$personalHostWiringEnd = $personalLauncherAppText.IndexOf(
    '            _launcherWindow = new MainWindow(settings, _hostService);',
    $personalHostWiringStart,
    [StringComparison]::Ordinal)
if ($personalHostWiringStart -lt 0 -or
    $personalHostWiringEnd -le $personalHostWiringStart) {
    throw 'Personal production Host runtime-admission wiring boundary is missing.'
}
$personalHostWiringText = $personalLauncherAppText.Substring(
    $personalHostWiringStart,
    $personalHostWiringEnd - $personalHostWiringStart)
$personalHostConstruction = $personalHostWiringText.IndexOf(
    '_hostService = new DshHostService(',
    [StringComparison]::Ordinal)
$personalHostValidator = $personalHostWiringText.IndexOf(
    'validateBeforeProcessStart: () =>',
    $personalHostConstruction,
    [StringComparison]::Ordinal)
$personalHostGuard = $personalHostWiringText.IndexOf(
    'RequireSamePersonalRuntimeForLaunch(',
    $personalHostValidator,
    [StringComparison]::Ordinal)
$personalHostAdmittedRuntime = $personalHostWiringText.IndexOf(
    'admittedRuntimeDirectory));',
    $personalHostGuard,
    [StringComparison]::Ordinal)
if ($personalHostConstruction -lt 0 -or
    $personalHostValidator -le $personalHostConstruction -or
    $personalHostGuard -le $personalHostValidator -or
    $personalHostAdmittedRuntime -le $personalHostGuard) {
    throw 'Personal production Host must repeat the exact v3/development runtime guard under its launch lease.'
}
foreach ($required in @(
    'internal async Task<bool> RestartLauncherAsync()',
    'LauncherRestartCoordinator.TryStartAsync(',
    'LauncherRestartCoordinator.AcceptHandoff(',
    'ReleaseSingleInstanceForHandoff',
    'TryReacquireSingleInstance',
    'ReadyForParentExit',
    'layout.StartupStubPath',
    'Environment.ProcessPath',
    'RecoverRestartFailure(',
    'FailClosedRestartWithoutParentOwnership(',
    'attempt.ParentOwnershipProven',
    'ownership.ParentOwnershipProven',
    '_ownsSingleInstanceMutex',
    'PrepareHostForRestartAsync',
    'LauncherRestartOperationGate',
    'DispatcherPriority.ApplicationIdle',
    'CreateTrayIcon(visible: _incomingRestartHandoff is null)',
    'CompleteIncomingRestartHandoffAsync',
    'LauncherRestartRollbackOutcome.RollbackOwned',
    'Timeout.InfiniteTimeSpan',
    'PersonalCompiledTrustProcessVerifier',
    '.AcquireExecutableLaunchLease(',
    'trustedEntry.Start',
    'expectedReceiver.RequireProcessImage(process)',
    'RunTrayOperationAsync',
    'RunTrayAction(ShowLauncher)'
)) {
    if (-not $personalLauncherAppText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal Launcher restart/async event boundary is missing: $required"
    }
}
if ($personalLauncherAppText.Contains(
        'process.MainModule',
        [StringComparison]::Ordinal)) {
    throw 'Personal Launcher restart may not bind a receiver through a mutable/stale process path.'
}
foreach ($required in @(
    'catch (Exception validationFailure) when (',
    'expectedReceiver.RetainsRejectedProcess(process)',
    'throw new LauncherRestartReceiverProcessRetainedException(',
    'process,',
    'validationFailure);'
)) {
    if (-not $personalLauncherAppText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal Launcher restart receiver containment marker is missing: $required"
    }
}
foreach ($required in @(
    'internal sealed class LauncherRestartReceiverProcessRetainedException',
    'internal Process RetainedProcess { get; }',
    'is LauncherRestartReceiverProcessRetainedException retained',
    'ReferenceEquals(retained.RetainedProcess, process)',
    'process.Dispose();'
)) {
    if (-not $personalRestartCoordinatorText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal Launcher restart coordinator exact-handle boundary is missing: $required"
    }
}
$receiverCleanupStart = $personalRestartCoordinatorText.IndexOf(
    '    private static void DisposeReceiverAfterValidationFailure(',
    [StringComparison]::Ordinal)
$receiverCleanupEnd = $personalRestartCoordinatorText.IndexOf(
    '    private static async Task RequireStageAsync(',
    $receiverCleanupStart,
    [StringComparison]::Ordinal)
if ($receiverCleanupStart -lt 0 -or $receiverCleanupEnd -le $receiverCleanupStart) {
    throw 'Personal Launcher restart receiver cleanup helper boundary is missing.'
}
$receiverCleanupText = $personalRestartCoordinatorText.Substring(
    $receiverCleanupStart,
    $receiverCleanupEnd - $receiverCleanupStart)
$receiverCleanupMarker = $receiverCleanupText.IndexOf(
    'is LauncherRestartReceiverProcessRetainedException retained',
    [StringComparison]::Ordinal)
$receiverCleanupExactHandle = $receiverCleanupText.IndexOf(
    'ReferenceEquals(retained.RetainedProcess, process)',
    $receiverCleanupMarker,
    [StringComparison]::Ordinal)
$receiverCleanupRetainReturn = $receiverCleanupText.IndexOf(
    'return;',
    $receiverCleanupExactHandle,
    [StringComparison]::Ordinal)
$receiverCleanupDispose = $receiverCleanupText.IndexOf(
    'process.Dispose();',
    $receiverCleanupRetainReturn,
    [StringComparison]::Ordinal)
if ($receiverCleanupMarker -lt 0 -or
    $receiverCleanupExactHandle -le $receiverCleanupMarker -or
    $receiverCleanupRetainReturn -le $receiverCleanupExactHandle -or
    $receiverCleanupDispose -le $receiverCleanupRetainReturn) {
    throw 'Personal Launcher restart receiver cleanup must retain only the exact marked handle and dispose every mismatch.'
}
foreach ($required in @(
    'PersonalLauncherRestartRetainsRejectedReceiverHandleAsync',
    'lease.RetainsRejectedProcess(rejectedProcess)',
    'DisposeReceiverAfterValidationFailureForTests(',
    'unrelatedHandleDisposed',
    '// A positive delegate result is never sufficient proof:',
    'AssertFalse(rejectedProcess.HasExited);',
    'lease.DisposeForTests((_, _) => false);',
    'AssertRetainedReceiverMutationDenied(',
    'lease.RetryRejectedProcessTerminationForTests(',
    'AssertFalse(lease.RetainsRejectedProcess(rejectedProcess));'
)) {
    if (-not $launcherRestartReceiverRetentionTestsText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal Launcher restart receiver regression is missing: $required"
    }
}
if (-not $coreTestsText.Contains(
        '("personal Launcher restart retains the exact rejected receiver handle", PersonalLauncherRestartRetainsRejectedReceiverHandleAsync),',
        [StringComparison]::Ordinal)) {
    throw 'Personal Launcher restart receiver regression is not registered in CoreTests.'
}
foreach ($required in @(
    'public sealed class PersonalTrustedExecutableLaunchLease',
    'QueryFullProcessImageName(',
    'GetFileInformationByHandle(',
    'VolumeSerialNumber',
    'FileIndex',
    'NumberOfLinks != 1',
    'FileShare.Read',
    'process.Kill(entireProcessTree: true);',
    'process.WaitForExit(checked((int)timeout.TotalMilliseconds))',
    'RequireProcessImage(Process process)'
)) {
    if (-not $personalAuthenticodeText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal trusted executable launch lease is missing: $required"
    }
}
foreach ($required in @(
    'AcquireExecutableLaunchLease(',
    '.OpenTrustedExecutableForLaunch(path, expected)',
    'executableLease.Start(startInfo)',
    'return executableLease;'
)) {
    if (-not $personalCompiledTrustText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal compiled-trust launch lease is missing: $required"
    }
}
foreach ($launchHost in @(
    [pscustomobject]@{
        Name = 'Startup Stub'
        Text = $personalStartupStubText
    },
    [pscustomobject]@{
        Name = 'ClientBootstrapper'
        Text = $personalClientBootstrapperText
    }
)) {
    foreach ($required in @(
        '.AcquireExecutableLaunchLease(',
        'executable.Start(startInfo)',
        'UseShellExecute = false'
    )) {
        if (-not $launchHost.Text.Contains(
                $required,
                [StringComparison]::Ordinal)) {
            throw "Personal trusted launch chain is missing from $($launchHost.Name): $required"
        }
    }
}
foreach ($required in @(
    '.AcquireActiveMaintenanceExecutableLaunchLease(',
    'FileName = maintenanceExecutable.ExecutablePath',
    'using var process = maintenanceExecutable.Start(startInfo);'
)) {
    if (-not $personalStartupStubText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal Maintenance handle-bound launch is missing: $required"
    }
}
if ($personalStartupStubText.Contains(
        'if (!process.Start())',
        [StringComparison]::Ordinal)) {
    throw 'Personal Maintenance may not use a path-only Process.Start boundary.'
}
foreach ($required in @(
    'AcquireActiveMaintenanceExecutableLaunchLease(',
    '.AcquireExecutableLaunchLeaseWithAdmission(',
    'verifyWhileExecutableLocked',
    'var admittedPath = RequireActiveMaintenanceExecutable(layout, current);',
    'Volatile.Read(ref verificationCount) == 1'
)) {
    if (-not $personalMaintenanceIntegrityText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal Maintenance locked complete-tree admission is missing: $required"
    }
}
if (-not $personalCompiledTrustText.Contains(
        'AcquireExecutableLaunchLeaseWithAdmission(',
        [StringComparison]::Ordinal)) {
    throw 'Personal compiled-trust verifier has no locked admission callback boundary.'
}
$externalImageAdmissionStart = $personalAuthenticodeText.IndexOf(
    '    private void RequireProcessImageCore(',
    [StringComparison]::Ordinal)
$externalImageAdmissionEnd = $personalAuthenticodeText.IndexOf(
    '    internal Process StartForTests(',
    $externalImageAdmissionStart,
    [StringComparison]::Ordinal)
if ($externalImageAdmissionStart -lt 0 -or
    $externalImageAdmissionEnd -le $externalImageAdmissionStart) {
    throw 'Personal external process-image admission boundary is missing.'
}
$externalImageAdmissionText = $personalAuthenticodeText.Substring(
    $externalImageAdmissionStart,
    $externalImageAdmissionEnd - $externalImageAdmissionStart)
$externalAdmissionGate = $externalImageAdmissionText.IndexOf(
    'lock (_launchAdmissionSync)',
    [StringComparison]::Ordinal)
$externalAdmissionTry = $externalImageAdmissionText.IndexOf(
    '            try',
    $externalAdmissionGate,
    [StringComparison]::Ordinal)
$externalGlobalRetry = $externalImageAdmissionText.IndexOf(
    'RetryRetainedRejectedProcessTerminations(',
    [StringComparison]::Ordinal)
$externalLocalRetry = $externalImageAdmissionText.IndexOf(
    'RetryRejectedProcessTermination(TerminateRejectedProcess);',
    [StringComparison]::Ordinal)
$externalLockedIdentity = $externalImageAdmissionText.IndexOf(
    'lockedExecutable.SafeFileHandle',
    [StringComparison]::Ordinal)
$externalImageInspect = $externalImageAdmissionText.IndexOf(
    'var processImage = InspectProcessImage(process);',
    [StringComparison]::Ordinal)
$externalAdmissionCatch = $externalImageAdmissionText.IndexOf(
    'catch (Exception admissionFailure)',
    [StringComparison]::Ordinal)
$externalFailureHook = $externalImageAdmissionText.IndexOf(
    'admissionFailureObserved',
    $externalAdmissionCatch,
    [StringComparison]::Ordinal)
$externalContainment = $externalImageAdmissionText.IndexOf(
    'RequireRejectedProcessTerminated(',
    $externalAdmissionCatch,
    [StringComparison]::Ordinal)
$externalAdmissionGateCount = [regex]::Matches(
    $externalImageAdmissionText,
    [regex]::Escape('lock (_launchAdmissionSync)')).Count
$externalAdmissionLockOpen = $externalImageAdmissionText.IndexOf(
    [char]'{',
    $externalAdmissionGate)
$externalAdmissionLockClose = -1
if ($externalAdmissionLockOpen -ge 0) {
    $externalAdmissionDepth = 0
    for ($index = $externalAdmissionLockOpen;
         $index -lt $externalImageAdmissionText.Length;
         $index++) {
        if ($externalImageAdmissionText[$index] -eq [char]'{') {
            $externalAdmissionDepth++
        }
        elseif ($externalImageAdmissionText[$index] -eq [char]'}') {
            $externalAdmissionDepth--
            if ($externalAdmissionDepth -eq 0) {
                $externalAdmissionLockClose = $index
            }
        }
        if ($externalAdmissionLockClose -ge 0) {
            break
        }
    }
}
if ($externalAdmissionGate -lt 0 -or
    $externalAdmissionTry -le $externalAdmissionGate -or
    $externalGlobalRetry -le $externalAdmissionTry -or
    $externalLocalRetry -le $externalGlobalRetry -or
    $externalLockedIdentity -le $externalLocalRetry -or
    $externalImageInspect -le $externalLockedIdentity -or
    $externalAdmissionCatch -le $externalImageInspect -or
    $externalFailureHook -le $externalAdmissionCatch -or
    $externalContainment -le $externalFailureHook -or
    $externalAdmissionGateCount -ne 1 -or
    $externalAdmissionLockOpen -le $externalAdmissionGate -or
    $externalAdmissionLockClose -le $externalAdmissionLockOpen -or
    $externalAdmissionCatch -ge $externalAdmissionLockClose -or
    $externalContainment -ge $externalAdmissionLockClose) {
    throw 'Personal external process-image validation and exact containment must share one admission gate.'
}

foreach ($required in @(
    'private readonly List<RetainedRejectedProcess> _rejectedProcesses = [];',
    'RetainedRejectedProcesses.Add(this)',
    'RetainRejectedProcess(process, rejectionFailure);',
    'Exception RejectionFailure',
    'Action? admissionAttempted',
    'Action? disposalAttempted',
    'Action? admissionFailureObserved',
    '_disposeRequested = true;',
    'RetryRetainedRejectedProcessTerminations(',
    'exited = process.WaitForExit(0) && process.HasExited;',
    'if (_rejectedProcesses.Count == 0)',
    'RetainedRejectedProcesses.Remove(this);',
    'Personal rejected process remains retained for fail-closed termination retry.'
)) {
    if (-not $personalAuthenticodeText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal rejected-process handle retention is missing: $required"
    }
}
if ($personalAuthenticodeText.Contains(
        'TerminateRequired(',
        [StringComparison]::Ordinal)) {
    throw 'Personal rejected process may not use the legacy handle-losing termination helper.'
}
foreach ($required in @(
    '("personal rejected process containment retains exact handles until proven exit", PersonalRejectedProcessContainmentRetainsExactHandlesAsync),',
    '("personal external image admission contains the current process when prior containment blocks validation", PersonalExternalImageAdmissionContainsCurrentProcessAsync),',
    '("personal trusted launch lease serializes concurrent admissions and disposal", PersonalTrustedLaunchLeaseSerializesConcurrentAdmissionsAsync),',
    'PersonalRejectedProcessContainmentRetainsExactHandlesAsync',
    'PersonalExternalImageAdmissionContainsCurrentProcessAsync',
    'PersonalTrustedLaunchLeaseSerializesConcurrentAdmissionsAsync',
    'admissionAttempted:',
    'admissionFailureObserved:',
    'disposeAttempted.Set',
    'externalFailureObserved',
    'releaseExternalContainment',
    'concurrentStartAttempted.Wait(TimeSpan.FromSeconds(5))',
    'AssertFalse(concurrentAdmission.IsCompleted);',
    'AssertEqual(0, Volatile.Read(ref concurrentAdmissionStartCalls));',
    'AssertTrue(blockerLease.RetainsRejectedProcess(blockerProcess));',
    'AssertTrue(receiverLease.RetainsRejectedProcess(receiverProcess));'
)) {
    if (-not $personalUpdateTestsText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal trusted-launch containment/concurrency regression is missing: $required"
    }
}

$selfCheckAdmissionStart = $personalCompiledTrustText.IndexOf(
    '            var startedProcess = executableLease.Start(startInfo);',
    [StringComparison]::Ordinal)
$selfCheckAdmissionEnd = $personalCompiledTrustText.IndexOf(
    '    internal static void RequireSelfCheckProcessTerminatedForTests(',
    $selfCheckAdmissionStart,
    [StringComparison]::Ordinal)
if ($selfCheckAdmissionStart -lt 0 -or
    $selfCheckAdmissionEnd -le $selfCheckAdmissionStart) {
    throw 'Personal compiled-trust self-check ownership boundary is missing.'
}
$selfCheckAdmissionText = $personalCompiledTrustText.Substring(
    $selfCheckAdmissionStart,
    $selfCheckAdmissionEnd - $selfCheckAdmissionStart)
$selfCheckTimeoutCatch = $selfCheckAdmissionText.IndexOf(
    'catch (OperationCanceledException) when (timeout.IsCancellationRequested)',
    [StringComparison]::Ordinal)
$selfCheckTimeoutContainment = $selfCheckAdmissionText.IndexOf(
    'RequireSelfCheckProcessTerminated(',
    $selfCheckTimeoutCatch,
    [StringComparison]::Ordinal)
$selfCheckFailureCatch = $selfCheckAdmissionText.IndexOf(
    'catch (Exception selfCheckFailure)',
    $selfCheckTimeoutContainment,
    [StringComparison]::Ordinal)
$selfCheckFailureContainment = $selfCheckAdmissionText.IndexOf(
    'RequireSelfCheckProcessTerminated(',
    $selfCheckFailureCatch,
    [StringComparison]::Ordinal)
$selfCheckOwnedDispose = $selfCheckAdmissionText.IndexOf(
    'ownedProcess?.Dispose();',
    $selfCheckFailureContainment,
    [StringComparison]::Ordinal)
$selfCheckOuterCatch = $selfCheckAdmissionText.IndexOf(
    'catch (Exception acquisitionFailure)',
    $selfCheckOwnedDispose,
    [StringComparison]::Ordinal)
$selfCheckLeaseDispose = $selfCheckAdmissionText.IndexOf(
    'executableLease.Dispose();',
    $selfCheckOuterCatch,
    [StringComparison]::Ordinal)
$selfCheckAggregate = $selfCheckAdmissionText.IndexOf(
    'new AggregateException(',
    $selfCheckLeaseDispose,
    [StringComparison]::Ordinal)
$selfCheckAcquisitionFailureArgument = $selfCheckAdmissionText.IndexOf(
    'acquisitionFailure,',
    $selfCheckAggregate,
    [StringComparison]::Ordinal)
$selfCheckContainmentFailureArgument = $selfCheckAdmissionText.IndexOf(
    'containmentFailure));',
    $selfCheckAcquisitionFailureArgument,
    [StringComparison]::Ordinal)
if ($selfCheckTimeoutCatch -lt 0 -or
    $selfCheckTimeoutContainment -le $selfCheckTimeoutCatch -or
    $selfCheckFailureCatch -le $selfCheckTimeoutContainment -or
    $selfCheckFailureContainment -le $selfCheckFailureCatch -or
    $selfCheckOwnedDispose -le $selfCheckFailureContainment -or
    $selfCheckOuterCatch -le $selfCheckOwnedDispose -or
    $selfCheckLeaseDispose -le $selfCheckOuterCatch -or
    $selfCheckAggregate -le $selfCheckLeaseDispose -or
    $selfCheckAcquisitionFailureArgument -le $selfCheckAggregate -or
    $selfCheckContainmentFailureArgument -le $selfCheckAcquisitionFailureArgument -or
    -not $selfCheckAdmissionText.Contains(
        'Process? ownedProcess = startedProcess;',
        [StringComparison]::Ordinal)) {
    throw 'Personal compiled-trust timeout/read failures must transfer exact process ownership before lease cleanup.'
}
$selfCheckHelperStart = $personalCompiledTrustText.IndexOf(
    '    private static void RequireSelfCheckProcessTerminated(',
    [StringComparison]::Ordinal)
$selfCheckHelperEnd = $personalCompiledTrustText.IndexOf(
    '    private static async Task<string> ReadBoundedAsync(',
    $selfCheckHelperStart,
    [StringComparison]::Ordinal)
if ($selfCheckHelperStart -lt 0 -or
    $selfCheckHelperEnd -le $selfCheckHelperStart) {
    throw 'Personal compiled-trust exact process containment helper is missing.'
}
$selfCheckHelperText = $personalCompiledTrustText.Substring(
    $selfCheckHelperStart,
    $selfCheckHelperEnd - $selfCheckHelperStart)
$selfCheckHelperContainment = $selfCheckHelperText.IndexOf(
    'executableLease.RequireRejectedProcessTerminated(',
    [StringComparison]::Ordinal)
$selfCheckHelperFinally = $selfCheckHelperText.IndexOf(
    'finally',
    $selfCheckHelperContainment,
    [StringComparison]::Ordinal)
$selfCheckHelperTransfer = $selfCheckHelperText.IndexOf(
    'ownedProcess = null;',
    $selfCheckHelperFinally,
    [StringComparison]::Ordinal)
if ($selfCheckHelperContainment -lt 0 -or
    $selfCheckHelperFinally -le $selfCheckHelperContainment -or
    $selfCheckHelperTransfer -le $selfCheckHelperFinally -or
    $personalCompiledTrustText.Contains(
        'using var process = executableLease.Start(startInfo);',
        [StringComparison]::Ordinal)) {
    throw 'Personal compiled-trust self-check may not dispose an unconfirmed rejected process handle.'
}
foreach ($required in @(
    'RequireSelfCheckProcessTerminatedForTests(',
    'ref rejectedSelfCheckProcess,',
    'originalSelfCheckFailure,',
    'AssertTrue(rejectedSelfCheckProcess is null);',
    'lease.RetainedRejectedProcessFailureForTests',
    'lease.DisposeForTests((_, _) => false)',
    'AssertMutationDenied(() =>'
)) {
    if (-not $personalUpdateTestsText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal compiled-trust self-check containment regression is missing: $required"
    }
}
foreach ($required in @(
    'RunUiEventAsync(CheckForUpdatesAsync)',
    'RunUiEventAsync(HandlePrimaryActionAsync)',
    'RunUiEventAsync(OpenWebUiAsync)',
    'catch (Exception exception)',
    'An async-void WPF event must never escape'
)) {
    if (-not $personalLauncherWindowText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal Launcher WPF event boundary is missing: $required"
    }
}
foreach ($required in @(
    'catch (Exception exception)',
    'command.ArmedEventName',
    'command.OwnedEventName',
    'command.ReadyEventName',
    'command.CommitEventName',
    'command.CommitAcknowledgedEventName',
    'command.ReleasedEventName',
    'command.RollbackOwnedEventName',
    'command.PipeName',
    'command.CancellationEventName',
    'GetNamedPipeClientProcessId(',
    'PipeOptions.CurrentUserOnly',
    'process.StartTime.ToUniversalTime()',
    'process.SessionId != parentSessionId',
    'validateReceiverProcess?.Invoke(process)',
    'PrepareWhileMonitoringAsync(',
    'CancelAndRecoverParentOwnership(',
    'DefaultCancellationGrace',
    'TimeSpan.FromSeconds(5)',
    'LauncherRestartParentOwnership.Unproven',
    'LauncherRestartParentOwnership.Recovered',
    'waitForReceiverExit(',
    'tryReacquireSingleton(cancellationGrace)',
    'return OwnershipUnproven(',
    'receiverProcess.Kill(entireProcessTree: true);',
    '"替代 Launcher 本地初始化超时。"',
    'releasedObserved?.Invoke();',
    'TrySet(rollbackOwned);',
    'releaseSingleton();',
    'tryReacquireSingleton(',
    'WaitForMutexOrCancellation(',
    'UseShellExecute = false',
    'CreateNoWindow = true',
    'MaximumFailureLength = 512',
    'NormalizeFailure(exception)'
)) {
    if (-not $personalRestartCoordinatorText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal Launcher restart coordinator contract is missing: $required"
    }
}
foreach ($required in @(
    'public const string CommandSwitch = "--launcher-restart-handoff"',
    'public const string ParentProcessIdSwitch = "--parent-pid"',
    'RandomNumberGenerator.GetBytes(32)',
    'public string ArmedEventName',
    'public string OwnedEventName',
    'public string ReadyEventName',
    'public string CommitEventName',
    'public string CommitAcknowledgedEventName',
    'public string ReleasedEventName',
    'public string RollbackOwnedEventName',
    'public string PipeName',
    'public string CancellationEventName',
    'public string FailureEventName'
)) {
    if (-not $personalRestartHandoffContractText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal Launcher restart handoff command contract is missing: $required"
    }
}
foreach ($required in @(
    'PersonalLauncherRestartHandoffCommand.TryParse(',
    'startInfo.ArgumentList.Add(argument)',
    'PersonalLauncherRestartHandoffForwarder.WaitForFinalReceiver('
)) {
    if (-not $personalStartupStubText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal Launcher restart handoff forwarding is missing from Startup Stub: $required"
    }
}
function Assert-PersonalClientBootstrapperRestartHandoffContract {
    param(
        [Parameter(Mandatory)]
        [string]$SourceText,
        [Parameter(Mandatory)]
        [string]$Label
    )

    $parseAndStrip = $SourceText.IndexOf(
        'PersonalDevelopmentE2ELayoutArguments.ParseAndStrip(',
        [StringComparison]::Ordinal)
    if ($parseAndStrip -lt 0) {
        throw "Personal ClientBootstrapper restart handoff must parse stripped command arguments before forwarding: $Label"
    }
    $commandArguments = $SourceText.IndexOf(
        'out var commandArguments);',
        $parseAndStrip,
        [StringComparison]::Ordinal)
    if ($commandArguments -le $parseAndStrip) {
        throw "Personal ClientBootstrapper restart handoff must parse stripped command arguments before forwarding: $Label"
    }
    $isIntent = $SourceText.IndexOf(
        'PersonalLauncherRestartHandoffCommand.IsIntent(commandArguments)',
        $commandArguments,
        [StringComparison]::Ordinal)
    if ($isIntent -le $commandArguments) {
        throw "Personal ClientBootstrapper restart handoff must parse stripped command arguments before forwarding: $Label"
    }
    $parseRequired = $SourceText.IndexOf(
        'PersonalLauncherRestartHandoffCommand.ParseRequired(commandArguments)',
        $isIntent,
        [StringComparison]::Ordinal)
    if ($parseRequired -le $isIntent) {
        throw "Personal ClientBootstrapper restart handoff must parse stripped command arguments before forwarding: $Label"
    }
    $toArguments = $SourceText.IndexOf(
        'restartHandoff.ToArguments()',
        $parseRequired,
        [StringComparison]::Ordinal)
    if ($toArguments -le $parseRequired) {
        throw "Personal ClientBootstrapper restart handoff must parse stripped command arguments before forwarding: $Label"
    }
    $argumentForward = $SourceText.IndexOf(
        'startInfo.ArgumentList.Add(argument)',
        $toArguments,
        [StringComparison]::Ordinal)
    $receiverWait = $SourceText.IndexOf(
        'PersonalLauncherRestartHandoffForwarder.WaitForFinalReceiver(',
        $parseRequired,
        [StringComparison]::Ordinal)
    if ($argumentForward -le $toArguments -or
        $receiverWait -le $parseRequired) {
        throw "Personal ClientBootstrapper restart handoff must parse stripped command arguments before forwarding: $Label"
    }
}
Assert-PersonalClientBootstrapperRestartHandoffContract `
    -SourceText $personalClientBootstrapperText `
    -Label 'current ClientBootstrapper restart handoff'
$clientBootstrapperRestartMutation = $personalClientBootstrapperText.Replace(
    'PersonalLauncherRestartHandoffCommand.ParseRequired(commandArguments)',
    'PersonalLauncherRestartHandoffCommand.ParseRequired(args)',
    [StringComparison]::Ordinal)
Assert-ExpectedContractFailure `
    -Action {
        Assert-PersonalClientBootstrapperRestartHandoffContract `
            -SourceText $clientBootstrapperRestartMutation `
            -Label 'ClientBootstrapper unstripped handoff mutation'
    } `
    -ExpectedMessage 'Personal ClientBootstrapper restart handoff must parse stripped command arguments before forwarding: ClientBootstrapper unstripped handoff mutation' `
    -Label 'ClientBootstrapper unstripped handoff mutation'
$clientBootstrapperNoStripMutation = $personalClientBootstrapperText.Replace(
    'PersonalDevelopmentE2ELayoutArguments.ParseAndStrip(',
    'PersonalDevelopmentE2ELayoutArguments.ParseWithoutStripping(',
    [StringComparison]::Ordinal)
Assert-ExpectedContractFailure `
    -Action {
        Assert-PersonalClientBootstrapperRestartHandoffContract `
            -SourceText $clientBootstrapperNoStripMutation `
            -Label 'ClientBootstrapper missing ParseAndStrip mutation'
    } `
    -ExpectedMessage 'Personal ClientBootstrapper restart handoff must parse stripped command arguments before forwarding: ClientBootstrapper missing ParseAndStrip mutation' `
    -Label 'ClientBootstrapper missing ParseAndStrip mutation'
$clientBootstrapperNoIntentMutation = $personalClientBootstrapperText.Replace(
    'PersonalLauncherRestartHandoffCommand.IsIntent(commandArguments)',
    'PersonalLauncherRestartHandoffCommand.IsIntent(args)',
    [StringComparison]::Ordinal)
Assert-ExpectedContractFailure `
    -Action {
        Assert-PersonalClientBootstrapperRestartHandoffContract `
            -SourceText $clientBootstrapperNoIntentMutation `
            -Label 'ClientBootstrapper unstripped IsIntent mutation'
    } `
    -ExpectedMessage 'Personal ClientBootstrapper restart handoff must parse stripped command arguments before forwarding: ClientBootstrapper unstripped IsIntent mutation' `
    -Label 'ClientBootstrapper unstripped IsIntent mutation'
$personalForwarderText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.UpdateEngine\PersonalLauncherRestartHandoffForwarder.cs')
foreach ($required in @(
    'WaitForFinalReceiver(',
    'command.ArmedEventName',
    'command.FailureEventName',
    'command.CancellationEventName',
    'ForwardedProcessWaitHandle',
    'forwardedProcess.ExitCode'
)) {
    if (-not $personalForwarderText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal restart forwarder is not observable through final HELLO: $required"
    }
}
$personalPublishedArtifactsText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'scripts\Test-PersonalPublishedArtifacts.ps1')
foreach ($required in @(
    'Assert-NonInteractiveStartupStubMachineFailure',
    "Name = 'extra-binary-self-check-argument'",
    "Name = 'extra-installer-health-argument'",
    'Ensou DSH Personal Startup Stub machine command failed.',
    'blocked on interactive UI'
)) {
    if (-not $personalPublishedArtifactsText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal Startup Stub published malformed-command gate is missing: $required"
    }
}
$personalPublishedArtifactsPath = Join-Path `
    $RepositoryRoot `
    'scripts\Test-PersonalPublishedArtifacts.ps1'
$personalPublishedArtifactsTokens = $null
$personalPublishedArtifactsParseErrors = $null
$personalPublishedArtifactsAst =
    [Management.Automation.Language.Parser]::ParseFile(
        $personalPublishedArtifactsPath,
        [ref]$personalPublishedArtifactsTokens,
        [ref]$personalPublishedArtifactsParseErrors)
if ($personalPublishedArtifactsParseErrors.Count -ne 0) {
    throw 'Personal published-artifact RFC3161 gate no longer parses.'
}
$personalAuthenticodeFunctions = @($personalPublishedArtifactsAst.FindAll(
    {
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Assert-Authenticode'
    },
    $true))
$personalLockedReadFunctions = @($personalPublishedArtifactsAst.FindAll(
    {
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Read-LockedDescriptorBytes'
    },
    $true))
if ($personalAuthenticodeFunctions.Count -ne 1 -or
    $personalLockedReadFunctions.Count -ne 1) {
    throw 'Personal published-artifact RFC3161 gate lost its unique verifier or locked-byte reader.'
}
$personalAuthenticodeFunctionText =
    $personalAuthenticodeFunctions[0].Extent.Text
$personalLockedReadFunctionText =
    $personalLockedReadFunctions[0].Extent.Text
foreach ($required in @(
    '$signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature',
    '[byte[]]$lockedBytes = Read-LockedDescriptorBytes $Descriptor',
    '$timestampAdmission = ProductionReleaseState\Assert-PeRfc3161Timestamp',
    '-Bytes $lockedBytes',
    '-SignerCertificate $signature.SignerCertificate',
    '-TimeStamperCertificate $signature.TimeStamperCertificate',
    '$timestampAdmission.TimestampProtocol -cne ''RFC3161''',
    '$timestamped = $true'
)) {
    if (-not $personalAuthenticodeFunctionText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal published-artifact RFC3161 admission is missing: $required"
    }
}
foreach ($required in @(
    '$Descriptor.Stream.Length -ne $Descriptor.SizeBytes',
    '$Descriptor.Stream.Position = 0',
    '$Descriptor.Stream.Read(',
    '$Descriptor.Stream.ReadByte() -ne -1'
)) {
    if (-not $personalLockedReadFunctionText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal published-artifact RFC3161 locked-byte reader is missing: $required"
    }
}
$lockedReadIndex = $personalAuthenticodeFunctionText.IndexOf(
    '[byte[]]$lockedBytes = Read-LockedDescriptorBytes $Descriptor',
    [StringComparison]::Ordinal)
$canonicalTimestampIndex = $personalAuthenticodeFunctionText.IndexOf(
    '$timestampAdmission = ProductionReleaseState\Assert-PeRfc3161Timestamp',
    [StringComparison]::Ordinal)
$timestampProtocolIndex = $personalAuthenticodeFunctionText.IndexOf(
    '$timestampAdmission.TimestampProtocol -cne ''RFC3161''',
    [StringComparison]::Ordinal)
$admittedEvidenceIndex = $personalAuthenticodeFunctionText.IndexOf(
    '$timestamped = $true',
    [StringComparison]::Ordinal)
if ($lockedReadIndex -lt 0 -or
    $canonicalTimestampIndex -le $lockedReadIndex -or
    $timestampProtocolIndex -le $canonicalTimestampIndex -or
    $admittedEvidenceIndex -le $timestampProtocolIndex -or
    [regex]::Matches(
        $personalAuthenticodeFunctionText,
        '(?m)^[ \t]*\$timestampAdmission = ProductionReleaseState\\Assert-PeRfc3161Timestamp[ \t]*`?[ \t]*\r?$').Count -ne 1) {
    throw 'Personal published-artifact timestamp evidence is no longer ordered after one canonical RFC3161 admission.'
}
foreach ($required in @(
    "'..\release\scripts\ProductionReleaseState.psm1'",
    '[IO.FileShare]::Read',
    'RequireOrdinarySingleLink(',
    'Assert-ExactFileDescriptorUnchanged',
    'Open-AdmittedDescriptorCopy',
    '$stubDescriptor,',
    '$clientBootstrapperDescriptor,',
    '$launcherDescriptor,',
    '$maintenanceDescriptor',
    'Assert-Authenticode $descriptor',
    '$installerAuthenticode = Assert-Authenticode $installerDescriptor'
)) {
    if (-not $personalPublishedArtifactsText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal published-artifact RFC3161 descriptor binding is missing: $required"
    }
}
if ($personalPublishedArtifactsText.Contains(
        'Get-AuthenticodeEvidence',
        [StringComparison]::Ordinal) -or
    [regex]::Matches(
        $personalPublishedArtifactsText,
        '(?m)^[ \t]*Assert-Authenticode \$descriptor[ \t]*\r?$').Count -ne 1 -or
    [regex]::Matches(
        $personalPublishedArtifactsText,
        '(?m)^[ \t]*\$installerAuthenticode = Assert-Authenticode \$installerDescriptor[ \t]*\r?$').Count -ne 1) {
    throw 'Personal published-artifact RFC3161 admission no longer covers exactly the shared client loop and Installer descriptor.'
}
$personalPublishedMainIndex = $personalPublishedArtifactsText.IndexOf(
    '$clientExecutableDescriptors = @(',
    [StringComparison]::Ordinal)
if ($personalPublishedMainIndex -lt 0) {
    throw 'Personal published-artifact executable-order contract lost its main gate body.'
}
$personalPublishedMain = $personalPublishedArtifactsText.Substring(
    $personalPublishedMainIndex)
$personalInstallerAdmissionIndex = $personalPublishedMain.IndexOf(
    '$installerAuthenticode = Assert-Authenticode $installerDescriptor',
    [StringComparison]::Ordinal)
$personalClientAdmissionIndex = $personalPublishedMain.IndexOf(
    'Assert-Authenticode $descriptor',
    [StringComparison]::Ordinal)
$personalFinalAdmissionIndex = [Math]::Max(
    $personalInstallerAdmissionIndex,
    $personalClientAdmissionIndex)
foreach ($executionSink in @(
    'Invoke-BinarySelfCheckWithoutSystemDotNet',
    'Assert-NonInteractiveStartupStubMachineFailure',
    'Assert-NonInteractiveClientBootstrapperHealthFailure',
    'Invoke-PayloadSelfCheckWithoutSystemDotNet',
    'Assert-InvalidInstallerSelfCheckIsNonInteractive')) {
    $executionIndex = $personalPublishedMain.IndexOf(
        $executionSink,
        [StringComparison]::Ordinal)
    if ($personalInstallerAdmissionIndex -lt 0 -or
        $personalClientAdmissionIndex -lt 0 -or
        $executionIndex -le $personalFinalAdmissionIndex) {
        throw "Personal published-artifact gate can execute '$executionSink' before every candidate EXE completes Authenticode/RFC3161 admission."
    }
}
if ([regex]::Matches(
        $personalPublishedMain,
        '(?m)^[ \t]*(?:\$[A-Za-z][A-Za-z0-9]*[ \t]*=[ \t]*)?Invoke-BinarySelfCheckWithoutSystemDotNet\b').Count -ne 2) {
    throw 'Personal published-artifact executable-order contract no longer covers its client loop and Installer primary self-checks.'
}
$personalExecutionFunctions = @(
    'Invoke-BinarySelfCheckWithoutSystemDotNet',
    'Assert-NonInteractiveStartupStubMachineFailure',
    'Assert-NonInteractiveClientBootstrapperHealthFailure',
    'Invoke-PayloadSelfCheckWithoutSystemDotNet',
    'Assert-InvalidInstallerSelfCheckIsNonInteractive')
foreach ($personalExecutionFunction in $personalExecutionFunctions) {
    $functionNodes = @($personalPublishedArtifactsAst.FindAll(
        {
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq $personalExecutionFunction
        },
        $true))
    if ($functionNodes.Count -ne 1) {
        throw "Personal published-artifact execution function is not unique: $personalExecutionFunction"
    }
    $functionText = $functionNodes[0].Extent.Text
    $identityIndex = $functionText.IndexOf(
        'Assert-ExactFileDescriptorUnchanged',
        [StringComparison]::Ordinal)
    $staticStartIndex = $functionText.IndexOf(
        '[Diagnostics.Process]::Start($start)',
        [StringComparison]::Ordinal)
    $instanceStartIndex = $functionText.IndexOf(
        '$process.Start()',
        [StringComparison]::Ordinal)
    $startIndex = if ($staticStartIndex -ge 0) {
        $staticStartIndex
    }
    else {
        $instanceStartIndex
    }
    if ($identityIndex -lt 0 -or
        $startIndex -lt 0 -or
        $identityIndex -gt $startIndex) {
        throw "Personal published-artifact execution function lost its launch-adjacent locked identity/hash check: $personalExecutionFunction"
    }
    if ($personalExecutionFunction -in @(
            'Assert-NonInteractiveStartupStubMachineFailure',
            'Assert-NonInteractiveClientBootstrapperHealthFailure') -and
        $functionText.IndexOf(
            'Open-AdmittedDescriptorCopy',
            [StringComparison]::Ordinal) -lt 0) {
        throw "Personal published-artifact copied execution probe is not bound to admitted bytes: $personalExecutionFunction"
    }
}

$personalUnsignedExecutionRoot = Join-Path `
    ([IO.Path]::GetTempPath()) `
    ("ensou-personal-unsigned-execution-{0}" -f [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($personalUnsignedExecutionRoot) | Out-Null
try {
    $personalUnsignedCandidate = Join-Path `
        $personalUnsignedExecutionRoot `
        'unsigned-marker-writer.exe'
    $personalMarkerControl = Join-Path `
        $personalUnsignedExecutionRoot `
        'control.marker'
    $personalMarkerRejected = Join-Path `
        $personalUnsignedExecutionRoot `
        'rejected.marker'
    Copy-Item `
        -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') `
        -Destination $personalUnsignedCandidate
    [byte[]]$personalUnsignedBytes = [IO.File]::ReadAllBytes(
        $personalUnsignedCandidate)
    $personalPeOffset = [BitConverter]::ToInt32($personalUnsignedBytes, 0x3c)
    $personalOptionalHeaderOffset = $personalPeOffset + 24
    $personalOptionalMagic = [BitConverter]::ToUInt16(
        $personalUnsignedBytes,
        $personalOptionalHeaderOffset)
    $personalDataDirectoryOffset = switch ($personalOptionalMagic) {
        0x10b { $personalOptionalHeaderOffset + 96 }
        0x20b { $personalOptionalHeaderOffset + 112 }
        default { throw 'Unsigned marker candidate has an unsupported PE optional header.' }
    }
    $personalSecurityDirectoryOffset = $personalDataDirectoryOffset + (4 * 8)
    if ($personalSecurityDirectoryOffset + 8 -gt $personalUnsignedBytes.Length) {
        throw 'Unsigned marker candidate has a truncated PE security directory.'
    }
    [Array]::Clear($personalUnsignedBytes, $personalSecurityDirectoryOffset, 8)
    [Array]::Resize(
        [ref]$personalUnsignedBytes,
        $personalUnsignedBytes.Length + 1)
    $personalUnsignedBytes[$personalUnsignedBytes.Length - 1] = 0x5a
    [IO.File]::WriteAllBytes(
        $personalUnsignedCandidate,
        $personalUnsignedBytes)
    $personalUnsignedSignature =
        Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
            -LiteralPath $personalUnsignedCandidate
    if ($personalUnsignedSignature.Status -ne
            [Management.Automation.SignatureStatus]::NotSigned) {
        throw 'Marker-writing Personal negative candidate is not unsigned.'
    }

    $controlStart = [Diagnostics.ProcessStartInfo]::new()
    $controlStart.FileName = $personalUnsignedCandidate
    $controlStart.WorkingDirectory = $personalUnsignedExecutionRoot
    $controlStart.UseShellExecute = $false
    $controlStart.CreateNoWindow = $true
    $controlStart.ArgumentList.Add('/d')
    $controlStart.ArgumentList.Add('/q')
    $controlStart.ArgumentList.Add('/c')
    $controlStart.ArgumentList.Add(
        'echo executed>control.marker')
    $controlProcess = [Diagnostics.Process]::Start($controlStart)
    try {
        if (-not $controlProcess.WaitForExit(10000) -or
            $controlProcess.ExitCode -ne 0 -or
            -not [IO.File]::Exists($personalMarkerControl)) {
            throw 'Unsigned Personal negative candidate did not prove its marker-writing control behavior.'
        }
    }
    finally {
        $controlProcess.Dispose()
    }
    [IO.File]::Delete($personalMarkerControl)

    $personalAuthenticodeScriptBlock =
        $personalAuthenticodeFunctions[0].Body.GetScriptBlock()
    $personalUnsignedAdmitted = & {
        param($Verifier, $Candidate)

        $RequireAuthenticode = $true
        $ProductionDistributionGate = $true
        $SignerSha256Thumbprint = '0' * 64
        try {
            [void](& $Verifier ([pscustomobject]@{ Path = $Candidate }))
            return $true
        }
        catch {
            if ($_.Exception.Message -notlike
                    'Authenticode signature is not valid:*') {
                throw
            }
            return $false
        }
    } $personalAuthenticodeScriptBlock $personalUnsignedCandidate
    if ($personalUnsignedAdmitted) {
        $rejectedStart = [Diagnostics.ProcessStartInfo]::new()
        $rejectedStart.FileName = $personalUnsignedCandidate
        $rejectedStart.WorkingDirectory = $personalUnsignedExecutionRoot
        $rejectedStart.UseShellExecute = $false
        $rejectedStart.CreateNoWindow = $true
        $rejectedStart.ArgumentList.Add('/d')
        $rejectedStart.ArgumentList.Add('/q')
        $rejectedStart.ArgumentList.Add('/c')
        $rejectedStart.ArgumentList.Add(
            'echo executed>rejected.marker')
        $rejectedProcess = [Diagnostics.Process]::Start($rejectedStart)
        try {
            if (-not $rejectedProcess.WaitForExit(10000)) {
                $rejectedProcess.Kill($true)
            }
        }
        finally {
            $rejectedProcess.Dispose()
        }
    }
    if ([IO.File]::Exists($personalMarkerRejected)) {
        throw 'Unsigned Personal marker-writing candidate executed before Authenticode/RFC3161 admission.'
    }
}
finally {
    $personalUnsignedExecutionFullPath = [IO.Path]::GetFullPath(
        $personalUnsignedExecutionRoot)
    $personalUnsignedExecutionPrefix =
        [IO.Path]::TrimEndingDirectorySeparator(
            [IO.Path]::GetFullPath([IO.Path]::GetTempPath())) +
        [IO.Path]::DirectorySeparatorChar +
        'ensou-personal-unsigned-execution-'
    if (-not $personalUnsignedExecutionFullPath.StartsWith(
            $personalUnsignedExecutionPrefix,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to remove an unexpected Personal unsigned-execution fixture directory.'
    }
    if ([IO.Directory]::Exists($personalUnsignedExecutionFullPath)) {
        [IO.Directory]::Delete($personalUnsignedExecutionFullPath, $true)
    }
}
$personalRfc3161PolicyPath = Join-Path `
    $RepositoryRoot `
    'scripts\Test-PersonalPublishedArtifactsRfc3161Policy.ps1'
$personalRfc3161PolicyText = Get-Content -Raw -LiteralPath `
    $personalRfc3161PolicyPath
foreach ($required in @(
    'New-TestPeWithCms',
    'wrong-primary-SignerInfo RFC3161 token regression',
    'truncated WIN_CERTIFICATE alignment regression',
    'invalid primary CMS with bound RFC3161 token regression',
    'invalid auxiliary CMS RFC3161 regression',
    'Authenticode locked-PE digest regression',
    'non-Authenticode CMS content-type regression',
    'legacy counterSignature regression',
    'ProductionReleaseState\Assert-PeRfc3161Timestamp',
    'PERSONAL-RFC3161-REAL-FIXTURE-PENDING',
    'PERSONAL-RFC3161-REAL-FIXTURE-PASS'
)) {
    if (-not $personalRfc3161PolicyText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal published-artifact RFC3161 semantic regression is missing: $required"
    }
}
$personalRfc3161PolicyOutput = @(& $personalRfc3161PolicyPath)
if ($personalRfc3161PolicyOutput.Count -ne 3 -or
    $personalRfc3161PolicyOutput[0] -cne
        'PERSONAL-RFC3161-NEGATIVE-CONTRACTS-PASS' -or
    $personalRfc3161PolicyOutput[2] -cne
        'PERSONAL-RFC3161-POLICY-CONTRACT-PASS' -or
    ($personalRfc3161PolicyOutput[1] -notlike
        'PERSONAL-RFC3161-REAL-FIXTURE-PASS:*' -and
     $personalRfc3161PolicyOutput[1] -notlike
        'PERSONAL-RFC3161-REAL-FIXTURE-PENDING:*')) {
    throw 'Personal published-artifact RFC3161 semantic regression did not pass with an explicit real-fixture outcome.'
}
foreach ($required in @(
    'IsMachineCommandIntent(IReadOnlyList<string> args)',
    'or "--installer-health"',
    'WriteMachineCommandFailure();',
    'Ensou DSH Personal Startup Stub machine command failed.'
)) {
    if (-not $personalStartupStubText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal Startup Stub machine-command boundary is missing: $required"
    }
}
foreach ($required in @(
    'personal Launcher restart performs a real two-process singleton handoff',
    'LauncherRestartParentProbe',
    'LauncherRestartChildProbe',
    'LauncherRestartForwarderProbe',
    '"forwarded-success"',
    '"delayed-prepare"',
    '"post-ready-failure"',
    '"hung-before-ready"',
    '"forwarded-hung-before-ready"',
    '"receiver-image-mismatch"',
    '"hung-after-ready"',
    '"hung-after-ack"',
    '"release-failure"',
    '"abort-rollback"',
    '"abort-parent-crash"',
    'Environment.Exit(31);',
    'receiver.SignalReleased();',
    'WaitForRollbackOwnedOrParentExitAsync()',
    'AssertLauncherRestartSingleFlightAsync()',
    'Enumerable.Range(0, 20)',
    'catch (OperationCanceledException)',
    'TryWriteLauncherProbeMarker(exitMarkerPath, "30");',
    'expectedChildExit',
    'AssertLauncherRestartOwnershipFailureResults()',
    'LauncherRestartParentOwnership.Unproven',
    'simulated kill failure',
    'simulated reacquire failure',
    'cancellationGrace: TimeSpan.FromSeconds(1)',
    'starterProcessId == receiverProcessId',
    'expectedReceiver.RequireProcessImage(process)',
    'CreateMismatchedCoreTestsExecutable()',
    'WaitForLauncherProbeProcessExit(',
    '$"{markerPath}.forwarder-exit"',
    'StartCurrentTestProcess(',
    'LauncherRestartCoordinator.AcceptHandoff(',
    'Process.GetProcessById(childProcessId)',
    'observed.WaitOne(TimeSpan.Zero)'
)) {
    if (-not $coreTestsText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal Launcher restart real-process executable test is missing: $required"
    }
}
foreach ($required in @(
    'personal trusted launch lease binds the real process image through mutation races',
    'OpenExecutableForLaunchForTests(executable)',
    'File.Move(executable, renamed)',
    'File.Move(replacement, executable, overwrite: true)',
    'File.Delete(executable)',
    'lease.Start(startInfo)',
    'lease.InspectProcessImageIdentityForTests(process)',
    'lease.StartForTests(',
    'WaitForProcessExit(mismatchedProcessId)'
)) {
    if (-not $personalUpdateTestsText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Personal trusted launch real-process regression is missing: $required"
    }
}

$backgroundPilotText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'docs\windows-background-runtime-pilot.md')
$enterpriseWindowsPilotText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'docs\enterprise\windows-employee-pilot.md')
foreach ($required in @(
    'do **not** force every future process',
    'A Job Object propagates lifetime ownership',
    'one real production plugin or tool action',
    'dotnet.exe - Application Error',
    'at least once per second',
    'unexercised required spawn path',
    'never authorizes the statement'
)) {
    if (-not $backgroundPilotText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Windows background-runtime Pilot gate is incomplete: $required"
    }
}
foreach ($required in @(
    'Receipt 2 is an active subprocess exercise',
    'process-tree lifetime ownership, not descendant window suppression'
)) {
    if (-not $enterpriseWindowsPilotText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Enterprise Windows Pilot no-window gate is incomplete: $required"
    }
}

$runtimeWebAuthContractPath = Join-Path `
    $RepositoryRoot `
    'scripts\Test-SourceRuntimeWebAuthContract.ps1'
if (-not (Test-Path -LiteralPath $runtimeWebAuthContractPath -PathType Leaf)) {
    throw "Source-runtime Web auth contract test is missing: $runtimeWebAuthContractPath"
}
& pwsh -NoLogo -NoProfile -File $runtimeWebAuthContractPath
$runtimeWebAuthContractExitCode = $LASTEXITCODE
if ($runtimeWebAuthContractExitCode -ne 0) {
    throw "Source-runtime Web auth contract test failed with exit code $runtimeWebAuthContractExitCode."
}

$personalProductionPublishProjects = @(
    [pscustomobject]@{
        Path = 'src\Ensou.Dsh.Bootstrapper\Ensou.Dsh.Bootstrapper.csproj'
        Target = 'ValidatePersonalStartupStubPublish'
    },
    [pscustomobject]@{
        Path = 'src\Ensou.Dsh.ClientBootstrapper\Ensou.Dsh.ClientBootstrapper.csproj'
        Target = 'ValidatePersonalClientBootstrapperPublish'
    },
    [pscustomobject]@{
        Path = 'src\Ensou.Dsh.Launcher\Ensou.Dsh.Launcher.csproj'
        Target = 'ValidatePersonalLauncherPublish'
    },
    [pscustomobject]@{
        Path = 'src\Ensou.Dsh.Personal.Installer\Ensou.Dsh.Personal.Installer.csproj'
        Target = 'ValidatePersonalInstallerPublish'
    },
    [pscustomobject]@{
        Path = 'src\Ensou.Dsh.Personal.Maintenance\Ensou.Dsh.Personal.Maintenance.csproj'
        Target = 'ValidatePersonalMaintenancePublish'
    }
)
foreach ($project in $personalProductionPublishProjects) {
    $projectPath = Join-Path $RepositoryRoot $project.Path
    $projectText = Get-Content -Raw -LiteralPath $projectPath
    $targetMatch = [regex]::Match(
        $projectText,
        '<Target\s+Name="' + [regex]::Escape($project.Target) + '"[^>]*>.*?</Target>',
        [Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $targetMatch.Success) {
        throw "Personal production publish validator is missing: $projectPath"
    }
    foreach ($required in @(
        'BeforeTargets="PrepareForPublish"',
        '!$([System.Text.RegularExpressions.Regex]::IsMatch(''$(PersonalCanonicalLowSFromSequence)'', ''^[1-9][0-9]{0,15}$''))',
        '$([System.Int64]::Parse(''$(PersonalCanonicalLowSFromSequence)'')) &gt; 9007199254740991'
    )) {
        if (-not $targetMatch.Value.Contains($required, [StringComparison]::Ordinal)) {
            throw "Personal production low-S publish validation is incomplete in $projectPath`: $required"
        }
    }
}

$publishValidationTargets = 0
foreach ($project in @(Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot 'src') `
        -Filter '*.csproj' -File -Recurse)) {
    $projectText = Get-Content -Raw -LiteralPath $project.FullName
    foreach ($match in [regex]::Matches(
            $projectText,
            '<Target\s+Name="Validate[^"]*Publish"[^>]*>')) {
        $publishValidationTargets++
        if (-not $match.Value.Contains(
                'BeforeTargets="PrepareForPublish"',
                [StringComparison]::Ordinal)) {
            throw "Publish validation can run after release files are copied: $($project.FullName)"
        }
    }
}
if ($publishValidationTargets -lt 14) {
    throw "Expected all 14 executable publish validators, found $publishValidationTargets."
}

$feedPromoterBundlePublisherPath = Join-Path $RepositoryRoot `
    'release\scripts\Publish-EnterpriseFeedPromoterProductionBundle.ps1'
$feedPromoterBundleTestPath = Join-Path $RepositoryRoot `
    'release\scripts\Test-EnterpriseFeedPromoterProductionBundle.ps1'
$feedPromoterBundleSchemaPath = Join-Path $RepositoryRoot `
    'release\schemas\enterprise-feed-promoter-production-bundle-v1.schema.json'
foreach ($requiredPath in @(
    $feedPromoterBundlePublisherPath,
    $feedPromoterBundleTestPath,
    $feedPromoterBundleSchemaPath
)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Enterprise FeedPromoter production bundle contract is missing: $requiredPath"
    }
}
$feedPromoterBundleSchemaText = Get-Content -Raw -LiteralPath `
    $feedPromoterBundleSchemaPath
if (-not (Test-Json -Json $feedPromoterBundleSchemaText -ErrorAction Stop)) {
    throw 'Enterprise FeedPromoter production bundle schema is not valid JSON.'
}
$feedPromoterBundlePublisherText = Get-Content -Raw -LiteralPath `
    $feedPromoterBundlePublisherPath
$feedPromoterBundleTestText = Get-Content -Raw -LiteralPath `
    $feedPromoterBundleTestPath
$enterpriseWorkflowPath = Join-Path $RepositoryRoot `
    '.github\workflows\enterprise-managed-release-v2.yml'
$enterpriseWorkflowText = Get-Content -Raw -LiteralPath $enterpriseWorkflowPath
foreach ($required in @(
    '[string]$ExpectedProductionTrustSha256',
    "'^[0-9a-f]{64}$'",
    'does not match the explicitly approved SHA-256',
    'environment -cne ''production''',
    'non-placeholder production DNS origin',
    '[StringComparer]::OrdinalIgnoreCase',
    'P-256 points must be globally unique',
    '[Security.Cryptography.ECDsa]::Create($parameters)',
    'canonical LF line endings without CR bytes',
    "'ensou-dsh-enterprise-feed-promoter'",
    "'enterprise-feed-production-trust.json'",
    "'enterprise-feed-promoter-production-bundle.v1.json'",
    "'SHA256SUMS'",
    '-p:EnterpriseFeedPromoterProductionBuild=true',
    '$publishLog = @(& dotnet publish',
    '$publishLog | Select-Object -Last 40',
    'ELF64 little-endian x86-64 PIE',
    '[IO.FileMode]::CreateNew',
    '[IO.Directory]::Move($stagingRoot, $outputFullPath)',
    'git -C $repository archive',
    'Test-Json -Json $manifestText -SchemaFile $schemaPath',
    '$trustInput.Bytes'
)) {
    if (-not $feedPromoterBundlePublisherText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Enterprise FeedPromoter production bundle publisher is missing: $required"
    }
}
foreach ($forbiddenGlobalPublishProperty in @(
    '--runtime linux-x64',
    '--self-contained true',
    '-p:PublishSingleFile=true')) {
    if ($feedPromoterBundlePublisherText.Contains(
            $forbiddenGlobalPublishProperty,
            [StringComparison]::Ordinal)) {
        throw "Enterprise FeedPromoter publisher propagates a production-only property into portable ProjectReferences: $forbiddenGlobalPublishProperty"
    }
}
$feedPromoterProjectText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.Enterprise.FeedPromoter\Ensou.Dsh.Enterprise.FeedPromoter.csproj')
foreach ($requiredProductionProfileControl in @(
    '<EnterpriseFeedPromoterProductionBuild Condition="''$(EnterpriseFeedPromoterProductionBuild)'' == ''''">false</EnterpriseFeedPromoterProductionBuild>',
    '<RuntimeIdentifier Condition="''$(EnterpriseFeedPromoterProductionBuild)'' == ''true''">linux-x64</RuntimeIdentifier>',
    '<SelfContained Condition="''$(EnterpriseFeedPromoterProductionBuild)'' == ''true''">true</SelfContained>',
    '<PublishSingleFile Condition="''$(EnterpriseFeedPromoterProductionBuild)'' == ''true''">true</PublishSingleFile>',
    '<Error Condition="''$(EnterpriseFeedPromoterProductionBuild)'' != ''true''"')) {
    if (-not $feedPromoterProjectText.Contains(
            $requiredProductionProfileControl,
            [StringComparison]::Ordinal)) {
        throw "Enterprise FeedPromoter production profile is incomplete: $requiredProductionProfileControl"
    }
}
if ($feedPromoterBundlePublisherText -match
        '(?i)SignData|ExportParameters\s*\(\s*\$true|private.?key|pkcs.?8|New-.*(?:Key|Trust)') {
    throw 'Enterprise FeedPromoter production bundle publisher must never create or package private signing material.'
}
foreach ($required in @(
    'mismatched expected trust hash',
    'uppercase expected trust hash',
    'development environment',
    'test origin',
    'invalid origin',
    'loopback origin',
    'placeholder key id',
    'cross-ring key id reuse',
    'cross-ring point reuse',
    'duplicate trust member',
    'CRLF trust',
    'hard-linked trust',
    'symbolic-linked trust',
    'exact four-file inventory',
    'exactly one canonical ELF executable',
    'existing bundle output',
    'unknown source commit',
    '$global:LASTEXITCODE = 0'
)) {
    if (-not $feedPromoterBundleTestText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Enterprise FeedPromoter production bundle regression is missing: $required"
    }
}
foreach ($required in @(
    'publish_feed_promoter_production_bundle:',
    'expected_production_trust_sha256:',
    'feed-promoter-production-contract:',
    'runs-on: ubuntu-latest',
    './release/scripts/Test-EnterpriseFeedPromoterProductionBundle.ps1',
    'feed-promoter-production-bundle:',
    "github.ref == 'refs/heads/main'",
    'environment: enterprise-feed-production-release',
    'ENSOU_ENTERPRISE_FEED_PRODUCTION_TRUST_BASE64',
    'Protected environment did not provide external production trust bytes.',
    '-ExpectedProductionTrustSha256 $env:EXPECTED_PRODUCTION_TRUST_SHA256',
    'actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f',
    'if-no-files-found: error',
    'compression-level: 0'
)) {
    if (-not $enterpriseWorkflowText.Contains(
            $required,
            [StringComparison]::Ordinal)) {
        throw "Enterprise FeedPromoter production workflow is missing: $required"
    }
}
$feedPromoterProductionJob = [Text.RegularExpressions.Regex]::Match(
    $enterpriseWorkflowText,
    '(?ms)^  feed-promoter-production-bundle:\r?\n(?<body>.*)\z')
$feedPromoterContractJob = [Text.RegularExpressions.Regex]::Match(
    $enterpriseWorkflowText,
    '(?ms)^  feed-promoter-production-contract:\r?\n(?<body>.*?)(?=^  feed-promoter-production-bundle:\r?$)')
if (-not $feedPromoterProductionJob.Success -or
    -not $feedPromoterContractJob.Success -or
    $feedPromoterContractJob.Groups['body'].Value.Contains(
        'actions/upload-artifact',
        [StringComparison]::Ordinal) -or
    [regex]::Matches(
        $feedPromoterProductionJob.Groups['body'].Value,
        [regex]::Escape('actions/upload-artifact@')).Count -ne 1 -or
    $feedPromoterProductionJob.Groups['body'].Value -match
        '(?i)SignData|GenerateKey|CreatePkcs8|private.?key') {
    throw 'Enterprise FeedPromoter contract fixtures must never reach the protected production upload job.'
}

$windowsPilotObserverPaths = @(
    'src\Ensou.Dsh.WindowsPilotObserver\Ensou.Dsh.WindowsPilotObserver.csproj',
    'src\Ensou.Dsh.WindowsPilotObserver\app.manifest',
    'src\Ensou.Dsh.WindowsPilotObserver\ObservationEngine.cs',
    'src\Ensou.Dsh.WindowsPilotObserver\ObservationSummaryVerifier.cs',
    'src\Ensou.Dsh.WindowsPilotObserver\PlatformEvidence.cs',
    'src\Ensou.Dsh.WindowsPilotObserver\EvidenceRelevancePolicy.cs',
    'src\Ensou.Dsh.WindowsPilotObserver\ObservationTiming.cs',
    'src\Ensou.Dsh.WindowsPilotObserver\WindowsEventHookCollector.cs',
    'src\Ensou.Dsh.WindowsPilotObserver\WindowsObservation.cs',
    'tests\Ensou.Dsh.WindowsPilotObserverTests\Ensou.Dsh.WindowsPilotObserverTests.csproj',
    'tests\Ensou.Dsh.WindowsPilotObserverTests\Program.cs',
    'tests\Ensou.Dsh.WindowsPilotObserverFixture\Ensou.Dsh.WindowsPilotObserverFixture.csproj',
    'tests\Ensou.Dsh.WindowsPilotObserverFixture\Program.cs',
    'release\schemas\windows-pilot-observation-plan-v1.schema.json',
    'release\schemas\windows-pilot-observation-summary-v1.schema.json',
    'docs\windows-pilot-observer.md'
)
foreach ($relativePath in $windowsPilotObserverPaths) {
    $observerPath = Join-Path $RepositoryRoot $relativePath
    if (-not (Test-Path -LiteralPath $observerPath -PathType Leaf)) {
        throw "Windows Pilot Observer contract file is missing: $relativePath"
    }
}

$observerProjectText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.WindowsPilotObserver\Ensou.Dsh.WindowsPilotObserver.csproj')
foreach ($required in @(
    '<OutputType>WinExe</OutputType>',
    '<TargetFramework>net10.0-windows</TargetFramework>',
    '<RuntimeIdentifier>win-x64</RuntimeIdentifier>',
    '<SelfContained>true</SelfContained>',
    '<PublishSingleFile>true</PublishSingleFile>',
    '<ApplicationManifest>app.manifest</ApplicationManifest>',
    'BeforeTargets="PrepareForPublish"',
    'AfterTargets="Publish"'
)) {
    if (-not $observerProjectText.Contains($required, [StringComparison]::Ordinal)) {
        throw "Windows Pilot Observer publish profile is incomplete: $required"
    }
}
if ($observerProjectText.Contains('<PackageReference', [StringComparison]::Ordinal)) {
    throw 'Windows Pilot Observer must not introduce a third-party package dependency.'
}

$observerManifestText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'src\Ensou.Dsh.WindowsPilotObserver\app.manifest')
if (-not $observerManifestText.Contains(
        '<requestedExecutionLevel level="asInvoker" uiAccess="false" />',
        [StringComparison]::Ordinal)) {
    throw 'Windows Pilot Observer must remain an asInvoker executable.'
}

$observerSourceText = @(Get-ChildItem -LiteralPath (Join-Path `
        $RepositoryRoot `
        'src\Ensou.Dsh.WindowsPilotObserver') -Filter '*.cs' -File) |
    ForEach-Object { Get-Content -Raw -LiteralPath $_.FullName } |
    Join-String -Separator "`n"
foreach ($required in @(
    'EventSystemForeground = 0x0003',
    'EventSystemDialogStart = 0x0010',
    'EventObjectCreate = 0x8000',
    'EventObjectShow = 0x8002',
    'SetWinEventHook(',
    'CreateToolhelp32Snapshot(',
    'LightweightIntervalMilliseconds = 250',
    'MinimumDurationSeconds = 900',
    'CreationTimeUtcFileTime',
    'StandaloneAdmissionEvidence = false',
    'ProcessTokenElevationType.Default or ProcessTokenElevationType.Limited',
    'integrityRid == MediumIntegrityRid',
    'PlatformEvidence.CaptureCurrent()',
    'ProductType == WorkstationProductType',
    'operatingSystemArchitecture == Architecture.X64',
    'ProcessMachine == ImageFileMachineUnknown',
    'CaptureFinalEnrichedSnapshot()',
    'final-enriched-snapshot',
    'ValidateRelevantCreationTimes(',
    'PROCESS_CREATION_TIME_UNAVAILABLE',
    'WINDOW_PROCESS_CREATION_TIME_UNAVAILABLE',
    'EvidenceRelevancePolicy',
    'ObservationSummaryVerifier.Validate(',
    'UNEXPECTED_WINDOW',
    'RECORDING_PROCESS_INTERRUPTED'
)) {
    if (-not $observerSourceText.Contains($required, [StringComparison]::Ordinal)) {
        throw "Windows Pilot Observer fail-closed implementation is incomplete: $required"
    }
}

$observerPlanSchemaPath = Join-Path `
    $RepositoryRoot `
    'release\schemas\windows-pilot-observation-plan-v1.schema.json'
$observerSummarySchemaPath = Join-Path `
    $RepositoryRoot `
    'release\schemas\windows-pilot-observation-summary-v1.schema.json'
$observerPlanSchemaText = Get-Content -Raw -LiteralPath $observerPlanSchemaPath
$observerSummarySchemaText = Get-Content -Raw -LiteralPath $observerSummarySchemaPath
foreach ($schemaText in @($observerPlanSchemaText, $observerSummarySchemaText)) {
    if (-not (Test-Json -Json $schemaText -ErrorAction Stop)) {
        throw 'Windows Pilot Observer schema is not valid JSON.'
    }
    $schema = $schemaText | ConvertFrom-Json -Depth 100
    if ($schema.type -cne 'object' -or $schema.additionalProperties -ne $false) {
        throw 'Windows Pilot Observer schema root must reject unknown properties.'
    }
}
$observerPlanSchema = $observerPlanSchemaText | ConvertFrom-Json -Depth 100
if ($observerPlanSchema.properties.minimumObservationSeconds.minimum -ne 900 -or
    $observerPlanSchema.properties.requiredActions.minItems -ne 9 -or
    $observerPlanSchema.properties.candidate.'$ref' -cne '#/$defs/candidate' -or
    $observerPlanSchema.'$defs'.candidate.additionalProperties -ne $false -or
    $observerPlanSchema.'$defs'.candidateFile.additionalProperties -ne $false -or
    $observerPlanSchema.'$defs'.recording.additionalProperties -ne $false) {
    throw 'Windows Pilot Observer plan schema lost strict duration, action, candidate, or recording constraints.'
}
$observerSummarySchema = $observerSummarySchemaText | ConvertFrom-Json -Depth 100
$observerSummaryPropertyNames = @(
    $observerSummarySchema.properties.PSObject.Properties.Name)
if ($observerSummarySchema.properties.standaloneAdmissionEvidence.const -ne $false -or
    $observerSummarySchema.'$defs'.executionIdentity.additionalProperties -ne $false -or
    $observerSummarySchema.'$defs'.executionIdentity.properties.integrityRid.const -ne 8192 -or
    $observerSummarySchema.'$defs'.platform.additionalProperties -ne $false -or
    $observerSummarySchema.'$defs'.platform.properties.workstation.const -ne $true -or
    $observerSummarySchema.'$defs'.platform.properties.processArchitecture.const -cne 'x64' -or
    $observerSummarySchema.'$defs'.platform.properties.operatingSystemArchitecture.const -cne 'x64' -or
    $observerSummarySchema.'$defs'.platform.properties.processMachine.const -cne 'native' -or
    $observerSummarySchema.'$defs'.platform.properties.nativeMachine.const -cne 'amd64' -or
    $observerSummarySchema.'$defs'.recording.additionalProperties -ne $false -or
    -not ($observerSummarySchema.required -ccontains 'platform') -or
    @($observerSummarySchema.allOf).Count -lt 1 -or
    $observerSummaryPropertyNames -ccontains 'path' -or
    $observerSummaryPropertyNames -ccontains 'windowTitle') {
    throw 'Windows Pilot Observer public summary schema lost non-admission or privacy constraints.'
}
$eligibleThen = @($observerSummarySchema.allOf) |
    Where-Object { $_.'if'.properties.verdict.const -ceq 'ELIGIBLE_FOR_REVIEW' } |
    Select-Object -First 1
if ($null -eq $eligibleThen -or
    $eligibleThen.then.properties.monotonicDurationMilliseconds.minimum -ne 900000 -or
    $eligibleThen.then.properties.reasonCodes.maxItems -ne 0 -or
    $eligibleThen.then.properties.actions.minItems -ne 9 -or
    $eligibleThen.then.properties.unexpectedWindows.maxItems -ne 0) {
    throw 'Windows Pilot Observer summary schema lost ELIGIBLE_FOR_REVIEW conditional invariants.'
}
$eligibleSamplingRules = @($eligibleThen.then.properties.sampling.allOf)[1].properties
$eligibleCandidateRules = @($eligibleThen.then.properties.candidate.allOf)[1].properties.files
$eligibleCandidateItemRules = @($eligibleCandidateRules.prefixItems)
$eligibleRecordingRules = @($eligibleThen.then.properties.recording.allOf)[1].properties
if ($eligibleSamplingRules.lightweightCount.minimum -ne 1 -or
    $eligibleSamplingRules.fullCount.minimum -ne 1 -or
    $eligibleSamplingRules.maximumFullGapMilliseconds.maximum -ne 1000 -or
    $eligibleSamplingRules.lostEventCount.const -ne 0 -or
    $eligibleCandidateRules.minItems -ne 7 -or
    $eligibleCandidateRules.maxItems -ne 7 -or
    $eligibleCandidateItemRules.Count -ne 7 -or
    @($eligibleCandidateItemRules | Where-Object {
        $_.properties.sizeBytes.minimum -ne 1 -or
        $_.properties.observed.const -ne $true -or
        -not ($_.required -ccontains 'sizeBytes') -or
        -not ($_.required -ccontains 'observed')
    }).Count -ne 0 -or
    $eligibleRecordingRules.sizeBytes.minimum -ne 1 -or
    $eligibleRecordingRules.observationCoverageMilliseconds.minimum -ne 900000) {
    throw 'Windows Pilot Observer eligible sampling, candidate, or recording schema gate is incomplete.'
}

$observerTestsText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    'tests\Ensou.Dsh.WindowsPilotObserverTests\Program.cs')
foreach ($required in @(
    'strict plan rejects unknown duplicate and reordered content',
    'medium unelevated administrator-account tokens are accepted',
    'medium-plus integrity RID 0x2100 is rejected',
    'only native x64 Windows workstations are accepted',
    'preflight time is excluded and boundary gaps are strict',
    'hash-chain evidence is create-only and verifiable',
    'short console and error windows are unexpected',
    'only candidate recorder and suspicious evidence is persistent',
    'relevant zero creation times are unusable',
    'eligible summaries enforce every runtime admission invariant',
    'summary schema conditionally gates eligible evidence',
    'fixture is build-only and never launched by tests'
)) {
    if (-not $observerTestsText.Contains($required, [StringComparison]::Ordinal)) {
        throw "Windows Pilot Observer regression is missing: $required"
    }
}
if ($observerTestsText.Contains('Process.Start(', [StringComparison]::Ordinal)) {
    throw 'Windows Pilot Observer CI tests must never launch the GUI fixture.'
}

$observerCiText = Get-Content -Raw -LiteralPath (Join-Path `
    $RepositoryRoot `
    '.github\workflows\ci.yml')
if (-not $observerCiText.Contains(
        'Ensou.Dsh.WindowsPilotObserverTests.csproj',
        [StringComparison]::Ordinal) -or
    -not $observerCiText.Contains('--no-restore', [StringComparison]::Ordinal)) {
    throw 'Windows Pilot Observer non-GUI CI regression is not wired.'
}

Write-Host 'Release contract validation passed.'
