#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
. (Join-Path $PSScriptRoot 'EnterpriseDevelopmentRuntimeAdmission.ps1')

if (-not $IsWindows) {
    Write-Host 'SKIP  Enterprise Development runtime locked-file contract requires Windows.'
    return
}

function Assert-Rejected {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Label
    )

    try {
        & $Action
    }
    catch {
        return
    }
    throw "Enterprise Development runtime admission accepted negative: $Label"
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )

    $Value | ConvertTo-Json -Depth 64 | Set-Content `
        -LiteralPath $Path `
        -Encoding utf8NoBOM
}

function New-RuntimeFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Name,
        [string]$MetadataReleaseId = 'managed-v2026.08.25.1',
        [string]$SourceReleaseId = 'managed-v2026.08.25.1',
        [bool]$MetadataPromotionEligible = $true,
        [bool]$SourcePromotionEligible = $true,
        [string]$SourceTag,
        [string]$SourceCommit,
        [string]$SourceArtifactType,
        [string]$HashManifestSourceBuildSha256,
        [int64]$SourceRuntimeClosurePackageCount = -1,
        [switch]$AddUnknownSourceMember,
        [switch]$EnterpriseDirectLocal
    )

    $metadata = Get-Content `
        -LiteralPath (Join-Path $repositoryRoot 'release\examples\source-runtime.metadata.json') `
        -Raw | ConvertFrom-Json -Depth 64
    $metadata.releaseId = $MetadataReleaseId
    $metadata.promotionEligible = $MetadataPromotionEligible
    $directSmoke = [ordered]@{
        status = 'PASS'
        resultStatus = 'PASS'
        scope = 'BUILT_ENTERPRISE_DIRECT_LOCAL_RUNTIME_CAPABILITY_ONLY'
        cycles = 2
        kernelBootstrapVerified = $true
        settingsReadOnly = $true
        credentialsWritable = $true
        exactChildExited = $true
        authenticationNegativesVerified = $true
        launchRefusalsVerified = $true
        modelRequestsSent = 0
        outputBytes = 1024
    }
    if ($EnterpriseDirectLocal) {
        $metadata.schemaVersion = 3
        $metadata.artifactType = 'ensou-dsh-enterprise-direct-local-source-runtime'
        $metadata.lockfileSha256 = '07974704247ec18915df8fdf117c682bba2d861aafe7059ea4bca4aab1677080'
        $metadata.managedPatch = [pscustomobject][ordered]@{
            id = 'dsh-v0.1.2-rc.1-enterprise-direct-local-v1'
            manifestSchema = 'ensou.dsh.upstream-patch-manifest.v4'
            manifestSha256 = '977ebb374bf9449e34daa7b0ef393a06b2c862d944200abb69a30434a2597cf0'
            patchSha256 = '7f10ec9492b399cede422428013b0c77bc932699fa3a14fa7ced158454272b6f'
            patchBytes = 415878
            changedFileCount = 112
            modifiedPreimageCount = 86
        }
        $metadata.managedPolicy = [pscustomobject][ordered]@{
            signal = 'DSH_ENTERPRISE_MANAGED_BOOT=ensou-dsh-launcher/v1'
            profile = 'enterprise-direct-local'
            webArguments = '--host 127.0.0.1 --port <canonical 1..65535>'
            model = 'deepseek-v4-flash'
            maxTokens = 8192
            modelBaseUrl = 'https://api.deepseek.com'
            searchBaseUrl = 'https://api.deepseek.com/anthropic/v1'
            credentialEnvironment = 'DEEPSEEK_API_KEY'
            credentialSource = '@deepseek-ai/dsh-credentials-local writable local credential store'
            launchEnvironmentProviderOverrides = @(
                'DEEPSEEK_BASE_URL', 'DEEPSEEK_SEARCH_BASE_URL', 'DEEPSEEK_API_KEY')
            settingsProvider = '@deepseek-ai/dsh-settings-file/composition-only'
            managedSkillsRootEnvironment = 'ENSOU_DSH_ENTERPRISE_SKILLS_ROOT'
            sandboxMode = 'workspace-write'
            sandboxMaximumMode = 'workspace-write'
            approvalPolicy = 'ask'
            permissionPresets = @('workspace-write')
            workspaceRootSource = 'process.cwd()'
            restoredSessionCwdPolicy = 'must-equal-workspace-root'
            hostCompositionCanonicalSha256 = 'cad7cdf7f1b13f1892a2b857e3f628de71579ab4bef89f3b97ac0fed03cc25ba'
            presetCompositionCanonicalSha256 = 'e3c01ae98d9bf12e57e3ba270169f7059e3b098615e21b4db11fd377367ea546'
            presetMetadataCanonicalSha256 = '3590423cb2fb8809c0d11b18dec12f9e1df370a4f05dc93fff1c54e82abc75be'
            loaderRootCanonicalSha256 = '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'
            pluginResolutionPolicy = 'frozen exact installation map from managed base/web bundles; no ambient fallback'
        }
        $metadata | Add-Member -NotePropertyName runtimeProfile `
            -NotePropertyValue 'enterprise-direct-local'
        $metadata | Add-Member -NotePropertyName managedUpdateProtocol `
            -NotePropertyValue 'enterprise-direct-local-v1'
        $metadata.verification | Add-Member -NotePropertyName directLocalAssembledSmoke `
            -NotePropertyValue ([pscustomobject]$directSmoke)
        $metadata.verification | Add-Member -NotePropertyName directLocalExtractedSmoke `
            -NotePropertyValue ([pscustomobject]$directSmoke)
    }
    $archivePath = Join-Path $Root "$Name.zip"
    $metadataPath = Join-Path $Root "$Name.metadata.json"
    $sourceBuild = [ordered]@{
        schemaVersion = if ($EnterpriseDirectLocal) { 4 } else { 3 }
        sourceBuilt = $true
        releaseId = $SourceReleaseId
        promotionEligible = $SourcePromotionEligible
        artifactType = if ($SourceArtifactType) { $SourceArtifactType } else { [string]$metadata.artifactType }
        sourceIdentity = [string]$metadata.sourceIdentity
        sourceRepository = [string]$metadata.sourceRepository
        sourceTag = if ($SourceTag) { $SourceTag } else { [string]$metadata.sourceTag }
        sourceCommit = if ($SourceCommit) { $SourceCommit } else { [string]$metadata.sourceCommit }
        sourceTree = [string]$metadata.sourceTree
        runtimeWebAuthProtocol = [string]$metadata.runtimeWebAuthProtocol
        remoteTagVerified = [bool]$metadata.verification.remoteTagCommitMatch
        tagSignatureVerified = [bool]$metadata.verification.tagSignatureVerified
        dshVersion = [string]$metadata.dshVersion
        platform = [string]$metadata.platform
        baseLockfileSha256 = [string]$metadata.baseLockfileSha256
        lockfileSha256 = [string]$metadata.lockfileSha256
        managedPatch = $metadata.managedPatch
        managedPolicy = $metadata.managedPolicy
        nodeVersion = [string]$metadata.toolchain.nodeVersion
        nodeSha256 = [string]$metadata.toolchain.nodeSha256
        pnpmVersion = [string]$metadata.toolchain.pnpmVersion
        npmVersion = [string]$metadata.toolchain.npmVersion
        buildPipeline = 'installation-owned-isolated-managed-source-v1'
        deploymentMode = [string]$metadata.verification.deploymentMode
        restoredWorkspacePeerCount = 0
        restoredWorkspacePeers = @()
        normalizedSourceRegionCommentCount = 1
        normalizedBinShimTargetCommentCount = 1
        runtimeClosurePackageCount = if ($SourceRuntimeClosurePackageCount -ge 0) {
            $SourceRuntimeClosurePackageCount
        }
        else {
            [long]$metadata.verification.runtimeClosurePackageCount
        }
        runtimeClosureAgainstPinnedSourceAndLock =
            [bool]$metadata.verification.runtimeClosureAgainstPinnedSourceAndLock
        assembledRuntimeSmoke = [bool]$metadata.verification.extractedArtifactSmoke
        managedFocusedTests = [bool]$metadata.verification.managedFocusedTests
        managedWindowsExcludedFocusedTests =
            [bool]$metadata.verification.managedWindowsExcludedFocusedTests
        managedRefusalSmoke = [bool]$metadata.verification.managedRefusalSmoke
        officialCheckoutUnchanged = [bool]$metadata.verification.officialCheckoutUnchanged
        builtAtUtc = $metadata.builtAtUtc.ToString(
            'o',
            [Globalization.CultureInfo]::InvariantCulture)
        licensing = [ordered]@{
            harnessLicense = [string]$metadata.licensing.harnessLicense
            includedFiles = @(
                'LICENSE',
                'THIRD_PARTY_NOTICES.md',
                'RUNTIME_DEPENDENCY_LICENSES.json')
            organizationReviewRequired =
                [bool]$metadata.licensing.organizationReviewRequired
        }
    }
    if ($AddUnknownSourceMember) {
        $sourceBuild['unexpectedSourceMember'] = 'must-be-rejected'
    }
    if ($EnterpriseDirectLocal) {
        $sourceBuild['runtimeProfile'] = 'enterprise-direct-local'
        $sourceBuild['managedUpdateProtocol'] = 'enterprise-direct-local-v1'
        $sourceBuild['directLocalRuntimeSmoke'] = $directSmoke
    }
    $sourceBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($sourceBuild | ConvertTo-Json -Depth 64))
    $sourceSha256 = ([Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($sourceBytes))).ToLowerInvariant()
    $archive = [IO.Compression.ZipFile]::Open(
        $archivePath,
        [IO.Compression.ZipArchiveMode]::Create)
    try {
        $entry = $archive.CreateEntry('source-build.json')
        $stream = $entry.Open()
        try {
            $stream.Write($sourceBytes, 0, $sourceBytes.Length)
        }
        finally {
            $stream.Dispose()
        }
        $marker = $archive.CreateEntry('fixture.txt')
        $markerStream = $marker.Open()
        try {
            $markerStream.WriteByte(0x31)
        }
        finally {
            $markerStream.Dispose()
        }
        $hashManifest = $archive.CreateEntry('runtime-files.sha256')
        $hashManifestStream = $hashManifest.Open()
        try {
            $manifestSourceSha256 = if ($HashManifestSourceBuildSha256) {
                $HashManifestSourceBuildSha256
            }
            else {
                $sourceSha256
            }
            $hashManifestBytes = [Text.Encoding]::ASCII.GetBytes(
                "$manifestSourceSha256  source-build.json`n")
            $hashManifestStream.Write(
                $hashManifestBytes,
                0,
                $hashManifestBytes.Length)
        }
        finally {
            $hashManifestStream.Dispose()
        }
    }
    finally {
        $archive.Dispose()
    }
    $metadata.artifact.fileName = [IO.Path]::GetFileName($archivePath)
    $metadata.artifact.sizeBytes = (Get-Item -LiteralPath $archivePath).Length
    $metadata.artifact.sha256 =
        (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-JsonFile -Path $metadataPath -Value $metadata
    return [pscustomobject]@{
        ArchivePath = $archivePath
        MetadataPath = $metadataPath
        ReleaseId = $MetadataReleaseId
        FileName = [string]$metadata.artifact.fileName
        SizeBytes = [int64]$metadata.artifact.sizeBytes
        Sha256 = [string]$metadata.artifact.sha256
    }
}

function Open-FixtureEvidence {
    param(
        [Parameter(Mandatory = $true)]$Fixture,
        [switch]$AllowLocalLab,
        [switch]$EnterpriseDirectLocal
    )

    $leases = [Collections.Generic.List[IDisposable]]::new()
    try {
        $metadataSchemaPath = if ($EnterpriseDirectLocal) {
            Join-Path $repositoryRoot `
                'release\schemas\enterprise-development-direct-local-runtime-metadata.schema.json'
        }
        else {
            Join-Path $repositoryRoot `
                'release\schemas\enterprise-development-runtime-metadata.schema.json'
        }
        $evidence = Read-EnterpriseDevelopmentRuntimeEvidence `
            -ArchivePath $Fixture.ArchivePath `
            -MetadataPath $Fixture.MetadataPath `
            -MetadataSchemaPath $metadataSchemaPath `
            -ExpectedReleaseId $Fixture.ReleaseId `
            -ExpectedArchiveFileName $Fixture.FileName `
            -ExpectedArchiveSha256 $Fixture.Sha256 `
            -AllowLocalLab:$AllowLocalLab `
            -EnterpriseDirectLocal:$EnterpriseDirectLocal `
            -Leases $leases
        return [pscustomobject]@{ Evidence = $evidence; Leases = $leases }
    }
    catch {
        foreach ($lease in $leases) { $lease.Dispose() }
        throw
    }
}

function Test-Candidate22SchemaOnlyTuple {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$SchemaPath
    )

    $examplePath = Join-Path $repositoryRoot 'release\examples\source-runtime.metadata.json'
    $base = Get-Content -LiteralPath $examplePath -Raw | ConvertFrom-Json -Depth 64
    if (-not (Test-Json -Json ($base | ConvertTo-Json -Depth 64) -SchemaFile $SchemaPath -ErrorAction Stop)) {
        throw 'Schema-only regression rejected the existing production example metadata.'
    }
    $candidate = $base | ConvertTo-Json -Depth 64 | ConvertFrom-Json -Depth 64
    $candidate.releaseId = 'lab-rc1-candidate22-20260911-13'
    $candidate.promotionEligible = $false
    $candidate.lockfileSha256 = '8f7056e679f38165b9f48fc3a3ba31920ea1edca28e796a73327007737a7e3f5'
    $candidate.managedPatch.id = 'dsh-v0.1.2-rc.1-candidate22-local-lab'
    $candidate.managedPatch.manifestSchema = 'ensou.dsh.upstream-patch-manifest.v3'
    $candidate.managedPatch.manifestSha256 = 'f83a73bbe7df7d5c218e3d26442a9f2dc84b5ea6f60a0131d078b2a20138b6d2'
    $candidate.managedPatch.patchSha256 = '9d11c88037161763f81a69e7c05d411c3711b7b53395c5f537cb6de752795372'
    $candidate.managedPatch.patchBytes = 675934
    $candidate.managedPatch.changedFileCount = 185
    $candidate.managedPatch.modifiedPreimageCount = 153
    $candidate.artifact.fileName = 'EnsouDshRuntime-lab-rc1-candidate22-20260911-13-win-x64.zip'
    $candidate.artifact.sizeBytes = 104413259
    $candidate.artifact.sha256 = 'b2afef17bbbfe86225a4738e6adcf7b6085bf09a016446f15e4dce730c67ee78'

    $candidatePath = Join-Path $Root 'candidate22-schema-only.metadata.json'
    Write-JsonFile -Path $candidatePath -Value $candidate
    $candidateJson = Get-Content -LiteralPath $candidatePath -Raw
    if (-not (Test-Json -Json $candidateJson -SchemaFile $SchemaPath -ErrorAction Stop)) {
        throw 'Schema-only Candidate22 Lab metadata tuple was rejected.'
    }

    $assertSchemaRejected = {
        param([string]$Name, [scriptblock]$Mutate)
        $negative = $candidate | ConvertTo-Json -Depth 64 | ConvertFrom-Json -Depth 64
        & $Mutate $negative
        $negativePath = Join-Path $Root ("candidate22-schema-only-$Name.metadata.json")
        Write-JsonFile -Path $negativePath -Value $negative
        if (Test-Json -Json (Get-Content -LiteralPath $negativePath -Raw) -SchemaFile $SchemaPath -ErrorAction SilentlyContinue) {
            throw "Schema-only Candidate22 negative was accepted: $Name"
        }
    }
    & $assertSchemaRejected 'promotion-true-lab-tuple' {
        param($value) $value.promotionEligible = $true
    }
    & $assertSchemaRejected 'managed-release-lab-tuple' {
        param($value) $value.releaseId = 'managed-v2026.09.11.1'
    }
    & $assertSchemaRejected 'unknown-lab-release' {
        param($value) $value.releaseId = 'lab-unknown-candidate'
    }
    & $assertSchemaRejected 'old-lock-new-patch' {
        param($value) $value.lockfileSha256 = '0cc4aba6915e0221cf65f806c5ab932849137d5aa4f8f8d129afd6501b8bef7f'
    }
    & $assertSchemaRejected 'unknown-patch' {
        param($value) $value.managedPatch.id = 'dsh-v0.1.2-rc.1-candidate22-unknown'
    }
    & $assertSchemaRejected 'unknown-patch-hash' {
        param($value) $value.managedPatch.patchSha256 = ('0' * 64)
    }
    & $assertSchemaRejected 'wrong-patch-size' {
        param($value) $value.managedPatch.patchBytes = 675935
    }
    & $assertSchemaRejected 'wrong-archive-hash' {
        param($value) $value.artifact.sha256 = ('0' * 64)
    }
    & $assertSchemaRejected 'wrong-archive-size' {
        param($value) $value.artifact.sizeBytes = 104413260
    }
    & $assertSchemaRejected 'wrong-archive-name' {
        param($value) $value.artifact.fileName = 'another-runtime.zip'
    }
    $target = $candidate | ConvertTo-Json -Depth 64 | ConvertFrom-Json -Depth 64
    $target.releaseId = 'lab-rc1-candidate22-20260911-15'
    $target.artifact.fileName = 'EnsouDshRuntime-lab-rc1-candidate22-20260911-15-win-x64.zip'
    $target.artifact.sizeBytes = 104413343
    $target.artifact.sha256 = 'f93859a807c9858a0aa5c40375763548348cb180beeb3f83ebb1b8bc59f09f8f'
    if (-not (Test-Json -Json ($target | ConvertTo-Json -Depth 64) -SchemaFile $SchemaPath -ErrorAction Stop)) {
        throw 'Schema-only independently rebuilt Candidate22 target tuple was rejected.'
    }
    foreach ($tuple in @($candidate, $target)) {
        $other = if ($tuple.releaseId -ceq $candidate.releaseId) { $target } else { $candidate }
        foreach ($field in @('releaseId', 'fileName', 'sizeBytes', 'sha256', 'promotionEligible')) {
            $mixed = $tuple | ConvertTo-Json -Depth 64 | ConvertFrom-Json -Depth 64
            if ($field -ceq 'releaseId') { $mixed.releaseId = $other.releaseId }
            elseif ($field -ceq 'promotionEligible') { $mixed.promotionEligible = $true }
            else { $mixed.artifact.$field = $other.artifact.$field }
            if (Test-Json -Json ($mixed | ConvertTo-Json -Depth 64) -SchemaFile $SchemaPath -ErrorAction SilentlyContinue) {
                throw "Schema-only exact Lab tuple allowed cross-mixing or promotion: $field"
            }
        }
    }
    Write-Host 'PASS  Candidate22 schema-only Lab tuples: existing production contract, two exact Lab builds, ten original negatives and ten cross-tuple/non-promotion negatives.'
}

$testId = [Guid]::NewGuid().ToString('N')
$testRoot = Join-Path ([IO.Path]::GetTempPath()) "ensou-dsh-runtime-admission-$testId"
[IO.Directory]::CreateDirectory($testRoot) | Out-Null
try {
    $valid = New-RuntimeFixture -Root $testRoot -Name 'valid-runtime'
    Test-Candidate22SchemaOnlyTuple `
        -Root $testRoot `
        -SchemaPath (Join-Path $repositoryRoot 'release\schemas\enterprise-development-runtime-metadata.schema.json')
    $locked = Open-FixtureEvidence -Fixture $valid
    try {
        if ($locked.Evidence.ReleaseId -cne $valid.ReleaseId -or
            $locked.Evidence.ArchiveSizeBytes -ne $valid.SizeBytes -or
            $locked.Evidence.ArchiveSha256 -cne $valid.Sha256) {
            throw 'Valid runtime fixture did not preserve its exact identity tuple.'
        }
        Assert-EnterpriseDevelopmentRuntimeEvidenceUnchanged -Evidence $locked.Evidence
        Assert-Rejected -Label 'locked archive overwrite' -Action {
            [IO.File]::Open(
                $valid.ArchivePath,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Write,
                [IO.FileShare]::Read).Dispose()
        }
        Assert-Rejected -Label 'locked metadata overwrite' -Action {
            [IO.File]::Open(
                $valid.MetadataPath,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Write,
                [IO.FileShare]::Read).Dispose()
        }
    }
    finally {
        foreach ($lease in $locked.Leases) { $lease.Dispose() }
    }

    $direct = New-RuntimeFixture -Root $testRoot -Name 'valid-direct-runtime' `
        -EnterpriseDirectLocal
    $openedDirect = Open-FixtureEvidence -Fixture $direct -EnterpriseDirectLocal
    try {
        if ($openedDirect.Evidence.RuntimeMode -cne 'enterprise-direct-local') {
            throw 'Direct-local fixture lost its explicit selected runtime mode.'
        }
    }
    finally {
        foreach ($lease in $openedDirect.Leases) { $lease.Dispose() }
    }
    Assert-Rejected -Label 'direct metadata in legacy mode' -Action {
        $opened = Open-FixtureEvidence -Fixture $direct
        foreach ($lease in $opened.Leases) { $lease.Dispose() }
    }
    Assert-Rejected -Label 'legacy metadata in direct mode' -Action {
        $opened = Open-FixtureEvidence -Fixture $valid -EnterpriseDirectLocal
        foreach ($lease in $opened.Leases) { $lease.Dispose() }
    }
    $wrongDirectProfileMetadata = Get-Content -LiteralPath $direct.MetadataPath -Raw |
        ConvertFrom-Json -Depth 64
    $wrongDirectProfileMetadata.runtimeProfile = 'enterprise-managed'
    $wrongDirectProfilePath = Join-Path $testRoot 'wrong-direct-profile.metadata.json'
    Write-JsonFile -Path $wrongDirectProfilePath -Value $wrongDirectProfileMetadata
    $wrongDirectProfile = [pscustomobject]@{
        ArchivePath = $direct.ArchivePath
        MetadataPath = $wrongDirectProfilePath
        ReleaseId = $direct.ReleaseId
        FileName = $direct.FileName
        Sha256 = $direct.Sha256
    }
    Assert-Rejected -Label 'direct metadata wrong runtime profile' -Action {
        $opened = Open-FixtureEvidence -Fixture $wrongDirectProfile -EnterpriseDirectLocal
        foreach ($lease in $opened.Leases) { $lease.Dispose() }
    }
    $badDirectReceipt = Get-Content -LiteralPath $direct.MetadataPath -Raw |
        ConvertFrom-Json -Depth 64
    $badDirectReceipt.verification.directLocalExtractedSmoke.cycles = 1
    $badDirectReceiptPath = Join-Path $testRoot 'bad-direct-receipt.metadata.json'
    Write-JsonFile -Path $badDirectReceiptPath -Value $badDirectReceipt
    $badDirect = [pscustomobject]@{
        ArchivePath = $direct.ArchivePath
        MetadataPath = $badDirectReceiptPath
        ReleaseId = $direct.ReleaseId
        FileName = $direct.FileName
        Sha256 = $direct.Sha256
    }
    Assert-Rejected -Label 'direct metadata invalid extracted smoke receipt' -Action {
        $opened = Open-FixtureEvidence -Fixture $badDirect -EnterpriseDirectLocal
        foreach ($lease in $opened.Leases) { $lease.Dispose() }
    }

    $localLab = New-RuntimeFixture `
        -Root $testRoot `
        -Name 'local-lab-runtime' `
        -MetadataReleaseId 'lab-enterprise-development-e2e' `
        -SourceReleaseId 'lab-enterprise-development-e2e' `
        -MetadataPromotionEligible:$false `
        -SourcePromotionEligible:$false
    Assert-Rejected -Label 'local Lab runtime without explicit switch' -Action {
        $opened = Open-FixtureEvidence -Fixture $localLab
        foreach ($lease in $opened.Leases) { $lease.Dispose() }
    }
    $openedLab = Open-FixtureEvidence -Fixture $localLab -AllowLocalLab
    try {
        if ($openedLab.Evidence.ReleaseId -cne $localLab.ReleaseId -or
            $openedLab.Evidence.PromotionEligible -ne $false) {
            throw 'Explicit Enterprise Development Lab admission lost its non-promotable identity.'
        }
    }
    finally {
        foreach ($lease in $openedLab.Leases) { $lease.Dispose() }
    }

    $sourceEligibilityMismatch = New-RuntimeFixture `
        -Root $testRoot `
        -Name 'source-eligibility-mismatch' `
        -SourcePromotionEligible:$false
    Assert-Rejected -Label 'ZIP source promotion eligibility mismatch' -Action {
        $opened = Open-FixtureEvidence -Fixture $sourceEligibilityMismatch
        foreach ($lease in $opened.Leases) { $lease.Dispose() }
    }
    $managedFalse = New-RuntimeFixture `
        -Root $testRoot `
        -Name 'managed-false-eligibility' `
        -MetadataPromotionEligible:$false `
        -SourcePromotionEligible:$false
    Assert-Rejected -Label 'false eligibility with managed releaseId' -Action {
        $opened = Open-FixtureEvidence -Fixture $managedFalse -AllowLocalLab
        foreach ($lease in $opened.Leases) { $lease.Dispose() }
    }

    $releaseMismatch = New-RuntimeFixture `
        -Root $testRoot `
        -Name 'release-mismatch' `
        -SourceReleaseId 'managed-v2026.08.25.2'
    Assert-Rejected -Label 'ZIP source releaseId mismatch' -Action {
        $opened = Open-FixtureEvidence -Fixture $releaseMismatch
        foreach ($lease in $opened.Leases) { $lease.Dispose() }
    }
    $tagMismatch = New-RuntimeFixture `
        -Root $testRoot `
        -Name 'tag-mismatch' `
        -SourceTag 'dsh-v9.9.9'
    Assert-Rejected -Label 'ZIP sourceTag mismatch' -Action {
        $opened = Open-FixtureEvidence -Fixture $tagMismatch
        foreach ($lease in $opened.Leases) { $lease.Dispose() }
    }
    $commitMismatch = New-RuntimeFixture `
        -Root $testRoot `
        -Name 'commit-mismatch' `
        -SourceCommit ('1' * 40)
    Assert-Rejected -Label 'ZIP sourceCommit mismatch' -Action {
        $opened = Open-FixtureEvidence -Fixture $commitMismatch
        foreach ($lease in $opened.Leases) { $lease.Dispose() }
    }
    $artifactTypeMismatch = New-RuntimeFixture `
        -Root $testRoot `
        -Name 'artifact-type-mismatch' `
        -SourceArtifactType 'different-runtime-type'
    Assert-Rejected -Label 'ZIP artifact type mismatch' -Action {
        $opened = Open-FixtureEvidence -Fixture $artifactTypeMismatch
        foreach ($lease in $opened.Leases) { $lease.Dispose() }
    }
    $unknownSourceMember = New-RuntimeFixture `
        -Root $testRoot `
        -Name 'source-unknown-member' `
        -AddUnknownSourceMember
    Assert-Rejected -Label 'ZIP source-build unknown member' -Action {
        $opened = Open-FixtureEvidence -Fixture $unknownSourceMember
        foreach ($lease in $opened.Leases) { $lease.Dispose() }
    }
    $provenanceMismatch = New-RuntimeFixture `
        -Root $testRoot `
        -Name 'source-provenance-mismatch' `
        -SourceRuntimeClosurePackageCount 539
    Assert-Rejected -Label 'ZIP source-build provenance mismatch' -Action {
        $opened = Open-FixtureEvidence -Fixture $provenanceMismatch
        foreach ($lease in $opened.Leases) { $lease.Dispose() }
    }
    $manifestDigestMismatch = New-RuntimeFixture `
        -Root $testRoot `
        -Name 'runtime-files-digest-mismatch' `
        -HashManifestSourceBuildSha256 ('0' * 64)
    Assert-Rejected -Label 'runtime-files source-build digest mismatch' -Action {
        $opened = Open-FixtureEvidence -Fixture $manifestDigestMismatch
        foreach ($lease in $opened.Leases) { $lease.Dispose() }
    }

    Assert-Rejected -Label 'explicit releaseId mismatch' -Action {
        $leases = [Collections.Generic.List[IDisposable]]::new()
        try {
            Read-EnterpriseDevelopmentRuntimeEvidence `
                -ArchivePath $valid.ArchivePath `
                -MetadataPath $valid.MetadataPath `
                -MetadataSchemaPath (Join-Path $repositoryRoot 'release\schemas\enterprise-development-runtime-metadata.schema.json') `
                -ExpectedReleaseId 'managed-v2026.08.25.2' `
                -ExpectedArchiveFileName $valid.FileName `
                -ExpectedArchiveSha256 $valid.Sha256 `
                -Leases $leases | Out-Null
        }
        finally {
            foreach ($lease in $leases) { $lease.Dispose() }
        }
    }

    $repackedArchive = Join-Path $testRoot 'repacked-runtime.zip'
    Copy-Item -LiteralPath $valid.ArchivePath -Destination $repackedArchive
    $archive = [IO.Compression.ZipFile]::Open(
        $repackedArchive,
        [IO.Compression.ZipArchiveMode]::Update)
    try {
        $entry = $archive.CreateEntry('repacked.txt')
        $stream = $entry.Open()
        try { $stream.WriteByte(0x32) } finally { $stream.Dispose() }
    }
    finally {
        $archive.Dispose()
    }
    $repackedMetadata = Get-Content -LiteralPath $valid.MetadataPath -Raw |
        ConvertFrom-Json -Depth 64
    $repackedMetadata.artifact.fileName = [IO.Path]::GetFileName($repackedArchive)
    $repackedMetadataPath = Join-Path $testRoot 'repacked-runtime.metadata.json'
    Write-JsonFile -Path $repackedMetadataPath -Value $repackedMetadata
    $repacked = [pscustomobject]@{
        ArchivePath = $repackedArchive
        MetadataPath = $repackedMetadataPath
        ReleaseId = $valid.ReleaseId
        FileName = [IO.Path]::GetFileName($repackedArchive)
        Sha256 = $valid.Sha256
    }
    Assert-Rejected -Label 'repacked archive bytes' -Action {
        $opened = Open-FixtureEvidence -Fixture $repacked
        foreach ($lease in $opened.Leases) { $lease.Dispose() }
    }

    $tamperedMetadata = Get-Content -LiteralPath $valid.MetadataPath -Raw |
        ConvertFrom-Json -Depth 64
    $tamperedMetadata | Add-Member -NotePropertyName unexpected -NotePropertyValue $true
    $tamperedMetadataPath = Join-Path $testRoot 'tampered-shape.metadata.json'
    Write-JsonFile -Path $tamperedMetadataPath -Value $tamperedMetadata
    $tampered = [pscustomobject]@{
        ArchivePath = $valid.ArchivePath
        MetadataPath = $tamperedMetadataPath
        ReleaseId = $valid.ReleaseId
        FileName = $valid.FileName
        Sha256 = $valid.Sha256
    }
    Assert-Rejected -Label 'metadata unexpected member' -Action {
        $opened = Open-FixtureEvidence -Fixture $tampered
        foreach ($lease in $opened.Leases) { $lease.Dispose() }
    }
    $tamperedType = Get-Content -LiteralPath $valid.MetadataPath -Raw |
        ConvertFrom-Json -Depth 64
    $tamperedType.schemaVersion = '1'
    $tamperedTypePath = Join-Path $testRoot 'tampered-type.metadata.json'
    Write-JsonFile -Path $tamperedTypePath -Value $tamperedType
    $tampered.MetadataPath = $tamperedTypePath
    Assert-Rejected -Label 'metadata type coercion' -Action {
        $opened = Open-FixtureEvidence -Fixture $tampered
        foreach ($lease in $opened.Leases) { $lease.Dispose() }
    }
    $tamperedDigest = Get-Content -LiteralPath $valid.MetadataPath -Raw |
        ConvertFrom-Json -Depth 64
    $tamperedDigest.artifact.sha256 = '0' * 64
    $tamperedDigestPath = Join-Path $testRoot 'tampered-digest.metadata.json'
    Write-JsonFile -Path $tamperedDigestPath -Value $tamperedDigest
    $tampered.MetadataPath = $tamperedDigestPath
    Assert-Rejected -Label 'metadata archive digest tamper' -Action {
        $opened = Open-FixtureEvidence -Fixture $tampered
        foreach ($lease in $opened.Leases) { $lease.Dispose() }
    }

    $hardLinkPath = Join-Path $testRoot 'hard-linked-runtime.zip'
    New-Item -ItemType HardLink -Path $hardLinkPath -Target $valid.ArchivePath | Out-Null
    try {
        $hardLinkMetadata = Get-Content -LiteralPath $valid.MetadataPath -Raw |
            ConvertFrom-Json -Depth 64
        $hardLinkMetadata.artifact.fileName = [IO.Path]::GetFileName($hardLinkPath)
        $hardLinkMetadataPath = Join-Path $testRoot 'hard-linked-runtime.metadata.json'
        Write-JsonFile -Path $hardLinkMetadataPath -Value $hardLinkMetadata
        $hardLinked = [pscustomobject]@{
            ArchivePath = $hardLinkPath
            MetadataPath = $hardLinkMetadataPath
            ReleaseId = $valid.ReleaseId
            FileName = [IO.Path]::GetFileName($hardLinkPath)
            Sha256 = $valid.Sha256
        }
        Assert-Rejected -Label 'multi-link runtime archive' -Action {
            $opened = Open-FixtureEvidence -Fixture $hardLinked
            foreach ($lease in $opened.Leases) { $lease.Dispose() }
        }
    }
    finally {
        Remove-Item -LiteralPath $hardLinkPath -Force
    }

    $policyId = '70000000-0000-4000-8000-000000000003'
    $policyBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        '{"schemaVersion":1,"policyId":"70000000-0000-4000-8000-000000000003","generation":1,"compatibility":{"launcherReleaseIds":["launcher-development-e2e-v1"],"runtimeReleaseIds":["managed-v2026.08.25.1"]},"revoked":false,"critical":false}')
    Assert-EnterpriseDevelopmentPluginRuntimeCompatibility `
        -MetadataLauncherReleaseIds @('launcher-development-e2e-v1') `
        -MetadataRuntimeReleaseIds @('managed-v2026.08.25.1') `
        -PolicyBytes $policyBytes `
        -ExpectedRuntimeReleaseId 'managed-v2026.08.25.1' `
        -ExpectedPolicyId $policyId `
        -ExpectedGeneration 1 `
        -ExpectedCritical $false `
        -ExpectedRevoked $false
    Assert-Rejected -Label 'plugin compatibility runtime mismatch' -Action {
        Assert-EnterpriseDevelopmentPluginRuntimeCompatibility `
            -MetadataLauncherReleaseIds @('launcher-development-e2e-v1') `
            -MetadataRuntimeReleaseIds @('managed-v2026.08.25.1') `
            -PolicyBytes $policyBytes `
            -ExpectedRuntimeReleaseId 'managed-v2026.08.25.3' `
            -ExpectedPolicyId $policyId `
            -ExpectedGeneration 1 `
            -ExpectedCritical $false `
            -ExpectedRevoked $false
    }
    Assert-Rejected -Label 'plugin compatibility launcher mismatch' -Action {
        Assert-EnterpriseDevelopmentPluginRuntimeCompatibility `
            -MetadataLauncherReleaseIds @('launcher-other-v1') `
            -MetadataRuntimeReleaseIds @('managed-v2026.08.25.1') `
            -PolicyBytes $policyBytes `
            -ExpectedRuntimeReleaseId 'managed-v2026.08.25.1' `
            -ExpectedPolicyId $policyId `
            -ExpectedGeneration 1 `
            -ExpectedCritical $false `
            -ExpectedRevoked $false
    }
    Assert-Rejected -Label 'plugin raw policy identity mismatch' -Action {
        Assert-EnterpriseDevelopmentPluginRuntimeCompatibility `
            -MetadataLauncherReleaseIds @('launcher-development-e2e-v1') `
            -MetadataRuntimeReleaseIds @('managed-v2026.08.25.1') `
            -PolicyBytes $policyBytes `
            -ExpectedRuntimeReleaseId 'managed-v2026.08.25.1' `
            -ExpectedPolicyId $policyId `
            -ExpectedGeneration 2 `
            -ExpectedCritical $false `
            -ExpectedRevoked $false
    }

    Write-Host 'PASS  Enterprise Development runtime admission: exact legacy/direct selection, metadata/source provenance, locked bytes, repack/tamper/single-link and plugin compatibility negatives.'
}
finally {
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $expectedPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
        [IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolved) -cne "ensou-dsh-runtime-admission-$testId") {
        throw "Refusing to clean unexpected runtime admission test root: $resolved"
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
