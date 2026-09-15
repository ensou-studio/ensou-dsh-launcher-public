#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$lockPath = Join-Path $repositoryRoot 'versions\locked.json'
$indexPath = Join-Path $repositoryRoot 'upstream-patches\index.json'
$directLocalIndexPath = Join-Path $repositoryRoot 'upstream-patches\direct-local-index.v1.json'
$modulePath = Join-Path $PSScriptRoot 'ManagedSourcePatch.psm1'

Import-Module $modulePath -Force -DisableNameChecking

$releaseSecurityPath = Join-Path $repositoryRoot 'security\README.md'
$releaseSecurityText = Get-Content -Raw -LiteralPath $releaseSecurityPath
foreach ($requiredReleasePrerequisite in @(
    'The repository **must have GitHub Immutable Releases enabled**',
    'the release chain does not rely on tag rulesets; they are not a prerequisite',
    'permanently consumes only the create-once `release_id`',
    'artifact-bearing immutable Release is a separate later gate')) {
    if (-not $releaseSecurityText.Contains(
            $requiredReleasePrerequisite,
            [StringComparison]::Ordinal)) {
        throw "Release repository prerequisite documentation is missing: $requiredReleasePrerequisite"
    }
}

function Assert-ReviewedRuntimeWebAuthPair(
    [string]$Tag,
    [string]$Protocol
) {
    $reviewedPairs = @{
        'dsh-v0.1.1-rc.2' = 'legacy-clean-root-v1'
        'dsh-v0.1.2-alpha.3' = 'browser-launch-cookie-v1'
        'dsh-v0.1.2-rc.1' = 'browser-launch-cookie-v1'
    }
    if (-not $reviewedPairs.ContainsKey($Tag) -or
        [string]$reviewedPairs[$Tag] -cne $Protocol) {
        throw 'The locked upstream tag and runtimeWebAuthProtocol are not a reviewed pair.'
    }
}

$lock = Get-ManagedSourceLock $lockPath
if ([int]$lock.schemaVersion -ne 4 -or [string]$lock.buildMode -cne 'official-source') {
    throw 'versions/locked.json must use managed source lock schema v4.'
}
$lockedWebAuthProtocol = [string]$lock.runtimeWebAuthProtocol
Assert-ReviewedRuntimeWebAuthPair `
    -Tag ([string]$lock.officialTag) `
    -Protocol $lockedWebAuthProtocol
foreach ($rejectedPair in @(
    [pscustomobject]@{ Tag = 'dsh-v0.1.1-rc.2'; Protocol = 'browser-launch-cookie-v1' },
    [pscustomobject]@{ Tag = 'dsh-v0.1.2-alpha.3'; Protocol = 'legacy-clean-root-v1' },
    [pscustomobject]@{ Tag = 'dsh-v0.1.2-rc.1'; Protocol = 'legacy-clean-root-v1' },
    [pscustomobject]@{ Tag = 'dsh-v0.1.2-alpha.2'; Protocol = 'legacy-clean-root-v1' })) {
    $rejected = $false
    try {
        Assert-ReviewedRuntimeWebAuthPair `
            -Tag $rejectedPair.Tag `
            -Protocol $rejectedPair.Protocol
    } catch {
        if ($_.Exception.Message -eq
            'The locked upstream tag and runtimeWebAuthProtocol are not a reviewed pair.') {
            $rejected = $true
        } else {
            throw
        }
    }
    if (-not $rejected) {
        throw "Unreviewed runtime Web auth pair was accepted: $($rejectedPair.Tag) / $($rejectedPair.Protocol)"
    }
}
foreach ($property in @('officialCommit', 'officialTree')) {
    if ([string]$lock.$property -cnotmatch '^[0-9a-f]{40}$') {
        throw "Locked $property is not a lowercase full Git object id."
    }
}
foreach ($property in @('baseLockfileSha256', 'lockfileSha256')) {
    if ([string]$lock.$property -cnotmatch '^[0-9a-f]{64}$') {
        throw "Locked $property is not a lowercase SHA-256."
    }
}

$bundle = Get-ManagedSourcePatchBundle `
    -IndexPath $indexPath `
    -Repository 'https://github.com/deepseek-ai/deepseek-harness.git' `
    -Tag ([string]$lock.officialTag) `
    -Commit ([string]$lock.officialCommit) `
    -Tree ([string]$lock.officialTree)
if ($bundle.Id -cnotmatch '-enterprise-managed-v1$') {
    throw 'The omitted patch variant no longer selects the legacy enterprise-managed-v1 bundle.'
}
if ($bundle.Id -cne [string]$lock.managedPatch.id -or
    $bundle.ManifestSha256 -cne [string]$lock.managedPatch.manifestSha256 -or
    $bundle.PatchSha256 -cne [string]$lock.managedPatch.patchSha256) {
    throw 'versions/locked.json does not match the indexed managed patch bytes.'
}
Assert-CanonicalManagedPatchBytes ([IO.File]::ReadAllBytes($bundle.PatchPath))
if ([string]$lock.officialTag -in @('dsh-v0.1.2-alpha.3', 'dsh-v0.1.2-rc.1')) {
    $modernPatchText = [IO.File]::ReadAllText($bundle.PatchPath)
    foreach ($requiredModernPolicyAssertion in @(
        "expect(row(composed, 'session-persistence-jsonl').disabled).not.toBe(true)",
        "expect(row(composed, 'session-query-sqlite').config).toEqual({ path: ':memory:', openAt: 'never' })",
        "expect(composed.rows.has('session-persistence-sqlite')).toBe(false)")) {
        if (-not $modernPatchText.Contains(
                $requiredModernPolicyAssertion,
                [StringComparison]::Ordinal)) {
            throw "Modern managed patch does not pin the reviewed JSONL/no-persistent-SQLite policy: $requiredModernPolicyAssertion"
        }
    }
    $modernReadme = [IO.File]::ReadAllText((Join-Path $bundle.Directory 'README.md'))
    foreach ($requiredUpgradeGateText in @(
        'The managed composition uses session-persistence-jsonl.',
        'automatic upgrade must stop',
        'does not claim or implement automatic SQLite-to-JSONL migration')) {
        if (-not $modernReadme.Contains(
                $requiredUpgradeGateText,
                [StringComparison]::Ordinal)) {
            throw "Modern local-data upgrade gate is missing: $requiredUpgradeGateText"
        }
    }
}

$directLocalBundle = Get-ManagedSourcePatchBundle `
    -IndexPath $directLocalIndexPath `
    -Repository 'https://github.com/deepseek-ai/deepseek-harness.git' `
    -Tag 'dsh-v0.1.2-rc.1' `
    -Commit 'a66e4702047846cdaa10c66c9d3df3951f5ea70d' `
    -Tree '27ab636bb3d77e698f5637e518db44ae1f61e262' `
    -PatchVariant 'enterprise-direct-local-v1'
if ($directLocalBundle.Id -cne 'dsh-v0.1.2-rc.1-enterprise-direct-local-v1' -or
    $directLocalBundle.ManifestSha256 -cne '977ebb374bf9449e34daa7b0ef393a06b2c862d944200abb69a30434a2597cf0' -or
    $directLocalBundle.PatchSha256 -cne '7f10ec9492b399cede422428013b0c77bc932699fa3a14fa7ced158454272b6f' -or
    [int64](Get-Item -LiteralPath $directLocalBundle.PatchPath).Length -ne [int64]415878 -or
    $directLocalBundle.Files.Count -ne 112 -or $directLocalBundle.Changes.Count -ne 112) {
    throw 'The explicit enterprise direct-local bundle is not the exact frozen 112-path candidate.'
}
if ([string]$directLocalBundle.Manifest.schema -cne 'ensou.dsh.upstream-patch-manifest.v4' -or
    [string]$directLocalBundle.Manifest.patchVariant -cne 'enterprise-direct-local-v1' -or
    [string]$directLocalBundle.Manifest.managedPolicy.profile -cne 'enterprise-direct-local' -or
    [string]$directLocalBundle.Manifest.managedPolicy.modelBaseUrl -cne 'https://api.deepseek.com' -or
    [string]$directLocalBundle.Manifest.managedPolicy.searchBaseUrl -cne 'https://api.deepseek.com/anthropic/v1' -or
    [string]$directLocalBundle.Manifest.managedPolicy.credentialEnvironment -cne 'DEEPSEEK_API_KEY' -or
    $directLocalBundle.Manifest.managedPolicy.PSObject.Properties.Name -contains 'gatewayAllowedModel' -or
    $directLocalBundle.Manifest.managedPolicy.PSObject.Properties.Name -contains 'gatewayMaxTokens') {
    throw 'The enterprise direct-local manifest does not describe its exact official-provider credential policy.'
}
$directPatchedLock = $directLocalBundle.FilesByPath['pnpm-lock.yaml']
if ([string]$directPatchedLock.sha256 -cne '07974704247ec18915df8fdf117c682bba2d861aafe7059ea4bca4aab1677080' -or
    [string]$directPatchedLock.gitBlob -cne '68ad6b76b1577112091beaa532667ac02ddcbccf' -or
    [int64]$directPatchedLock.bytes -ne [int64]743966) {
    throw 'The enterprise direct-local patched lockfile identity changed.'
}

$legacyDefaultRejectedDirectIndex = $false
try {
    Get-ManagedSourcePatchBundle `
        -IndexPath $directLocalIndexPath `
        -Repository 'https://github.com/deepseek-ai/deepseek-harness.git' `
        -Tag 'dsh-v0.1.2-rc.1' `
        -Commit 'a66e4702047846cdaa10c66c9d3df3951f5ea70d' `
        -Tree '27ab636bb3d77e698f5637e518db44ae1f61e262' | Out-Null
} catch {
    if ($_.Exception.Message -eq 'Unsupported managed patch index schema: ensou.dsh.upstream-patch-index.v2') {
        $legacyDefaultRejectedDirectIndex = $true
    } else {
        throw
    }
}
if (-not $legacyDefaultRejectedDirectIndex) {
    throw 'The legacy default silently accepted the explicit direct-local index.'
}

$directVariantRejectedLegacyIndex = $false
try {
    Get-ManagedSourcePatchBundle `
        -IndexPath $indexPath `
        -Repository 'https://github.com/deepseek-ai/deepseek-harness.git' `
        -Tag 'dsh-v0.1.2-rc.1' `
        -Commit 'a66e4702047846cdaa10c66c9d3df3951f5ea70d' `
        -Tree '27ab636bb3d77e698f5637e518db44ae1f61e262' `
        -PatchVariant 'enterprise-direct-local-v1' | Out-Null
} catch {
    if ($_.Exception.Message -eq 'Unsupported managed patch index schema: ensou.dsh.upstream-patch-index.v1') {
        $directVariantRejectedLegacyIndex = $true
    } else {
        throw
    }
}
if (-not $directVariantRejectedLegacyIndex) {
    throw 'The explicit direct-local selector accepted the legacy managed index.'
}

$directVariantRejectedWrongBase = $false
try {
    Get-ManagedSourcePatchBundle `
        -IndexPath $directLocalIndexPath `
        -Repository 'https://github.com/deepseek-ai/deepseek-harness.git' `
        -Tag 'dsh-v0.1.2-alpha.3' `
        -Commit 'dd6322d604e00eec1ba5e0c8541159906a21094a' `
        -Tree '86be9091c78528b5ef0866ae6d58b01d4a53582e' `
        -PatchVariant 'enterprise-direct-local-v1' | Out-Null
} catch {
    if ($_.Exception.Message -like 'No unique reviewed managed patch matches exact repository/tag/commit/tree/variant*') {
        $directVariantRejectedWrongBase = $true
    } else {
        throw
    }
}
if (-not $directVariantRejectedWrongBase) {
    throw 'The enterprise direct-local variant was admitted for an unapproved upstream base.'
}
$dirtyPatchRejected = $false
try {
    Assert-CanonicalManagedPatchBytes (
        [Text.Encoding]::UTF8.GetBytes("diff --git a/a b/a`n@@ -0,0 +1 @@`n+ `n"))
} catch {
    if ($_.Exception.Message -eq 'Managed patch contains trailing horizontal whitespace.') {
        $dirtyPatchRejected = $true
    } else {
        throw
    }
}
if (-not $dirtyPatchRejected) { throw 'Managed patch trailing whitespace did not fail closed.' }
$patchedLock = $bundle.FilesByPath['pnpm-lock.yaml']
$baseLock = $bundle.ChangesByPath['pnpm-lock.yaml'].preimage
if ([string]$patchedLock.sha256 -cne [string]$lock.lockfileSha256 -or
    [string]$baseLock.sha256 -cne [string]$lock.baseLockfileSha256) {
    throw 'Locked base/patched pnpm lockfile digests do not match the patch manifest.'
}

$unknownBaseRejected = $false
try {
    Get-ManagedSourcePatchBundle `
        -IndexPath $indexPath `
        -Repository 'https://github.com/deepseek-ai/deepseek-harness.git' `
        -Tag ([string]$lock.officialTag) `
        -Commit ([string]$lock.officialCommit) `
        -Tree ('0' * 40) | Out-Null
} catch {
    if ($_.Exception.Message -like 'No unique reviewed managed patch matches exact*') {
        $unknownBaseRejected = $true
    } else {
        throw
    }
}
if (-not $unknownBaseRejected) { throw 'Unknown upstream tree did not fail closed.' }

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'ensou-managed-patch-contract-' + [guid]::NewGuid().ToString('N'))
try {
    [IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
    $lockText = [IO.File]::ReadAllText($lockPath)
    $lockedProtocolJson = ConvertTo-Json -InputObject ([string]$lock.runtimeWebAuthProtocol) -Compress
    $lockedTagJson = ConvertTo-Json -InputObject ([string]$lock.officialTag) -Compress
    $lockedCommitJson = ConvertTo-Json -InputObject ([string]$lock.officialCommit) -Compress
    $protocolMember = '"runtimeWebAuthProtocol": ' + $lockedProtocolJson
    $tagMember = '"officialTag": ' + $lockedTagJson + ','
    $commitMember = '"officialCommit": ' + $lockedCommitJson + ','
    $lockMutations = @(
        [pscustomobject]@{
            Name = 'string-schema-version'
            Text = $lockText.Replace(
                '"schemaVersion": 4',
                '"schemaVersion": "4"',
                [StringComparison]::Ordinal)
        },
        [pscustomobject]@{
            Name = 'array-runtime-web-auth-protocol'
            Text = $lockText.Replace(
                $protocolMember,
                '"runtimeWebAuthProtocol": [' + $lockedProtocolJson + ']',
                [StringComparison]::Ordinal)
        },
        [pscustomobject]@{
            Name = 'duplicate-official-tag'
            Text = $lockText.Replace(
                $tagMember,
                $tagMember + "`n  " + $tagMember,
                [StringComparison]::Ordinal)
        },
        [pscustomobject]@{
            Name = 'unknown-official-tag'
            Text = $lockText.Replace(
                $tagMember,
                '"officialTag": "dsh-v9.9.9-unknown.1",',
                [StringComparison]::Ordinal)
        },
        [pscustomobject]@{
            Name = 'unknown-official-commit'
            Text = $lockText.Replace(
                $commitMember,
                '"officialCommit": "0000000000000000000000000000000000000000",',
                [StringComparison]::Ordinal)
        })
    foreach ($mutation in $lockMutations) {
        if ($mutation.Text -ceq $lockText) {
            throw "Managed source lock mutation was not constructed: $($mutation.Name)"
        }
        $mutatedLockPath = Join-Path $temporaryRoot "$($mutation.Name).json"
        [IO.File]::WriteAllText(
            $mutatedLockPath,
            $mutation.Text,
            [Text.UTF8Encoding]::new($false))
        $mutationRejected = $false
        try {
            Get-ManagedSourceLock $mutatedLockPath | Out-Null
        } catch {
            $mutationRejected = $true
        }
        if (-not $mutationRejected) {
            throw "Managed source lock accepted invalid JSON types or members: $($mutation.Name)"
        }
    }

    $approvedSourceTuples = @(
        [pscustomobject]@{
            Tag = 'dsh-v0.1.1-rc.2'
            Commit = 'b150a551b8d465e31e418e1b2eaf5e79bbb7d28e'
            Tree = '53915efe4e2126cc7779b73dfc8a3bcec5318c44'
            DshVersion = '0.1.1-rc.2'
            Protocol = 'legacy-clean-root-v1'
            BaseLockfileSha256 = '6f20c268e76df1294c16f016ab10a7fa1271608b4db0f4fafe8f7c21ec90013e'
        },
        [pscustomobject]@{
            Tag = 'dsh-v0.1.2-alpha.3'
            Commit = 'dd6322d604e00eec1ba5e0c8541159906a21094a'
            Tree = '86be9091c78528b5ef0866ae6d58b01d4a53582e'
            DshVersion = '0.1.2-alpha.3'
            Protocol = 'browser-launch-cookie-v1'
            BaseLockfileSha256 = '17bbd38216e31a8b821957f77d2e3f57b859046cc3a18076ad16e94ca952a8da'
        },
        [pscustomobject]@{
            Tag = 'dsh-v0.1.2-rc.1'
            Commit = 'a66e4702047846cdaa10c66c9d3df3951f5ea70d'
            Tree = '27ab636bb3d77e698f5637e518db44ae1f61e262'
            DshVersion = '0.1.2-rc.1'
            Protocol = 'browser-launch-cookie-v1'
            BaseLockfileSha256 = 'e12083149a77f790d39b64d018b6b8745c6a7aa95777ecb73e0a2f5ed5fdd0d9'
        })
    foreach ($tuple in $approvedSourceTuples) {
        $candidate = $lockText | ConvertFrom-Json -Depth 64
        $candidate.officialTag = $tuple.Tag
        $candidate.officialCommit = $tuple.Commit
        $candidate.officialTree = $tuple.Tree
        $candidate.dshVersion = $tuple.DshVersion
        $candidate.runtimeWebAuthProtocol = $tuple.Protocol
        $candidate.baseLockfileSha256 = $tuple.BaseLockfileSha256
        $candidatePath = Join-Path $temporaryRoot ("approved-$($tuple.DshVersion).json")
        [IO.File]::WriteAllText(
            $candidatePath,
            ($candidate | ConvertTo-Json -Depth 64),
            [Text.UTF8Encoding]::new($false))
        $parsedCandidate = Get-ManagedSourceLock $candidatePath
        if ([string]$parsedCandidate.officialTag -cne [string]$tuple.Tag -or
            [string]$parsedCandidate.officialCommit -cne [string]$tuple.Commit) {
            throw "Exact approved managed source tuple did not round-trip: $($tuple.Tag)"
        }
    }

    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'upstream-patches') `
        -Destination (Join-Path $temporaryRoot 'upstream-patches') -Recurse
    $relativePatch = [IO.Path]::GetRelativePath($repositoryRoot, $bundle.PatchPath)
    $temporaryPatch = Join-Path $temporaryRoot $relativePatch
    $stream = [IO.File]::Open($temporaryPatch, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $first = $stream.ReadByte()
        $stream.Position = 0
        $stream.WriteByte($first -bxor 1)
    } finally {
        $stream.Dispose()
    }
    $tamperRejected = $false
    try {
        Get-ManagedSourcePatchBundle `
            -IndexPath (Join-Path $temporaryRoot 'upstream-patches\index.json') `
            -Repository 'https://github.com/deepseek-ai/deepseek-harness.git' `
            -Tag ([string]$lock.officialTag) `
            -Commit ([string]$lock.officialCommit) `
            -Tree ([string]$lock.officialTree) | Out-Null
    } catch {
        if ($_.Exception.Message -like 'Managed patch SHA-256 mismatch*') {
            $tamperRejected = $true
        } else {
            throw
        }
    }
    if (-not $tamperRejected) { throw 'Tampered managed patch bytes did not fail closed.' }
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

$builderPath = Join-Path $PSScriptRoot 'build-source-runtime.ps1'
$builderText = Get-Content -Raw -LiteralPath $builderPath
if ($builderText -match 'Push-Location\s+\$officialCheckout' -or
    $builderText.IndexOf('Apply-ManagedSourcePatch', [StringComparison]::Ordinal) -gt
        $builderText.IndexOf("@('install', '--frozen-lockfile')", [StringComparison]::Ordinal) -or
    $builderText -notmatch 'Copy-Item -LiteralPath \$officialGitDirectory' -or
    $builderText -notmatch 'Invoke-OfficialGitCaptured @\(''ls-files''\)' -or
    $builderText -notmatch 'Assert-NoBuildToolingInRuntime') {
    throw 'Source builder isolation or runtime build-input exclusion contract regressed.'
}

$generatorPath = Join-Path $PSScriptRoot 'New-ManagedSourcePatchBundle.ps1'
$generatorText = Get-Content -Raw -LiteralPath $generatorPath
if ($generatorText -notmatch "'--unified=0'" -or
    $generatorText -notmatch "'--binary', '--full-index'" -or
    $generatorText -notmatch 'StructuralEqualityComparer' -or
    $generatorText -notmatch '\[IO\.Directory\]::Move\(\$staging, \$Output\)') {
    throw 'Managed patch deterministic zero-context generator contract regressed.'
}
foreach ($exactAlphaLiteral in @(
    'dsh-v0.1.2-alpha.3',
    'dd6322d604e00eec1ba5e0c8541159906a21094a',
    '86be9091c78528b5ef0866ae6d58b01d4a53582e',
    '17bbd38216e31a8b821957f77d2e3f57b859046cc3a18076ad16e94ca952a8da',
    '51de950c3e3c9dcdf118206888d05e8b3fba9ed5')) {
    if (-not $generatorText.Contains($exactAlphaLiteral, [StringComparison]::Ordinal)) {
        throw "Managed patch generator lost exact alpha base identity: $exactAlphaLiteral"
    }
}
foreach ($exactRc1Literal in @(
    'dsh-v0.1.2-rc.1',
    'a66e4702047846cdaa10c66c9d3df3951f5ea70d',
    '27ab636bb3d77e698f5637e518db44ae1f61e262',
    'e12083149a77f790d39b64d018b6b8745c6a7aa95777ecb73e0a2f5ed5fdd0d9',
    '4521b1bbf42de10ad2c19e85523b56661d19d8f7')) {
    if (-not $generatorText.Contains($exactRc1Literal, [StringComparison]::Ordinal)) {
        throw "Managed patch generator lost exact rc.1 base identity: $exactRc1Literal"
    }
}
foreach ($exactDirectLocalLiteral in @(
    'enterprise-direct-local-v1',
    '7f10ec9492b399cede422428013b0c77bc932699fa3a14fa7ced158454272b6f',
    '07974704247ec18915df8fdf117c682bba2d861aafe7059ea4bca4aab1677080',
    '68ad6b76b1577112091beaa532667ac02ddcbccf',
    'https://api.deepseek.com',
    'https://api.deepseek.com/anthropic/v1',
    '@deepseek-ai/dsh-credentials-local writable local credential store')) {
    if (-not $generatorText.Contains($exactDirectLocalLiteral, [StringComparison]::Ordinal)) {
        throw "Managed patch generator lost exact direct-local identity or policy: $exactDirectLocalLiteral"
    }
}
$unknownGeneratorBaseRejected = $false
try {
    & $generatorPath `
        -PatchedCheckout $repositoryRoot `
        -OutputDirectory (Join-Path ([IO.Path]::GetTempPath()) (
            'ensou-rejected-managed-patch-' + [guid]::NewGuid().ToString('N'))) `
        -BaseTag 'dsh-v9.9.9-unknown.1' `
        -BaseCommit ('0' * 40) | Out-Null
} catch {
    if ($_.Exception.Message -like 'Base tag/commit is not an exact approved managed source base:*') {
        $unknownGeneratorBaseRejected = $true
    } else {
        throw
    }
}
if (-not $unknownGeneratorBaseRejected) {
    throw 'Managed patch generator accepted an unknown base tag/commit.'
}
$directGeneratorWrongBaseRejected = $false
try {
    & $generatorPath `
        -PatchedCheckout $repositoryRoot `
        -OutputDirectory (Join-Path ([IO.Path]::GetTempPath()) (
            'ensou-rejected-direct-local-patch-' + [guid]::NewGuid().ToString('N'))) `
        -BaseTag 'dsh-v0.1.2-alpha.3' `
        -BaseCommit 'dd6322d604e00eec1ba5e0c8541159906a21094a' `
        -PatchVariant 'enterprise-direct-local-v1' | Out-Null
} catch {
    if ($_.Exception.Message -like 'Patch variant enterprise-direct-local-v1 is not approved for base*') {
        $directGeneratorWrongBaseRejected = $true
    } else {
        throw
    }
}
if (-not $directGeneratorWrongBaseRejected) {
    throw 'Managed patch generator accepted the direct-local variant for an unapproved base.'
}
if ($builderText -notmatch "'--unidiff-zero'" -and
    (Get-Content -Raw -LiteralPath $modulePath) -notmatch "'--unidiff-zero'") {
    throw 'Managed patch zero-context apply contract regressed.'
}

Write-Host 'Managed source patch contract passed: legacy-default isolation, explicit direct-local selection, exact canonical bundles, deterministic generator, lock coupling, unknown-base refusal, and tamper refusal.' -ForegroundColor Green
