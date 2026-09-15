#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PatchedCheckout,

    [Parameter(Mandatory)]
    [string]$OutputDirectory,

    [Parameter(Mandatory)]
    [string]$BaseTag,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$BaseCommit,

    [ValidateSet('enterprise-managed-v1', 'enterprise-direct-local-v1')]
    [string]$PatchVariant = 'enterprise-managed-v1',

    [string]$Git = 'git'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$CanonicalRepository = 'https://github.com/deepseek-ai/deepseek-harness.git'
$PatchFileName = if ($PatchVariant -ceq 'enterprise-direct-local-v1') {
    '0001-ensou-enterprise-direct-local.patch'
} else {
    '0001-ensou-enterprise-managed-boot.patch'
}
$Rc2ExpectedPaths = [string[]]@(
    '.agents/notes/implemented/architecture/2026-08-24-launcher-owned-managed-composition.i18n.yaml'
    '.agents/notes/implemented/architecture/2026-08-24-launcher-owned-managed-composition.md'
    '.agents/notes/implemented/architecture/2026-08-24-launcher-owned-managed-composition.zh.md'
    'apps/cli/config/managed-agent-presets/enterprise/agent.cordis.yml'
    'apps/cli/config/managed-agent-presets/enterprise/preset.yml'
    'apps/cli/config/managed-profile/cordis.yml'
    'apps/cli/src/bin.ts'
    'apps/cli/src/managed-boot.ts'
    'apps/cli/src/profile-boot.ts'
    'apps/cli/tests/managed-boot.spec.ts'
    'docs/config-catalog.i18n.yaml'
    'docs/config-catalog.md'
    'docs/config-catalog.zh.md'
    'docs/subsystems/sandbox.i18n.yaml'
    'docs/subsystems/sandbox.md'
    'docs/subsystems/sandbox.zh.md'
    'packages/boot/app-boot/README.i18n.yaml'
    'packages/boot/app-boot/README.md'
    'packages/boot/app-boot/README.zh.md'
    'packages/boot/app-boot/src/index.ts'
    'packages/boot/app-boot/tests/app-boot.spec.ts'
    'packages/extensions/tool-cordis/src/api-catalog.ts'
    'packages/fs/tool-fs/package.json'
    'packages/fs/tool-fs/src/sandbox.ts'
    'packages/fs/tool-fs/tests/tools.spec.ts'
    'packages/preset/agent-presets/src/mount.ts'
    'packages/preset/agent-presets/tests/mount.spec.ts'
    'packages/sandbox/sandbox-policy/README.i18n.yaml'
    'packages/sandbox/sandbox-policy/README.md'
    'packages/sandbox/sandbox-policy/README.zh.md'
    'packages/sandbox/sandbox-policy/package.json'
    'packages/sandbox/sandbox-policy/src/index.ts'
    'packages/sandbox/sandbox-policy/tests/policy.spec.ts'
    'packages/shell/tool-bash/src/index.ts'
    'packages/shell/tool-bash/tests/tools.spec.ts'
    'packages/shell/tool-pwsh/package.json'
    'packages/shell/tool-pwsh/src/index.ts'
    'packages/shell/tool-pwsh/tests/tools.spec.ts'
    'packages/terminal/terminal-bash/tests/index.spec.ts'
    'pnpm-lock.yaml'
    'scripts/gen-cordis-catalog.ts'
)
$AlphaExpectedPaths = [string[]]@(
    $Rc2ExpectedPaths + @(
        'apps/cli/package.json'
        'packages/terminal/terminal-bash/src/index.ts'
    )
)
[Array]::Sort($AlphaExpectedPaths, [StringComparer]::Ordinal)
$DirectLocalExpectedPaths = [string[]]@(
    $AlphaExpectedPaths + @(
        '.agents/notes/implemented/architecture/2026-09-14-composition-settings-with-local-credentials.i18n.yaml'
        '.agents/notes/implemented/architecture/2026-09-14-composition-settings-with-local-credentials.md'
        '.agents/notes/implemented/architecture/2026-09-14-composition-settings-with-local-credentials.zh.md'
        '.agents/notes/implemented/architecture/2026-09-14-managed-runtime-update-checkpoint.i18n.yaml'
        '.agents/notes/implemented/architecture/2026-09-14-managed-runtime-update-checkpoint.md'
        '.agents/notes/implemented/architecture/2026-09-14-managed-runtime-update-checkpoint.zh.md'
        '.agents/notes/implemented/architecture/2026-09-14-trusted-client-module-discovery.i18n.yaml'
        '.agents/notes/implemented/architecture/2026-09-14-trusted-client-module-discovery.md'
        '.agents/notes/implemented/architecture/2026-09-14-trusted-client-module-discovery.zh.md'
        'apps/cli/config/direct-local-agent-presets/enterprise-direct-local/agent.cordis.yml'
        'apps/cli/config/direct-local-agent-presets/enterprise-direct-local/preset.yml'
        'apps/cli/config/direct-local-profile/cordis.yml'
        'apps/cli/README.i18n.yaml'
        'apps/cli/README.md'
        'apps/cli/README.zh.md'
        'apps/cli/src/managed-runtime-update.ts'
        'apps/cli/tests/enterprise-direct-local.spec.ts'
        'apps/cli/tests/managed-runtime-update.spec.ts'
        'docs/subsystems/credentials.i18n.yaml'
        'docs/subsystems/credentials.md'
        'docs/subsystems/credentials.zh.md'
        'docs/subsystems/client-modules.i18n.yaml'
        'docs/subsystems/client-modules.md'
        'docs/subsystems/client-modules.zh.md'
        'docs/subsystems/settings.i18n.yaml'
        'docs/subsystems/settings.md'
        'docs/subsystems/settings.zh.md'
        'docs/subsystems/web-server.i18n.yaml'
        'docs/subsystems/web-server.md'
        'docs/subsystems/web-server.zh.md'
        'packages/client/modules/package.json'
        'packages/client/modules/src/index.ts'
        'packages/client/modules/tests/node-half.client.spec.ts'
        'packages/client/modules/tsconfig.json'
        'packages/client/ui-settings-models/README.i18n.yaml'
        'packages/client/ui-settings-models/README.md'
        'packages/client/ui-settings-models/README.zh.md'
        'packages/client/ui-settings-models/src/client/store.ts'
        'packages/client/ui-settings-models/src/client/welcome-store.ts'
        'packages/client/ui-settings-models/tests/onboarding-dialog.client.spec.tsx'
        'packages/client/ui-settings-models/tests/readiness.client.spec.ts'
        'packages/client/ui-settings-models/tests/welcome-store.client.spec.ts'
        'packages/credentials/credentials-local/README.i18n.yaml'
        'packages/credentials/credentials-local/README.md'
        'packages/credentials/credentials-local/README.zh.md'
        'packages/credentials/credentials-local/src/index.ts'
        'packages/credentials/credentials-local/tests/drain.spec.ts'
        'packages/credentials/credentials/README.i18n.yaml'
        'packages/credentials/credentials/README.md'
        'packages/credentials/credentials/README.zh.md'
        'packages/credentials/credentials/src/index.ts'
        'packages/host/webserver/README.i18n.yaml'
        'packages/host/webserver/README.md'
        'packages/host/webserver/README.zh.md'
        'packages/host/webserver/src/index.ts'
        'packages/host/webserver/tests/webserver.spec.ts'
        'packages/settings/settings-file/README.i18n.yaml'
        'packages/settings/settings-file/README.md'
        'packages/settings/settings-file/README.zh.md'
        'packages/settings/settings-file/package.json'
        'packages/settings/settings-file/src/composition-only.ts'
        'packages/settings/settings-file/tests/composition-only.spec.ts'
        'packages/settings/settings-file/tsdown.config.ts'
        'packages/settings/settings/README.i18n.yaml'
        'packages/settings/settings/README.md'
        'packages/settings/settings/README.zh.md'
        'packages/settings/settings/src/index.ts'
        'packages/settings/settings/tests/settings.spec.ts'
        'tsconfig.base.json'
    )
)
[Array]::Sort($DirectLocalExpectedPaths, [StringComparer]::Ordinal)

$ApprovedBases = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
$ApprovedBases.Add('dsh-v0.1.1-rc.2', [pscustomobject]@{
    Commit = 'b150a551b8d465e31e418e1b2eaf5e79bbb7d28e'
    Tree = '53915efe4e2126cc7779b73dfc8a3bcec5318c44'
    BaseLockfileSha256 = '6f20c268e76df1294c16f016ab10a7fa1271608b4db0f4fafe8f7c21ec90013e'
    BaseLockfileGitBlob = '737a21eea64d9ab25ed35258719442ae55376710'
    BaseLockfileBytes = [int64]698644
    ExpectedPaths = $Rc2ExpectedPaths
    ChangedFiles = 41
    AddedFiles = 8
    ModifiedFiles = 33
})
$ApprovedBases.Add('dsh-v0.1.2-alpha.3', [pscustomobject]@{
    Commit = 'dd6322d604e00eec1ba5e0c8541159906a21094a'
    Tree = '86be9091c78528b5ef0866ae6d58b01d4a53582e'
    BaseLockfileSha256 = '17bbd38216e31a8b821957f77d2e3f57b859046cc3a18076ad16e94ca952a8da'
    BaseLockfileGitBlob = '51de950c3e3c9dcdf118206888d05e8b3fba9ed5'
    BaseLockfileBytes = [int64]769826
    ExpectedPaths = $AlphaExpectedPaths
    ChangedFiles = 43
    AddedFiles = 8
    ModifiedFiles = 35
})
$ApprovedBases.Add('dsh-v0.1.2-rc.1', [pscustomobject]@{
    Commit = 'a66e4702047846cdaa10c66c9d3df3951f5ea70d'
    Tree = '27ab636bb3d77e698f5637e518db44ae1f61e262'
    BaseLockfileSha256 = 'e12083149a77f790d39b64d018b6b8745c6a7aa95777ecb73e0a2f5ed5fdd0d9'
    BaseLockfileGitBlob = '4521b1bbf42de10ad2c19e85523b56661d19d8f7'
    BaseLockfileBytes = [int64]742793
    ExpectedPaths = $AlphaExpectedPaths
    ChangedFiles = 43
    AddedFiles = 8
    ModifiedFiles = 35
})

$ApprovedBase = $null
if (-not $ApprovedBases.TryGetValue($BaseTag, [ref]$ApprovedBase) -or
    [string]$ApprovedBase.Commit -cne $BaseCommit) {
    throw "Base tag/commit is not an exact approved managed source base: $BaseTag / $BaseCommit"
}
$ExpectedPaths = [string[]]$ApprovedBase.ExpectedPaths
$ExpectedChangedFiles = [int]$ApprovedBase.ChangedFiles
$ExpectedAddedFiles = [int]$ApprovedBase.AddedFiles
$ExpectedModifiedFiles = [int]$ApprovedBase.ModifiedFiles
if ($PatchVariant -ceq 'enterprise-direct-local-v1') {
    if ($BaseTag -cne 'dsh-v0.1.2-rc.1' -or
        $BaseCommit -cne 'a66e4702047846cdaa10c66c9d3df3951f5ea70d') {
        throw "Patch variant $PatchVariant is not approved for base $BaseTag / $BaseCommit"
    }
    $ExpectedPaths = $DirectLocalExpectedPaths
    $ExpectedChangedFiles = 112
    $ExpectedAddedFiles = 26
    $ExpectedModifiedFiles = 86
}

function Get-FullPath([string]$Path, [switch]$MustExist) {
    $full = [IO.Path]::GetFullPath(
        $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path))
    if ($MustExist -and -not (Test-Path -LiteralPath $full)) {
        throw "Path does not exist: $full"
    }
    if ($full -ceq [IO.Path]::GetPathRoot($full)) { return $full }
    return $full.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
}

function Test-IsWithin([string]$Parent, [string]$Child) {
    $relative = [IO.Path]::GetRelativePath((Get-FullPath $Parent), (Get-FullPath $Child))
    return $relative -ceq '.' -or (
        $relative -cne '..' -and
        -not $relative.StartsWith('..' + [IO.Path]::DirectorySeparatorChar, [StringComparison]::Ordinal) -and
        -not [IO.Path]::IsPathRooted($relative))
}

function Assert-NoReparsePath([string]$Path) {
    $item = Get-Item -LiteralPath (Get-FullPath $Path -MustExist) -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Path must not traverse a symbolic link or reparse point: $($item.FullName)"
        }
        $item = if ($item -is [IO.DirectoryInfo]) { $item.Parent } else { $item.Directory }
    }
}

function New-GitStartInfo([string[]]$Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Git
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in @(
            '-c', 'core.longpaths=true',
            '-c', 'core.autocrlf=false',
            '-c', 'core.quotepath=false',
            '-c', "safe.directory=$($script:Checkout.Replace('\', '/'))",
            '-C', $script:Checkout) + $Arguments) {
        [void]$start.ArgumentList.Add($argument)
    }
    return $start
}

function Invoke-GitBytes([string[]]$Arguments, [string]$Label) {
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = New-GitStartInfo $Arguments
    if (-not $process.Start()) { throw "Unable to start Git for $Label." }
    $errorTask = $process.StandardError.ReadToEndAsync()
    $memory = [IO.MemoryStream]::new()
    try {
        $process.StandardOutput.BaseStream.CopyTo($memory)
        $process.WaitForExit()
        $errorText = $errorTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "$Label failed with exit code $($process.ExitCode).`n$errorText"
        }
        return ,$memory.ToArray()
    } finally {
        $memory.Dispose()
        $process.Dispose()
    }
}

function Convert-StrictUtf8([byte[]]$Bytes, [string]$Label) {
    try {
        return [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
    } catch {
        throw "$Label is not canonical UTF-8: $($_.Exception.Message)"
    }
}

function Invoke-GitText([string[]]$Arguments, [string]$Label) {
    $text = Convert-StrictUtf8 (Invoke-GitBytes $Arguments $Label) $Label
    return $text.TrimEnd([char[]]"`r`n")
}

function Get-Sha256([byte[]]$Bytes) {
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Assert-CanonicalTextBytes([byte[]]$Bytes, [string]$Label, [switch]$RequireNonEmpty) {
    if ($RequireNonEmpty -and $Bytes.Length -eq 0) { throw "$Label must not be empty." }
    $text = Convert-StrictUtf8 $Bytes $Label
    if ($text.Contains("`r")) { throw "$Label must use LF line endings only." }
    if ([Text.RegularExpressions.Regex]::IsMatch(
            $text, '[\x20\x09]+(?=\n|\z)',
            [Text.RegularExpressions.RegexOptions]::CultureInvariant)) {
        throw "$Label contains trailing horizontal whitespace."
    }
    if ($RequireNonEmpty -and $Bytes[-1] -ne 10) { throw "$Label must be LF-terminated." }
    return $text
}

function Get-BlobRecord([string]$Revision, [string]$Path) {
    $object = Invoke-GitText @('rev-parse', "$Revision`:$Path") "resolve blob $Revision`:$Path"
    if ($object -cnotmatch '^[0-9a-f]{40}$') { throw "Unexpected Git blob id for $Revision`:$Path." }
    $bytes = Invoke-GitBytes @('cat-file', 'blob', $object) "read blob $object"
    [void](Assert-CanonicalTextBytes $bytes "blob $Revision`:$Path")
    return [ordered]@{
        gitBlob = $object
        bytes = [int64]$bytes.Length
        sha256 = Get-Sha256 $bytes
    }
}

function Get-ExactDigest([string]$Text, [string]$Constant) {
    $pattern = "(?m)^const $([Text.RegularExpressions.Regex]::Escape($Constant)) = '([0-9a-f]{64})'$"
    $matches = [Text.RegularExpressions.Regex]::Matches(
        $Text, $pattern, [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if ($matches.Count -ne 1) {
        throw "Managed source must define exactly one canonical $Constant digest."
    }
    return $matches[0].Groups[1].Value
}

function Write-Utf8Lf([string]$Path, [string]$Text) {
    $canonical = $Text.Replace("`r`n", "`n").Replace("`r", "`n")
    if (-not $canonical.EndsWith("`n", [StringComparison]::Ordinal)) { $canonical += "`n" }
    [IO.File]::WriteAllText($Path, $canonical, [Text.UTF8Encoding]::new($false))
}

function Assert-CanonicalPatch([byte[]]$Bytes) {
    $text = Assert-CanonicalTextBytes $Bytes 'generated managed patch' -RequireNonEmpty
    [string[]]$paths = @([Text.RegularExpressions.Regex]::Matches(
        $text, '(?m)^diff --git a/(?<path>.+) b/\k<path>$') |
        ForEach-Object { $_.Groups['path'].Value })
    if ($paths.Count -ne $ExpectedPaths.Count) {
        throw "Generated patch has $($paths.Count) file sections; expected $($ExpectedPaths.Count)."
    }
    for ($index = 0; $index -lt $ExpectedPaths.Count; $index++) {
        if ($paths[$index] -cne $ExpectedPaths[$index]) {
            throw "Generated patch path/order mismatch at index ${index}: $($paths[$index])"
        }
    }
    $indexes = [Text.RegularExpressions.Regex]::Matches(
        $text, '(?m)^index [0-9a-f]{40}\.\.[0-9a-f]{40}(?: 100644)?$')
    if ($indexes.Count -ne $ExpectedPaths.Count) {
        throw 'Generated patch is not a full-index patch for every changed file.'
    }
}

foreach ($approvedTag in $ApprovedBases.Keys) {
    $contract = $ApprovedBases[$approvedTag]
    [string[]]$contractPaths = $contract.ExpectedPaths
    if ($contractPaths.Count -ne [int]$contract.ChangedFiles -or
        [int]$contract.AddedFiles + [int]$contract.ModifiedFiles -ne [int]$contract.ChangedFiles) {
        throw "Internal expected count contract is inconsistent for $approvedTag."
    }
    $uniquePaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $orderedPaths = [string[]]$contractPaths.Clone()
    [Array]::Sort($orderedPaths, [StringComparer]::Ordinal)
    for ($index = 0; $index -lt $contractPaths.Count; $index++) {
        if (-not $uniquePaths.Add($contractPaths[$index])) {
            throw "Internal expected path is repeated for ${approvedTag}: $($contractPaths[$index])"
        }
        if ($contractPaths[$index] -cne $orderedPaths[$index]) {
            throw "Internal expected paths are not in Unicode code-point ascending order for $approvedTag."
        }
    }
}
$directLocalUniquePaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
for ($index = 0; $index -lt $DirectLocalExpectedPaths.Count; $index++) {
    if (-not $directLocalUniquePaths.Add($DirectLocalExpectedPaths[$index])) {
        throw "Internal direct-local expected path is repeated: $($DirectLocalExpectedPaths[$index])"
    }
    if ($index -gt 0 -and
        [StringComparer]::Ordinal.Compare(
            $DirectLocalExpectedPaths[$index - 1], $DirectLocalExpectedPaths[$index]) -ge 0) {
        throw 'Internal direct-local expected paths are not in Unicode code-point ascending order.'
    }
}
if ($DirectLocalExpectedPaths.Count -ne 112) {
    throw 'Internal direct-local expected path count is not exactly 112.'
}

$Checkout = Get-FullPath $PatchedCheckout -MustExist
if (-not (Test-Path -LiteralPath $Checkout -PathType Container)) {
    throw "Patched checkout is not a directory: $Checkout"
}
Assert-NoReparsePath $Checkout

$Output = Get-FullPath $OutputDirectory
if (Test-Path -LiteralPath $Output) { throw "Output directory already exists: $Output" }
$outputParent = Split-Path -Parent $Output
if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
    throw "Output parent directory does not exist: $outputParent"
}
Assert-NoReparsePath $outputParent
if (Test-IsWithin $Checkout $Output) { throw 'Output directory must be outside the patched checkout.' }

$origins = @(Invoke-GitText @('remote', 'get-url', '--all', 'origin') 'resolve origin' -split "`n")
if ($origins.Count -ne 1 -or $origins[0] -cne $CanonicalRepository) {
    throw "Origin must be exactly $CanonicalRepository"
}
$baseFromTag = Invoke-GitText @('rev-parse', "$BaseTag^{commit}") 'resolve official base tag'
if ($baseFromTag -cne $BaseCommit) {
    throw "Base tag $BaseTag does not resolve to exact commit $BaseCommit."
}
$baseTree = Invoke-GitText @('rev-parse', "$BaseCommit^{tree}") 'resolve official base tree'
if ($baseTree -cne [string]$ApprovedBase.Tree) {
    throw "Base tag/commit tree is not the exact approved tree. Expected $($ApprovedBase.Tree), got $baseTree."
}
$baseLockfile = Get-BlobRecord $BaseCommit 'pnpm-lock.yaml'
if ([string]$baseLockfile.sha256 -cne [string]$ApprovedBase.BaseLockfileSha256 -or
    [string]$baseLockfile.gitBlob -cne [string]$ApprovedBase.BaseLockfileGitBlob -or
    [int64]$baseLockfile.bytes -ne [int64]$ApprovedBase.BaseLockfileBytes) {
    throw 'Exact approved base pnpm-lock.yaml SHA-256, Git blob, or byte length changed.'
}
$head = Invoke-GitText @('rev-parse', 'HEAD') 'resolve patched HEAD'
if ($head -cnotmatch '^[0-9a-f]{40}$') { throw 'Patched HEAD is not a full lowercase Git id.' }
$parentLine = Invoke-GitText @('rev-list', '--parents', '-n', '1', 'HEAD') 'resolve patched parent'
$parentParts = @($parentLine.Split(' ', [StringSplitOptions]::RemoveEmptyEntries))
if ($parentParts.Count -ne 2 -or $parentParts[0] -cne $head -or $parentParts[1] -cne $BaseCommit) {
    throw 'Patched HEAD must be a single commit whose only parent is the exact official base commit.'
}
$status = Invoke-GitText @('status', '--porcelain=v1', '--untracked-files=all') 'verify clean patched checkout'
if ($status.Length -ne 0) { throw "Patched checkout is dirty.`n$status" }

$nameStatus = Invoke-GitText @('diff', '--name-status', '--no-renames', $BaseCommit, $head, '--') 'enumerate managed changes'
$changeRows = @($nameStatus -split "`n" | Where-Object { $_.Length -gt 0 })
if ($changeRows.Count -ne $ExpectedPaths.Count) {
    throw "Managed commit changed $($changeRows.Count) paths; expected exactly $($ExpectedPaths.Count)."
}
$statuses = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
for ($index = 0; $index -lt $changeRows.Count; $index++) {
    if ($changeRows[$index] -notmatch '^(?<status>[AM])\t(?<path>.+)$') {
        throw "Managed commit contains a deletion, rename, mode-only, or unsupported change: $($changeRows[$index])"
    }
    $path = $Matches.path
    if ($path -cne $ExpectedPaths[$index]) { throw "Managed changed-path contract mismatch: $path" }
    if (-not $statuses.TryAdd($path, $Matches.status)) { throw "Repeated managed changed path: $path" }
}
$actualAddedFiles = @($statuses.Values | Where-Object { $_ -ceq 'A' }).Count
$actualModifiedFiles = @($statuses.Values | Where-Object { $_ -ceq 'M' }).Count
if ($actualAddedFiles -ne $ExpectedAddedFiles -or
    $actualModifiedFiles -ne $ExpectedModifiedFiles) {
    throw "Managed commit must contain exactly $ExpectedAddedFiles added and $ExpectedModifiedFiles modified files for $BaseTag."
}
[void](Invoke-GitText @('diff', '--check', $BaseCommit, $head, '--') 'verify managed change whitespace')

foreach ($path in $ExpectedPaths) {
    $mode = Invoke-GitText @('ls-tree', $head, '--', $path) "resolve postimage mode $path"
    if ($mode -cnotmatch '^100644 blob [0-9a-f]{40}\t') {
        throw "Managed postimage must be a regular non-link 100644 blob: $path"
    }
    if ($statuses[$path] -ceq 'M') {
        $baseMode = Invoke-GitText @('ls-tree', $BaseCommit, '--', $path) "resolve preimage mode $path"
        if ($baseMode -cnotmatch '^100644 blob [0-9a-f]{40}\t') {
            throw "Managed preimage must be a regular non-link 100644 blob: $path"
        }
    }
    $nativePath = Join-Path $Checkout ($path -replace '/', '\')
    if (-not (Test-Path -LiteralPath $nativePath -PathType Leaf)) { throw "Managed postimage is absent: $path" }
    Assert-NoReparsePath $nativePath
}

$patchArguments = [Collections.Generic.List[string]]::new()
foreach ($argument in @(
        'diff', '--binary', '--full-index', '--no-ext-diff', '--no-color',
        '--no-renames', '--unified=0', $BaseCommit, $head, '--')) {
    [void]$patchArguments.Add($argument)
}
foreach ($path in $ExpectedPaths) { [void]$patchArguments.Add($path) }
$firstPatch = Invoke-GitBytes $patchArguments.ToArray() 'generate canonical managed patch'
$secondPatch = Invoke-GitBytes $patchArguments.ToArray() 'regenerate canonical managed patch'
Assert-CanonicalPatch $firstPatch
Assert-CanonicalPatch $secondPatch
if (-not [Collections.StructuralComparisons]::StructuralEqualityComparer.Equals($firstPatch, $secondPatch)) {
    throw 'Managed patch regeneration was not byte-identical.'
}
if ($PatchVariant -ceq 'enterprise-direct-local-v1') {
    $frozenPatchSha256 = Get-Sha256 $firstPatch
    $frozenPatchLfLines = @($firstPatch | Where-Object { $_ -eq 10 }).Count
    if ($frozenPatchSha256 -cne '7f10ec9492b399cede422428013b0c77bc932699fa3a14fa7ced158454272b6f' -or
        $firstPatch.Length -ne 415878 -or $frozenPatchLfLines -ne 7453) {
        throw 'Generated enterprise direct-local patch is not the exact frozen reviewed candidate.'
    }
}

$files = [Collections.Generic.List[object]]::new()
$changes = [Collections.Generic.List[object]]::new()
$modifiedPreimages = [ordered]@{}
foreach ($path in $ExpectedPaths) {
    $postimage = Get-BlobRecord $head $path
    $file = [ordered]@{ path = $path }
    foreach ($key in @('gitBlob', 'bytes', 'sha256')) { $file[$key] = $postimage[$key] }
    [void]$files.Add($file)
    $preimage = $null
    if ($statuses[$path] -ceq 'M') {
        $preimage = Get-BlobRecord $BaseCommit $path
        $modifiedPreimages[$path] = $preimage.gitBlob
    }
    [void]$changes.Add([ordered]@{
        path = $path
        status = $statuses[$path]
        preimage = $preimage
        postimage = $postimage
    })
}

$managedBoot = Convert-StrictUtf8 (
    Invoke-GitBytes @('cat-file', 'blob', "$head`:apps/cli/src/managed-boot.ts") 'read managed semantic source'
) 'managed semantic source'
$digestPrefix = if ($PatchVariant -ceq 'enterprise-direct-local-v1') { 'DIRECT_LOCAL' } else { 'MANAGED' }
$hostDigest = Get-ExactDigest $managedBoot ($digestPrefix + '_HOST_COMPOSITION_SHA256')
$presetDigest = Get-ExactDigest $managedBoot ($digestPrefix + '_PRESET_COMPOSITION_SHA256')
$metadataDigest = Get-ExactDigest $managedBoot ($digestPrefix + '_PRESET_METADATA_SHA256')
$loaderDigest = Get-ExactDigest $managedBoot ($digestPrefix + '_ROOT_COMPOSITION_SHA256')

if ($PatchVariant -ceq 'enterprise-direct-local-v1') {
    $patchedLockfile = $files | Where-Object {
        [string]$_.path -ceq 'pnpm-lock.yaml'
    } | Select-Object -First 1
    if ($null -eq $patchedLockfile -or
        [string]$patchedLockfile.sha256 -cne '07974704247ec18915df8fdf117c682bba2d861aafe7059ea4bca4aab1677080' -or
        [string]$patchedLockfile.gitBlob -cne '68ad6b76b1577112091beaa532667ac02ddcbccf' -or
        [int64]$patchedLockfile.bytes -ne [int64]743966) {
        throw 'Generated enterprise direct-local pnpm-lock.yaml is not the exact frozen reviewed postimage.'
    }
}

$patchSha256 = Get-Sha256 $firstPatch
$patchLfLines = @($firstPatch | Where-Object { $_ -eq 10 }).Count
$manifest = [ordered]@{
    schema = if ($PatchVariant -ceq 'enterprise-direct-local-v1') {
        'ensou.dsh.upstream-patch-manifest.v4'
    } else {
        'ensou.dsh.upstream-patch-manifest.v3'
    }
    generator = [ordered]@{
        version = 2
        pathOrder = 'Unicode code-point ascending'
        lineEndings = 'LF'
        coreAutocrlf = $false
        contextLines = 0
        trailingWhitespace = 'reject'
    }
    base = [ordered]@{
        repository = $CanonicalRepository
        tag = $BaseTag
        commit = $BaseCommit
        tree = $baseTree
        modifiedPreimages = $modifiedPreimages
    }
    patch = [ordered]@{
        file = $PatchFileName
        bytes = [int64]$firstPatch.Length
        lfLines = [int]$patchLfLines
        sha256 = $patchSha256
    }
    counts = [ordered]@{
        changedFiles = $ExpectedChangedFiles
        addedFiles = $ExpectedAddedFiles
        modifiedFiles = $ExpectedModifiedFiles
    }
    managedPolicy = [ordered]@{
        signal = 'DSH_ENTERPRISE_MANAGED_BOOT=ensou-dsh-launcher/v1'
        profile = 'enterprise-managed'
        webArguments = '--host 127.0.0.1 --port <canonical 1..65535>'
        model = 'deepseek-v4-flash'
        maxTokens = 8192
        gatewayAllowedModel = 'deepseek-v4-flash'
        gatewayMaxTokens = 8192
        managedSkillsRootEnvironment = 'ENSOU_DSH_ENTERPRISE_SKILLS_ROOT'
        sandboxMode = 'workspace-write'
        sandboxMaximumMode = 'workspace-write'
        approvalPolicy = 'ask'
        permissionPresets = @('workspace-write')
        workspaceRootSource = 'process.cwd()'
        restoredSessionCwdPolicy = 'must-equal-workspace-root'
        hostCompositionCanonicalSha256 = $hostDigest
        presetCompositionCanonicalSha256 = $presetDigest
        presetMetadataCanonicalSha256 = $metadataDigest
        loaderRootCanonicalSha256 = $loaderDigest
        pluginResolutionPolicy = 'frozen exact installation map from managed base/web bundles; no ambient fallback'
    }
    requiredLauncherCoupling = [ordered]@{
        childEnvironmentMustUnset = @('NODE_OPTIONS', 'NODE_PATH', 'NODE_EXTRA_CA_CERTS')
        note = 'Launcher child-environment sanitization is required integration and is not implemented by this DSH patch.'
    }
    files = $files.ToArray()
    changes = $changes.ToArray()
}
if ($PatchVariant -ceq 'enterprise-direct-local-v1') {
    $manifest.patchVariant = $PatchVariant
    $manifest.managedPolicy = [ordered]@{
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
        hostCompositionCanonicalSha256 = $hostDigest
        presetCompositionCanonicalSha256 = $presetDigest
        presetMetadataCanonicalSha256 = $metadataDigest
        loaderRootCanonicalSha256 = $loaderDigest
        pluginResolutionPolicy = 'frozen exact installation map from managed base/web bundles; no ambient fallback'
    }
}

$localDataUpgradeGate = if ($BaseTag -in @('dsh-v0.1.2-alpha.3', 'dsh-v0.1.2-rc.1')) {
@"

## Local data upgrade gate

The managed composition uses session-persistence-jsonl. It does not include session-persistence-sqlite; the remaining session-query-sqlite row is in-memory query support and is not a persistent store. The modern 0.1.2 source line removed the former optional SQLite persistence package. Before automatic upgrade, Launcher must detect evidence that an older installation used that optional persistent SQLite backend. If such evidence exists, automatic upgrade must stop and an operator must export the data with the old version first. This handoff does not claim or implement automatic SQLite-to-JSONL migration.
"@
} else { '' }

$handoffTitle = if ($PatchVariant -ceq 'enterprise-direct-local-v1') {
    'Enterprise direct-local DSH patch handoff'
} else {
    'Enterprise managed DSH patch handoff'
}
$providerCoupling = if ($PatchVariant -ceq 'enterprise-direct-local-v1') {
    'The direct-local profile pins the official DeepSeek model and search endpoints and references DEEPSEEK_API_KEY only through the writable local credential store. Launcher-provided provider URL or credential overrides are rejected; no Gateway endpoint or Gateway model admission is claimed by this patch.'
} else {
    'The Launcher must provide the exact managed signal, loopback proxy tuple, canonical bearer, managed skills root, fixed profile and Web arguments recorded in the manifest. The Gateway must allow only deepseek-v4-flash for this profile and enforce max_tokens <= 8192.'
}
$readme = @"
# $handoffTitle

This directory is a deterministic reviewed-input candidate for the Launcher runtime build pipeline. It is not a fork, and the patch must never be applied to an arbitrary upstream revision.

Patch SHA-256: $patchSha256 ($($firstPatch.Length) bytes, $patchLfLines LF-terminated lines). Exact preimage and postimage byte lengths, SHA-256 values, and Git blob ids for all $ExpectedChangedFiles changed files ($ExpectedAddedFiles added and $ExpectedModifiedFiles modified) are in manifest.json.

## Apply gate

1. Use an otherwise clean deepseek-ai/deepseek-harness checkout at tag $BaseTag.
2. Verify that HEAD is exactly $BaseCommit and its tree is exactly $baseTree.
3. Verify manifest.json, the patch byte length, LF line count, patch SHA-256, and every modified-file preimage.
4. Apply only with zero-context support and whitespace errors enabled: git -c core.autocrlf=false -c core.whitespace=-blank-at-eof apply --check --index --unidiff-zero --whitespace=error-all $PatchFileName, then repeat without --check.
5. Verify every postimage byte length, SHA-256, and Git blob id from the manifest before installing dependencies or building.

Any upstream tag, commit, tree, preimage, patch, postimage, path set, or semantic digest mismatch must stop the build. An upstream update requires a fresh rebase, review, test run, and regenerated handoff. This directory is not admitted merely because it was generated; signing, independent review, runtime tests, and controlled promotion remain separate gates.

## Required Launcher coupling

$providerCoupling The Launcher must remove NODE_OPTIONS, NODE_PATH, and NODE_EXTRA_CA_CERTS before starting the managed Node child.

Local conversations and workspaces remain local and writable by design. The managed guarantees apply only to a verified release set launched through the controlled Launcher path.
$localDataUpgradeGate
"@

$staging = Join-Path $outputParent ('.' + [IO.Path]::GetFileName($Output) + '.staging.' + [guid]::NewGuid().ToString('N'))
try {
    [IO.Directory]::CreateDirectory($staging) | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $staging $PatchFileName), $firstPatch)
    Write-Utf8Lf (Join-Path $staging 'manifest.json') ($manifest | ConvertTo-Json -Depth 64)
    Write-Utf8Lf (Join-Path $staging 'README.md') $readme
    foreach ($name in @($PatchFileName, 'manifest.json', 'README.md')) {
        $path = Join-Path $staging $name
        Assert-NoReparsePath $path
        [void](Assert-CanonicalTextBytes ([IO.File]::ReadAllBytes($path)) $name -RequireNonEmpty)
    }
    [IO.Directory]::Move($staging, $Output)
} finally {
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
}

$manifestPath = Join-Path $Output 'manifest.json'
$manifestSha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
[pscustomobject]@{
    OutputDirectory = $Output
    BaseTag = $BaseTag
    BaseCommit = $BaseCommit
    BaseTree = $baseTree
    PatchedCommit = $head
    PatchSha256 = $patchSha256
    PatchBytes = [int64]$firstPatch.Length
    PatchLfLines = [int]$patchLfLines
    ManifestSha256 = $manifestSha256
    ChangedFiles = $ExpectedChangedFiles
    AddedFiles = $ExpectedAddedFiles
    ModifiedFiles = $ExpectedModifiedFiles
}
