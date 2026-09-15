#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')]
    [string]$ReleaseId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^dsh-v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$')]
    [string]$OfficialTag,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$OfficialCommit,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+$')]
    [string]$NodeVersion,

    [ValidateSet(
        '',
        'legacy-clean-root-v1',
        'browser-launch-cookie-v1')]
    [string]$RuntimeWebAuthProtocol = '',

    [switch]$PersonalManagedUpdate,

    [switch]$EnterpriseDirectLocal,

    [string]$HarnessCheckout = 'C:\Agents\deepseek',
    [string]$NodeExe = '',
    [string]$PnpmCommand = '',
    [string]$OutDir = (Join-Path $PSScriptRoot '..\out\source-runtime'),
    [switch]$ValidateOnly,
    [switch]$LocalLab
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$managedReleaseIdPattern =
    '^managed-v[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]*$'
$localLabReleaseIdPattern = '^lab-[A-Za-z0-9][A-Za-z0-9._-]{0,123}$'
$isManagedReleaseId = $ReleaseId -cmatch $managedReleaseIdPattern
$isLocalLabReleaseId = $ReleaseId -cmatch $localLabReleaseIdPattern
if ($LocalLab) {
    if (-not $isLocalLabReleaseId) {
        throw 'LocalLab mode requires a canonical lab-* releaseId.'
    }
}
elseif (-not $isManagedReleaseId) {
    throw 'Production-candidate mode requires a canonical managed-vYYYY.MM.DD.N releaseId; use -LocalLab only for lab-* builds.'
}
$promotionEligible = -not [bool]$LocalLab

$OfficialRepository = 'https://github.com/deepseek-ai/deepseek-harness.git'
$LauncherRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$PatchVariant = if ($EnterpriseDirectLocal) { 'enterprise-direct-local-v1' } else { 'enterprise-managed-v1' }
$ManagedPatchIndexPath = if ($EnterpriseDirectLocal) {
    Join-Path $PSScriptRoot '..\upstream-patches\direct-local-index.v1.json'
} else {
    Join-Path $PSScriptRoot '..\upstream-patches\index.json'
}
$RuntimeArtifactType = if ($EnterpriseDirectLocal) {
    'ensou-dsh-enterprise-direct-local-source-runtime'
} else {
    'ensou-dsh-enterprise-managed-source-runtime'
}
$ExpectedEngine = '^22.19.0 || >=24.0.0'
$Platform = 'win32-x64'
$MaximumNativeToolPathLengthExclusive = 240
$ReviewedLongestNativeToolRelativePath = 'node_modules\.pnpm\@oxlint-tsgolint+win32-x64@7.0.2001\node_modules\@oxlint-tsgolint\win32-x64\tsgolint.exe'
$LegacyCleanRootWebAuthProtocol = 'legacy-clean-root-v1'
$BrowserLaunchCookieWebAuthProtocol = 'browser-launch-cookie-v1'
$effectiveRuntimeWebAuthProtocol = if ($RuntimeWebAuthProtocol) {
    $RuntimeWebAuthProtocol
} else {
    $LegacyCleanRootWebAuthProtocol
}
$ReviewedRuntimeWebAuthPairs = @{
    'dsh-v0.1.1-rc.2' = $LegacyCleanRootWebAuthProtocol
    'dsh-v0.1.2-alpha.3' = $BrowserLaunchCookieWebAuthProtocol
    'dsh-v0.1.2-rc.1' = $BrowserLaunchCookieWebAuthProtocol
}
if ($PersonalManagedUpdate -and $EnterpriseDirectLocal) {
    throw 'Personal managed-update and Enterprise direct-local are distinct runtime capabilities and cannot be combined.'
}
if ($EnterpriseDirectLocal -and ($OfficialTag -cne 'dsh-v0.1.2-rc.1' -or
        $OfficialCommit.ToLowerInvariant() -cne 'a66e4702047846cdaa10c66c9d3df3951f5ea70d' -or
        $effectiveRuntimeWebAuthProtocol -cne $BrowserLaunchCookieWebAuthProtocol)) {
    throw 'Enterprise direct-local requires the exact reviewed rc.1 source and explicit browser-launch-cookie-v1 protocol.'
}
if ($PersonalManagedUpdate -and $effectiveRuntimeWebAuthProtocol -cne $BrowserLaunchCookieWebAuthProtocol) {
    throw 'Personal managed-update builds require browser-launch-cookie-v1.'
}
if (-not $ReviewedRuntimeWebAuthPairs.ContainsKey($OfficialTag) -or
    [string]$ReviewedRuntimeWebAuthPairs[$OfficialTag] -cne
        $effectiveRuntimeWebAuthProtocol) {
    if ([string]$ReviewedRuntimeWebAuthPairs[$OfficialTag] -ceq $BrowserLaunchCookieWebAuthProtocol -and
        -not $RuntimeWebAuthProtocol) {
        throw "$OfficialTag requires explicit -RuntimeWebAuthProtocol $BrowserLaunchCookieWebAuthProtocol."
    }
    throw "The official tag and runtime Web authentication protocol are not an explicit reviewed pair: $OfficialTag / $effectiveRuntimeWebAuthProtocol."
}
$oldPath = $env:Path
$oldCi = $env:CI
$oldTelemetry = $env:DSH_TELEMETRY_DISABLED
$oldBuildNodePath = $env:NODE_PATH
$oldBuildNodeOptions = $env:NODE_OPTIONS
$oldBuildNodeExtraCaCerts = $env:NODE_EXTRA_CA_CERTS
$reservation = $null
$stagingParent = $null
$stagingRoot = $null
$productsRoot = $null
$completed = $false

Import-Module (Join-Path $PSScriptRoot 'ManagedSourcePatch.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'RuntimeProtocolMetadata.psm1') -Force

function Write-Step([string]$Message) {
    Write-Host ("== {0} ==" -f $Message) -ForegroundColor Cyan
}

function Read-RuntimeWebAuthProtocolMetadata([string]$RuntimeRoot) {
    $path = Join-Path $RuntimeRoot 'ensou-runtime-metadata.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Runtime Web authentication metadata is missing: $path"
    }
    $file = Get-Item -LiteralPath $path -Force
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $file.Length -le 0 -or $file.Length -gt 4096) {
        throw 'Runtime Web authentication metadata must be one bounded ordinary file.'
    }
    try {
        $text = [Text.UTF8Encoding]::new($false, $true).GetString(
            [IO.File]::ReadAllBytes($path))
    } catch {
        throw "Runtime Web authentication metadata is not strict UTF-8: $($_.Exception.Message)"
    }
    $metadata = Read-RuntimeProtocolMetadata $RuntimeRoot
    $expected = [Text.UTF8Encoding]::new($false).GetString([byte[]](New-RuntimeProtocolMetadataBytes `
        -WebAuthProtocol $metadata.WebAuthProtocol -PersonalManagedUpdate:$PersonalManagedUpdate `
        -EnterpriseDirectLocal:$EnterpriseDirectLocal))
    if ($text -cne $expected -or $metadata.SupportsPersonalManagedUpdate -ne [bool]$PersonalManagedUpdate -or
        $metadata.SupportsEnterpriseDirectLocal -ne [bool]$EnterpriseDirectLocal) {
        throw 'Runtime Web authentication metadata is not the exact selected canonical contract.'
    }
    return $metadata.WebAuthProtocol
}

function Invoke-PersonalManagedUpdateSmoke([string]$RuntimeRoot, [string]$SmokeRoot) {
    if (-not $PersonalManagedUpdate) { return }
    Invoke-Checked (Join-Path $RuntimeRoot 'node.exe') @(
        (Join-Path $PSScriptRoot 'Test-PersonalManagedRuntimeSmoke.mjs'),
        $RuntimeRoot, $SmokeRoot) 'Personal built runtime private update protocol'
}

function Read-EnterpriseDirectLocalSmokeReceipt([string]$Text) {
    if ([Text.Encoding]::UTF8.GetByteCount($Text) -gt 4096) {
        throw 'Direct-local smoke receipt exceeds its size limit.'
    }
    $document = [System.Text.Json.JsonDocument]::Parse($Text)
    try {
        $root = $document.RootElement
        if ($root.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) {
            throw 'Direct-local smoke receipt must be an object.'
        }
        $expected = @('status', 'resultStatus', 'scope', 'cycles', 'kernelBootstrapVerified',
            'settingsReadOnly', 'credentialsWritable', 'exactChildExited',
            'authenticationNegativesVerified', 'launchRefusalsVerified', 'modelRequestsSent', 'outputBytes')
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $root.EnumerateObject()) {
            if ($expected -cnotcontains $property.Name -or -not $seen.Add($property.Name)) {
                throw 'Direct-local smoke receipt contains an unknown or duplicate field.'
            }
        }
        if ($seen.Count -ne $expected.Count) { throw 'Direct-local smoke receipt is incomplete.' }
        foreach ($pair in @{
            status = 'PASS'; resultStatus = 'PASS'
            scope = 'BUILT_ENTERPRISE_DIRECT_LOCAL_RUNTIME_CAPABILITY_ONLY'
        }.GetEnumerator()) {
            $value = $root.GetProperty($pair.Key)
            if ($value.ValueKind -ne [System.Text.Json.JsonValueKind]::String -or
                $value.GetString() -cne $pair.Value) { throw 'Direct-local smoke scope or result is invalid.' }
        }
        foreach ($name in @('kernelBootstrapVerified', 'settingsReadOnly', 'credentialsWritable',
            'exactChildExited', 'authenticationNegativesVerified', 'launchRefusalsVerified')) {
            if ($root.GetProperty($name).ValueKind -ne [System.Text.Json.JsonValueKind]::True) {
                throw 'Direct-local smoke capability was not positively verified.'
            }
        }
        foreach ($name in @('cycles', 'modelRequestsSent', 'outputBytes')) {
            $value = $root.GetProperty($name)
            [int]$number = 0
            if ($value.ValueKind -ne [System.Text.Json.JsonValueKind]::Number -or
                -not $value.TryGetInt32([ref]$number) -or
                ($name -ceq 'cycles' -and $number -ne 2) -or
                ($name -ceq 'modelRequestsSent' -and $number -ne 0) -or
                ($name -ceq 'outputBytes' -and ($number -lt 0 -or $number -gt 8388608))) {
                throw 'Direct-local smoke counters are invalid.'
            }
        }
        return ($Text | ConvertFrom-Json -Depth 4)
    } finally { $document.Dispose() }
}

function Invoke-EnterpriseDirectLocalSmoke([string]$RuntimeRoot, [string]$SmokeRoot) {
    if (-not $EnterpriseDirectLocal) { return }
    $raw = Invoke-Captured (Join-Path $RuntimeRoot 'node.exe') @(
        (Join-Path $PSScriptRoot 'Test-EnterpriseDirectLocalRuntimeSmoke.mjs'),
        $RuntimeRoot, $SmokeRoot) 'Enterprise direct-local built runtime bootstrap and private update protocol'
    $receipt = Read-EnterpriseDirectLocalSmokeReceipt $raw
    Write-Host 'Enterprise direct-local bootstrap, native credential capability and two private update cycles passed.'
    return $receipt
}

function Format-Command([string]$Command, [string[]]$Arguments) {
    $parts = @($Command) + $Arguments
    return ($parts | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    }) -join ' '
}

function Invoke-Checked(
    [string]$Command,
    [string[]]$Arguments,
    [string]$Label
) {
    Write-Host ("[{0}] {1}" -f $Label, (Format-Command $Command $Arguments))
    & $Command @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$Label failed with exit code $exitCode."
    }
}

function Invoke-Captured(
    [string]$Command,
    [string[]]$Arguments,
    [string]$Label
) {
    $output = @(& $Command @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    $text = ($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
    if ($exitCode -ne 0) {
        throw "$Label failed with exit code $exitCode.`n$text"
    }
    return $text.Trim()
}

function Get-FullProviderPath([string]$Path, [switch]$MustExist) {
    $providerPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $fullPath = [IO.Path]::GetFullPath($providerPath)
    if ($MustExist -and -not (Test-Path -LiteralPath $fullPath)) {
        throw "Path does not exist: $fullPath"
    }
    if ([string]::Equals($fullPath, [IO.Path]::GetPathRoot($fullPath), [StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath
    }
    return $fullPath.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
}

function Test-SamePath([string]$Left, [string]$Right) {
    return [string]::Equals(
        (Get-FullProviderPath $Left),
        (Get-FullProviderPath $Right),
        [StringComparison]::OrdinalIgnoreCase)
}

function Test-IsWithin([string]$Parent, [string]$Child) {
    $relative = [IO.Path]::GetRelativePath(
        (Get-FullProviderPath $Parent),
        (Get-FullProviderPath $Child))
    return $relative -eq '.' -or (
        $relative -ne '..' -and
        -not $relative.StartsWith('..' + [IO.Path]::DirectorySeparatorChar) -and
        -not [IO.Path]::IsPathRooted($relative))
}

function Resolve-CommandPath([string]$Requested, [string[]]$FallbackNames, [string]$Label) {
    if ($Requested) {
        if (Test-Path -LiteralPath $Requested) {
            return Get-FullProviderPath $Requested -MustExist
        }
        $command = Get-Command $Requested -ErrorAction SilentlyContinue
        if ($command) { return $command.Source }
        throw "$Label was not found: $Requested"
    }
    foreach ($name in $FallbackNames) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) { return $command.Source }
    }
    throw "$Label was not found."
}

function Resolve-LinkTargetPath([IO.FileSystemInfo]$Item) {
    if (-not ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        return Get-FullProviderPath $Item.FullName -MustExist
    }
    $resolved = $Item.ResolveLinkTarget($true)
    if ($null -eq $resolved) {
        throw "Cannot resolve link target: $($Item.FullName)"
    }
    return Get-FullProviderPath $resolved.FullName -MustExist
}

function Get-FirstReparsePoint([string]$Root, [string]$SkipRoot = '') {
    $queue = [Collections.Generic.Queue[string]]::new()
    $queue.Enqueue((Get-FullProviderPath $Root -MustExist))
    $skip = if ($SkipRoot) { Get-FullProviderPath $SkipRoot } else { '' }
    while ($queue.Count -gt 0) {
        $directory = $queue.Dequeue()
        foreach ($item in Get-ChildItem -LiteralPath $directory -Force) {
            if ($skip -and (Test-SamePath $item.FullName $skip)) { continue }
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                return $item
            }
            if ($item.PSIsContainer) { $queue.Enqueue($item.FullName) }
        }
    }
    return $null
}

function Copy-MaterializedItem(
    [string]$Source,
    [string]$Destination,
    [switch]$PackageRoot
) {
    $sourceItem = Get-Item -LiteralPath $Source -Force
    if ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        $sourceItem = Get-Item -LiteralPath (Resolve-LinkTargetPath $sourceItem) -Force
        $PackageRoot = $sourceItem.PSIsContainer
    }

    if (-not $sourceItem.PSIsContainer) {
        $parent = Split-Path -Parent $Destination
        [IO.Directory]::CreateDirectory($parent) | Out-Null
        Copy-Item -LiteralPath $sourceItem.FullName -Destination $Destination
        return
    }

    [IO.Directory]::CreateDirectory($Destination) | Out-Null
    foreach ($child in Get-ChildItem -LiteralPath $sourceItem.FullName -Force) {
        if ($PackageRoot -and $child.PSIsContainer -and $child.Name -eq 'node_modules') {
            continue
        }
        $childDestination = Join-Path $Destination $child.Name
        if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            Copy-MaterializedItem $child.FullName $childDestination -PackageRoot:$child.PSIsContainer
        } elseif ($child.PSIsContainer) {
            Copy-MaterializedItem $child.FullName $childDestination
        } else {
            Copy-MaterializedItem $child.FullName $childDestination
        }
    }
}

function Remove-LinkOnly([IO.FileSystemInfo]$Item) {
    if (-not ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Refusing to unlink a non-link: $($Item.FullName)"
    }
    if ($Item.PSIsContainer) {
        [IO.Directory]::Delete($Item.FullName)
    } else {
        [IO.File]::Delete($Item.FullName)
    }
}

function Materialize-StagedLinks([string]$NodeModules, [Collections.IDictionary]$WorkspacePackages) {
    $nodeModulesFull = Get-FullProviderPath $NodeModules -MustExist
    $virtualStore = Join-Path $nodeModulesFull '.pnpm'
    $count = 0
    while ($true) {
        $link = Get-FirstReparsePoint $nodeModulesFull $virtualStore
        if ($null -eq $link) { break }
        $count++
        if ($count -gt 20000) {
            throw "Too many links while materializing $nodeModulesFull; possible link cycle."
        }

        $relative = [IO.Path]::GetRelativePath($nodeModulesFull, $link.FullName)
        $segments = $relative -split '[\\/]'
        $binIndex = [Array]::IndexOf($segments, '.bin')
        if ($binIndex -ge 0) {
            $binPath = $nodeModulesFull
            for ($index = 0; $index -le $binIndex; $index++) {
                $binPath = Join-Path $binPath $segments[$index]
            }
            if (-not (Test-IsWithin $nodeModulesFull $binPath)) {
                throw "Refusing to remove .bin outside staged node_modules: $binPath"
            }
            Remove-Item -LiteralPath $binPath -Recurse -Force
            continue
        }

        $destination = $link.FullName
        $target = Resolve-LinkTargetPath $link
        $isDirectory = $link.PSIsContainer
        if ($isDirectory) {
            $targetManifestPath = Join-Path $target 'package.json'
            if (Test-Path -LiteralPath $targetManifestPath) {
                $targetManifest = Get-Content -LiteralPath $targetManifestPath -Raw | ConvertFrom-Json
                $targetNameProperty = $targetManifest.PSObject.Properties['name']
                $targetName = if ($null -ne $targetNameProperty) { [string]$targetNameProperty.Value } else { '' }
                if ($targetName -and $WorkspacePackages.Contains($targetName)) {
                    $expectedTarget = Get-FullProviderPath ([string]$WorkspacePackages[$targetName]) -MustExist
                    if (-not (Test-SamePath $target $expectedTarget)) {
                        throw "Staged workspace package $targetName points to $target; expected exact source $expectedTarget."
                    }
                }
            }
        }
        Remove-LinkOnly $link
        Copy-MaterializedItem $target $destination -PackageRoot:$isDirectory
    }
    Write-Host "Materialized $count staged pnpm link(s); no installed checkout tree was moved."
}

function Assert-NoReparsePoints([string]$Root) {
    $link = Get-FirstReparsePoint $Root
    if ($null -ne $link) {
        throw "Runtime is not movable; a filesystem link remains: $($link.FullName)"
    }
}

function Assert-NoReparsePointInPath([string]$Path) {
    $item = Get-Item -LiteralPath (Get-FullProviderPath $Path -MustExist) -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Path must not traverse a filesystem link: $($item.FullName)"
        }
        $item = $item.Parent
    }
}

function Resolve-InstalledWorkspaceCommand(
    [string]$SourceRoot,
    [ValidatePattern('^[a-z0-9-]+$')]
    [string]$Name
) {
    $sourceFull = Get-FullProviderPath $SourceRoot -MustExist
    $command = Get-FullProviderPath (
        Join-Path $sourceFull ("node_modules\.bin\{0}.CMD" -f $Name)) -MustExist
    if (-not (Test-IsWithin $sourceFull $command) -or
        -not (Test-Path -LiteralPath $command -PathType Leaf)) {
        throw "Installed workspace command escapes the patched staging source: $Name"
    }
    $item = Get-Item -LiteralPath $command -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        $item.Length -le 0 -or $item.Length -gt 64KB) {
        throw "Installed workspace command is not a bounded regular shim: $Name"
    }
    return $command
}

function Assert-NativeToolPathBudget(
    [string]$SourceRoot,
    [string[]]$RelativeNativeToolPaths = @($ReviewedLongestNativeToolRelativePath)
) {
    $source = Get-FullProviderPath $SourceRoot
    $maximumObserved = 0
    foreach ($relativePath in $RelativeNativeToolPaths) {
        if (-not $relativePath -or [IO.Path]::IsPathFullyQualified($relativePath)) {
            throw "Native-tool budget paths must be non-empty and relative: $relativePath"
        }
        $candidate = Get-FullProviderPath (Join-Path $source $relativePath)
        if (-not (Test-IsWithin $source $candidate)) {
            throw "Native-tool budget path escapes the staged source: $relativePath"
        }
        $maximumObserved = [Math]::Max($maximumObserved, $candidate.Length)
        if ($candidate.Length -ge $MaximumNativeToolPathLengthExclusive) {
            throw "Staged native-tool path is $($candidate.Length) characters; it must remain below $MaximumNativeToolPathLengthExclusive for reliable Windows process launch: $candidate"
        }
    }
    Write-Host "Planned longest reviewed native-tool path: $maximumObserved/$($MaximumNativeToolPathLengthExclusive - 1) characters."
}

function Assert-InstalledNativeToolPathBudget([string]$SourceRoot) {
    $source = Get-FullProviderPath $SourceRoot -MustExist
    Assert-NativeToolPathBudget $source
    $reviewedTool = Get-FullProviderPath (
        Join-Path $source $ReviewedLongestNativeToolRelativePath) -MustExist
    if (-not (Test-Path -LiteralPath $reviewedTool -PathType Leaf)) {
        throw "Reviewed tsgolint executable is missing after frozen install: $reviewedTool"
    }

    $executables = @(Get-ChildItem -LiteralPath (Join-Path $source 'node_modules') `
        -Filter '*.exe' -File -Force -Recurse)
    if ($executables.Count -eq 0) {
        throw 'Frozen install produced no staged native executables to validate.'
    }
    $longest = $executables |
        Sort-Object { $_.FullName.Length } -Descending |
        Select-Object -First 1
    if ($longest.FullName.Length -ge $MaximumNativeToolPathLengthExclusive) {
        throw "Installed native-tool path is $($longest.FullName.Length) characters; it must remain below $MaximumNativeToolPathLengthExclusive for reliable Windows process launch: $($longest.FullName)"
    }
    Write-Host "Installed native-tool path gate checked $($executables.Count) executable(s); longest is $($longest.FullName.Length)/$($MaximumNativeToolPathLengthExclusive - 1)."
}

function New-ShortSourceStagingRoot(
    [string]$OutRoot,
    [string]$OfficialRoot,
    [string]$LauncherRoot
) {
    $tempParent = Get-FullProviderPath ([IO.Path]::GetTempPath()) -MustExist
    $tempItem = Get-Item -LiteralPath $tempParent -Force
    if (-not $tempItem.PSIsContainer -or
        ($tempItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Windows temp staging parent must be a real directory: $tempParent"
    }
    if (Test-SamePath $tempParent ([IO.Path]::GetPathRoot($tempParent))) {
        throw "Windows temp staging parent cannot be a filesystem root: $tempParent"
    }
    Assert-NoReparsePointInPath $tempParent
    foreach ($protectedRoot in @($OutRoot, $OfficialRoot, $LauncherRoot)) {
        if ((Test-IsWithin $protectedRoot $tempParent) -or
            (Test-IsWithin $tempParent $protectedRoot)) {
            throw "Windows temp staging parent must be disjoint from protected build trees: $tempParent / $protectedRoot"
        }
    }

    for ($attempt = 0; $attempt -lt 32; $attempt++) {
        $leaf = 'edsh-' + [guid]::NewGuid().ToString('N')
        $candidate = Join-Path $tempParent $leaf
        try {
            $created = New-Item -Path $candidate -ItemType Directory -ErrorAction Stop
        } catch {
            if (Test-Path -LiteralPath $candidate) { continue }
            throw
        }

        $root = Get-FullProviderPath $created.FullName -MustExist
        try {
            if (-not (Test-SamePath (Split-Path -Parent $root) $tempParent) -or
                (Split-Path -Leaf $root) -cnotmatch '^edsh-[0-9a-f]{32}$') {
                throw "Short staging root has an unexpected identity: $root"
            }
            Assert-NoReparsePointInPath $root
            Assert-NativeToolPathBudget (Join-Path $root 's')
            return [pscustomobject]@{
                Parent = $tempParent
                Root = $root
                Token = $leaf
            }
        } catch {
            $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction SilentlyContinue
            if ($null -ne $rootItem -and
                -not ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
                (Test-SamePath (Split-Path -Parent $root) $tempParent) -and
                (Split-Path -Leaf $root) -cmatch '^edsh-[0-9a-f]{32}$') {
                [IO.Directory]::Delete($root, $true)
            }
            throw
        }
    }
    throw "Could not reserve a unique short staging directory below $tempParent."
}

function Remove-OwnedBuildDirectory(
    [string]$Path,
    [string]$ExpectedParent,
    [string]$ExpectedLeafPattern
) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $full = Get-FullProviderPath $Path -MustExist
    $parent = Get-FullProviderPath $ExpectedParent -MustExist
    $item = Get-Item -LiteralPath $full -Force
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        -not (Test-SamePath (Split-Path -Parent $full) $parent) -or
        (Split-Path -Leaf $full) -cnotmatch $ExpectedLeafPattern) {
        throw "Refusing unsafe owned-build cleanup: $full"
    }
    Assert-NoReparsePointInPath $full
    Remove-Item -LiteralPath $full -Recurse -Force
}

function Copy-DirectoryContents([string]$Source, [string]$Destination) {
    [IO.Directory]::CreateDirectory($Destination) | Out-Null
    foreach ($item in Get-ChildItem -LiteralPath $Source -Force) {
        Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $Destination $item.Name) -Recurse
    }
}

function Assert-PortableBinShims([string]$NodeModules, [string[]]$ForbiddenRoots) {
    $forbiddenNeedles = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($root in $ForbiddenRoots) {
        if (-not $root) { continue }
        $fullRoot = Get-FullProviderPath $root -MustExist
        $forbiddenNeedles.Add($fullRoot) | Out-Null
        $forbiddenNeedles.Add($fullRoot.Replace('\', '/')) | Out-Null
        $forbiddenNeedles.Add($fullRoot.Replace('\', '\\')) | Out-Null
    }

    foreach ($binDirectory in Get-ChildItem -LiteralPath $NodeModules -Directory -Force -Recurse | Where-Object Name -CEQ '.bin') {
        foreach ($file in Get-ChildItem -LiteralPath $binDirectory.FullName -File -Force) {
            $content = [IO.File]::ReadAllText($file.FullName)
            if ($content.IndexOf('.pnpm', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                throw "Runtime command shim still references the removed pnpm virtual store: $($file.FullName)"
            }
            foreach ($needle in $forbiddenNeedles) {
                if ($content.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    throw "Runtime command shim contains a build-machine path: $($file.FullName)"
                }
            }
        }
    }
}

function Normalize-GeneratedBinShimTargetComments([string]$NodeModules) {
    $nodeModulesFull = Get-FullProviderPath $NodeModules -MustExist
    $markerPattern = '(?m)^(?<prefix>[ \t]*# cmd-shim-target=)(?<target>[^\r\n]+)(?<lineEnding>\r?)$'
    $count = 0
    $utf8 = [Text.UTF8Encoding]::new($false)
    foreach ($binDirectory in Get-ChildItem -LiteralPath $nodeModulesFull -Directory -Force -Recurse | Where-Object Name -CEQ '.bin') {
        foreach ($file in Get-ChildItem -LiteralPath $binDirectory.FullName -File -Force) {
            $text = [IO.File]::ReadAllText($file.FullName)
            $matches = @([Regex]::Matches($text, $markerPattern))
            if ($matches.Count -eq 0) { continue }

            $normalized = $text
            foreach ($match in $matches) {
                $targetText = $match.Groups['target'].Value
                if ($targetText.StartsWith('<runtime>/node_modules/', [StringComparison]::Ordinal)) {
                    continue
                }

                $targetNative = $targetText.Replace('/', [IO.Path]::DirectorySeparatorChar)
                if (-not [IO.Path]::IsPathFullyQualified($targetNative)) {
                    throw "Runtime command shim contains an unreviewed target marker: $($file.FullName)"
                }
                $targetFull = Get-FullProviderPath $targetNative -MustExist
                if (-not (Test-IsWithin $nodeModulesFull $targetFull)) {
                    throw "Runtime command shim target escapes staged node_modules: $($file.FullName)"
                }
                $relativeTarget = [IO.Path]::GetRelativePath($nodeModulesFull, $targetFull) -replace '\\', '/'
                if (-not $relativeTarget -or $relativeTarget -eq '..' -or
                    $relativeTarget.StartsWith('../', [StringComparison]::Ordinal) -or
                    [IO.Path]::IsPathFullyQualified($relativeTarget)) {
                    throw "Runtime command shim target cannot be made portable: $($file.FullName)"
                }

                $replacement = $match.Groups['prefix'].Value +
                    '<runtime>/node_modules/' + $relativeTarget +
                    $match.Groups['lineEnding'].Value
                $normalized = $normalized.Replace($match.Value, $replacement)
                $count++
            }

            if ($normalized -cne $text) {
                [IO.File]::WriteAllText($file.FullName, $normalized, $utf8)
            }
        }
    }
    Write-Host "Normalized $count generated command-shim target comment(s)."
    return $count
}

function Normalize-SourceBuildRegionComments([string]$Root, [string]$SourceRoot) {
    $source = Get-FullProviderPath $SourceRoot -MustExist
    $pattern = '(?m)^(?<prefix>[ \t]*//#region \\0dsh-(?:css|inline-css):)' +
        [Regex]::Escape($source) + '[\\/]'
    $replacement = '${prefix}<dsh-source>/'
    $count = 0
    $utf8 = [Text.UTF8Encoding]::new($false)
    foreach ($file in Get-ChildItem -LiteralPath $Root -File -Recurse -Filter '*.js') {
        $text = [IO.File]::ReadAllText($file.FullName)
        $matches = [Regex]::Matches($text, $pattern)
        if ($matches.Count -eq 0) { continue }
        $normalized = [Regex]::Replace($text, $pattern, $replacement)
        [IO.File]::WriteAllText($file.FullName, $normalized, $utf8)
        $count += $matches.Count
    }
    Write-Host "Normalized $count source-build-only CSS region comment(s)."
    return $count
}

function Assert-NoEmbeddedBuildRoot([string]$Root, [string[]]$BuildRoots) {
    $needleTexts = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($buildRoot in $BuildRoots) {
        if (-not $buildRoot) { continue }
        $buildRootFull = Get-FullProviderPath $buildRoot -MustExist
        $needleTexts.Add($buildRootFull) | Out-Null
        $needleTexts.Add($buildRootFull.Replace('\', '/')) | Out-Null
        $needleTexts.Add($buildRootFull.Replace('\', '\\')) | Out-Null
    }
    if ($needleTexts.Count -eq 0) { return }

    # Decode every file window using the text encodings that can contain a
    # Windows path. Searching decoded Unicode preserves OrdinalIgnoreCase
    # semantics for non-ASCII checkout paths while still scanning arbitrary
    # binaries and every filename extension.
    $encodingRecords = @(
        [pscustomobject]@{
            Name = 'UTF-8'
            Encoding = [Text.Encoding]::UTF8
            ByteOffsets = @(0)
        },
        [pscustomobject]@{
            Name = 'UTF-16LE'
            Encoding = [Text.Encoding]::Unicode
            ByteOffsets = @(0, 1)
        },
        [pscustomobject]@{
            Name = 'UTF-16BE'
            Encoding = [Text.Encoding]::BigEndianUnicode
            ByteOffsets = @(0, 1)
        })
    $maximumNeedleBytes = [int](
        $encodingRecords |
            ForEach-Object {
                $encoding = $_.Encoding
                $needleTexts | ForEach-Object {
                    $needleText = [string]$_
                    $encoding.GetMaxByteCount($needleText.Length)
                }
            } |
            Measure-Object -Maximum
    ).Maximum
    $buffer = [byte[]]::new(1024 * 1024)

    foreach ($file in Get-ChildItem -LiteralPath $Root -File -Recurse -Force) {
        $stream = [IO.File]::OpenRead($file.FullName)
        try {
            [byte[]]$carry = @()
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $window = [byte[]]::new($carry.Length + $read)
                if ($carry.Length -gt 0) {
                    [Buffer]::BlockCopy($carry, 0, $window, 0, $carry.Length)
                }
                [Buffer]::BlockCopy($buffer, 0, $window, $carry.Length, $read)
                foreach ($encodingRecord in $encodingRecords) {
                    foreach ($byteOffset in $encodingRecord.ByteOffsets) {
                        if ($window.Length -le $byteOffset) { continue }
                        $decodedWindow = $encodingRecord.Encoding.GetString(
                            $window,
                            $byteOffset,
                            $window.Length - $byteOffset)
                        foreach ($needle in $needleTexts) {
                            if ($decodedWindow.IndexOf(
                                    $needle,
                                    [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                                throw "Runtime file contains an embedded build root ($($encodingRecord.Name)): $($file.FullName)"
                            }
                        }
                    }
                }

                $carryLength = [Math]::Min($maximumNeedleBytes - 1, $window.Length)
                $nextCarry = [byte[]]::new($carryLength)
                if ($carryLength -gt 0) {
                    [Buffer]::BlockCopy(
                        $window,
                        $window.Length - $carryLength,
                        $nextCarry,
                        0,
                        $carryLength)
                }
                $carry = $nextCarry
            }
        } finally {
            $stream.Dispose()
        }
    }
}

function Get-RelativeFileName([string]$Root, [string]$Path) {
    return ([IO.Path]::GetRelativePath($Root, $Path) -replace '\\', '/')
}

function Assert-RuntimeFileHashes([string]$Runtime) {
    $runtimeFull = Get-FullProviderPath $Runtime -MustExist
    $manifestPath = Join-Path $runtimeFull 'runtime-files.sha256'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Extracted runtime has no file hash manifest: $manifestPath"
    }

    $listedFiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in [IO.File]::ReadLines($manifestPath)) {
        if ($line -notmatch '^(?<hash>[0-9a-f]{64})  (?<path>.+)$') {
            throw "Malformed runtime hash line: $line"
        }
        $relativePath = $Matches.path -replace '/', [IO.Path]::DirectorySeparatorChar
        if ([IO.Path]::IsPathRooted($relativePath)) {
            throw "Runtime hash manifest contains a rooted path: $relativePath"
        }
        $filePath = Get-FullProviderPath (Join-Path $runtimeFull $relativePath)
        if (-not (Test-IsWithin $runtimeFull $filePath) -or (Test-SamePath $filePath $manifestPath)) {
            throw "Runtime hash manifest contains an unsafe path: $relativePath"
        }
        if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
            throw "Runtime hash manifest references a missing file: $relativePath"
        }
        if (-not $listedFiles.Add($filePath)) {
            throw "Runtime hash manifest repeats a file: $relativePath"
        }
        $actualHash = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -cne $Matches.hash) {
            throw "Runtime hash mismatch for ${relativePath}: expected $($Matches.hash), got $actualHash"
        }
    }

    foreach ($file in Get-ChildItem -LiteralPath $runtimeFull -File -Recurse -Force) {
        if (Test-SamePath $file.FullName $manifestPath) { continue }
        if (-not $listedFiles.Contains((Get-FullProviderPath $file.FullName -MustExist))) {
            throw "Extracted runtime contains an unhashed file: $(Get-RelativeFileName $runtimeFull $file.FullName)"
        }
    }
}

function Invoke-RuntimeSmoke(
    [string]$Runtime,
    [string]$ExpectedVersion,
    [string]$SmokeRoot,
    [string]$Label,
    [string]$WebAuthProtocol
) {
    $runtimeFull = Get-FullProviderPath $Runtime -MustExist
    $runtimeNode = Join-Path $runtimeFull 'node.exe'
    $runtimeEntry = Join-Path $runtimeFull 'node_modules\@deepseek-ai\dsh\lib\bin.js'
    if (-not (Test-Path -LiteralPath $runtimeNode -PathType Leaf) -or
        -not (Test-Path -LiteralPath $runtimeEntry -PathType Leaf)) {
        throw "$Label is missing node.exe or the DSH CLI entry."
    }

    [IO.Directory]::CreateDirectory($SmokeRoot) | Out-Null
    $webSmokePath = Join-Path $SmokeRoot 'web-http-smoke.mjs'
    @'
import { spawn } from 'node:child_process'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { lstatSync, mkdirSync, realpathSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { createServer } from 'node:net'

const [runtimeArg, stateArg, webAuthProtocol] = process.argv.slice(2)
if (!runtimeArg || !stateArg || !['legacy-clean-root-v1', 'browser-launch-cookie-v1'].includes(webAuthProtocol)) {
  throw new Error('usage: web-http-smoke.mjs <runtime> <state> <web-auth-protocol>')
}
const runtime = resolve(runtimeArg)
const state = resolve(stateArg)
mkdirSync(state, { recursive: true })
const workspace = join(state, 'workspace')
mkdirSync(workspace, { recursive: true })
const skillsRoot = join(state, 'skills')
mkdirSync(skillsRoot, { recursive: true })
const skillsRootStatus = lstatSync(skillsRoot)
const canonicalSkillsRoot = realpathSync.native(skillsRoot)
if (!skillsRootStatus.isDirectory() || skillsRootStatus.isSymbolicLink() || canonicalSkillsRoot !== skillsRoot) {
  throw new Error('managed Web smoke skills root must be one canonical non-reparse directory')
}
const node = join(runtime, 'node.exe')
const entry = join(runtime, 'node_modules', '@deepseek-ai', 'dsh', 'lib', 'bin.js')

async function reserveLoopbackPort() {
  const server = createServer()
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen)
    server.listen(0, '127.0.0.1', resolveListen)
  })
  const address = server.address()
  if (!address || typeof address === 'string' || address.port < 1 || address.port > 65535) {
    server.close()
    throw new Error('failed to reserve a canonical loopback port')
  }
  await new Promise((resolveClose, rejectClose) => server.close(error => error ? rejectClose(error) : resolveClose()))
  return address.port
}

const blockedEnvironment = new Set([
  'NODE_OPTIONS', 'NODE_PATH', 'NODE_EXTRA_CA_CERTS',
  'DSH_ENTERPRISE_MANAGED_BOOT', 'DSH_HOME', 'DSH_AGENTS_HOME',
  'ENSOU_DSH_ENTERPRISE_SKILLS_ROOT',
  'DEEPSEEK_API_KEY', 'DEEPSEEK_BASE_URL', 'DEEPSEEK_SEARCH_BASE_URL',
  'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
  'OPENSSL_CONF', 'SSLKEYLOGFILE',
])
const cleanEnvironment = Object.fromEntries(Object.entries(process.env).filter(
  ([key]) => !blockedEnvironment.has(key.toUpperCase()),
))
const proxyPort = await reserveLoopbackPort()
const webPort = await reserveLoopbackPort()
const managedEnvironment = {
  ...cleanEnvironment,
  DSH_ENTERPRISE_MANAGED_BOOT: 'ensou-dsh-launcher/v1',
  DSH_HOME: join(state, '.dsh'),
  DSH_AGENTS_HOME: join(state, '.agents'),
  ENSOU_DSH_ENTERPRISE_SKILLS_ROOT: canonicalSkillsRoot,
  DSH_TELEMETRY_DISABLED: '1',
  DEEPSEEK_BASE_URL: `http://127.0.0.1:${proxyPort}/v1`,
  DEEPSEEK_SEARCH_BASE_URL: `http://127.0.0.1:${proxyPort}/v1`,
  DEEPSEEK_API_KEY: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  NO_PROXY: '127.0.0.1,localhost',
}
const exactArguments = [
  entry, '--profile', 'enterprise-managed',
  '--host', '127.0.0.1', '--port', String(webPort),
]

const maximumDiagnosticCharacters = 16_384
function redactDiagnostic(value) {
  return value
    .replace(/([?&]token=)[^\s)]+/g, '$1<redacted>')
    .slice(-maximumDiagnosticCharacters)
}

const maximumHealthResponseBytes = 1024 * 1024
function decodeCanonicalBase64Url(value, maximumBytes) {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximumBytes * 2 ||
      value.length % 4 === 1 || !/^[A-Za-z0-9_-]+$/.test(value)) return undefined
  const decoded = Buffer.from(value, 'base64url')
  return decoded.length <= maximumBytes && decoded.toString('base64url') === value
    ? decoded
    : undefined
}

function validateBrowserSetCookie(setCookie, authority) {
  const segments = setCookie.split(';')
  const maxAge = segments[1]?.slice(' Max-Age='.length)
  const expires = segments[3]?.slice(' Expires='.length)
  if (segments.length !== 6 || !segments[1]?.startsWith(' Max-Age=') ||
      !/^[1-9][0-9]*$/.test(maxAge) || !Number.isSafeInteger(Number(maxAge)) ||
      segments[2] !== ' Path=/' || !segments[3]?.startsWith(' Expires=') ||
      Number.isNaN(Date.parse(expires)) || segments[4] !== ' HttpOnly' ||
      segments[5] !== ' SameSite=Strict') {
    throw new Error('managed Web browser-token exchange returned unexpected cookie attributes')
  }
  const separator = segments[0].indexOf('=')
  const expectedName = `dsh-auth-${createHash('sha256').update(authority).digest('base64url')}`
  const name = segments[0].slice(0, separator)
  const value = segments[0].slice(separator + 1)
  const parts = value.split('.')
  if (separator <= 0 || name !== expectedName || parts.length !== 3 || parts[0] !== 'v1' ||
      decodeCanonicalBase64Url(parts[1], 2048) === undefined ||
      parts[2].length !== 43 || decodeCanonicalBase64Url(parts[2], 32)?.length !== 32) {
    throw new Error('managed Web browser-token exchange returned a malformed signed cookie')
  }
  return segments[0]
}

async function readBoundedText(response, label) {
  const declared = response.headers.get('content-length')
  if (declared !== null && (!/^[0-9]+$/.test(declared) || Number(declared) > maximumHealthResponseBytes)) {
    throw new Error(`${label} declared an invalid or oversized response`)
  }
  const body = await response.text()
  if (Buffer.byteLength(body, 'utf8') > maximumHealthResponseBytes) {
    throw new Error(`${label} returned an oversized response`)
  }
  return body
}

async function assertHealthyRoot(cleanUrl, cookie, label) {
  const response = await fetch(`${cleanUrl}/`, {
    redirect: 'manual',
    headers: cookie ? { cookie } : undefined,
    signal: AbortSignal.timeout(15_000),
  })
  if (response.status !== 200) {
    throw new Error(`${label} returned HTTP ${response.status}`)
  }
  const html = await readBoundedText(response, label)
  const recognizedTitle = html.includes('<title>DeepSeek Harness</title>') ||
    html.includes('<title>DSH Local Build</title>')
  if (!recognizedTitle || !html.includes('__DSH_BOOT__')) {
    throw new Error(`${label} omitted the reviewed WebUI boot markers`)
  }
}

async function assertAlphaSessionList(cleanUrl, cookie) {
  const rpcId = `source-runtime-health-${Date.now()}`
  const body = JSON.stringify({
    type: 'client-request',
    rpcId,
    method: 'session/list',
    payload: { args: { _request: {} } },
  })
  const response = await fetch(`${cleanUrl}/api/session/list`, {
    method: 'POST',
    redirect: 'manual',
    headers: { cookie, 'content-type': 'application/json' },
    body,
    signal: AbortSignal.timeout(15_000),
  })
  if (response.status < 200 || response.status >= 300 ||
      !response.headers.get('content-type')?.toLowerCase().startsWith('application/json')) {
    throw new Error('managed Web alpha session/list endpoint rejected its reviewed request')
  }
  const raw = await readBoundedText(response, 'managed Web alpha session/list endpoint')
  let envelope
  try {
    envelope = JSON.parse(raw)
  } catch {
    throw new Error('managed Web alpha session/list endpoint returned invalid JSON')
  }
  if (envelope === null || typeof envelope !== 'object' || Array.isArray(envelope) ||
      envelope.type !== 'server-response' || envelope.rpcId !== rpcId ||
      envelope.result?.ok !== true || !Array.isArray(envelope.result?.value?.items)) {
    throw new Error('managed Web alpha session/list endpoint returned an uncorrelated response')
  }
}

async function assertAlphaAuthenticationRejected(cleanUrl, cookie, label) {
  const rootResponse = await fetch(`${cleanUrl}/`, {
    redirect: 'manual',
    headers: cookie ? { cookie } : undefined,
    signal: AbortSignal.timeout(15_000),
  })
  if (rootResponse.status !== 401 || rootResponse.headers.get('location') !== null ||
      rootResponse.headers.getSetCookie().length !== 0) {
    throw new Error(`${label} root was not rejected with an exact cookie-free HTTP 401`)
  }
  await readBoundedText(rootResponse, `${label} root rejection`)

  const rpcId = `source-runtime-rejected-${Date.now()}`
  const headers = { 'content-type': 'application/json' }
  if (cookie) headers.cookie = cookie
  const apiResponse = await fetch(`${cleanUrl}/api/session/list`, {
    method: 'POST',
    redirect: 'manual',
    headers,
    body: JSON.stringify({
      type: 'client-request',
      rpcId,
      method: 'session/list',
      payload: { args: { _request: {} } },
    }),
    signal: AbortSignal.timeout(15_000),
  })
  if (apiResponse.status !== 401 || apiResponse.headers.get('location') !== null ||
      apiResponse.headers.getSetCookie().length !== 0) {
    throw new Error(`${label} session/list was not rejected with an exact cookie-free HTTP 401`)
  }
  await readBoundedText(apiResponse, `${label} session/list rejection`)
}

function assertRefused(label, args, environment, expected) {
  const result = spawnSync(node, args, {
    cwd: workspace,
    env: environment,
    windowsHide: true,
    encoding: 'utf8',
    timeout: 30_000,
  })
  if (result.error) throw new Error(`${label} could not execute: ${result.error.message}`)
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`
  if (result.status === 0 || !output.includes(expected)) {
    throw new Error(
      `${label} was not refused as expected (status=${result.status}):\n${redactDiagnostic(output)}`,
    )
  }
}
const noSignalEnvironment = { ...managedEnvironment }
delete noSignalEnvironment.DSH_ENTERPRISE_MANAGED_BOOT
assertRefused(
  'managed profile without Launcher signal', exactArguments, noSignalEnvironment,
  'requires the enterprise Launcher',
)
assertRefused(
  'wrong profile under Launcher signal',
  [entry, '--profile', 'web', '--host', '127.0.0.1', '--port', String(webPort)],
  managedEnvironment,
  'may boot only profile',
)
assertRefused(
  'extra managed Web argument', [...exactArguments, '--trusted-host', 'attacker.example'],
  managedEnvironment,
  'must provide exactly --host 127.0.0.1',
)

const child = spawn(node, exactArguments, {
  cwd: workspace,
  env: managedEnvironment,
  windowsHide: true,
  stdio: ['ignore', 'pipe', 'pipe'],
})

let output = ''
let readyTimer
const ready = new Promise((resolveReady, rejectReady) => {
  readyTimer = setTimeout(() => {
    rejectReady(new Error(
      `dsh web did not become ready in 90 seconds:\n${redactDiagnostic(output)}`,
    ))
  }, 90_000)
  const onData = (chunk) => {
    output = (output + chunk.toString()).slice(-maximumDiagnosticCharacters)
    const match = webAuthProtocol === 'browser-launch-cookie-v1'
      ? /dsh web: (http:\/\/127\.0\.0\.1:\d+\/\?token=[A-Za-z0-9_-]{43})(?:\r?\n|$)/.exec(output)
      : /dsh web: (http:\/\/127\.0\.0\.1:\d+)(?:\r?\n|$)/.exec(output)
    if (match?.[1]) {
      clearTimeout(readyTimer)
      resolveReady(match[1])
    }
  }
  child.stdout.on('data', onData)
  child.stderr.on('data', onData)
  child.once('error', rejectReady)
  child.once('exit', (code, signal) => {
    rejectReady(new Error(
      `dsh web exited before readiness with code=${code} signal=${signal}:\n${redactDiagnostic(output)}`,
    ))
  })
})

let primaryError
let launchUrl = ''
try {
  launchUrl = await ready
  const cleanUrl = `http://127.0.0.1:${webPort}`
  if (webAuthProtocol === 'legacy-clean-root-v1' && launchUrl !== cleanUrl) {
    throw new Error(`managed Web reported unexpected URL ${redactDiagnostic(launchUrl)}`)
  }
  if (webAuthProtocol === 'browser-launch-cookie-v1') {
    if (!launchUrl.startsWith(`${cleanUrl}/?token=`)) {
      throw new Error('managed Web reported a browser token outside the expected loopback authority')
    }
    async function exchangeBrowserCookie() {
      const exchange = await fetch(launchUrl, {
        redirect: 'manual',
        signal: AbortSignal.timeout(15_000),
      })
      const setCookies = exchange.headers.getSetCookie()
      if (exchange.status !== 303 || exchange.headers.get('location') !== '/' ||
          exchange.headers.get('cache-control') !== 'no-store' ||
          exchange.headers.get('referrer-policy') !== 'no-referrer' || setCookies.length !== 1) {
        throw new Error('managed Web browser-token exchange violated the reviewed 303 contract')
      }
      return validateBrowserSetCookie(setCookies[0], `127.0.0.1:${webPort}`)
    }
    await assertAlphaAuthenticationRejected(cleanUrl, undefined, 'anonymous Host')
    const hostCookie = await exchangeBrowserCookie()
    const forgedHostCookie = `${hostCookie.slice(0, -1)}${hostCookie.endsWith('A') ? 'B' : 'A'}`
    await assertAlphaAuthenticationRejected(cleanUrl, forgedHostCookie, 'forged-cookie Host')
    await assertHealthyRoot(cleanUrl, hostCookie, 'authenticated Host root')
    await assertAlphaSessionList(cleanUrl, hostCookie)
    // The Launcher first exchanges the token for its in-memory health cookie,
    // then gives the same process-scoped URL to the employee's browser. Prove
    // the reviewed upstream alpha keeps that launch token replayable.
    const browserReplayCookie = await exchangeBrowserCookie()
    await assertHealthyRoot(cleanUrl, browserReplayCookie, 'browser replay root')
  } else {
    await assertHealthyRoot(cleanUrl, undefined, 'legacy clean root')
  }
} catch (error) {
  const diagnostic = error instanceof Error ? error.message : String(error)
  primaryError = new Error(redactDiagnostic(diagnostic))
} finally {
  launchUrl = ''
  output = ''
  clearTimeout(readyTimer)
  if (child.pid && child.exitCode === null && child.signalCode === null) {
    const closed = new Promise(resolveClose => child.once('close', resolveClose))
    child.kill()
    await Promise.race([
      closed,
      new Promise((_, rejectClose) => setTimeout(() => rejectClose(new Error('dsh web did not stop in 10 seconds')), 10_000)),
    ])
  }
}
if (primaryError) throw primaryError
'@ | Set-Content -LiteralPath $webSmokePath -Encoding utf8

    $stateRoot = Join-Path $SmokeRoot 'state'
    $oldDshHome = $env:DSH_HOME
    $oldAgentsHome = $env:DSH_AGENTS_HOME
    $oldSmokePath = $env:Path
    $oldNodePath = $env:NODE_PATH
    $oldNodeOptions = $env:NODE_OPTIONS
    $oldNodeExtraCaCerts = $env:NODE_EXTRA_CA_CERTS
    $oldDeepSeekKey = $env:DEEPSEEK_API_KEY
    try {
        $env:Path = $runtimeFull + [IO.Path]::PathSeparator + [Environment]::SystemDirectory
        $env:NODE_PATH = $null
        $env:NODE_OPTIONS = $null
        $env:NODE_EXTRA_CA_CERTS = $null
        $env:DEEPSEEK_API_KEY = 'source-runtime-smoke-no-call'
        $env:DSH_HOME = Join-Path $stateRoot '.dsh-dump'
        $env:DSH_AGENTS_HOME = Join-Path $stateRoot '.agents-dump'
        Push-Location $runtimeFull
        try {
            $smokeVersion = Invoke-Captured $runtimeNode @($runtimeEntry, '--version') "$Label version smoke"
            if ($smokeVersion -cne $ExpectedVersion) {
                throw "$Label reports $smokeVersion instead of $ExpectedVersion."
            }
            Invoke-Checked $runtimeNode @('-e', "require('node-pty'); require('koffi')") "$Label native module smoke"
            $dump = Invoke-Captured $runtimeNode @($runtimeEntry, 'web', '--dump-config') "$Label Web profile config smoke"
            if (-not $dump) { throw "$Label Web profile dump returned no configuration." }
            Invoke-Checked $runtimeNode @(
                $webSmokePath,
                $runtimeFull,
                (Join-Path $stateRoot 'web'),
                $WebAuthProtocol) "$Label Web HTTP smoke"
        } finally {
            Pop-Location
        }
    } finally {
        $env:DSH_HOME = $oldDshHome
        $env:DSH_AGENTS_HOME = $oldAgentsHome
        $env:DEEPSEEK_API_KEY = $oldDeepSeekKey
        $env:NODE_OPTIONS = $oldNodeOptions
        $env:NODE_PATH = $oldNodePath
        $env:NODE_EXTRA_CA_CERTS = $oldNodeExtraCaCerts
        $env:Path = $oldSmokePath
    }
}

function Get-LockedPackageIdentities([string]$Lockfile) {
    $identities = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $inPackages = $false
    foreach ($line in [IO.File]::ReadLines($Lockfile)) {
        if ($line -ceq 'packages:') {
            $inPackages = $true
            continue
        }
        if (-not $inPackages) { continue }
        if ($line -match '^\S') { break }
        if ($line -notmatch '^  (?<key>.+):$') { continue }
        $key = $Matches.key.Trim()
        if (($key.StartsWith("'", [StringComparison]::Ordinal) -and $key.EndsWith("'", [StringComparison]::Ordinal)) -or
            ($key.StartsWith('"', [StringComparison]::Ordinal) -and $key.EndsWith('"', [StringComparison]::Ordinal))) {
            $key = $key.Substring(1, $key.Length - 2)
        }
        $separator = $key.LastIndexOf('@')
        if ($separator -le 0 -or $separator -eq $key.Length - 1) { continue }
        $name = $key.Substring(0, $separator)
        $version = $key.Substring($separator + 1)
        if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$') { continue }
        [void]$identities.Add("$name@$version")
    }
    if ($identities.Count -eq 0) {
        throw "Could not read any package identities from lockfile packages section: $Lockfile"
    }
    return ,$identities
}

function Get-CheckoutFilesystemInventorySha256(
    [string]$Root,
    [Collections.Generic.Dictionary[string, string]]$Records = $null
) {
    $rootFull = Get-FullProviderPath $Root -MustExist
    $hash = [Security.Cryptography.IncrementalHash]::CreateHash(
        [Security.Cryptography.HashAlgorithmName]::SHA256)
    $utf8 = [Text.UTF8Encoding]::new($false)
    $queue = [Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($rootFull)
    try {
        while ($queue.Count -gt 0) {
            $directory = $queue.Dequeue()
            foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force | Sort-Object Name)) {
                $relative = Get-RelativeFileName $rootFull $item.FullName
                if ($relative -ceq '.git' -or $relative.StartsWith('.git/', [StringComparison]::Ordinal)) {
                    continue
                }
                $isLink = [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
                $kind = if ($item.PSIsContainer) { 'd' } else { 'f' }
                $length = if ($item.PSIsContainer) { 0L } else { [int64]$item.Length }
                $linkTarget = if ($isLink) { [string]$item.LinkTarget } else { '' }
                $record = "{0}`0{1}`0{2}`0{3}`0{4}`0{5}`n" -f
                    $relative,
                    $kind,
                    ([int64]$item.Attributes),
                    $length,
                    $item.LastWriteTimeUtc.Ticks,
                    $linkTarget
                if ($null -ne $Records) {
                    if ($Records.ContainsKey($relative)) {
                        throw "Duplicate checkout inventory path: $relative"
                    }
                    $Records.Add($relative, $record)
                }
                $hash.AppendData($utf8.GetBytes($record))
                if ($item.PSIsContainer -and -not $isLink) { $queue.Enqueue($item.FullName) }
            }
        }
        return [Convert]::ToHexString($hash.GetHashAndReset()).ToLowerInvariant()
    } finally {
        $hash.Dispose()
    }
}

function Get-CheckoutFilesystemInventoryPathUnion(
    [Collections.Generic.IDictionary[string, string]]$ExpectedRecords,
    [Collections.Generic.IDictionary[string, string]]$CurrentRecords
) {
    $paths = [Collections.Generic.SortedSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($relative in $ExpectedRecords.Keys) {
        [void]$paths.Add([string]$relative)
    }
    foreach ($relative in $CurrentRecords.Keys) {
        [void]$paths.Add([string]$relative)
    }
    return [string[]]@($paths)
}

function Assert-CheckoutFilesystemInventoryUnchanged([string]$Context) {
    $currentRecords = [Collections.Generic.Dictionary[string, string]]::new(
        [StringComparer]::Ordinal)
    $currentSha256 = Get-CheckoutFilesystemInventorySha256 `
        $officialCheckout $currentRecords
    if ($currentSha256 -ceq $officialFilesystemInventorySha256) {
        return
    }

    $allPaths = @(Get-CheckoutFilesystemInventoryPathUnion `
        $officialFilesystemInventoryRecords $currentRecords)
    $changedCount = 0
    $changedRecords = [Collections.Generic.List[string]]::new()
    foreach ($relative in $allPaths) {
        $before = if ($officialFilesystemInventoryRecords.ContainsKey($relative)) {
            $officialFilesystemInventoryRecords[$relative]
        } else {
            '<missing>'
        }
        $after = if ($currentRecords.ContainsKey($relative)) {
            $currentRecords[$relative]
        } else {
            '<missing>'
        }
        if ($before -ceq $after) { continue }
        $changedCount++
        if ($changedRecords.Count -lt 20) {
            $beforeDisplay = $before.Replace("`0", '|').TrimEnd("`r", "`n")
            $afterDisplay = $after.Replace("`0", '|').TrimEnd("`r", "`n")
            $changedRecords.Add("$relative :: before=[$beforeDisplay] after=[$afterDisplay]")
        }
    }
    $details = if ($changedRecords.Count -gt 0) {
        "`n" + ($changedRecords -join "`n")
    } else {
        ''
    }
    throw "Official Harness checkout filesystem inventory changed $Context " +
        "(expected sha256=$officialFilesystemInventorySha256 records=$($officialFilesystemInventoryRecords.Count); " +
        "current sha256=$currentSha256 records=$($currentRecords.Count); " +
        "$changedCount changed record(s); first $($changedRecords.Count) shown).$details"
}

function Assert-NoBuildToolingInRuntime([string]$Root) {
    $runtimeFull = Get-FullProviderPath $Root -MustExist
    $forbiddenFileNames = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @(
        'git', 'git.exe', 'git.cmd', 'git.ps1',
        'patch', 'patch.exe', 'patch.cmd', 'patch.ps1',
        'pnpm', 'pnpm.exe', 'pnpm.cmd', 'pnpm.ps1',
        'npm', 'npm.exe', 'npm.cmd', 'npm.ps1',
        'npx', 'npx.exe', 'npx.cmd', 'npx.ps1',
        'corepack', 'corepack.exe', 'corepack.cmd', 'corepack.ps1',
        'ManagedSourcePatch.psm1', '0001-ensou-enterprise-managed-boot.patch')) {
        [void]$forbiddenFileNames.Add($name)
    }
    foreach ($item in Get-ChildItem -LiteralPath $runtimeFull -Force -Recurse) {
        if ($item.PSIsContainer -and $item.Name -in @('.git', 'upstream-patches')) {
            throw "Runtime contains a build-only source directory: $($item.FullName)"
        }
        if (-not $item.PSIsContainer -and (
            $forbiddenFileNames.Contains($item.Name) -or
            $item.Extension -in @('.patch', '.rej', '.orig'))) {
            throw "Runtime contains build/patch tooling input: $($item.FullName)"
        }
    }
}

function Assert-ManagedTestDependencyBoundary([string]$SourceRoot) {
    $testDependency = '@deepseek-ai/dsh-session-persistence-jsonl'
    foreach ($relativeManifest in @(
        'packages/sandbox/sandbox-policy/package.json',
        'packages/fs/tool-fs/package.json',
        'packages/shell/tool-pwsh/package.json')) {
        $manifestPath = Join-Path $SourceRoot ($relativeManifest -replace '/', '\')
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 20
        foreach ($runtimeSectionName in @('dependencies', 'peerDependencies', 'optionalDependencies')) {
            $runtimeSection = $manifest.PSObject.Properties[$runtimeSectionName]
            if ($null -ne $runtimeSection -and
                $null -ne $runtimeSection.Value.PSObject.Properties[$testDependency]) {
                throw "$relativeManifest must not expose test-only $testDependency through $runtimeSectionName."
            }
        }
        $devSection = $manifest.PSObject.Properties['devDependencies']
        $devDependency = if ($null -ne $devSection) {
            $devSection.Value.PSObject.Properties[$testDependency]
        } else {
            $null
        }
        if ($null -eq $devDependency -or [string]$devDependency.Value -cne 'workspace:^') {
            throw "$relativeManifest must pin test-only $testDependency as exactly workspace:^ in devDependencies."
        }
    }
}

try {
$env:NODE_PATH = $null
$env:NODE_OPTIONS = $null
$env:NODE_EXTRA_CA_CERTS = $null
$officialCheckout = Get-FullProviderPath $HarnessCheckout -MustExist
$out = Get-FullProviderPath $OutDir
if (Test-SamePath $out ([IO.Path]::GetPathRoot($out))) {
    throw "OutDir cannot be a filesystem root: $out"
}
if ((Test-IsWithin $officialCheckout $out) -or (Test-IsWithin $out $officialCheckout)) {
    throw "OutDir and the Harness checkout must be separate trees so build outputs cannot contaminate source provenance: $out"
}
Assert-NoReparsePointInPath $officialCheckout
if ($env:OS -ne 'Windows_NT') {
    throw 'This builder only produces the Windows x64 runtime.'
}

$git = Resolve-CommandPath '' @('git.exe', 'git') 'Git'
$officialGitPrefix = @(
    '-c', 'core.longpaths=true',
    '-c', "safe.directory=$($officialCheckout.Replace('\', '/'))",
    '-C', $officialCheckout)
function Invoke-OfficialGitCaptured([string[]]$Arguments, [string]$Label) {
    return Invoke-Captured $git ($officialGitPrefix + $Arguments) $Label
}
function Invoke-OfficialGitExit([string[]]$Arguments) {
    & $git @officialGitPrefix @Arguments *> $null
    return $LASTEXITCODE
}
function Assert-OfficialCheckoutIdentity {
    $topLevel = Invoke-OfficialGitCaptured @('rev-parse', '--show-toplevel') 'locate official Git checkout'
    if (-not (Test-SamePath $officialCheckout $topLevel)) {
        throw "HarnessCheckout must be the repository root. Expected $officialCheckout, Git reported $topLevel."
    }
    $currentOrigin = Invoke-OfficialGitCaptured @('remote', 'get-url', 'origin') 'read official origin URL'
    if ($currentOrigin -notin $allowedOrigins) {
        throw "origin is not the official DeepSeek Harness repository: $currentOrigin"
    }
    $currentHead = (Invoke-OfficialGitCaptured @('rev-parse', 'HEAD') 'resolve official HEAD').ToLowerInvariant()
    $currentTree = (Invoke-OfficialGitCaptured @('rev-parse', 'HEAD^{tree}') 'resolve official tree').ToLowerInvariant()
    $currentTagCommit = (Invoke-OfficialGitCaptured @('rev-parse', '--verify', "$OfficialTag^{commit}") 'resolve official tag').ToLowerInvariant()
    if ($currentHead -cne $OfficialCommit -or $currentTree -cne $OfficialTree -or
        $currentTagCommit -cne $OfficialCommit) {
        throw "Official checkout identity changed: HEAD=$currentHead tree=$currentTree tag=$currentTagCommit."
    }
    $status = Invoke-OfficialGitCaptured @('status', '--porcelain=v1', '--untracked-files=all') 'official git status'
    if ($status) {
        throw "Harness checkout is not clean. Commit/stash/remove every tracked and untracked change before building:`n$status"
    }
}

$allowedOrigins = @(
    $OfficialRepository,
    'git@github.com:deepseek-ai/deepseek-harness.git',
    'ssh://git@github.com/deepseek-ai/deepseek-harness.git'
)
$OfficialCommit = $OfficialCommit.ToLowerInvariant()
$head = (Invoke-OfficialGitCaptured @('rev-parse', 'HEAD') 'resolve HEAD').ToLowerInvariant()
if ($head -cne $OfficialCommit) {
    throw "HEAD is $head, not requested commit $OfficialCommit."
}
$OfficialTree = (Invoke-OfficialGitCaptured @('rev-parse', 'HEAD^{tree}') 'resolve official base tree').ToLowerInvariant()
if ((Invoke-OfficialGitExit @('show-ref', '--verify', '--quiet', "refs/tags/$OfficialTag")) -ne 0) {
    throw "Official tag is absent from the checkout: $OfficialTag"
}
$tagCommit = (Invoke-OfficialGitCaptured @('rev-parse', '--verify', "$OfficialTag^{commit}") 'resolve official tag').ToLowerInvariant()
if ($tagCommit -cne $OfficialCommit) {
    throw "Tag $OfficialTag resolves to $tagCommit, not requested commit $OfficialCommit."
}

Write-Step '1/10 validate the exact official base and installation-owned managed patch'
$managedPatch = Get-ManagedSourcePatchBundle `
    -IndexPath $ManagedPatchIndexPath `
    -Repository $OfficialRepository `
    -Tag $OfficialTag `
    -Commit $OfficialCommit `
    -Tree $OfficialTree `
    -PatchVariant $PatchVariant
Assert-OfficialCheckoutIdentity
Assert-ManagedSourcePreimages -Bundle $managedPatch -Checkout $officialCheckout -Git $git
$officialFilesystemInventoryRecords = [Collections.Generic.Dictionary[string, string]]::new(
    [StringComparer]::Ordinal)
$officialFilesystemInventorySha256 = Get-CheckoutFilesystemInventorySha256 `
    $officialCheckout $officialFilesystemInventoryRecords
$officialGitDirectory = Invoke-OfficialGitCaptured @('rev-parse', '--absolute-git-dir') 'locate official Git metadata'
if (-not (Test-Path -LiteralPath $officialGitDirectory -PathType Container)) {
    throw "Official checkout must use an on-disk .git directory for isolated copy: $officialGitDirectory"
}
$officialCommonDirectoryMarker = Join-Path $officialGitDirectory 'commondir'
if (Test-Path -LiteralPath $officialCommonDirectoryMarker) {
    throw 'Official checkout is a linked Git worktree. Use an independent clone so the isolated source copy receives a complete object database.'
}
$officialAlternates = Join-Path $officialGitDirectory 'objects\info\alternates'
if (Test-Path -LiteralPath $officialAlternates) {
    throw "Official checkout uses Git object alternates and cannot be copied independently: $officialAlternates"
}
$gitMetadataLink = Get-FirstReparsePoint $officialGitDirectory
if ($null -ne $gitMetadataLink) {
    throw "Official Git metadata contains a reparse point and cannot be copied safely: $($gitMetadataLink.FullName)"
}

$remoteTagOutput = Invoke-Captured $git @(
    'ls-remote',
    '--exit-code',
    $OfficialRepository,
    "refs/tags/$OfficialTag",
    "refs/tags/$OfficialTag^{}"
) 'verify tag against the official GitHub remote'
$remoteRefs = @{}
foreach ($line in ($remoteTagOutput -split "`r?`n")) {
    if ($line -match '^(?<commit>[0-9a-fA-F]{40})\s+(?<ref>refs/tags/.+)$') {
        $remoteRefs[$Matches.ref] = $Matches.commit.ToLowerInvariant()
    }
}
$peeledRemoteRef = "refs/tags/$OfficialTag^{}"
$directRemoteRef = "refs/tags/$OfficialTag"
$remoteTagCommit = if ($remoteRefs.ContainsKey($peeledRemoteRef)) {
    $remoteRefs[$peeledRemoteRef]
} elseif ($remoteRefs.ContainsKey($directRemoteRef)) {
    $remoteRefs[$directRemoteRef]
} else {
    throw "Official GitHub did not return tag $OfficialTag."
}
if ($remoteTagCommit -cne $OfficialCommit) {
    throw "Official GitHub tag $OfficialTag resolves to $remoteTagCommit, not requested commit $OfficialCommit."
}
Assert-OfficialCheckoutIdentity

$requiredInputs = @(
    'package.json',
    'pnpm-lock.yaml',
    'pnpm-workspace.yaml',
    'apps/cli/package.json',
    'LICENSE',
    'THIRD_PARTY_NOTICES.md'
)
foreach ($relativePath in $requiredInputs) {
    if ((Invoke-OfficialGitExit @('ls-files', '--error-unmatch', '--', $relativePath)) -ne 0) {
        throw "Required source input is not tracked at ${OfficialCommit}: $relativePath"
    }
    $workingBlob = Invoke-OfficialGitCaptured @('hash-object', '--', $relativePath) "hash $relativePath"
    $commitBlob = Invoke-OfficialGitCaptured @('rev-parse', "${OfficialCommit}:$relativePath") "resolve $relativePath at commit"
    if ($workingBlob -cne $commitBlob) {
        throw "$relativePath does not match the exact bytes at $OfficialCommit."
    }
}

$baseRootManifest = Get-Content -LiteralPath (Join-Path $officialCheckout 'package.json') -Raw | ConvertFrom-Json
$baseCliManifest = Get-Content -LiteralPath (Join-Path $officialCheckout 'apps\cli\package.json') -Raw | ConvertFrom-Json
$dshVersion = [string]$baseRootManifest.version
if ($OfficialTag -cne "dsh-v$dshVersion") {
    throw "Tag $OfficialTag does not match package version $dshVersion (expected dsh-v$dshVersion)."
}
if ([string]$baseCliManifest.version -cne $dshVersion) {
    throw "apps/cli version $($baseCliManifest.version) does not match root version $dshVersion."
}
if ([string]$baseRootManifest.license -cne 'MIT' -or [string]$baseCliManifest.license -cne 'MIT') {
    throw 'The checked source no longer declares MIT for the root and dsh CLI; review licensing before packaging.'
}
if ([string]$baseRootManifest.engines.node -cne $ExpectedEngine) {
    throw "Unsupported upstream Node engine expression '$($baseRootManifest.engines.node)'; review this builder before using a changed engine contract."
}
if (-not ([string]$baseRootManifest.scripts.build)) {
    throw 'The upstream root package has no build script.'
}

$packageManager = [string]$baseRootManifest.packageManager
if ($packageManager -notmatch '^pnpm@(?<version>[0-9]+\.[0-9]+\.[0-9]+)$') {
    throw "Unsupported packageManager declaration: $packageManager"
}
$expectedPnpmVersion = $Matches.version
$baseLockfilePath = Join-Path $officialCheckout 'pnpm-lock.yaml'
$baseLockfileSha256 = (Get-FileHash -LiteralPath $baseLockfilePath -Algorithm SHA256).Hash.ToLowerInvariant()
$licensePath = Join-Path $officialCheckout 'LICENSE'
$noticesPath = Join-Path $officialCheckout 'THIRD_PARTY_NOTICES.md'
if ((Get-Item -LiteralPath $licensePath).Length -eq 0 -or (Get-Item -LiteralPath $noticesPath).Length -eq 0) {
    throw 'LICENSE and THIRD_PARTY_NOTICES.md must both be non-empty.'
}

Write-Step '2/10 validate the pinned Windows toolchain'
$nodeCommand = Resolve-CommandPath $NodeExe @('node.exe', 'node') 'Node.js'
$resolvedNode = Invoke-Captured $nodeCommand @('-p', 'process.execPath') 'resolve Node executable'
$nodeCommand = Get-FullProviderPath $resolvedNode -MustExist
$nodeDirectory = Split-Path -Parent $nodeCommand
$env:Path = $nodeDirectory + [IO.Path]::PathSeparator + $oldPath
$actualNodeVersion = (Invoke-Captured $nodeCommand @('-p', 'process.versions.node') 'read Node version').Trim()
$nodePlatform = (Invoke-Captured $nodeCommand @('-p', "process.platform + '-' + process.arch") 'read Node platform').Trim()
if ($actualNodeVersion -cne $NodeVersion) {
    throw "Selected Node is $actualNodeVersion, not pinned version $NodeVersion."
}
if ($nodePlatform -cne $Platform) {
    throw "Selected Node is $nodePlatform; this builder requires $Platform."
}
$nodeParts = $actualNodeVersion.Split('.') | ForEach-Object { [int]$_ }
if (-not (($nodeParts[0] -eq 22 -and $nodeParts[1] -ge 19) -or $nodeParts[0] -ge 24)) {
    throw "Node $actualNodeVersion does not satisfy upstream engines.node $ExpectedEngine."
}

$npm = Join-Path $nodeDirectory 'npm.cmd'
if (-not (Test-Path -LiteralPath $npm)) {
    throw "The selected Node distribution must include npm.cmd because upstream's build script calls npm: $npm"
}
$npmVersion = Invoke-Captured $npm @('--version') 'read npm version'
$pnpm = Resolve-CommandPath $PnpmCommand @('pnpm.cmd', 'pnpm') 'pnpm'
$actualPnpmVersion = Invoke-Captured $pnpm @('--version') 'read pnpm version'
if ($actualPnpmVersion -cne $expectedPnpmVersion) {
    throw "pnpm is $actualPnpmVersion, but the exact source declares $packageManager. Use that exact pnpm version."
}
$toolchainProbeDirectory = Join-Path ([IO.Path]::GetTempPath()) (
    'ensou-dsh-toolchain-probe-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($toolchainProbeDirectory) | Out-Null
[IO.File]::WriteAllText(
    (Join-Path $toolchainProbeDirectory 'package.json'),
    '{"private":true}')
try {
    Push-Location $toolchainProbeDirectory
    try {
        # Probe outside the Harness workspace so validation never asks pnpm to
        # reconcile or purge the checkout's node_modules tree.
        $pnpmNode = Invoke-Captured $pnpm @('--reporter=silent', 'exec', 'node', '-p', 'process.execPath') 'verify pnpm Node runtime'
    } finally {
        Pop-Location
    }
} finally {
    Remove-OwnedBuildDirectory $toolchainProbeDirectory ([IO.Path]::GetTempPath()) '^ensou-dsh-toolchain-probe-[0-9a-f]{32}$'
}
if (-not (Test-SamePath $nodeCommand $pnpmNode)) {
    throw "pnpm resolves Node from $pnpmNode instead of the selected $nodeCommand."
}
$nodeSha256 = (Get-FileHash -LiteralPath $nodeCommand -Algorithm SHA256).Hash.ToLowerInvariant()

$baseName = "EnsouDshRuntime-$ReleaseId-win-x64"
$releaseDirectory = Join-Path $out $ReleaseId
$zipName = "$baseName.zip"
$metadataName = "$baseName.metadata.json"
$shaName = "$zipName.sha256"
if (Test-Path -LiteralPath $releaseDirectory) {
    throw "ReleaseId already exists and will never be overwritten: $releaseDirectory"
}

Write-Step '3/10 reserve short disjoint staging and copy the official base independently'
[IO.Directory]::CreateDirectory($out) | Out-Null
$outItem = Get-Item -LiteralPath $out -Force
if ($outItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "OutDir must not be a filesystem link: $out"
}
Assert-NoReparsePointInPath $out
$reservationPath = Join-Path $out ".$ReleaseId.reservation"
try {
    $reservation = [IO.File]::Open(
        $reservationPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
} catch [IO.IOException] {
    throw "ReleaseId is already being built or has a stale reservation: $reservationPath"
}

$shortStaging = New-ShortSourceStagingRoot $out $officialCheckout $LauncherRepositoryRoot
$stagingParent = [string]$shortStaging.Parent
$stagingRoot = [string]$shortStaging.Root
$stagingToken = [string]$shortStaging.Token
$checkout = Join-Path $stagingRoot 's'
$deployRoot = Join-Path $stagingRoot 'd'
$runtimeRoot = Join-Path $stagingRoot 'r'
$productsRoot = Join-Path $out (".{0}.products" -f $stagingToken)
if (Test-Path -LiteralPath $productsRoot) {
    throw "Unique publication staging already exists and will not be overwritten: $productsRoot"
}
$productsItem = New-Item -Path $productsRoot -ItemType Directory -ErrorAction Stop
if ($productsItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "Publication staging must not be a filesystem link: $productsRoot"
}
Assert-NoReparsePointInPath $productsRoot

[ordered]@{
    schemaVersion = 1
    releaseId = $ReleaseId
    localLab = [bool]$LocalLab
    promotionEligible = $promotionEligible
    officialCommit = $OfficialCommit
    plannedOutput = $releaseDirectory
    createdAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
} | ConvertTo-Json | Set-Content -LiteralPath (
    Join-Path $stagingRoot 'build-context.json') -Encoding utf8

[IO.Directory]::CreateDirectory($checkout) | Out-Null
Copy-Item -LiteralPath $officialGitDirectory -Destination (Join-Path $checkout '.git') -Recurse
$trackedSourceFiles = Invoke-OfficialGitCaptured @('ls-files') 'enumerate exact official tracked files'
foreach ($relativePath in ($trackedSourceFiles -split "`r?`n")) {
    if (-not $relativePath) { continue }
    $sourceFile = Get-FullProviderPath (Join-Path $officialCheckout ($relativePath -replace '/', '\')) -MustExist
    $destinationFile = Get-FullProviderPath (Join-Path $checkout ($relativePath -replace '/', '\'))
    if (-not (Test-IsWithin $officialCheckout $sourceFile) -or -not (Test-IsWithin $checkout $destinationFile) -or
        -not (Test-Path -LiteralPath $sourceFile -PathType Leaf)) {
        throw "Official tracked path is unsafe or not a regular file: $relativePath"
    }
    $sourceItem = Get-Item -LiteralPath $sourceFile -Force
    if ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Official tracked file is a reparse point and cannot enter managed staging: $relativePath"
    }
    [IO.Directory]::CreateDirectory((Split-Path -Parent $destinationFile)) | Out-Null
    Copy-Item -LiteralPath $sourceFile -Destination $destinationFile
}
$gitPrefix = @(
    '-c', 'core.longpaths=true',
    '-c', "safe.directory=$($checkout.Replace('\', '/'))",
    '-C', $checkout)
function Invoke-GitCaptured([string[]]$Arguments, [string]$Label) {
    return Invoke-Captured $git ($gitPrefix + $Arguments) $Label
}
function Invoke-GitExit([string[]]$Arguments) {
    & $git @gitPrefix @Arguments *> $null
    return $LASTEXITCODE
}
$stagedHead = (Invoke-GitCaptured @('rev-parse', 'HEAD') 'resolve staged HEAD').ToLowerInvariant()
$stagedTree = (Invoke-GitCaptured @('rev-parse', 'HEAD^{tree}') 'resolve staged base tree').ToLowerInvariant()
$stagedTagCommit = (Invoke-GitCaptured @('rev-parse', "$OfficialTag^{commit}") 'resolve staged tag').ToLowerInvariant()
$stagedOrigin = Invoke-GitCaptured @('remote', 'get-url', 'origin') 'read staged canonical origin'
$stagedStatus = Invoke-GitCaptured @('status', '--porcelain=v1', '--untracked-files=all') 'read staged base status'
if ($stagedHead -cne $OfficialCommit -or $stagedTree -cne $OfficialTree -or
    $stagedTagCommit -cne $OfficialCommit -or $stagedOrigin -notin $allowedOrigins -or $stagedStatus) {
    throw "Staged source is not the exact clean official base: HEAD=$stagedHead tree=$stagedTree tag=$stagedTagCommit origin=$stagedOrigin status=$stagedStatus"
}
[void](Invoke-GitCaptured @('fsck', '--no-dangling') 'verify copied Git object integrity')
Assert-NoReparsePointInPath $checkout
Apply-ManagedSourcePatch -Bundle $managedPatch -Checkout $checkout -Git $git
Assert-ManagedTestDependencyBoundary $checkout

$rootManifest = Get-Content -LiteralPath (Join-Path $checkout 'package.json') -Raw | ConvertFrom-Json
$cliManifestPath = Join-Path $checkout 'apps\cli\package.json'
$cliManifest = Get-Content -LiteralPath $cliManifestPath -Raw | ConvertFrom-Json
if ([string]$rootManifest.version -cne $dshVersion -or
    [string]$cliManifest.version -cne $dshVersion -or
    [string]$rootManifest.packageManager -cne $packageManager -or
    [string]$rootManifest.engines.node -cne $ExpectedEngine -or
    [string]$rootManifest.license -cne 'MIT' -or
    [string]$cliManifest.license -cne 'MIT') {
    throw 'Managed patch changed an unreviewed root/CLI identity, toolchain, engine, or license field.'
}
$lockfilePath = Join-Path $checkout 'pnpm-lock.yaml'
$lockfileSha256 = (Get-FileHash -LiteralPath $lockfilePath -Algorithm SHA256).Hash.ToLowerInvariant()
$patchLockRecord = $managedPatch.FilesByPath['pnpm-lock.yaml']
if ($null -eq $patchLockRecord -or $lockfileSha256 -cne [string]$patchLockRecord.sha256) {
    throw 'Patched pnpm lockfile does not match the reviewed managed patch postimage.'
}
$lockedPackageIdentities = Get-LockedPackageIdentities $lockfilePath
$licensePath = Join-Path $checkout 'LICENSE'
$noticesPath = Join-Path $checkout 'THIRD_PARTY_NOTICES.md'

Assert-OfficialCheckoutIdentity
Assert-CheckoutFilesystemInventoryUnchanged `
    'while creating the patched staging source'

$managedFocusedTestFiles = @(
    'apps/cli/tests/managed-boot.spec.ts',
    'packages/sandbox/sandbox-policy/tests/policy.spec.ts',
    'packages/fs/tool-fs/tests/tools.spec.ts',
    'packages/shell/tool-pwsh/tests/tools.spec.ts'
)
if ($EnterpriseDirectLocal) {
    $managedFocusedTestFiles += @(
        'apps/cli/tests/enterprise-direct-local.spec.ts',
        'apps/cli/tests/managed-runtime-update.spec.ts',
        'packages/host/webserver/tests/webserver.spec.ts',
        'packages/credentials/credentials-local/tests/drain.spec.ts',
        'packages/settings/settings/tests/settings.spec.ts',
        'packages/settings/settings-file/tests/composition-only.spec.ts',
        'packages/client/modules/tests/node-half.client.spec.ts',
        'packages/client/ui-settings-models/tests/readiness.client.spec.ts',
        'packages/client/ui-settings-models/tests/welcome-store.client.spec.ts',
        'packages/client/ui-settings-models/tests/onboarding-dialog.client.spec.tsx'
    )
}
$managedWindowsExcludedTestFiles = @(
    'packages/shell/tool-bash/tests/tools.spec.ts',
    'packages/terminal/terminal-bash/tests/index.spec.ts'
)
$managedTypeScriptFiles = @($managedPatch.Files | ForEach-Object { [string]$_.path } |
    Where-Object { $_.EndsWith('.ts', [StringComparison]::Ordinal) -or
        ($EnterpriseDirectLocal -and $_.EndsWith('.tsx', [StringComparison]::Ordinal)) } | Sort-Object)
$managedChangedFileCount = $managedPatch.Files.Count
$managedModifiedPreimageCount = @(
    $managedPatch.Changes | Where-Object { [string]$_.status -ceq 'M' }).Count
$buildCommands = @(
    'copy exact .git metadata and tracked official files into a unique short Windows-temp staging source (no links or ignored node_modules)',
    "verify exact patch manifest/$managedModifiedPreimageCount preimages; git apply --check --whitespace=error-all; apply; verify $managedChangedFileCount postimages",
    'verify JSONL restore helpers remain test-only devDependencies and never runtime dependencies/peers',
    'pnpm install --frozen-lockfile (patched staging only)',
    'execute exact installed node_modules/.bin/tsc.CMD -b <changed package and CLI projects>',
    'execute exact installed node_modules/.bin/tsdown.CMD --config tsdown.config.ts from apps/cli',
    'execute exact installed node_modules/.bin/tsx.CMD scripts/run-oxlint.ts <changed TypeScript files>',
    'pnpm run verify-config-catalog; verify-cordis-catalog; verify-cordis-api; verify-cordis-config',
    'pnpm run verify-translation-pairing; verify-agent-note-format; verify-agent-note-classification',
    'pnpm run release:verify --family dsh',
    'pnpm run verify-dsh-package-licenses',
    'pnpm run verify-third-party-notices',
    'pnpm run clean',
    'pnpm run build',
    'pnpm run verify-built-package-invariants',
    'execute exact installed node_modules/.bin/vitest.CMD run --testTimeout=15000 <managed Windows-focused tests plus selected direct-mode persistence and update-barrier regressions>',
    'execute exact installed node_modules/.bin/vitest.CMD with a narrow temporary config <two normally Windows-excluded managed policy tests>',
    'pnpm --filter @deepseek-ai/dsh deploy --prod --offline --config.inject-workspace-packages=true --config.node-linker=hoisted --config.auto-install-peers=true --config.link-workspace-packages=true --config.strict-dep-builds=false <staging>',
    'restore required non-optional workspace peer roots from the exact patched source',
    'node node_modules/@deepseek-ai/dsh-subprocess-local/scripts/ensure-spawn-helper.mjs',
    'normalize reviewed source-build comments in CSS regions and command shims, then reject embedded build roots',
    'managed exact environment/profile/no-web argv/workspace-cwd smoke plus refusal smokes'
)

Write-Host "Official base: $OfficialTag / $OfficialCommit / tree $OfficialTree"
Write-Host "Managed patch: $($managedPatch.Id) / manifest $($managedPatch.ManifestSha256) / patch $($managedPatch.PatchSha256)"
Write-Host "DSH: $dshVersion; base lock SHA-256: $baseLockfileSha256; patched lock SHA-256: $lockfileSha256"
Write-Host "Toolchain: Node $actualNodeVersion; pnpm $actualPnpmVersion; npm $npmVersion"
Write-Host "Planned immutable output: $releaseDirectory"
if ($ValidateOnly) {
    Assert-ManagedSourcePostimages -Bundle $managedPatch -Checkout $checkout -Git $git
    Assert-OfficialCheckoutIdentity
    Assert-CheckoutFilesystemInventoryUnchanged 'during validation'
    Write-Host "Validation-only mode proved exact base, patch bytes, $managedModifiedPreimageCount preimages, apply-check/application, $managedChangedFileCount postimages, and toolchain pins." -ForegroundColor Yellow
    Write-Host 'No install, test, build, deploy, or employee artifact was produced; temporary staging will be removed.' -ForegroundColor Yellow
    foreach ($command in $buildCommands) { Write-Host "  $command" }
    $completed = $true
    return
}

function Assert-CheckoutInputsUnchanged {
    Assert-ManagedSourcePostimages -Bundle $managedPatch -Checkout $checkout -Git $git
    $currentHead = (Invoke-GitCaptured @('rev-parse', 'HEAD') 'verify staged HEAD').ToLowerInvariant()
    $currentTree = (Invoke-GitCaptured @('rev-parse', 'HEAD^{tree}') 'verify staged base tree').ToLowerInvariant()
    if ($currentHead -cne $OfficialCommit -or $currentTree -cne $OfficialTree) {
        throw "Patched staging base identity changed: HEAD=$currentHead tree=$currentTree."
    }
    $currentLockSha = (Get-FileHash -LiteralPath $lockfilePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($currentLockSha -cne $lockfileSha256) {
        throw "pnpm-lock.yaml changed during the build ($lockfileSha256 -> $currentLockSha)."
    }
    Assert-OfficialCheckoutIdentity
    Assert-CheckoutFilesystemInventoryUnchanged 'during the staged build'
}

function Get-GitBlobObjectId([byte[]]$Bytes) {
    $length = $Bytes.LongLength.ToString([Globalization.CultureInfo]::InvariantCulture)
    $header = [Text.Encoding]::ASCII.GetBytes("blob $length`0")
    $objectBytes = [byte[]]::new($header.Length + $Bytes.Length)
    [Buffer]::BlockCopy($header, 0, $objectBytes, 0, $header.Length)
    [Buffer]::BlockCopy($Bytes, 0, $objectBytes, $header.Length, $Bytes.Length)
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA1]::HashData($objectBytes)).ToLowerInvariant()
}

function Invoke-ReviewedMaterializedCordisConfigGate {
    $linkRelative = 'apps/cli/tests/profiles/acp/cordis.yml'
    $targetPointer = '../../../../../snapshots/acp/escalation-approved/cordis.yml'
    $expectedTargetRelative = 'snapshots/acp/escalation-approved/cordis.yml'
    $expectedLinkBlob = '8a6e191c8e97ad8f581569c74f922c60aa5797c0'
    $expectedTargetBlob = 'cc8f9609f9ee1ddd230582e1c809ccd2a61018a7'
    $linkPath = Get-FullProviderPath (Join-Path $checkout ($linkRelative -replace '/', '\\')) -MustExist
    $targetPath = Get-FullProviderPath (Join-Path (Split-Path -Parent $linkPath) ($targetPointer -replace '/', '\\')) -MustExist
    if (-not (Test-IsWithin $checkout $linkPath) -or
        -not (Test-IsWithin $checkout $targetPath) -or
        -not (Test-Path -LiteralPath $linkPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
        throw 'Reviewed Cordis source link or target escapes the patched staging source.'
    }
    foreach ($path in @($linkPath, $targetPath)) {
        $item = Get-Item -LiteralPath $path -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Reviewed Cordis source link materialization accepts ordinary staged files only: $path"
        }
    }
    $linkIndex = Invoke-GitCaptured @('ls-files', '-s', '--', $linkRelative) 'verify reviewed Cordis source-link index mode'
    $targetRelative = [IO.Path]::GetRelativePath($checkout, $targetPath).Replace('\', '/')
    $targetIndex = Invoke-GitCaptured @('ls-files', '-s', '--', $targetRelative) 'verify reviewed Cordis target index mode'
    $officialLinkBlob = Invoke-GitCaptured @(
        'rev-parse', "${OfficialCommit}:$linkRelative") 'bind reviewed Cordis source-link blob to official commit'
    $officialTargetBlob = Invoke-GitCaptured @(
        'rev-parse', "${OfficialCommit}:$expectedTargetRelative") 'bind reviewed Cordis target blob to official commit'
    $workingLinkBlob = Invoke-GitCaptured @(
        'hash-object', '--no-filters', '--', $linkPath) 'hash reviewed Cordis staged source-link bytes'
    $workingTargetBlob = Invoke-GitCaptured @(
        'hash-object', '--no-filters', '--', $targetPath) 'hash reviewed Cordis staged target bytes'
    if ($targetRelative -cne $expectedTargetRelative -or
        $linkIndex -cne "120000 $expectedLinkBlob 0`t$linkRelative" -or
        $targetIndex -cne "100644 $expectedTargetBlob 0`t$expectedTargetRelative" -or
        $officialLinkBlob -cne $expectedLinkBlob -or
        $officialTargetBlob -cne $expectedTargetBlob -or
        $workingLinkBlob -cne $expectedLinkBlob -or
        $workingTargetBlob -cne $expectedTargetBlob) {
        throw 'Reviewed Cordis source link or target is not byte-bound to the exact official commit and Git index blobs.'
    }
    $originalBytes = [IO.File]::ReadAllBytes($linkPath)
    $targetBytes = [IO.File]::ReadAllBytes($targetPath)
    if ((Get-GitBlobObjectId $originalBytes) -cne $expectedLinkBlob -or
        (Get-GitBlobObjectId $targetBytes) -cne $expectedTargetBlob) {
        throw 'Reviewed Cordis bytes changed between working-tree identity validation and materialization.'
    }
    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    if ($strictUtf8.GetString($originalBytes) -cne $targetPointer) {
        throw 'Reviewed Cordis source link no longer contains the exact approved relative target.'
    }
    $originalSha256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($originalBytes)).ToLowerInvariant()
    try {
        [IO.File]::WriteAllBytes($linkPath, $targetBytes)
        Invoke-Checked $pnpm @('run', 'verify-cordis-config') 'managed source gate verify-cordis-config'
    } finally {
        [IO.File]::WriteAllBytes($linkPath, $originalBytes)
    }
    $restoredSha256 = (Get-FileHash -LiteralPath $linkPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($restoredSha256 -cne $originalSha256) {
        throw 'Reviewed Cordis source link bytes were not restored after the Windows-only gate.'
    }
    Write-Host 'Materialized and restored 1 reviewed Git source link for the Windows Cordis config gate.'
}

function Get-WorkspacePackageMap {
    $map = @{}
    $files = Invoke-GitCaptured @('ls-files', '--', 'apps', 'packages', 'vendor', 'native') 'enumerate workspace manifests'
    foreach ($relativePath in ($files -split "`r?`n")) {
        if ($relativePath -notmatch '^(?:apps/[^/]+|packages/[^/]+/[^/]+|vendor/[^/]+|native/landlock-run|native/landlock-run/packages/[^/]+)/package\.json$') {
            continue
        }
        $manifestPath = Join-Path $checkout ($relativePath -replace '/', '\\')
        try { $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json } catch { continue }
        $nameProperty = $manifest.PSObject.Properties['name']
        $name = if ($null -ne $nameProperty) { [string]$nameProperty.Value } else { '' }
        if (-not $name) { continue }
        if ($map.ContainsKey($name)) {
            throw "Duplicate workspace package name while validating pnpm links: $name"
        }
        $map[$name] = Split-Path -Parent $manifestPath
    }
    return $map
}

function Assert-CliWorkspaceLinks {
    $workspacePackages = Get-WorkspacePackageMap
    foreach ($property in $cliManifest.dependencies.PSObject.Properties) {
        if (-not ([string]$property.Value).StartsWith('workspace:', [StringComparison]::Ordinal)) { continue }
        $name = $property.Name
        if (-not $workspacePackages.ContainsKey($name)) {
            throw "Cannot locate workspace source for CLI dependency $name."
        }
        $installed = Join-Path $checkout ("apps\cli\node_modules\" + ($name -replace '/', '\\'))
        if (-not (Test-Path -LiteralPath $installed)) {
            throw "pnpm install did not link CLI workspace dependency $name at $installed."
        }
        $installedItem = Get-Item -LiteralPath $installed -Force
        if (-not ($installedItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "CLI workspace dependency is not a pnpm link and cannot prove source provenance: $installed"
        }
        $actual = Resolve-LinkTargetPath $installedItem
        $expected = Get-FullProviderPath $workspacePackages[$name] -MustExist
        if (-not (Test-SamePath $actual $expected)) {
            throw "Stale pnpm workspace link for $name points to $actual; expected $expected. Reinstall in the checkout's final path."
        }
    }
    return $workspacePackages
}

function Restore-RequiredWorkspacePeers(
    [object]$EntryManifest,
    [string]$NodeModules,
    [Collections.IDictionary]$WorkspacePackages,
    [string]$PnpmCommand
) {
    $required = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $queue = [Collections.Generic.Queue[string]]::new()

    function Add-RequiredWorkspacePackage([string]$Name) {
        if (-not $Name -or -not $WorkspacePackages.Contains($Name)) { return }
        if ($required.Add($Name)) { $queue.Enqueue($Name) }
    }

    function Add-ManifestDependencies([object]$Manifest, [switch]$IncludePeers) {
        foreach ($propertyName in @('dependencies', 'optionalDependencies')) {
            $property = $Manifest.PSObject.Properties[$propertyName]
            if ($null -eq $property -or $null -eq $property.Value) { continue }
            foreach ($dependency in $property.Value.PSObject.Properties) {
                Add-RequiredWorkspacePackage ([string]$dependency.Name)
            }
        }
        if (-not $IncludePeers) { return }

        $peersProperty = $Manifest.PSObject.Properties['peerDependencies']
        if ($null -eq $peersProperty -or $null -eq $peersProperty.Value) { return }
        $peerMetaProperty = $Manifest.PSObject.Properties['peerDependenciesMeta']
        foreach ($peer in $peersProperty.Value.PSObject.Properties) {
            $optional = $false
            if ($null -ne $peerMetaProperty -and $null -ne $peerMetaProperty.Value) {
                $metadata = $peerMetaProperty.Value.PSObject.Properties[[string]$peer.Name]
                if ($null -ne $metadata -and $null -ne $metadata.Value) {
                    $optionalProperty = $metadata.Value.PSObject.Properties['optional']
                    $optional = $null -ne $optionalProperty -and $optionalProperty.Value -eq $true
                }
            }
            if (-not $optional) { Add-RequiredWorkspacePackage ([string]$peer.Name) }
        }
    }

    # The CLI manifest owns the initial production graph. Required workspace
    # peers are then closed transitively because pnpm dedicated deploy does not
    # root workspace peers that are supplied only through peerDependencies.
    Add-ManifestDependencies $EntryManifest -IncludePeers
    while ($queue.Count -gt 0) {
        $name = $queue.Dequeue()
        $source = Get-FullProviderPath ([string]$WorkspacePackages[$name]) -MustExist
        $manifestPath = Join-Path $source 'package.json'
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $manifestName = [string]$manifest.name
        if ($manifestName -cne $name) {
            throw "Workspace package map mismatch: expected $name at $source, found $manifestName."
        }
        Add-ManifestDependencies $manifest -IncludePeers
    }

    $missing = @($required | Where-Object {
        -not (Test-Path -LiteralPath (Join-Path $NodeModules ($_ -replace '/', '\\')))
    } | Sort-Object)
    $packRecordsByName = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal)
    $sourceManifestsByName = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal)
    foreach ($name in $missing) {
        $source = Get-FullProviderPath ([string]$WorkspacePackages[$name]) -MustExist
        $sourceManifest = Get-Content -LiteralPath (Join-Path $source 'package.json') -Raw |
            ConvertFrom-Json
        if ([string]$sourceManifest.name -cne $name) {
            throw "Workspace package map mismatch before pack: expected $name, found $($sourceManifest.name)."
        }
        $scriptsProperty = $sourceManifest.PSObject.Properties['scripts']
        foreach ($lifecycleName in @(
            'preinstall', 'install', 'postinstall',
            'prepack', 'prepare', 'postpack', 'prepublish', 'prepublishOnly')) {
            if ($null -eq $scriptsProperty -or $null -eq $scriptsProperty.Value) { continue }
            $lifecycle = $scriptsProperty.Value.PSObject.Properties[$lifecycleName]
            if ($null -ne $lifecycle -and [string]$lifecycle.Value) {
                throw "Restored workspace peer $name has an unreviewed $lifecycleName lifecycle script."
            }
        }
        $sourceManifestsByName[$name] = $sourceManifest
        $packJson = Invoke-Captured $PnpmCommand @(
            '--dir', $source, 'pack', '--dry-run', '--json', '--ignore-workspace',
            '--config.ignore-scripts=true'
        ) "enumerate $name publish files"
        [object[]]$packRecords = @($packJson | ConvertFrom-Json)
        if ($packRecords.Count -ne 1) {
            throw "pnpm pack listed $($packRecords.Count) records for workspace peer $name."
        }
        $record = $packRecords[0]
        $recordName = [string]$record.name
        if ($recordName -cne $name -or -not $required.Contains($recordName) -or
            $packRecordsByName.ContainsKey($recordName)) {
            throw "pnpm pack returned an unexpected or repeated workspace peer: $recordName"
        }
        $packRecordsByName[$recordName] = $record
    }

    $restored = [Collections.Generic.List[string]]::new()
    foreach ($name in @($required | Sort-Object)) {
        $destination = Join-Path $NodeModules ($name -replace '/', '\\')
        if (-not (Test-Path -LiteralPath $destination)) {
            $source = Get-FullProviderPath ([string]$WorkspacePackages[$name]) -MustExist
            if (-not $packRecordsByName.ContainsKey($name)) {
                throw "pnpm pack did not return the missing workspace peer $name."
            }
            $record = $packRecordsByName[$name]
            $sourceManifest = $sourceManifestsByName[$name]
            if ([string]$record.name -cne $name -or
                [string]$record.version -cne [string]$sourceManifest.version) {
                throw "pnpm pack identity for $name does not match the exact source."
            }
            [object[]]$publishedFiles = @($record.files)
            if ($publishedFiles.Count -eq 0 -or
                -not ($publishedFiles | Where-Object { [string]$_.path -ceq 'package.json' })) {
                throw "pnpm pack returned no publishable package.json for workspace peer $name."
            }
            foreach ($publishedFile in $publishedFiles) {
                $relative = [string]$publishedFile.path
                $relativeNative = $relative -replace '/', '\\'
                if (-not $relative -or [IO.Path]::IsPathRooted($relativeNative) -or
                    ($relative -split '/|\\') -contains 'node_modules') {
                    throw "pnpm pack returned an unsafe workspace peer path for ${name}: $relative"
                }
                $sourceFile = Get-FullProviderPath (Join-Path $source $relativeNative) -MustExist
                $destinationFile = Get-FullProviderPath (Join-Path $destination $relativeNative)
                if (-not (Test-IsWithin $source $sourceFile) -or
                    -not (Test-IsWithin $destination $destinationFile) -or
                    -not (Test-Path -LiteralPath $sourceFile -PathType Leaf)) {
                    throw "pnpm pack returned a non-file or escaping path for ${name}: $relative"
                }
                $sourceItem = Get-Item -LiteralPath $sourceFile -Force
                if ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                    throw "Workspace peer publish file is a filesystem link: $sourceFile"
                }
                [IO.Directory]::CreateDirectory((Split-Path -Parent $destinationFile)) | Out-Null
                Copy-Item -LiteralPath $sourceFile -Destination $destinationFile
            }
            Assert-NoReparsePoints $destination
            $restored.Add($name)
        }
        $destinationManifestPath = Join-Path $destination 'package.json'
        if (-not (Test-Path -LiteralPath $destinationManifestPath -PathType Leaf)) {
            throw "Required workspace package $name has no deployed package.json: $destinationManifestPath"
        }
        $destinationManifest = Get-Content -LiteralPath $destinationManifestPath -Raw | ConvertFrom-Json
        $sourceManifest = Get-Content -LiteralPath (
            Join-Path ([string]$WorkspacePackages[$name]) 'package.json') -Raw | ConvertFrom-Json
        if ([string]$destinationManifest.name -cne $name -or
            [string]$destinationManifest.version -cne [string]$sourceManifest.version) {
            throw "Required workspace package $name does not match the exact source version."
        }
        $mainProperty = $sourceManifest.PSObject.Properties['main']
        if ($null -ne $mainProperty -and [string]$mainProperty.Value -and
            -not (Test-Path -LiteralPath (Join-Path $destination ([string]$mainProperty.Value)) -PathType Leaf)) {
            throw "Required workspace package $name is missing its built main entry."
        }
    }

    Write-Host ("Restored {0} required workspace peer root(s): {1}" -f
        $restored.Count,
        $(if ($restored.Count -eq 0) { '<none>' } else { $restored -join ', ' }))
    return $restored.ToArray()
}

    $env:CI = 'true'
    $env:DSH_TELEMETRY_DISABLED = '1'
    Push-Location $checkout
    try {
        Write-Step '4/10 install, test, gate, and build only the patched staging source'
        Invoke-Checked $pnpm @('install', '--frozen-lockfile') 'immutable install'
        Assert-InstalledNativeToolPathBudget $checkout
        Assert-CheckoutInputsUnchanged
        $workspacePackageMap = Assert-CliWorkspaceLinks
        $tscCommand = Resolve-InstalledWorkspaceCommand $checkout 'tsc'
        $tsdownCommand = Resolve-InstalledWorkspaceCommand $checkout 'tsdown'
        $tsxCommand = Resolve-InstalledWorkspaceCommand $checkout 'tsx'
        $vitestCommand = Resolve-InstalledWorkspaceCommand $checkout 'vitest'
        if ($EnterpriseDirectLocal) {
            # Client providers import remote types emitted by the Host bundle.
            # This is also the upstream prerequisite for client type/lint gates.
            Invoke-Checked $pnpm @('run', 'build:lib:host') 'direct-local generated remote contracts'
            Assert-CheckoutInputsUnchanged
        }
        $managedProjectConfigs = @(
            'packages/sandbox/sandbox-policy/tsconfig.json',
            'packages/fs/tool-fs/tsconfig.json',
            'packages/shell/tool-pwsh/tsconfig.json',
            'packages/shell/tool-bash/tsconfig.json',
            'packages/terminal/terminal-bash/tsconfig.json',
            'apps/cli/tsconfig.json'
        )
        if ($EnterpriseDirectLocal) {
            $managedProjectConfigs += @(
                'packages/client/modules/tsconfig.json',
                'packages/client/ui-settings-models/tsconfig.json',
                'packages/settings/settings-file/tsconfig.json',
                'packages/host/webserver/tsconfig.json',
                'packages/credentials/credentials/tsconfig.json',
                'packages/credentials/credentials-local/tsconfig.json',
                'packages/settings/settings/tsconfig.json'
            )
        }
        Invoke-Checked $tscCommand (@('-b') + $managedProjectConfigs) 'managed changed-package type build'
        Push-Location (Join-Path $checkout 'apps\cli')
        try {
            Invoke-Checked $tsdownCommand @('--config', 'tsdown.config.ts') 'managed CLI bundle'
        } finally {
            Pop-Location
        }
        Invoke-Checked $tsxCommand (@('scripts/run-oxlint.ts') + $managedTypeScriptFiles) 'managed changed TypeScript lint'
        foreach ($gate in @(
            'verify-config-catalog',
            'verify-cordis-catalog',
            'verify-cordis-api',
            'verify-cordis-config',
            'verify-translation-pairing',
            'verify-agent-note-format',
            'verify-agent-note-classification')) {
            if ($gate -ceq 'verify-cordis-config') {
                Invoke-ReviewedMaterializedCordisConfigGate
            } else {
                Invoke-Checked $pnpm @('run', $gate) "managed source gate $gate"
            }
        }
        Assert-CheckoutInputsUnchanged
        Invoke-Checked $pnpm @('run', 'release:verify', '--family', 'dsh') 'release version verification'
        Invoke-Checked $pnpm @('run', 'verify-dsh-package-licenses') 'DSH license declaration verification'
        Invoke-Checked $pnpm @('run', 'verify-third-party-notices') 'third-party notices verification'
        Invoke-Checked $pnpm @('run', 'clean') 'clean generated build outputs'
        Invoke-Checked $pnpm @('run', 'build') 'upstream source build'
        Invoke-Checked $pnpm @('run', 'verify-built-package-invariants') 'built package verification'
        Assert-CheckoutInputsUnchanged

        # Managed boot resolves every trusted package export and mounts the Web
        # bundle. Run these tests only after the complete upstream build so a
        # clean source checkout is tested against the same artifacts we deploy.
        # Full managed composition resolves the reviewed package graph twice in
        # one test. A clean Windows build can legitimately exceed Vitest's
        # five-second default while still completing deterministically.
        Invoke-Checked $vitestCommand (@('run', '--testTimeout=15000') + $managedFocusedTestFiles) 'managed focused behavior tests'
        $windowsExcludedConfigPath = Join-Path $checkout (
            '.ensou-managed-windows-excluded-' + [guid]::NewGuid().ToString('N') + '.vitest.config.ts')
        @'
import tsconfigPaths from 'vite-tsconfig-paths'
import { defineConfig } from 'vitest/config'
import { standardDecoratorPlugin, vitestExecArgv } from './vitest.shared.ts'

export default defineConfig({
  plugins: [tsconfigPaths({ projects: ['./tsconfig.base.json'] }), standardDecoratorPlugin()],
  test: {
    execArgv: vitestExecArgv,
    pool: 'forks',
    setupFiles: ['./scripts/test-invariants.ts'],
    include: [
      'packages/shell/tool-bash/tests/tools.spec.ts',
      'packages/terminal/terminal-bash/tests/index.spec.ts',
    ],
  },
})
'@ | Set-Content -LiteralPath $windowsExcludedConfigPath -Encoding utf8
        try {
            $windowsExcludedArguments = @(
                'run',
                '--configLoader', 'runner',
                '--config', $windowsExcludedConfigPath,
                '-t', 'deployment maximum|real JSONL-restored outside cwd',
                '--reporter', 'verbose') + $managedWindowsExcludedTestFiles
            Write-Host ("[{0}] {1}" -f
                'managed normally Windows-excluded policy tests',
                (Format-Command $vitestCommand $windowsExcludedArguments))
            $windowsExcludedOutput = Invoke-Captured `
                $vitestCommand $windowsExcludedArguments 'managed normally Windows-excluded policy tests'
            Write-Host $windowsExcludedOutput
            $windowsExcludedPlain = [Regex]::Replace(
                $windowsExcludedOutput,
                "`e\[[0-?]*[ -/]*[@-~]",
                '')
            $windowsExcludedExpectedTests = @(
                'confines a terminal to the deployment maximum despite a durable danger mode',
                'never executes above a deployment maximum after session restore or per-call approval',
                'rejects a real JSONL-restored outside cwd before bash reaches the executor'
            )
            $windowsExcludedMissingOrRepeatedTests = @(
                $windowsExcludedExpectedTests | Where-Object {
                    ([Regex]::Matches($windowsExcludedPlain, [Regex]::Escape($_))).Count -ne 1
                })
            if ($windowsExcludedPlain -notmatch 'Test Files\s+2 passed\s+\(2\)' -or
                $windowsExcludedPlain -notmatch 'Tests\s+3 passed\s+\|\s+[0-9]+ skipped\s+\([0-9]+\)' -or
                $windowsExcludedMissingOrRepeatedTests.Count -ne 0) {
                throw 'The normally Windows-excluded managed lane did not execute the exact reviewed 2-file/3-pass selection.'
            }
        } finally {
            if (Test-Path -LiteralPath $windowsExcludedConfigPath) {
                Remove-Item -LiteralPath $windowsExcludedConfigPath -Force
            }
        }
        Assert-CheckoutInputsUnchanged

        $entryBuilt = Join-Path $checkout 'apps\cli\lib\bin.js'
        $frontendBuilt = Join-Path $checkout 'apps\web\dist\index.html'
        if (-not (Test-Path -LiteralPath $entryBuilt) -or -not (Test-Path -LiteralPath $frontendBuilt)) {
            throw 'Upstream build completed without the required CLI or Web frontend artifacts.'
        }

        Write-Step '5/10 deploy a separate production closure from patched source'
        Invoke-Checked $pnpm @(
            '--filter', '@deepseek-ai/dsh',
            'deploy',
            '--prod',
            '--offline',
            '--config.inject-workspace-packages=true',
            '--config.node-linker=hoisted',
            '--config.auto-install-peers=true',
            '--config.link-workspace-packages=true',
            '--config.strict-dep-builds=false',
            $deployRoot
        ) 'pnpm dedicated-lockfile deploy'
    } finally {
        Pop-Location
    }

    $deployedManifestPath = Join-Path $deployRoot 'package.json'
    $deployedNodeModules = Join-Path $deployRoot 'node_modules'
    if (-not (Test-Path -LiteralPath $deployedManifestPath) -or -not (Test-Path -LiteralPath $deployedNodeModules)) {
        throw 'pnpm deploy did not create a package manifest and node_modules closure.'
    }

    $modulesManifestPath = Join-Path $deployedNodeModules '.modules.yaml'
    if (-not (Test-Path -LiteralPath $modulesManifestPath -PathType Leaf)) {
        throw 'pnpm deploy did not create its modules manifest.'
    }
    $modulesManifest = Get-Content -LiteralPath $modulesManifestPath -Raw | ConvertFrom-Json
    $ignoredBuildsProperty = $modulesManifest.PSObject.Properties['ignoredBuilds']
    [string[]]$ignoredBuilds = @()
    if ($null -ne $ignoredBuildsProperty) {
        $ignoredBuilds = @(
            $ignoredBuildsProperty.Value |
                ForEach-Object { [string]$_ }
        )
    }
    $reviewedSubprocessSource = Get-FullProviderPath (
        Join-Path $checkout 'packages\subprocess\subprocess-local') -MustExist
    $expectedIgnoredBuild = '@deepseek-ai/dsh-subprocess-local@' + ([Uri]$reviewedSubprocessSource).AbsoluteUri
    if ($ignoredBuilds.Count -ne 1 -or $ignoredBuilds[0] -cne $expectedIgnoredBuild) {
        throw "pnpm deploy ignored an unreviewed build-script set: $($ignoredBuilds -join ', ')"
    }

    $restoredWorkspacePeers = @(Restore-RequiredWorkspacePeers `
        $cliManifest $deployedNodeModules $workspacePackageMap $pnpm)
    Assert-CheckoutInputsUnchanged
    Write-Step '6/10 materialize the closure without moving the installed pnpm tree'
    Materialize-StagedLinks $deployedNodeModules $workspacePackageMap
    $reviewedPostinstall = Join-Path $deployedNodeModules (
        '@deepseek-ai\dsh-subprocess-local\scripts\ensure-spawn-helper.mjs')
    if (-not (Test-Path -LiteralPath $reviewedPostinstall -PathType Leaf)) {
        throw "Reviewed workspace postinstall is missing from the deployed closure: $reviewedPostinstall"
    }
    Invoke-Checked $nodeCommand @($reviewedPostinstall) 'reviewed workspace postinstall'
    Assert-CheckoutInputsUnchanged
    $normalizedSourceRegionComments = Normalize-SourceBuildRegionComments `
        $deployedNodeModules $checkout
    $normalizedBinShimTargetComments = Normalize-GeneratedBinShimTargetComments `
        $deployedNodeModules
    $virtualStore = Join-Path $deployedNodeModules '.pnpm'
    if (Test-Path -LiteralPath $virtualStore) {
        if (-not (Test-SamePath (Split-Path -Parent $virtualStore) $deployedNodeModules)) {
            throw "Refusing unsafe staged virtual-store cleanup: $virtualStore"
        }
        Remove-Item -LiteralPath $virtualStore -Recurse -Force
    }
    foreach ($stagingMetadataName in @('.modules.yaml', '.pnpm-workspace-state-v1.json')) {
        $stagingMetadataPath = Join-Path $deployedNodeModules $stagingMetadataName
        if (Test-Path -LiteralPath $stagingMetadataPath) {
            Remove-Item -LiteralPath $stagingMetadataPath -Force
        }
    }
    Assert-PortableBinShims $deployedNodeModules @($checkout, $stagingRoot)
    Assert-NoReparsePoints $deployRoot

    [IO.Directory]::CreateDirectory($runtimeRoot) | Out-Null
    $runtimeNodeModules = Join-Path $runtimeRoot 'node_modules'
    Copy-DirectoryContents $deployedNodeModules $runtimeNodeModules
    $runtimeCli = Join-Path $runtimeNodeModules '@deepseek-ai\dsh'
    if (Test-Path -LiteralPath $runtimeCli) {
        throw "Unexpected @deepseek-ai/dsh collision in deployed dependencies: $runtimeCli"
    }
    [IO.Directory]::CreateDirectory($runtimeCli) | Out-Null
    foreach ($item in Get-ChildItem -LiteralPath $deployRoot -Force) {
        if ($item.Name -in @('node_modules', 'package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml')) { continue }
        Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $runtimeCli $item.Name) -Recurse
    }
    Copy-Item -LiteralPath $cliManifestPath -Destination (Join-Path $runtimeCli 'package.json')
    Copy-Item -LiteralPath $nodeCommand -Destination (Join-Path $runtimeRoot 'node.exe')
    Copy-Item -LiteralPath $licensePath -Destination (Join-Path $runtimeRoot 'LICENSE')
    Copy-Item -LiteralPath $noticesPath -Destination (Join-Path $runtimeRoot 'THIRD_PARTY_NOTICES.md')
    Assert-NoReparsePoints $runtimeRoot

    $runtimeEntry = Join-Path $runtimeCli 'lib\bin.js'
    $runtimeFrontend = Join-Path $runtimeNodeModules '@deepseek-ai\dsh-web-frontend\dist\index.html'
    if (-not (Test-Path -LiteralPath $runtimeEntry) -or -not (Test-Path -LiteralPath $runtimeFrontend)) {
        throw 'The movable runtime is missing its built CLI or Web frontend entry.'
    }

    $bundledNode = Join-Path $runtimeRoot 'node.exe'
    $closureVerifier = Join-Path $stagingRoot 'verify-runtime-closure.mjs'
    $closureInventoryPath = Join-Path $runtimeRoot 'runtime-closure.json'
    @'
import { createRequire } from 'node:module'
import { existsSync, readFileSync, readdirSync, realpathSync, writeFileSync } from 'node:fs'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'

const [runtimeArg, outputArg] = process.argv.slice(2)
if (!runtimeArg || !outputArg) throw new Error('usage: verify-runtime-closure.mjs <runtime> <output>')
const runtime = realpathSync(resolve(runtimeArg))
const output = resolve(outputArg)
const entryManifest = join(runtime, 'node_modules', '@deepseek-ai', 'dsh', 'package.json')

function insideRuntime(path) {
  const rel = relative(runtime, path)
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel))
}

function manifestFor(name, fromDirectory) {
  const resolver = createRequire(join(fromDirectory, '__ensou_closure_probe__.cjs'))
  for (const base of resolver.resolve.paths(name) ?? []) {
    const candidate = join(base, ...name.split('/'), 'package.json')
    if (!existsSync(candidate)) continue
    const manifest = realpathSync(candidate)
    if (!insideRuntime(manifest)) {
      throw new Error(`${name} resolves outside the runtime: ${manifest}`)
    }
    return manifest
  }
  return undefined
}

const pending = [entryManifest]
const visited = new Set()
const packages = []
const failures = []
let edgeCount = 0

function installedPackageManifests(nodeModules) {
  if (!existsSync(nodeModules)) return []
  const manifests = []
  for (const entry of readdirSync(nodeModules, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name.startsWith('.')) continue
    if (entry.name.startsWith('@')) {
      const scope = join(nodeModules, entry.name)
      for (const scopedEntry of readdirSync(scope, { withFileTypes: true })) {
        if (scopedEntry.isDirectory()) collectPackage(join(scope, scopedEntry.name), manifests)
      }
    } else {
      collectPackage(join(nodeModules, entry.name), manifests)
    }
  }
  return manifests
}

function collectPackage(packageRoot, manifests) {
  const manifest = join(packageRoot, 'package.json')
  if (!existsSync(manifest)) {
    failures.push(`installed node_modules entry has no package.json: ${packageRoot}`)
    return
  }
  manifests.push(realpathSync(manifest))
  const nestedNodeModules = join(packageRoot, 'node_modules')
  for (const nested of installedPackageManifests(nestedNodeModules)) manifests.push(nested)
}

while (pending.length > 0) {
  const manifestPath = realpathSync(pending.pop())
  if (visited.has(manifestPath)) continue
  visited.add(manifestPath)
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
  if (typeof manifest.name !== 'string' || typeof manifest.version !== 'string') {
    failures.push(`${manifestPath}: missing name/version`)
    continue
  }

  const edges = new Map()
  for (const name of Object.keys(manifest.dependencies ?? {})) edges.set(name, false)
  for (const name of Object.keys(manifest.optionalDependencies ?? {})) {
    if (!edges.has(name)) edges.set(name, true)
  }
  for (const name of Object.keys(manifest.peerDependencies ?? {})) {
    const optional = manifest.peerDependenciesMeta?.[name]?.optional === true
    if (!edges.has(name) || edges.get(name) === true) edges.set(name, optional)
  }

  const resolvedEdges = []
  for (const [name, optional] of [...edges].sort(([left], [right]) => left.localeCompare(right))) {
    const target = manifestFor(name, dirname(manifestPath))
    if (target === undefined) {
      if (!optional) failures.push(`${manifest.name}@${manifest.version}: missing ${name}`)
      continue
    }
    edgeCount++
    resolvedEdges.push({ name, optional, package: relative(runtime, dirname(target)).replaceAll('\\', '/') })
    pending.push(target)
  }

  packages.push({
    name: manifest.name,
    version: manifest.version,
    path: relative(runtime, dirname(manifestPath)).replaceAll('\\', '/'),
    dependencies: resolvedEdges,
  })
}

const physicalManifests = installedPackageManifests(join(runtime, 'node_modules'))
for (const manifestPath of physicalManifests) {
  if (!visited.has(manifestPath)) {
    failures.push(`installed package is outside the reachable runtime closure: ${manifestPath}`)
  }
}
for (const manifestPath of visited) {
  if (!physicalManifests.includes(manifestPath)) {
    failures.push(`resolved package is not an installed package root: ${manifestPath}`)
  }
}

if (failures.length > 0) {
  throw new Error(`runtime dependency closure is incomplete:\n${failures.sort().map(value => `  ${value}`).join('\n')}`)
}
packages.sort((left, right) => left.path.localeCompare(right.path))
writeFileSync(output, `${JSON.stringify({ schemaVersion: 1, packageCount: packages.length, physicalPackageCount: physicalManifests.length, edgeCount, packages }, null, 2)}\n`)
'@ | Set-Content -LiteralPath $closureVerifier -Encoding utf8
    Invoke-Checked $bundledNode @($closureVerifier, $runtimeRoot, $closureInventoryPath) 'relocated runtime dependency closure verification'
    $closureInventory = Get-Content -LiteralPath $closureInventoryPath -Raw | ConvertFrom-Json
    foreach ($package in $closureInventory.packages) {
        $identity = "$($package.name)@$($package.version)"
        if ($workspacePackageMap.Contains([string]$package.name)) {
            $sourceManifestPath = Join-Path ([string]$workspacePackageMap[[string]$package.name]) 'package.json'
            $sourceManifest = Get-Content -LiteralPath $sourceManifestPath -Raw | ConvertFrom-Json
            if ([string]$sourceManifest.version -cne [string]$package.version) {
                throw "Deployed workspace package $identity does not match source version $($sourceManifest.version)."
            }
        } elseif (-not $lockedPackageIdentities.Contains($identity)) {
            throw "Deployed external package is absent from the pinned pnpm-lock.yaml packages section: $identity"
        }
    }
    $runtimeClosurePackageCount = [int]$closureInventory.packageCount
    if ($runtimeClosurePackageCount -ne [int]$closureInventory.physicalPackageCount) {
        throw "Reachable runtime closure count $runtimeClosurePackageCount does not match installed package count $($closureInventory.physicalPackageCount)."
    }

    $licenseRecords = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($manifestFile in Get-ChildItem -LiteralPath $runtimeNodeModules -Filter package.json -File -Recurse) {
        try { $manifest = Get-Content -LiteralPath $manifestFile.FullName -Raw | ConvertFrom-Json } catch { continue }
        $nameProperty = $manifest.PSObject.Properties['name']
        $versionProperty = $manifest.PSObject.Properties['version']
        $name = if ($null -ne $nameProperty) { [string]$nameProperty.Value } else { '' }
        $version = if ($null -ne $versionProperty) { [string]$versionProperty.Value } else { '' }
        if (-not $name -or -not $version) { continue }
        $key = "$name@$version"
        if ($licenseRecords.ContainsKey($key)) { continue }
        $licenseProperty = $manifest.PSObject.Properties['license']
        $licenseValue = if ($null -ne $licenseProperty -and $licenseProperty.Value -is [string]) {
            [string]$licenseProperty.Value
        } elseif ($null -ne $licenseProperty -and $null -ne $licenseProperty.Value) {
            $typeProperty = $licenseProperty.Value.PSObject.Properties['type']
            if ($null -ne $typeProperty) { [string]$typeProperty.Value } else { $null }
        } else {
            $null
        }
        $licenseRecords[$key] = [ordered]@{ name = $name; version = $version; license = $licenseValue }
    }
    $runtimeLicenses = [ordered]@{
        schemaVersion = 1
        generatedFrom = $OfficialCommit
        legalApproval = $false
        note = 'Inventory only. Distribution terms still require organization-specific legal review.'
        packages = @($licenseRecords.GetEnumerator() | Sort-Object Key | ForEach-Object { $_.Value })
    }
    $runtimeLicenses | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $runtimeRoot 'RUNTIME_DEPENDENCY_LICENSES.json') -Encoding utf8

    # Capability is emitted only after this exact built selected profile has
    # drained, resumed and shut down through its real private update channel.
    Invoke-PersonalManagedUpdateSmoke $runtimeRoot (Join-Path $stagingRoot 'personal-assembled-smoke')
    $assembledDirectLocalReceipt = Invoke-EnterpriseDirectLocalSmoke $runtimeRoot (Join-Path $stagingRoot 'direct-local-assembled-smoke')
    Write-RuntimeProtocolMetadata $runtimeRoot -WebAuthProtocol $effectiveRuntimeWebAuthProtocol `
        -PersonalManagedUpdate:$PersonalManagedUpdate -EnterpriseDirectLocal:$EnterpriseDirectLocal | Out-Null
    $assembledRuntimeWebAuthProtocol = Read-RuntimeWebAuthProtocolMetadata $runtimeRoot
    if ($assembledRuntimeWebAuthProtocol -cne $effectiveRuntimeWebAuthProtocol) {
        throw 'Assembled runtime Web authentication metadata differs from the reviewed build input.'
    }

    Write-Step '7/10 smoke-test the assembled enterprise-managed source runtime'
    Invoke-RuntimeSmoke `
        $runtimeRoot `
        $dshVersion `
        (Join-Path $stagingRoot 'assembled-smoke') `
        'assembled runtime' `
        $assembledRuntimeWebAuthProtocol
    Assert-CheckoutInputsUnchanged

    $builtAt = [DateTimeOffset]::UtcNow.ToString('o')
    # The bundle reader has already validated the exact variant-specific policy
    # shape and values. Preserve that policy without relabeling direct traffic
    # as a gateway or emitting nonexistent gateway fields.
    $managedPolicyProvenance = [ordered]@{}
    foreach ($property in $managedPatch.Manifest.managedPolicy.PSObject.Properties) {
        $managedPolicyProvenance[$property.Name] = $property.Value
    }
    $managedPatchProvenance = [ordered]@{
        id = $managedPatch.Id
        manifestSchema = [string]$managedPatch.Manifest.schema
        manifestSha256 = $managedPatch.ManifestSha256
        patchSha256 = $managedPatch.PatchSha256
        patchBytes = [int64]$managedPatch.Manifest.patch.bytes
        changedFileCount = $managedPatch.Files.Count
        modifiedPreimageCount = @($managedPatch.Changes | Where-Object status -CEQ 'M').Count
    }
    $sourceProvenance = [ordered]@{
        schemaVersion = $(if ($EnterpriseDirectLocal) { 4 } else { 3 })
        sourceBuilt = $true
        releaseId = $ReleaseId
        promotionEligible = $promotionEligible
        artifactType = $RuntimeArtifactType
        sourceIdentity = 'github-https-tag-plus-ensou-managed-patch'
        sourceRepository = $OfficialRepository
        sourceTag = $OfficialTag
        sourceCommit = $OfficialCommit
        sourceTree = $OfficialTree
        remoteTagVerified = $true
        tagSignatureVerified = $false
        dshVersion = $dshVersion
        platform = $Platform
        baseLockfileSha256 = $baseLockfileSha256
        lockfileSha256 = $lockfileSha256
        runtimeWebAuthProtocol = $assembledRuntimeWebAuthProtocol
        managedPatch = $managedPatchProvenance
        managedPolicy = $managedPolicyProvenance
        nodeVersion = $actualNodeVersion
        nodeSha256 = $nodeSha256
        pnpmVersion = $actualPnpmVersion
        npmVersion = $npmVersion
        buildPipeline = 'installation-owned-isolated-managed-source-v1'
        deploymentMode = 'pnpm-dedicated-lockfile-offline-deploy'
        restoredWorkspacePeerCount = $restoredWorkspacePeers.Count
        restoredWorkspacePeers = $restoredWorkspacePeers
        normalizedSourceRegionCommentCount = $normalizedSourceRegionComments
        normalizedBinShimTargetCommentCount = $normalizedBinShimTargetComments
        runtimeClosurePackageCount = $runtimeClosurePackageCount
        runtimeClosureAgainstPinnedSourceAndLock = $true
        assembledRuntimeSmoke = $true
        managedFocusedTests = $true
        managedWindowsExcludedFocusedTests = $true
        managedRefusalSmoke = $true
        officialCheckoutUnchanged = $true
        builtAtUtc = $builtAt
        licensing = [ordered]@{
            harnessLicense = 'MIT'
            includedFiles = @('LICENSE', 'THIRD_PARTY_NOTICES.md', 'RUNTIME_DEPENDENCY_LICENSES.json')
            organizationReviewRequired = $true
        }
    }
    if ($EnterpriseDirectLocal) {
        $sourceProvenance.runtimeProfile = 'enterprise-direct-local'
        $sourceProvenance.managedUpdateProtocol = 'enterprise-direct-local-v1'
        $sourceProvenance.directLocalRuntimeSmoke = $assembledDirectLocalReceipt
    }
    $sourceProvenance | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $runtimeRoot 'source-build.json') -Encoding utf8

    # This final raw-file gate runs only after every generated runtime file is
    # present, and scans binaries plus all text extensions and encodings.
    Assert-NoBuildToolingInRuntime $runtimeRoot
    Assert-NoEmbeddedBuildRoot $runtimeRoot @(
        $officialCheckout, $checkout, $stagingRoot, $LauncherRepositoryRoot)

    $hashManifest = Join-Path $runtimeRoot 'runtime-files.sha256'
    $hashLines = foreach ($file in Get-ChildItem -LiteralPath $runtimeRoot -File -Recurse -Force | Sort-Object FullName) {
        if (Test-SamePath $file.FullName $hashManifest) { continue }
        $fileHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "{0}  {1}" -f $fileHash, (Get-RelativeFileName $runtimeRoot $file.FullName)
    }
    $hashLines | Set-Content -LiteralPath $hashManifest -Encoding ascii

    Write-Step '8/10 create ZIP and verify the extracted artifact offline'
    $stagedZip = Join-Path $productsRoot $zipName
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory(
        $runtimeRoot,
        $stagedZip,
        [IO.Compression.CompressionLevel]::Optimal,
        $false)
    $extractedRuntimeRoot = Join-Path $stagingRoot 'extracted-runtime'
    [IO.Compression.ZipFile]::ExtractToDirectory($stagedZip, $extractedRuntimeRoot)
    Assert-NoReparsePoints $extractedRuntimeRoot
    Assert-RuntimeFileHashes $extractedRuntimeRoot
    Assert-NoBuildToolingInRuntime $extractedRuntimeRoot
    $extractedRuntimeWebAuthProtocol =
        Read-RuntimeWebAuthProtocolMetadata $extractedRuntimeRoot
    if ($extractedRuntimeWebAuthProtocol -cne $assembledRuntimeWebAuthProtocol) {
        throw 'Extracted runtime Web authentication metadata differs from the assembled artifact.'
    }
    Invoke-RuntimeSmoke `
        $extractedRuntimeRoot `
        $dshVersion `
        (Join-Path $stagingRoot 'extracted-smoke') `
        'extracted ZIP runtime' `
        $extractedRuntimeWebAuthProtocol
    Invoke-PersonalManagedUpdateSmoke $extractedRuntimeRoot (Join-Path $stagingRoot 'personal-extracted-smoke')
    $extractedDirectLocalReceipt = Invoke-EnterpriseDirectLocalSmoke $extractedRuntimeRoot (Join-Path $stagingRoot 'direct-local-extracted-smoke')
    $zipHash = (Get-FileHash -LiteralPath $stagedZip -Algorithm SHA256).Hash.ToLowerInvariant()
    $zipSize = (Get-Item -LiteralPath $stagedZip).Length
    "{0}  {1}" -f $zipHash, $zipName | Set-Content -LiteralPath (Join-Path $productsRoot $shaName) -Encoding ascii

    $metadata = [ordered]@{
        schemaVersion = $(if ($EnterpriseDirectLocal) { 3 } else { 2 })
        releaseId = $ReleaseId
        promotionEligible = $promotionEligible
        artifactType = $RuntimeArtifactType
        sourceBuilt = $true
        platform = $Platform
        sourceIdentity = 'github-https-tag-plus-ensou-managed-patch'
        sourceRepository = $OfficialRepository
        sourceTag = $OfficialTag
        sourceCommit = $OfficialCommit
        sourceTree = $OfficialTree
        dshVersion = $dshVersion
        baseLockfileSha256 = $baseLockfileSha256
        lockfileSha256 = $lockfileSha256
        runtimeWebAuthProtocol = $extractedRuntimeWebAuthProtocol
        managedPatch = $managedPatchProvenance
        managedPolicy = $managedPolicyProvenance
        builtAtUtc = $builtAt
        toolchain = [ordered]@{
            nodeVersion = $actualNodeVersion
            nodeSha256 = $nodeSha256
            pnpmVersion = $actualPnpmVersion
            npmVersion = $npmVersion
        }
        verification = [ordered]@{
            cleanCheckout = $true
            tagCommitMatch = $true
            remoteTagCommitMatch = $true
            tagSignatureVerified = $false
            officialCheckoutUnchanged = $true
            patchManifestValidated = $true
            patchPreimagesVerified = $true
            patchApplyCheck = $true
            patchPostimagesVerified = $true
            frozenLockfileInstall = $true
            managedFocusedTests = $true
            managedWindowsExcludedFocusedTests = $true
            managedChangedPackageTypeBuild = $true
            managedCliBundle = $true
            managedSourceGates = $true
            sourceBuild = 'pnpm run build (reviewed managed patch applied)'
            builtPackageInvariants = $true
            deploymentMode = 'pnpm-dedicated-lockfile-offline-deploy'
            runtimeClosureAgainstPinnedSourceAndLock = $true
            runtimeClosurePackageCount = $runtimeClosurePackageCount
            portableCommandShimGate = $true
            symlinkFreeRuntime = $true
            bundledNodeVersionSmoke = $true
            nativeModuleSmoke = @('node-pty', 'koffi')
            webProfileDumpSmoke = $true
            webHttpSmoke = $true
            managedExactEnvironmentSmoke = $true
            managedWorkspaceCwdSmoke = $true
            managedRefusalSmoke = $true
            extractedArtifactHashManifestVerified = $true
            extractedArtifactSmoke = $true
            buildToolingExcluded = $true
            webSmokeUrl = 'http://127.0.0.1:<ephemeral-port>/'
            externalNetworkIsolation = $false
        }
        artifact = [ordered]@{
            fileName = $zipName
            sizeBytes = $zipSize
            sha256 = $zipHash
        }
        licensing = [ordered]@{
            harnessLicense = 'MIT'
            noticesIncluded = $true
            organizationReviewRequired = $true
        }
    }
    if ($EnterpriseDirectLocal) {
        $metadata.runtimeProfile = 'enterprise-direct-local'
        $metadata.managedUpdateProtocol = 'enterprise-direct-local-v1'
        $metadata.verification.directLocalAssembledSmoke = $assembledDirectLocalReceipt
        $metadata.verification.directLocalExtractedSmoke = $extractedDirectLocalReceipt
    }
    $metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $productsRoot $metadataName) -Encoding utf8

    Write-Step '9/10 prove the official checkout remained exact and untouched'
    Assert-CheckoutInputsUnchanged
    Assert-CheckoutFilesystemInventoryUnchanged 'before publication'

    Write-Step '10/10 publish the immutable local artifact directory'
    if (Test-Path -LiteralPath $releaseDirectory) {
        throw "ReleaseId appeared while building and will not be overwritten: $releaseDirectory"
    }
    [IO.Directory]::Move($productsRoot, $releaseDirectory)
    $completed = $true

    Write-Host "Completed $PatchVariant source runtime: $releaseDirectory" -ForegroundColor Green
    Write-Host "ZIP: $(Join-Path $releaseDirectory $zipName)"
    Write-Host "SHA-256: $zipHash"
    Write-Host "Metadata: $(Join-Path $releaseDirectory $metadataName)"
} finally {
    try {
        if ($null -ne $reservation) {
            $reservation.Dispose()
            if (Test-Path -LiteralPath $reservationPath) {
                Remove-Item -LiteralPath $reservationPath -Force
            }
        }
        if ($completed) {
            if ($stagingRoot -and (Test-Path -LiteralPath $stagingRoot)) {
                Remove-OwnedBuildDirectory `
                    $stagingRoot $stagingParent '^edsh-[0-9a-f]{32}$'
            }
            if ($productsRoot -and (Test-Path -LiteralPath $productsRoot)) {
                Remove-OwnedBuildDirectory `
                    $productsRoot $out '^\.edsh-[0-9a-f]{32}\.products$'
            }
        } else {
            if ($stagingRoot -and (Test-Path -LiteralPath $stagingRoot)) {
                Write-Warning "Build $ReleaseId failed; diagnostic source staging was retained at $stagingRoot"
            }
            if ($productsRoot -and (Test-Path -LiteralPath $productsRoot)) {
                Write-Warning "Build $ReleaseId failed; diagnostic publication staging was retained at $productsRoot"
            }
        }
    } finally {
        $env:Path = $oldPath
        $env:CI = $oldCi
        $env:DSH_TELEMETRY_DISABLED = $oldTelemetry
        $env:NODE_OPTIONS = $oldBuildNodeOptions
        $env:NODE_PATH = $oldBuildNodePath
        $env:NODE_EXTRA_CA_CERTS = $oldBuildNodeExtraCaCerts
    }
}
