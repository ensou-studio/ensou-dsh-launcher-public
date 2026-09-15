#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [Alias('SourceARoot')]
    [string]$SourceA,

    [Parameter(Mandatory = $true)]
    [Alias('SourceBRoot')]
    [string]$SourceB,

    [Parameter(Mandatory = $true)]
    [string]$BuildIntentPath,

    [Parameter(Mandatory = $true)]
    [string]$EvidenceRoot,

    [Parameter(Mandatory = $true)]
    [string]$OfflinePackageCacheRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    throw 'Personal two-clean production builds require native Windows.'
}

$script:Utf8 = [Text.UTF8Encoding]::new($false, $true)
$script:MaximumProcessOutputBytes = 8MB
$script:ProducerRelativePath =
    'release/scripts/New-PersonalTwoCleanBuildEvidence.ps1'
$script:StateModuleRelativePath = 'release/scripts/ProductionReleaseState.psm1'
$script:AccountModuleRelativePath = 'release/scripts/PersonalAccountReleaseConfiguration.psm1'
$script:ProcessModuleRelativePath = 'release/scripts/ProductionBoundedProcess.psm1'
$script:IntentSchemaRelativePath =
    'release/schemas/personal-two-clean-build-intent-v1.schema.json'
$script:EvidenceSchemaRelativePath =
    'release/schemas/personal-two-clean-build-evidence-v1.schema.json'
$script:DependencyPaths = @(
    'Directory.Build.props',
    'global.json',
    'release/locks/dotnet-sdk-10.0.302-win-x64.files.lock.json',
    'src/Ensou.Dsh.Contracts/packages.lock.json',
    'src/Ensou.Dsh.UpdateEngine/packages.lock.json'
)
$script:ProjectContract = @(
    [pscustomobject]@{
        Ordinal = 1
        Role = 'startup-stub'
        FileName = 'Ensou.Dsh.Bootstrapper.exe'
        Project = 'src/Ensou.Dsh.Bootstrapper/Ensou.Dsh.Bootstrapper.csproj'
    },
    [pscustomobject]@{
        Ordinal = 2
        Role = 'client-bootstrapper'
        FileName = 'Ensou.Dsh.ClientBootstrapper.exe'
        Project = 'src/Ensou.Dsh.ClientBootstrapper/Ensou.Dsh.ClientBootstrapper.csproj'
    },
    [pscustomobject]@{
        Ordinal = 3
        Role = 'launcher'
        FileName = 'Ensou.Dsh.Launcher.exe'
        Project = 'src/Ensou.Dsh.Launcher/Ensou.Dsh.Launcher.csproj'
    },
    [pscustomobject]@{
        Ordinal = 4
        Role = 'maintenance'
        FileName = 'Ensou.Dsh.Personal.Maintenance.exe'
        Project = 'src/Ensou.Dsh.Personal.Maintenance/Ensou.Dsh.Personal.Maintenance.csproj'
    }
)

$scriptCheckoutRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$stateModulePath = Join-Path $scriptCheckoutRoot `
    $script:StateModuleRelativePath.Replace(
        '/', [IO.Path]::DirectorySeparatorChar)
$intentSchemaPath = Join-Path $scriptCheckoutRoot `
    $script:IntentSchemaRelativePath.Replace(
        '/', [IO.Path]::DirectorySeparatorChar)
$evidenceSchemaPath = Join-Path $scriptCheckoutRoot `
    $script:EvidenceSchemaRelativePath.Replace(
        '/', [IO.Path]::DirectorySeparatorChar)
Import-Module $stateModulePath -Force
Import-Module (Join-Path $scriptCheckoutRoot $script:AccountModuleRelativePath) -Force
Import-Module (Join-Path $scriptCheckoutRoot $script:ProcessModuleRelativePath) -Force

function Get-Sha256Bytes {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [ValidateNotNull()]
        [byte[]]$Bytes
    )

    return ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $Bytes
}

function Get-TextSha256([string]$Value) {
    [byte[]]$bytes = $script:Utf8.GetBytes($Value)
    try {
        return Get-Sha256Bytes -Bytes $bytes
    }
    finally {
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
    }
}

function Get-CanonicalUtc {
    return [DateTimeOffset]::UtcNow.ToString(
        'yyyy-MM-ddTHH:mm:ssZ',
        [Globalization.CultureInfo]::InvariantCulture)
}

function Test-ProductionSha256([string]$Value) {
    return $Value -match '^[0-9a-f]{64}$' -and
        $Value -notmatch '^([0-9a-f])\1{63}$'
}

function Test-ProductionGitObject([string]$Value) {
    return $Value -match '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -and
        $Value -notmatch '^([0-9a-f])\1{39}(?:\1{24})?$'
}

function Get-FullAbsolutePath([string]$Path, [string]$Label) {
    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw "$Label path must be absolute."
    }
    return [IO.Path]::GetFullPath($Path).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
}

function Test-PathIntersection([string]$First, [string]$Second) {
    $firstPath = [IO.Path]::GetFullPath($First).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $secondPath = [IO.Path]::GetFullPath($Second).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $comparison = [StringComparison]::OrdinalIgnoreCase
    return $firstPath.Equals($secondPath, $comparison) -or
        $firstPath.StartsWith(
            $secondPath + [IO.Path]::DirectorySeparatorChar,
            $comparison) -or
        $secondPath.StartsWith(
            $firstPath + [IO.Path]::DirectorySeparatorChar,
            $comparison)
}

function Assert-DisjointPaths(
    [string]$First,
    [string]$Second,
    [string]$Label
) {
    if (Test-PathIntersection -First $First -Second $Second) {
        throw "$Label must be physically separate and path-disjoint."
    }
}

function Assert-NewOrdinaryDirectoryTarget([string]$Path, [string]$Label) {
    if (Test-Path -LiteralPath $Path) {
        throw "$Label must be a new absent directory."
    }
    $parent = [IO.Path]::GetDirectoryName($Path)
    if ([string]::IsNullOrWhiteSpace($parent)) {
        throw "$Label has no ordinary existing parent."
    }
    $parentLease = ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
        -Path $parent -Label "$Label parent"
    $parentLease.Handle.Dispose()
}

function Get-DirectoryPhysicalIdentitySha256($Lease) {
    $identity = '{0:x16}|{1:x16}|{2}' -f `
        [uint64]$Lease.VolumeSerialNumber,
        [uint64]$Lease.FileIndex,
        ([string]$Lease.Path).ToLowerInvariant()
    return Get-TextSha256 ($identity + "`n")
}

function New-OrdinaryDirectory([string]$Path, [string]$Label) {
    Assert-NewOrdinaryDirectoryTarget -Path $Path -Label $Label
    [IO.Directory]::CreateDirectory($Path) | Out-Null
    return ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
        -Path $Path -Label $Label
}

function Get-BaseEnvironment([string]$ScratchRoot) {
    $windows = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::Windows)
    if ([string]::IsNullOrWhiteSpace($windows)) {
        $windows = $env:SystemRoot
    }
    if ([string]::IsNullOrWhiteSpace($windows)) {
        throw 'Windows root is unavailable for the fixed build environment.'
    }
    $system32 = Join-Path $windows 'System32'
    return [ordered]@{
        'SystemRoot' = $windows
        'WINDIR' = $windows
        'PATH' = "$system32;$windows"
        'TEMP' = $ScratchRoot
        'TMP' = $ScratchRoot
    }
}

function Invoke-LockedProcess(
    [string]$Executable,
    [string[]]$Arguments,
    [string]$WorkingDirectory,
    [Collections.IDictionary]$Environment,
    [int]$TimeoutMilliseconds = 1800000
) {
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = $script:Utf8
    $startInfo.StandardErrorEncoding = $script:Utf8
    $startInfo.Environment.Clear()
    foreach ($name in $Environment.Keys) {
        $startInfo.Environment[[string]$name] = [string]$Environment[$name]
    }
    foreach ($argument in $Arguments) {
        $startInfo.ArgumentList.Add($argument)
    }
    $startedAt = Get-CanonicalUtc
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "Unable to start fixed process '$Executable'."
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            try { $process.Kill($true) } catch { }
            throw "Fixed process '$Executable' exceeded its timeout."
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        [byte[]]$stdoutBytes = $script:Utf8.GetBytes($stdout)
        [byte[]]$stderrBytes = $script:Utf8.GetBytes($stderr)
        try {
            if ($stdoutBytes.LongLength -gt $script:MaximumProcessOutputBytes -or
                $stderrBytes.LongLength -gt $script:MaximumProcessOutputBytes) {
                throw "Fixed process '$Executable' output exceeded its evidence bound."
            }
            return [pscustomobject]@{
                StartedAtUtc = $startedAt
                CompletedAtUtc = Get-CanonicalUtc
                ExitCode = [int]$process.ExitCode
                Stdout = $stdout
                Stderr = $stderr
                StdoutBytes = [int64]$stdoutBytes.LongLength
                StdoutSha256 = Get-Sha256Bytes -Bytes $stdoutBytes
                StderrBytes = [int64]$stderrBytes.LongLength
                StderrSha256 = Get-Sha256Bytes -Bytes $stderrBytes
            }
        }
        finally {
            [Security.Cryptography.CryptographicOperations]::ZeroMemory(
                $stdoutBytes)
            [Security.Cryptography.CryptographicOperations]::ZeroMemory(
                $stderrBytes)
        }
    }
    finally {
        $process.Dispose()
    }
}

function Initialize-PersonalNuGetEnvironment(
    [Collections.IDictionary]$Environment,
    [string]$WorkRoot
) {
    # NuGet resolves default configuration folders even with --configfile.
    # Supply private empty roots instead of inheriting machine/user settings.
    foreach ($name in @('ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432',
            'PROGRAMDATA', 'ALLUSERSPROFILE', 'USERPROFILE', 'APPDATA',
            'LOCALAPPDATA')) {
        $path = Join-Path (Join-Path $WorkRoot 'environment') $name
        $Environment[$name] = [IO.Directory]::CreateDirectory($path).FullName
    }
}

function Get-PersonalBuildFailureDiagnostic($Result) {
    # MSBuild reports most restore errors on stdout, not stderr. Keep bounded
    # tails from both channels so an exit code cannot hide the actual cause.
    $parts = foreach ($name in @('Stderr', 'Stdout')) {
        $value = ([string]$Result.$name).Trim()
        if ($value.Length -gt 4096) {
            $value = '[tail] ' + $value.Substring($value.Length - 4096)
        }
        if ($value.Length -gt 0) { "${name}: $value" }
    }
    return $parts -join "`n"
}

function Resolve-LockedApplication([string]$Name, [string]$Label) {
    $command = Get-Command $Name -CommandType Application -ErrorAction Stop |
        Select-Object -First 1
    if ($null -eq $command -or
        -not [IO.Path]::IsPathFullyQualified([string]$command.Source)) {
        throw "$Label must resolve to one absolute application path."
    }
    return ProductionReleaseState\Open-ProductionReleaseInput `
        -Path ([string]$command.Source) -Label $Label -MaximumBytes 512MB
}

function Invoke-Git(
    $GitDescriptor,
    [string]$SourceRoot,
    [string[]]$Arguments
) {
    $environment = Get-BaseEnvironment -ScratchRoot $SourceRoot
    $environment['GIT_CONFIG_NOSYSTEM'] = '1'
    $environment['GIT_CONFIG_GLOBAL'] = 'NUL'
    $environment['GIT_OPTIONAL_LOCKS'] = '0'
    $environment['LC_ALL'] = 'C'
    $safeDirectory = 'safe.directory=' + $SourceRoot.Replace('\', '/')
    $result = Invoke-LockedProcess -Executable $GitDescriptor.Path `
        -Arguments (@(
            '-c', $safeDirectory,
            '-c', 'core.fsmonitor=false',
            '-c', 'core.untrackedCache=false',
            '-C', $SourceRoot
        ) + $Arguments) -WorkingDirectory $SourceRoot `
        -Environment $environment -TimeoutMilliseconds 120000
    if ($result.ExitCode -ne 0) {
        throw "Read-only Git inspection failed: $($result.Stderr.Trim())"
    }
    return $result.Stdout
}

function Get-CleanSourceSnapshot(
    $GitDescriptor,
    [string]$SourceRoot,
    [string]$Label
) {
    $topLevel = (Invoke-Git $GitDescriptor $SourceRoot @(
        'rev-parse', '--show-toplevel')).Trim()
    $topLevel = [IO.Path]::GetFullPath($topLevel).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    if (-not $topLevel.Equals(
            $SourceRoot,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must be the exact Git top-level checkout."
    }
    $status = Invoke-Git $GitDescriptor $SourceRoot @(
        'status', '--porcelain=v1', '--untracked-files=all')
    if (-not [string]::IsNullOrWhiteSpace($status)) {
        throw "$Label is not completely clean, including untracked files."
    }
    $commit = (Invoke-Git $GitDescriptor $SourceRoot @(
        'rev-parse', 'HEAD')).Trim()
    $tree = (Invoke-Git $GitDescriptor $SourceRoot @(
        'rev-parse', 'HEAD^{tree}')).Trim()
    if (-not (Test-ProductionGitObject $commit) -or
        -not (Test-ProductionGitObject $tree)) {
        throw "$Label has a malformed or placeholder Git identity."
    }
    $inventoryText = Invoke-Git $GitDescriptor $SourceRoot @(
        'ls-tree', '-r', '--full-tree', $commit)
    if ([string]::IsNullOrWhiteSpace($inventoryText)) {
        throw "$Label tracked source inventory is empty."
    }
    $inventory = $inventoryText.TrimEnd("`r", "`n").Replace("`r`n", "`n") +
        "`n"
    $epochText = (Invoke-Git $GitDescriptor $SourceRoot @(
        'show', '-s', '--format=%ct', $commit)).Trim()
    [int64]$epoch = 0
    if (-not [int64]::TryParse(
            $epochText,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$epoch) -or $epoch -le 0) {
        throw "$Label commit timestamp is invalid."
    }
    return [pscustomobject]@{
        Commit = $commit
        Tree = $tree
        InventorySha256 = Get-TextSha256 $inventory
        SourceDateEpoch = $epoch
    }
}

function Assert-SourceStillClean(
    $GitDescriptor,
    [string]$SourceRoot,
    $Before,
    [string]$Label
) {
    $after = Get-CleanSourceSnapshot -GitDescriptor $GitDescriptor `
        -SourceRoot $SourceRoot -Label $Label
    if ($after.Commit -cne $Before.Commit -or
        $after.Tree -cne $Before.Tree -or
        $after.InventorySha256 -cne $Before.InventorySha256 -or
        $after.SourceDateEpoch -ne $Before.SourceDateEpoch) {
        throw "$Label changed during its production build."
    }
}

function Assert-CanonicalHttpsOrigin([string]$Value, [string]$Label) {
    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -cne 'https' -or
        -not [string]::IsNullOrEmpty($uri.UserInfo) -or
        -not [string]::IsNullOrEmpty($uri.Query) -or
        -not [string]::IsNullOrEmpty($uri.Fragment) -or
        $uri.AbsolutePath -cne '/' -or
        $uri.AbsoluteUri -cne $Value) {
        throw "$Label must be one canonical HTTPS origin ending in '/'."
    }
}

function Assert-P256Coordinate([string]$Value, [string]$Label) {
    if ($Value -notmatch '^[A-Za-z0-9_-]{43}$' -or
        $Value -match '^([A-Za-z0-9_-])\1{42}$') {
        throw "$Label is malformed or a placeholder."
    }
    $padded = $Value.Replace('-', '+').Replace('_', '/') + '='
    try {
        [byte[]]$bytes = [Convert]::FromBase64String($padded)
    }
    catch {
        throw "$Label is not canonical base64url."
    }
    try {
        if ($bytes.Length -ne 32) {
            throw "$Label is not one P-256 coordinate."
        }
    }
    finally {
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
    }
}

function Read-AndLockBuildIntent([string]$Path) {
    $descriptor = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $Path -Label 'Personal two-clean build intent' `
        -MaximumBytes 1MB
    try {
        [byte[]]$bytes =
            ProductionReleaseState\Read-ProductionReleaseInputBytes `
                -Descriptor $descriptor -Label 'Personal two-clean build intent'
        try {
            $value = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
                -Bytes $bytes -Label 'Personal two-clean build intent' `
                -SchemaPath $intentSchemaPath
            $jsonInput = [pscustomobject]@{
                Bytes = $bytes
                Sha256 = [string]$descriptor.Sha256
                Value = $value
            }
            [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
                -JsonInput $jsonInput -Label 'Personal two-clean build intent')
            if (-not (Test-ProductionGitObject ([string]$value.sourceCommit)) -or
                -not (Test-ProductionGitObject ([string]$value.sourceTree)) -or
                -not (Test-ProductionSha256 `
                    ([string]$value.authenticodeSignerSha256Thumbprint))) {
                throw 'Personal two-clean build intent contains a placeholder production identity.'
            }
            Assert-CanonicalHttpsOrigin -Value ([string]$value.manifestOrigin) `
                -Label 'Personal manifest origin'
            Assert-CanonicalHttpsOrigin -Value ([string]$value.artifactOrigin) `
                -Label 'Personal artifact origin'
            [void](PersonalAccountReleaseConfiguration\Assert-PersonalAccountOrigin `
                -Value ([string]$value.personalAccountOrigin) -Label 'Personal account origin')
            Assert-P256Coordinate -Value ([string]$value.releaseManifestTrust.x) `
                -Label 'Personal release trust x'
            Assert-P256Coordinate -Value ([string]$value.releaseManifestTrust.y) `
                -Label 'Personal release trust y'
            if ([string]$value.releaseManifestTrust.x -ceq
                [string]$value.releaseManifestTrust.y) {
                throw 'Personal release trust coordinates must be distinct.'
            }
            return [pscustomobject]@{
                Descriptor = $descriptor
                Bytes = $bytes
                Value = $value
            }
        }
        catch {
            [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
            throw
        }
    }
    catch {
        $descriptor.Stream.Dispose()
        throw
    }
}

function Get-DependencyClosure(
    [string]$SourceRoot,
    [Collections.Generic.List[object]]$HeldInputs
) {
    $lines = [Collections.Generic.List[string]]::new()
    foreach ($relativePath in $script:DependencyPaths) {
        $path = Join-Path $SourceRoot `
            $relativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)
        $input = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $path -Label "Personal build lock '$relativePath'" `
            -MaximumBytes 64MB
        $HeldInputs.Add($input)
        $lines.Add(
            "$relativePath|$([int64]$input.SizeBytes)|$([string]$input.Sha256)")
    }
    return Get-TextSha256 (($lines -join "`n") + "`n")
}

function Assert-HeldInputsStillLocked(
    [Collections.Generic.List[object]]$Inputs,
    [string]$Label
) {
    foreach ($input in $Inputs) {
        ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $input -Label "$Label '$([string]$input.FileName)'"
    }
}

function New-OfflineNuGetConfig([string]$Path) {
    [byte[]]$bytes = $script:Utf8.GetBytes(@'
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
  </packageSources>
</configuration>
'@.Trim() + "`n")
    try {
        $stream = [IO.File]::Open(
            $Path,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        try {
            $stream.Write($bytes)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
    }
}

function New-MaterializedCheckout(
    [string]$SourceRoot,
    $SourceSnapshot,
    $GitDescriptor,
    [string]$Destination,
    [Collections.IDictionary]$Environment,
    [string]$Label
) {
    Assert-NewOrdinaryDirectoryTarget -Path $Destination `
        -Label "$Label materialized checkout"
    $safeDirectory = 'safe.directory=' + $SourceRoot.Replace('\', '/')
    # Clone must not inherit machine/user Git conversion policy.  Keep this
    # separate from the build environment so dotnet retains only its own fixed
    # execution inputs.
    $cloneEnvironment = [ordered]@{}
    foreach ($name in $Environment.Keys) {
        $cloneEnvironment[[string]$name] = [string]$Environment[$name]
    }
    $cloneEnvironment['GIT_CONFIG_NOSYSTEM'] = '1'
    $cloneEnvironment['GIT_CONFIG_GLOBAL'] = 'NUL'
    $cloneEnvironment['GIT_OPTIONAL_LOCKS'] = '0'
    $cloneEnvironment['LC_ALL'] = 'C'
    $clone = Invoke-LockedProcess -Executable $GitDescriptor.Path `
        -Arguments @(
            '-c', $safeDirectory,
            'clone', '--no-hardlinks', '--no-tags', '--quiet',
            $SourceRoot, $Destination) `
        -WorkingDirectory ([IO.Path]::GetDirectoryName($Destination)) `
        -Environment $cloneEnvironment
    if ($clone.ExitCode -ne 0) {
        throw "$Label could not materialize its clean source checkout: $($clone.Stderr.Trim())"
    }
    $checkout = Invoke-Git -GitDescriptor $GitDescriptor -SourceRoot $Destination `
        -Arguments @('checkout', '--detach', '--quiet', [string]$SourceSnapshot.Commit)
    if ([string]::IsNullOrWhiteSpace($checkout) -eq $false) {
        throw "$Label materialized checkout emitted unexpected checkout output."
    }
    $snapshot = Get-CleanSourceSnapshot -GitDescriptor $GitDescriptor `
        -SourceRoot $Destination -Label "$Label materialized checkout"
    foreach ($name in @('Commit', 'Tree', 'InventorySha256', 'SourceDateEpoch')) {
        if ([string]$snapshot.$name -cne [string]$SourceSnapshot.$name) {
            throw "$Label materialized checkout differs from its locked source $name."
        }
    }
    $existingObjRoots = @(Get-ChildItem -LiteralPath $Destination -Recurse `
        -Force -Directory | Where-Object { $_.Name -ceq 'obj' })
    if ($existingObjRoots.Count -ne 0) {
        throw "$Label materialized checkout contains pre-existing obj intermediates before restore."
    }
    return ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
        -Path $Destination -Label "$Label materialized checkout"
}

function Get-RestoreAssetClosure(
    [string]$MaterializedCheckout,
    [string]$EvidenceRootPath,
    [string]$Label
) {
    $assetNames = @(
        'project.assets.json',
        'project.nuget.cache',
        '*.nuget.g.props',
        '*.nuget.g.targets',
        '*.nuget.dgspec.json'
    )
    $paths = @(Get-ChildItem -LiteralPath $MaterializedCheckout -Recurse -Force -File |
        Where-Object {
            $_.FullName.StartsWith(
                (Join-Path $MaterializedCheckout 'obj') +
                    [IO.Path]::DirectorySeparatorChar,
                [StringComparison]::OrdinalIgnoreCase) -or
            $_.FullName -match '[\\/]obj[\\/]'
        } |
        Where-Object {
            $admitted = $false
            foreach ($name in $assetNames) {
                if ($_.Name -like $name) {
                    $admitted = $true
                    break
                }
            }
            $admitted
        } | Sort-Object FullName)
    if ($paths.Count -eq 0) {
        throw "$Label offline locked restore did not produce any admitted assets."
    }
    $inputs = [Collections.Generic.List[object]]::new()
    try {
        $files = [Collections.Generic.List[object]]::new()
        foreach ($path in $paths) {
            $input = ProductionReleaseState\Open-ProductionReleaseInput `
                -Path $path.FullName -Label "$Label restore asset" `
                -MaximumBytes 64MB
            $inputs.Add($input)
            $files.Add([ordered]@{
                relativePath = [IO.Path]::GetRelativePath(
                    $EvidenceRootPath, [string]$input.Path).Replace('\', '/')
                sizeBytes = [int64]$input.SizeBytes
                sha256 = [string]$input.Sha256
            })
        }
        $lines = foreach ($file in $files) {
            '{0}|{1}|{2}' -f $file.relativePath, $file.sizeBytes, $file.sha256
        }
        return [pscustomobject]@{
            Inputs = $inputs
            Files = @($files)
            Sha256 = Get-TextSha256 (($lines -join "`n") + "`n")
        }
    }
    catch {
        foreach ($input in $inputs) { $input.Stream.Dispose() }
        throw
    }
}

function Assert-RestoreAssetClosureStillLocked($Closure, [string]$Label) {
    foreach ($input in $Closure.Inputs) {
        ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $input -Label "$Label restore asset"
    }
}

function Invoke-PersonalAccountBuildProbe(
    $LauncherOutput,
    $Intent,
    [string]$EvidenceRootPath,
    [string]$WorkRoot,
    [string]$RunLabel
) {
    # This is an unsigned build observation, not Authenticode admission. Hold
    # the exact published PE while capturing its raw, bounded metadata output.
    if ($LauncherOutput.role -cne 'launcher' -or
        $LauncherOutput.fileName -cne 'Ensou.Dsh.Launcher.exe' -or
        $LauncherOutput.relativePath -cne "build-artifacts/$RunLabel/launcher/Ensou.Dsh.Launcher.exe") {
        throw 'The account self-check requires the canonical Launcher output.'
    }
    $input = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path (Join-Path $EvidenceRootPath $LauncherOutput.relativePath) `
        -Label 'Personal account self-check executable' -MaximumBytes 1GB
    $probeLease = $null
    try {
        if ($input.Sha256 -cne $LauncherOutput.sha256 -or
            $input.SizeBytes -ne $LauncherOutput.sizeBytes) {
            throw 'The published Launcher changed before its account self-check.'
        }
        $probeRoot = Join-Path $WorkRoot 'account-self-check'
        $probeLease = New-OrdinaryDirectory -Path $probeRoot -Label 'Personal account self-check scratch'
        $environment = Get-BaseEnvironment -ScratchRoot $probeRoot
        foreach ($name in @('USERPROFILE', 'HOME', 'APPDATA', 'LOCALAPPDATA',
                'DOTNET_CLI_HOME', 'DOTNET_BUNDLE_EXTRACT_BASE_DIR')) {
            $environment[$name] = $probeRoot
        }
        $environment['DOTNET_ROOT'] = Join-Path $probeRoot 'no-global-dotnet'
        $environment['DOTNET_ROOT_X64'] = $environment['DOTNET_ROOT']
        $environment['DOTNET_MULTILEVEL_LOOKUP'] = '0'
        $environment['DOTNET_EnableDiagnostics'] = '0'
        $environment['COMPlus_EnableDiagnostics'] = '0'
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $input.Path
        $start.WorkingDirectory = $probeRoot
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.ArgumentList.Add('--personal-account-self-check')
        $start.Environment.Clear()
        foreach ($name in $environment.Keys) {
            $start.Environment[[string]$name] = [string]$environment[$name]
        }
        $started = Get-CanonicalUtc
        $capture = ProductionBoundedProcess\Invoke-ProductionBoundedProcessCapture `
            -StartInfo $start -TimeoutMilliseconds 40000 -MaximumOutputBytes 16384
        $completed = Get-CanonicalUtc
        if ($capture.TimedOut -or $capture.ExitCode -ne 0 -or
            $capture.StandardOutput.Overflowed -or $capture.StandardError.Overflowed -or
            $capture.StandardError.Bytes.Length -ne 0) {
            throw 'The published Launcher account self-check did not complete cleanly.'
        }
        [void](PersonalAccountReleaseConfiguration\ConvertFrom-PersonalAccountSelfCheck `
            -Bytes $capture.StandardOutput.Bytes -ExpectedOrigin ([string]$Intent.personalAccountOrigin))
        ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $input -Label 'Personal account self-check executable'
        ProductionReleaseState\Assert-ProductionReleaseDirectoryStillLocked `
            -Descriptor $probeLease -Label 'Personal account self-check scratch'
        $relative = "builds/$RunLabel-personal-account-self-check.json"
        $outputStream = [IO.File]::Open((Join-Path $EvidenceRootPath $relative),
            [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $outputStream.Write($capture.StandardOutput.Bytes)
            $outputStream.Flush($true)
        } finally { $outputStream.Dispose() }
        return [ordered]@{
            command = '--personal-account-self-check'
            executableSha256 = [string]$input.Sha256
            startedAtUtc = $started
            completedAtUtc = $completed
            exitCode = 0
            stdout = [ordered]@{
                relativePath = $relative
                sizeBytes = [int64]$capture.StandardOutput.Bytes.Length
                sha256 = Get-Sha256Bytes -Bytes $capture.StandardOutput.Bytes
            }
            stderrBytes = 0
            stderrSha256 = Get-Sha256Bytes -Bytes $capture.StandardError.Bytes
        }
    } finally {
        if ($null -ne $probeLease) { $probeLease.Handle.Dispose() }
        $input.Stream.Dispose()
    }
}

function Get-PersonalProductionPropertyArguments(
    [string]$SourceRoot,
    $Intent
) {
    return @(
        '-p:PublishSingleFile=true',
        '-p:EnableCompressionInSingleFile=true',
        '-p:IncludeNativeLibrariesForSelfExtract=true',
        '-p:PublishTrimmed=false',
        '-p:PublishAot=false',
        '-p:ContinuousIntegrationBuild=true',
        '-p:Deterministic=true',
        '-p:PersonalProductionBuild=true',
        '-p:PersonalDevelopmentPublish=false',
        "-p:Version=$([string]$Intent.version)",
        "-p:PathMap=$SourceRoot=/_/src",
        "-p:PersonalManifestOrigin=$([string]$Intent.manifestOrigin)",
        "-p:PersonalArtifactOrigin=$([string]$Intent.artifactOrigin)",
        "-p:PersonalAccountOrigin=$([string]$Intent.personalAccountOrigin)",
        "-p:PersonalChannel=$([string]$Intent.channel)",
        "-p:PersonalReleaseKeyId=$([string]$Intent.releaseManifestTrust.keyId)",
        "-p:PersonalReleaseKeyX=$([string]$Intent.releaseManifestTrust.x)",
        "-p:PersonalReleaseKeyY=$([string]$Intent.releaseManifestTrust.y)",
        "-p:PersonalStartupStubVersion=$([string]$Intent.startupStubVersion)",
        "-p:PersonalCanonicalLowSFromSequence=$([int64]$Intent.canonicalLowSFromSequence)",
        "-p:PersonalAuthenticodeSignerSha256Thumbprint=$([string]$Intent.authenticodeSignerSha256Thumbprint)"
    )
}

function Get-RestoreArguments(
    [string]$SourceRoot,
    [string]$OfflineNuGetConfig,
    [string]$OfflinePackageCacheRoot,
    $Intent,
    $Project
) {
    $projectPath = Join-Path $SourceRoot `
        $Project.Project.Replace('/', [IO.Path]::DirectorySeparatorChar)
    return @(
        'restore', $projectPath,
        '--locked-mode', '--disable-parallel',
        '--configfile', $OfflineNuGetConfig,
        '--packages', $OfflinePackageCacheRoot,
        '-p:Configuration=Release'
    ) + @(Get-PersonalProductionPropertyArguments `
        -SourceRoot $SourceRoot -Intent $Intent | Where-Object {
            # The executable projects pin RID/SelfContained/PublishSingleFile.
            # NuGet restore propagates command-line globals to library graphs
            # even when ProjectReference.GlobalPropertiesToRemove is present.
            # Keep trust/production inputs, but scope these three settings to
            # the executable projects so existing portable library locks hold.
            $_ -cne '-p:PublishSingleFile=true'
        })
}

function Get-PublishArguments(
    [string]$SourceRoot,
    [string]$OutputDirectory,
    $Intent,
    $Project
) {
    $projectPath = Join-Path $SourceRoot `
        $Project.Project.Replace('/', [IO.Path]::DirectorySeparatorChar)
    return @(
        'publish',
        $projectPath,
        '--configuration', 'Release',
        '--runtime', 'win-x64',
        '--self-contained', 'true',
        '--no-restore'
    ) + @(Get-PersonalProductionPropertyArguments `
        -SourceRoot $SourceRoot -Intent $Intent) + @(
        '--output', $OutputDirectory
    )
}

function Get-NormalizedCommandContractSha256(
    [string]$SourceRoot,
    [string]$OutputRoot,
    $Intent
) {
    $lines = [Collections.Generic.List[string]]::new()
    foreach ($project in $script:ProjectContract) {
        $output = Join-Path $OutputRoot $project.Role
        $arguments = Get-PublishArguments -SourceRoot $SourceRoot `
            -OutputDirectory $output -Intent $Intent -Project $project
        $normalized = foreach ($argument in $arguments) {
            $argument.Replace($SourceRoot, '<SOURCE>',
                    [StringComparison]::OrdinalIgnoreCase).
                Replace($OutputRoot, '<OUTPUT>',
                    [StringComparison]::OrdinalIgnoreCase)
        }
        $lines.Add(
            "$($project.Ordinal)|$($project.Role)|$($project.Project)|$($normalized -join [char]0x1f)")
    }
    return Get-TextSha256 (($lines -join "`n") + "`n")
}

function Get-OutputDescriptor(
    [string]$EvidenceRootPath,
    [string]$OutputDirectory,
    $Project
) {
    $entries = @(Get-ChildItem -LiteralPath $OutputDirectory -Force)
    if ($entries.Count -ne 1 -or $entries[0].PSIsContainer -or
        [string]$entries[0].Name -cne [string]$Project.FileName) {
        throw "Personal publish '$($Project.Role)' did not create exactly its canonical PE."
    }
    $input = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $entries[0].FullName `
        -Label "Personal unsigned output '$($Project.Role)'" `
        -MaximumBytes 1GB
    try {
        [byte[]]$bytes =
            ProductionReleaseState\Read-ProductionReleaseInputBytes `
                -Descriptor $input `
                -Label "Personal unsigned output '$($Project.Role)'"
        try {
            $peContentSha256 =
                ProductionReleaseState\Get-PeContentSha256 -Bytes $bytes
        }
        finally {
            [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
        }
        $signature =
            Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
                -LiteralPath $input.Path
        if ([string]$signature.Status -cne 'NotSigned' -or
            $null -ne $signature.SignerCertificate) {
            throw "Personal output '$($Project.Role)' is already signed; the two-clean producer admits unsigned bytes only."
        }
        return [ordered]@{
            role = [string]$Project.Role
            fileName = [string]$Project.FileName
            relativePath = [IO.Path]::GetRelativePath(
                    $EvidenceRootPath,
                    [string]$input.Path).
                Replace('\', '/')
            sizeBytes = [int64]$input.SizeBytes
            sha256 = [string]$input.Sha256
            peContentSha256 = $peContentSha256
            authenticodeStatus = 'NotSigned'
        }
    }
    finally {
        $input.Stream.Dispose()
    }
}

function Get-OutputClosureSha256([object[]]$Invocations) {
    $lines = foreach ($invocation in $Invocations) {
        $output = $invocation.output
        '{0}|{1}|{2}|{3}|{4}' -f `
            [string]$output.role,
            [string]$output.fileName,
            [int64]$output.sizeBytes,
            [string]$output.sha256,
            [string]$output.peContentSha256
    }
    return Get-TextSha256 (($lines -join "`n") + "`n")
}

function Get-RestoreCommandContractSha256(
    [Collections.Generic.List[object]]$Commands,
    [string]$MaterializedCheckout,
    [string]$OfflinePackageCacheRoot,
    [string]$OfflineNuGetConfig
) {
    $lines = foreach ($command in $Commands) {
        $normalized = foreach ($argument in @($command.arguments)) {
            $argument.Replace($MaterializedCheckout, '<SOURCE>',
                    [StringComparison]::OrdinalIgnoreCase).
                Replace($OfflinePackageCacheRoot, '<OFFLINE_PACKAGE_CACHE>',
                    [StringComparison]::OrdinalIgnoreCase).
                Replace($OfflineNuGetConfig, '<OFFLINE_NUGET_CONFIG>',
                    [StringComparison]::OrdinalIgnoreCase)
        }
        '{0}|{1}|{2}|{3}' -f `
            [int]$command.ordinal,
            [string]$command.role,
            [string]$command.projectRelativePath,
            ($normalized -join [char]0x1f)
    }
    return Get-TextSha256 (($lines -join "`n") + "`n")
}

function Get-RestoreClosureSha256([object[]]$Runs) {
    $lines = [Collections.Generic.List[string]]::new()
    foreach ($run in $Runs) {
        $restore = $run.restore
        $lines.Add(('run|{0}|{1}|{2}|{3}|{4}|{5}' -f `
            [string]$run.runLabel,
            [string]$run.materializedCheckoutPhysicalIdentitySha256,
            [string]$run.intermediateRootPhysicalIdentitySha256,
            [string]$restore.packageCacheRootPhysicalIdentitySha256,
            [string]$restore.commandContractSha256,
            [string]$restore.assetsClosureSha256))
        foreach ($command in @($restore.commands)) {
            $lines.Add(('command|{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}|{9}' -f `
                [string]$run.runLabel,
                [int]$command.ordinal,
                [string]$command.role,
                [string]$command.projectRelativePath,
                ((@($command.arguments)) -join [char]0x1f),
                [int]$command.exitCode,
                [int64]$command.stdoutBytes,
                [string]$command.stdoutSha256,
                [int64]$command.stderrBytes,
                [string]$command.stderrSha256))
        }
        foreach ($asset in @($restore.assets)) {
            $lines.Add(('asset|{0}|{1}|{2}|{3}' -f `
                [string]$run.runLabel,
                [string]$asset.relativePath,
                [int64]$asset.sizeBytes,
                [string]$asset.sha256))
        }
    }
    return Get-TextSha256 (($lines -join "`n") + "`n")
}

function Invoke-CleanBuildRun(
    [string]$RunLabel,
    [string]$SourceRoot,
    $SourceLease,
    $SourceSnapshot,
    [string]$EvidenceRootPath,
    $Intent,
    $DotnetDescriptor,
    $GitDescriptor,
    [Collections.Generic.List[object]]$SourceInputs,
    $OfflinePackageCacheLease,
    [string]$ExpectedCommandContractSha256
) {
    $artifactParent = Join-Path $EvidenceRootPath 'build-artifacts'
    if (-not (Test-Path -LiteralPath $artifactParent)) {
        [IO.Directory]::CreateDirectory($artifactParent) | Out-Null
    }
    $outputRoot = Join-Path $artifactParent $RunLabel
    $outputLease = New-OrdinaryDirectory -Path $outputRoot `
        -Label "Personal $RunLabel output root"
    try {
        $workParent = Join-Path $EvidenceRootPath 'work'
        if (-not (Test-Path -LiteralPath $workParent)) {
            [IO.Directory]::CreateDirectory($workParent) | Out-Null
        }
        $workRoot = Join-Path $workParent $RunLabel
        $workLease = New-OrdinaryDirectory -Path $workRoot `
            -Label "Personal $RunLabel work root"
        try {
            $dotnetHome = Join-Path $workRoot 'dotnet-home'
            $tempRoot = Join-Path $workRoot 'temp'
            [IO.Directory]::CreateDirectory($dotnetHome) | Out-Null
            [IO.Directory]::CreateDirectory($tempRoot) | Out-Null
            $environment = Get-BaseEnvironment -ScratchRoot $tempRoot
            Initialize-PersonalNuGetEnvironment -Environment $environment `
                -WorkRoot $workRoot
            $environment['PATH'] =
                ([IO.Path]::GetDirectoryName($DotnetDescriptor.Path) + ';' +
                 $environment['PATH'])
            $environment['CI'] = 'true'
            $environment['DOTNET_ROOT'] =
                [IO.Path]::GetDirectoryName($DotnetDescriptor.Path)
            $environment['DOTNET_CLI_HOME'] = $dotnetHome
            $environment['DOTNET_NOLOGO'] = '1'
            $environment['DOTNET_CLI_TELEMETRY_OPTOUT'] = '1'
            $environment['DOTNET_SKIP_FIRST_TIME_EXPERIENCE'] = '1'
            $environment['DOTNET_GENERATE_ASPNET_CERTIFICATE'] = 'false'
            $environment['DOTNET_MULTILEVEL_LOOKUP'] = '0'
            $environment['DOTNET_CLI_UI_LANGUAGE'] = 'en-US'
            $environment['NUGET_XMLDOC_MODE'] = 'skip'
            $environment['NUGET_PACKAGES'] =
                [string]$OfflinePackageCacheLease.Path
            $environment['NUGET_HTTP_CACHE_PATH'] =
                Join-Path $workRoot 'nuget-http-cache'
            $environment['NUGET_PLUGINS_CACHE_PATH'] =
                Join-Path $workRoot 'nuget-plugins-cache'
            $environment['MSBUILDNOINPROCNODE'] = '1'
            $environment['MSBUILDDISABLENODEREUSE'] = '1'
            $environment['SOURCE_DATE_EPOCH'] =
                [string]$SourceSnapshot.SourceDateEpoch
            $environment['TZ'] = 'UTC'

            [IO.Directory]::CreateDirectory(
                [string]$environment['NUGET_HTTP_CACHE_PATH']) | Out-Null
            [IO.Directory]::CreateDirectory(
                [string]$environment['NUGET_PLUGINS_CACHE_PATH']) | Out-Null
            $materializedLease = $null
            $intermediateLease = $null
            $restoreClosure = $null
            try {
                $materializedPath = Join-Path $workRoot 'source'
                $materializedLease = New-MaterializedCheckout `
                    -SourceRoot $SourceRoot -SourceSnapshot $SourceSnapshot `
                    -GitDescriptor $GitDescriptor -Destination $materializedPath `
                    -Environment $environment -Label "Personal $RunLabel"
                $offlineNuGetConfig = Join-Path $workRoot 'NuGet.Config'
                New-OfflineNuGetConfig -Path $offlineNuGetConfig
                $restoreCommands = [Collections.Generic.List[object]]::new()
                foreach ($project in $script:ProjectContract) {
                    $restoreArguments = Get-RestoreArguments `
                        -SourceRoot $materializedPath `
                        -OfflineNuGetConfig $offlineNuGetConfig `
                        -OfflinePackageCacheRoot `
                            ([string]$OfflinePackageCacheLease.Path) `
                        -Intent $Intent -Project $project
                    $restore = Invoke-LockedProcess `
                        -Executable $DotnetDescriptor.Path `
                        -Arguments $restoreArguments `
                        -WorkingDirectory $materializedPath `
                        -Environment $environment
                    if ($restore.ExitCode -ne 0) {
                        throw "Personal $RunLabel '$($project.Role)' offline locked restore failed with exit $($restore.ExitCode): $(Get-PersonalBuildFailureDiagnostic -Result $restore)"
                    }
                    $restoreCommands.Add([ordered]@{
                        ordinal = [int]$project.Ordinal
                        role = [string]$project.Role
                        projectRelativePath = [string]$project.Project
                        arguments = @($restoreArguments)
                        startedAtUtc = [string]$restore.StartedAtUtc
                        completedAtUtc = [string]$restore.CompletedAtUtc
                        exitCode = [int]$restore.ExitCode
                        stdoutBytes = [int64]$restore.StdoutBytes
                        stdoutSha256 = [string]$restore.StdoutSha256
                        stderrBytes = [int64]$restore.StderrBytes
                        stderrSha256 = [string]$restore.StderrSha256
                    })
                }
                $restoreClosure = Get-RestoreAssetClosure `
                    -MaterializedCheckout $materializedPath `
                    -EvidenceRootPath $EvidenceRootPath `
                    -Label "Personal $RunLabel"
                $restoreCommandContractSha256 =
                    Get-RestoreCommandContractSha256 `
                        -Commands $restoreCommands `
                        -MaterializedCheckout $materializedPath `
                        -OfflinePackageCacheRoot `
                            ([string]$OfflinePackageCacheLease.Path) `
                        -OfflineNuGetConfig $offlineNuGetConfig
                # The detached checkout is the containment root for every
                # project-local obj directory.  A Git clone excludes ignored
                # obj state, so the restore closure cannot consume either
                # source checkout's pre-existing intermediates.
                $intermediatePath = $materializedPath

                $actualCommandContractSha256 =
                    Get-NormalizedCommandContractSha256 `
                        -SourceRoot $materializedPath -OutputRoot $outputRoot `
                        -Intent $Intent
            if ($actualCommandContractSha256 -cne
                $ExpectedCommandContractSha256) {
                throw "Personal $RunLabel command contract drifted."
            }

            $runStarted = Get-CanonicalUtc
            $invocations = [Collections.Generic.List[object]]::new()
            foreach ($project in $script:ProjectContract) {
                $projectPath = Join-Path $materializedPath `
                    $project.Project.Replace(
                        '/', [IO.Path]::DirectorySeparatorChar)
                $projectInput = ProductionReleaseState\Open-ProductionReleaseInput `
                    -Path $projectPath `
                    -Label "Personal project '$($project.Role)'" `
                    -MaximumBytes 4MB
                try {
                    $outputDirectory = Join-Path $outputRoot $project.Role
                    $outputDirectoryLease = New-OrdinaryDirectory `
                        -Path $outputDirectory `
                        -Label "Personal $RunLabel '$($project.Role)' publish output"
                    try {
                        $arguments = Get-PublishArguments `
                            -SourceRoot $materializedPath `
                            -OutputDirectory $outputDirectory -Intent $Intent `
                            -Project $project
                        $process = Invoke-LockedProcess `
                            -Executable $DotnetDescriptor.Path `
                            -Arguments $arguments `
                            -WorkingDirectory $materializedPath `
                            -Environment $environment
                        if ($process.ExitCode -ne 0) {
                            throw "Personal $RunLabel '$($project.Role)' fixed dotnet publish failed with exit $($process.ExitCode): $(Get-PersonalBuildFailureDiagnostic -Result $process)"
                        }
                        $output = Get-OutputDescriptor `
                            -EvidenceRootPath $EvidenceRootPath `
                            -OutputDirectory $outputDirectory -Project $project
                        $invocations.Add([ordered]@{
                            ordinal = [int]$project.Ordinal
                            role = [string]$project.Role
                            projectRelativePath = [string]$project.Project
                            arguments = @($arguments)
                            startedAtUtc = [string]$process.StartedAtUtc
                            completedAtUtc = [string]$process.CompletedAtUtc
                            exitCode = [int]$process.ExitCode
                            stdoutBytes = [int64]$process.StdoutBytes
                            stdoutSha256 = [string]$process.StdoutSha256
                            stderrBytes = [int64]$process.StderrBytes
                            stderrSha256 = [string]$process.StderrSha256
                            output = $output
                        })
                    }
                    finally {
                        $outputDirectoryLease.Handle.Dispose()
                    }
                }
                finally {
                    $projectInput.Stream.Dispose()
                }
                Assert-SourceStillClean -GitDescriptor $GitDescriptor `
                    -SourceRoot $SourceRoot -Before $SourceSnapshot `
                    -Label "Personal $RunLabel source checkout"
                Assert-SourceStillClean -GitDescriptor $GitDescriptor `
                    -SourceRoot $materializedPath -Before $SourceSnapshot `
                    -Label "Personal $RunLabel materialized checkout"
                Assert-HeldInputsStillLocked -Inputs $SourceInputs `
                    -Label "Personal $RunLabel source input"
                Assert-RestoreAssetClosureStillLocked -Closure $restoreClosure `
                    -Label "Personal $RunLabel"
                ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                    -Descriptor $DotnetDescriptor -Label 'Locked dotnet executable'
                ProductionReleaseState\Assert-ProductionReleaseDirectoryStillLocked `
                    -Descriptor $SourceLease `
                    -Label "Personal $RunLabel source checkout"
                ProductionReleaseState\Assert-ProductionReleaseDirectoryStillLocked `
                    -Descriptor $materializedLease `
                    -Label "Personal $RunLabel materialized checkout"
                ProductionReleaseState\Assert-ProductionReleaseDirectoryStillLocked `
                    -Descriptor $OfflinePackageCacheLease `
                    -Label 'Personal offline package cache root'
            }
            $accountSelfCheck = Invoke-PersonalAccountBuildProbe `
                -LauncherOutput $invocations[2].output -Intent $Intent `
                -EvidenceRootPath $EvidenceRootPath -WorkRoot $workRoot -RunLabel $RunLabel
            return [ordered]@{
                runLabel = $RunLabel
                buildId = [Guid]::NewGuid().ToString().ToLowerInvariant()
                checkoutPath = $SourceRoot
                checkoutPhysicalIdentitySha256 =
                    Get-DirectoryPhysicalIdentitySha256 -Lease $SourceLease
                materializedCheckoutPath = $materializedPath
                materializedCheckoutPhysicalIdentitySha256 =
                    Get-DirectoryPhysicalIdentitySha256 -Lease $materializedLease
                intermediateRootPath = $intermediatePath
                intermediateRootPhysicalIdentitySha256 =
                    Get-DirectoryPhysicalIdentitySha256 -Lease $materializedLease
                outputRootPath = $outputRoot
                outputRootPhysicalIdentitySha256 =
                    Get-DirectoryPhysicalIdentitySha256 -Lease $outputLease
                sourceStatusBefore = 'CLEAN_TRACKED_HEAD'
                sourceStatusAfter = 'CLEAN_TRACKED_HEAD'
                startedAtUtc = $runStarted
                completedAtUtc = Get-CanonicalUtc
                sourceDateEpoch = [int64]$SourceSnapshot.SourceDateEpoch
                restore = [ordered]@{
                    packageCacheRootPath = [string]$OfflinePackageCacheLease.Path
                    packageCacheRootPhysicalIdentitySha256 =
                        Get-DirectoryPhysicalIdentitySha256 `
                            -Lease $OfflinePackageCacheLease
                    commands = @($restoreCommands)
                    commandContractSha256 = $restoreCommandContractSha256
                    assets = @($restoreClosure.Files)
                    assetsClosureSha256 = [string]$restoreClosure.Sha256
                }
                invocations = @($invocations)
                personalAccountSelfCheck = $accountSelfCheck
                outputClosureSha256 =
                    Get-OutputClosureSha256 -Invocations @($invocations)
            }
            }
            finally {
                if ($null -ne $restoreClosure) {
                    foreach ($input in $restoreClosure.Inputs) {
                        $input.Stream.Dispose()
                    }
                }
                if ($null -ne $materializedLease) {
                    $materializedLease.Handle.Dispose()
                }
            }
        }
        finally {
            $workLease.Handle.Dispose()
        }
    }
    finally {
        $outputLease.Handle.Dispose()
    }
}

function Assert-RunsByteIdentical($First, $Second) {
    if ([string]$First.outputClosureSha256 -cne
        [string]$Second.outputClosureSha256) {
        throw 'Two clean Personal builds produced different output closures.'
    }
    for ($index = 0; $index -lt $script:ProjectContract.Count; $index++) {
        $a = $First.invocations[$index]
        $b = $Second.invocations[$index]
        foreach ($name in @(
            'role', 'fileName', 'sizeBytes', 'sha256', 'peContentSha256',
            'authenticodeStatus')) {
            if ([string]$a.output.$name -cne [string]$b.output.$name) {
                throw "Two clean Personal builds differ on '$name' for output $index."
            }
        }
    }
}

$sourceAPath = Get-FullAbsolutePath -Path $SourceA -Label 'Source A'
$sourceBPath = Get-FullAbsolutePath -Path $SourceB -Label 'Source B'
$intentPath = Get-FullAbsolutePath -Path $BuildIntentPath `
    -Label 'Build intent'
$evidencePath = Get-FullAbsolutePath -Path $EvidenceRoot `
    -Label 'Evidence root'
$offlinePackageCachePath = Get-FullAbsolutePath -Path $OfflinePackageCacheRoot `
    -Label 'Offline package cache root'
if (-not (Test-Path -LiteralPath $offlinePackageCachePath -PathType Container)) {
    throw 'Offline package cache root must be an existing directory.'
}
if (Test-Path -LiteralPath $evidencePath) {
    throw 'Personal two-clean evidence root must not already exist.'
}
Assert-DisjointPaths -First $sourceAPath -Second $sourceBPath `
    -Label 'Source A and Source B'
Assert-DisjointPaths -First $evidencePath -Second $sourceAPath `
    -Label 'Evidence root and Source A'
Assert-DisjointPaths -First $evidencePath -Second $sourceBPath `
    -Label 'Evidence root and Source B'
Assert-DisjointPaths -First $offlinePackageCachePath -Second $sourceAPath `
    -Label 'Offline package cache root and Source A'
Assert-DisjointPaths -First $offlinePackageCachePath -Second $sourceBPath `
    -Label 'Offline package cache root and Source B'
Assert-DisjointPaths -First $offlinePackageCachePath -Second $evidencePath `
    -Label 'Offline package cache root and evidence root'
$userProfile = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::UserProfile)
if (-not [string]::IsNullOrWhiteSpace($userProfile)) {
    Assert-DisjointPaths -First $evidencePath -Second $userProfile `
        -Label 'Evidence root and the user profile'
}
Assert-NewOrdinaryDirectoryTarget -Path $evidencePath `
    -Label 'Personal two-clean evidence root'

$sourceALease = $null
$sourceBLease = $null
$gitDescriptor = $null
$dotnetDescriptor = $null
$intentInput = $null
$evidenceLease = $null
$offlinePackageCacheLease = $null
$sourceAInputs = [Collections.Generic.List[object]]::new()
$sourceBInputs = [Collections.Generic.List[object]]::new()
try {
    $sourceALease = ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
        -Path $sourceAPath -Label 'Personal Source A checkout'
    $sourceBLease = ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
        -Path $sourceBPath -Label 'Personal Source B checkout'
    $offlinePackageCacheLease =
        ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
            -Path $offlinePackageCachePath `
            -Label 'Personal offline package cache root'
    if ($sourceALease.VolumeSerialNumber -eq $sourceBLease.VolumeSerialNumber -and
        $sourceALease.FileIndex -eq $sourceBLease.FileIndex) {
        throw 'Source A and Source B resolve to the same physical directory.'
    }

    $gitDescriptor = Resolve-LockedApplication -Name 'git.exe' `
        -Label 'Production Git executable'
    $snapshotA = Get-CleanSourceSnapshot -GitDescriptor $gitDescriptor `
        -SourceRoot $sourceAPath -Label 'Personal Source A checkout'
    $snapshotB = Get-CleanSourceSnapshot -GitDescriptor $gitDescriptor `
        -SourceRoot $sourceBPath -Label 'Personal Source B checkout'
    foreach ($name in @(
        'Commit', 'Tree', 'InventorySha256', 'SourceDateEpoch')) {
        if ([string]$snapshotA.$name -cne [string]$snapshotB.$name) {
            throw "Source A and Source B disagree on immutable '$name'."
        }
    }

    $intentInput = Read-AndLockBuildIntent -Path $intentPath
    $intent = $intentInput.Value
    if ([string]$intent.sourceCommit -cne [string]$snapshotA.Commit -or
        [string]$intent.sourceTree -cne [string]$snapshotA.Tree) {
        throw 'Build intent sourceCommit/sourceTree differs from both clean checkouts.'
    }

    $dependencyA = Get-DependencyClosure -SourceRoot $sourceAPath `
        -HeldInputs $sourceAInputs
    $dependencyB = Get-DependencyClosure -SourceRoot $sourceBPath `
        -HeldInputs $sourceBInputs
    if ($dependencyA -cne $dependencyB) {
        throw 'Source A and Source B dependency closures differ.'
    }

    $producerContractPaths = @(
        $script:ProducerRelativePath,
        $script:StateModuleRelativePath,
        $script:IntentSchemaRelativePath,
        $script:EvidenceSchemaRelativePath,
        $script:AccountModuleRelativePath,
        $script:ProcessModuleRelativePath
    )
    $producerScriptSha256 = $null
    foreach ($relativePath in $producerContractPaths) {
        $a = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path (Join-Path $sourceAPath `
                $relativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)) `
            -Label "Source A producer contract '$relativePath'" `
            -MaximumBytes 16MB
        $sourceAInputs.Add($a)
        $b = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path (Join-Path $sourceBPath `
                $relativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)) `
            -Label "Source B producer contract '$relativePath'" `
            -MaximumBytes 16MB
        $sourceBInputs.Add($b)
        if ([int64]$a.SizeBytes -ne [int64]$b.SizeBytes -or
            [string]$a.Sha256 -cne [string]$b.Sha256) {
            throw "Source checkouts disagree on producer contract '$relativePath'."
        }
        $runningContract = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path (Join-Path $scriptCheckoutRoot $relativePath) `
            -Label "Running Personal producer contract '$relativePath'" -MaximumBytes 16MB
        $sourceAInputs.Add($runningContract)
        if ($runningContract.Sha256 -cne $a.Sha256 -or $runningContract.SizeBytes -ne $a.SizeBytes) {
            throw "Running Personal producer contract '$relativePath' differs from both clean source checkouts."
        }
        if ($relativePath -ceq $script:ProducerRelativePath) {
            $producerScriptSha256 = [string]$runningContract.Sha256
        }
    }

    $globalJson = ProductionReleaseState\Read-StrictProductionJsonFile `
        -Path (Join-Path $sourceAPath 'global.json') `
        -Label 'Personal build global.json'
    ProductionReleaseState\Assert-ExactProductionJsonMembers `
        -Value $globalJson.Value -Expected @('sdk') `
        -Label 'Personal build global.json'
    ProductionReleaseState\Assert-ExactProductionJsonMembers `
        -Value $globalJson.Value.sdk `
        -Expected @('version', 'rollForward', 'allowPrerelease') `
        -Label 'Personal build global.json sdk'
    if ([string]$globalJson.Value.sdk.version -cne '10.0.302' -or
        [string]$globalJson.Value.sdk.rollForward -cne 'disable' -or
        [bool]$globalJson.Value.sdk.allowPrerelease) {
        throw 'Personal two-clean build requires exact global.json SDK 10.0.302 with roll-forward disabled.'
    }

    $dotnetDescriptor = Resolve-LockedApplication -Name 'dotnet.exe' `
        -Label 'Production dotnet executable'
    $versionEnvironment = Get-BaseEnvironment -ScratchRoot $sourceAPath
    $versionEnvironment['DOTNET_ROOT'] =
        [IO.Path]::GetDirectoryName($dotnetDescriptor.Path)
    $versionEnvironment['DOTNET_MULTILEVEL_LOOKUP'] = '0'
    $versionEnvironment['DOTNET_NOLOGO'] = '1'
    $versionEnvironment['DOTNET_CLI_TELEMETRY_OPTOUT'] = '1'
    $version = Invoke-LockedProcess -Executable $dotnetDescriptor.Path `
        -Arguments @('--version') -WorkingDirectory $sourceAPath `
        -Environment $versionEnvironment -TimeoutMilliseconds 120000
    if ($version.ExitCode -ne 0 -or
        $version.Stdout.Trim() -cne '10.0.302') {
        throw 'Personal two-clean build did not resolve exact dotnet SDK 10.0.302.'
    }

    Assert-SourceStillClean -GitDescriptor $gitDescriptor `
        -SourceRoot $sourceAPath -Before $snapshotA `
        -Label 'Personal Source A checkout'
    Assert-SourceStillClean -GitDescriptor $gitDescriptor `
        -SourceRoot $sourceBPath -Before $snapshotB `
        -Label 'Personal Source B checkout'
    Assert-HeldInputsStillLocked -Inputs $sourceAInputs `
        -Label 'Personal Source A input'
    Assert-HeldInputsStillLocked -Inputs $sourceBInputs `
        -Label 'Personal Source B input'
    ProductionReleaseState\Assert-ProductionReleaseDirectoryStillLocked `
        -Descriptor $offlinePackageCacheLease `
        -Label 'Personal offline package cache root'
    [IO.Directory]::CreateDirectory($evidencePath) | Out-Null
    $evidenceLease = ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
        -Path $evidencePath -Label 'Personal two-clean evidence root'
    $buildsRoot = Join-Path $evidencePath 'builds'
    $buildsLease = New-OrdinaryDirectory -Path $buildsRoot `
        -Label 'Personal two-clean builds evidence directory'
    try {
        $intentCopyPath = Join-Path $buildsRoot 'build-intent.v1.json'
        $intentCopyStream = [IO.File]::Open(
            $intentCopyPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        try {
            $intentCopyStream.Write($intentInput.Bytes)
            $intentCopyStream.Flush($true)
        }
        finally {
            $intentCopyStream.Dispose()
        }
        $intentCopy = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $intentCopyPath -Label 'Copied two-clean build intent' `
            -MaximumBytes 1MB
        try {
            if ([int64]$intentCopy.SizeBytes -ne
                    [int64]$intentInput.Descriptor.SizeBytes -or
                [string]$intentCopy.Sha256 -cne
                    [string]$intentInput.Descriptor.Sha256) {
                throw 'Copied two-clean build intent differs from locked input bytes.'
            }
            $intentEvidenceDescriptor = [ordered]@{
                relativePath = 'builds/build-intent.v1.json'
                sizeBytes = [int64]$intentCopy.SizeBytes
                sha256 = [string]$intentCopy.Sha256
            }
        }
        finally {
            $intentCopy.Stream.Dispose()
        }

        $contractA = Get-NormalizedCommandContractSha256 `
            -SourceRoot $sourceAPath `
            -OutputRoot (Join-Path $evidencePath `
                'build-artifacts\isolated-a') -Intent $intent
        $contractB = Get-NormalizedCommandContractSha256 `
            -SourceRoot $sourceBPath `
            -OutputRoot (Join-Path $evidencePath `
                'build-artifacts\isolated-b') -Intent $intent
        if ($contractA -cne $contractB) {
            throw 'Source-independent Personal command contracts differ.'
        }

        $runA = Invoke-CleanBuildRun -RunLabel 'isolated-a' `
            -SourceRoot $sourceAPath -SourceLease $sourceALease `
            -SourceSnapshot $snapshotA -EvidenceRootPath $evidencePath `
            -Intent $intent -DotnetDescriptor $dotnetDescriptor `
            -GitDescriptor $gitDescriptor -SourceInputs $sourceAInputs `
            -OfflinePackageCacheLease $offlinePackageCacheLease `
            -ExpectedCommandContractSha256 $contractA
        $runB = Invoke-CleanBuildRun -RunLabel 'isolated-b' `
            -SourceRoot $sourceBPath -SourceLease $sourceBLease `
            -SourceSnapshot $snapshotB -EvidenceRootPath $evidencePath `
            -Intent $intent -DotnetDescriptor $dotnetDescriptor `
            -GitDescriptor $gitDescriptor -SourceInputs $sourceBInputs `
            -OfflinePackageCacheLease $offlinePackageCacheLease `
            -ExpectedCommandContractSha256 $contractB
        Assert-RunsByteIdentical -First $runA -Second $runB

        Assert-SourceStillClean -GitDescriptor $gitDescriptor `
            -SourceRoot $sourceAPath -Before $snapshotA `
            -Label 'Personal Source A checkout'
        Assert-SourceStillClean -GitDescriptor $gitDescriptor `
            -SourceRoot $sourceBPath -Before $snapshotB `
            -Label 'Personal Source B checkout'
        Assert-HeldInputsStillLocked -Inputs $sourceAInputs `
            -Label 'Personal Source A input'
        Assert-HeldInputsStillLocked -Inputs $sourceBInputs `
            -Label 'Personal Source B input'
        ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $intentInput.Descriptor `
            -Label 'Personal two-clean build intent'
        ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $dotnetDescriptor -Label 'Production dotnet executable'
        ProductionReleaseState\Assert-ProductionReleaseDirectoryStillLocked `
            -Descriptor $offlinePackageCacheLease `
            -Label 'Personal offline package cache root'

        $receipt = [ordered]@{
            schemaVersion = 1
            evidenceType =
                'ensou-dsh-personal-two-clean-production-build-evidence'
            unsignedProductionCandidate = $true
            productionAdmission = 'NO_GO'
            producerScriptSha256 = $producerScriptSha256
            buildIntent = $intentEvidenceDescriptor
            sourceCommit = [string]$snapshotA.Commit
            sourceTree = [string]$snapshotA.Tree
            sourceInventorySha256 = [string]$snapshotA.InventorySha256
            dependencyClosureSha256 = $dependencyA
            sdk = [ordered]@{
                path = [string]$dotnetDescriptor.Path
                version = '10.0.302'
                sizeBytes = [int64]$dotnetDescriptor.SizeBytes
                sha256 = [string]$dotnetDescriptor.Sha256
            }
            commandContractSha256 = $contractA
            runs = @($runA, $runB)
            restoreClosureSha256 = Get-RestoreClosureSha256 -Runs @($runA, $runB)
            outputsByteIdentical = $true
            combinedOutputClosureSha256 =
                [string]$runA.outputClosureSha256
            result = 'PASS'
        }
        [byte[]]$receiptBytes =
            ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $receipt
        try {
            $receiptText = $script:Utf8.GetString($receiptBytes)
            if (-not (Microsoft.PowerShell.Utility\Test-Json `
                    -Json $receiptText -SchemaFile $evidenceSchemaPath `
                    -ErrorAction Stop)) {
                throw 'Generated two-clean Personal evidence violates its strict schema.'
            }
            $receiptPath = Join-Path $buildsRoot `
                'two-clean-build-evidence.v1.json'
            $receiptStream = [IO.File]::Open(
                $receiptPath,
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write,
                [IO.FileShare]::None)
            try {
                $receiptStream.Write($receiptBytes)
                $receiptStream.Flush($true)
            }
            finally {
                $receiptStream.Dispose()
            }
        }
        finally {
            [Security.Cryptography.CryptographicOperations]::ZeroMemory(
                $receiptBytes)
        }
    }
    finally {
        $buildsLease.Handle.Dispose()
    }

    [pscustomobject]@{
        Result = 'PASS'
        ProductionAdmission = 'NO_GO'
        UnsignedProductionCandidate = $true
        SourceCommit = [string]$snapshotA.Commit
        SourceTree = [string]$snapshotA.Tree
        CombinedOutputClosureSha256 = [string]$runA.outputClosureSha256
        EvidenceRoot = $evidencePath
        ReceiptPath = Join-Path $evidencePath `
            'builds\two-clean-build-evidence.v1.json'
    }
}
finally {
    if ($null -ne $evidenceLease) { $evidenceLease.Handle.Dispose() }
    if ($null -ne $intentInput) {
        [Security.Cryptography.CryptographicOperations]::ZeroMemory(
            $intentInput.Bytes)
        $intentInput.Descriptor.Stream.Dispose()
    }
    foreach ($input in $sourceAInputs) { $input.Stream.Dispose() }
    foreach ($input in $sourceBInputs) { $input.Stream.Dispose() }
    if ($null -ne $dotnetDescriptor) { $dotnetDescriptor.Stream.Dispose() }
    if ($null -ne $gitDescriptor) { $gitDescriptor.Stream.Dispose() }
    if ($null -ne $offlinePackageCacheLease) {
        $offlinePackageCacheLease.Handle.Dispose()
    }
    if ($null -ne $sourceBLease) { $sourceBLease.Handle.Dispose() }
    if ($null -ne $sourceALease) { $sourceALease.Handle.Dispose() }
}
