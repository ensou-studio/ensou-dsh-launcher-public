[CmdletBinding(DefaultParameterSetName = 'RuntimeDirectory')]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$')]
    [string]$LauncherReleaseId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$')]
    [string]$RuntimeReleaseId,

    [Parameter(Mandatory = $true)]
    [string]$LauncherPublishDirectory,

    [Parameter(Mandatory = $true)]
    [string]$ClientBootstrapperPublishDirectory,

    [Parameter(Mandatory = $true)]
    [string]$MaintenancePublishDirectory,

    [Parameter(Mandatory = $true, ParameterSetName = 'RuntimeDirectory')]
    [string]$RuntimeDirectory,

    [Parameter(Mandatory = $true, ParameterSetName = 'RuntimeArchive')]
    [string]$RuntimeArchivePath,

    [Parameter(Mandatory = $true)]
    [string]$BootstrapperPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [switch]$DevelopmentE2E
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Resolve-ExistingLocalPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [bool]$Directory
    )

    if ($Path.StartsWith('\\', [StringComparison]::Ordinal) -or
        $Path.StartsWith('//', [StringComparison]::Ordinal)) {
        throw "Network and device paths are not accepted: $Path"
    }

    $resolved = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $resolved -Force
    if ($Directory -and -not $item.PSIsContainer) {
        throw "Expected a directory: $resolved"
    }

    if (-not $Directory -and $item.PSIsContainer) {
        throw "Expected a file: $resolved"
    }

    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Input paths may not be filesystem links: $resolved"
    }

    return $resolved
}

function Assert-SafeTree {
    param([Parameter(Mandatory = $true)][string]$Root)

    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($Root)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($entry in Get-ChildItem -LiteralPath $directory -Force) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Payload inputs may not contain filesystem links: $($entry.FullName)"
            }

            if ($entry.PSIsContainer) {
                $pending.Push($entry.FullName)
            }
        }
    }
}

function Get-Sha256Lower {
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-SafeRuntimeArchive {
    param([Parameter(Mandatory = $true)][string]$Path)

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        if ($archive.Entries.Count -gt 200000) {
            throw 'Runtime archive contains too many entries.'
        }

        $seen = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        $expandedBytes = 0L
        $hasNode = $false
        $hasDshEntry = $false
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName
            if ([string]::IsNullOrWhiteSpace($name) -or
                $name.Contains('\') -or
                $name.StartsWith('/', [StringComparison]::Ordinal) -or
                $name -cmatch '^[A-Za-z]:') {
                throw "Runtime archive contains an unsafe path: $name"
            }

            $segments = @($name.Split('/'))
            for ($index = 0; $index -lt $segments.Count; $index++) {
                $segment = $segments[$index]
                $isTrailingDirectoryMarker =
                    $index -eq $segments.Count - 1 -and $segment.Length -eq 0
                if (-not $isTrailingDirectoryMarker -and
                    ($segment.Length -eq 0 -or $segment -in @('.', '..'))) {
                    throw "Runtime archive contains traversal or ambiguous segments: $name"
                }
            }

            if (-not $seen.Add($name)) {
                throw "Runtime archive contains a duplicate path: $name"
            }

            $unixFileType = (([uint32]$entry.ExternalAttributes -shr 16) -band 0xF000)
            if ($unixFileType -eq 0xA000) {
                throw "Runtime archive contains a symbolic link: $name"
            }

            $expandedBytes += $entry.Length
            if ($expandedBytes -gt 8L * 1024 * 1024 * 1024) {
                throw 'Runtime archive expands beyond the supported size boundary.'
            }

            if ($name -ceq 'node.exe' -and $entry.Length -gt 0) {
                $hasNode = $true
            }

            if ($name -ceq 'node_modules/@deepseek-ai/dsh/lib/bin.js' -and
                $entry.Length -gt 0) {
                $hasDshEntry = $true
            }
        }

        if (-not $hasNode -or -not $hasDshEntry) {
            throw 'Runtime archive is missing bundled node.exe or the DSH entrypoint.'
        }
    } finally {
        $archive.Dispose()
    }
}

$launcherRoot = Resolve-ExistingLocalPath -Path $LauncherPublishDirectory -Directory $true
$clientBootstrapperRoot = Resolve-ExistingLocalPath `
    -Path $ClientBootstrapperPublishDirectory -Directory $true
$maintenanceRoot = Resolve-ExistingLocalPath -Path $MaintenancePublishDirectory -Directory $true
$runtimeRoot = $null
$runtimeSourceArchive = $null
if ($PSCmdlet.ParameterSetName -ceq 'RuntimeArchive') {
    $runtimeSourceArchive = Resolve-ExistingLocalPath `
        -Path $RuntimeArchivePath `
        -Directory $false
    if ([IO.Path]::GetExtension($runtimeSourceArchive) -cne '.zip') {
        throw "Runtime archive must have a lowercase .zip extension: $runtimeSourceArchive"
    }

    Assert-SafeRuntimeArchive -Path $runtimeSourceArchive
} else {
    $runtimeRoot = Resolve-ExistingLocalPath -Path $RuntimeDirectory -Directory $true
}
$bootstrapper = Resolve-ExistingLocalPath -Path $BootstrapperPath -Directory $false
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)

Assert-SafeTree -Root $launcherRoot
Assert-SafeTree -Root $clientBootstrapperRoot
Assert-SafeTree -Root $maintenanceRoot
if ($runtimeRoot) {
    Assert-SafeTree -Root $runtimeRoot
}

$launcherExecutable = Join-Path $launcherRoot 'Ensou.Dsh.Enterprise.Launcher.exe'
$clientBootstrapperExecutable = Join-Path `
    $clientBootstrapperRoot 'Ensou.Dsh.Enterprise.ClientBootstrapper.exe'
$maintenanceExecutable = Join-Path `
    $maintenanceRoot 'Ensou.Dsh.Enterprise.Maintenance.exe'
$launcherProfileMarker = Join-Path $launcherRoot 'enterprise-build-profile.json'
$clientBootstrapperProfileMarker = Join-Path `
    $clientBootstrapperRoot 'enterprise-build-profile.json'
$bootstrapperProfileMarker = Join-Path (Split-Path -Parent $bootstrapper) 'enterprise-build-profile.json'
$requiredFiles = @(
    $launcherExecutable,
    $clientBootstrapperExecutable,
    $maintenanceExecutable,
    $launcherProfileMarker,
    $clientBootstrapperProfileMarker,
    $bootstrapperProfileMarker)
if ($runtimeRoot) {
    $requiredFiles += @(
        (Join-Path $runtimeRoot 'node.exe'),
        (Join-Path $runtimeRoot 'node_modules\@deepseek-ai\dsh\lib\bin.js'))
}

foreach ($required in $requiredFiles) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required payload file is missing: $required"
    }
}

$layoutProfile = if ($DevelopmentE2E) { 'development-e2e' } else { 'enterprise' }
foreach ($markerPath in @(
    $launcherProfileMarker,
    $clientBootstrapperProfileMarker,
    $bootstrapperProfileMarker)) {
    $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
    $markerProperties = @($marker.PSObject.Properties.Name | Sort-Object)
    if (($markerProperties -join ',') -ne 'layoutProfile,schemaVersion' -or
        $marker.schemaVersion -ne 1 -or
        $marker.layoutProfile -cne $layoutProfile) {
        throw "Binary build profile does not match requested layout '$layoutProfile': $markerPath"
    }
}

if (Test-Path -LiteralPath $outputRoot) {
    if ((Get-ChildItem -LiteralPath $outputRoot -Force | Select-Object -First 1)) {
        throw "Output directory must be empty; refusing to overwrite: $outputRoot"
    }
} else {
    New-Item -ItemType Directory -Path $outputRoot | Out-Null
}

$outputItem = Get-Item -LiteralPath $outputRoot -Force
if (($outputItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Output directory may not be a filesystem link: $outputRoot"
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$launcherArchive = Join-Path $outputRoot 'launcher.zip'
$runtimeArchive = Join-Path $outputRoot 'runtime.zip'
$clientBundleStaging = Join-Path $outputRoot '.client-bundle-staging'
New-Item -ItemType Directory -Path $clientBundleStaging | Out-Null
try {
    Get-ChildItem -LiteralPath $launcherRoot -Force | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName `
            -Destination $clientBundleStaging -Recurse -Force
    }
    Copy-Item -LiteralPath $clientBootstrapperExecutable `
        -Destination (Join-Path $clientBundleStaging 'Ensou.Dsh.Enterprise.ClientBootstrapper.exe')
    Copy-Item -LiteralPath $maintenanceExecutable `
        -Destination (Join-Path $clientBundleStaging 'Ensou.Dsh.Enterprise.Maintenance.exe')
    Assert-SafeTree -Root $clientBundleStaging
    [IO.Compression.ZipFile]::CreateFromDirectory(
        $clientBundleStaging,
        $launcherArchive,
        [IO.Compression.CompressionLevel]::Optimal,
        $false)
} finally {
    if (Test-Path -LiteralPath $clientBundleStaging -PathType Container) {
        [IO.Directory]::Delete($clientBundleStaging, $true)
    }
}
if ($runtimeSourceArchive) {
    Copy-Item -LiteralPath $runtimeSourceArchive -Destination $runtimeArchive
} else {
    [IO.Compression.ZipFile]::CreateFromDirectory(
        $runtimeRoot,
        $runtimeArchive,
        [IO.Compression.CompressionLevel]::Optimal,
        $false)
}

$bootstrapperOutput = Join-Path $outputRoot 'Ensou.Dsh.Enterprise.Bootstrapper.exe'
Copy-Item -LiteralPath $bootstrapper -Destination $bootstrapperOutput

$manifest = [ordered]@{
    schemaVersion = 1
    layoutProfile = $layoutProfile
    launcherReleaseId = $LauncherReleaseId
    runtimeReleaseId = $RuntimeReleaseId
    launcherArchive = 'launcher.zip'
    launcherArchiveSizeBytes = (Get-Item -LiteralPath $launcherArchive).Length
    launcherArchiveSha256 = Get-Sha256Lower -Path $launcherArchive
    runtimeArchive = 'runtime.zip'
    runtimeArchiveSizeBytes = (Get-Item -LiteralPath $runtimeArchive).Length
    runtimeArchiveSha256 = Get-Sha256Lower -Path $runtimeArchive
    bootstrapperFile = 'Ensou.Dsh.Enterprise.Bootstrapper.exe'
    bootstrapperSizeBytes = (Get-Item -LiteralPath $bootstrapperOutput).Length
    bootstrapperSha256 = Get-Sha256Lower -Path $bootstrapperOutput
    publishedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
}
$manifestPath = Join-Path $outputRoot 'enterprise-install-manifest.json'
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM

$consentPath = Join-Path $outputRoot 'ALLOW-UNSIGNED-DEVELOPMENT-PAYLOAD.txt'
'UNSIGNED ENTERPRISE DEVELOPMENT PAYLOAD - NOT FOR EMPLOYEE DEPLOYMENT' |
    Set-Content -LiteralPath $consentPath -Encoding ascii -NoNewline

[pscustomobject]@{
    OutputDirectory = $outputRoot
    LauncherReleaseId = $LauncherReleaseId
    RuntimeReleaseId = $RuntimeReleaseId
    LauncherArchiveSha256 = $manifest.launcherArchiveSha256
    RuntimeArchiveSha256 = $manifest.runtimeArchiveSha256
    DevelopmentOnly = $true
    LayoutProfile = $layoutProfile
}
