#requires -Version 7.2

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force -ErrorAction Stop
$script:ClosureSchemaPath = [IO.Path]::GetFullPath((Join-Path `
        $PSScriptRoot '..\schemas\portable-dotnet-sdk-byte-closure-v1.schema.json'))

$script:ClosureContract = 'portable-dotnet-sdk-byte-closure-v1'
$script:ExpectedOperatingSystem = 'windows'
$script:ExpectedArchitecture = 'x64'
$script:ExpectedArchiveFileName = 'dotnet-sdk-10.0.302-win-x64.zip'
$script:DefaultMaximumFileCount = 16384
$script:DefaultMaximumArchiveEntryCount = 32768
$script:DefaultMaximumArchiveBytes = 4GB
$script:DefaultMaximumFileBytes = 512MB
$script:DefaultMaximumTotalBytes = 4GB
$script:MaximumLockBytes = 4MB
$script:ClosureRecords =
    [Runtime.CompilerServices.ConditionalWeakTable[object, object]]::new()
$script:DisposedClosures =
    [Runtime.CompilerServices.ConditionalWeakTable[object, object]]::new()
$script:OfficialArchiveHosts = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase)
[void]$script:OfficialArchiveHosts.Add('builds.dotnet.microsoft.com')
[void]$script:OfficialArchiveHosts.Add('download.visualstudio.microsoft.com')

if ($null -eq ('EnsouLauncherProduction.NativeDirectoryCreation' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace EnsouLauncherProduction
{
    public static class NativeDirectoryCreation
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateDirectoryW(
            string path,
            IntPtr securityAttributes);

        public static void CreateNew(string path)
        {
            if (String.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("Directory path is required.", nameof(path));
            }
            var nativePath = path.StartsWith(@"\\?\", StringComparison.Ordinal)
                ? path
                : @"\\?\" + path;
            if (!CreateDirectoryW(nativePath, IntPtr.Zero))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not atomically create the private SDK directory (create-only target).");
            }
        }
    }
}
'@ -ErrorAction Stop
}

function Assert-PortableDotNetSdkHost {
    if (-not $IsWindows -or
        $PSVersionTable.PSEdition -ne 'Core' -or
        $PSVersionTable.PSVersion -lt [version]'7.2' -or
        [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne
            [Runtime.InteropServices.Architecture]::X64) {
        throw 'Portable .NET SDK closure requires native Windows x64 and PowerShell 7.2 or newer.'
    }
}

function Resolve-PortableDotNetSdkDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not [IO.Path]::IsPathFullyQualified($Path) -or
        $Path.StartsWith('\\', [StringComparison]::Ordinal) -or
        $Path.StartsWith('//', [StringComparison]::Ordinal)) {
        throw "$Label must be an absolute local path."
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must be one ordinary non-linked directory: $fullPath"
    }
    for ($current = $item; $null -ne $current; $current = $current.Parent) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label crosses a filesystem link: $fullPath"
        }
    }
    return $fullPath
}

function Test-PortableDotNetSdkSameOrDescendant {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $candidate = [IO.Path]::TrimEndingDirectorySeparator(
        [IO.Path]::GetFullPath($Path))
    $boundary = [IO.Path]::TrimEndingDirectorySeparator(
        [IO.Path]::GetFullPath($Root))
    return $candidate.Equals($boundary, [StringComparison]::OrdinalIgnoreCase) -or
        $candidate.StartsWith(
            $boundary + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)
}

function Assert-PortableDotNetSdkRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($RelativePath.Length -gt 1024 -or
        $RelativePath -cnotmatch
            '^[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*$') {
        throw "$Label is not one canonical Windows relative path: $RelativePath"
    }
    foreach ($segment in $RelativePath.Split('/')) {
        if ($segment -in @('', '.', '..') -or
            $segment.Length -gt 255 -or
            $segment.EndsWith('.', [StringComparison]::Ordinal) -or
            $segment -imatch
                '^(?:CON|PRN|AUX|NUL|CLOCK[$]|COM[1-9]|LPT[1-9])(?:[.]|$)') {
            throw "$Label contains a reserved Windows path segment: $RelativePath"
        }
    }
    return $RelativePath
}

function ConvertTo-PortableDotNetSdkRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $relative = [IO.Path]::GetRelativePath($Root, $Path).Replace('\', '/')
    return Assert-PortableDotNetSdkRelativePath `
        -RelativePath $relative `
        -Label 'Portable .NET SDK path'
}

function Get-PortableDotNetSdkStreamSha256 {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)

    $Stream.Position = 0
    try {
        return [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($Stream)).ToLowerInvariant()
    }
    finally {
        $Stream.Position = 0
    }
}

function Get-PortableDotNetSdkStreamSha512 {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)

    $Stream.Position = 0
    try {
        return [Convert]::ToHexString(
            [Security.Cryptography.SHA512]::HashData($Stream)).ToLowerInvariant()
    }
    finally {
        $Stream.Position = 0
    }
}

function Resolve-PortableDotNetSdkFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw "$Label must be an absolute path."
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must be one ordinary non-linked file: $fullPath"
    }
    [void](Resolve-PortableDotNetSdkDirectory `
            -Path $item.Directory.FullName `
            -Label "$Label parent")
    return $fullPath
}

function Open-PortableDotNetSdkFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][int64]$MaximumBytes
    )

    $fullPath = Resolve-PortableDotNetSdkFile -Path $Path -Label $Label
    $stream = [IO.File]::Open(
        $fullPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $identity =
            [EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinarySingleLink(
                $stream.SafeFileHandle)
        if ($stream.Length -lt 0 -or $stream.Length -gt $MaximumBytes) {
            throw "$Label exceeds its byte bound."
        }
        $sha256 = Get-PortableDotNetSdkStreamSha256 -Stream $stream
        $pathStream = [IO.File]::Open(
            (Resolve-PortableDotNetSdkFile -Path $fullPath -Label $Label),
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read)
        try {
            $pathIdentity =
                [EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinarySingleLink(
                    $pathStream.SafeFileHandle)
            if ($pathIdentity.VolumeSerialNumber -ne $identity.VolumeSerialNumber -or
                $pathIdentity.FileIndex -ne $identity.FileIndex) {
                throw "$Label path no longer names the locked file."
            }
        }
        finally {
            $pathStream.Dispose()
        }
        return [pscustomobject]@{
            Path = $fullPath
            FileName = [IO.Path]::GetFileName($fullPath)
            SizeBytes = [int64]$stream.Length
            Sha256 = $sha256
            Stream = $stream
            VolumeSerialNumber = $identity.VolumeSerialNumber
            FileIndex = $identity.FileIndex
        }
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Assert-PortableDotNetSdkFileStillLocked {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $pathStream = [IO.File]::Open(
        (Resolve-PortableDotNetSdkFile -Path $Descriptor.Path -Label $Label),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $identity =
            [EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinarySingleLink(
                $pathStream.SafeFileHandle)
        if ($identity.VolumeSerialNumber -ne $Descriptor.VolumeSerialNumber -or
            $identity.FileIndex -ne $Descriptor.FileIndex -or
            [int64]$pathStream.Length -ne [int64]$Descriptor.SizeBytes -or
            (Get-PortableDotNetSdkStreamSha256 -Stream $pathStream) -cne
                [string]$Descriptor.Sha256) {
            throw "$Label changed after admission."
        }
    }
    finally {
        $pathStream.Dispose()
    }
}

function Get-PortableDotNetSdkFiles {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][int]$MaximumFileCount
    )

    $rootPath = Resolve-PortableDotNetSdkDirectory `
        -Path $Root `
        -Label 'Portable .NET SDK capsule'
    $queue = [Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($rootPath)
    $files = [Collections.Generic.List[object]]::new()
    $identities = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    while ($queue.Count -gt 0) {
        $directory = $queue.Dequeue()
        [void](Resolve-PortableDotNetSdkDirectory `
                -Path $directory `
                -Label 'Portable .NET SDK child directory')
        foreach ($entry in @(Get-ChildItem -LiteralPath $directory -Force)) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Portable .NET SDK contains a filesystem link: $($entry.FullName)"
            }
            if ($entry.PSIsContainer) {
                $queue.Enqueue($entry.FullName)
                continue
            }
            $relative = ConvertTo-PortableDotNetSdkRelativePath `
                -Root $rootPath `
                -Path $entry.FullName
            if (-not $identities.Add($relative)) {
                throw "Portable .NET SDK contains a case-insensitive path collision: $relative"
            }
            $files.Add([pscustomobject]@{
                RelativePath = $relative
                FullName = [IO.Path]::GetFullPath($entry.FullName)
            })
            if ($files.Count -gt $MaximumFileCount) {
                throw 'Portable .NET SDK exceeds its file-count bound.'
            }
        }
    }
    $array = $files.ToArray()
    [Array]::Sort(
        $array,
        [Collections.Generic.Comparer[object]]::Create({
                param($left, $right)
                return [string]::Compare(
                    [string]$left.RelativePath,
                    [string]$right.RelativePath,
                    [StringComparison]::OrdinalIgnoreCase)
            }))
    return $array
}

function Get-PortableDotNetSdkInventorySha256 {
    param([Parameter(Mandatory = $true)][object[]]$Files)

    $bytes = ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $Files
    try {
        return ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $bytes
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Test-PortableDotNetSdkJsonInteger {
    param([Parameter(Mandatory = $true)]$Value)

    return $Value -is [byte] -or $Value -is [sbyte] -or
        $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64]
}

function Assert-PortableDotNetSdkArchiveSource {
    param(
        [Parameter(Mandatory = $true)]$ArchiveSource,
        [Parameter(Mandatory = $true)][string]$ExpectedSdkVersion
    )

    ProductionReleaseState\Assert-ExactProductionJsonMembers `
        -Value $ArchiveSource `
        -Expected @('url', 'officialMicrosoft') `
        -Label 'Portable .NET SDK archive source'
    if ($ArchiveSource.url -isnot [string] -or
        $ArchiveSource.officialMicrosoft -isnot [bool] -or
        $ArchiveSource.officialMicrosoft -ne $true) {
        throw 'Portable .NET SDK archive source is not marked as official Microsoft.'
    }
    $urlText = [string]$ArchiveSource.url
    try {
        $uri = [Uri]::new($urlText, [UriKind]::Absolute)
    }
    catch {
        throw 'Portable .NET SDK archive source URL is invalid.'
    }
    $sdkVersionPattern = [Text.RegularExpressions.Regex]::Escape($ExpectedSdkVersion)
    $canonicalUrlPattern =
        '^https://(?:builds[.]dotnet[.]microsoft[.]com|' +
        'download[.]visualstudio[.]microsoft[.]com)/' +
        '(?:[A-Za-z0-9_+-][A-Za-z0-9._+-]*/)*' +
        'dotnet-sdk-' + $sdkVersionPattern + '-win-x64[.]zip$'
    if ($urlText -cnotmatch $canonicalUrlPattern -or
        $uri.Scheme -cne 'https' -or
        -not $script:OfficialArchiveHosts.Contains($uri.IdnHost) -or
        -not [string]::IsNullOrEmpty($uri.UserInfo) -or
        -not [string]::IsNullOrEmpty($uri.Query) -or
        -not [string]::IsNullOrEmpty($uri.Fragment) -or
        $uri.AbsolutePath -cnotmatch
            ('/dotnet-sdk-' + $sdkVersionPattern + '-win-x64[.]zip$')) {
        throw 'Portable .NET SDK archive source must be one final official Microsoft HTTPS win-x64 SDK ZIP URL.'
    }
}

function Get-PortableDotNetSdkZipEntryType {
    param(
        [Parameter(Mandatory = $true)]
        [IO.Compression.ZipArchiveEntry]$Entry
    )

    $attributes = [BitConverter]::ToUInt32(
        [BitConverter]::GetBytes([int32]$Entry.ExternalAttributes),
        0)
    $unixType = (($attributes -shr 16) -band [uint32]0xF000)
    $dosDirectory =
        ($attributes -band [uint32][IO.FileAttributes]::Directory) -ne 0
    $dosReparse =
        ($attributes -band [uint32][IO.FileAttributes]::ReparsePoint) -ne 0
    $nameDirectory = $Entry.FullName.EndsWith(
        '/',
        [StringComparison]::Ordinal)

    if ($dosReparse -or $unixType -eq [uint32]0xA000) {
        throw "Portable .NET SDK ZIP contains a symbolic link or reparse point: '$($Entry.FullName)'."
    }
    if ($nameDirectory -or $dosDirectory -or $unixType -eq [uint32]0x4000) {
        if (-not $nameDirectory -or
            ($unixType -ne 0 -and $unixType -ne [uint32]0x4000) -or
            $Entry.Length -ne 0) {
            throw "Portable .NET SDK ZIP directory entry is contradictory: '$($Entry.FullName)'."
        }
        return 'directory'
    }
    if ($unixType -ne 0 -and $unixType -ne [uint32]0x8000) {
        throw "Portable .NET SDK ZIP entry is not a regular file: '$($Entry.FullName)'."
    }
    return 'file'
}

function ConvertTo-PortableDotNetSdkZipEntryPath {
    param(
        [Parameter(Mandatory = $true)][string]$RawName,
        [Parameter(Mandatory = $true)][bool]$IsDirectory
    )

    if ([string]::IsNullOrEmpty($RawName) -or
        $RawName.Length -gt 1025 -or
        $RawName.Contains('\', [StringComparison]::Ordinal) -or
        $RawName.Contains([char]0) -or
        $RawName.StartsWith('/', [StringComparison]::Ordinal)) {
        throw "Portable .NET SDK ZIP entry path is unsafe: '$RawName'."
    }
    if ($IsDirectory) {
        if (-not $RawName.EndsWith('/', [StringComparison]::Ordinal)) {
            throw "Portable .NET SDK ZIP directory lacks its canonical '/' suffix: '$RawName'."
        }
        $relative = $RawName.Substring(0, $RawName.Length - 1)
        if ($relative.EndsWith('/', [StringComparison]::Ordinal)) {
            throw "Portable .NET SDK ZIP directory contains an empty segment: '$RawName'."
        }
    }
    else {
        if ($RawName.EndsWith('/', [StringComparison]::Ordinal)) {
            throw "Portable .NET SDK ZIP file uses a directory suffix: '$RawName'."
        }
        $relative = $RawName
    }
    return Assert-PortableDotNetSdkRelativePath `
        -RelativePath $relative `
        -Label 'Portable .NET SDK ZIP entry path'
}

function Register-PortableDotNetSdkZipDirectorySpelling {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.Dictionary[string, string]]$Spellings,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $existing = $null
    if ($Spellings.TryGetValue($Path, [ref]$existing)) {
        if ($existing -cne $Path) {
            throw "Portable .NET SDK ZIP paths collide under OrdinalIgnoreCase: '$existing' and '$Path'."
        }
        return
    }
    $Spellings.Add($Path, $Path)
}

function Register-PortableDotNetSdkZipEntryPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$IsDirectory,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.HashSet[string]]$ExplicitEntries,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.HashSet[string]]$FilePaths,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.Dictionary[string, string]]$DirectorySpellings
    )

    if (-not $ExplicitEntries.Add($Path)) {
        throw "Portable .NET SDK ZIP contains a duplicate or case-colliding entry: '$Path'."
    }
    $segments = $Path.Split('/')
    for ($index = 1; $index -lt $segments.Length; $index++) {
        $parent = $segments[0..($index - 1)] -join '/'
        if ($FilePaths.Contains($parent)) {
            throw "Portable .NET SDK ZIP entry descends through a file path: '$parent'."
        }
        Register-PortableDotNetSdkZipDirectorySpelling `
            -Spellings $DirectorySpellings `
            -Path $parent
    }
    if ($IsDirectory) {
        if ($FilePaths.Contains($Path)) {
            throw "Portable .NET SDK ZIP path is both a file and directory: '$Path'."
        }
        Register-PortableDotNetSdkZipDirectorySpelling `
            -Spellings $DirectorySpellings `
            -Path $Path
        return
    }
    if ($DirectorySpellings.ContainsKey($Path)) {
        throw "Portable .NET SDK ZIP path is both a directory and file: '$Path'."
    }
    if (-not $FilePaths.Add($Path)) {
        throw "Portable .NET SDK ZIP contains a duplicate file path: '$Path'."
    }
}

function Get-PortableDotNetSdkZipEntryDigest {
    param(
        [Parameter(Mandatory = $true)]
        [IO.Compression.ZipArchiveEntry]$Entry,
        [Parameter(Mandatory = $true)][int64]$MaximumBytes
    )

    if ($Entry.Length -lt 0 -or $Entry.Length -gt $MaximumBytes) {
        throw "Portable .NET SDK ZIP file exceeds its byte bound: '$($Entry.FullName)'."
    }
    $stream = $null
    $hash = $null
    $buffer = $null
    [int64]$count = 0
    try {
        $stream = $Entry.Open()
        $hash = [Security.Cryptography.IncrementalHash]::CreateHash(
            [Security.Cryptography.HashAlgorithmName]::SHA256)
        $bufferLength = [int][Math]::Min(
            1MB,
            [Math]::Max([int64]1, [int64]$Entry.Length))
        $buffer = [byte[]]::new($bufferLength)
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $count += [int64]$read
            if ($count -gt $MaximumBytes) {
                throw "Portable .NET SDK ZIP file expands beyond its byte bound: '$($Entry.FullName)'."
            }
            $hash.AppendData($buffer, 0, $read)
        }
        if ($count -ne [int64]$Entry.Length) {
            throw "Portable .NET SDK ZIP file length differs from its streamed bytes: '$($Entry.FullName)'."
        }
        return [pscustomobject]@{
            SizeBytes = $count
            Sha256 = [Convert]::ToHexString(
                $hash.GetHashAndReset()).ToLowerInvariant()
        }
    }
    finally {
        if ($null -ne $buffer) {
            [Array]::Clear($buffer, 0, $buffer.Length)
        }
        if ($null -ne $hash) {
            $hash.Dispose()
        }
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Expand-PortableDotNetSdkVerifiedArchive {
    param(
        [Parameter(Mandatory = $true)]$ArchiveDescriptor,
        [Parameter(Mandatory = $true)]$Lock,
        [Parameter(Mandatory = $true)][string]$DestinationDirectory,
        [Parameter(Mandatory = $true)][int]$MaximumArchiveEntryCount,
        [Parameter(Mandatory = $true)][int]$MaximumFileCount,
        [Parameter(Mandatory = $true)][int64]$MaximumFileBytes,
        [Parameter(Mandatory = $true)][int64]$MaximumTotalBytes
    )

    $archiveSha512 = Get-PortableDotNetSdkStreamSha512 `
        -Stream $ArchiveDescriptor.Stream
    if ($archiveSha512 -cne [string]$Lock.Value.archiveSha512) {
        throw 'Portable .NET SDK ZIP SHA-512 differs from its reviewed lock.'
    }

    $zip = [IO.Compression.ZipArchive]::new(
        $ArchiveDescriptor.Stream,
        [IO.Compression.ZipArchiveMode]::Read,
        $true)
    try {
        if ($zip.Entries.Count -le 0 -or
            $zip.Entries.Count -gt $MaximumArchiveEntryCount) {
            throw 'Portable .NET SDK ZIP has an invalid or excessive entry count.'
        }
        $explicitEntries = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        $filePaths = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        $directorySpellings =
            [Collections.Generic.Dictionary[string, string]]::new(
                [StringComparer]::OrdinalIgnoreCase)
        $records = [Collections.Generic.List[object]]::new()
        [int64]$total = 0

        foreach ($entry in $zip.Entries) {
            $entryType = Get-PortableDotNetSdkZipEntryType -Entry $entry
            $isDirectory = $entryType -ceq 'directory'
            $relative = ConvertTo-PortableDotNetSdkZipEntryPath `
                -RawName $entry.FullName `
                -IsDirectory $isDirectory
            Register-PortableDotNetSdkZipEntryPath `
                -Path $relative `
                -IsDirectory $isDirectory `
                -ExplicitEntries $explicitEntries `
                -FilePaths $filePaths `
                -DirectorySpellings $directorySpellings
            if ($isDirectory) {
                continue
            }
            if ($records.Count -ge $MaximumFileCount) {
                throw 'Portable .NET SDK ZIP exceeds its file-count bound.'
            }
            if ([int64]$entry.Length -gt ($MaximumTotalBytes - $total)) {
                throw 'Portable .NET SDK ZIP expands beyond its total byte bound.'
            }
            $digest = Get-PortableDotNetSdkZipEntryDigest `
                -Entry $entry `
                -MaximumBytes $MaximumFileBytes
            if ([int64]$digest.SizeBytes -gt ($MaximumTotalBytes - $total)) {
                throw 'Portable .NET SDK ZIP streamed bytes exceed its total byte bound.'
            }
            $total += [int64]$digest.SizeBytes
            $records.Add([pscustomobject]@{
                    RelativePath = $relative
                    SizeBytes = [int64]$digest.SizeBytes
                    Sha256 = [string]$digest.Sha256
                    Entry = $entry
                })
        }

        $recordArray = $records.ToArray()
        [Array]::Sort(
            $recordArray,
            [Collections.Generic.Comparer[object]]::Create({
                    param($left, $right)
                    return [string]::Compare(
                        [string]$left.RelativePath,
                        [string]$right.RelativePath,
                        [StringComparison]::OrdinalIgnoreCase)
                }))
        if ($recordArray.Count -ne $Lock.Files.Count -or
            $total -ne [int64]$Lock.Value.totalSizeBytes) {
            throw 'Portable .NET SDK ZIP inventory differs from its reviewed lock.'
        }
        $actualInventory = [Collections.Generic.List[object]]::new()
        for ($index = 0; $index -lt $recordArray.Count; $index++) {
            $actual = $recordArray[$index]
            $expected = $Lock.Files[$index]
            if ([string]$actual.RelativePath -cne
                    [string]$expected.relativePath -or
                [int64]$actual.SizeBytes -ne [int64]$expected.sizeBytes -or
                [string]$actual.Sha256 -cne [string]$expected.sha256) {
                throw 'Portable .NET SDK ZIP file inventory differs from its reviewed lock.'
            }
            $actualInventory.Add([pscustomobject][ordered]@{
                    relativePath = [string]$actual.RelativePath
                    sizeBytes = [int64]$actual.SizeBytes
                    sha256 = [string]$actual.Sha256
                })
        }
        if ((Get-PortableDotNetSdkInventorySha256 `
                -Files @($actualInventory)) -cne
            [string]$Lock.Value.inventorySha256) {
            throw 'Portable .NET SDK ZIP inventory digest differs from its reviewed lock.'
        }

        [EnsouLauncherProduction.NativeDirectoryCreation]::CreateNew(
            $DestinationDirectory)
        [void](Resolve-PortableDotNetSdkDirectory `
                -Path $DestinationDirectory `
                -Label 'Portable .NET SDK extracted capsule root')

        $directoryPaths = [string[]]@($directorySpellings.Values)
        [Array]::Sort(
            $directoryPaths,
            [Collections.Generic.Comparer[string]]::Create({
                    param([string]$left, [string]$right)
                    $depth = $left.Split('/').Count.CompareTo(
                        $right.Split('/').Count)
                    if ($depth -ne 0) {
                        return $depth
                    }
                    return [string]::Compare(
                        $left,
                        $right,
                        [StringComparison]::OrdinalIgnoreCase)
                }))
        foreach ($relativeDirectory in $directoryPaths) {
            $directoryPath = Join-Path `
                $DestinationDirectory `
                $relativeDirectory.Replace('/', '\')
            [EnsouLauncherProduction.NativeDirectoryCreation]::CreateNew(
                $directoryPath)
            [void](Resolve-PortableDotNetSdkDirectory `
                    -Path $directoryPath `
                    -Label 'Portable .NET SDK extracted capsule directory')
        }

        foreach ($record in $recordArray) {
            $path = Join-Path `
                $DestinationDirectory `
                ([string]$record.RelativePath).Replace('/', '\')
            $input = $null
            $output = $null
            $hash = $null
            $buffer = $null
            [int64]$count = 0
            try {
                $input = $record.Entry.Open()
                $output = [IO.FileStream]::new(
                    $path,
                    [IO.FileMode]::CreateNew,
                    [IO.FileAccess]::Write,
                    [IO.FileShare]::None,
                    1MB,
                    [IO.FileOptions]::WriteThrough)
                $hash = [Security.Cryptography.IncrementalHash]::CreateHash(
                    [Security.Cryptography.HashAlgorithmName]::SHA256)
                $buffer = [byte[]]::new(1MB)
                while (($read = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $count += [int64]$read
                    if ($count -gt $MaximumFileBytes -or
                        $count -gt [int64]$record.SizeBytes) {
                        throw "Portable .NET SDK extraction exceeded its byte bound: '$($record.RelativePath)'."
                    }
                    $hash.AppendData($buffer, 0, $read)
                    $output.Write($buffer, 0, $read)
                }
                $output.Flush($true)
                $sha256 = [Convert]::ToHexString(
                    $hash.GetHashAndReset()).ToLowerInvariant()
                if ($count -ne [int64]$record.SizeBytes -or
                    $sha256 -cne [string]$record.Sha256) {
                    throw "Portable .NET SDK extracted bytes differ from the reviewed lock: '$($record.RelativePath)'."
                }
            }
            finally {
                if ($null -ne $buffer) {
                    [Array]::Clear($buffer, 0, $buffer.Length)
                }
                if ($null -ne $hash) {
                    $hash.Dispose()
                }
                if ($null -ne $output) {
                    $output.Dispose()
                }
                if ($null -ne $input) {
                    $input.Dispose()
                }
            }
        }
        return [pscustomobject]@{
            ArchiveSha512 = $archiveSha512
            InventorySha256 = [string]$Lock.Value.inventorySha256
            FileCount = [int]$recordArray.Count
            TotalSizeBytes = $total
        }
    }
    finally {
        $zip.Dispose()
        $ArchiveDescriptor.Stream.Position = 0
    }
}

function Read-PortableDotNetSdkLock {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSdkVersion,
        [Parameter(Mandatory = $true)][int]$MaximumFileCount,
        [Parameter(Mandatory = $true)][int64]$MaximumFileBytes,
        [Parameter(Mandatory = $true)][int64]$MaximumTotalBytes
    )

    $descriptor = Open-PortableDotNetSdkFile `
        -Path $Path `
        -Label 'Portable .NET SDK closure lock' `
        -MaximumBytes $script:MaximumLockBytes
    try {
        if ($descriptor.SizeBytes -le 0 -or $descriptor.SizeBytes -gt [int]::MaxValue) {
            throw 'Portable .NET SDK closure lock is empty or too large.'
        }
        $bytes = [byte[]]::new([int]$descriptor.SizeBytes)
        $descriptor.Stream.Position = 0
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $descriptor.Stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                throw 'Portable .NET SDK closure lock ended before its admitted length.'
            }
            $offset += $read
        }
        $descriptor.Stream.Position = 0
        $value = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
            -Bytes $bytes `
            -Label 'Portable .NET SDK closure lock' `
            -SchemaPath $script:ClosureSchemaPath
        $jsonInput = [pscustomobject]@{
            Path = $descriptor.Path
            Bytes = $bytes
            Sha256 = $descriptor.Sha256
            Value = $value
        }
        [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
                -JsonInput $jsonInput `
                -Label 'Portable .NET SDK closure lock')
        ProductionReleaseState\Assert-ExactProductionJsonMembers `
            -Value $value `
            -Expected @(
                'contract', 'sdkVersion', 'os', 'architecture',
                'archiveSource', 'archiveSha512', 'fileCount',
                'totalSizeBytes', 'inventorySha256', 'files') `
            -Label 'Portable .NET SDK closure lock'
        if ([string]$value.contract -cne $script:ClosureContract -or
            [string]$value.sdkVersion -cne $ExpectedSdkVersion -or
            [string]$value.os -cne $script:ExpectedOperatingSystem -or
            [string]$value.architecture -cne $script:ExpectedArchitecture -or
            [string]$value.archiveSha512 -cnotmatch '^[0-9a-f]{128}$') {
            throw 'Portable .NET SDK closure lock has the wrong contract, SDK, platform, or archive digest.'
        }
        Assert-PortableDotNetSdkArchiveSource `
            -ArchiveSource $value.archiveSource `
            -ExpectedSdkVersion $ExpectedSdkVersion
        if (-not (Test-PortableDotNetSdkJsonInteger -Value $value.fileCount) -or
            -not (Test-PortableDotNetSdkJsonInteger -Value $value.totalSizeBytes) -or
            $value.files -isnot [Array]) {
            throw 'Portable .NET SDK closure counts and files must use their exact JSON types.'
        }
        $files = @($value.files)
        if ($files.Count -le 0 -or
            $files.Count -gt $MaximumFileCount -or
            [int]$value.fileCount -ne $files.Count) {
            throw 'Portable .NET SDK closure lock has an invalid file count.'
        }
        $identities = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        $previous = ''
        [int64]$total = 0
        foreach ($file in $files) {
            ProductionReleaseState\Assert-ExactProductionJsonMembers `
                -Value $file `
                -Expected @('relativePath', 'sizeBytes', 'sha256') `
                -Label 'Portable .NET SDK closure file'
            if ($file.relativePath -isnot [string] -or
                -not (Test-PortableDotNetSdkJsonInteger -Value $file.sizeBytes) -or
                $file.sha256 -isnot [string]) {
                throw 'Portable .NET SDK closure file members have invalid JSON types.'
            }
            $relative = Assert-PortableDotNetSdkRelativePath `
                -RelativePath ([string]$file.relativePath) `
                -Label 'Portable .NET SDK closure file path'
            if (-not $identities.Add($relative) -or
                ($previous -and [string]::Compare(
                        $previous,
                        $relative,
                        [StringComparison]::OrdinalIgnoreCase) -ge 0) -or
                [int64]$file.sizeBytes -lt 0 -or
                [int64]$file.sizeBytes -gt $MaximumFileBytes -or
                [string]$file.sha256 -cnotmatch '^[0-9a-f]{64}$') {
                throw 'Portable .NET SDK closure files are unsafe, duplicated, unsorted, or out of bounds.'
            }
            $total += [int64]$file.sizeBytes
            if ($total -gt $MaximumTotalBytes) {
                throw 'Portable .NET SDK closure exceeds its total byte bound.'
            }
            $previous = $relative
        }
        if ($total -le 0 -or
            [int64]$value.totalSizeBytes -ne $total -or
            [string]$value.inventorySha256 -cne
                (Get-PortableDotNetSdkInventorySha256 -Files $files)) {
            throw 'Portable .NET SDK closure totals or inventory SHA-256 are not exact.'
        }
        return [pscustomobject]@{
            Descriptor = $descriptor
            JsonInput = $jsonInput
            Value = $value
            Files = $files
        }
    }
    catch {
        $descriptor.Stream.Dispose()
        throw
    }
}

function New-PortableDotNetSdkClosureObject {
    param(
        [Parameter(Mandatory = $true)][string]$RootPath,
        [Parameter(Mandatory = $true)]$Lock,
        [Parameter(Mandatory = $true)][object[]]$Descriptors,
        [Parameter(Mandatory = $true)][bool]$OwnsLockDescriptor,
        [Parameter(Mandatory = $true)][bool]$IsPrivateCopy,
        [Parameter(Mandatory = $true)][int]$MaximumFileCount,
        [Parameter(Mandatory = $true)][int64]$MaximumFileBytes,
        [Parameter(Mandatory = $true)][int64]$MaximumTotalBytes
    )

    $files = @(
        foreach ($file in $Lock.Files) {
            [pscustomobject]@{
                relativePath = [string]$file.relativePath
                sizeBytes = [int64]$file.sizeBytes
                sha256 = [string]$file.sha256
            }
        })
    $record = [pscustomobject]@{
        RootPath = [string]$RootPath
        LockDescriptor = $Lock.Descriptor
        LockSha256 = [string]$Lock.Descriptor.Sha256
        SdkVersion = [string]$Lock.Value.sdkVersion
        ArchiveSourceUrl = [string]$Lock.Value.archiveSource.url
        ArchiveSha512 = [string]$Lock.Value.archiveSha512
        ArchiveBindingStatus = 'LOCK_ONLY'
        ArchiveDescriptor = $null
        OwnsArchiveDescriptor = $false
        Files = $files
        InventorySha256 = [string]$Lock.Value.inventorySha256
        FileCount = [int]$Lock.Value.fileCount
        TotalSizeBytes = [int64]$Lock.Value.totalSizeBytes
        Descriptors = @($Descriptors)
        OwnsLockDescriptor = [bool]$OwnsLockDescriptor
        IsPrivateCopy = [bool]$IsPrivateCopy
        MaximumFileCount = [int]$MaximumFileCount
        MaximumFileBytes = [int64]$MaximumFileBytes
        MaximumTotalBytes = [int64]$MaximumTotalBytes
    }
    $closure = [pscustomobject]@{
        ClosureType = 'PortableDotNetSdkByteClosure'
        RootPath = $RootPath
        InventorySha256 = [string]$Lock.Value.inventorySha256
        FileCount = [int]$Lock.Value.fileCount
        TotalSizeBytes = [int64]$Lock.Value.totalSizeBytes
        IsPrivateCopy = $IsPrivateCopy
        Disposed = $false
    }
    $script:ClosureRecords.Add($closure, $record)
    return $closure
}

function Get-PortableDotNetSdkClosureRecord {
    param(
        [Parameter(Mandatory = $true)]$Closure,
        [switch]$AllowDisposed
    )

    $record = $null
    if ($null -eq $Closure -or
        -not $script:ClosureRecords.TryGetValue(
            [object]$Closure,
            [ref]$record)) {
        throw 'Portable .NET SDK closure handle is not authentic.'
    }
    $disposedMarker = $null
    if (-not $AllowDisposed -and
        $script:DisposedClosures.TryGetValue(
            [object]$Closure,
            [ref]$disposedMarker)) {
        throw 'Portable .NET SDK closure is already disposed.'
    }
    return $record
}

function Open-PortableDotNetSdkClosure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$CapsuleDirectory,
        [Parameter(Mandatory = $true)][string]$LockPath,
        [ValidateSet('10.0.302')]
        [string]$ExpectedSdkVersion = '10.0.302',
        [ValidateRange(1, 16384)][int]$MaximumFileCount =
            $script:DefaultMaximumFileCount,
        [ValidateRange(1, 536870912)][int64]$MaximumFileBytes =
            $script:DefaultMaximumFileBytes,
        [ValidateRange(1, 4294967296)][int64]$MaximumTotalBytes =
            $script:DefaultMaximumTotalBytes
    )

    Assert-PortableDotNetSdkHost
    $root = Resolve-PortableDotNetSdkDirectory `
        -Path $CapsuleDirectory `
        -Label 'Portable .NET SDK capsule'
    $lock = Read-PortableDotNetSdkLock `
        -Path $LockPath `
        -ExpectedSdkVersion $ExpectedSdkVersion `
        -MaximumFileCount $MaximumFileCount `
        -MaximumFileBytes $MaximumFileBytes `
        -MaximumTotalBytes $MaximumTotalBytes
    $descriptors = [Collections.Generic.List[object]]::new()
    $closure = $null
    try {
        $actualFiles = @(Get-PortableDotNetSdkFiles `
                -Root $root `
                -MaximumFileCount $MaximumFileCount)
        if ($actualFiles.Count -ne $lock.Files.Count) {
            throw 'Portable .NET SDK capsule inventory differs from its lock.'
        }
        [int64]$total = 0
        for ($index = 0; $index -lt $lock.Files.Count; $index++) {
            $expected = $lock.Files[$index]
            $actual = $actualFiles[$index]
            if ([string]$actual.RelativePath -cne [string]$expected.relativePath) {
                throw 'Portable .NET SDK capsule path inventory differs from its lock.'
            }
            $descriptor = Open-PortableDotNetSdkFile `
                -Path $actual.FullName `
                -Label "Portable .NET SDK file '$($actual.RelativePath)'" `
                -MaximumBytes $MaximumFileBytes
            $descriptors.Add($descriptor)
            if ([int64]$descriptor.SizeBytes -ne [int64]$expected.sizeBytes -or
                [string]$descriptor.Sha256 -cne [string]$expected.sha256) {
                throw "Portable .NET SDK file differs from its lock: $($actual.RelativePath)"
            }
            $total += [int64]$descriptor.SizeBytes
            if ($total -gt $MaximumTotalBytes) {
                throw 'Portable .NET SDK capsule exceeds its total byte bound.'
            }
        }
        if ($total -ne [int64]$lock.Value.totalSizeBytes) {
            throw 'Portable .NET SDK capsule total bytes differ from its lock.'
        }
        $closure = New-PortableDotNetSdkClosureObject `
            -RootPath $root `
            -Lock $lock `
            -Descriptors @($descriptors) `
            -OwnsLockDescriptor $true `
            -IsPrivateCopy $false `
            -MaximumFileCount $MaximumFileCount `
            -MaximumFileBytes $MaximumFileBytes `
            -MaximumTotalBytes $MaximumTotalBytes
        [void](Assert-PortableDotNetSdkClosureUnchanged -Closure $closure)
        return $closure
    }
    catch {
        if ($null -ne $closure) {
            Close-PortableDotNetSdkClosure -Closure $closure
        }
        else {
            for ($index = $descriptors.Count - 1; $index -ge 0; $index--) {
                $descriptors[$index].Stream.Dispose()
            }
            $lock.Descriptor.Stream.Dispose()
        }
        throw
    }
}

function Open-PortableDotNetSdkArchiveClosure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ArchivePath,
        [Parameter(Mandatory = $true)][string]$LockPath,
        [Parameter(Mandatory = $true)][string]$ExtractionDirectory,
        [ValidateSet('10.0.302')]
        [string]$ExpectedSdkVersion = '10.0.302',
        [ValidateRange(1, 32768)][int]$MaximumArchiveEntryCount =
            $script:DefaultMaximumArchiveEntryCount,
        [ValidateRange(1, 4294967296)][int64]$MaximumArchiveBytes =
            $script:DefaultMaximumArchiveBytes,
        [ValidateRange(1, 16384)][int]$MaximumFileCount =
            $script:DefaultMaximumFileCount,
        [ValidateRange(1, 536870912)][int64]$MaximumFileBytes =
            $script:DefaultMaximumFileBytes,
        [ValidateRange(1, 4294967296)][int64]$MaximumTotalBytes =
            $script:DefaultMaximumTotalBytes
    )

    Assert-PortableDotNetSdkHost
    if (-not [IO.Path]::IsPathFullyQualified($ExtractionDirectory) -or
        $ExtractionDirectory.StartsWith('\', [StringComparison]::Ordinal) -or
        $ExtractionDirectory.StartsWith('//', [StringComparison]::Ordinal)) {
        throw 'Portable .NET SDK extraction must use an absolute local path.'
    }
    $destination = [IO.Path]::GetFullPath($ExtractionDirectory)
    [void](Resolve-PortableDotNetSdkDirectory `
            -Path ([IO.Path]::GetDirectoryName($destination)) `
            -Label 'Portable .NET SDK extraction parent')

    $lock = Read-PortableDotNetSdkLock `
        -Path $LockPath `
        -ExpectedSdkVersion $ExpectedSdkVersion `
        -MaximumFileCount $MaximumFileCount `
        -MaximumFileBytes $MaximumFileBytes `
        -MaximumTotalBytes $MaximumTotalBytes
    $archiveDescriptor = $null
    $closure = $null
    try {
        $archiveFullPath = Resolve-PortableDotNetSdkFile `
            -Path $ArchivePath `
            -Label 'Portable .NET SDK source ZIP'
        if ([IO.Path]::GetFileName($archiveFullPath) -cne
            $script:ExpectedArchiveFileName) {
            throw "Portable .NET SDK source ZIP must use the exact file name '$($script:ExpectedArchiveFileName)'."
        }
        $archiveDescriptor = Open-PortableDotNetSdkFile `
            -Path $archiveFullPath `
            -Label 'Portable .NET SDK source ZIP' `
            -MaximumBytes $MaximumArchiveBytes
        $archiveEvidence = Expand-PortableDotNetSdkVerifiedArchive `
            -ArchiveDescriptor $archiveDescriptor `
            -Lock $lock `
            -DestinationDirectory $destination `
            -MaximumArchiveEntryCount $MaximumArchiveEntryCount `
            -MaximumFileCount $MaximumFileCount `
            -MaximumFileBytes $MaximumFileBytes `
            -MaximumTotalBytes $MaximumTotalBytes

        $closure = Open-PortableDotNetSdkClosure `
            -CapsuleDirectory $destination `
            -LockPath $LockPath `
            -ExpectedSdkVersion $ExpectedSdkVersion `
            -MaximumFileCount $MaximumFileCount `
            -MaximumFileBytes $MaximumFileBytes `
            -MaximumTotalBytes $MaximumTotalBytes
        $record = Get-PortableDotNetSdkClosureRecord -Closure $closure
        if ([string]$record.LockSha256 -cne
                [string]$lock.Descriptor.Sha256 -or
            [string]$archiveEvidence.ArchiveSha512 -cne
                [string]$record.ArchiveSha512 -or
            [string]$archiveEvidence.InventorySha256 -cne
                [string]$record.InventorySha256 -or
            [int]$archiveEvidence.FileCount -ne [int]$record.FileCount -or
            [int64]$archiveEvidence.TotalSizeBytes -ne
                [int64]$record.TotalSizeBytes) {
            throw 'Portable .NET SDK extracted closure differs from its locked ZIP admission.'
        }
        $record.ArchiveBindingStatus =
            'ZIP_SHA512_AND_FILE_INVENTORY_VERIFIED'
        $record.ArchiveDescriptor = $archiveDescriptor
        $record.OwnsArchiveDescriptor = $true
        $archiveDescriptor = $null
        $lock.Descriptor.Stream.Dispose()
        $lock = $null
        [void](Assert-PortableDotNetSdkClosureUnchanged -Closure $closure)
        return $closure
    }
    catch {
        if ($null -ne $closure) {
            Close-PortableDotNetSdkClosure -Closure $closure
        }
        if ($null -ne $archiveDescriptor -and
            $null -ne $archiveDescriptor.Stream) {
            $archiveDescriptor.Stream.Dispose()
        }
        if ($null -ne $lock -and
            $null -ne $lock.Descriptor.Stream) {
            $lock.Descriptor.Stream.Dispose()
        }
        throw
    }
}

function Assert-PortableDotNetSdkClosureUnchanged {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Closure)

    $record = Get-PortableDotNetSdkClosureRecord -Closure $Closure
    $root = Resolve-PortableDotNetSdkDirectory `
        -Path ([string]$record.RootPath) `
        -Label 'Portable .NET SDK closure root'
    $actualFiles = @(Get-PortableDotNetSdkFiles `
            -Root $root `
            -MaximumFileCount ([int]$record.MaximumFileCount))
    if ($actualFiles.Count -ne [int]$record.FileCount -or
        @($record.Descriptors).Count -ne [int]$record.FileCount) {
        throw 'Portable .NET SDK closure file count changed after admission.'
    }
    [int64]$total = 0
    for ($index = 0; $index -lt $actualFiles.Count; $index++) {
        $actual = $actualFiles[$index]
        $expected = $record.Files[$index]
        $descriptor = $record.Descriptors[$index]
        if ([string]$actual.RelativePath -cne [string]$expected.relativePath -or
            [IO.Path]::GetFullPath([string]$actual.FullName) -cne
                [IO.Path]::GetFullPath([string]$descriptor.Path)) {
            throw 'Portable .NET SDK closure namespace changed after admission.'
        }
        Assert-PortableDotNetSdkFileStillLocked `
            -Descriptor $descriptor `
            -Label "Portable .NET SDK file '$($actual.RelativePath)'"
        if ([int64]$descriptor.SizeBytes -ne [int64]$expected.sizeBytes -or
            [string]$descriptor.Sha256 -cne [string]$expected.sha256) {
            throw 'Portable .NET SDK closure descriptor differs from its lock.'
        }
        $total += [int64]$descriptor.SizeBytes
        if ($total -gt [int64]$record.MaximumTotalBytes) {
            throw 'Portable .NET SDK closure exceeds its total byte bound.'
        }
    }
    if ($total -ne [int64]$record.TotalSizeBytes -or
        (Get-PortableDotNetSdkInventorySha256 -Files @($record.Files)) -cne
            [string]$record.InventorySha256) {
        throw 'Portable .NET SDK closure inventory changed after admission.'
    }
    if ([bool]$record.OwnsLockDescriptor) {
        Assert-PortableDotNetSdkFileStillLocked `
            -Descriptor $record.LockDescriptor `
            -Label 'Portable .NET SDK closure lock'
    }
    if ([bool]$record.OwnsArchiveDescriptor) {
        Assert-PortableDotNetSdkFileStillLocked `
            -Descriptor $record.ArchiveDescriptor `
            -Label 'Portable .NET SDK source ZIP'
    }
    return $true
}

function New-PortableDotNetSdkPrivateCopy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$SourceClosure,
        [Parameter(Mandatory = $true)][string]$DestinationDirectory
    )

    [void](Assert-PortableDotNetSdkClosureUnchanged -Closure $SourceClosure)
    $sourceRecord = Get-PortableDotNetSdkClosureRecord -Closure $SourceClosure
    if (-not [IO.Path]::IsPathFullyQualified($DestinationDirectory) -or
        $DestinationDirectory.StartsWith('\\', [StringComparison]::Ordinal) -or
        $DestinationDirectory.StartsWith('//', [StringComparison]::Ordinal)) {
        throw 'Portable .NET SDK private copy must use an absolute local path.'
    }
    $destination = [IO.Path]::GetFullPath($DestinationDirectory)
    $destinationParent = Resolve-PortableDotNetSdkDirectory `
        -Path ([IO.Path]::GetDirectoryName($destination)) `
        -Label 'Portable .NET SDK private-copy parent'
    if ((Test-PortableDotNetSdkSameOrDescendant `
            -Path $destination `
            -Root ([string]$sourceRecord.RootPath)) -or
        (Test-PortableDotNetSdkSameOrDescendant `
            -Path ([string]$sourceRecord.RootPath) `
            -Root $destination)) {
        throw 'Portable .NET SDK private copy may not overlap the source capsule.'
    }

    $copyDescriptors = [Collections.Generic.List[object]]::new()
    $createdDirectories = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $closure = $null
    $privateLockDescriptor = $null
    try {
        [EnsouLauncherProduction.NativeDirectoryCreation]::CreateNew($destination)
        [void](Resolve-PortableDotNetSdkDirectory `
                -Path $destination `
                -Label 'Portable .NET SDK private-copy root')
        for ($index = 0; $index -lt $sourceRecord.Files.Count; $index++) {
            $file = $sourceRecord.Files[$index]
            $source = $sourceRecord.Descriptors[$index]
            Assert-PortableDotNetSdkFileStillLocked `
                -Descriptor $source `
                -Label "Portable .NET SDK source '$($file.relativePath)'"
            $path = Join-Path $destination (
                ([string]$file.relativePath).Replace('/', '\'))
            $segments = ([string]$file.relativePath).Split('/')
            $parent = $destination
            $relativeParent = ''
            for ($segmentIndex = 0;
                $segmentIndex -lt $segments.Count - 1;
                $segmentIndex++) {
                $relativeParent = if ($relativeParent) {
                    $relativeParent + '/' + $segments[$segmentIndex]
                }
                else {
                    $segments[$segmentIndex]
                }
                $parent = Join-Path $parent $segments[$segmentIndex]
                if ($createdDirectories.Add($relativeParent)) {
                    [EnsouLauncherProduction.NativeDirectoryCreation]::CreateNew($parent)
                }
                [void](Resolve-PortableDotNetSdkDirectory `
                        -Path $parent `
                        -Label 'Portable .NET SDK private-copy child directory')
            }
            $output = [IO.FileStream]::new(
                $path,
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write,
                [IO.FileShare]::None,
                1MB,
                [IO.FileOptions]::WriteThrough)
            try {
                $source.Stream.Position = 0
                $source.Stream.CopyTo($output)
                $output.Flush($true)
                $source.Stream.Position = 0
            }
            finally {
                $output.Dispose()
            }
            $copy = Open-PortableDotNetSdkFile `
                -Path $path `
                -Label "Portable .NET SDK private copy '$($file.relativePath)'" `
                -MaximumBytes ([int64]$sourceRecord.MaximumFileBytes)
            $copyDescriptors.Add($copy)
            if ([int64]$copy.SizeBytes -ne [int64]$file.sizeBytes -or
                [string]$copy.Sha256 -cne [string]$file.sha256) {
                throw "Portable .NET SDK private copy differs from its locked source: $($file.relativePath)"
            }
        }
        $privateLockDescriptor = Open-PortableDotNetSdkFile `
            -Path ([string]$sourceRecord.LockDescriptor.Path) `
            -Label 'Portable .NET SDK private-copy lock' `
            -MaximumBytes $script:MaximumLockBytes
        if ([string]$privateLockDescriptor.Sha256 -cne
            [string]$sourceRecord.LockSha256) {
            throw 'Portable .NET SDK lock changed while creating the private copy.'
        }
        $lockReference = [pscustomobject]@{
            Value = [pscustomobject]@{
                sdkVersion = [string]$sourceRecord.SdkVersion
                archiveSource = [pscustomobject]@{
                    url = [string]$sourceRecord.ArchiveSourceUrl
                    officialMicrosoft = $true
                }
                archiveSha512 = [string]$sourceRecord.ArchiveSha512
                inventorySha256 = [string]$sourceRecord.InventorySha256
                fileCount = [int]$sourceRecord.FileCount
                totalSizeBytes = [int64]$sourceRecord.TotalSizeBytes
            }
            Descriptor = $privateLockDescriptor
            Files = @($sourceRecord.Files)
        }
        $closure = New-PortableDotNetSdkClosureObject `
            -RootPath $destination `
            -Lock $lockReference `
            -Descriptors @($copyDescriptors) `
            -OwnsLockDescriptor $true `
            -IsPrivateCopy $true `
            -MaximumFileCount ([int]$sourceRecord.MaximumFileCount) `
            -MaximumFileBytes ([int64]$sourceRecord.MaximumFileBytes) `
            -MaximumTotalBytes ([int64]$sourceRecord.MaximumTotalBytes)
        $privateRecord = Get-PortableDotNetSdkClosureRecord -Closure $closure
        $privateRecord.ArchiveBindingStatus =
            [string]$sourceRecord.ArchiveBindingStatus
        $privateLockDescriptor = $null
        [void](Assert-PortableDotNetSdkClosureUnchanged -Closure $closure)
        return $closure
    }
    catch {
        if ($null -ne $closure) {
            Close-PortableDotNetSdkClosure -Closure $closure
        }
        else {
            for ($index = $copyDescriptors.Count - 1; $index -ge 0; $index--) {
                $copyDescriptors[$index].Stream.Dispose()
            }
            if ($null -ne $privateLockDescriptor -and
                $null -ne $privateLockDescriptor.Stream) {
                $privateLockDescriptor.Stream.Dispose()
            }
        }
        throw
    }
}

function Get-PortableDotNetSdkPrivateToolchain {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Closure)

    [void](Assert-PortableDotNetSdkClosureUnchanged -Closure $Closure)
    $record = Get-PortableDotNetSdkClosureRecord -Closure $Closure
    if (-not [bool]$record.IsPrivateCopy -or
        -not [bool]$record.OwnsLockDescriptor) {
        throw 'Portable .NET SDK toolchain access requires one authentic self-contained private-copy closure.'
    }
    if ([string]$record.ArchiveBindingStatus -cne
        'ZIP_SHA512_AND_FILE_INVENTORY_VERIFIED') {
        throw 'Portable .NET SDK toolchain access requires verified original-ZIP byte closure.'
    }
    $dotnetIndexes = @(
        for ($index = 0; $index -lt $record.Files.Count; $index++) {
            if ([string]$record.Files[$index].relativePath -ceq 'dotnet.exe') {
                $index
            }
        })
    if ($dotnetIndexes.Count -ne 1) {
        throw 'Portable .NET SDK private closure must contain exactly one root dotnet.exe.'
    }
    $descriptor = $record.Descriptors[[int]$dotnetIndexes[0]]
    $expectedDotnetPath = [IO.Path]::GetFullPath(
        (Join-Path ([string]$record.RootPath) 'dotnet.exe'))
    if (-not [IO.Path]::GetFullPath([string]$descriptor.Path).Equals(
            $expectedDotnetPath,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Portable .NET SDK private dotnet.exe path differs from the authenticated closure record.'
    }
    Assert-PortableDotNetSdkFileStillLocked `
        -Descriptor $descriptor `
        -Label 'Portable .NET SDK private dotnet.exe'

    return [pscustomobject][ordered]@{
        RootPath = [string]$record.RootPath
        DotnetPath = $expectedDotnetPath
        SdkVersion = [string]$record.SdkVersion
        LockSha256 = [string]$record.LockSha256
        ArchiveSourceUrl = [string]$record.ArchiveSourceUrl
        ArchiveSha512 = [string]$record.ArchiveSha512
        InventorySha256 = [string]$record.InventorySha256
        FileCount = [int]$record.FileCount
        TotalSizeBytes = [int64]$record.TotalSizeBytes
        ArchiveBindingStatus = [string]$record.ArchiveBindingStatus
    }
}

function Close-PortableDotNetSdkClosure {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Closure)

    $record = Get-PortableDotNetSdkClosureRecord `
        -Closure $Closure `
        -AllowDisposed
    $disposedMarker = $null
    if ($script:DisposedClosures.TryGetValue(
            [object]$Closure,
            [ref]$disposedMarker)) {
        return
    }
    for ($index = @($record.Descriptors).Count - 1; $index -ge 0; $index--) {
        if ($null -ne $record.Descriptors[$index].Stream) {
            $record.Descriptors[$index].Stream.Dispose()
        }
    }
    if ([bool]$record.OwnsLockDescriptor -and
        $null -ne $record.LockDescriptor.Stream) {
        $record.LockDescriptor.Stream.Dispose()
    }
    if ([bool]$record.OwnsArchiveDescriptor -and
        $null -ne $record.ArchiveDescriptor -and
        $null -ne $record.ArchiveDescriptor.Stream) {
        $record.ArchiveDescriptor.Stream.Dispose()
    }
    $script:DisposedClosures.Add($Closure, [object]$true)
    try {
        $Closure.Disposed = $true
    }
    catch {
        # Public metadata is advisory and is never trusted by this module.
    }
}

Export-ModuleMember -Function @(
    'Assert-PortableDotNetSdkClosureUnchanged',
    'Close-PortableDotNetSdkClosure',
    'Get-PortableDotNetSdkPrivateToolchain',
    'New-PortableDotNetSdkPrivateCopy',
    'Open-PortableDotNetSdkArchiveClosure',
    'Open-PortableDotNetSdkClosure'
)
