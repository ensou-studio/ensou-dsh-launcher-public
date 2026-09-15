#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ArchivePath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ArchiveUrl,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedArchiveSha512,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [switch]$TestOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedSdkVersion = '10.0.302'
$expectedArchiveName = 'dotnet-sdk-10.0.302-win-x64.zip'
$maximumFileCount = 16384
$maximumArchiveEntryCount = 32768
[int64]$maximumFileBytes = 512MB
[int64]$maximumTotalBytes = 4GB
[int64]$maximumLockBytes = 4MB
$schemaPath = [IO.Path]::GetFullPath((Join-Path `
        $PSScriptRoot '..\schemas\portable-dotnet-sdk-byte-closure-v1.schema.json'))
$utf8 = [Text.UTF8Encoding]::new($false, $true)

function Resolve-OrdinaryDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not [IO.Path]::IsPathFullyQualified($Path) -or
        $Path.StartsWith('\\', [StringComparison]::Ordinal) -or
        $Path.StartsWith('//', [StringComparison]::Ordinal)) {
        throw "$Label must be one absolute local directory."
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

function Resolve-OrdinaryArchive {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not [IO.Path]::IsPathFullyQualified($Path) -or
        $Path.StartsWith('\\', [StringComparison]::Ordinal) -or
        $Path.StartsWith('//', [StringComparison]::Ordinal)) {
        throw 'ArchivePath must be one absolute local file.'
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    if ([IO.Path]::GetFileName($fullPath) -cne $expectedArchiveName) {
        throw "ArchivePath must use the exact file name '$expectedArchiveName'."
    }
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'ArchivePath must be one ordinary non-linked file.'
    }
    [void](Resolve-OrdinaryDirectory `
            -Path $item.Directory.FullName `
            -Label 'ArchivePath parent')
    return $fullPath
}

function Resolve-NewOutputPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not [IO.Path]::IsPathFullyQualified($Path) -or
        $Path.StartsWith('\\', [StringComparison]::Ordinal) -or
        $Path.StartsWith('//', [StringComparison]::Ordinal)) {
        throw 'OutputPath must be one absolute local file.'
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    if ([string]::IsNullOrWhiteSpace([IO.Path]::GetFileName($fullPath))) {
        throw 'OutputPath must name a file.'
    }
    $parent = Resolve-OrdinaryDirectory `
        -Path ([IO.Path]::GetDirectoryName($fullPath)) `
        -Label 'OutputPath parent'
    if ([IO.Path]::GetDirectoryName($fullPath) -cne $parent) {
        throw 'OutputPath parent is not canonical.'
    }
    if (Test-Path -LiteralPath $fullPath) {
        throw 'OutputPath must not already exist.'
    }
    return $fullPath
}

function Assert-OfficialArchiveUrl {
    param([Parameter(Mandatory = $true)][string]$Value)

    $escapedVersion = [Text.RegularExpressions.Regex]::Escape($expectedSdkVersion)
    $escapedName = [Text.RegularExpressions.Regex]::Escape($expectedArchiveName)
    $pattern =
        '^https://(?:builds[.]dotnet[.]microsoft[.]com|' +
        'download[.]visualstudio[.]microsoft[.]com)/' +
        '(?:[A-Za-z0-9_+-][A-Za-z0-9._+-]*/)*' +
        $escapedName + '$'
    if ($Value -cnotmatch $pattern) {
        throw 'ArchiveUrl must be one final official Microsoft HTTPS URL for the fixed win-x64 SDK ZIP.'
    }
    try {
        $uri = [Uri]::new($Value, [UriKind]::Absolute)
    }
    catch {
        throw 'ArchiveUrl is not an absolute URI.'
    }
    $allowedHost =
        $uri.IdnHost -ceq 'builds.dotnet.microsoft.com' -or
        $uri.IdnHost -ceq 'download.visualstudio.microsoft.com'
    if ($uri.Scheme -cne 'https' -or
        -not $allowedHost -or
        -not $uri.IsDefaultPort -or
        -not [string]::IsNullOrEmpty($uri.UserInfo) -or
        -not [string]::IsNullOrEmpty($uri.Query) -or
        -not [string]::IsNullOrEmpty($uri.Fragment) -or
        [IO.Path]::GetFileName($uri.AbsolutePath) -cne $expectedArchiveName -or
        $uri.AbsolutePath -cnotmatch ('/' + $escapedName + '$') -or
        $Value.IndexOf($expectedSdkVersion, [StringComparison]::Ordinal) -lt 0) {
        throw 'ArchiveUrl is not the canonical official Microsoft SDK 10.0.302 win-x64 ZIP URL.'
    }
}

function Assert-SafeWindowsSegment {
    param([Parameter(Mandatory = $true)][string]$Segment)

    if ($Segment.Length -gt 255) {
        throw "ZIP entry contains a Windows path segment longer than 255 characters: '$Segment'."
    }
    if ($Segment -in @('', '.', '..') -or
        $Segment.EndsWith('.', [StringComparison]::Ordinal)) {
        throw "ZIP entry contains a non-round-trippable Windows segment: '$Segment'."
    }
    $stem = $Segment.Split('.')[0]
    if ($stem -match '^(?:CON|PRN|AUX|NUL|CLOCK[$]|COM[1-9]|LPT[1-9])$') {
        throw "ZIP entry contains a reserved Windows device segment: '$Segment'."
    }
}

function Get-SafeEntryPath {
    param(
        [Parameter(Mandatory = $true)][string]$RawName,
        [Parameter(Mandatory = $true)][bool]$IsDirectory
    )

    if ([string]::IsNullOrEmpty($RawName) -or $RawName.Length -gt 1025 -or
        $RawName.Contains('\', [StringComparison]::Ordinal) -or
        $RawName.Contains([char]0) -or
        $RawName.StartsWith('/', [StringComparison]::Ordinal)) {
        throw "ZIP entry path is unsafe: '$RawName'."
    }
    if ($IsDirectory) {
        if (-not $RawName.EndsWith('/', [StringComparison]::Ordinal)) {
            throw "ZIP directory entry lacks its canonical '/' suffix: '$RawName'."
        }
        $relative = $RawName.Substring(0, $RawName.Length - 1)
        if ($relative.EndsWith('/', [StringComparison]::Ordinal)) {
            throw "ZIP directory entry has an empty segment: '$RawName'."
        }
    }
    else {
        if ($RawName.EndsWith('/', [StringComparison]::Ordinal)) {
            throw "ZIP file entry uses a directory suffix: '$RawName'."
        }
        $relative = $RawName
    }
    if ($relative.Length -le 0 -or $relative.Length -gt 1024 -or
        $relative -cnotmatch '^[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*$') {
        throw "ZIP entry path is not canonical: '$RawName'."
    }
    foreach ($segment in $relative.Split('/')) {
        Assert-SafeWindowsSegment -Segment $segment
    }
    return $relative
}

function Register-DirectorySpelling {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.Dictionary[string, string]]$Spellings,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $existing = $null
    if ($Spellings.TryGetValue($Path, [ref]$existing)) {
        if ($existing -cne $Path) {
            throw "ZIP paths collide under OrdinalIgnoreCase: '$existing' and '$Path'."
        }
        return
    }
    $Spellings.Add($Path, $Path)
}

function Register-SafeEntryPath {
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
        throw "ZIP contains a duplicate or OrdinalIgnoreCase-colliding entry: '$Path'."
    }
    $segments = $Path.Split('/')
    for ($index = 1; $index -lt $segments.Length; $index++) {
        $parent = $segments[0..($index - 1)] -join '/'
        if ($FilePaths.Contains($parent)) {
            throw "ZIP entry descends through a file path: '$parent'."
        }
        Register-DirectorySpelling -Spellings $DirectorySpellings -Path $parent
    }
    if ($IsDirectory) {
        if ($FilePaths.Contains($Path)) {
            throw "ZIP path is both a file and directory: '$Path'."
        }
        Register-DirectorySpelling -Spellings $DirectorySpellings -Path $Path
        return
    }
    if ($DirectorySpellings.ContainsKey($Path)) {
        throw "ZIP path is both a directory and file: '$Path'."
    }
    if (-not $FilePaths.Add($Path)) {
        throw "ZIP contains a duplicate file path: '$Path'."
    }
}

function Get-ZipEntryType {
    param([Parameter(Mandatory = $true)][IO.Compression.ZipArchiveEntry]$Entry)

    $attributes = [BitConverter]::ToUInt32(
        [BitConverter]::GetBytes([int32]$Entry.ExternalAttributes),
        0)
    $unixType = (($attributes -shr 16) -band [uint32]0xF000)
    $dosDirectory =
        ($attributes -band [uint32][IO.FileAttributes]::Directory) -ne 0
    $dosReparse =
        ($attributes -band [uint32][IO.FileAttributes]::ReparsePoint) -ne 0
    $nameDirectory = $Entry.FullName.EndsWith('/', [StringComparison]::Ordinal)

    if ($dosReparse -or $unixType -eq [uint32]0xA000) {
        throw "ZIP entry is a symbolic link or reparse point: '$($Entry.FullName)'."
    }
    if ($nameDirectory -or $dosDirectory -or $unixType -eq [uint32]0x4000) {
        if (-not $nameDirectory -or
            ($unixType -ne 0 -and $unixType -ne [uint32]0x4000) -or
            $Entry.Length -ne 0) {
            throw "ZIP directory entry has contradictory or non-directory attributes: '$($Entry.FullName)'."
        }
        return 'directory'
    }
    if ($unixType -ne 0 -and $unixType -ne [uint32]0x8000) {
        throw "ZIP entry is not a regular file: '$($Entry.FullName)'."
    }
    return 'file'
}

function Get-EntrySha256 {
    param(
        [Parameter(Mandatory = $true)][IO.Compression.ZipArchiveEntry]$Entry,
        [Parameter(Mandatory = $true)][int64]$MaximumBytes
    )

    if ($Entry.Length -lt 0 -or $Entry.Length -gt $MaximumBytes) {
        throw "ZIP file entry exceeds 512 MiB: '$($Entry.FullName)'."
    }
    $stream = $Entry.Open()
    $hash = [Security.Cryptography.IncrementalHash]::CreateHash(
        [Security.Cryptography.HashAlgorithmName]::SHA256)
    $bufferLength = [int][Math]::Min(
        1MB,
        [Math]::Max([int64]1, [int64]$Entry.Length))
    $buffer = [byte[]]::new($bufferLength)
    [int64]$count = 0
    try {
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $count += [int64]$read
            if ($count -gt $MaximumBytes) {
                throw "ZIP file entry expands beyond 512 MiB: '$($Entry.FullName)'."
            }
            $hash.AppendData($buffer, 0, $read)
        }
        if ($count -ne [int64]$Entry.Length) {
            throw "ZIP file entry length differs from its streamed bytes: '$($Entry.FullName)'."
        }
        return [pscustomobject]@{
            SizeBytes = $count
            Sha256 = [Convert]::ToHexString($hash.GetHashAndReset()).ToLowerInvariant()
        }
    }
    finally {
        [Array]::Clear($buffer, 0, $buffer.Length)
        $hash.Dispose()
        $stream.Dispose()
    }
}

Assert-OfficialArchiveUrl -Value $ArchiveUrl
if ($ExpectedArchiveSha512 -cnotmatch '^[0-9A-Fa-f]{128}$') {
    throw 'ExpectedArchiveSha512 must contain exactly 128 hexadecimal characters.'
}
$expectedSha512 = $ExpectedArchiveSha512.ToLowerInvariant()
$archiveFullPath = Resolve-OrdinaryArchive -Path $ArchivePath
$outputFullPath = Resolve-NewOutputPath -Path $OutputPath
if (-not [IO.File]::Exists($schemaPath)) {
    throw "Portable .NET SDK closure schema is missing: $schemaPath"
}
if ($TestOnly) {
    Write-Verbose 'TestOnly is active; all production archive, path, hash, size, schema, and CreateNew checks remain enforced.'
}

$archiveStream = [IO.File]::Open(
    $archiveFullPath,
    [IO.FileMode]::Open,
    [IO.FileAccess]::Read,
    [IO.FileShare]::Read)
try {
    if ($archiveStream.Length -le 0 -or $archiveStream.Length -gt $maximumTotalBytes) {
        throw 'SDK ZIP is empty or exceeds the 4 GiB archive bound.'
    }
    $archiveHasher = [Security.Cryptography.SHA512]::Create()
    try {
        $actualArchiveSha512 = [Convert]::ToHexString(
            $archiveHasher.ComputeHash($archiveStream)).ToLowerInvariant()
    }
    finally {
        $archiveHasher.Dispose()
    }
    if ($actualArchiveSha512 -cne $expectedSha512) {
        throw 'SDK ZIP SHA-512 differs from ExpectedArchiveSha512.'
    }
    $archiveStream.Position = 0

    $filesByPath = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $explicitEntries = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $filePaths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $directorySpellings = [Collections.Generic.Dictionary[string, string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    [int64]$totalSizeBytes = 0

    $zip = [IO.Compression.ZipArchive]::new(
        $archiveStream,
        [IO.Compression.ZipArchiveMode]::Read,
        $true)
    try {
        if ($zip.Entries.Count -le 0 -or
            $zip.Entries.Count -gt $maximumArchiveEntryCount) {
            throw 'SDK ZIP has an invalid or excessive entry count.'
        }
        foreach ($entry in $zip.Entries) {
            $entryType = Get-ZipEntryType -Entry $entry
            $isDirectory = $entryType -ceq 'directory'
            $relativePath = Get-SafeEntryPath `
                -RawName $entry.FullName `
                -IsDirectory $isDirectory
            Register-SafeEntryPath `
                -Path $relativePath `
                -IsDirectory $isDirectory `
                -ExplicitEntries $explicitEntries `
                -FilePaths $filePaths `
                -DirectorySpellings $directorySpellings
            if ($isDirectory) {
                continue
            }
            if ($filesByPath.Count -ge $maximumFileCount) {
                throw 'SDK ZIP contains more than 16,384 files.'
            }
            if ([int64]$entry.Length -gt ($maximumTotalBytes - $totalSizeBytes)) {
                throw 'SDK ZIP expands beyond the 4 GiB total bound.'
            }
            $digest = Get-EntrySha256 `
                -Entry $entry `
                -MaximumBytes $maximumFileBytes
            if ([int64]$digest.SizeBytes -gt ($maximumTotalBytes - $totalSizeBytes)) {
                throw 'SDK ZIP streamed bytes exceed the 4 GiB total bound.'
            }
            $totalSizeBytes += [int64]$digest.SizeBytes
            $filesByPath.Add(
                $relativePath,
                [ordered]@{
                    relativePath = $relativePath
                    sizeBytes = [int64]$digest.SizeBytes
                    sha256 = [string]$digest.Sha256
                })
        }
    }
    finally {
        $zip.Dispose()
    }

    if ($filesByPath.Count -le 0 -or $totalSizeBytes -le 0) {
        throw 'SDK ZIP must contain at least one non-empty byte across its regular files.'
    }
    $sortedPaths = [string[]]@($filesByPath.Keys)
    [Array]::Sort($sortedPaths, [StringComparer]::OrdinalIgnoreCase)
    $files = [Collections.Generic.List[object]]::new()
    $previous = $null
    foreach ($path in $sortedPaths) {
        if ($null -ne $previous -and
            [string]::Compare(
                $previous,
                $path,
                [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw 'SDK ZIP inventory is not strictly ordered by OrdinalIgnoreCase.'
        }
        $files.Add($filesByPath[$path])
        $previous = $path
    }
    $fileArray = [object[]]$files.ToArray()
    $filesJson = Microsoft.PowerShell.Utility\ConvertTo-Json `
        -InputObject $fileArray `
        -Depth 4 `
        -Compress
    $inventoryBytes = $utf8.GetBytes($filesJson)
    try {
        $inventorySha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData(
                $inventoryBytes)).ToLowerInvariant()
    }
    finally {
        [Array]::Clear($inventoryBytes, 0, $inventoryBytes.Length)
    }
    $lock = [ordered]@{
        contract = 'portable-dotnet-sdk-byte-closure-v1'
        sdkVersion = $expectedSdkVersion
        os = 'windows'
        architecture = 'x64'
        archiveSource = [ordered]@{
            url = $ArchiveUrl
            officialMicrosoft = $true
        }
        archiveSha512 = $actualArchiveSha512
        fileCount = [int]$fileArray.Count
        totalSizeBytes = $totalSizeBytes
        inventorySha256 = $inventorySha256
        files = $fileArray
    }
    $lockJson = Microsoft.PowerShell.Utility\ConvertTo-Json `
        -InputObject $lock `
        -Depth 8 `
        -Compress
    $lockBytes = $utf8.GetBytes($lockJson)
    if ($lockBytes.LongLength -le 0 -or
        $lockBytes.LongLength -gt $maximumLockBytes) {
        throw 'Generated portable .NET SDK lock exceeds the 4 MiB canonical JSON byte bound.'
    }
    if (-not (Microsoft.PowerShell.Utility\Test-Json `
            -Json $lockJson `
            -SchemaFile $schemaPath `
            -ErrorAction Stop)) {
        throw 'Generated portable .NET SDK lock failed schema validation.'
    }

    [void](Resolve-OrdinaryDirectory `
            -Path ([IO.Path]::GetDirectoryName($outputFullPath)) `
            -Label 'OutputPath parent before CreateNew')
    $output = [IO.FileStream]::new(
        $outputFullPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None,
        64KB,
        [IO.FileOptions]::WriteThrough)
    try {
        $output.Write($lockBytes, 0, $lockBytes.Length)
        $output.Flush($true)
        $output.Position = 0
        $readBack = [byte[]]::new($lockBytes.Length)
        $offset = 0
        while ($offset -lt $readBack.Length) {
            $read = $output.Read($readBack, $offset, $readBack.Length - $offset)
            if ($read -le 0) {
                throw 'CreateNew lock output ended before its expected length.'
            }
            $offset += $read
        }
        if ($output.ReadByte() -ne -1 -or
            -not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                [Security.Cryptography.SHA256]::HashData($lockBytes),
                [Security.Cryptography.SHA256]::HashData($readBack))) {
            throw 'CreateNew lock output differs from the canonical generated bytes.'
        }
        $readBackJson = $utf8.GetString($readBack)
        if (-not (Microsoft.PowerShell.Utility\Test-Json `
                -Json $readBackJson `
                -SchemaFile $schemaPath `
                -ErrorAction Stop)) {
            throw 'CreateNew portable .NET SDK lock failed its post-write schema validation.'
        }
    }
    finally {
        $output.Dispose()
    }

    [pscustomobject]@{
        Path = $outputFullPath
        FileCount = $fileArray.Count
        TotalSizeBytes = $totalSizeBytes
        ArchiveSha512 = $actualArchiveSha512
        InventorySha256 = $inventorySha256
        TestOnly = [bool]$TestOnly
    }
}
finally {
    $archiveStream.Dispose()
}
