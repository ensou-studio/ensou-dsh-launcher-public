#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SourceRuntimeArchivePath,

    [Parameter(Mandatory = $true)]
    [string]$SourceRuntimeMetadataPath,

    [Parameter(Mandatory = $true)]
    [string]$SourceRuntimeHashEvidencePath,

    [Parameter(Mandatory = $true)]
    [string]$ReleaseId,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $true)]
    [string]$WorkDirectory,

    [switch]$AllowLocalLab,

    [Parameter(DontShow = $true)]
    [scriptblock]$SourceEvidenceLockedObserver
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$completeTreeName = '.ensou-complete-tree.v1.json'
$runtimeHashManifestName = 'runtime-files.sha256'
$sourceProvenanceName = 'source-build.json'
$maximumArchiveEntries = 250000
$maximumExpandedBytes = 16L * 1024 * 1024 * 1024
$maximumTreeBytes = 16 * 1024 * 1024
$maximumRuntimeArchiveBytes = 8L * 1024 * 1024 * 1024
$utf8Strict = [Text.UTF8Encoding]::new($false, $true)

if (-not ('EnsouPersonalSourceRuntime.NativeFileIdentity' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace EnsouPersonalSourceRuntime
{
    public readonly struct ExactFileIdentity
    {
        public ExactFileIdentity(uint volume, ulong index)
        {
            VolumeSerialNumber = volume;
            FileIndex = index;
        }

        public uint VolumeSerialNumber { get; }
        public ulong FileIndex { get; }
    }

    public static class NativeFileIdentity
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle handle,
            out ByHandleFileInformation information);

        public static ExactFileIdentity RequireOrdinarySingleLink(SafeFileHandle handle)
        {
            if (handle == null || handle.IsInvalid || handle.IsClosed)
            {
                throw new InvalidDataException("Source-runtime evidence handle is invalid.");
            }
            if (!GetFileInformationByHandle(handle, out var information))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not inspect source-runtime evidence identity.");
            }
            const uint directory = 0x10;
            const uint reparsePoint = 0x400;
            if (information.NumberOfLinks != 1
                || (information.FileAttributes & (directory | reparsePoint)) != 0)
            {
                throw new InvalidDataException(
                    "Source-runtime evidence must be one ordinary single-link file.");
            }
            var index = ((ulong)information.FileIndexHigh << 32)
                | information.FileIndexLow;
            return new ExactFileIdentity(information.VolumeSerialNumber, index);
        }
    }
}
'@
}

function Resolve-OrdinaryFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0) {
        throw "Personal source-runtime input must be one ordinary non-empty file: $resolved"
    }
    for ($current = $item.Directory; $null -ne $current; $current = $current.Parent) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Personal source-runtime input crosses a filesystem link: $resolved"
        }
    }
    return $resolved
}

function Assert-OrdinaryExistingParent {
    param([Parameter(Mandatory = $true)][string]$Path)

    $parentPath = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path))
    if ([string]::IsNullOrEmpty($parentPath)) {
        throw "Personal source-runtime path has no parent: $Path"
    }
    $parent = Get-Item -LiteralPath $parentPath -Force -ErrorAction Stop
    if (-not $parent.PSIsContainer -or
        ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Personal source-runtime parent must be one ordinary directory: $parentPath"
    }
    for ($current = $parent; $null -ne $current; $current = $current.Parent) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Personal source-runtime path crosses a filesystem link: $Path"
        }
    }
}

function Test-SameOrDescendant {
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

function Get-CanonicalRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$Directory
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path.Length -gt 1024 -or
        $Path.Contains('\') -or
        $Path.Contains(':') -or
        $Path.StartsWith('/', [StringComparison]::Ordinal) -or
        $Path.Contains('//') -or
        -not $Path.IsNormalized([Text.NormalizationForm]::FormC)) {
        throw "Source-runtime ZIP path is not canonical: $Path"
    }
    if ($Directory) {
        if (-not $Path.EndsWith('/', [StringComparison]::Ordinal) -or
            $Path.EndsWith('//', [StringComparison]::Ordinal)) {
            throw "Source-runtime ZIP directory path is not canonical: $Path"
        }
        $canonical = $Path.Substring(0, $Path.Length - 1)
    } else {
        if ($Path.EndsWith('/', [StringComparison]::Ordinal)) {
            throw "Source-runtime ZIP file path is not canonical: $Path"
        }
        $canonical = $Path
    }
    $invalid = [IO.Path]::GetInvalidFileNameChars()
    foreach ($segment in $canonical.Split('/')) {
        $baseName = $segment.Split('.', 2)[0]
        if ([string]::IsNullOrEmpty($segment) -or
            $segment -in @('.', '..') -or
            $segment.Length -gt 255 -or
            $segment.EndsWith(' ', [StringComparison]::Ordinal) -or
            $segment.EndsWith('.', [StringComparison]::Ordinal) -or
            $segment.IndexOfAny($invalid) -ge 0 -or
            @($segment.ToCharArray() | Where-Object { [int]$_ -lt 32 }).Count -ne 0 -or
            $baseName -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
            throw "Source-runtime ZIP path has an unsafe Windows segment: $Path"
        }
    }
    return $canonical
}

function Get-ContainedPath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )

    $rootFull = [IO.Path]::GetFullPath($Root)
    $candidate = [IO.Path]::GetFullPath((Join-Path $rootFull (
        $RelativePath.Replace('/', [IO.Path]::DirectorySeparatorChar))))
    if (-not (Test-SameOrDescendant -Path $candidate -Root $rootFull) -or
        $candidate.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Source-runtime ZIP path escaped its extraction root: $RelativePath"
    }
    return $candidate
}

function Get-StreamSha256 {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)

    if (-not $Stream.CanSeek) {
        throw 'SHA-256 input stream must be seekable.'
    }
    $Stream.Position = 0
    $digest = ([Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($Stream))).ToLowerInvariant()
    $Stream.Position = 0
    return $digest
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        return Get-StreamSha256 $stream
    } finally {
        $stream.Dispose()
    }
}

function Open-ExactLockedInput {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[IDisposable]]$Leases,
        [Parameter(Mandatory = $true)][int64]$MaximumBytes
    )

    $resolved = Resolve-OrdinaryFile $Path
    $stream = [IO.File]::Open(
        $resolved,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $identity = [EnsouPersonalSourceRuntime.NativeFileIdentity]::
            RequireOrdinarySingleLink($stream.SafeFileHandle)
        if ($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) {
            throw "Source-runtime evidence is empty or unbounded: $resolved"
        }
        $pathStream = [IO.File]::Open(
            (Resolve-OrdinaryFile $resolved),
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read)
        try {
            $pathIdentity = [EnsouPersonalSourceRuntime.NativeFileIdentity]::
                RequireOrdinarySingleLink($pathStream.SafeFileHandle)
            if ($pathIdentity.VolumeSerialNumber -ne $identity.VolumeSerialNumber -or
                $pathIdentity.FileIndex -ne $identity.FileIndex) {
                throw "Source-runtime path no longer names its locked evidence: $resolved"
            }
        } finally {
            $pathStream.Dispose()
        }
        $sha256 = Get-StreamSha256 $stream
        $Leases.Add($stream)
        return [pscustomobject]@{
            Path = $resolved
            SizeBytes = $stream.Length
            Sha256 = $sha256
            Stream = $stream
            VolumeSerialNumber = $identity.VolumeSerialNumber
            FileIndex = $identity.FileIndex
        }
    } catch {
        $stream.Dispose()
        throw
    }
}

function Read-LockedInputBytes {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][int]$MaximumBytes
    )

    if ($Descriptor.SizeBytes -le 0 -or $Descriptor.SizeBytes -gt $MaximumBytes) {
        throw "Locked source-runtime evidence is empty or unbounded: $($Descriptor.Path)"
    }
    $Descriptor.Stream.Position = 0
    $bytes = [byte[]]::new([int]$Descriptor.SizeBytes)
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $read = $Descriptor.Stream.Read($bytes, $offset, $bytes.Length - $offset)
        if ($read -eq 0) {
            throw "Locked source-runtime evidence ended early: $($Descriptor.Path)"
        }
        $offset += $read
    }
    if ($Descriptor.Stream.ReadByte() -ne -1) {
        throw "Locked source-runtime evidence grew while reading: $($Descriptor.Path)"
    }
    $Descriptor.Stream.Position = 0
    return $bytes
}

function New-LockedSnapshotFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[IDisposable]]$Leases
    )

    $resolved = [IO.Path]::GetFullPath($Path)
    Assert-OrdinaryExistingParent $resolved
    $stream = [IO.File]::Open(
        $resolved,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::Read)
    try {
        $identity = [EnsouPersonalSourceRuntime.NativeFileIdentity]::
            RequireOrdinarySingleLink($stream.SafeFileHandle)
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
        $stream.Position = 0
        if ($stream.Length -ne $Bytes.LongLength -or
            (Get-StreamSha256 $stream) -cne
                ([Convert]::ToHexString(
                    [Security.Cryptography.SHA256]::HashData($Bytes))).ToLowerInvariant()) {
            throw 'Source-runtime evidence snapshot changed while it was created.'
        }
        $Leases.Add($stream)
        return [pscustomobject]@{
            Path = $resolved
            SizeBytes = $stream.Length
            Stream = $stream
            VolumeSerialNumber = $identity.VolumeSerialNumber
            FileIndex = $identity.FileIndex
        }
    } catch {
        $stream.Dispose()
        throw
    }
}

function Assert-OrdinaryExtractedTree {
    param([Parameter(Mandatory = $true)][string]$Root)

    $rootItem = Get-Item -LiteralPath $Root -Force
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Personal source-runtime extraction root is linked or invalid.'
    }
    foreach ($entry in Get-ChildItem -LiteralPath $Root -Force -Recurse) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not ($entry.PSIsContainer -or $entry -is [IO.FileInfo])) {
            throw "Personal source-runtime extraction contains a linked or special entry: $($entry.FullName)"
        }
    }
}

function Read-ExactZipEntryBytes {
    param([Parameter(Mandatory = $true)][IO.Compression.ZipArchiveEntry]$Entry)

    if ($Entry.Length -gt $maximumTreeBytes) {
        throw "Bounded ZIP entry is too large: $($Entry.FullName)"
    }
    $input = $Entry.Open()
    try {
        $output = [IO.MemoryStream]::new([int]$Entry.Length)
        try {
            $input.CopyTo($output)
            if ($output.Length -ne $Entry.Length) {
                throw "ZIP entry changed length while reading: $($Entry.FullName)"
            }
            return $output.ToArray()
        } finally {
            $output.Dispose()
        }
    } finally {
        $input.Dispose()
    }
}

function Assert-PersonalRuntimeArchive {
    param(
        [Parameter(Mandatory = $true)][string]$ArchivePath,
        [Parameter(Mandatory = $true)][byte[]]$TreeBytes,
        [Parameter(Mandatory = $true)][Collections.Generic.Dictionary[string, object]]$Descriptors
    )

    $stream = [IO.File]::Open(
        $ArchivePath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $stream,
            [IO.Compression.ZipArchiveMode]::Read,
            $true)
        try {
            if ($archive.Entries.Count -ne $Descriptors.Count + 1) {
                throw 'Personal runtime archive has an unexpected entry count.'
            }
            $seen = [Collections.Generic.HashSet[string]]::new(
                [StringComparer]::Ordinal)
            foreach ($entry in $archive.Entries) {
                $relative = Get-CanonicalRelativePath `
                    -Path $entry.FullName `
                    -Directory $false
                $unixType = (($entry.ExternalAttributes -shr 16) -band 0xF000)
                if ($unixType -notin @(0, 0x8000) -or
                    ($entry.ExternalAttributes -band [int][IO.FileAttributes]::Directory) -ne 0 -or
                    ($entry.ExternalAttributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0 -or
                    -not $seen.Add($relative)) {
                    throw "Personal runtime archive contains a linked, special, or duplicate entry: $relative"
                }
                if ($relative -ceq $completeTreeName) {
                    $embedded = Read-ExactZipEntryBytes $entry
                    if ($embedded.Length -ne $TreeBytes.Length -or
                        [Convert]::ToHexString(
                            [Security.Cryptography.SHA256]::HashData($embedded)) -cne
                        [Convert]::ToHexString(
                            [Security.Cryptography.SHA256]::HashData($TreeBytes))) {
                        throw 'Personal runtime archive does not embed the exact external complete-tree manifest.'
                    }
                    continue
                }
                if (-not $Descriptors.ContainsKey($relative)) {
                    throw "Personal runtime archive contains an unexpected file: $relative"
                }
                $descriptor = $Descriptors[$relative]
                $entryStream = $entry.Open()
                try {
                    $entryHash = ([Convert]::ToHexString(
                        [Security.Cryptography.SHA256]::HashData(
                            $entryStream))).ToLowerInvariant()
                } finally {
                    $entryStream.Dispose()
                }
                if ($entry.Length -ne [int64]$descriptor.sizeBytes -or
                    $entryHash -cne [string]$descriptor.sha256) {
                    throw "Personal runtime archive differs from its complete-tree descriptor: $relative"
                }
            }
            if (-not $seen.Contains($completeTreeName) -or
                @($Descriptors.Keys | Where-Object {
                    -not $seen.Contains($_)
                }).Count -ne 0) {
                throw 'Personal runtime archive is missing complete-tree files.'
            }
        } finally {
            $archive.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Assert-PersonalSourceBuildNoDuplicateJsonMembers {
    param(
        [Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) {
                throw "$Label contains a duplicate JSON member: $($property.Name)"
            }
            Assert-PersonalSourceBuildNoDuplicateJsonMembers `
                -Element $property.Value `
                -Label $Label
        }
    }
    elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) {
            Assert-PersonalSourceBuildNoDuplicateJsonMembers `
                -Element $item `
                -Label $Label
        }
    }
}

function Get-PersonalSourceBuildRequiredJsonProperty {
    param(
        [Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Element.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
        throw "$Label is not a JSON object."
    }
    $property = [Text.Json.JsonElement]::new()
    if (-not $Element.TryGetProperty($Name, [ref]$property)) {
        throw "$Label is missing $Name."
    }
    return $property
}

function Read-PersonalSourceBuildEvidence {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $document = [Text.Json.JsonDocument]::Parse(
        [ReadOnlyMemory[byte]]::new($Bytes))
    try {
        $root = $document.RootElement
        Assert-PersonalSourceBuildNoDuplicateJsonMembers `
            -Element $root `
            -Label $Label

        $schemaVersionProperty = Get-PersonalSourceBuildRequiredJsonProperty `
            -Element $root `
            -Name 'schemaVersion' `
            -Label $Label
        $schemaVersion = 0
        if ($schemaVersionProperty.ValueKind -ne
                [Text.Json.JsonValueKind]::Number -or
            -not $schemaVersionProperty.TryGetInt32([ref]$schemaVersion) -or
            $schemaVersion -ne 3) {
            throw "$Label schemaVersion is not the exact integer 3."
        }

        $sourceBuiltProperty = Get-PersonalSourceBuildRequiredJsonProperty `
            -Element $root `
            -Name 'sourceBuilt' `
            -Label $Label
        if ($sourceBuiltProperty.ValueKind -ne [Text.Json.JsonValueKind]::True) {
            throw "$Label sourceBuilt is not the JSON literal true."
        }

        $values = [ordered]@{
            schemaVersion = $schemaVersion
            sourceBuilt = $true
        }
        $promotionEligibleProperty = Get-PersonalSourceBuildRequiredJsonProperty `
            -Element $root `
            -Name 'promotionEligible' `
            -Label $Label
        if ($promotionEligibleProperty.ValueKind -notin @(
                [Text.Json.JsonValueKind]::True,
                [Text.Json.JsonValueKind]::False)) {
            throw "$Label promotionEligible is not a JSON Boolean."
        }
        $values['promotionEligible'] = $promotionEligibleProperty.GetBoolean()
        foreach ($name in @(
            'releaseId',
            'artifactType',
            'sourceIdentity',
            'sourceRepository',
            'sourceTag',
            'sourceCommit',
            'sourceTree',
            'runtimeWebAuthProtocol',
            'platform',
            'nodeSha256',
            'buildPipeline',
            'builtAtUtc')) {
            $property = Get-PersonalSourceBuildRequiredJsonProperty `
                -Element $root `
                -Name $name `
                -Label $Label
            if ($property.ValueKind -ne [Text.Json.JsonValueKind]::String) {
                throw "$Label $name is not a JSON string."
            }
            if ($name -ceq 'builtAtUtc') {
                try {
                    $values[$name] = $property.GetDateTime()
                } catch {
                    throw "$Label builtAtUtc is not an ISO 8601 timestamp."
                }
            } else {
                $values[$name] = $property.GetString()
            }
        }
        foreach ($name in @(
            'runtimeClosureAgainstPinnedSourceAndLock',
            'managedFocusedTests',
            'managedWindowsExcludedFocusedTests',
            'managedRefusalSmoke',
            'officialCheckoutUnchanged')) {
            $property = Get-PersonalSourceBuildRequiredJsonProperty `
                -Element $root `
                -Name $name `
                -Label $Label
            if ($property.ValueKind -ne [Text.Json.JsonValueKind]::True) {
                throw "$Label $name is not the JSON literal true."
            }
            $values[$name] = $true
        }
        return [pscustomobject]$values
    } finally {
        $document.Dispose()
    }
}

if ($AllowLocalLab) {
    if ($ReleaseId -cnotmatch '^lab-[A-Za-z0-9][A-Za-z0-9._-]{0,123}$') {
        throw "Personal local Lab runtime releaseId is invalid: $ReleaseId"
    }
}
elseif ($ReleaseId -cnotmatch
        '^managed-v[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]*$') {
    throw "Personal runtime releaseId is invalid or requires explicit -AllowLocalLab: $ReleaseId"
}

$sourceLeases = [Collections.Generic.List[IDisposable]]::new()
$metadataBytes = $null
$hashEvidenceBytes = $null
try {
    $outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
    $workRoot = [IO.Path]::GetFullPath($WorkDirectory)
    if (Test-Path -LiteralPath $outputRoot) {
        throw "Personal runtime output directory must be a new absent path: $outputRoot"
    }
    if (Test-Path -LiteralPath $workRoot) {
        throw "Personal runtime work directory must be a new absent path: $workRoot"
    }
    if ((Test-SameOrDescendant -Path $outputRoot -Root $workRoot) -or
        (Test-SameOrDescendant -Path $workRoot -Root $outputRoot)) {
        throw 'Personal runtime output and work directories must be disjoint.'
    }
    if ([IO.Path]::GetPathRoot($outputRoot) -cne [IO.Path]::GetPathRoot($workRoot)) {
        throw 'Personal runtime output and work directories must share one volume for atomic publication.'
    }
    Assert-OrdinaryExistingParent $outputRoot
    Assert-OrdinaryExistingParent $workRoot

    $sourceArchiveFile = Open-ExactLockedInput `
        -Path $SourceRuntimeArchivePath `
        -Leases $sourceLeases `
        -MaximumBytes $maximumRuntimeArchiveBytes
    $sourceMetadataFile = Open-ExactLockedInput `
        -Path $SourceRuntimeMetadataPath `
        -Leases $sourceLeases `
        -MaximumBytes (1MB)
    $sourceHashEvidenceFile = Open-ExactLockedInput `
        -Path $SourceRuntimeHashEvidencePath `
        -Leases $sourceLeases `
        -MaximumBytes (4KB)
    $sourceArchive = $sourceArchiveFile.Path
    $sourceMetadata = $sourceMetadataFile.Path
    $sourceHashEvidence = $sourceHashEvidenceFile.Path
    $expectedSourceArchiveName = "EnsouDshRuntime-$ReleaseId-win-x64.zip"
    if ([IO.Path]::GetFileName($sourceArchive) -cne
            $expectedSourceArchiveName -or
        [IO.Path]::GetFileName($sourceMetadata) -cne
            "EnsouDshRuntime-$ReleaseId-win-x64.metadata.json" -or
        [IO.Path]::GetFileName($sourceHashEvidence) -cne
            "$expectedSourceArchiveName.sha256") {
        throw 'Source-runtime evidence filenames do not bind the exact managed releaseId.'
    }
    if ($null -ne $SourceEvidenceLockedObserver) {
        $null = & $SourceEvidenceLockedObserver ([pscustomobject]@{
            Archive = $sourceArchiveFile
            Metadata = $sourceMetadataFile
            HashEvidence = $sourceHashEvidenceFile
        })
    }

    [IO.Directory]::CreateDirectory($workRoot) | Out-Null
    $treeRoot = Join-Path $workRoot 'source-tree'
    $publishRoot = Join-Path $workRoot 'publish'
    [IO.Directory]::CreateDirectory($treeRoot) | Out-Null
    [IO.Directory]::CreateDirectory($publishRoot) | Out-Null

    $metadataBytes = Read-LockedInputBytes `
        -Descriptor $sourceMetadataFile `
        -MaximumBytes (1MB)
    $hashEvidenceBytes = Read-LockedInputBytes `
        -Descriptor $sourceHashEvidenceFile `
        -MaximumBytes (4KB)
    $metadataSnapshot = New-LockedSnapshotFile `
        -Path (Join-Path $workRoot 'source-runtime-metadata.snapshot.json') `
        -Bytes $metadataBytes `
        -Leases $sourceLeases
    $hashEvidenceText = $utf8Strict.GetString($hashEvidenceBytes)
    $hashEvidenceMatch = [Text.RegularExpressions.Regex]::Match(
        $hashEvidenceText,
        '\A(?<sha256>[0-9a-f]{64})  (?<fileName>[A-Za-z0-9][A-Za-z0-9._-]*\.zip)\r?\n?\z',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $hashEvidenceMatch.Success -or
        $hashEvidenceMatch.Groups['fileName'].Value -cne
            [IO.Path]::GetFileName($sourceArchive) -or
        [IO.Path]::GetFileName($sourceHashEvidence) -cne
            ([IO.Path]::GetFileName($sourceArchive) + '.sha256')) {
        throw 'Source-runtime hash evidence is not the exact canonical archive digest record.'
    }
    $expectedSourceSha256 = $hashEvidenceMatch.Groups['sha256'].Value
    if ($sourceArchiveFile.Sha256 -cne $expectedSourceSha256) {
        throw 'Locked source-runtime archive differs from its hash evidence.'
    }

    $metadataValidator = Join-Path $PSScriptRoot `
        '..\release\scripts\Test-SourceRuntimeMetadata.ps1'
    $metadataValidation = @{
        MetadataPath = $metadataSnapshot.Path
        ArtifactPath = $sourceArchive
        ExpectedReleaseId = $ReleaseId
        ExpectedArtifactFileName = [IO.Path]::GetFileName($sourceArchive)
        ExpectedArtifactSha256 = $expectedSourceSha256
    }
    if ($AllowLocalLab) {
        $metadataValidation.AllowLocalLab = $true
    }
    $metadataOutput = @(& $metadataValidator @metadataValidation)
    if ($metadataOutput.Count -ne 1) {
        throw 'Source-runtime metadata validator did not return one exact record.'
    }
    $metadata = $metadataOutput[0]
    if ($metadata.releaseId -cne $ReleaseId -or
        $metadata.artifact.sha256 -cne $expectedSourceSha256 -or
        [int64]$metadata.artifact.sizeBytes -ne $sourceArchiveFile.SizeBytes) {
        throw 'Source-runtime metadata identity differs from the locked Personal runtime.'
    }

    Add-Type -AssemblyName System.IO.Compression
    $sourceStream = $sourceArchiveFile.Stream
    $extracted = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal)
    if ($sourceStream.Length -ne [int64]$metadata.artifact.sizeBytes -or
        (Get-StreamSha256 $sourceStream) -cne $expectedSourceSha256) {
        throw 'Source-runtime archive changed after metadata admission.'
    }
    $archive = [IO.Compression.ZipArchive]::new(
        $sourceStream,
        [IO.Compression.ZipArchiveMode]::Read,
        $true)
    try {
        if ($archive.Entries.Count -le 0 -or
            $archive.Entries.Count -gt $maximumArchiveEntries) {
            throw 'Source-runtime ZIP entry count is outside the Personal runtime bound.'
        }
        $records = [Collections.Generic.List[object]]::new()
        $seenEntries = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        $filePaths = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        [int64]$expandedBytes = 0
        foreach ($entry in $archive.Entries) {
            $directory = $entry.FullName.EndsWith('/', [StringComparison]::Ordinal)
            $relative = Get-CanonicalRelativePath `
                -Path $entry.FullName `
                -Directory $directory
            $unixType = (($entry.ExternalAttributes -shr 16) -band 0xF000)
            if (($entry.ExternalAttributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($directory -and ($unixType -notin @(0, 0x4000) -or $entry.Length -ne 0)) -or
                (-not $directory -and (
                    $unixType -notin @(0, 0x8000) -or
                    ($entry.ExternalAttributes -band [int][IO.FileAttributes]::Directory) -ne 0))) {
                throw "Source-runtime ZIP contains a link or non-ordinary entry: $($entry.FullName)"
            }
            if (-not $seenEntries.Add($relative)) {
                throw "Source-runtime ZIP contains a duplicate or Windows-colliding path: $relative"
            }
            if (-not $directory) {
                if ([int64]$entry.Length -gt $maximumExpandedBytes - $expandedBytes) {
                    throw 'Source-runtime ZIP expands beyond the Personal runtime bound.'
                }
                $expandedBytes = [int64]($expandedBytes + [int64]$entry.Length)
                [void]$filePaths.Add($relative)
            }
            $records.Add([pscustomobject]@{
                Entry = $entry
                Relative = $relative
                Directory = $directory
            })
        }
        if ($filePaths.Contains($completeTreeName)) {
            throw 'Source-runtime ZIP already contains Personal complete-tree evidence; provenance must be reassessed.'
        }
        foreach ($record in $records) {
            $segments = $record.Relative.Split('/')
            for ($index = 1; $index -lt $segments.Length; $index++) {
                $ancestor = [string]::Join('/', $segments[0..($index - 1)])
                if ($filePaths.Contains($ancestor)) {
                    throw "Source-runtime ZIP places a child below a file: $($record.Relative)"
                }
            }
        }
        foreach ($record in $records) {
            $destination = Get-ContainedPath `
                -Root $treeRoot `
                -RelativePath $record.Relative
            if ($record.Directory) {
                [IO.Directory]::CreateDirectory($destination) | Out-Null
                continue
            }
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) |
                Out-Null
            $input = $record.Entry.Open()
            $output = [IO.File]::Open(
                $destination,
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write,
                [IO.FileShare]::None)
            $hasher = [Security.Cryptography.IncrementalHash]::CreateHash(
                [Security.Cryptography.HashAlgorithmName]::SHA256)
            try {
                $buffer = [byte[]]::new(128 * 1024)
                [int64]$written = 0
                while ($true) {
                    $read = $input.Read($buffer, 0, $buffer.Length)
                    if ($read -eq 0) { break }
                    if ([int64]$read -gt [int64]$record.Entry.Length - $written) {
                        throw "Source-runtime ZIP entry expanded beyond its declared size: $($record.Relative)"
                    }
                    $written = [int64]($written + [int64]$read)
                    $hasher.AppendData($buffer, 0, $read)
                    $output.Write($buffer, 0, $read)
                }
                $output.Flush($true)
                if ($written -ne [int64]$record.Entry.Length) {
                    throw "Source-runtime ZIP entry changed size while extracting: $($record.Relative)"
                }
                $extracted.Add($record.Relative, [pscustomobject]@{
                    path = $record.Relative
                    sizeBytes = $written
                    sha256 = ([Convert]::ToHexString(
                        $hasher.GetHashAndReset())).ToLowerInvariant()
                    filePath = $destination
                })
            } finally {
                $hasher.Dispose()
                $output.Dispose()
                $input.Dispose()
            }
        }
    } finally {
        $archive.Dispose()
    }
    $sourceStream.Position = 0

Assert-OrdinaryExtractedTree $treeRoot
if (-not $extracted.ContainsKey($runtimeHashManifestName)) {
    throw 'Source-runtime ZIP has no runtime-files.sha256 evidence.'
}
if (-not $extracted.ContainsKey($sourceProvenanceName) -or
    [int64]$extracted[$sourceProvenanceName].sizeBytes -le 0) {
    throw 'Source-runtime ZIP has no non-empty source-build.json provenance evidence.'
}
$sourceProvenancePath = [string]$extracted[$sourceProvenanceName].filePath
try {
    $sourceProvenanceDocument = Read-PersonalSourceBuildEvidence `
        -Bytes ([IO.File]::ReadAllBytes($sourceProvenancePath)) `
        -Label 'Source-runtime source-build.json provenance'
} catch {
    throw 'Source-runtime source-build.json provenance is not strict UTF-8 JSON.'
}
if ($sourceProvenanceDocument.schemaVersion -ne 3 -or
    $sourceProvenanceDocument.sourceBuilt -ne $true -or
    [string]$sourceProvenanceDocument.releaseId -cne $ReleaseId -or
    [bool]$sourceProvenanceDocument.promotionEligible -ne
        [bool]$metadata.promotionEligible -or
    [string]$sourceProvenanceDocument.artifactType -cne
        [string]$metadata.artifactType -or
    [string]$sourceProvenanceDocument.sourceIdentity -cne
        [string]$metadata.sourceIdentity -or
    [string]$sourceProvenanceDocument.sourceRepository -cne
        [string]$metadata.sourceRepository -or
    [string]$sourceProvenanceDocument.sourceTag -cne
        [string]$metadata.sourceTag -or
    [string]$sourceProvenanceDocument.sourceCommit -cne
        [string]$metadata.sourceCommit -or
    [string]$sourceProvenanceDocument.sourceTree -cne
        [string]$metadata.sourceTree -or
    [string]$sourceProvenanceDocument.runtimeWebAuthProtocol -cne
        [string]$metadata.runtimeWebAuthProtocol -or
    [string]$sourceProvenanceDocument.nodeSha256 -cne
        [string]$metadata.toolchain.nodeSha256 -or
    [string]$sourceProvenanceDocument.buildPipeline -cne
        'installation-owned-isolated-managed-source-v1' -or
    [string]$sourceProvenanceDocument.platform -cne 'win32-x64' -or
    $sourceProvenanceDocument.runtimeClosureAgainstPinnedSourceAndLock -ne
        $true -or
    $sourceProvenanceDocument.managedFocusedTests -ne $true -or
    $sourceProvenanceDocument.managedWindowsExcludedFocusedTests -ne $true -or
    $sourceProvenanceDocument.managedRefusalSmoke -ne $true -or
    $sourceProvenanceDocument.officialCheckoutUnchanged -ne $true -or
    [string]$sourceProvenanceDocument.builtAtUtc -cne
        [string]$metadata.builtAtUtc) {
    throw 'Source-runtime source-build.json differs from admitted metadata provenance.'
}
$sourceHashManifestPath = [string]$extracted[$runtimeHashManifestName].filePath
$sourceHashLines = [IO.File]::ReadAllLines($sourceHashManifestPath, $utf8Strict)
$sourceHashPaths = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase)
foreach ($line in $sourceHashLines) {
    $match = [Text.RegularExpressions.Regex]::Match(
        $line,
        '\A(?<sha256>[0-9a-f]{64})  (?<path>.+)\z',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $match.Success) {
        throw "Source-runtime file hash evidence contains a malformed line: $line"
    }
    $relative = Get-CanonicalRelativePath `
        -Path $match.Groups['path'].Value `
        -Directory $false
    if ($relative -ceq $runtimeHashManifestName -or
        -not $sourceHashPaths.Add($relative) -or
        -not $extracted.ContainsKey($relative)) {
        throw "Source-runtime file hash evidence contains an unsafe, duplicate, or missing path: $relative"
    }
    if ([string]$extracted[$relative].sha256 -cne $match.Groups['sha256'].Value) {
        throw "Source-runtime file hash evidence disagrees with extracted bytes: $relative"
    }
}
if ($sourceHashPaths.Count -ne $extracted.Count - 1 -or
    @($extracted.Keys | Where-Object {
        $_ -cne $runtimeHashManifestName -and -not $sourceHashPaths.Contains($_)
    }).Count -ne 0) {
    throw 'Source-runtime file hash evidence does not cover the exact extracted tree.'
}

$nodePath = 'node.exe'
$dshEntryPath = 'node_modules/@deepseek-ai/dsh/lib/bin.js'
if (-not $extracted.ContainsKey($nodePath) -or
    -not $extracted.ContainsKey($dshEntryPath) -or
    [int64]$extracted[$nodePath].sizeBytes -lt 2 -or
    [int64]$extracted[$dshEntryPath].sizeBytes -le 0 -or
    [string]$extracted[$nodePath].sha256 -cne [string]$metadata.toolchain.nodeSha256) {
    throw 'Source-runtime critical node.exe or DSH entry is missing or differs from builder evidence.'
}
$nodeStream = [IO.File]::Open(
    [string]$extracted[$nodePath].filePath,
    [IO.FileMode]::Open,
    [IO.FileAccess]::Read,
    [IO.FileShare]::Read)
try {
    if ($nodeStream.ReadByte() -ne 0x4D -or $nodeStream.ReadByte() -ne 0x5A) {
        throw 'Source-runtime node.exe is not a Windows PE executable; CI placeholders are forbidden.'
    }
} finally {
    $nodeStream.Dispose()
}

[string[]]$paths = @($extracted.Keys)
[Array]::Sort($paths, [StringComparer]::Ordinal)
$files = [Collections.Generic.List[object]]::new()
foreach ($path in $paths) {
    $descriptor = $extracted[$path]
    $files.Add([ordered]@{
        path = $path
        sizeBytes = [int64]$descriptor.sizeBytes
        sha256 = [string]$descriptor.sha256
    })
}
$treeJson = [ordered]@{
    schemaVersion = 1
    component = 'runtime'
    releaseId = $ReleaseId
    files = $files
} | ConvertTo-Json -Depth 5 -Compress
$treeBytes = $utf8Strict.GetBytes($treeJson)
if ($treeBytes.Length -le 0 -or $treeBytes.Length -gt $maximumTreeBytes) {
    throw 'Generated Personal complete-tree manifest exceeds its bound.'
}
$embeddedTreePath = Join-Path $treeRoot $completeTreeName
[IO.File]::WriteAllBytes($embeddedTreePath, $treeBytes)

$archiveName = "EnsouDshPersonalRuntime-$ReleaseId-win-x64.zip"
$treeName = "EnsouDshPersonalRuntime-$ReleaseId-win-x64.complete-tree.json"
$artifactDescriptorName =
    "EnsouDshPersonalRuntime-$ReleaseId-win-x64.artifact.v1.json"
$stagedArchive = Join-Path $publishRoot $archiveName
$stagedTree = Join-Path $publishRoot $treeName
$stagedArtifactDescriptor = Join-Path $publishRoot $artifactDescriptorName
[IO.File]::WriteAllBytes($stagedTree, $treeBytes)
[string[]]$archivePaths = @($paths) + $completeTreeName
[Array]::Sort($archivePaths, [StringComparer]::Ordinal)
$zipStream = [IO.File]::Open(
    $stagedArchive,
    [IO.FileMode]::CreateNew,
    [IO.FileAccess]::ReadWrite,
    [IO.FileShare]::None)
try {
    $zip = [IO.Compression.ZipArchive]::new(
        $zipStream,
        [IO.Compression.ZipArchiveMode]::Create,
        $true)
    try {
        foreach ($relative in $archivePaths) {
            $sourcePath = Get-ContainedPath -Root $treeRoot -RelativePath $relative
            $entry = $zip.CreateEntry(
                $relative,
                [IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = [DateTimeOffset]::new(
                1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
            $entry.ExternalAttributes = 0
            $input = [IO.File]::Open(
                $sourcePath,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::Read)
            $output = $entry.Open()
            try {
                $input.CopyTo($output)
            } finally {
                $output.Dispose()
                $input.Dispose()
            }
        }
    } finally {
        $zip.Dispose()
    }
    $zipStream.Flush($true)
} finally {
    $zipStream.Dispose()
}

$archiveItem = Get-Item -LiteralPath $stagedArchive -Force
if ($archiveItem.Length -le 0 -or $archiveItem.Length -gt $maximumRuntimeArchiveBytes) {
    throw 'Generated Personal runtime archive exceeds its signed artifact bound.'
}
Assert-PersonalRuntimeArchive `
    -ArchivePath $stagedArchive `
    -TreeBytes $treeBytes `
    -Descriptors $extracted

$stagedArchiveItem = Get-Item -LiteralPath $stagedArchive -Force
$stagedTreeItem = Get-Item -LiteralPath $stagedTree -Force
$archiveSha256 = Get-FileSha256 $stagedArchive
$treeSha256 = Get-FileSha256 $stagedTree
$sourceProvenance = $extracted[$sourceProvenanceName]
$artifactDescriptor = [ordered]@{
    schemaVersion = 1
    artifactType = 'ensou-dsh-personal-source-runtime-artifact'
    releaseId = $ReleaseId
    promotionEligible = [bool]$metadata.promotionEligible
    archive = [ordered]@{
        path = Join-Path $outputRoot $archiveName
        sizeBytes = $stagedArchiveItem.Length
        sha256 = $archiveSha256
    }
    completeTree = [ordered]@{
        path = Join-Path $outputRoot $treeName
        sizeBytes = $stagedTreeItem.Length
        sha256 = $treeSha256
    }
    sourceRuntime = [ordered]@{
        archive = [ordered]@{
            fileName = [IO.Path]::GetFileName($sourceArchive)
            sizeBytes = [int64]$metadata.artifact.sizeBytes
            sha256 = $expectedSourceSha256
        }
        metadata = [ordered]@{
            fileName = [IO.Path]::GetFileName($sourceMetadata)
            sizeBytes = $sourceMetadataFile.SizeBytes
            sha256 = $sourceMetadataFile.Sha256
        }
        hashEvidence = [ordered]@{
            fileName = [IO.Path]::GetFileName($sourceHashEvidence)
            sizeBytes = $sourceHashEvidenceFile.SizeBytes
            sha256 = $sourceHashEvidenceFile.Sha256
        }
        provenance = [ordered]@{
            path = $sourceProvenanceName
            sizeBytes = [int64]$sourceProvenance.sizeBytes
            sha256 = [string]$sourceProvenance.sha256
        }
    }
    fileCount = $extracted.Count
    expandedSizeBytes = [int64]($extracted.Values |
        Measure-Object -Property sizeBytes -Sum).Sum
}
$artifactDescriptorBytes = $utf8Strict.GetBytes(
    ($artifactDescriptor | ConvertTo-Json -Depth 10 -Compress))
try {
    $artifactDescriptorStream = [IO.File]::Open(
        $stagedArtifactDescriptor,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try {
        $artifactDescriptorStream.Write($artifactDescriptorBytes)
        $artifactDescriptorStream.Flush($true)
    } finally {
        $artifactDescriptorStream.Dispose()
    }
} finally {
    [Array]::Clear($artifactDescriptorBytes, 0, $artifactDescriptorBytes.Length)
}

if (@(Get-ChildItem -LiteralPath $publishRoot -Force).Count -ne 3) {
    throw 'Personal runtime publication staging must contain exactly archive, complete-tree, and artifact descriptor.'
}
[IO.Directory]::Move($publishRoot, $outputRoot)
$publishedArchive = Join-Path $outputRoot $archiveName
$publishedTree = Join-Path $outputRoot $treeName
$publishedArtifactDescriptor = Join-Path $outputRoot $artifactDescriptorName
if ((Get-FileSha256 $publishedArchive) -cne $archiveSha256 -or
    (Get-FileSha256 $publishedTree) -cne $treeSha256) {
    throw 'Published Personal runtime artifact changed during atomic publication.'
}
if ($treeSha256 -cne
        ([Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($treeBytes))).ToLowerInvariant()) {
    throw 'Published Personal complete-tree descriptor changed during atomic publication.'
}

[pscustomobject]@{
    ReleaseId = $ReleaseId
    PromotionEligible = [bool]$metadata.promotionEligible
    ArchivePath = $publishedArchive
    ArchiveSizeBytes = (Get-Item -LiteralPath $publishedArchive -Force).Length
    ArchiveSha256 = $archiveSha256
    CompleteTreeManifestPath = $publishedTree
    CompleteTreeSizeBytes = (Get-Item -LiteralPath $publishedTree -Force).Length
    CompleteTreeSha256 = $treeSha256
    ArtifactDescriptorPath = $publishedArtifactDescriptor
    ArtifactDescriptorSizeBytes =
        (Get-Item -LiteralPath $publishedArtifactDescriptor -Force).Length
    ArtifactDescriptorSha256 = Get-FileSha256 $publishedArtifactDescriptor
    FileCount = $extracted.Count
    ExpandedSizeBytes = [int64]($extracted.Values |
        Measure-Object -Property sizeBytes -Sum).Sum
}
} finally {
    if ($null -ne $metadataBytes) {
        [Array]::Clear($metadataBytes, 0, $metadataBytes.Length)
    }
    if ($null -ne $hashEvidenceBytes) {
        [Array]::Clear($hashEvidenceBytes, 0, $hashEvidenceBytes.Length)
    }
    for ($index = $sourceLeases.Count - 1; $index -ge 0; $index--) {
        $sourceLeases[$index].Dispose()
    }
}
