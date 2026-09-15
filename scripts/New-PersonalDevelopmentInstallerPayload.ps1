[CmdletBinding(DefaultParameterSetName = 'CiPlaceholder')]
param(
    [Parameter(Mandatory = $true)]
    [string]$StartupStubPath,

    [Parameter(Mandatory = $true)]
    [string]$ClientBundleArchivePath,

    [Parameter(Mandatory = $true)]
    [string]$ClientBundleCompleteTreePath,

    [Parameter(Mandatory = $true)]
    [string]$TrustDescriptorPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $true)]
    [string]$WorkDirectory,

    [Parameter(Mandatory = $true, ParameterSetName = 'VerifiedRuntimeArtifact')]
    [string]$RuntimeArtifactDescriptorPath,

    [Parameter(ParameterSetName = 'VerifiedRuntimeArtifact')]
    [switch]$AllowLocalLab,

    [Parameter(ParameterSetName = 'VerifiedRuntimeArtifact', DontShow = $true)]
    [scriptblock]$RuntimeArtifactLockedObserver
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not ('EnsouPersonalRuntimePayload.NativeFileIdentity' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace EnsouPersonalRuntimePayload
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
                throw new InvalidDataException("Runtime artifact handle is invalid.");
            }
            if (!GetFileInformationByHandle(handle, out var information))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not inspect runtime artifact identity.");
            }
            const uint directory = 0x10;
            const uint reparsePoint = 0x400;
            if (information.NumberOfLinks != 1
                || (information.FileAttributes & (directory | reparsePoint)) != 0)
            {
                throw new InvalidDataException(
                    "Runtime artifact must be one ordinary single-link file.");
            }
            var index = ((ulong)information.FileIndexHigh << 32)
                | information.FileIndexLow;
            return new ExactFileIdentity(information.VolumeSerialNumber, index);
        }
    }
}
'@
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

function Assert-OrdinaryDirectoryChain {
    param([Parameter(Mandatory = $true)][string]$Path)

    for ($current = Get-Item -LiteralPath $Path -Force -ErrorAction Stop;
         $null -ne $current;
         $current = $current.Parent) {
        if (-not ($current -is [IO.DirectoryInfo]) -or
            ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Development payload directory chain is not ordinary: $Path"
        }
    }
}

function Resolve-OrdinaryFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $resolved -Force
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0) {
        throw "Development payload input is not one ordinary non-empty file: $resolved"
    }
    for ($current = $item.Directory; $null -ne $current; $current = $current.Parent) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Development payload input crosses a filesystem link: $resolved"
        }
    }
    return $resolved
}

function New-EmptyOrdinaryDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = [IO.Path]::GetFullPath($Path)
    if (Test-Path -LiteralPath $resolved) {
        $item = Get-Item -LiteralPath $resolved -Force
        if (-not $item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            @(Get-ChildItem -LiteralPath $resolved -Force).Count -ne 0) {
            throw "Development payload output must be an absent or empty ordinary directory: $resolved"
        }
    } else {
        Assert-OrdinaryDirectoryChain ([IO.Path]::GetDirectoryName($resolved))
        New-Item -ItemType Directory -Path $resolved | Out-Null
    }
    Assert-OrdinaryDirectoryChain $resolved
    return $resolved
}

function Get-FileDescriptor {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = Resolve-OrdinaryFile $Path
    $item = Get-Item -LiteralPath $resolved -Force
    return [ordered]@{
        path = $resolved
        sizeBytes = $item.Length
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolved).Hash.ToLowerInvariant()
    }
}

function Get-BytesSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return ([Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($Bytes))).ToLowerInvariant()
}

function Get-StreamSha256 {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)

    $Stream.Position = 0
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([Convert]::ToHexString($sha.ComputeHash($Stream))).ToLowerInvariant()
    } finally {
        $sha.Dispose()
        $Stream.Position = 0
    }
}

function Open-ExactLockedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[IDisposable]]$Leases,
        [int64]$MaximumBytes = [int64]::MaxValue
    )

    $resolved = Resolve-OrdinaryFile $Path
    $stream = [IO.File]::Open(
        $resolved,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $identity = [EnsouPersonalRuntimePayload.NativeFileIdentity]::
            RequireOrdinarySingleLink($stream.SafeFileHandle)
        if ($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) {
            throw "Development runtime artifact input is empty or unbounded: $resolved"
        }
        $postOpenPath = Resolve-OrdinaryFile $resolved
        $pathStream = [IO.File]::Open(
            $postOpenPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read)
        try {
            $pathIdentity = [EnsouPersonalRuntimePayload.NativeFileIdentity]::
                RequireOrdinarySingleLink($pathStream.SafeFileHandle)
            if ($pathIdentity.VolumeSerialNumber -ne $identity.VolumeSerialNumber -or
                $pathIdentity.FileIndex -ne $identity.FileIndex) {
                throw "Runtime artifact path no longer names its locked file: $resolved"
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

function Read-LockedBytes {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][int]$MaximumBytes
    )

    if ($Descriptor.SizeBytes -le 0 -or $Descriptor.SizeBytes -gt $MaximumBytes) {
        throw "Locked runtime artifact input is empty or unbounded: $($Descriptor.Path)"
    }
    $Descriptor.Stream.Position = 0
    $bytes = [byte[]]::new([int]$Descriptor.SizeBytes)
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $read = $Descriptor.Stream.Read($bytes, $offset, $bytes.Length - $offset)
        if ($read -eq 0) {
            throw "Locked runtime artifact input ended early: $($Descriptor.Path)"
        }
        $offset += $read
    }
    if ($Descriptor.Stream.ReadByte() -ne -1) {
        throw "Locked runtime artifact input grew while reading: $($Descriptor.Path)"
    }
    $Descriptor.Stream.Position = 0
    return $bytes
}

function Copy-ExactLockedFile {
    param(
        [Parameter(Mandatory = $true)]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $destinationPath = [IO.Path]::GetFullPath($Destination)
    Assert-OrdinaryDirectoryChain ([IO.Path]::GetDirectoryName($destinationPath))
    $output = [IO.File]::Open(
        $destinationPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
    try {
        $identity = [EnsouPersonalRuntimePayload.NativeFileIdentity]::
            RequireOrdinarySingleLink($output.SafeFileHandle)
        $hasher = [Security.Cryptography.IncrementalHash]::CreateHash(
            [Security.Cryptography.HashAlgorithmName]::SHA256)
        $buffer = [byte[]]::new(128 * 1024)
        try {
            $Source.Stream.Position = 0
            [int64]$written = 0
            while ($true) {
                $read = $Source.Stream.Read($buffer, 0, $buffer.Length)
                if ($read -eq 0) { break }
                if ([int64]$read -gt [int64]::MaxValue - $written) {
                    throw 'Locked runtime artifact copy size overflowed.'
                }
                $written += [int64]$read
                $hasher.AppendData($buffer, 0, $read)
                $output.Write($buffer, 0, $read)
            }
            $output.Flush($true)
            $sha256 = ([Convert]::ToHexString(
                $hasher.GetHashAndReset())).ToLowerInvariant()
        } finally {
            $hasher.Dispose()
            [Array]::Clear($buffer, 0, $buffer.Length)
            $Source.Stream.Position = 0
        }
        if ($written -ne $Source.SizeBytes -or $sha256 -cne $Source.Sha256 -or
            $output.Length -ne $Source.SizeBytes) {
            throw 'Locked runtime artifact changed while entering the development payload.'
        }
        $sizeBytes = $output.Length
        $output.Dispose()
        return [pscustomobject]@{
            Path = $destinationPath
            SizeBytes = $sizeBytes
            Sha256 = $sha256
        }
    } catch {
        $output.Dispose()
        throw
    }
}

function Read-BoundedZipEntryBytes {
    param(
        [Parameter(Mandatory = $true)][IO.Compression.ZipArchiveEntry]$Entry,
        [Parameter(Mandatory = $true)][int]$MaximumBytes
    )

    if ($Entry.Length -le 0 -or $Entry.Length -gt $MaximumBytes) {
        throw "Development runtime complete-tree entry is empty or unbounded: $($Entry.FullName)"
    }
    $input = $Entry.Open()
    try {
        $output = [IO.MemoryStream]::new([int]$Entry.Length)
        try {
            $input.CopyTo($output)
            if ($output.Length -ne $Entry.Length) {
                throw 'Development runtime complete-tree entry changed while reading.'
            }
            return $output.ToArray()
        } finally {
            $output.Dispose()
        }
    } finally {
        $input.Dispose()
    }
}

function Get-CanonicalRuntimePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path.Length -gt 1024 -or
        $Path.Contains('\') -or
        $Path.Contains(':') -or
        $Path.StartsWith('/', [StringComparison]::Ordinal) -or
        $Path.EndsWith('/', [StringComparison]::Ordinal) -or
        $Path.Contains('//') -or
        -not $Path.IsNormalized([Text.NormalizationForm]::FormC)) {
        throw "Development runtime ZIP path is not canonical: $Path"
    }
    $invalid = [IO.Path]::GetInvalidFileNameChars()
    foreach ($segment in $Path.Split('/')) {
        $baseName = $segment.Split('.', 2)[0]
        if ([string]::IsNullOrEmpty($segment) -or
            $segment -in @('.', '..') -or
            $segment.Length -gt 255 -or
            $segment.EndsWith(' ', [StringComparison]::Ordinal) -or
            $segment.EndsWith('.', [StringComparison]::Ordinal) -or
            $segment.IndexOfAny($invalid) -ge 0 -or
            @($segment.ToCharArray() | Where-Object { [int]$_ -lt 32 }).Count -ne 0 -or
            $baseName -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
            throw "Development runtime ZIP path has an unsafe Windows segment: $Path"
        }
    }
    return $Path
}

function Assert-PersonalPayloadSourceBuildNoDuplicateJsonMembers {
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
            Assert-PersonalPayloadSourceBuildNoDuplicateJsonMembers `
                -Element $property.Value `
                -Label $Label
        }
    }
    elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) {
            Assert-PersonalPayloadSourceBuildNoDuplicateJsonMembers `
                -Element $item `
                -Label $Label
        }
    }
}

function Get-PersonalPayloadSourceBuildRequiredJsonProperty {
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

function Read-PersonalPayloadSourceBuildEvidence {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $document = [Text.Json.JsonDocument]::Parse(
        [ReadOnlyMemory[byte]]::new($Bytes))
    try {
        $root = $document.RootElement
        Assert-PersonalPayloadSourceBuildNoDuplicateJsonMembers `
            -Element $root `
            -Label $Label

        $schemaVersionProperty =
            Get-PersonalPayloadSourceBuildRequiredJsonProperty `
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

        $sourceBuiltProperty =
            Get-PersonalPayloadSourceBuildRequiredJsonProperty `
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
        $promotionEligibleProperty =
            Get-PersonalPayloadSourceBuildRequiredJsonProperty `
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
            $property = Get-PersonalPayloadSourceBuildRequiredJsonProperty `
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
            $property = Get-PersonalPayloadSourceBuildRequiredJsonProperty `
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

function Resolve-VerifiedRuntimeArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$DescriptorPath,
        [switch]$AllowLocalLab,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[IDisposable]]$Leases
    )

    $descriptorFile = Open-ExactLockedFile `
        -Path $DescriptorPath `
        -Leases $Leases `
        -MaximumBytes (256KB)
    $descriptorBytes = Read-LockedBytes `
        -Descriptor $descriptorFile `
        -MaximumBytes (256KB)
    $utf8Strict = [Text.UTF8Encoding]::new($false, $true)
    $descriptorText = $utf8Strict.GetString($descriptorBytes)
    $descriptor = $descriptorText | ConvertFrom-Json -Depth 20
    if ((@($descriptor.PSObject.Properties.Name | Sort-Object) -join ',') -cne
            'archive,artifactType,completeTree,expandedSizeBytes,fileCount,promotionEligible,releaseId,schemaVersion,sourceRuntime' -or
        $descriptor.schemaVersion -ne 1 -or
        $descriptor.artifactType -cne
            'ensou-dsh-personal-source-runtime-artifact' -or
        $descriptor.promotionEligible -notin @($true, $false) -or
        [string]$descriptor.releaseId -cnotmatch
            '^(?:managed-v[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]*|lab-[A-Za-z0-9][A-Za-z0-9._-]{0,123})$' -or
        [int]$descriptor.fileCount -le 0 -or
        [int]$descriptor.fileCount -gt 250000 -or
        [int64]$descriptor.expandedSizeBytes -le 0 -or
        [int64]$descriptor.expandedSizeBytes -gt (16L * 1024 * 1024 * 1024)) {
        throw 'Development runtime artifact descriptor identity is invalid.'
    }
    $promotionEligible = [bool]$descriptor.promotionEligible
    if (-not $promotionEligible -and -not $AllowLocalLab) {
        throw 'Development runtime local Lab artifact requires explicit -AllowLocalLab admission.'
    }
    if (($promotionEligible -and
            [string]$descriptor.releaseId -cnotmatch
                '^managed-v[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]*$') -or
        (-not $promotionEligible -and
            [string]$descriptor.releaseId -cnotmatch
                '^lab-[A-Za-z0-9][A-Za-z0-9._-]{0,123}$')) {
        throw 'Development runtime artifact promotion eligibility does not bind its releaseId class.'
    }
    foreach ($property in @('archive', 'completeTree')) {
        $value = $descriptor.$property
        if ((@($value.PSObject.Properties.Name | Sort-Object) -join ',') -cne
                'path,sha256,sizeBytes' -or
            -not [IO.Path]::IsPathFullyQualified([string]$value.path) -or
            [string]$value.path -cne [IO.Path]::GetFullPath([string]$value.path) -or
            [int64]$value.sizeBytes -le 0 -or
            [string]$value.sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw "Development runtime artifact descriptor $property is invalid."
        }
    }
    $sourceRuntime = $descriptor.sourceRuntime
    if ((@($sourceRuntime.PSObject.Properties.Name | Sort-Object) -join ',') -cne
            'archive,hashEvidence,metadata,provenance') {
        throw 'Development runtime source evidence descriptor is invalid.'
    }
    foreach ($property in @('archive', 'metadata', 'hashEvidence')) {
        $value = $sourceRuntime.$property
        if ((@($value.PSObject.Properties.Name | Sort-Object) -join ',') -cne
                'fileName,sha256,sizeBytes' -or
            [string]$value.fileName -cnotmatch
                '^[A-Za-z0-9][A-Za-z0-9._-]+$' -or
            [int64]$value.sizeBytes -le 0 -or
            [string]$value.sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw "Development runtime source $property evidence is invalid."
        }
    }
    $sourceProvenance = $sourceRuntime.provenance
    if ((@($sourceProvenance.PSObject.Properties.Name | Sort-Object) -join ',') -cne
            'path,sha256,sizeBytes' -or
        $sourceProvenance.path -cne 'source-build.json' -or
        [int64]$sourceProvenance.sizeBytes -le 0 -or
        [string]$sourceProvenance.sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Development runtime source provenance evidence is invalid.'
    }

    $releaseId = [string]$descriptor.releaseId
    $expectedSourceArchiveName = "EnsouDshRuntime-$releaseId-win-x64.zip"
    if ($sourceRuntime.archive.fileName -cne $expectedSourceArchiveName -or
        $sourceRuntime.metadata.fileName -cne
            "EnsouDshRuntime-$releaseId-win-x64.metadata.json" -or
        $sourceRuntime.hashEvidence.fileName -cne
            "$expectedSourceArchiveName.sha256") {
        throw 'Development runtime source evidence names do not bind the releaseId.'
    }
    $descriptorRoot = Split-Path -Parent $descriptorFile.Path
    $expectedArchivePath = Join-Path $descriptorRoot `
        "EnsouDshPersonalRuntime-$releaseId-win-x64.zip"
    $expectedTreePath = Join-Path $descriptorRoot `
        "EnsouDshPersonalRuntime-$releaseId-win-x64.complete-tree.json"
    $expectedDescriptorPath = Join-Path $descriptorRoot `
        "EnsouDshPersonalRuntime-$releaseId-win-x64.artifact.v1.json"
    if ($descriptorFile.Path -cne $expectedDescriptorPath -or
        [string]$descriptor.archive.path -cne $expectedArchivePath -or
        [string]$descriptor.completeTree.path -cne $expectedTreePath) {
        throw 'Development runtime artifact descriptor paths are not the exact builder closure.'
    }
    $expectedClosureNames = @(
        [IO.Path]::GetFileName($expectedArchivePath),
        [IO.Path]::GetFileName($expectedTreePath),
        [IO.Path]::GetFileName($expectedDescriptorPath)
    )
    [Array]::Sort($expectedClosureNames, [StringComparer]::Ordinal)
    $closureItems = @(Get-ChildItem -LiteralPath $descriptorRoot -Force)
    [string[]]$actualClosureNames = @($closureItems | ForEach-Object Name)
    [Array]::Sort($actualClosureNames, [StringComparer]::Ordinal)
    if ($closureItems.Count -ne 3 -or
        @($closureItems | Where-Object {
            -not ($_ -is [IO.FileInfo]) -or
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        }).Count -ne 0 -or
        ([string]::Join("`n", $actualClosureNames)) -cne
            ([string]::Join("`n", $expectedClosureNames))) {
        throw 'Development runtime artifact directory is not the exact three-file builder closure.'
    }

    $canonicalDescriptor = [ordered]@{
        schemaVersion = 1
        artifactType = 'ensou-dsh-personal-source-runtime-artifact'
        releaseId = $releaseId
        promotionEligible = $promotionEligible
        archive = [ordered]@{
            path = $expectedArchivePath
            sizeBytes = [int64]$descriptor.archive.sizeBytes
            sha256 = [string]$descriptor.archive.sha256
        }
        completeTree = [ordered]@{
            path = $expectedTreePath
            sizeBytes = [int64]$descriptor.completeTree.sizeBytes
            sha256 = [string]$descriptor.completeTree.sha256
        }
        sourceRuntime = [ordered]@{
            archive = [ordered]@{
                fileName = [string]$sourceRuntime.archive.fileName
                sizeBytes = [int64]$sourceRuntime.archive.sizeBytes
                sha256 = [string]$sourceRuntime.archive.sha256
            }
            metadata = [ordered]@{
                fileName = [string]$sourceRuntime.metadata.fileName
                sizeBytes = [int64]$sourceRuntime.metadata.sizeBytes
                sha256 = [string]$sourceRuntime.metadata.sha256
            }
            hashEvidence = [ordered]@{
                fileName = [string]$sourceRuntime.hashEvidence.fileName
                sizeBytes = [int64]$sourceRuntime.hashEvidence.sizeBytes
                sha256 = [string]$sourceRuntime.hashEvidence.sha256
            }
            provenance = [ordered]@{
                path = 'source-build.json'
                sizeBytes = [int64]$sourceProvenance.sizeBytes
                sha256 = [string]$sourceProvenance.sha256
            }
        }
        fileCount = [int]$descriptor.fileCount
        expandedSizeBytes = [int64]$descriptor.expandedSizeBytes
    }
    $canonicalBytes = $utf8Strict.GetBytes(
        ($canonicalDescriptor | ConvertTo-Json -Depth 10 -Compress))
    try {
        if ($canonicalBytes.Length -ne $descriptorBytes.Length -or
            [Convert]::ToBase64String($canonicalBytes) -cne
                [Convert]::ToBase64String($descriptorBytes)) {
            throw 'Development runtime artifact descriptor is not canonical.'
        }
    } finally {
        [Array]::Clear($canonicalBytes, 0, $canonicalBytes.Length)
        [Array]::Clear($descriptorBytes, 0, $descriptorBytes.Length)
    }

    $archiveFile = Open-ExactLockedFile `
        -Path $expectedArchivePath `
        -Leases $Leases `
        -MaximumBytes (8L * 1024 * 1024 * 1024)
    $treeFile = Open-ExactLockedFile `
        -Path $expectedTreePath `
        -Leases $Leases `
        -MaximumBytes (16MB)
    if ($archiveFile.SizeBytes -ne [int64]$descriptor.archive.sizeBytes -or
        $archiveFile.Sha256 -cne [string]$descriptor.archive.sha256 -or
        $treeFile.SizeBytes -ne [int64]$descriptor.completeTree.sizeBytes -or
        $treeFile.Sha256 -cne [string]$descriptor.completeTree.sha256) {
        throw 'Development runtime artifact bytes differ from the builder descriptor.'
    }

    $treeBytes = Read-LockedBytes -Descriptor $treeFile -MaximumBytes (16MB)
    $treeText = $utf8Strict.GetString($treeBytes)
    $tree = $treeText | ConvertFrom-Json -Depth 20
    if ((@($tree.PSObject.Properties.Name | Sort-Object) -join ',') -cne
            'component,files,releaseId,schemaVersion' -or
        $tree.schemaVersion -ne 1 -or
        $tree.component -cne 'runtime' -or
        $tree.releaseId -cne $releaseId) {
        throw 'Development runtime external complete-tree identity is invalid.'
    }
    $files = @($tree.files)
    if ($files.Count -le 0 -or $files.Count -gt 250000) {
        throw 'Development runtime external complete-tree file count is invalid.'
    }
    [string[]]$paths = @($files | ForEach-Object { [string]$_.path })
    [string[]]$sortedPaths = $paths.Clone()
    [Array]::Sort($sortedPaths, [StringComparer]::Ordinal)
    if (([string]::Join("`n", $paths)) -cne
            ([string]::Join("`n", $sortedPaths)) -or
        $paths -cnotcontains 'node.exe' -or
        $paths -cnotcontains 'node_modules/@deepseek-ai/dsh/lib/bin.js' -or
        $paths -cnotcontains 'source-build.json' -or
        $paths -ccontains '.ensou-complete-tree.v1.json') {
        throw 'Development runtime external complete-tree ordering or required files are invalid.'
    }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $seenWindows = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $fileDescriptors = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal)
    [int64]$expandedSizeBytes = 0
    foreach ($file in $files) {
        $filePath = Get-CanonicalRuntimePath ([string]$file.path)
        if ((@($file.PSObject.Properties.Name | Sort-Object) -join ',') -cne
                'path,sha256,sizeBytes' -or
            [int64]$file.sizeBytes -lt 0 -or
            [string]$file.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            -not $seen.Add($filePath) -or
            -not $seenWindows.Add($filePath) -or
            [int64]$file.sizeBytes -gt
                (16L * 1024 * 1024 * 1024) - $expandedSizeBytes) {
            throw "Development runtime complete-tree file descriptor is invalid: $($file.path)"
        }
        $fileDescriptors.Add($filePath, $file)
        $expandedSizeBytes += [int64]$file.sizeBytes
    }
    $provenanceFile = @($files | Where-Object {
        $_.path -ceq 'source-build.json'
    })
    if ($provenanceFile.Count -ne 1 -or
        [int64]$provenanceFile[0].sizeBytes -ne
            [int64]$sourceProvenance.sizeBytes -or
        [string]$provenanceFile[0].sha256 -cne
            [string]$sourceProvenance.sha256 -or
        $files.Count -ne [int]$descriptor.fileCount -or
        $expandedSizeBytes -ne [int64]$descriptor.expandedSizeBytes) {
        throw 'Development runtime complete-tree differs from builder provenance evidence.'
    }

    Add-Type -AssemblyName System.IO.Compression
    $archiveFile.Stream.Position = 0
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $archiveFile.Stream,
            [IO.Compression.ZipArchiveMode]::Read,
            $true)
        try {
            if ($archive.Entries.Count -ne $files.Count + 1) {
                throw 'Development runtime artifact ZIP entry count differs from its complete-tree.'
            }
            $archivePaths = [Collections.Generic.HashSet[string]]::new(
                [StringComparer]::Ordinal)
            $archiveWindowsPaths = [Collections.Generic.HashSet[string]]::new(
                [StringComparer]::OrdinalIgnoreCase)
            $embeddedTreeBytes = $null
            $sourceProvenanceBytes = $null
            foreach ($entry in $archive.Entries) {
                $entryPath = Get-CanonicalRuntimePath $entry.FullName
                $unixType = (($entry.ExternalAttributes -shr 16) -band 0xF000)
                if ($unixType -notin @(0, 0x8000) -or
                    ($entry.ExternalAttributes -band
                        [int][IO.FileAttributes]::Directory) -ne 0 -or
                    ($entry.ExternalAttributes -band
                        [int][IO.FileAttributes]::ReparsePoint) -ne 0 -or
                    -not $archivePaths.Add($entryPath) -or
                    -not $archiveWindowsPaths.Add($entryPath)) {
                    throw "Development runtime archive contains a linked, special, duplicate, or colliding entry: $entryPath"
                }
                if ($entryPath -ceq '.ensou-complete-tree.v1.json') {
                    $embeddedTreeBytes = Read-BoundedZipEntryBytes `
                        -Entry $entry `
                        -MaximumBytes (16MB)
                    continue
                }
                if (-not $fileDescriptors.ContainsKey($entryPath)) {
                    throw "Development runtime archive contains an unexpected file: $entryPath"
                }
                $fileDescriptor = $fileDescriptors[$entryPath]
                if ($entryPath -ceq 'source-build.json') {
                    $sourceProvenanceBytes = Read-BoundedZipEntryBytes `
                        -Entry $entry `
                        -MaximumBytes (1MB)
                    $entrySha256 = Get-BytesSha256 $sourceProvenanceBytes
                } else {
                    $entryStream = $entry.Open()
                    try {
                        $entrySha256 = ([Convert]::ToHexString(
                            [Security.Cryptography.SHA256]::HashData(
                                $entryStream))).ToLowerInvariant()
                    } finally {
                        $entryStream.Dispose()
                    }
                }
                if ($entry.Length -ne [int64]$fileDescriptor.sizeBytes -or
                    $entrySha256 -cne [string]$fileDescriptor.sha256) {
                    throw "Development runtime archive differs from its complete-tree: $entryPath"
                }
            }
            if ($null -eq $embeddedTreeBytes -or
                $null -eq $sourceProvenanceBytes -or
                @($fileDescriptors.Keys | Where-Object {
                    -not $archivePaths.Contains($_)
                }).Count -ne 0) {
                throw 'Development runtime archive is missing complete-tree files.'
            }
        } finally {
            $archive.Dispose()
        }
    } finally {
        $archiveFile.Stream.Position = 0
    }
    $externalTreeSha256 = Get-BytesSha256 $treeBytes
    $embeddedTreeSha256 = Get-BytesSha256 $embeddedTreeBytes
    if ($embeddedTreeBytes.Length -ne $treeBytes.Length -or
        $embeddedTreeSha256 -cne $externalTreeSha256) {
        throw 'Development runtime embedded and external complete-tree bytes differ.'
    }
    try {
        $sourceProvenanceDocument = Read-PersonalPayloadSourceBuildEvidence `
            -Bytes $sourceProvenanceBytes `
            -Label 'Development runtime source-build.json provenance'
    } catch {
        throw 'Development runtime source-build.json provenance is invalid.'
    }
    $sourceBuiltAtValid = $true
    try {
        $sourceBuiltAt = [DateTimeOffset]$sourceProvenanceDocument.builtAtUtc
        if ($sourceBuiltAt -eq [DateTimeOffset]::MinValue) {
            $sourceBuiltAtValid = $false
        }
    } catch {
        $sourceBuiltAtValid = $false
    }
    $reviewedRuntimeWebAuthPairs = @{
        'dsh-v0.1.1-rc.2' = 'legacy-clean-root-v1'
        'dsh-v0.1.2-alpha.3' = 'browser-launch-cookie-v1'
        'dsh-v0.1.2-rc.1' = 'browser-launch-cookie-v1'
    }
    if ($sourceProvenanceDocument.schemaVersion -ne 3 -or
        $sourceProvenanceDocument.sourceBuilt -ne $true -or
        [string]$sourceProvenanceDocument.releaseId -cne $releaseId -or
        $sourceProvenanceDocument.promotionEligible -notin @($true, $false) -or
        [bool]$sourceProvenanceDocument.promotionEligible -ne
            $promotionEligible -or
        ($sourceProvenanceDocument.promotionEligible -eq $true -and
            $releaseId -cnotmatch
                '^managed-v[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]*$') -or
        ($sourceProvenanceDocument.promotionEligible -eq $false -and
            $releaseId -cnotmatch
                '^lab-[A-Za-z0-9][A-Za-z0-9._-]{0,123}$') -or
        [string]$sourceProvenanceDocument.artifactType -cne
            'ensou-dsh-enterprise-managed-source-runtime' -or
        [string]$sourceProvenanceDocument.sourceIdentity -cne
            'github-https-tag-plus-ensou-managed-patch' -or
        [string]$sourceProvenanceDocument.sourceRepository -cne
            'https://github.com/deepseek-ai/deepseek-harness.git' -or
        [string]$sourceProvenanceDocument.sourceTag -cnotmatch
            '^dsh-v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$' -or
        -not $reviewedRuntimeWebAuthPairs.ContainsKey(
            [string]$sourceProvenanceDocument.sourceTag) -or
        [string]$reviewedRuntimeWebAuthPairs[
            [string]$sourceProvenanceDocument.sourceTag] -cne
            [string]$sourceProvenanceDocument.runtimeWebAuthProtocol -or
        [string]$sourceProvenanceDocument.sourceCommit -cnotmatch
            '^[0-9a-f]{40}$' -or
        [string]$sourceProvenanceDocument.sourceTree -cnotmatch
            '^[0-9a-f]{40}$' -or
        [string]$sourceProvenanceDocument.platform -cne 'win32-x64' -or
        [string]$sourceProvenanceDocument.nodeSha256 -cne
            [string]$fileDescriptors['node.exe'].sha256 -or
        [string]$sourceProvenanceDocument.buildPipeline -cne
            'installation-owned-isolated-managed-source-v1' -or
        $sourceProvenanceDocument.runtimeClosureAgainstPinnedSourceAndLock -ne
            $true -or
        $sourceProvenanceDocument.managedFocusedTests -ne $true -or
        $sourceProvenanceDocument.managedWindowsExcludedFocusedTests -ne $true -or
        $sourceProvenanceDocument.managedRefusalSmoke -ne $true -or
        $sourceProvenanceDocument.officialCheckoutUnchanged -ne $true -or
        -not $sourceBuiltAtValid) {
        throw 'Development runtime source-build.json is not admitted managed-source provenance.'
    }

    return [pscustomobject]@{
        Descriptor = $descriptorFile
        Archive = $archiveFile
        CompleteTree = $treeFile
        CompleteTreeSha256 = $externalTreeSha256
        ReleaseId = $releaseId
        PromotionEligible = $promotionEligible
    }
}

$runtimeLeases = [Collections.Generic.List[IDisposable]]::new()
try {
$stub = Resolve-OrdinaryFile $StartupStubPath
$clientArchive = Resolve-OrdinaryFile $ClientBundleArchivePath
$clientTree = Resolve-OrdinaryFile $ClientBundleCompleteTreePath
$trustDescriptor = Resolve-OrdinaryFile $TrustDescriptorPath
$verifiedRuntimeArtifact = $null
if ($PSCmdlet.ParameterSetName -ceq 'VerifiedRuntimeArtifact') {
    $verifiedRuntimeArtifact = Resolve-VerifiedRuntimeArtifact `
        -DescriptorPath $RuntimeArtifactDescriptorPath `
        -AllowLocalLab:$AllowLocalLab `
        -Leases $runtimeLeases
}
$outputCandidate = [IO.Path]::GetFullPath($OutputDirectory)
$workCandidate = [IO.Path]::GetFullPath($WorkDirectory)
if ((Test-SameOrDescendant -Path $outputCandidate -Root $workCandidate) -or
    (Test-SameOrDescendant -Path $workCandidate -Root $outputCandidate)) {
    throw 'Development payload output and work directories must be disjoint.'
}
$inputPaths = @($stub, $clientArchive, $clientTree, $trustDescriptor)
if ($null -ne $verifiedRuntimeArtifact) {
    $inputPaths += @(
        $verifiedRuntimeArtifact.Descriptor.Path,
        $verifiedRuntimeArtifact.Archive.Path,
        $verifiedRuntimeArtifact.CompleteTree.Path)
}
foreach ($inputPath in $inputPaths) {
    if ((Test-SameOrDescendant -Path $inputPath -Root $outputCandidate) -or
        (Test-SameOrDescendant -Path $inputPath -Root $workCandidate)) {
        throw "Development payload output or work overlaps an input closure: $inputPath"
    }
}
if ($null -ne $verifiedRuntimeArtifact) {
    $runtimeClosureRoot = [IO.Path]::GetDirectoryName(
        $verifiedRuntimeArtifact.Descriptor.Path)
    if ((Test-SameOrDescendant -Path $outputCandidate -Root $runtimeClosureRoot) -or
        (Test-SameOrDescendant -Path $workCandidate -Root $runtimeClosureRoot)) {
        throw 'Development payload output or work would modify the runtime artifact closure.'
    }
}
if ($null -ne $verifiedRuntimeArtifact -and
    $null -ne $RuntimeArtifactLockedObserver) {
    & $RuntimeArtifactLockedObserver $verifiedRuntimeArtifact
}
$outputRoot = New-EmptyOrdinaryDirectory $outputCandidate
$workRoot = New-EmptyOrdinaryDirectory $workCandidate

$trust = Get-Content -Raw -LiteralPath $trustDescriptor | ConvertFrom-Json
$expectedTrustProperties = @(
    'artifactOrigin',
    'authenticodeSignerSha256Thumbprint',
    'canonicalLowSFromSequence',
    'channel',
    'keyId',
    'keyX',
    'keyY',
    'manifestOrigin',
    'productionBuild',
    'schemaVersion',
    'signingPrivateKeyPkcs8Path',
    'startupStubVersion'
)
if ((@($trust.PSObject.Properties.Name | Sort-Object) -join ',') -cne
        (@($expectedTrustProperties | Sort-Object) -join ',') -or
    $trust.schemaVersion -ne 1 -or
    $trust.productionBuild -ne $false -or
    $trust.manifestOrigin -cne 'https://updates.example.test/' -or
    $trust.artifactOrigin -cne 'https://updates.example.test/' -or
    $trust.channel -cne 'stable' -or
    $trust.keyId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' -or
    $trust.keyX -notmatch '^[A-Za-z0-9_-]+$' -or
    $trust.keyY -notmatch '^[A-Za-z0-9_-]+$' -or
    $trust.startupStubVersion -cne '1.2.0' -or
    $trust.canonicalLowSFromSequence -ne 1 -or
    $null -ne $trust.authenticodeSignerSha256Thumbprint) {
    throw 'Development trust descriptor is not the strict CI trust tuple.'
}
$keyPath = Resolve-OrdinaryFile ([string]$trust.signingPrivateKeyPkcs8Path)
$keyId = [string]$trust.keyId
$keyX = [string]$trust.keyX
$keyY = [string]$trust.keyY

$clientTreeDocument = Get-Content -Raw -LiteralPath $clientTree | ConvertFrom-Json
if ((@($clientTreeDocument.PSObject.Properties.Name | Sort-Object) -join ',') -cne
        'component,files,releaseId,schemaVersion' -or
    $clientTreeDocument.schemaVersion -ne 1 -or
    $clientTreeDocument.component -cne 'client-bundle' -or
    $clientTreeDocument.releaseId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
    throw 'Development client complete-tree identity is invalid.'
}
$clientReleaseId = [string]$clientTreeDocument.releaseId

$payloadStub = Join-Path $outputRoot 'Ensou.Dsh.Bootstrapper.exe'
$payloadClient = Join-Path $outputRoot 'client-bundle.zip'
Copy-Item -LiteralPath $stub -Destination $payloadStub
Copy-Item -LiteralPath $clientArchive -Destination $payloadClient

$runtimeArchive = Join-Path $outputRoot 'runtime.zip'
$runtimeSource = 'ci-placeholder'
$runtimeArtifactDescriptorSha256 = $null
if ($null -ne $verifiedRuntimeArtifact) {
    $runtimeReleaseId = [string]$verifiedRuntimeArtifact.ReleaseId
    $runtimeTreePath = Join-Path $workRoot 'runtime-complete-tree.json'
    $payloadArchiveDescriptor = Copy-ExactLockedFile `
        -Source $verifiedRuntimeArtifact.Archive `
        -Destination $runtimeArchive
    $payloadTreeDescriptor = Copy-ExactLockedFile `
        -Source $verifiedRuntimeArtifact.CompleteTree `
        -Destination $runtimeTreePath
    $runtimeSource = 'verified-source-runtime-artifact'
    $runtimeArtifactDescriptorSha256 =
        [string]$verifiedRuntimeArtifact.Descriptor.Sha256
} else {
    $runtimeTreeRoot = Join-Path $workRoot 'runtime-tree'
    New-Item -ItemType Directory -Path `
        (Join-Path $runtimeTreeRoot 'node_modules\@deepseek-ai\dsh\lib') `
        -Force | Out-Null
    [IO.File]::WriteAllBytes(
        (Join-Path $runtimeTreeRoot 'node.exe'),
        [Text.Encoding]::UTF8.GetBytes('CI-only placeholder Node runtime'))
    [IO.File]::WriteAllBytes(
        (Join-Path $runtimeTreeRoot 'node_modules\@deepseek-ai\dsh\lib\bin.js'),
        [Text.Encoding]::UTF8.GetBytes("console.log('CI-only dsh runtime');"))
    [IO.File]::WriteAllBytes(
        (Join-Path $runtimeTreeRoot 'node_modules\@deepseek-ai\dsh\package.json'),
        [Text.Encoding]::UTF8.GetBytes('{"name":"@deepseek-ai/dsh","version":"0.0.0-ci"}'))

    $runtimeFiles = @()
    foreach ($relative in @(
        'node.exe',
        'node_modules/@deepseek-ai/dsh/lib/bin.js',
        'node_modules/@deepseek-ai/dsh/package.json'
    )) {
        $nativeRelative = $relative.Replace('/', [IO.Path]::DirectorySeparatorChar)
        $descriptor = Get-FileDescriptor (Join-Path $runtimeTreeRoot $nativeRelative)
        $runtimeFiles += [ordered]@{
            path = $relative
            sizeBytes = $descriptor.sizeBytes
            sha256 = $descriptor.sha256
        }
    }
    $runtimeReleaseId = 'ci-personal-runtime-v1'
    $runtimeTreePath = Join-Path $runtimeTreeRoot '.ensou-complete-tree.v1.json'
    [ordered]@{
        schemaVersion = 1
        component = 'runtime'
        releaseId = $runtimeReleaseId
        files = $runtimeFiles
    } | ConvertTo-Json -Depth 5 -Compress | Set-Content `
        -LiteralPath $runtimeTreePath `
        -Encoding utf8NoBOM

    Add-Type -AssemblyName System.IO.Compression
    [IO.Compression.ZipFile]::CreateFromDirectory(
        $runtimeTreeRoot,
        $runtimeArchive,
        [IO.Compression.CompressionLevel]::Optimal,
        $false)
}

$now = [DateTimeOffset]::UtcNow
$releaseSetId = 'ci-personal-installer-v1'
$startupStubVersion = [string]$trust.startupStubVersion
$artifactOrigin = [string]$trust.artifactOrigin
$manifestOrigin = [string]$trust.manifestOrigin
$manifestPath = Join-Path $outputRoot 'release-set.v2.json'
$configPath = Join-Path $workRoot 'publisher-config.json'
$config = [ordered]@{
    schemaVersion = 1
    environment = 'production'
    channel = [string]$trust.channel
    releaseSetId = $releaseSetId
    provenance = [ordered]@{
        launcherRepositoryCommit = ('a' * 40)
        harnessSourceTag = 'dsh-ci-only'
        harnessSourceCommit = ('b' * 40)
    }
    generation = 1
    sequence = 1
    minAcceptedSequence = 0
    issuedAtUtc = $now.AddMinutes(-1).ToString('O', [Globalization.CultureInfo]::InvariantCulture)
    expiresAtUtc = $now.AddDays(7).ToString('O', [Globalization.CultureInfo]::InvariantCulture)
    maximumOfflineGraceSeconds = 604800
    startupStub = [ordered]@{
        minimumVersion = '1.2.0'
        maximumVersion = '1.9.9'
    }
    certifiedStartupStubVersion = $startupStubVersion
    revokedReleaseSetIds = @()
    artifactOrigin = $artifactOrigin
    signingKeyId = $keyId
    trustedKeys = @([ordered]@{
        keyId = $keyId
        x = $keyX
        y = $keyY
    })
    signingPrivateKeyPkcs8Path = $keyPath
    signingLedgerRoot = (Join-Path $workRoot 'signing-ledger')
    outputManifestPath = $manifestPath
    artifacts = @(
        [ordered]@{
            component = 'client-bundle'
            releaseId = $clientReleaseId
            uri = $artifactOrigin + 'artifacts/client-bundle.zip'
            sourcePath = $payloadClient
            completeTreeManifestPath = $clientTree
        },
        [ordered]@{
            component = 'runtime'
            releaseId = $runtimeReleaseId
            uri = $artifactOrigin + 'artifacts/runtime.zip'
            sourcePath = if ($null -ne $verifiedRuntimeArtifact) {
                $verifiedRuntimeArtifact.Archive.Path
            } else {
                $runtimeArchive
            }
            completeTreeManifestPath = if ($null -ne $verifiedRuntimeArtifact) {
                $verifiedRuntimeArtifact.CompleteTree.Path
            } else {
                $runtimeTreePath
            }
        }
    )
}
$config | ConvertTo-Json -Depth 10 | Set-Content `
    -LiteralPath $configPath `
    -Encoding utf8NoBOM

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$developmentPublisherProject = Join-Path $repositoryRoot `
    'tests\Ensou.Dsh.Personal.UpdateTests\Ensou.Dsh.Personal.UpdateTests.csproj'
$developmentPublisherOutput = @(dotnet run `
    --project $developmentPublisherProject `
    --configuration Release `
    --no-build `
    --no-restore `
    -- `
    --development-payload-publish `
    --config $configPath 2>&1)
$developmentPublisherExitCode = $LASTEXITCODE
$developmentPublisherPassed = @($developmentPublisherOutput | Where-Object {
    $_ -is [string] -and
        $_ -cmatch '^PERSONAL-DEVELOPMENT-PAYLOAD-PUBLISH-PASS [0-9a-f]{64}$'
}).Count -eq 1
if ($developmentPublisherExitCode -ne 0 -or -not $developmentPublisherPassed) {
    $developmentPublisherDetails =
        ($developmentPublisherOutput | Out-String).Trim()
    throw "Development Personal ReleasePublisher failed. $developmentPublisherDetails"
}

$expectedPayloadNames = @(
    'Ensou.Dsh.Bootstrapper.exe',
    'client-bundle.zip',
    'release-set.v2.json',
    'runtime.zip'
)
$actualPayloadNames = @(
    Get-ChildItem -LiteralPath $outputRoot -Force |
        ForEach-Object Name)
if (@(Compare-Object $expectedPayloadNames $actualPayloadNames -CaseSensitive).Count -ne 0) {
    throw 'Development Personal Installer payload is not the exact four-file closure.'
}

$descriptorPath = Join-Path $workRoot 'development-payload.json'
$runtimeArchiveDescriptor = Get-FileDescriptor $runtimeArchive
$runtimeCompleteTreeDescriptor = Get-FileDescriptor $runtimeTreePath
if ($null -ne $verifiedRuntimeArtifact) {
    if ($runtimeArchiveDescriptor.sizeBytes -ne
            $verifiedRuntimeArtifact.Archive.SizeBytes -or
        $runtimeArchiveDescriptor.sha256 -cne
            $verifiedRuntimeArtifact.Archive.Sha256 -or
        $runtimeCompleteTreeDescriptor.sizeBytes -ne
            $verifiedRuntimeArtifact.CompleteTree.SizeBytes -or
        $runtimeCompleteTreeDescriptor.sha256 -cne
            $verifiedRuntimeArtifact.CompleteTree.Sha256) {
        throw 'Development payload copies changed after exact locked admission.'
    }
    $publishedManifest = Get-Content -Raw -LiteralPath $manifestPath |
        ConvertFrom-Json -Depth 20
    $publishedRuntime = @($publishedManifest.artifacts | Where-Object {
        $_.component -ceq 'runtime'
    })
    if ($publishedRuntime.Count -ne 1 -or
        $publishedRuntime[0].releaseId -cne $verifiedRuntimeArtifact.ReleaseId -or
        [int64]$publishedRuntime[0].sizeBytes -ne
            $verifiedRuntimeArtifact.Archive.SizeBytes -or
        [string]$publishedRuntime[0].sha256 -cne
            $verifiedRuntimeArtifact.Archive.Sha256 -or
        [string]$publishedRuntime[0].completeTreeSha256 -cne
            $verifiedRuntimeArtifact.CompleteTree.Sha256) {
        throw 'Development release manifest differs from the locked runtime artifact.'
    }
}
[ordered]@{
    schemaVersion = 1
    nonDistributableDevelopment = $true
    runtimeSource = $runtimeSource
    runtimeArtifactTrustBoundary = 'trusted-local-development-build-account'
    runtimeArtifactAuthenticity = 'not-asserted'
    runtimeReleaseId = $runtimeReleaseId
    runtimePromotionEligible = if ($null -ne $verifiedRuntimeArtifact) {
        [bool]$verifiedRuntimeArtifact.PromotionEligible
    } else {
        $false
    }
    runtimeArtifactDescriptorSha256 = $runtimeArtifactDescriptorSha256
    runtimeArchiveSha256 = $runtimeArchiveDescriptor.sha256
    runtimeCompleteTreeSha256 = $runtimeCompleteTreeDescriptor.sha256
    payloadDirectory = $outputRoot
    releaseSetId = $releaseSetId
    manifestOrigin = $manifestOrigin
    artifactOrigin = $artifactOrigin
    keyId = $keyId
    keyX = $keyX
    keyY = $keyY
    startupStubVersion = $startupStubVersion
    developmentInstallDefault = 'refused'
    developmentInstallOverrideArgument =
        '--allow-unsigned-development-install'
} | ConvertTo-Json -Depth 4 | Set-Content `
    -LiteralPath $descriptorPath `
    -Encoding utf8NoBOM

Write-Output $descriptorPath
} finally {
    for ($index = $runtimeLeases.Count - 1; $index -ge 0; $index--) {
        $runtimeLeases[$index].Dispose()
    }
}
