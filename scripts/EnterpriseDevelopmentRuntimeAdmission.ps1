Set-StrictMode -Version Latest

if (-not ('EnsouDshEnterpriseDevelopmentRuntimeInput.NativeFileIdentity' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace EnsouDshEnterpriseDevelopmentRuntimeInput
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
                throw new InvalidDataException(
                    "Enterprise Development runtime input handle is invalid.");
            }
            if (!GetFileInformationByHandle(handle, out var information))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not inspect Enterprise Development runtime input identity.");
            }
            const uint directory = 0x10;
            const uint reparsePoint = 0x400;
            if (information.NumberOfLinks != 1
                || (information.FileAttributes & (directory | reparsePoint)) != 0)
            {
                throw new InvalidDataException(
                    "Enterprise Development runtime input must be one ordinary single-link file.");
            }
            return new ExactFileIdentity(
                information.VolumeSerialNumber,
                ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow);
        }
    }
}
'@
}

function Resolve-EnterpriseDevelopmentRuntimeOrdinaryFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path.StartsWith('\\', [StringComparison]::Ordinal) -or
        $Path.StartsWith('//', [StringComparison]::Ordinal)) {
        throw "Enterprise Development runtime input must be a local file: $Path"
    }
    $resolved = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0) {
        throw "Enterprise Development runtime input must be an ordinary non-empty file: $resolved"
    }
    for ($current = $item.Directory; $null -ne $current; $current = $current.Parent) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Enterprise Development runtime input crosses a filesystem link: $resolved"
        }
    }
    return $resolved
}

function Get-EnterpriseDevelopmentRuntimeStreamSha256 {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)

    if (-not $Stream.CanSeek) {
        throw 'Enterprise Development runtime hash input must be seekable.'
    }
    $Stream.Position = 0
    $sha256 = ([Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($Stream))).ToLowerInvariant()
    $Stream.Position = 0
    return $sha256
}

function Open-EnterpriseDevelopmentRuntimeLockedInput {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int64]$MaximumBytes,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[IDisposable]]$Leases
    )

    if (-not $IsWindows) {
        throw 'Enterprise Development runtime locked input admission requires Windows.'
    }
    $resolved = Resolve-EnterpriseDevelopmentRuntimeOrdinaryFile -Path $Path
    $stream = [IO.File]::Open(
        $resolved,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $identity = [EnsouDshEnterpriseDevelopmentRuntimeInput.NativeFileIdentity]::
            RequireOrdinarySingleLink($stream.SafeFileHandle)
        if ($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) {
            throw "Enterprise Development runtime input is empty or unbounded: $resolved"
        }
        $pathStream = [IO.File]::Open(
            (Resolve-EnterpriseDevelopmentRuntimeOrdinaryFile -Path $resolved),
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read)
        try {
            $pathIdentity = [EnsouDshEnterpriseDevelopmentRuntimeInput.NativeFileIdentity]::
                RequireOrdinarySingleLink($pathStream.SafeFileHandle)
            if ($pathIdentity.VolumeSerialNumber -ne $identity.VolumeSerialNumber -or
                $pathIdentity.FileIndex -ne $identity.FileIndex) {
                throw "Enterprise Development runtime path no longer names its locked input: $resolved"
            }
        }
        finally {
            $pathStream.Dispose()
        }
        $descriptor = [pscustomobject]@{
            Path = $resolved
            SizeBytes = [int64]$stream.Length
            Sha256 = Get-EnterpriseDevelopmentRuntimeStreamSha256 -Stream $stream
            Stream = $stream
            VolumeSerialNumber = [uint32]$identity.VolumeSerialNumber
            FileIndex = [uint64]$identity.FileIndex
        }
        $Leases.Add($stream)
        return $descriptor
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Read-EnterpriseDevelopmentRuntimeLockedBytes {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][int]$MaximumBytes
    )

    if ($Descriptor.SizeBytes -le 0 -or $Descriptor.SizeBytes -gt $MaximumBytes) {
        throw "Enterprise Development runtime input is empty or unbounded: $($Descriptor.Path)"
    }
    $Descriptor.Stream.Position = 0
    $bytes = [byte[]]::new([int]$Descriptor.SizeBytes)
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $read = $Descriptor.Stream.Read($bytes, $offset, $bytes.Length - $offset)
        if ($read -eq 0) {
            throw "Enterprise Development runtime input ended early: $($Descriptor.Path)"
        }
        $offset += $read
    }
    if ($Descriptor.Stream.ReadByte() -ne -1) {
        throw "Enterprise Development runtime input grew while reading: $($Descriptor.Path)"
    }
    $Descriptor.Stream.Position = 0
    return $bytes
}

function Assert-EnterpriseDevelopmentRuntimeNoDuplicateJsonMembers {
    param(
        [Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) {
                throw "$Label contains a duplicate JSON member: $($property.Name)"
            }
            Assert-EnterpriseDevelopmentRuntimeNoDuplicateJsonMembers `
                -Element $property.Value `
                -Label $Label
        }
    }
    elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) {
            Assert-EnterpriseDevelopmentRuntimeNoDuplicateJsonMembers `
                -Element $item `
                -Label $Label
        }
    }
}

function Get-EnterpriseDevelopmentRuntimeJsonProperty {
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

function Get-EnterpriseDevelopmentRuntimeJsonString {
    param(
        [Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Label,
        [int]$MaximumLength = 1024
    )

    $property = Get-EnterpriseDevelopmentRuntimeJsonProperty `
        -Element $Element `
        -Name $Name `
        -Label $Label
    if ($property.ValueKind -ne [Text.Json.JsonValueKind]::String) {
        throw "$Label $Name is not a string."
    }
    $value = $property.GetString()
    if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt $MaximumLength) {
        throw "$Label $Name is empty or unbounded."
    }
    return $value
}

function Assert-EnterpriseDevelopmentRuntimeExactJsonProperties {
    param(
        [Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
        [Parameter(Mandatory = $true)][string[]]$Names,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Element.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
        throw "$Label is not a JSON object."
    }
    $expected = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($name in $Names) {
        if (-not $expected.Add($name)) {
            throw "$Label exact-property contract is invalid."
        }
    }
    $actualCount = 0
    foreach ($property in $Element.EnumerateObject()) {
        $actualCount++
        if (-not $expected.Contains($property.Name)) {
            throw "$Label contains an unrecognized member: $($property.Name)"
        }
    }
    if ($actualCount -ne $expected.Count) {
        throw "$Label does not contain its exact required member set."
    }
}

function Get-EnterpriseDevelopmentRuntimeJsonBoolean {
    param(
        [Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $property = Get-EnterpriseDevelopmentRuntimeJsonProperty `
        -Element $Element `
        -Name $Name `
        -Label $Label
    if ($property.ValueKind -notin @(
            [Text.Json.JsonValueKind]::True,
            [Text.Json.JsonValueKind]::False)) {
        throw "$Label $Name is not a Boolean."
    }
    return $property.GetBoolean()
}

function Get-EnterpriseDevelopmentRuntimeJsonInt64 {
    param(
        [Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][int64]$Minimum,
        [Parameter(Mandatory = $true)][int64]$Maximum
    )

    $property = Get-EnterpriseDevelopmentRuntimeJsonProperty `
        -Element $Element `
        -Name $Name `
        -Label $Label
    $value = [int64]0
    if ($property.ValueKind -ne [Text.Json.JsonValueKind]::Number -or
        -not $property.TryGetInt64([ref]$value) -or
        $value -lt $Minimum -or $value -gt $Maximum) {
        throw "$Label $Name is not a bounded integer."
    }
    return $value
}

function Get-EnterpriseDevelopmentRuntimeJsonStringArray {
    param(
        [Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][int]$MinimumCount,
        [Parameter(Mandatory = $true)][int]$MaximumCount,
        [Parameter(Mandatory = $true)][int]$MaximumItemLength
    )

    $property = Get-EnterpriseDevelopmentRuntimeJsonProperty `
        -Element $Element `
        -Name $Name `
        -Label $Label
    if ($property.ValueKind -ne [Text.Json.JsonValueKind]::Array) {
        throw "$Label $Name is not an array."
    }
    $values = [Collections.Generic.List[string]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($item in $property.EnumerateArray()) {
        if ($item.ValueKind -ne [Text.Json.JsonValueKind]::String) {
            throw "$Label $Name contains a non-string value."
        }
        $value = $item.GetString()
        if ([string]::IsNullOrWhiteSpace($value) -or
            $value.Length -gt $MaximumItemLength -or
            -not $seen.Add($value)) {
            throw "$Label $Name contains an empty, unbounded, or duplicate value."
        }
        $values.Add($value)
    }
    if ($values.Count -lt $MinimumCount -or $values.Count -gt $MaximumCount) {
        throw "$Label $Name has an invalid item count."
    }
    return [string[]]$values
}

function ConvertTo-EnterpriseDevelopmentRuntimeUtcTicks {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Value -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?(?:Z|[+-][0-9]{2}:[0-9]{2})$') {
        throw "$Label is not a canonical bounded timestamp."
    }
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse(
            $Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None,
            [ref]$parsed)) {
        throw "$Label is not a valid timestamp."
    }
    return $parsed.UtcDateTime.Ticks
}

function ConvertFrom-EnterpriseDevelopmentRuntimeStrictJson {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Bytes.Length -ge 3 -and
        $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
        throw "$Label must be UTF-8 without a byte-order mark."
    }
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    try {
        return $utf8.GetString($Bytes)
    }
    catch {
        throw [IO.InvalidDataException]::new("$Label is not strict UTF-8.", $_.Exception)
    }
}

function Read-EnterpriseDevelopmentRuntimeZipEntryBytes {
    param(
        [Parameter(Mandatory = $true)][IO.Compression.ZipArchiveEntry]$Entry,
        [Parameter(Mandatory = $true)][int]$MaximumBytes,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Entry.Length -le 0 -or $Entry.Length -gt $MaximumBytes) {
        throw "$Label is empty or unbounded."
    }
    $input = $Entry.Open()
    try {
        $output = [IO.MemoryStream]::new([int]$Entry.Length)
        try {
            $input.CopyTo($output)
            if ($output.Length -ne $Entry.Length) {
                throw "$Label length changed while reading."
            }
            return $output.ToArray()
        }
        finally {
            $output.Dispose()
        }
    }
    finally {
        $input.Dispose()
    }
}

function Read-EnterpriseDevelopmentRuntimeSourceBuild {
    param(
        [Parameter(Mandatory = $true)]$ArchiveDescriptor,
        [Parameter(Mandatory = $true)]$Metadata,
        [Parameter(Mandatory = $true)][Text.Json.JsonElement]$MetadataRoot,
        [switch]$EnterpriseDirectLocal
    )

    $ArchiveDescriptor.Stream.Position = 0
    $archive = [IO.Compression.ZipArchive]::new(
        $ArchiveDescriptor.Stream,
        [IO.Compression.ZipArchiveMode]::Read,
        $true)
    try {
        $entries = @($archive.Entries | Where-Object {
            $_.FullName.Equals('source-build.json', [StringComparison]::OrdinalIgnoreCase)
        })
        if ($entries.Count -ne 1 -or
            $entries[0].FullName -cne 'source-build.json' -or
            $entries[0].Length -le 0 -or $entries[0].Length -gt 1MB) {
            throw 'Enterprise Development runtime ZIP must contain one exact bounded root source-build.json.'
        }
        $manifestEntries = @($archive.Entries | Where-Object {
            $_.FullName.Equals('runtime-files.sha256', [StringComparison]::OrdinalIgnoreCase)
        })
        if ($manifestEntries.Count -ne 1 -or
            $manifestEntries[0].FullName -cne 'runtime-files.sha256') {
            throw 'Enterprise Development runtime ZIP must contain one exact root runtime-files.sha256.'
        }
        $sourceBytes = Read-EnterpriseDevelopmentRuntimeZipEntryBytes `
            -Entry $entries[0] `
            -MaximumBytes (1MB) `
            -Label 'Enterprise Development runtime source-build.json'
        $hashManifestBytes = Read-EnterpriseDevelopmentRuntimeZipEntryBytes `
            -Entry $manifestEntries[0] `
            -MaximumBytes (32MB) `
            -Label 'Enterprise Development runtime runtime-files.sha256'
    }
    finally {
        $archive.Dispose()
        $ArchiveDescriptor.Stream.Position = 0
    }

    if (@($hashManifestBytes | Where-Object { $_ -gt 0x7F }).Count -ne 0) {
        throw 'Enterprise Development runtime runtime-files.sha256 is not ASCII.'
    }
    $sourceBuildSha256 = ([Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($sourceBytes))).ToLowerInvariant()
    $hashManifestText = [Text.Encoding]::ASCII.GetString($hashManifestBytes)
    $sourceBuildBindings = @($hashManifestText -split "`r?`n" | Where-Object {
        if ([string]::IsNullOrEmpty($_)) { return $false }
        $match = [Text.RegularExpressions.Regex]::Match(
            $_,
            '\A(?<sha256>[0-9a-f]{64})  (?<path>.+)\z',
            [Text.RegularExpressions.RegexOptions]::CultureInvariant)
        if (-not $match.Success) {
            throw 'Enterprise Development runtime runtime-files.sha256 contains a malformed line.'
        }
        return $match.Groups['path'].Value.Equals(
            'source-build.json',
            [StringComparison]::OrdinalIgnoreCase)
    })
    if ($sourceBuildBindings.Count -ne 1 -or
        $sourceBuildBindings[0] -cne "$sourceBuildSha256  source-build.json") {
        throw 'Enterprise Development runtime runtime-files.sha256 does not bind exact source-build.json bytes.'
    }

    $sourceJson = ConvertFrom-EnterpriseDevelopmentRuntimeStrictJson `
        -Bytes $sourceBytes `
        -Label 'Enterprise Development runtime source-build.json'
    $document = [Text.Json.JsonDocument]::Parse(
        [ReadOnlyMemory[byte]]::new($sourceBytes))
    try {
        $root = $document.RootElement
        Assert-EnterpriseDevelopmentRuntimeNoDuplicateJsonMembers `
            -Element $root `
            -Label 'Enterprise Development runtime source-build.json'
        $sourcePropertyNames = @(
            'schemaVersion', 'sourceBuilt', 'releaseId', 'promotionEligible',
            'artifactType',
            'sourceIdentity', 'sourceRepository', 'sourceTag', 'sourceCommit',
            'sourceTree', 'remoteTagVerified', 'tagSignatureVerified',
            'dshVersion', 'platform', 'baseLockfileSha256', 'lockfileSha256',
            'runtimeWebAuthProtocol',
            'managedPatch', 'managedPolicy', 'nodeVersion', 'nodeSha256',
            'pnpmVersion', 'npmVersion', 'buildPipeline', 'deploymentMode',
            'restoredWorkspacePeerCount', 'restoredWorkspacePeers',
            'normalizedSourceRegionCommentCount',
            'normalizedBinShimTargetCommentCount', 'runtimeClosurePackageCount',
            'runtimeClosureAgainstPinnedSourceAndLock', 'assembledRuntimeSmoke',
            'managedFocusedTests', 'managedWindowsExcludedFocusedTests',
            'managedRefusalSmoke', 'officialCheckoutUnchanged', 'builtAtUtc',
            'licensing')
        if ($EnterpriseDirectLocal) {
            $sourcePropertyNames += @(
                'runtimeProfile', 'managedUpdateProtocol', 'directLocalRuntimeSmoke')
        }
        Assert-EnterpriseDevelopmentRuntimeExactJsonProperties `
            -Element $root `
            -Label 'Enterprise Development runtime source-build.json' `
            -Names $sourcePropertyNames
        $schemaVersionProperty = Get-EnterpriseDevelopmentRuntimeJsonProperty `
            -Element $root `
            -Name 'schemaVersion' `
            -Label 'Enterprise Development runtime source-build.json'
        $schemaVersion = 0
        $sourceBuiltProperty = Get-EnterpriseDevelopmentRuntimeJsonProperty `
            -Element $root `
            -Name 'sourceBuilt' `
            -Label 'Enterprise Development runtime source-build.json'
        if ($schemaVersionProperty.ValueKind -ne [Text.Json.JsonValueKind]::Number -or
            -not $schemaVersionProperty.TryGetInt32([ref]$schemaVersion) -or
            $schemaVersion -ne $(if ($EnterpriseDirectLocal) { 4 } else { 3 }) -or
            $sourceBuiltProperty.ValueKind -notin @(
                [Text.Json.JsonValueKind]::True,
                [Text.Json.JsonValueKind]::False) -or
            -not $sourceBuiltProperty.GetBoolean()) {
            throw 'Enterprise Development runtime source-build.json identity flags are invalid.'
        }

        $promotionEligible = Get-EnterpriseDevelopmentRuntimeJsonBoolean `
            -Element $root `
            -Name 'promotionEligible' `
            -Label 'Enterprise Development runtime source-build.json'

        $sourceValues = [ordered]@{
            releaseId = Get-EnterpriseDevelopmentRuntimeJsonString -Element $root -Name 'releaseId' -Label 'Enterprise Development runtime source-build.json' -MaximumLength 128
            promotionEligible = $promotionEligible
            artifactType = Get-EnterpriseDevelopmentRuntimeJsonString -Element $root -Name 'artifactType' -Label 'Enterprise Development runtime source-build.json' -MaximumLength 128
            sourceIdentity = Get-EnterpriseDevelopmentRuntimeJsonString -Element $root -Name 'sourceIdentity' -Label 'Enterprise Development runtime source-build.json' -MaximumLength 128
            sourceRepository = Get-EnterpriseDevelopmentRuntimeJsonString -Element $root -Name 'sourceRepository' -Label 'Enterprise Development runtime source-build.json' -MaximumLength 512
            sourceTag = Get-EnterpriseDevelopmentRuntimeJsonString -Element $root -Name 'sourceTag' -Label 'Enterprise Development runtime source-build.json' -MaximumLength 128
            sourceCommit = Get-EnterpriseDevelopmentRuntimeJsonString -Element $root -Name 'sourceCommit' -Label 'Enterprise Development runtime source-build.json' -MaximumLength 40
            sourceTree = Get-EnterpriseDevelopmentRuntimeJsonString -Element $root -Name 'sourceTree' -Label 'Enterprise Development runtime source-build.json' -MaximumLength 40
            dshVersion = Get-EnterpriseDevelopmentRuntimeJsonString -Element $root -Name 'dshVersion' -Label 'Enterprise Development runtime source-build.json' -MaximumLength 128
            platform = Get-EnterpriseDevelopmentRuntimeJsonString -Element $root -Name 'platform' -Label 'Enterprise Development runtime source-build.json' -MaximumLength 64
            baseLockfileSha256 = Get-EnterpriseDevelopmentRuntimeJsonString -Element $root -Name 'baseLockfileSha256' -Label 'Enterprise Development runtime source-build.json' -MaximumLength 64
            lockfileSha256 = Get-EnterpriseDevelopmentRuntimeJsonString -Element $root -Name 'lockfileSha256' -Label 'Enterprise Development runtime source-build.json' -MaximumLength 64
            runtimeWebAuthProtocol = Get-EnterpriseDevelopmentRuntimeJsonString -Element $root -Name 'runtimeWebAuthProtocol' -Label 'Enterprise Development runtime source-build.json' -MaximumLength 64
            nodeVersion = Get-EnterpriseDevelopmentRuntimeJsonString -Element $root -Name 'nodeVersion' -Label 'Enterprise Development runtime source-build.json' -MaximumLength 64
            nodeSha256 = Get-EnterpriseDevelopmentRuntimeJsonString -Element $root -Name 'nodeSha256' -Label 'Enterprise Development runtime source-build.json' -MaximumLength 64
            pnpmVersion = Get-EnterpriseDevelopmentRuntimeJsonString -Element $root -Name 'pnpmVersion' -Label 'Enterprise Development runtime source-build.json' -MaximumLength 64
            npmVersion = Get-EnterpriseDevelopmentRuntimeJsonString -Element $root -Name 'npmVersion' -Label 'Enterprise Development runtime source-build.json' -MaximumLength 64
            builtAtUtc = Get-EnterpriseDevelopmentRuntimeJsonString -Element $root -Name 'builtAtUtc' -Label 'Enterprise Development runtime source-build.json' -MaximumLength 64
        }
        if ($EnterpriseDirectLocal) {
            $sourceValues['runtimeProfile'] = Get-EnterpriseDevelopmentRuntimeJsonString `
                -Element $root -Name 'runtimeProfile' `
                -Label 'Enterprise Development runtime source-build.json' -MaximumLength 64
            $sourceValues['managedUpdateProtocol'] = Get-EnterpriseDevelopmentRuntimeJsonString `
                -Element $root -Name 'managedUpdateProtocol' `
                -Label 'Enterprise Development runtime source-build.json' -MaximumLength 64
        }
        $sourceManagedPatch = Get-EnterpriseDevelopmentRuntimeJsonProperty `
            -Element $root `
            -Name 'managedPatch' `
            -Label 'Enterprise Development runtime source-build.json'
        $sourceManagedPolicy = Get-EnterpriseDevelopmentRuntimeJsonProperty `
            -Element $root `
            -Name 'managedPolicy' `
            -Label 'Enterprise Development runtime source-build.json'
        $metadataManagedPatch = Get-EnterpriseDevelopmentRuntimeJsonProperty `
            -Element $MetadataRoot `
            -Name 'managedPatch' `
            -Label 'Enterprise Development source-runtime metadata'
        $metadataManagedPolicy = Get-EnterpriseDevelopmentRuntimeJsonProperty `
            -Element $MetadataRoot `
            -Name 'managedPolicy' `
            -Label 'Enterprise Development source-runtime metadata'
        if (-not [Text.Json.JsonElement]::DeepEquals(
                $sourceManagedPatch,
                $metadataManagedPatch) -or
            -not [Text.Json.JsonElement]::DeepEquals(
                $sourceManagedPolicy,
                $metadataManagedPolicy)) {
            throw 'Enterprise Development runtime managed patch or policy provenance differs from external metadata.'
        }
        if ($EnterpriseDirectLocal) {
            $sourceDirectSmoke = Get-EnterpriseDevelopmentRuntimeJsonProperty `
                -Element $root -Name 'directLocalRuntimeSmoke' `
                -Label 'Enterprise Development runtime source-build.json'
            $metadataVerification = Get-EnterpriseDevelopmentRuntimeJsonProperty `
                -Element $MetadataRoot -Name 'verification' `
                -Label 'Enterprise Development source-runtime metadata'
            $metadataDirectSmoke = Get-EnterpriseDevelopmentRuntimeJsonProperty `
                -Element $metadataVerification -Name 'directLocalAssembledSmoke' `
                -Label 'Enterprise Development source-runtime metadata verification'
            if (-not [Text.Json.JsonElement]::DeepEquals(
                    $sourceDirectSmoke,
                    $metadataDirectSmoke)) {
                throw 'Enterprise Development direct-local source smoke differs from external metadata.'
            }
        }

        $remoteTagVerified = Get-EnterpriseDevelopmentRuntimeJsonBoolean `
            -Element $root -Name 'remoteTagVerified' `
            -Label 'Enterprise Development runtime source-build.json'
        $tagSignatureVerified = Get-EnterpriseDevelopmentRuntimeJsonBoolean `
            -Element $root -Name 'tagSignatureVerified' `
            -Label 'Enterprise Development runtime source-build.json'
        $buildPipeline = Get-EnterpriseDevelopmentRuntimeJsonString `
            -Element $root -Name 'buildPipeline' `
            -Label 'Enterprise Development runtime source-build.json' `
            -MaximumLength 128
        $deploymentMode = Get-EnterpriseDevelopmentRuntimeJsonString `
            -Element $root -Name 'deploymentMode' `
            -Label 'Enterprise Development runtime source-build.json' `
            -MaximumLength 128
        $restoredWorkspacePeerCount = Get-EnterpriseDevelopmentRuntimeJsonInt64 `
            -Element $root -Name 'restoredWorkspacePeerCount' `
            -Label 'Enterprise Development runtime source-build.json' `
            -Minimum 0 -Maximum 100000
        $restoredWorkspacePeers = @(Get-EnterpriseDevelopmentRuntimeJsonStringArray `
            -Element $root -Name 'restoredWorkspacePeers' `
            -Label 'Enterprise Development runtime source-build.json' `
            -MinimumCount 0 -MaximumCount 100000 -MaximumItemLength 256)
        $normalizedSourceRegionCommentCount = Get-EnterpriseDevelopmentRuntimeJsonInt64 `
            -Element $root -Name 'normalizedSourceRegionCommentCount' `
            -Label 'Enterprise Development runtime source-build.json' `
            -Minimum 0 -Maximum 1000000
        $normalizedBinShimTargetCommentCount = Get-EnterpriseDevelopmentRuntimeJsonInt64 `
            -Element $root -Name 'normalizedBinShimTargetCommentCount' `
            -Label 'Enterprise Development runtime source-build.json' `
            -Minimum 0 -Maximum 1000000
        $runtimeClosurePackageCount = Get-EnterpriseDevelopmentRuntimeJsonInt64 `
            -Element $root -Name 'runtimeClosurePackageCount' `
            -Label 'Enterprise Development runtime source-build.json' `
            -Minimum 1 -Maximum 100000
        $runtimeClosureAgainstPinnedSourceAndLock =
            Get-EnterpriseDevelopmentRuntimeJsonBoolean `
                -Element $root `
                -Name 'runtimeClosureAgainstPinnedSourceAndLock' `
                -Label 'Enterprise Development runtime source-build.json'
        $assembledRuntimeSmoke = Get-EnterpriseDevelopmentRuntimeJsonBoolean `
            -Element $root -Name 'assembledRuntimeSmoke' `
            -Label 'Enterprise Development runtime source-build.json'
        $managedFocusedTests = Get-EnterpriseDevelopmentRuntimeJsonBoolean `
            -Element $root -Name 'managedFocusedTests' `
            -Label 'Enterprise Development runtime source-build.json'
        $managedWindowsExcludedFocusedTests =
            Get-EnterpriseDevelopmentRuntimeJsonBoolean `
                -Element $root `
                -Name 'managedWindowsExcludedFocusedTests' `
                -Label 'Enterprise Development runtime source-build.json'
        $managedRefusalSmoke = Get-EnterpriseDevelopmentRuntimeJsonBoolean `
            -Element $root -Name 'managedRefusalSmoke' `
            -Label 'Enterprise Development runtime source-build.json'
        $officialCheckoutUnchanged = Get-EnterpriseDevelopmentRuntimeJsonBoolean `
            -Element $root -Name 'officialCheckoutUnchanged' `
            -Label 'Enterprise Development runtime source-build.json'
        $sourceLicensing = Get-EnterpriseDevelopmentRuntimeJsonProperty `
            -Element $root -Name 'licensing' `
            -Label 'Enterprise Development runtime source-build.json'
        Assert-EnterpriseDevelopmentRuntimeExactJsonProperties `
            -Element $sourceLicensing `
            -Names @('harnessLicense', 'includedFiles', 'organizationReviewRequired') `
            -Label 'Enterprise Development runtime source-build.json licensing'
        $sourceHarnessLicense = Get-EnterpriseDevelopmentRuntimeJsonString `
            -Element $sourceLicensing -Name 'harnessLicense' `
            -Label 'Enterprise Development runtime source-build.json licensing' `
            -MaximumLength 32
        $sourceIncludedFiles = @(Get-EnterpriseDevelopmentRuntimeJsonStringArray `
            -Element $sourceLicensing -Name 'includedFiles' `
            -Label 'Enterprise Development runtime source-build.json licensing' `
            -MinimumCount 3 -MaximumCount 3 -MaximumItemLength 128)
        $sourceOrganizationReviewRequired =
            Get-EnterpriseDevelopmentRuntimeJsonBoolean `
                -Element $sourceLicensing `
                -Name 'organizationReviewRequired' `
                -Label 'Enterprise Development runtime source-build.json licensing'

        $requiredIncludedFiles = @(
            'LICENSE',
            'THIRD_PARTY_NOTICES.md',
            'RUNTIME_DEPENDENCY_LICENSES.json')
        if ($buildPipeline -cne 'installation-owned-isolated-managed-source-v1' -or
            $restoredWorkspacePeerCount -ne $restoredWorkspacePeers.Count -or
            $normalizedSourceRegionCommentCount -lt 0 -or
            $normalizedBinShimTargetCommentCount -lt 0 -or
            @($requiredIncludedFiles | Where-Object {
                $sourceIncludedFiles -cnotcontains $_
            }).Count -ne 0) {
            throw 'Enterprise Development runtime source-build.json bounded build contract is invalid.'
        }
    }
    finally {
        $document.Dispose()
    }

    $sourceBuiltAtUtcTicks = ConvertTo-EnterpriseDevelopmentRuntimeUtcTicks `
        -Value ([string]$sourceValues.builtAtUtc) `
        -Label 'Enterprise Development runtime source-build.json builtAtUtc'
    $metadataBuiltAtUtc = Get-EnterpriseDevelopmentRuntimeJsonString `
        -Element $MetadataRoot `
        -Name 'builtAtUtc' `
        -Label 'Enterprise Development source-runtime metadata' `
        -MaximumLength 64
    $metadataBuiltAtUtcTicks = ConvertTo-EnterpriseDevelopmentRuntimeUtcTicks `
        -Value $metadataBuiltAtUtc `
        -Label 'Enterprise Development source-runtime metadata builtAtUtc'
    if ([string]$sourceValues.releaseId -cne [string]$Metadata.releaseId -or
        [bool]$sourceValues.promotionEligible -ne [bool]$Metadata.promotionEligible -or
        [string]$sourceValues.artifactType -cne [string]$Metadata.artifactType -or
        [string]$sourceValues.sourceIdentity -cne [string]$Metadata.sourceIdentity -or
        [string]$sourceValues.sourceRepository -cne [string]$Metadata.sourceRepository -or
        [string]$sourceValues.sourceTag -cne [string]$Metadata.sourceTag -or
        [string]$sourceValues.sourceCommit -cne [string]$Metadata.sourceCommit -or
        [string]$sourceValues.sourceTree -cne [string]$Metadata.sourceTree -or
        [string]$sourceValues.dshVersion -cne [string]$Metadata.dshVersion -or
        [string]$sourceValues.platform -cne [string]$Metadata.platform -or
        [string]$sourceValues.baseLockfileSha256 -cne [string]$Metadata.baseLockfileSha256 -or
        [string]$sourceValues.lockfileSha256 -cne [string]$Metadata.lockfileSha256 -or
        [string]$sourceValues.runtimeWebAuthProtocol -cne
            [string]$Metadata.runtimeWebAuthProtocol -or
        [string]$sourceValues.nodeVersion -cne [string]$Metadata.toolchain.nodeVersion -or
        [string]$sourceValues.nodeSha256 -cne [string]$Metadata.toolchain.nodeSha256 -or
        [string]$sourceValues.pnpmVersion -cne [string]$Metadata.toolchain.pnpmVersion -or
        [string]$sourceValues.npmVersion -cne [string]$Metadata.toolchain.npmVersion -or
        $remoteTagVerified -ne [bool]$Metadata.verification.remoteTagCommitMatch -or
        $tagSignatureVerified -ne [bool]$Metadata.verification.tagSignatureVerified -or
        $deploymentMode -cne [string]$Metadata.verification.deploymentMode -or
        $runtimeClosurePackageCount -ne [long]$Metadata.verification.runtimeClosurePackageCount -or
        $runtimeClosureAgainstPinnedSourceAndLock -ne
            [bool]$Metadata.verification.runtimeClosureAgainstPinnedSourceAndLock -or
        $assembledRuntimeSmoke -ne [bool]$Metadata.verification.extractedArtifactSmoke -or
        $managedFocusedTests -ne [bool]$Metadata.verification.managedFocusedTests -or
        $managedWindowsExcludedFocusedTests -ne
            [bool]$Metadata.verification.managedWindowsExcludedFocusedTests -or
        $managedRefusalSmoke -ne [bool]$Metadata.verification.managedRefusalSmoke -or
        $officialCheckoutUnchanged -ne
            [bool]$Metadata.verification.officialCheckoutUnchanged -or
        $sourceHarnessLicense -cne [string]$Metadata.licensing.harnessLicense -or
        $sourceOrganizationReviewRequired -ne
            [bool]$Metadata.licensing.organizationReviewRequired -or
        $sourceBuiltAtUtcTicks -ne $metadataBuiltAtUtcTicks) {
        throw 'Enterprise Development runtime source-build.json differs from external metadata provenance.'
    }
    if ($EnterpriseDirectLocal -and
        ([string]$sourceValues.runtimeProfile -cne 'enterprise-direct-local' -or
         [string]$sourceValues.managedUpdateProtocol -cne 'enterprise-direct-local-v1' -or
         [string]$sourceValues.runtimeProfile -cne [string]$Metadata.runtimeProfile -or
         [string]$sourceValues.managedUpdateProtocol -cne
            [string]$Metadata.managedUpdateProtocol)) {
        throw 'Enterprise Development direct-local runtime mode differs from external metadata.'
    }
    $sourceValues['sourceBuildSha256'] = $sourceBuildSha256
    return [pscustomobject]$sourceValues
}

function Read-EnterpriseDevelopmentRuntimeEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$ArchivePath,
        [Parameter(Mandatory = $true)][string]$MetadataPath,
        [Parameter(Mandatory = $true)][string]$MetadataSchemaPath,
        [Parameter(Mandatory = $true)][string]$ExpectedReleaseId,
        [Parameter(Mandatory = $true)][string]$ExpectedArchiveFileName,
        [Parameter(Mandatory = $true)][string]$ExpectedArchiveSha256,
        [switch]$AllowLocalLab,
        [switch]$EnterpriseDirectLocal,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[IDisposable]]$Leases
    )

    $expectedManagedRelease = $ExpectedReleaseId -cmatch
        '^managed-v[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]*$'
    $expectedLabRelease = $ExpectedReleaseId -cmatch
        '^lab-[A-Za-z0-9][A-Za-z0-9._-]{0,123}$'
    if ((-not $expectedManagedRelease -and
            (-not $AllowLocalLab -or -not $expectedLabRelease)) -or
        $ExpectedArchiveFileName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}\.zip$' -or
        [IO.Path]::GetFileName($ExpectedArchiveFileName) -cne $ExpectedArchiveFileName -or
        $ExpectedArchiveSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Enterprise Development expected runtime release/file/hash tuple is not canonical.'
    }
    $schema = Resolve-EnterpriseDevelopmentRuntimeOrdinaryFile -Path $MetadataSchemaPath
    $archive = Open-EnterpriseDevelopmentRuntimeLockedInput `
        -Path $ArchivePath `
        -MaximumBytes (8L * 1024 * 1024 * 1024) `
        -Leases $Leases
    $metadataInput = Open-EnterpriseDevelopmentRuntimeLockedInput `
        -Path $MetadataPath `
        -MaximumBytes (4MB) `
        -Leases $Leases
    $metadataBytes = Read-EnterpriseDevelopmentRuntimeLockedBytes `
        -Descriptor $metadataInput `
        -MaximumBytes (4MB)
    $metadataJson = ConvertFrom-EnterpriseDevelopmentRuntimeStrictJson `
        -Bytes $metadataBytes `
        -Label 'Enterprise Development source-runtime metadata'
    try {
        if (-not (Test-Json -Json $metadataJson -SchemaFile $schema -ErrorAction Stop)) {
            throw 'Enterprise Development source-runtime metadata did not satisfy its exact schema.'
        }
    }
    catch {
        throw [IO.InvalidDataException]::new(
            'Enterprise Development source-runtime metadata did not satisfy its exact schema.',
            $_.Exception)
    }
    $document = [Text.Json.JsonDocument]::Parse(
        [ReadOnlyMemory[byte]]::new($metadataBytes))
    try {
        Assert-EnterpriseDevelopmentRuntimeNoDuplicateJsonMembers `
            -Element $document.RootElement `
            -Label 'Enterprise Development source-runtime metadata'
        $metadataRoot = $document.RootElement.Clone()
    }
    finally {
        $document.Dispose()
    }
    $metadata = $metadataJson | ConvertFrom-Json -Depth 64
    if ([int]$metadata.schemaVersion -ne $(if ($EnterpriseDirectLocal) { 3 } else { 2 }) -or
        [string]$metadata.releaseId -cne $ExpectedReleaseId -or
        [string]$metadata.artifact.fileName -cne $ExpectedArchiveFileName -or
        [long]$metadata.artifact.sizeBytes -le 0 -or
        [long]$metadata.artifact.sizeBytes -gt 8L * 1024 * 1024 * 1024 -or
        [string]$metadata.artifact.sha256 -cne $ExpectedArchiveSha256 -or
        [IO.Path]::GetFileName($archive.Path) -cne $ExpectedArchiveFileName -or
        $archive.SizeBytes -ne [long]$metadata.artifact.sizeBytes -or
        $archive.Sha256 -cne [string]$metadata.artifact.sha256) {
        throw 'Enterprise Development runtime archive, metadata, and explicit expected tuple differ.'
    }
    $expectedArtifactType = if ($EnterpriseDirectLocal) {
        'ensou-dsh-enterprise-direct-local-source-runtime'
    } else {
        'ensou-dsh-enterprise-managed-source-runtime'
    }
    if ([string]$metadata.artifactType -cne $expectedArtifactType -or
        ($EnterpriseDirectLocal -and
            ([string]$metadata.runtimeProfile -cne 'enterprise-direct-local' -or
             [string]$metadata.managedUpdateProtocol -cne 'enterprise-direct-local-v1'))) {
        throw 'Enterprise Development runtime metadata is for the wrong selected runtime mode.'
    }
    if (-not [bool]$metadata.promotionEligible -and -not $AllowLocalLab) {
        throw 'Enterprise Development local Lab runtime requires explicit -AllowLocalLab admission.'
    }
    $sourceBuild = Read-EnterpriseDevelopmentRuntimeSourceBuild `
        -ArchiveDescriptor $archive `
        -Metadata $metadata `
        -MetadataRoot $metadataRoot `
        -EnterpriseDirectLocal:$EnterpriseDirectLocal
    return [pscustomobject]@{
        ReleaseId = [string]$metadata.releaseId
        PromotionEligible = [bool]$metadata.promotionEligible
        ArchiveFileName = [string]$metadata.artifact.fileName
        ArchiveSizeBytes = [int64]$archive.SizeBytes
        ArchiveSha256 = [string]$archive.Sha256
        MetadataSizeBytes = [int64]$metadataInput.SizeBytes
        MetadataSha256 = [string]$metadataInput.Sha256
        SourceTag = [string]$sourceBuild.sourceTag
        SourceCommit = [string]$sourceBuild.sourceCommit
        SourceBuildSha256 = [string]$sourceBuild.sourceBuildSha256
        RuntimeMode = if ($EnterpriseDirectLocal) { 'enterprise-direct-local' } else { 'enterprise-managed' }
        Archive = $archive
        Metadata = $metadataInput
    }
}

function Assert-EnterpriseDevelopmentRuntimeLockedInputUnchanged {
    param([Parameter(Mandatory = $true)]$Descriptor)

    $currentIdentity = [EnsouDshEnterpriseDevelopmentRuntimeInput.NativeFileIdentity]::
        RequireOrdinarySingleLink($Descriptor.Stream.SafeFileHandle)
    if ($currentIdentity.VolumeSerialNumber -ne $Descriptor.VolumeSerialNumber -or
        $currentIdentity.FileIndex -ne $Descriptor.FileIndex -or
        $Descriptor.Stream.Length -ne $Descriptor.SizeBytes -or
        (Get-EnterpriseDevelopmentRuntimeStreamSha256 -Stream $Descriptor.Stream) -cne
            $Descriptor.Sha256) {
        throw "Locked Enterprise Development runtime input changed: $($Descriptor.Path)"
    }
    $pathStream = [IO.File]::Open(
        (Resolve-EnterpriseDevelopmentRuntimeOrdinaryFile -Path $Descriptor.Path),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $pathIdentity = [EnsouDshEnterpriseDevelopmentRuntimeInput.NativeFileIdentity]::
            RequireOrdinarySingleLink($pathStream.SafeFileHandle)
        if ($pathIdentity.VolumeSerialNumber -ne $Descriptor.VolumeSerialNumber -or
            $pathIdentity.FileIndex -ne $Descriptor.FileIndex -or
            $pathStream.Length -ne $Descriptor.SizeBytes -or
            (Get-EnterpriseDevelopmentRuntimeStreamSha256 -Stream $pathStream) -cne
                $Descriptor.Sha256) {
            throw "Enterprise Development runtime path no longer names its locked input: $($Descriptor.Path)"
        }
    }
    finally {
        $pathStream.Dispose()
    }
}

function Assert-EnterpriseDevelopmentRuntimeEvidenceUnchanged {
    param([Parameter(Mandatory = $true)]$Evidence)

    Assert-EnterpriseDevelopmentRuntimeLockedInputUnchanged -Descriptor $Evidence.Archive
    Assert-EnterpriseDevelopmentRuntimeLockedInputUnchanged -Descriptor $Evidence.Metadata
}

function Open-EnterpriseDevelopmentRuntimePayloadCopy {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int64]$ExpectedSizeBytes,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[IDisposable]]$Leases
    )

    $copy = Open-EnterpriseDevelopmentRuntimeLockedInput `
        -Path $Path `
        -MaximumBytes (8L * 1024 * 1024 * 1024) `
        -Leases $Leases
    if ($copy.SizeBytes -ne $ExpectedSizeBytes -or $copy.Sha256 -cne $ExpectedSha256) {
        throw 'Enterprise Development payload runtime differs from locked admitted archive bytes.'
    }
    return $copy
}

function Get-EnterpriseDevelopmentRuntimeCompatibilityIds {
    param(
        [Parameter(Mandatory = $true)][Text.Json.JsonElement]$Compatibility,
        [Parameter(Mandatory = $true)][string]$Label,
        [string]$PropertyName = 'runtimeReleaseIds'
    )

    $property = Get-EnterpriseDevelopmentRuntimeJsonProperty `
        -Element $Compatibility `
        -Name $PropertyName `
        -Label $Label
    if ($property.ValueKind -ne [Text.Json.JsonValueKind]::Array) {
        throw "$Label $PropertyName is not an array."
    }
    $ids = @($property.EnumerateArray() | ForEach-Object {
        if ($_.ValueKind -ne [Text.Json.JsonValueKind]::String) {
            throw "$Label $PropertyName contains a non-string value."
        }
        $_.GetString()
    })
    if ($ids.Count -le 0 -or $ids.Count -gt 64 -or
        @($ids | Where-Object {
            $_ -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$'
        }).Count -ne 0 -or
        @($ids | Select-Object -Unique).Count -ne $ids.Count) {
        throw "$Label $PropertyName is invalid."
    }
    return [string[]]$ids
}

function Assert-EnterpriseDevelopmentPluginRuntimeCompatibility {
    param(
        [Parameter(Mandatory = $true)][string[]]$MetadataLauncherReleaseIds,
        [Parameter(Mandatory = $true)][string[]]$MetadataRuntimeReleaseIds,
        [Parameter(Mandatory = $true)][byte[]]$PolicyBytes,
        [Parameter(Mandatory = $true)][string]$ExpectedRuntimeReleaseId,
        [Parameter(Mandatory = $true)][string]$ExpectedPolicyId,
        [Parameter(Mandatory = $true)][int64]$ExpectedGeneration,
        [Parameter(Mandatory = $true)][bool]$ExpectedCritical,
        [Parameter(Mandatory = $true)][bool]$ExpectedRevoked
    )

    if ($ExpectedRuntimeReleaseId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$' -or
        $ExpectedPolicyId -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or
        $ExpectedGeneration -le 0 -or
        $MetadataLauncherReleaseIds.Count -le 0 -or
        $MetadataLauncherReleaseIds.Count -gt 64 -or
        $MetadataRuntimeReleaseIds.Count -le 0 -or
        $MetadataRuntimeReleaseIds.Count -gt 64 -or
        $MetadataRuntimeReleaseIds -cnotcontains $ExpectedRuntimeReleaseId) {
        throw 'Plugin artifact metadata is incompatible with the admitted runtime releaseId.'
    }
    $policyJson = ConvertFrom-EnterpriseDevelopmentRuntimeStrictJson `
        -Bytes $PolicyBytes `
        -Label 'Managed plugin-policy.json'
    $document = [Text.Json.JsonDocument]::Parse(
        [ReadOnlyMemory[byte]]::new($PolicyBytes))
    try {
        Assert-EnterpriseDevelopmentRuntimeNoDuplicateJsonMembers `
            -Element $document.RootElement `
            -Label 'Managed plugin-policy.json'
        $schemaVersion = Get-EnterpriseDevelopmentRuntimeJsonInt64 `
            -Element $document.RootElement -Name 'schemaVersion' `
            -Label 'Managed plugin-policy.json' -Minimum 1 -Maximum 1
        $policyId = Get-EnterpriseDevelopmentRuntimeJsonString `
            -Element $document.RootElement -Name 'policyId' `
            -Label 'Managed plugin-policy.json' -MaximumLength 36
        $generation = Get-EnterpriseDevelopmentRuntimeJsonInt64 `
            -Element $document.RootElement -Name 'generation' `
            -Label 'Managed plugin-policy.json' -Minimum 1 -Maximum ([int64]::MaxValue)
        $critical = Get-EnterpriseDevelopmentRuntimeJsonBoolean `
            -Element $document.RootElement -Name 'critical' `
            -Label 'Managed plugin-policy.json'
        $revoked = Get-EnterpriseDevelopmentRuntimeJsonBoolean `
            -Element $document.RootElement -Name 'revoked' `
            -Label 'Managed plugin-policy.json'
        $compatibility = Get-EnterpriseDevelopmentRuntimeJsonProperty `
            -Element $document.RootElement `
            -Name 'compatibility' `
            -Label 'Managed plugin-policy.json'
        Assert-EnterpriseDevelopmentRuntimeExactJsonProperties `
            -Element $compatibility `
            -Names @('launcherReleaseIds', 'runtimeReleaseIds') `
            -Label 'Managed plugin-policy.json compatibility'
        $policyLauncherReleaseIds = @(Get-EnterpriseDevelopmentRuntimeCompatibilityIds `
            -Compatibility $compatibility `
            -PropertyName 'launcherReleaseIds' `
            -Label 'Managed plugin-policy.json compatibility')
        $policyRuntimeReleaseIds = @(Get-EnterpriseDevelopmentRuntimeCompatibilityIds `
            -Compatibility $compatibility `
            -Label 'Managed plugin-policy.json compatibility')
    }
    finally {
        $document.Dispose()
    }
    if ($schemaVersion -ne 1 -or
        $policyId -cne $ExpectedPolicyId -or
        $generation -ne $ExpectedGeneration -or
        $critical -ne $ExpectedCritical -or
        $revoked -ne $ExpectedRevoked -or
        [string]::Join("`n", $policyLauncherReleaseIds) -cne
            [string]::Join("`n", $MetadataLauncherReleaseIds) -or
        $policyRuntimeReleaseIds -cnotcontains $ExpectedRuntimeReleaseId -or
        [string]::Join("`n", $policyRuntimeReleaseIds) -cne
            [string]::Join("`n", $MetadataRuntimeReleaseIds)) {
        throw 'Plugin artifact metadata and ZIP policy compatibility do not bind the same admitted runtime releaseId.'
    }
}
