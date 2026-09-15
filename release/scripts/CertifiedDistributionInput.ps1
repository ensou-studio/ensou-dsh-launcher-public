#requires -Version 7.2

Set-StrictMode -Version Latest

if (-not ('EnsouDshCertifiedDistributionInput.NativeFileIdentity' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace EnsouDshCertifiedDistributionInput
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

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        public static ExactFileIdentity RequireOrdinarySingleLink(SafeFileHandle handle)
        {
            if (handle == null || handle.IsInvalid || handle.IsClosed)
            {
                throw new InvalidDataException("Certified distribution input handle is invalid.");
            }
            if (!GetFileInformationByHandle(handle, out var information))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not inspect certified distribution input identity.");
            }
            const uint directory = 0x10;
            const uint reparsePoint = 0x400;
            if (information.NumberOfLinks != 1
                || (information.FileAttributes & (directory | reparsePoint)) != 0)
            {
                throw new InvalidDataException(
                    "Certified distribution input must be one ordinary single-link file.");
            }
            return new ExactFileIdentity(
                information.VolumeSerialNumber,
                ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow);
        }

        public static ExactFileIdentity RequireOrdinaryDirectory(SafeFileHandle handle)
        {
            if (handle == null || handle.IsInvalid || handle.IsClosed)
            {
                throw new InvalidDataException("Certified distribution directory handle is invalid.");
            }
            if (!GetFileInformationByHandle(handle, out var information))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not inspect certified distribution directory identity.");
            }
            const uint directory = 0x10;
            const uint reparsePoint = 0x400;
            if ((information.FileAttributes & directory) == 0
                || (information.FileAttributes & reparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Certified distribution directory must be ordinary and not a reparse point.");
            }
            return new ExactFileIdentity(
                information.VolumeSerialNumber,
                ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow);
        }

        public static SafeFileHandle OpenDirectoryWithoutDeleteSharing(string path)
        {
            const uint fileReadAttributes = 0x80;
            const uint shareRead = 0x1;
            const uint shareWrite = 0x2;
            const uint openExisting = 3;
            const uint openReparsePoint = 0x00200000;
            const uint backupSemantics = 0x02000000;
            var handle = CreateFileW(
                path,
                fileReadAttributes,
                shareRead | shareWrite,
                IntPtr.Zero,
                openExisting,
                openReparsePoint | backupSemantics,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(
                    error,
                    "Could not lock certified distribution directory against rename or deletion.");
            }
            try
            {
                RequireOrdinaryDirectory(handle);
                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }
    }
}
'@
}

function Assert-CertifiedDistributionOrdinaryDirectoryChain {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $resolved = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if (-not $item.PSIsContainer) {
        throw "$Label must be an existing directory."
    }
    for ($current = $item; $null -ne $current; $current = $current.Parent) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label crosses a filesystem link: $resolved"
        }
    }
    return $resolved
}

function Open-CertifiedDistributionLockedInput {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][int64]$MaximumBytes,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[IDisposable]]$Leases
    )

    if (-not $IsWindows) {
        throw 'Certified distribution admission requires Windows.'
    }
    if ([string]::IsNullOrWhiteSpace($Path) -or
        -not [IO.Path]::IsPathFullyQualified($Path) -or
        $Path.StartsWith('\\', [StringComparison]::Ordinal) -or
        $Path.StartsWith('//', [StringComparison]::Ordinal)) {
        throw "$Label must be an absolute local file."
    }
    $resolved = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or
        $item.Length -gt $MaximumBytes) {
        throw "$Label must be one ordinary, non-empty, bounded file."
    }
    [void](Assert-CertifiedDistributionOrdinaryDirectoryChain `
        -Path $item.Directory.FullName `
        -Label "$Label parent")

    $stream = [IO.File]::Open(
        $resolved,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $identity = [EnsouDshCertifiedDistributionInput.NativeFileIdentity]::
            RequireOrdinarySingleLink($stream.SafeFileHandle)
        if ($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) {
            throw "$Label changed to an empty or unbounded file."
        }
        $pathStream = [IO.File]::Open(
            $resolved,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read)
        try {
            $pathIdentity = [EnsouDshCertifiedDistributionInput.NativeFileIdentity]::
                RequireOrdinarySingleLink($pathStream.SafeFileHandle)
            if ($identity.VolumeSerialNumber -ne $pathIdentity.VolumeSerialNumber -or
                $identity.FileIndex -ne $pathIdentity.FileIndex) {
                throw "$Label path no longer names its locked file."
            }
        }
        finally {
            $pathStream.Dispose()
        }
        $descriptor = [pscustomobject]@{
            Label = $Label
            Path = $resolved
            FileName = $item.Name
            SizeBytes = [int64]$stream.Length
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

function Open-CertifiedDistributionLockedDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[IDisposable]]$Leases
    )

    if (-not $IsWindows -or
        [string]::IsNullOrWhiteSpace($Path) -or
        -not [IO.Path]::IsPathFullyQualified($Path) -or
        $Path.StartsWith('\\', [StringComparison]::Ordinal) -or
        $Path.StartsWith('//', [StringComparison]::Ordinal)) {
        throw "$Label must be an absolute local Windows directory."
    }
    $resolved = Assert-CertifiedDistributionOrdinaryDirectoryChain `
        -Path $Path `
        -Label $Label
    $chainPaths = [Collections.Generic.List[string]]::new()
    for ($item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop;
        $null -ne $item;
        $item = $item.Parent) {
        $chainPaths.Add($item.FullName)
    }
    $chainPaths.Reverse()
    $opened = [Collections.Generic.List[object]]::new()
    try {
        foreach ($chainPath in $chainPaths) {
            try {
                $handle = [EnsouDshCertifiedDistributionInput.NativeFileIdentity]::
                    OpenDirectoryWithoutDeleteSharing($chainPath)
            }
            catch {
                throw [IO.IOException]::new(
                    "Could not lock certified distribution directory chain member: $chainPath",
                    $_.Exception)
            }
            $identity = [EnsouDshCertifiedDistributionInput.NativeFileIdentity]::
                RequireOrdinaryDirectory($handle)
            $opened.Add([pscustomobject]@{
                Label = "$Label chain member"
                Path = [IO.Path]::GetFullPath($chainPath)
                Handle = $handle
                VolumeSerialNumber = [uint32]$identity.VolumeSerialNumber
                FileIndex = [uint64]$identity.FileIndex
            })
        }
        [void](Assert-CertifiedDistributionOrdinaryDirectoryChain `
            -Path $resolved `
            -Label $Label)
        foreach ($entry in $opened) {
            $Leases.Add($entry.Handle)
        }
        $leaf = $opened[$opened.Count - 1]
        $leaf.Label = $Label
        $leaf | Add-Member -NotePropertyName Chain -NotePropertyValue @($opened)
        return $leaf
    }
    catch {
        for ($index = $opened.Count - 1; $index -ge 0; $index--) {
            $opened[$index].Handle.Dispose()
        }
        throw
    }
}

function Get-CertifiedDistributionStreamSha256 {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)

    if (-not $Stream.CanSeek) {
        throw 'Certified distribution hash input must be seekable.'
    }
    $Stream.Position = 0
    $value = ([Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($Stream))).ToLowerInvariant()
    $Stream.Position = 0
    return $value
}

function Read-CertifiedDistributionLockedBytes {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][int]$MaximumBytes
    )

    if ($Descriptor.SizeBytes -le 0 -or $Descriptor.SizeBytes -gt $MaximumBytes) {
        throw "$($Descriptor.Label) is empty or exceeds its in-memory bound."
    }
    $Descriptor.Stream.Position = 0
    $bytes = [byte[]]::new([int]$Descriptor.SizeBytes)
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $read = $Descriptor.Stream.Read($bytes, $offset, $bytes.Length - $offset)
        if ($read -eq 0) {
            throw "$($Descriptor.Label) ended early while reading locked bytes."
        }
        $offset += $read
    }
    if ($Descriptor.Stream.ReadByte() -ne -1) {
        throw "$($Descriptor.Label) grew while reading locked bytes."
    }
    $Descriptor.Stream.Position = 0
    Write-Output -NoEnumerate $bytes
}

function Assert-CertifiedDistributionLockedInputUnchanged {
    param([Parameter(Mandatory = $true)]$Descriptor)

    $identity = [EnsouDshCertifiedDistributionInput.NativeFileIdentity]::
        RequireOrdinarySingleLink($Descriptor.Stream.SafeFileHandle)
    if ($identity.VolumeSerialNumber -ne $Descriptor.VolumeSerialNumber -or
        $identity.FileIndex -ne $Descriptor.FileIndex -or
        $Descriptor.Stream.Length -ne $Descriptor.SizeBytes) {
        throw "$($Descriptor.Label) identity changed while locked."
    }
}

function Assert-CertifiedDistributionLockedPathStillNamesInput {
    param([Parameter(Mandatory = $true)]$Descriptor)

    [void](Assert-CertifiedDistributionOrdinaryDirectoryChain `
        -Path ([IO.Path]::GetDirectoryName($Descriptor.Path)) `
        -Label "$($Descriptor.Label) parent")
    $pathStream = [IO.File]::Open(
        $Descriptor.Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite)
    try {
        $pathIdentity = [EnsouDshCertifiedDistributionInput.NativeFileIdentity]::
            RequireOrdinarySingleLink($pathStream.SafeFileHandle)
        if ($pathIdentity.VolumeSerialNumber -ne $Descriptor.VolumeSerialNumber -or
            $pathIdentity.FileIndex -ne $Descriptor.FileIndex) {
            throw "$($Descriptor.Label) path no longer names its locked file."
        }
    }
    finally {
        $pathStream.Dispose()
    }
}

function Assert-CertifiedDistributionLockedDirectoryUnchanged {
    param([Parameter(Mandatory = $true)]$Descriptor)

    foreach ($entry in $Descriptor.Chain) {
        $identity = [EnsouDshCertifiedDistributionInput.NativeFileIdentity]::
            RequireOrdinaryDirectory($entry.Handle)
        if ($identity.VolumeSerialNumber -ne $entry.VolumeSerialNumber -or
            $identity.FileIndex -ne $entry.FileIndex) {
            throw "$($entry.Label) identity changed while locked."
        }
        $pathHandle = [EnsouDshCertifiedDistributionInput.NativeFileIdentity]::
            OpenDirectoryWithoutDeleteSharing($entry.Path)
        try {
            $pathIdentity = [EnsouDshCertifiedDistributionInput.NativeFileIdentity]::
                RequireOrdinaryDirectory($pathHandle)
            if ($pathIdentity.VolumeSerialNumber -ne $entry.VolumeSerialNumber -or
                $pathIdentity.FileIndex -ne $entry.FileIndex) {
                throw "$($entry.Label) path no longer names its locked directory."
            }
        }
        finally {
            $pathHandle.Dispose()
        }
    }
    [void](Assert-CertifiedDistributionOrdinaryDirectoryChain `
        -Path $Descriptor.Path `
        -Label $Descriptor.Label)
}

function Copy-CertifiedDistributionLockedSnapshot {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)]$DirectoryDescriptor,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[IDisposable]]$Leases
    )

    $resolved = [IO.Path]::GetFullPath($Destination)
    $resolvedParent = [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($resolved))
    if ($resolvedParent -cne [IO.Path]::GetFullPath($DirectoryDescriptor.Path)) {
        throw 'Certified distribution snapshot must be a direct child of its locked directory.'
    }
    Assert-CertifiedDistributionLockedDirectoryUnchanged `
        -Descriptor $DirectoryDescriptor

    $output = $null
    $continuityGuard = $null
    $lockedSnapshot = $null
    try {
        $output = [IO.File]::Open(
            $resolved,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::Read)
        $identity = [EnsouDshCertifiedDistributionInput.NativeFileIdentity]::
            RequireOrdinarySingleLink($output.SafeFileHandle)
        $Descriptor.Stream.Position = 0
        $Descriptor.Stream.CopyTo($output)
        $output.Flush($true)
        if ($output.Length -ne $Descriptor.SizeBytes) {
            throw "$($Descriptor.Label) changed length while entering its protected snapshot."
        }
        $snapshotSha256 = Get-CertifiedDistributionStreamSha256 -Stream $output
        $sourceSha256 = Get-CertifiedDistributionStreamSha256 `
            -Stream $Descriptor.Stream
        if ($snapshotSha256 -cne $sourceSha256) {
            throw "$($Descriptor.Label) snapshot differs from its locked source."
        }

        # Transfer from the writer to a deny-write/delete read lease without
        # ever leaving the snapshot without an open, no-delete-sharing handle.
        $continuityGuard = [IO.File]::Open(
            $resolved,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::ReadWrite)
        $output.Dispose()
        $output = $null
        $lockedSnapshot = [IO.File]::Open(
            $resolved,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read)
        $continuityGuard.Dispose()
        $continuityGuard = $null

        $lockedIdentity = [EnsouDshCertifiedDistributionInput.NativeFileIdentity]::
            RequireOrdinarySingleLink($lockedSnapshot.SafeFileHandle)
        $lockedSha256 = Get-CertifiedDistributionStreamSha256 `
            -Stream $lockedSnapshot
        if ($lockedIdentity.VolumeSerialNumber -ne $identity.VolumeSerialNumber -or
            $lockedIdentity.FileIndex -ne $identity.FileIndex -or
            $lockedSnapshot.Length -ne $Descriptor.SizeBytes -or
            $lockedSha256 -cne $snapshotSha256) {
            throw "$($Descriptor.Label) protected snapshot lost exact-byte continuity."
        }
        Assert-CertifiedDistributionLockedDirectoryUnchanged `
            -Descriptor $DirectoryDescriptor
        $snapshot = [pscustomobject]@{
            Label = "$($Descriptor.Label) protected snapshot"
            Path = $resolved
            FileName = [IO.Path]::GetFileName($resolved)
            SizeBytes = [int64]$lockedSnapshot.Length
            Sha256 = $lockedSha256
            Stream = $lockedSnapshot
            VolumeSerialNumber = [uint32]$lockedIdentity.VolumeSerialNumber
            FileIndex = [uint64]$lockedIdentity.FileIndex
        }
        $Leases.Add($lockedSnapshot)
        $lockedSnapshot = $null
        return $snapshot
    }
    catch {
        if ($null -ne $lockedSnapshot) {
            $lockedSnapshot.Dispose()
        }
        if ($null -ne $continuityGuard) {
            $continuityGuard.Dispose()
        }
        if ($null -ne $output) {
            $output.Dispose()
        }
        throw
    }
}

function Assert-CertifiedDistributionNoDuplicateJsonMembers {
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
            Assert-CertifiedDistributionNoDuplicateJsonMembers `
                -Element $property.Value `
                -Label $Label
        }
    }
    elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) {
            Assert-CertifiedDistributionNoDuplicateJsonMembers `
                -Element $item `
                -Label $Label
        }
    }
}

function Assert-CertifiedDistributionStrictJson {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $document = [Text.Json.JsonDocument]::Parse([ReadOnlyMemory[byte]]::new($Bytes))
    try {
        Assert-CertifiedDistributionNoDuplicateJsonMembers `
            -Element $document.RootElement `
            -Label $Label
    }
    finally {
        $document.Dispose()
    }
}

function ConvertFrom-CertifiedDistributionBase64Url {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][int]$ExpectedBytes,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Value -cnotmatch '^[A-Za-z0-9_-]+$') {
        throw "$Label is not unpadded Base64URL."
    }
    $base64 = $Value.Replace('-', '+').Replace('_', '/')
    switch ($base64.Length % 4) {
        0 { }
        2 { $base64 += '==' }
        3 { $base64 += '=' }
        default { throw "$Label has an invalid Base64URL length." }
    }
    try {
        $bytes = [Convert]::FromBase64String($base64)
    }
    catch {
        throw [IO.InvalidDataException]::new("$Label is invalid Base64URL.", $_.Exception)
    }
    if ($bytes.Length -ne $ExpectedBytes) {
        throw "$Label must decode to exactly $ExpectedBytes bytes."
    }
    $canonical = [Convert]::ToBase64String($bytes).
        TrimEnd('=').Replace('+', '-').Replace('/', '_')
    if ($Value -cne $canonical) {
        throw "$Label is not canonical unpadded Base64URL."
    }
    Write-Output -NoEnumerate $bytes
}

function New-CertifiedDistributionP256Verifier {
    param(
        [Parameter(Mandatory = $true)][string]$X,
        [Parameter(Mandatory = $true)][string]$Y
    )

    $xBytes = ConvertFrom-CertifiedDistributionBase64Url `
        -Value $X -ExpectedBytes 32 -Label 'Receipt authentication key X'
    $yBytes = ConvertFrom-CertifiedDistributionBase64Url `
        -Value $Y -ExpectedBytes 32 -Label 'Receipt authentication key Y'
    $parameters = [Security.Cryptography.ECParameters]::new()
    $parameters.Curve = [Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $point = [Security.Cryptography.ECPoint]::new()
    $point.X = $xBytes
    $point.Y = $yBytes
    $parameters.Q = $point
    $verifier = [Security.Cryptography.ECDsa]::Create()
    try {
        $verifier.ImportParameters($parameters)
        return $verifier
    }
    catch {
        $verifier.Dispose()
        throw [IO.InvalidDataException]::new(
            'Receipt authentication trust is not one valid P-256 public key.',
            $_.Exception)
    }
}
