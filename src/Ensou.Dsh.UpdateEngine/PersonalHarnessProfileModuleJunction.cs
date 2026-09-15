using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.UpdateEngine;

/// <summary>
/// Preserves only DSH's profile-module directory junctions as opaque leaf
/// objects. Admission here never grants trust to, or reads, a junction target.
/// </summary>
internal sealed class PersonalHarnessProfileModuleJunction : IDisposable
{
    private const uint MountPointTag = 0xA0000003;
    private const uint GetReparsePoint = 0x000900A8;
    private const uint SetReparsePoint = 0x000900A4;
    private const int MaximumReparseBytes = 16 * 1024;
    private static readonly UnicodeEncoding StrictUnicode = new(false, false, true);
    private readonly SafeFileHandle _handle;
    private readonly byte[] _rawData;

    private PersonalHarnessProfileModuleJunction(SafeFileHandle handle, byte[] rawData)
    { _handle = handle; _rawData = rawData; }

    internal byte[] RawData => (byte[])_rawData.Clone();

    internal static PersonalHarnessProfileModuleJunction OpenRead(string treeRoot, string path)
    {
        var package = RequireLeafPath(treeRoot, path);
        RequireOrdinaryParents(path);
        var handle = Open(path, 0x80000000, FileShare.Read | FileShare.Delete);
        try
        {
            RequireDirectoryKind(handle, reparse: true);
            RequireNtfs(handle);
            var raw = ReadRaw(handle);
            ValidateRaw(raw, package);
            return new PersonalHarnessProfileModuleJunction(handle, raw);
        }
        catch { handle.Dispose(); throw; }
    }

    internal static void CreateClone(string treeRoot, string path, ReadOnlySpan<byte> rawData)
    {
        var package = RequireLeafPath(treeRoot, path);
        ValidateRaw(rawData, package);
        RequireOrdinaryParents(path);
        var parents = PinDestinationParents(treeRoot, path);
        try
        {
            // CreateDirectoryW must succeed with a new name. Never set a reparse
            // point on a pre-existing object or use a target-following copy API.
            if (!CreateDirectoryW(Extended(path), IntPtr.Zero))
                throw NativeFailure("Could not create a new profile-module junction leaf.");
            using var handle = Open(path, 0xC0000000, FileShare.Read);
            RequireDirectoryKind(handle, reparse: false);
            RequireNtfs(handle);
            var bytes = rawData.ToArray();
            if (!DeviceIoControl(handle, SetReparsePoint, bytes, bytes.Length, null, 0, out _, IntPtr.Zero))
                throw NativeFailure("Could not restore a profile-module junction object.");
            RequireDirectoryKind(handle, reparse: true);
            var observed = ReadRaw(handle);
            ValidateRaw(observed, package);
            if (!observed.AsSpan().SequenceEqual(bytes))
                throw new InvalidDataException("The cloned profile-module junction metadata changed.");
        }
        finally
        {
            for (var index = parents.Count - 1; index >= 0; index--) parents[index].Dispose();
        }
    }

    private static List<SafeFileHandle> PinDestinationParents(string treeRoot, string path)
    {
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(treeRoot));
        var pending = new Stack<string>();
        var current = Path.GetDirectoryName(Path.GetFullPath(path));
        while (current is not null)
        {
            pending.Push(current);
            if (string.Equals(Path.TrimEndingDirectorySeparator(current), root, StringComparison.OrdinalIgnoreCase)) break;
            current = Path.GetDirectoryName(current);
        }
        if (current is null) throw Invalid("The clone destination escaped its tree root.");
        var handles = new List<SafeFileHandle>();
        try
        {
            // The candidate destination has no source-root DELETE lease. These
            // no-follow handles deny both write and delete until SET and its
            // readback finish, preventing parent replacement by a junction.
            while (pending.TryPop(out var directory))
            {
                var handle = Open(directory, 0x80000000, FileShare.Read);
                handles.Add(handle);
                RequireDirectoryKind(handle, reparse: false);
            }
            return handles;
        }
        catch
        {
            for (var index = handles.Count - 1; index >= 0; index--) handles[index].Dispose();
            throw;
        }
    }

    internal void RequireUnchanged()
    {
        RequireDirectoryKind(_handle, reparse: true);
        if (!ReadRaw(_handle).AsSpan().SequenceEqual(_rawData))
            throw new InvalidDataException("The pinned profile-module junction metadata changed.");
    }

    public void Dispose() => _handle.Dispose();

    private static string RequireLeafPath(string treeRoot, string path)
    {
        if (!Path.IsPathFullyQualified(treeRoot) || !Path.IsPathFullyQualified(path))
            throw Invalid("Junction paths must be absolute.");
        var relative = Path.GetRelativePath(Path.GetFullPath(treeRoot), Path.GetFullPath(path)).Replace('\\', '/');
        var parts = relative.Split('/');
        if (parts.Length is not 3 and not 4
            || !parts[0].Equals("profiles", StringComparison.OrdinalIgnoreCase)
            || !parts[1].Equals("node_modules", StringComparison.OrdinalIgnoreCase)
            || (parts.Length == 3 && !IsPackagePart(parts[2]))
            || (parts.Length == 4 && (!parts[2].StartsWith('@') || !IsPackagePart(parts[2][1..]) || !IsPackagePart(parts[3]))))
            throw Invalid("A filesystem link is outside the supported profile-module leaf paths.");
        return string.Join('\\', parts.Skip(2));
    }

    private static bool IsPackagePart(string value) => value.Length is > 0 and <= 214
        && char.IsAsciiLetterOrDigit(value[0])
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');

    private static void ValidateRaw(ReadOnlySpan<byte> raw, string package)
    {
        if (raw.Length is < 16 or > MaximumReparseBytes
            || BinaryPrimitives.ReadUInt32LittleEndian(raw) != MountPointTag
            || BinaryPrimitives.ReadUInt16LittleEndian(raw[4..]) != raw.Length - 8)
            throw Invalid("Only a bounded mount-point directory junction is supported.");
        var substitute = ReadName(raw, 8);
        var print = ReadName(raw, 12);
        if (!substitute.StartsWith(@"\??\", StringComparison.Ordinal))
            throw Invalid("The profile-module junction target is not a local DOS path.");
        var target = substitute[4..];
        if (target.Length < 4 || !char.IsAsciiLetter(target[0]) || target[1] != ':' || target[2] != '\\'
            || target.Contains('/') || target[3..].Split('\\').Any(part => part.Length == 0
                || part is "." or ".." || part.EndsWith('.') || part.EndsWith(' ')
                || part.Any(character => char.IsControl(character) || character is ':' or '*' or '?' or '"' or '<' or '>' or '|'))
            || !string.Equals(Path.GetFullPath(target), target, StringComparison.OrdinalIgnoreCase)
            || !target.EndsWith(@"\node_modules\" + package, StringComparison.OrdinalIgnoreCase)
            || (print.Length != 0 && !string.Equals(print, target, StringComparison.OrdinalIgnoreCase)))
            throw Invalid("The profile-module junction target must be a canonical local directory for the same package.");
    }

    private static string ReadName(ReadOnlySpan<byte> raw, int fieldOffset)
    {
        var offset = BinaryPrimitives.ReadUInt16LittleEndian(raw[fieldOffset..]);
        var length = BinaryPrimitives.ReadUInt16LittleEndian(raw[(fieldOffset + 2)..]);
        if ((offset & 1) != 0 || (length & 1) != 0 || offset > raw.Length - 16 || length > raw.Length - 16 - offset)
            throw Invalid("The profile-module junction contains malformed name offsets.");
        try
        {
            var value = StrictUnicode.GetString(raw.Slice(16 + offset, length));
            if (value.Contains('\0')) throw Invalid("A junction name contains an embedded NUL.");
            return value;
        }
        catch (DecoderFallbackException exception) { throw new InvalidDataException("Malformed junction UTF-16 metadata.", exception); }
    }

    private static byte[] ReadRaw(SafeFileHandle handle)
    {
        var bytes = new byte[MaximumReparseBytes];
        if (!DeviceIoControl(handle, GetReparsePoint, null, 0, bytes, bytes.Length, out var returned, IntPtr.Zero))
            throw NativeFailure("Could not read a profile-module junction object.");
        if (returned is < 16 or > MaximumReparseBytes) throw Invalid("Invalid junction metadata length.");
        return bytes.AsSpan(0, returned).ToArray();
    }

    internal static void RequireOrdinaryDirectoryHandle(SafeFileHandle handle) => RequireDirectoryKind(handle, reparse: false);

    private static void RequireDirectoryKind(SafeFileHandle handle, bool reparse)
    {
        if (!GetFileInformationByHandle(handle, out var information)) throw NativeFailure("Could not inspect a no-follow directory handle.");
        if ((information.Attributes & 0x10) == 0 || ((information.Attributes & 0x400) != 0) != reparse || information.NumberOfLinks != 1)
            throw Invalid("The no-follow directory handle has an unexpected kind or link count.");
    }

    private static void RequireNtfs(SafeFileHandle handle)
    {
        var name = new StringBuilder(32);
        if (!GetVolumeInformationByHandleW(handle, null, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, name, name.Capacity))
            throw NativeFailure("Could not inspect the profile-module junction filesystem.");
        if (!name.ToString().Equals("NTFS", StringComparison.OrdinalIgnoreCase)) throw Invalid("Profile-module junction preservation requires NTFS.");
    }

    private static void RequireOrdinaryParents(string path)
    {
        for (var current = new DirectoryInfo(Path.GetDirectoryName(Path.GetFullPath(path))!); current is not null; current = current.Parent)
            if (!current.Exists || (current.Attributes & FileAttributes.ReparsePoint) != 0) throw Invalid("A junction ancestor is missing or linked.");
    }

    private static SafeFileHandle Open(string path, uint access, FileShare share)
    {
        var handle = CreateFileW(Extended(path), access, share, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (!handle.IsInvalid) return handle;
        var exception = NativeFailure("Could not open the no-follow profile-module junction object.");
        handle.Dispose();
        throw exception;
    }

    internal static string Extended(string path)
    {
        var full = Path.GetFullPath(path);
        return full.StartsWith(@"\\?\", StringComparison.Ordinal) ? full
            : full.StartsWith(@"\\", StringComparison.Ordinal) ? @"\\?\UNC\" + full[2..] : @"\\?\" + full;
    }

    private static InvalidDataException Invalid(string message) => new("Personal Harness-home junction admission failed: " + message);
    private static IOException NativeFailure(string message) => new(message, new Win32Exception(Marshal.GetLastPInvokeError()));

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateFileW(string path, uint access, FileShare share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CreateDirectoryW(string path, IntPtr security);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DeviceIoControl(SafeFileHandle handle, uint code, byte[]? input, int inputLength, [Out] byte[]? output, int outputLength, out int returned, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetVolumeInformationByHandleW(SafeFileHandle handle, StringBuilder? volumeName, int volumeNameLength, IntPtr serialNumber, IntPtr maximumComponentLength, IntPtr flags, StringBuilder fileSystemName, int fileSystemNameLength);
    [StructLayout(LayoutKind.Sequential)] private struct FileInformation
    {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        public uint Volume, SizeHigh, SizeLow, NumberOfLinks, IndexHigh, IndexLow;
    }
}
