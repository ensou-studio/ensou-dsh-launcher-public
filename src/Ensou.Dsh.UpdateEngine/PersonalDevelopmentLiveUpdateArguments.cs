using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.UpdateEngine;

/// <summary>
/// A compiled-development-only, process-forwarded live-update configuration envelope.
/// The configuration file is pinned by both a read-only lease and its digest.
/// </summary>
public sealed class PersonalDevelopmentLiveUpdateArguments : IDisposable
{
    public const string ConfigurationArgument = "--dev-e2e-live-update-config";
    public const string ConfigurationSha256Argument = "--dev-e2e-live-update-config-sha256";
    private const int MaximumConfigurationBytes = 64 * 1024;
    private const uint GenericRead = 0x80000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private readonly SafeFileHandle _configurationHandle;
    private readonly object _readLock = new();
    private bool _disposed;

    private PersonalDevelopmentLiveUpdateArguments(
        string configurationPath,
        string configurationSha256,
        SafeFileHandle configurationHandle)
    {
        ConfigurationPath = configurationPath;
        ConfigurationSha256 = configurationSha256;
        _configurationHandle = configurationHandle;
    }

    public string ConfigurationPath { get; }

    public string ConfigurationSha256 { get; }

    public static bool IsIntent(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        return args.Any(argument =>
            string.Equals(argument, ConfigurationArgument, StringComparison.OrdinalIgnoreCase)
            || string.Equals(
                argument,
                ConfigurationSha256Argument,
                StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Strips one exact live-update envelope and retains the process command.</summary>
    public static PersonalDevelopmentLiveUpdateArguments? ParseAndStrip(
        IReadOnlyList<string> arguments,
        bool developmentE2ECompiled,
        PersonalDevelopmentE2ELayoutArguments? layoutArgs,
        out string[] commandArguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        if (!IsIntent(arguments))
        {
            commandArguments = arguments.ToArray();
            return null;
        }
        if (!developmentE2ECompiled)
        {
            throw new InvalidOperationException(
                "Personal development live-update arguments are unavailable in this compiled binary.");
        }
        if (layoutArgs is null)
        {
            throw new ArgumentException(
                "Personal development live-update requires its explicit isolated layout.");
        }

        string? configurationPath = null;
        string? configurationSha256 = null;
        var retained = new List<string>();
        for (var index = 0; index < arguments.Count; index++)
        {
            var argument = arguments[index];
            if (string.Equals(argument, ConfigurationArgument, StringComparison.OrdinalIgnoreCase))
            {
                if (!string.Equals(argument, ConfigurationArgument, StringComparison.Ordinal)
                    || configurationPath is not null
                    || index + 1 >= arguments.Count)
                {
                    throw new ArgumentException(
                        "Personal development live-update configuration arguments must occur exactly once with exact casing.");
                }
                configurationPath = arguments[++index];
                continue;
            }
            if (string.Equals(
                    argument,
                    ConfigurationSha256Argument,
                    StringComparison.OrdinalIgnoreCase))
            {
                if (!string.Equals(
                        argument,
                        ConfigurationSha256Argument,
                        StringComparison.Ordinal)
                    || configurationSha256 is not null
                    || index + 1 >= arguments.Count)
                {
                    throw new ArgumentException(
                        "Personal development live-update configuration arguments must occur exactly once with exact casing.");
                }
                configurationSha256 = arguments[++index];
                continue;
            }
            retained.Add(argument);
        }
        if (configurationPath is null || configurationSha256 is null)
        {
            throw new ArgumentException(
                "Personal development live-update requires one configuration path and one SHA-256 digest.");
        }
        if (configurationSha256.Length != 64
            || !configurationSha256.All(character =>
                character is >= '0' and <= '9' or >= 'a' and <= 'f'))
        {
            throw new ArgumentException(
                "Personal development live-update configuration SHA-256 must be 64 lowercase hexadecimal characters.");
        }
        if (configurationPath.Length > 2
            && configurationPath.IndexOf(':', 2) >= 0)
        {
            throw new InvalidDataException(
                "Personal development live-update configuration must not be an alternate data stream.");
        }

        var canonicalPath = PersonalDevelopmentE2ELayoutArguments.RequireCanonicalLocalPath(
            configurationPath,
            "live-update configuration",
            directory: false);
        RequireIsolatedLayout(layoutArgs.Layout, canonicalPath);
        var handle = OpenPinnedConfiguration(canonicalPath);
        try
        {
            var result = new PersonalDevelopmentLiveUpdateArguments(
                canonicalPath,
                configurationSha256,
                handle);
            _ = result.ReadPinnedConfigurationBytes();
            commandArguments = retained.ToArray();
            return result;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public IEnumerable<string> ToArguments()
    {
        yield return ConfigurationArgument;
        yield return ConfigurationPath;
        yield return ConfigurationSha256Argument;
        yield return ConfigurationSha256;
    }

    public byte[] ReadPinnedConfigurationBytes()
    {
        lock (_readLock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var information = ReadAndValidateFileInformation(_configurationHandle);
            var length = checked(((long)information.FileSizeHigh << 32)
                | information.FileSizeLow);
            if (length is < 0 or > MaximumConfigurationBytes)
            {
                throw new InvalidDataException(
                    "Personal development live-update configuration exceeds 64 KiB.");
            }
            var bytes = new byte[checked((int)length)];
            var offset = 0;
            while (offset < bytes.Length)
            {
                var count = RandomAccess.Read(
                    _configurationHandle,
                    bytes.AsSpan(offset),
                    offset);
                if (count <= 0)
                {
                    throw new EndOfStreamException(
                        "Personal development live-update configuration ended before its pinned length.");
                }
                offset += count;
            }
            if (RandomAccess.GetLength(_configurationHandle) != length)
            {
                throw new InvalidDataException(
                    "Personal development live-update configuration length changed while reading.");
            }
            var actualSha256 = Convert.ToHexStringLower(SHA256.HashData(bytes));
            if (!string.Equals(actualSha256, ConfigurationSha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Personal development live-update configuration does not match its pinned SHA-256.");
            }
            return bytes;
        }
    }

    public void Dispose()
    {
        lock (_readLock)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            _configurationHandle.Dispose();
        }
        GC.SuppressFinalize(this);
    }

    private static SafeFileHandle OpenPinnedConfiguration(string path)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & (FileAttributes.Directory
                | FileAttributes.ReparsePoint
                | FileAttributes.Device)) != 0)
        {
            throw new InvalidDataException(
                "Personal development live-update configuration must be one regular local file.");
        }
        var handle = CreateFileW(
            @"\\?\" + path,
            GenericRead,
            FileShare.Read,
            IntPtr.Zero,
            FileMode.Open,
            FileFlagOpenReparsePoint | FileFlagSequentialScan,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new IOException(
                "Unable to acquire the Personal development live-update configuration read lease.",
                new System.ComponentModel.Win32Exception(error));
        }
        try
        {
            _ = ReadAndValidateFileInformation(handle);
            _ = PersonalDevelopmentE2ELayoutArguments.RequireCanonicalLocalPath(
                path,
                "live-update configuration",
                directory: false);
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static ByHandleFileInformation ReadAndValidateFileInformation(
        SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw new IOException(
                "Unable to inspect the Personal development live-update configuration file.",
                Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error()));
        }
        const uint rejectedAttributes = (uint)(FileAttributes.Directory
            | FileAttributes.ReparsePoint
            | FileAttributes.Device);
        if ((information.FileAttributes & rejectedAttributes) != 0
            || information.NumberOfLinks != 1)
        {
            throw new InvalidDataException(
                "Personal development live-update configuration must be a regular, single-link local file.");
        }
        return information;
    }

    private static void RequireIsolatedLayout(
        PersonalInstallationLayout layout,
        string configurationPath)
    {
        var live = PersonalInstallationLayout.CreateDefault();
        foreach (var isolatedPath in new[]
                 {
                     layout.ManagedRoot,
                     layout.HarnessHome,
                     configurationPath,
                 })
        {
            foreach (var livePath in new[] { live.ManagedRoot, live.HarnessHome })
            {
                if (PersonalPathGuard.IsSameOrDescendant(isolatedPath, livePath)
                    || PersonalPathGuard.IsSameOrDescendant(livePath, isolatedPath))
                {
                    throw new InvalidDataException(
                        "Personal development live-update isolation must not overlap the real Personal managed root or Harness home.");
                }
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        internal uint FileAttributes;
        internal System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        internal uint VolumeSerialNumber;
        internal uint FileSizeHigh;
        internal uint FileSizeLow;
        internal uint NumberOfLinks;
        internal uint FileIndexHigh;
        internal uint FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        FileShare shareMode,
        IntPtr securityAttributes,
        FileMode creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);
}
