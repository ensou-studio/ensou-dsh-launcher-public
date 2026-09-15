using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.Enterprise.Installation;

/// <summary>
/// Best-effort development evidence, never health authorization. Callers must also
/// gate use with their ENTERPRISE_DEVELOPMENT_E2E compilation condition.
/// </summary>
public sealed class EnterpriseDevelopmentHealthDiagnostics
{
    internal const string DirectoryName = "development-health-diagnostics";
    private const int MaximumRecordsPerInstance = 64;
    private const int MaximumDirectoryEntries = 513; // 512 records and the writer lock.
    private const uint OpenReparsePoint = 0x00200000;
    private const uint BackupSemantics = 0x02000000;
    private readonly object _gate = new();
    private readonly long _started = Stopwatch.GetTimestamp();
    private readonly string _session = Guid.NewGuid().ToString("N");
    private readonly string? _managedRoot;
    private readonly string? _component;
    private int _sequence;

    public EnterpriseDevelopmentHealthDiagnostics(
        EnterpriseInstallationLayout layout,
        string component)
    {
        try
        {
            if (!OperatingSystem.IsWindows() || layout is null || !layout.IsDevelopmentE2E
                || component is not ("client-bootstrapper" or "launcher" or "bootstrapper"))
            {
                return;
            }
            var root = Path.GetFullPath(layout.ManagedRoot);
            if (!Path.IsPathFullyQualified(root) || root.Length < 3
                || !char.IsAsciiLetter(root[0]) || root[1] != ':' || root[2] != '\\')
            {
                return;
            }
            _managedRoot = Path.TrimEndingDirectorySeparator(root);
            _component = component;
        }
        catch
        {
            // Diagnostics must not change admission, startup, or cleanup.
        }
    }

    public void Mark(
        string stage,
        Exception? exception = null,
        int? childProcessId = null,
        int? exitCode = null)
    {
        try
        {
            if (_managedRoot is null || !IsIdentifier(stage))
            {
                return;
            }
            lock (_gate)
            {
                if (_sequence >= MaximumRecordsPerInstance)
                {
                    return;
                }
                var sequence = ++_sequence;
                var payload = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schemaVersion = 1,
                    @event = "enterprise-development-health-trace",
                    component = _component,
                    stage,
                    processId = Environment.ProcessId,
                    elapsedMilliseconds = (long)Stopwatch.GetElapsedTime(_started).TotalMilliseconds,
                    sequence,
                    childProcessId,
                    exitCode,
                    exceptionType = SafeType(exception),
                    hResult = exception?.HResult,
                    innerExceptionType = SafeType(exception?.InnerException),
                    innerHResult = exception?.InnerException?.HResult,
                });
                if (payload.Length > 2048)
                {
                    return;
                }
                WriteRecord(sequence, payload);
            }
        }
        catch
        {
            // No message, stack, argument, environment, credential, or path is emitted.
        }
    }

    private void WriteRecord(int sequence, byte[] payload)
    {
        var parents = new List<SafeFileHandle>();
        try
        {
            // Pin every ancestor without write/delete sharing. OPEN_REPARSE_POINT
            // inspects each object itself, and retained handles close rename races.
            var current = Path.GetPathRoot(_managedRoot!)!;
            parents.Add(OpenOrdinaryDirectory(current));
            foreach (var segment in _managedRoot![current.Length..].Split('\\'))
            {
                current = Path.Combine(current, segment);
                parents.Add(OpenOrdinaryDirectory(current));
            }
            var directory = Path.Combine(_managedRoot!, DirectoryName);
            if (!CreateDirectory(NativePath(directory), IntPtr.Zero)
                && Marshal.GetLastWin32Error() != 183)
            {
                return;
            }
            parents.Add(OpenOrdinaryDirectory(directory));
            using var writerLock = OpenFile(Path.Combine(directory, ".writer.lock"), 4);
            if (writerLock is null)
            {
                return;
            }
            // Serialize the bounded directory inventory across CB/Launcher processes.
            if (Directory.EnumerateFileSystemEntries(directory)
                .Take(MaximumDirectoryEntries).Count() >= MaximumDirectoryEntries)
            {
                return;
            }
            var leaf = $"{_component}-{Environment.ProcessId}-{_session}-{sequence:D3}.json";
            using var handle = OpenFile(Path.Combine(directory, leaf), 1); // CREATE_NEW
            if (handle is null)
            {
                return;
            }
            using var stream = new FileStream(handle, FileAccess.Write);
            stream.Write(payload);
            stream.Flush();
        }
        finally
        {
            for (var index = parents.Count - 1; index >= 0; index--)
            {
                parents[index].Dispose();
            }
        }
    }

    private static SafeFileHandle OpenOrdinaryDirectory(string path)
    {
        var handle = CreateFile(NativePath(path), 0x80, 1, IntPtr.Zero, 3,
            OpenReparsePoint | BackupSemantics, IntPtr.Zero);
        try
        {
            if (handle.IsInvalid)
            {
                throw new IOException("Diagnostic directory is unavailable.");
            }
            var identity = EnterpriseManagedGcPathSafety.GetFileIdentity(handle);
            if ((identity.FileAttributes & (uint)FileAttributes.Directory) == 0
                || (identity.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException("Diagnostic directory is not ordinary.");
            }
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static SafeFileHandle? OpenFile(string path, uint disposition)
    {
        var handle = CreateFile(NativePath(path), 0xC0000000, 1, IntPtr.Zero,
            disposition, OpenReparsePoint | 0x80, IntPtr.Zero);
        try
        {
            if (handle.IsInvalid)
            {
                handle.Dispose();
                return null;
            }
            var identity = EnterpriseManagedGcPathSafety.GetFileIdentity(handle);
            if ((identity.FileAttributes & ((uint)FileAttributes.Directory
                    | (uint)FileAttributes.ReparsePoint)) != 0 || identity.NumberOfLinks != 1)
            {
                throw new IOException("Diagnostic file is not ordinary and single-linked.");
            }
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static bool IsIdentifier(string? value) => value is { Length: > 0 and <= 64 }
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '-');

    private static string? SafeType(Exception? exception)
    {
        var value = exception?.GetType().FullName;
        return value is { Length: > 0 and <= 192 }
            && value.All(character => char.IsAsciiLetterOrDigit(character)
                || character is '.' or '_' or '+' or '`') ? value : null;
    }

    private static string NativePath(string path) => "\\\\?\\" + path;

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectory(string path, IntPtr security);
}
