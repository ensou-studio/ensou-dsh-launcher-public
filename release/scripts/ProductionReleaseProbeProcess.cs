namespace EnsouLauncherProductionProbe
{
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Ensou.Dsh.Host;
using Microsoft.Win32.SafeHandles;

public static class ReleaseProbeProcess
{
    private const int OverallTimeoutMilliseconds = 30_000;
    private const int CleanupTimeoutMilliseconds = 5_000;
    private const int JobAccountingConvergenceGraceMilliseconds = 1_000;
    private const int StandardOutputLimitBytes = 32_768;
    private const int StandardErrorLimitBytes = 8_192;
    private const uint FileListDirectory = 0x00000001;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;

    public static string Execute(
        string executablePath,
        SafeFileHandle expectedImageHandle,
        bool personal)
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10))
        {
            throw Failure("unsupported-platform");
        }
        if (string.IsNullOrWhiteSpace(executablePath)
            || expectedImageHandle == null
            || expectedImageHandle.IsInvalid
            || expectedImageHandle.IsClosed)
        {
            throw Failure("invalid-input");
        }

        var normalizedExecutablePath = NormalizeAbsoluteDosOrUncPath(executablePath);
        var workingDirectory = NormalizeLocalDosPath(Environment.SystemDirectory);
        var timer = Stopwatch.StartNew();
        var expectedHandleRetained = false;
        var directoryLeases = new List<DirectoryLease>();
        WindowsJobObject? job = null;
        WindowsJobStartedProcess? started = null;
        Process? process = null;
        Process? retainedProcess = null;
        StreamReader? standardOutput = null;
        StreamReader? standardError = null;
        CancellationTokenSource? deadline = null;
        Task<string>? standardOutputTask = null;
        Task<string>? standardErrorTask = null;
        Exception? operationFailure = null;
        var cleanupConfirmed = false;
        string? output = null;

        try
        {
            expectedImageHandle.DangerousAddRef(ref expectedHandleRetained);
            var expectedIdentity = ReadOrdinarySingleLinkFile(expectedImageHandle);
            var executableDirectory = Path.GetDirectoryName(normalizedExecutablePath)
                ?? throw Failure("path-not-local-dos");
            directoryLeases.AddRange(OpenDirectoryChain(executableDirectory));
            directoryLeases.AddRange(OpenDirectoryChain(workingDirectory));
            VerifyDirectoryChain(directoryLeases);

            job = WindowsJobObject.CreateKillOnClose();
            RequireTimeRemaining(timer);
            var startInfo = CreateStartInfo(
                normalizedExecutablePath,
                workingDirectory,
                personal);
            started = job.StartAtomicSuspended(
                startInfo,
                candidate =>
                {
                    RequireTimeRemaining(timer);
                    VerifyDirectoryChain(directoryLeases);
                    var retainedIdentity = ReadOrdinarySingleLinkFile(expectedImageHandle);
                    if (!retainedIdentity.Equals(expectedIdentity))
                    {
                        throw Failure("expected-image-changed");
                    }
                    VerifySuspendedImage(
                        candidate,
                        normalizedExecutablePath,
                        expectedIdentity);
                });
            process = started.Process;
            var readers = started.DetachReaders();
            standardOutput = readers.Output
                ?? throw Failure("stdout-unavailable");
            standardError = readers.Error
                ?? throw Failure("stderr-unavailable");

            var remaining = GetRemainingMilliseconds(timer);
            deadline = new CancellationTokenSource(remaining);
            standardOutputTask = ReadBoundedAsync(
                standardOutput,
                StandardOutputLimitBytes,
                deadline.Token);
            standardErrorTask = ReadBoundedAsync(
                standardError,
                StandardErrorLimitBytes,
                deadline.Token);
            var exitTask = process.WaitForExitAsync(deadline.Token);
            WaitForExitOrFirstFailure(
                Task.Delay(remaining),
                exitTask,
                standardOutputTask,
                standardErrorTask);
            RequireTimeRemaining(timer);

            if (!process.HasExited)
            {
                throw Failure("exit-unconfirmed");
            }
            if (process.ExitCode != 0)
            {
                throw Failure("child-exit");
            }
            ConfirmJobEmpty(job, timer, standardOutputTask, standardErrorTask);
            // A descendant may retain the root process's output handles. Confirm
            // containment before waiting for EOF so it cannot hide until timeout.
            WaitForAllOrFirstFailure(
                Task.Delay(GetRemainingMilliseconds(timer)),
                standardOutputTask,
                standardErrorTask);
            RequireTimeRemaining(timer);
            VerifyDirectoryChain(directoryLeases);
            var finalExpectedIdentity = ReadOrdinarySingleLinkFile(expectedImageHandle);
            if (!finalExpectedIdentity.Equals(expectedIdentity))
            {
                throw Failure("expected-image-changed");
            }
            output = standardOutputTask.GetAwaiter().GetResult();
            _ = standardErrorTask.GetAwaiter().GetResult();
        }
        catch (WindowsSuspendedProcessContainmentException exception)
        {
            retainedProcess = exception.Process;
            operationFailure = Failure("launch-containment");
        }
        catch (OperationCanceledException)
        {
            operationFailure = Failure("timeout");
        }
        catch (ReleaseProbeFailure exception)
        {
            operationFailure = exception;
        }
        catch
        {
            operationFailure = Failure("execution-failed");
        }
        finally
        {
            deadline?.Cancel();
            try
            {
                if (job != null)
                {
                    job.Dispose();
                }
                ConfirmExited(process);
                ConfirmExited(retainedProcess);
                ConfirmReadersStopped(standardOutputTask, standardErrorTask);
                cleanupConfirmed = true;
            }
            catch
            {
                cleanupConfirmed = false;
            }
            finally
            {
                standardOutput?.Dispose();
                standardError?.Dispose();
                started?.Dispose();
                process?.Dispose();
                if (!ReferenceEquals(retainedProcess, process))
                {
                    retainedProcess?.Dispose();
                }
                deadline?.Dispose();
                for (var index = directoryLeases.Count - 1; index >= 0; index--)
                {
                    directoryLeases[index].Dispose();
                }
                if (expectedHandleRetained)
                {
                    expectedImageHandle.DangerousRelease();
                }
            }
        }

        if (!cleanupConfirmed)
        {
            throw Failure("cleanup-unconfirmed");
        }
        if (operationFailure != null)
        {
            throw operationFailure;
        }
        return output ?? throw Failure("stdout-unavailable");
    }

    private static ProcessStartInfo CreateStartInfo(
        string executablePath,
        string workingDirectory,
        bool personal)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = executablePath,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = new UTF8Encoding(false, true),
            StandardErrorEncoding = new UTF8Encoding(false, true),
        };
        startInfo.Environment.Clear();
        CopyEnvironment(startInfo, "ALLUSERSPROFILE");
        CopyEnvironment(startInfo, "APPDATA");
        CopyEnvironment(startInfo, "CommonProgramFiles");
        CopyEnvironment(startInfo, "CommonProgramFiles(x86)");
        CopyEnvironment(startInfo, "CommonProgramW6432");
        CopyEnvironment(startInfo, "HOME");
        CopyEnvironment(startInfo, "LOCALAPPDATA");
        CopyEnvironment(startInfo, "PATHEXT");
        CopyEnvironment(startInfo, "ProgramData");
        CopyEnvironment(startInfo, "ProgramFiles");
        CopyEnvironment(startInfo, "ProgramFiles(x86)");
        CopyEnvironment(startInfo, "ProgramW6432");
        CopyEnvironment(startInfo, "TEMP");
        CopyEnvironment(startInfo, "TMP");
        CopyEnvironment(startInfo, "USERDOMAIN");
        CopyEnvironment(startInfo, "USERNAME");
        CopyEnvironment(startInfo, "USERPROFILE");

        var windowsDirectory = Directory.GetParent(workingDirectory)?.FullName
            ?? throw Failure("system-directory-invalid");
        var systemRoot = Path.GetPathRoot(workingDirectory)
            ?? throw Failure("system-directory-invalid");
        startInfo.Environment["SystemRoot"] = windowsDirectory;
        startInfo.Environment["WINDIR"] = windowsDirectory;
        startInfo.Environment["SystemDrive"] = systemRoot.TrimEnd('\\');
        if (personal)
        {
            startInfo.Environment["ENSOU_DSH_PERSONAL_BINARY_SELF_CHECK_PROTOCOL"] =
                "ensou-personal-binary-self-check/v1";
            startInfo.ArgumentList.Add("--binary-self-check");
        }
        else
        {
            startInfo.ArgumentList.Add("--release-manifest-trust-probe");
        }
        return startInfo;
    }

    private static void CopyEnvironment(ProcessStartInfo startInfo, string name)
    {
        var value = Environment.GetEnvironmentVariable(name);
        if (!string.IsNullOrEmpty(value))
        {
            startInfo.Environment[name] = value;
        }
    }

    private static async Task<string> ReadBoundedAsync(
        StreamReader reader,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        using var value = new MemoryStream(capacity: maximumBytes);
        var buffer = new byte[4096];
        var encoding = new UTF8Encoding(false, true);
        while (true)
        {
            var remainingWithSentinel = checked(maximumBytes - (int)value.Length + 1);
            var count = await reader.BaseStream.ReadAsync(
                    buffer.AsMemory(0, Math.Min(buffer.Length, remainingWithSentinel)),
                    cancellationToken)
                .ConfigureAwait(false);
            if (count == 0)
            {
                var bytes = value.ToArray();
                var offset = bytes.Length >= 3
                    && bytes[0] == 0xEF
                    && bytes[1] == 0xBB
                    && bytes[2] == 0xBF
                    ? 3
                    : 0;
                return encoding.GetString(bytes, offset, bytes.Length - offset);
            }
            if (value.Length + count > maximumBytes)
            {
                throw Failure("output-limit");
            }
            value.Write(buffer, 0, count);
        }
    }

    private static void WaitForExitOrFirstFailure(
        Task timeout,
        Task exit,
        params Task[] readers)
    {
        var pendingReaders = new List<Task>(readers);
        while (!exit.IsCompleted)
        {
            var observed = new List<Task>(pendingReaders) { exit, timeout };
            var completed = Task.WhenAny(observed).GetAwaiter().GetResult();
            if (ReferenceEquals(completed, timeout))
            {
                throw Failure("timeout");
            }
            completed.GetAwaiter().GetResult();
            pendingReaders.Remove(completed);
        }
        exit.GetAwaiter().GetResult();
        // Preserve a reader failure that races with root exit; successful EOF
        // is not required until after the Job has been confirmed empty.
        foreach (var reader in readers)
        {
            if (reader.IsCompleted)
            {
                reader.GetAwaiter().GetResult();
            }
        }
    }

    private static void WaitForAllOrFirstFailure(
        Task timeout,
        params Task[] operations)
    {
        var pending = new List<Task>(operations);
        while (pending.Count != 0)
        {
            var observed = new List<Task>(pending) { timeout };
            var completed = Task.WhenAny(observed).GetAwaiter().GetResult();
            if (ReferenceEquals(completed, timeout))
            {
                throw Failure("timeout");
            }
            completed.GetAwaiter().GetResult();
            pending.Remove(completed);
        }
    }

    private static void ConfirmReadersStopped(params Task?[] readers)
    {
        var timer = Stopwatch.StartNew();
        while (readers.Any(reader => reader != null && !reader.IsCompleted)
               && timer.ElapsedMilliseconds < CleanupTimeoutMilliseconds)
        {
            Thread.Sleep(10);
        }
        if (readers.Any(reader => reader != null && !reader.IsCompleted))
        {
            throw Failure("cleanup-unconfirmed");
        }
    }

    private static void ConfirmJobEmpty(
        WindowsJobObject job,
        Stopwatch overallTimer,
        params Task[] readers)
    {
        var convergenceTimer = Stopwatch.StartNew();
        while (true)
        {
            foreach (var reader in readers)
            {
                if (reader.IsCompleted)
                {
                    reader.GetAwaiter().GetResult();
                }
            }
            if (job.ReadActiveProcessCountForTest() == 0)
            {
                break;
            }
            var graceRemaining = JobAccountingConvergenceGraceMilliseconds
                - convergenceTimer.ElapsedMilliseconds;
            var overallRemaining = OverallTimeoutMilliseconds
                - overallTimer.ElapsedMilliseconds;
            if (graceRemaining <= 0 || overallRemaining <= 0)
            {
                throw Failure("descendant-retained");
            }
            Thread.Sleep(checked((int)Math.Min(
                10,
                Math.Min(graceRemaining, overallRemaining))));
        }
        RequireTimeRemaining(overallTimer);
    }

    private static int GetRemainingMilliseconds(Stopwatch timer)
    {
        var elapsed = timer.ElapsedMilliseconds;
        if (elapsed >= OverallTimeoutMilliseconds)
        {
            throw Failure("timeout");
        }
        return checked(OverallTimeoutMilliseconds - (int)elapsed);
    }

    private static void RequireTimeRemaining(Stopwatch timer)
    {
        _ = GetRemainingMilliseconds(timer);
    }

    private static void ConfirmExited(Process? process)
    {
        if (process != null && !process.HasExited
            && !process.WaitForExit(CleanupTimeoutMilliseconds))
        {
            throw Failure("cleanup-unconfirmed");
        }
    }

    private static IEnumerable<DirectoryLease> OpenDirectoryChain(string path)
    {
        var root = Path.GetPathRoot(path)
            ?? throw Failure("system-directory-invalid");
        var current = root;
        yield return DirectoryLease.Open(current);
        var relative = path.Substring(root.Length);
        foreach (var component in relative.Split(
                     new[] { Path.DirectorySeparatorChar },
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, component);
            yield return DirectoryLease.Open(current);
        }
    }

    private static void VerifyDirectoryChain(IEnumerable<DirectoryLease> leases)
    {
        foreach (var lease in leases)
        {
            lease.RequireUnchanged();
        }
    }

    private static void VerifySuspendedImage(
        Process process,
        string executablePath,
        FileIdentity expectedIdentity)
    {
        var imagePathBuffer = new StringBuilder(32_768);
        var imagePathLength = checked((uint)imagePathBuffer.Capacity);
        if (!QueryFullProcessImageName(
                process.Handle,
                0,
                imagePathBuffer,
                ref imagePathLength))
        {
            throw Failure("image-query-failed");
        }
        var imagePath = NormalizeAbsoluteDosOrUncPath(imagePathBuffer.ToString());
        if (!string.Equals(imagePath, executablePath, StringComparison.OrdinalIgnoreCase))
        {
            throw Failure("image-path-mismatch");
        }
        using var imageHandle = CreateFile(
            ToExtendedPath(imagePath),
            FileReadAttributes,
            FileShareRead,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (imageHandle.IsInvalid)
        {
            throw Failure("image-open-failed");
        }
        var actualIdentity = ReadOrdinarySingleLinkFile(imageHandle);
        if (!actualIdentity.Equals(expectedIdentity))
        {
            throw Failure("image-identity-mismatch");
        }
    }

    private static FileIdentity ReadOrdinarySingleLinkFile(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw Failure("file-identity-unavailable");
        }
        if ((information.FileAttributes
                & (FileAttributeDirectory | FileAttributeReparsePoint)) != 0
            || information.NumberOfLinks != 1)
        {
            throw Failure("file-identity-invalid");
        }
        return new FileIdentity(
            information.VolumeSerialNumber,
            ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow);
    }

    private static string NormalizeLocalDosPath(string path)
    {
        var value = NormalizeAbsoluteDosOrUncPath(path);
        var root = Path.GetPathRoot(value);
        if (string.IsNullOrEmpty(root)
            || root.Length != 3
            || root[1] != ':'
            || root[2] != Path.DirectorySeparatorChar)
        {
            throw Failure("path-not-local-dos");
        }
        return value;
    }

    private static string NormalizeAbsoluteDosOrUncPath(string path)
    {
        var value = path;
        if (value.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase))
        {
            value = "\\\\" + value.Substring(8);
        }
        else if (value.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase))
        {
            value = value.Substring(4);
        }
        else if (value.StartsWith("\\\\.\\", StringComparison.OrdinalIgnoreCase))
        {
            throw Failure("path-not-absolute-dos-or-unc");
        }
        if (!Path.IsPathFullyQualified(value))
        {
            throw Failure("path-not-absolute-dos-or-unc");
        }
        var fullPath = Path.GetFullPath(value);
        var root = Path.GetPathRoot(fullPath);
        var localDos = !string.IsNullOrEmpty(root)
            && root.Length == 3
            && root[1] == ':'
            && root[2] == Path.DirectorySeparatorChar;
        var unc = !string.IsNullOrEmpty(root)
            && root.StartsWith("\\\\", StringComparison.Ordinal)
            && root.Length > 3;
        if ((!localDos && !unc)
            || !string.Equals(fullPath, value, StringComparison.OrdinalIgnoreCase))
        {
            throw Failure("path-not-absolute-dos-or-unc");
        }
        return fullPath;
    }

    private static string ToExtendedPath(string path) =>
        path.StartsWith("\\\\", StringComparison.Ordinal)
            ? "\\\\?\\UNC\\" + path.Substring(2)
            : "\\\\?\\" + path;

    private static ReleaseProbeFailure Failure(string code) =>
        new ReleaseProbeFailure("Release probe process failed: " + code + ".");

    private sealed class DirectoryLease : IDisposable
    {
        private readonly SafeFileHandle _handle;
        private readonly FileIdentity _identity;

        private DirectoryLease(SafeFileHandle handle, FileIdentity identity)
        {
            _handle = handle;
            _identity = identity;
        }

        internal static DirectoryLease Open(string path)
        {
            var handle = CreateFile(
                ToExtendedPath(path),
                FileListDirectory | FileReadAttributes,
                FileShareRead,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics | FileFlagOpenReparsePoint,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                handle.Dispose();
                throw Failure("path-directory-open-failed");
            }
            try
            {
                var identity = ReadOrdinaryDirectory(handle);
                return new DirectoryLease(handle, identity);
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        internal void RequireUnchanged()
        {
            if (!ReadOrdinaryDirectory(_handle).Equals(_identity))
            {
                throw Failure("path-directory-changed");
            }
        }

        public void Dispose() => _handle.Dispose();

        private static FileIdentity ReadOrdinaryDirectory(SafeFileHandle handle)
        {
            if (!GetFileInformationByHandle(handle, out var information))
            {
                throw Failure("path-directory-identity-unavailable");
            }
            if ((information.FileAttributes & FileAttributeDirectory) == 0
                || (information.FileAttributes & FileAttributeReparsePoint) != 0)
            {
                throw Failure("path-directory-identity-invalid");
            }
            return new FileIdentity(
                information.VolumeSerialNumber,
                ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow);
        }
    }

    private readonly struct FileIdentity : IEquatable<FileIdentity>
    {
        internal FileIdentity(uint volumeSerialNumber, ulong fileIndex)
        {
            VolumeSerialNumber = volumeSerialNumber;
            FileIndex = fileIndex;
        }

        private uint VolumeSerialNumber { get; }
        private ulong FileIndex { get; }

        public bool Equals(FileIdentity other) =>
            VolumeSerialNumber == other.VolumeSerialNumber
            && FileIndex == other.FileIndex;

        public override bool Equals(object? value) =>
            value is FileIdentity other && Equals(other);

        public override int GetHashCode() =>
            HashCode.Combine(VolumeSerialNumber, FileIndex);
    }

    private sealed class ReleaseProbeFailure : InvalidOperationException
    {
        internal ReleaseProbeFailure(string message)
            : base(message)
        {
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        IntPtr process,
        uint flags,
        StringBuilder executablePath,
        ref uint size);

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

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
}
}
