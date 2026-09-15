using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.Enterprise.Installation;

internal sealed record EnterpriseAuthenticodeInspection(
    int Status,
    string? SignerSha256Thumbprint,
    bool HasTrustedTimestamp);

internal delegate EnterpriseAuthenticodeInspection EnterpriseAuthenticodeInspector(
    string filePath,
    SafeFileHandle fileHandle);

internal static class EnterpriseTrustedProcessContainment
{
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const int JobObjectBasicAccountingInformationClass = 1;
    private const int JobObjectExtendedLimitInformationClass = 9;
    private const int FailedProcessExitWaitMilliseconds = 5_000;
    private const uint ContainmentExitCode = 0xE0000001;
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint CreateNoWindow = 0x08000000;
    private const uint StartfUseShowWindow = 0x00000001;
    private const uint ResumeThreadFailed = uint.MaxValue;
    private const uint WaitObject0 = 0;
    private static readonly object RetainedGate = new();
    private static readonly List<EnterpriseTrustedStartedProcess> RetainedLaunches = [];

    internal static EnterpriseTrustedStartedProcess StartSuspendedInJob(
        ProcessStartInfo startInfo,
        Action<int, uint>? beforeResumeForTests = null,
        Action<Process>? validateBeforeResume = null)
    {
        ValidateDirectStartInfo(startInfo);
        RetryRetainedContainmentOrThrow();
        var applicationPath = Path.GetFullPath(startInfo.FileName);
        var commandLine = new StringBuilder(BuildCommandLine(startInfo));
        var environment = IntPtr.Zero;
        var startupInfo = new StartupInfo
        {
            Size = checked((uint)Marshal.SizeOf<StartupInfo>()),
            Flags = StartfUseShowWindow,
            ShowWindow = startInfo.WindowStyle switch
            {
                ProcessWindowStyle.Hidden => 0,
                ProcessWindowStyle.Minimized => 2,
                ProcessWindowStyle.Maximized => 3,
                _ => 1,
            },
        };
        SafeFileHandle? job = null;
        var processInformation = default(ProcessInformation);
        Process? process = null;
        var created = false;
        var assigned = false;
        try
        {
            environment = BuildEnvironmentBlock(startInfo);
            job = CreateKillOnCloseJob();
            if (!CreateProcess(
                    applicationPath,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    inheritHandles: false,
                    CreateSuspended | CreateUnicodeEnvironment | CreateNoWindow,
                    environment,
                    Path.GetFullPath(startInfo.WorkingDirectory),
                    ref startupInfo,
                    out processInformation))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "CreateProcessW(CREATE_SUSPENDED) failed for Enterprise trusted launch.");
            }
            created = true;
            process = Process.GetProcessById(
                checked((int)processInformation.ProcessId));
            _ = process.Handle;
            if (!AssignProcessToJobObject(job, processInformation.ProcessHandle))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Enterprise trusted process could not be assigned to its containment Job Object before resume.");
            }
            assigned = true;
            var activeBeforeResume = ReadActiveProcessCount(job);
            if (activeBeforeResume != 1)
            {
                throw new InvalidOperationException(
                    "Enterprise containment Job Object did not contain exactly the suspended root process.");
            }
            beforeResumeForTests?.Invoke(process.Id, activeBeforeResume);
            validateBeforeResume?.Invoke(process);
            var previousSuspendCount = ResumeThread(processInformation.ThreadHandle);
            if (previousSuspendCount == ResumeThreadFailed
                || previousSuspendCount != 1)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Enterprise trusted process primary thread was not resumed exactly once.");
            }
            var result = new EnterpriseTrustedStartedProcess(process, job);
            process = null;
            job = null!;
            return result;
        }
        catch (Exception startFailure)
        {
            var failures = new List<Exception> { startFailure };
            if (assigned)
            {
                try
                {
                    TerminateJobAndWaitForZero(job!);
                }
                catch (Exception containmentFailure)
                {
                    failures.Add(containmentFailure);
                }
            }
            else if (created)
            {
                try
                {
                    if (!TerminateProcess(
                            processInformation.ProcessHandle,
                            ContainmentExitCode)
                        || WaitForSingleObject(
                            processInformation.ProcessHandle,
                            FailedProcessExitWaitMilliseconds) != WaitObject0)
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "Suspended Enterprise process could not be terminated after Job assignment failure.");
                    }
                }
                catch (Exception containmentFailure)
                {
                    failures.Add(containmentFailure);
                }
            }
            if (failures.Count == 1)
            {
                System.Runtime.ExceptionServices.ExceptionDispatchInfo
                    .Capture(startFailure)
                    .Throw();
            }
            if (process is not null && job is not null)
            {
                var retained = new EnterpriseTrustedStartedProcess(process, job);
                process = null;
                job = null;
                Exception? retryFailure = null;
                try
                {
                    retained.TerminateRequired();
                    retained.Dispose();
                }
                catch (Exception exception)
                {
                    retryFailure = exception;
                    failures.Add(exception);
                    RetainForRetry(retained);
                }
                if (retryFailure is null)
                {
                    System.Runtime.ExceptionServices.ExceptionDispatchInfo
                        .Capture(startFailure)
                        .Throw();
                }
            }
            throw new InvalidOperationException(
                "Enterprise trusted child could not be created suspended inside its containment Job Object.",
                new AggregateException(failures));
        }
        finally
        {
            process?.Dispose();
            if (processInformation.ThreadHandle != IntPtr.Zero)
            {
                CloseHandle(processInformation.ThreadHandle);
            }
            if (processInformation.ProcessHandle != IntPtr.Zero)
            {
                CloseHandle(processInformation.ProcessHandle);
            }
            if (environment != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(environment);
            }
            job?.Dispose();
        }
    }

    private static void RetryRetainedContainmentOrThrow()
    {
        List<Exception> failures = [];
        lock (RetainedGate)
        {
            foreach (var retained in RetainedLaunches.ToArray())
            {
                try
                {
                    retained.TerminateRequired();
                    retained.Dispose();
                    RetainedLaunches.Remove(retained);
                }
                catch (Exception exception)
                {
                    failures.Add(exception);
                }
            }
        }
        if (failures.Count > 0)
        {
            throw new InvalidOperationException(
                "Enterprise retained process containment still requires cleanup.",
                new AggregateException(failures));
        }
    }

    internal static void RetainForRetry(EnterpriseTrustedStartedProcess retained)
    {
        ArgumentNullException.ThrowIfNull(retained);
        lock (RetainedGate)
        {
            if (!RetainedLaunches.Any(candidate => ReferenceEquals(candidate, retained)))
            {
                RetainedLaunches.Add(retained);
            }
        }
    }

    internal static void TerminateRequired(
        Process process,
        SafeFileHandle containmentJob)
    {
        ArgumentNullException.ThrowIfNull(process);
        ArgumentNullException.ThrowIfNull(containmentJob);
        var failures = new List<Exception>();
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }
        try
        {
            TerminateJobAndWaitForZero(containmentJob);
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }
        try
        {
            if (!process.WaitForExit(FailedProcessExitWaitMilliseconds)
                || !process.HasExited)
            {
                throw new TimeoutException(
                    "Enterprise contained root process did not exit within the containment bound.");
            }
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }
        if (failures.Count > 0)
        {
            throw new InvalidOperationException(
                "Unable to prove Enterprise contained process-tree termination.",
                failures.Count == 1
                    ? failures[0]
                    : new AggregateException(failures));
        }
    }

    internal static void CompleteRequired(
        Process process,
        SafeFileHandle containmentJob)
    {
        ArgumentNullException.ThrowIfNull(process);
        ArgumentNullException.ThrowIfNull(containmentJob);
        if (!process.HasExited)
        {
            throw new InvalidOperationException(
                "Enterprise contained process cannot complete while its root remains active.");
        }
        try
        {
            WaitForActiveProcessZero(containmentJob);
        }
        catch (Exception completionFailure)
        {
            try
            {
                TerminateJobAndWaitForZero(containmentJob);
            }
            catch (Exception containmentFailure)
            {
                throw new InvalidOperationException(
                    "Enterprise completed root left a process tree that could not be contained.",
                    new AggregateException(
                        completionFailure,
                        containmentFailure));
            }
            throw new InvalidOperationException(
                "Enterprise completed root left active descendant processes; they were terminated.",
                completionFailure);
        }
    }

    internal static void ReleaseDetachedJob(SafeFileHandle containmentJob)
    {
        ArgumentNullException.ThrowIfNull(containmentJob);
        SetKillOnJobClose(containmentJob, enabled: false);
    }

    private static void ValidateDirectStartInfo(ProcessStartInfo startInfo)
    {
        ArgumentNullException.ThrowIfNull(startInfo);
        if (string.IsNullOrWhiteSpace(startInfo.FileName)
            || string.IsNullOrWhiteSpace(startInfo.WorkingDirectory)
            || startInfo.UseShellExecute
            || !startInfo.CreateNoWindow
            || startInfo.RedirectStandardInput
            || startInfo.RedirectStandardOutput
            || startInfo.RedirectStandardError
            || !string.IsNullOrEmpty(startInfo.Arguments))
        {
            throw new InvalidOperationException(
                "Enterprise trusted launch requires a direct no-window application path and ArgumentList-only command line.");
        }
    }

    private static string BuildCommandLine(ProcessStartInfo startInfo)
    {
        var parts = new List<string>
        {
            QuoteWindowsArgument(Path.GetFullPath(startInfo.FileName)),
        };
        parts.AddRange(startInfo.ArgumentList.Select(QuoteWindowsArgument));
        return string.Join(' ', parts);
    }

    private static string QuoteWindowsArgument(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length > 0
            && !value.Any(character => char.IsWhiteSpace(character) || character == '"'))
        {
            return value;
        }
        var result = new StringBuilder(value.Length + 2);
        result.Append('"');
        var backslashes = 0;
        foreach (var character in value)
        {
            if (character == '\\')
            {
                backslashes++;
                continue;
            }
            if (character == '"')
            {
                result.Append('\\', checked(backslashes * 2 + 1));
                result.Append('"');
            }
            else
            {
                result.Append('\\', backslashes);
                result.Append(character);
            }
            backslashes = 0;
        }
        result.Append('\\', checked(backslashes * 2));
        result.Append('"');
        return result.ToString();
    }

    private static IntPtr BuildEnvironmentBlock(ProcessStartInfo startInfo)
    {
        var environment = new StringBuilder();
        foreach (var pair in startInfo.Environment
                     .OrderBy(value => value.Key, StringComparer.OrdinalIgnoreCase))
        {
            if (string.IsNullOrEmpty(pair.Key)
                || pair.Key.Contains('=')
                || pair.Key.Contains('\0')
                || (pair.Value?.Contains('\0') ?? false))
            {
                throw new InvalidOperationException(
                    "Enterprise trusted launch environment contains an invalid entry.");
            }
            environment.Append(pair.Key);
            environment.Append('=');
            environment.Append(pair.Value ?? string.Empty);
            environment.Append('\0');
        }
        environment.Append('\0');
        return Marshal.StringToHGlobalUni(environment.ToString());
    }

    private static SafeFileHandle CreateKillOnCloseJob()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Enterprise process containment requires Windows Job Objects.");
        }
        var handle = CreateJobObject(IntPtr.Zero, null);
        if (handle.IsInvalid)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "CreateJobObject failed for Enterprise process containment.");
        }
        try
        {
            SetKillOnJobClose(handle, enabled: true);
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static void SetKillOnJobClose(
        SafeFileHandle handle,
        bool enabled)
    {
        var information = new JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new JobObjectBasicLimitInformation
            {
                LimitFlags = enabled ? JobObjectLimitKillOnJobClose : 0,
            },
        };
        var length = Marshal.SizeOf<JobObjectExtendedLimitInformation>();
        var pointer = Marshal.AllocHGlobal(length);
        try
        {
            Marshal.StructureToPtr(information, pointer, fDeleteOld: false);
            if (!SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformationClass,
                    pointer,
                    checked((uint)length)))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "SetInformationJobObject failed for Enterprise process containment.");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pointer);
        }
    }

    private static void TerminateJobAndWaitForZero(SafeFileHandle job)
    {
        if (!TerminateJobObject(job, ContainmentExitCode))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "TerminateJobObject failed for Enterprise process containment.");
        }
        WaitForActiveProcessZero(job);
    }

    private static void WaitForActiveProcessZero(SafeFileHandle job)
    {
        var deadline = Stopwatch.StartNew();
        while (deadline.ElapsedMilliseconds < FailedProcessExitWaitMilliseconds)
        {
            if (ReadActiveProcessCount(job) == 0)
            {
                return;
            }
            Thread.Sleep(10);
        }
        throw new TimeoutException(
            "Enterprise containment Job Object retained active processes after termination.");
    }

    private static uint ReadActiveProcessCount(SafeFileHandle job)
    {
        if (!QueryInformationJobObject(
                job,
                JobObjectBasicAccountingInformationClass,
                out var accounting,
                checked((uint)Marshal.SizeOf<JobObjectBasicAccountingInformation>()),
                IntPtr.Zero))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "QueryInformationJobObject failed for Enterprise process containment.");
        }
        return accounting.ActiveProcesses;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateJobObject(
        IntPtr jobAttributes,
        string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
        SafeFileHandle job,
        int informationClass,
        IntPtr information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(
        SafeFileHandle job,
        IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateJobObject(
        SafeFileHandle job,
        uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryInformationJobObject(
        SafeFileHandle job,
        int informationClass,
        out JobObjectBasicAccountingInformation information,
        uint informationLength,
        IntPtr returnLength);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "CreateProcessW",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcess(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref StartupInfo startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, int milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public uint Size;
        public string? Reserved;
        public string? Desktop;
        public string? Title;
        public uint X;
        public uint Y;
        public uint XSize;
        public uint YSize;
        public uint XCountChars;
        public uint YCountChars;
        public uint FillAttribute;
        public uint Flags;
        public ushort ShowWindow;
        public ushort Reserved2Size;
        public IntPtr Reserved2;
        public IntPtr StandardInput;
        public IntPtr StandardOutput;
        public IntPtr StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr ProcessHandle;
        public IntPtr ThreadHandle;
        public uint ProcessId;
        public uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicAccountingInformation
    {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long ThisPeriodTotalUserTime;
        public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public nuint MinimumWorkingSetSize;
        public nuint MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public nuint Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public nuint ProcessMemoryLimit;
        public nuint JobMemoryLimit;
        public nuint PeakProcessMemoryUsed;
        public nuint PeakJobMemoryUsed;
    }
}

internal sealed class EnterpriseTrustedStartedProcess : IDisposable
{
    private Process? _process;
    private SafeFileHandle? _containmentJob;

    internal EnterpriseTrustedStartedProcess(
        Process process,
        SafeFileHandle containmentJob)
    {
        _process = process ?? throw new ArgumentNullException(nameof(process));
        _containmentJob = containmentJob
            ?? throw new ArgumentNullException(nameof(containmentJob));
    }

    internal Process Process => _process
        ?? throw new ObjectDisposedException(nameof(EnterpriseTrustedStartedProcess));

    internal void TerminateRequired()
    {
        var job = _containmentJob
            ?? throw new ObjectDisposedException(nameof(EnterpriseTrustedStartedProcess));
        EnterpriseTrustedProcessContainment.TerminateRequired(Process, job);
        job.Dispose();
        _containmentJob = null;
    }

    internal void CompleteRequired()
    {
        var job = _containmentJob
            ?? throw new ObjectDisposedException(nameof(EnterpriseTrustedStartedProcess));
        EnterpriseTrustedProcessContainment.CompleteRequired(Process, job);
        job.Dispose();
        _containmentJob = null;
    }

    internal Process DetachAfterAdmission()
    {
        var job = _containmentJob
            ?? throw new ObjectDisposedException(nameof(EnterpriseTrustedStartedProcess));
        EnterpriseTrustedProcessContainment.ReleaseDetachedJob(job);
        job.Dispose();
        _containmentJob = null;
        return Interlocked.Exchange(ref _process, null)
            ?? throw new ObjectDisposedException(nameof(EnterpriseTrustedStartedProcess));
    }

    public void Dispose()
    {
        if (_containmentJob is not null)
        {
            try
            {
                TerminateRequired();
            }
            catch
            {
                EnterpriseTrustedProcessContainment.RetainForRetry(this);
                throw;
            }
        }
        Interlocked.Exchange(ref _process, null)?.Dispose();
    }
}

internal sealed class EnterpriseTrustedExecutableLaunchLease : IDisposable
{
    private const int MaximumProcessImagePathCharacters = 32_768;

    private FileStream? _lockedExecutable;

    internal EnterpriseTrustedExecutableLaunchLease(
        string executablePath,
        FileStream lockedExecutable,
        EnterpriseManagedFileIdentity identity)
    {
        ExecutablePath = executablePath;
        _lockedExecutable = lockedExecutable;
        Identity = identity;
    }

    internal string ExecutablePath { get; }

    internal EnterpriseManagedFileIdentity Identity { get; }

    internal Process Start(
        ProcessStartInfo startInfo,
        Action<Process>? validateBeforeResume = null)
    {
        using var started = StartCore(
            startInfo,
            beforeResumeForTests: null,
            afterResumeForTests: null,
            validateBeforeResume);
        return started.DetachAfterAdmission();
    }

    internal EnterpriseTrustedStartedProcess StartContained(
        ProcessStartInfo startInfo,
        Action<Process>? validateBeforeResume = null) =>
        StartCore(
            startInfo,
            beforeResumeForTests: null,
            afterResumeForTests: null,
            validateBeforeResume);

    internal Process StartForTests(
        ProcessStartInfo expectedStartInfo,
        ProcessStartInfo actualStartInfo,
        Action<int, uint> beforeResumeForTests,
        Action<Process> afterResumeForTests)
    {
        ArgumentNullException.ThrowIfNull(actualStartInfo);
        using var started = StartCore(
            expectedStartInfo,
            beforeResumeForTests,
            afterResumeForTests,
            validateBeforeResume: null,
            actualStartInfo);
        return started.DetachAfterAdmission();
    }

    private EnterpriseTrustedStartedProcess StartCore(
        ProcessStartInfo startInfo,
        Action<int, uint>? beforeResumeForTests,
        Action<Process>? afterResumeForTests,
        Action<Process>? validateBeforeResume,
        ProcessStartInfo? actualStartInfoForTests = null)
    {
        ArgumentNullException.ThrowIfNull(startInfo);
        var lockedExecutable = _lockedExecutable
            ?? throw new ObjectDisposedException(nameof(EnterpriseTrustedExecutableLaunchLease));
        if (string.IsNullOrWhiteSpace(startInfo.FileName)
            || !string.Equals(
                Path.GetFullPath(startInfo.FileName),
                ExecutablePath,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Enterprise trusted process start must use the verified executable path.");
        }
        RequireIdentity(
            EnterpriseManagedGcPathSafety.GetFileIdentity(
                lockedExecutable.SafeFileHandle),
            "before process creation");

        EnterpriseTrustedStartedProcess? started = null;
        try
        {
            started = EnterpriseTrustedProcessContainment.StartSuspendedInJob(
                actualStartInfoForTests ?? startInfo,
                beforeResumeForTests,
                suspendedProcess =>
                {
                    var suspendedProcessImage = InspectProcessImage(suspendedProcess);
                    RequireIdentity(
                        suspendedProcessImage.Identity,
                        "for the suspended process image before resume");
                    validateBeforeResume?.Invoke(suspendedProcess);
                });
            afterResumeForTests?.Invoke(started.Process);
            var processImage = InspectProcessImage(started.Process);
            RequireIdentity(
                processImage.Identity,
                $"for started process image '{processImage.Path}'");
            return started;
        }
        catch (Exception admissionFailure)
        {
            if (started is not null)
            {
                try
                {
                    started.TerminateRequired();
                }
                catch (Exception containmentFailure)
                {
                    EnterpriseTrustedProcessContainment.RetainForRetry(started);
                    throw new InvalidOperationException(
                        "Enterprise rejected process image could not be proven terminated.",
                        new AggregateException(
                            admissionFailure,
                            containmentFailure));
                }
                started.Dispose();
            }
            throw;
        }
    }

    internal EnterpriseManagedFileIdentity InspectProcessImageIdentityForTests(
        Process process)
    {
        ArgumentNullException.ThrowIfNull(process);
        return InspectProcessImage(process).Identity;
    }

    internal void RequireProcessImage(Process process)
    {
        ArgumentNullException.ThrowIfNull(process);
        var lockedExecutable = _lockedExecutable
            ?? throw new ObjectDisposedException(nameof(EnterpriseTrustedExecutableLaunchLease));
        RequireIdentity(
            EnterpriseManagedGcPathSafety.GetFileIdentity(lockedExecutable.SafeFileHandle),
            "while admitting the restart receiver");
        var image = InspectProcessImage(process);
        RequireIdentity(image.Identity, "for the restart receiver");
        if (!string.Equals(image.Path, ExecutablePath, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Enterprise restart receiver path differs from the active verified Launcher.");
        }
    }

    public void Dispose() =>
        Interlocked.Exchange(ref _lockedExecutable, null)?.Dispose();

    private void RequireIdentity(
        EnterpriseManagedFileIdentity actual,
        string stage)
    {
        if (actual.VolumeSerialNumber != Identity.VolumeSerialNumber
            || actual.FileIndex != Identity.FileIndex
            || actual.Length != Identity.Length)
        {
            throw new InvalidDataException(
                $"Enterprise started process image identity does not match the verified executable {stage}. Expected path: {ExecutablePath}");
        }
    }

    private static string ReadProcessImagePath(Process process)
    {
        var path = new StringBuilder(MaximumProcessImagePathCharacters);
        var length = (uint)path.Capacity;
        if (!QueryFullProcessImageName(process.Handle, 0, path, ref length)
            || length == 0
            || length >= MaximumProcessImagePathCharacters)
        {
            throw new IOException(
                "Unable to bind the started enterprise process image identity.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }
        return Path.GetFullPath(path.ToString(0, checked((int)length)));
    }

    private static (EnterpriseManagedFileIdentity Identity, string Path)
        InspectProcessImage(Process process)
    {
        var processImagePath = ReadProcessImagePath(process);
        using var processImage =
            EnterpriseAuthenticodeVerifier.OpenLockedExecutable(processImagePath);
        EnterpriseManagedGcPathSafety.RequireSingleLinkHandle(
            processImage.SafeFileHandle);
        return (
            EnterpriseManagedGcPathSafety.GetFileIdentity(
                processImage.SafeFileHandle),
            processImagePath);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        IntPtr process,
        uint flags,
        StringBuilder executableName,
        ref uint size);
}

internal static class EnterpriseTrustedLauncherProcessStarter
{
    internal static Process Start(
        EnterpriseInstallationLayout layout,
        string launcherPath,
        string workingDirectory,
        string? healthToken,
        IReadOnlyList<string>? additionalArguments = null,
        Action<Process>? validateBeforeResume = null)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentException.ThrowIfNullOrWhiteSpace(launcherPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(workingDirectory);
        var startInfo = CreateStartInfo(
            launcherPath,
            workingDirectory,
            healthToken,
            additionalArguments);
        using var executable =
            EnterpriseAuthenticodeVerifier.OpenTrustedExecutableForLaunch(
                launcherPath,
                layout);
        return executable.Start(startInfo, validateBeforeResume);
    }

    internal static EnterpriseTrustedStartedProcess StartContained(
        EnterpriseInstallationLayout layout,
        string launcherPath,
        string workingDirectory,
        string healthToken,
        Action<Process>? validateBeforeResume = null)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentException.ThrowIfNullOrWhiteSpace(launcherPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(workingDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(healthToken);
        var startInfo = CreateStartInfo(
            launcherPath,
            workingDirectory,
            healthToken);
        using var executable =
            EnterpriseAuthenticodeVerifier.OpenTrustedExecutableForLaunch(
                launcherPath,
                layout);
        return executable.StartContained(startInfo, validateBeforeResume);
    }

    internal static ProcessStartInfo CreateStartInfo(
        string launcherPath,
        string workingDirectory,
        string? healthToken,
        IReadOnlyList<string>? additionalArguments = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(launcherPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(workingDirectory);
        var startInfo = new ProcessStartInfo
        {
            FileName = launcherPath,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = healthToken is null && additionalArguments is null
                ? ProcessWindowStyle.Normal
                : ProcessWindowStyle.Hidden,
        };
        if (healthToken is not null)
        {
            startInfo.ArgumentList.Add("--installation-self-check");
            startInfo.ArgumentList.Add("--release-health-token");
            startInfo.ArgumentList.Add(healthToken);
        }
        else if (additionalArguments is not null)
        {
            foreach (var argument in additionalArguments)
            {
                ArgumentException.ThrowIfNullOrWhiteSpace(argument);
                startInfo.ArgumentList.Add(argument);
            }
        }
        return startInfo;
    }
}

public static class EnterpriseAuthenticodeVerifier
{
    private const uint WtdUiNone = 2;
    private const uint WtdRevokeWholeChain = 1;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdRevocationCheckChainExcludeRoot = 0x00000080;
    private const uint SgnrTypeTimestamp = 0x00000010;
    private const uint MaximumTimestampCounterSigners = 16;
    private static readonly Guid GenericVerifyAction =
        new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    public static void RequireTrustedSignature(string filePath)
    {
        RequireTrustedSignature(filePath, GetCompiledSignerSha256Thumbprint());
    }

    public static string GetCompiledSignerSha256Thumbprint()
    {
        var value = typeof(EnterpriseAuthenticodeVerifier)
            .Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .Single(attribute => string.Equals(
                attribute.Key,
                "EnterpriseAuthenticodeSignerSha256Thumbprint",
                StringComparison.Ordinal))
            .Value;
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException(
                "Production installer signer trust is not compiled into this build.");
        }
        return EnterpriseProductionTrustFingerprint.RequireSha256Thumbprint(value);
    }

    public static void RequireTrustedSignature(string filePath, string expectedThumbprint)
    {
        using var _ = OpenTrustedExecutableForLaunchCore(
            filePath,
            expectedThumbprint,
            InspectNativeSignature);
    }

    internal static void RequireTrustedSignatureForTests(
        string filePath,
        string expectedThumbprint,
        EnterpriseAuthenticodeInspector inspector)
    {
        using var _ = OpenTrustedExecutableForLaunchCore(
            filePath,
            expectedThumbprint,
            inspector);
    }

    internal static EnterpriseAuthenticodeInspection
        InspectTrustedSignatureForTests(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Enterprise production installation requires Windows Authenticode.");
        }
        var absolutePath = Path.GetFullPath(filePath);
        RejectLinkAncestors(Path.GetDirectoryName(absolutePath)!);
        if (!File.Exists(absolutePath)
            || (File.GetAttributes(absolutePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Production enterprise executable path is missing or linked.");
        }
        using var lockedFile = OpenLockedExecutable(absolutePath);
        var lockedLength = lockedFile.Length;
        var inspection = InspectNativeSignature(
            absolutePath,
            lockedFile.SafeFileHandle);
        if (lockedFile.Length != lockedLength)
        {
            throw new IOException(
                "Enterprise executable changed while its signature was verified.");
        }
        return inspection;
    }

    internal static EnterpriseAuthenticodeInspection
        InspectTrustedSignatureForTests(
            string filePath,
            SafeFileHandle fileHandle)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        ArgumentNullException.ThrowIfNull(fileHandle);
        return InspectNativeSignature(Path.GetFullPath(filePath), fileHandle);
    }

    internal static EnterpriseTrustedExecutableLaunchLease
        OpenTrustedExecutableForLaunch(
            string filePath,
            EnterpriseInstallationLayout layout)
    {
        ArgumentNullException.ThrowIfNull(layout);
        return layout.IsDevelopmentE2E
            ? OpenTrustedExecutableForLaunchCore(
                filePath,
                expectedThumbprint: null,
                inspector: null)
            : OpenTrustedExecutableForLaunchCore(
                filePath,
                GetCompiledSignerSha256Thumbprint(),
                InspectNativeSignature);
    }

    internal static EnterpriseTrustedExecutableLaunchLease
        OpenTrustedExecutableForLaunchForTests(
            string filePath,
            string expectedThumbprint,
            EnterpriseAuthenticodeInspector inspector) =>
        OpenTrustedExecutableForLaunchCore(
            filePath,
            expectedThumbprint,
            inspector);

    private static EnterpriseTrustedExecutableLaunchLease
        OpenTrustedExecutableForLaunchCore(
        string filePath,
        string? expectedThumbprint,
        EnterpriseAuthenticodeInspector? inspector)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Enterprise production installation requires Windows Authenticode.");
        }
        if (inspector is not null)
        {
            expectedThumbprint = EnterpriseProductionTrustFingerprint
                .RequireSha256Thumbprint(expectedThumbprint!);
        }
        else if (expectedThumbprint is not null)
        {
            throw new InvalidOperationException(
                "Enterprise executable trust inspection is unavailable.");
        }

        var absolutePath = Path.GetFullPath(filePath);
        RejectLinkAncestors(Path.GetDirectoryName(absolutePath)!);
        if (!File.Exists(absolutePath)
            || (File.GetAttributes(absolutePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Production enterprise executable path is missing or linked.");
        }

        var lockedFile = OpenLockedExecutable(absolutePath);
        try
        {
            EnterpriseManagedGcPathSafety.RequireSingleLinkHandle(
                lockedFile.SafeFileHandle);
            var identity = EnterpriseManagedGcPathSafety.GetFileIdentity(
                lockedFile.SafeFileHandle);
            if (identity.Length != lockedFile.Length)
            {
                throw new IOException(
                    "Enterprise executable identity length is inconsistent.");
            }
            if (inspector is not null)
            {
                var inspection = inspector(
                    absolutePath,
                    lockedFile.SafeFileHandle);
                if (inspection.Status != 0)
                {
                    throw new InvalidDataException(
                        $"Production enterprise executable Authenticode verification failed: 0x{unchecked((uint)inspection.Status):X8}");
                }
                if (string.IsNullOrWhiteSpace(inspection.SignerSha256Thumbprint)
                    || !string.Equals(
                        inspection.SignerSha256Thumbprint,
                        expectedThumbprint,
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException(
                        "Production enterprise executable signer does not match the compiled Ensou signer identity.");
                }
                if (!inspection.HasTrustedTimestamp)
                {
                    throw new InvalidDataException(
                        "Production enterprise executable has no trusted Authenticode timestamp.");
                }
            }
            if (EnterpriseManagedGcPathSafety.GetFileIdentity(
                    lockedFile.SafeFileHandle) != identity)
            {
                throw new IOException(
                    "Enterprise executable changed while its identity was verified.");
            }
            return new EnterpriseTrustedExecutableLaunchLease(
                absolutePath,
                lockedFile,
                identity);
        }
        catch
        {
            lockedFile.Dispose();
            throw;
        }
    }

    private static EnterpriseAuthenticodeInspection InspectNativeSignature(
        string absolutePath,
        SafeFileHandle lockedFileHandle)
    {
        var fileInfo = new WinTrustFileInfo(absolutePath, lockedFileHandle);
        var fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, fDeleteOld: false);
            var trustData = new WinTrustData(fileInfoPointer);
            try
            {
                var status = WinVerifyTrust(
                    IntPtr.Zero,
                    GenericVerifyAction,
                    ref trustData);
                if (status != 0)
                {
                    return new EnterpriseAuthenticodeInspection(status, null, false);
                }

                var providerInspection = InspectTrustedProviderState(
                    trustData.StateData);
                return new EnterpriseAuthenticodeInspection(
                    status,
                    providerInspection.SignerSha256Thumbprint,
                    providerInspection.HasTrustedTimestamp);
            }
            finally
            {
                if (trustData.StateData != IntPtr.Zero)
                {
                    trustData.StateAction = WtdStateActionClose;
                    _ = WinVerifyTrust(
                        IntPtr.Zero,
                        GenericVerifyAction,
                        ref trustData);
                }
            }
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPointer);
            Marshal.FreeHGlobal(fileInfoPointer);
            fileInfo.Dispose();
        }
    }

    private static (string SignerSha256Thumbprint, bool HasTrustedTimestamp)
        InspectTrustedProviderState(IntPtr stateData)
    {
        if (stateData == IntPtr.Zero)
        {
            throw new InvalidDataException(
                "WinVerifyTrust returned no provider state for the locked executable.");
        }
        var providerData = WTHelperProvDataFromStateData(stateData);
        if (providerData == IntPtr.Zero)
        {
            throw new InvalidDataException(
                "WinVerifyTrust provider state could not be inspected.");
        }
        var signerPointer = WTHelperGetProvSignerFromChain(
            providerData,
            signerIndex: 0,
            counterSigner: false,
            counterSignerIndex: 0);
        if (signerPointer == IntPtr.Zero)
        {
            throw new InvalidDataException(
                "WinVerifyTrust provider state has no primary signer.");
        }
        var signer = Marshal.PtrToStructure<CryptProviderSigner>(signerPointer);
        if (signer.Error != 0
            || signer.CertificateChainCount == 0
            || signer.CertificateChain == IntPtr.Zero)
        {
            throw new InvalidDataException(
                "WinVerifyTrust provider state has no trusted primary signer chain.");
        }
        var signerCertificatePointer = WTHelperGetProvCertFromChain(
            signerPointer,
            certificateIndex: 0);
        if (signerCertificatePointer == IntPtr.Zero)
        {
            throw new InvalidDataException(
                "WinVerifyTrust provider state has no primary signer certificate.");
        }
        var providerCertificate =
            Marshal.PtrToStructure<CryptProviderCertificate>(
                signerCertificatePointer);
        if (providerCertificate.Error != 0
            || providerCertificate.CertificateContext == IntPtr.Zero)
        {
            throw new InvalidDataException(
                "WinVerifyTrust primary signer certificate is not trusted.");
        }
        var certificateContext = Marshal.PtrToStructure<NativeCertificateContext>(
            providerCertificate.CertificateContext);
        if (certificateContext.EncodedBytes == IntPtr.Zero
            || certificateContext.EncodedByteCount is 0 or > 1048576)
        {
            throw new InvalidDataException(
                "WinVerifyTrust primary signer certificate is malformed.");
        }
        var encodedCertificate = new byte[
            checked((int)certificateContext.EncodedByteCount)];
        Marshal.Copy(
            certificateContext.EncodedBytes,
            encodedCertificate,
            startIndex: 0,
            encodedCertificate.Length);
        using var signerCertificate =
            X509CertificateLoader.LoadCertificate(encodedCertificate);
        var signerThumbprint = signerCertificate.GetCertHashString(
            HashAlgorithmName.SHA256);

        var hasTrustedTimestamp = false;
        if (signer.CounterSignerCount is 0 or > MaximumTimestampCounterSigners)
        {
            return (signerThumbprint, hasTrustedTimestamp);
        }
        for (uint index = 0; index < signer.CounterSignerCount; index++)
        {
            var timestampPointer = WTHelperGetProvSignerFromChain(
                providerData,
                signerIndex: 0,
                counterSigner: true,
                counterSignerIndex: index);
            if (timestampPointer == IntPtr.Zero)
            {
                continue;
            }
            var timestamp = Marshal.PtrToStructure<CryptProviderSigner>(
                timestampPointer);
            if (timestamp.SignerType == SgnrTypeTimestamp
                && timestamp.Error == 0
                && timestamp.CertificateChainCount > 0
                && timestamp.CertificateChain != IntPtr.Zero
                && timestamp.ChainContext != IntPtr.Zero
                && (timestamp.VerifyAsOf.LowDateTime != 0
                    || timestamp.VerifyAsOf.HighDateTime != 0))
            {
                hasTrustedTimestamp = true;
                break;
            }
        }
        return (signerThumbprint, hasTrustedTimestamp);
    }

    internal static FileStream OpenLockedExecutable(string filePath)
    {
        var stream = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.SequentialScan);
        if (stream.Length <= 0)
        {
            stream.Dispose();
            throw new InvalidDataException("Enterprise executable is empty.");
        }
        return stream;
    }

    private static void RejectLinkAncestors(string path)
    {
        for (var current = new DirectoryInfo(Path.GetFullPath(path));
             current is not null;
             current = current.Parent)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Enterprise executable path may not cross a filesystem link.");
            }
        }
    }

    public static void RequireTrustedSignature(
        string filePath,
        EnterpriseInstallationLayout layout)
    {
        ArgumentNullException.ThrowIfNull(layout);
        if (layout.IsDevelopmentE2E)
        {
            // The development-E2E binary is compiled to a separate product/layout and
            // cannot address the production managed root. It is the only unsigned mode.
            return;
        }
        RequireTrustedSignature(filePath);
    }

    [DllImport("wintrust.dll", EntryPoint = "WinVerifyTrust", SetLastError = true)]
    private static extern int WinVerifyTrust(
        IntPtr window,
        in Guid actionId,
        ref WinTrustData trustData);

    [DllImport("wintrust.dll", EntryPoint = "WTHelperProvDataFromStateData")]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr stateData);

    [DllImport("wintrust.dll", EntryPoint = "WTHelperGetProvSignerFromChain")]
    private static extern IntPtr WTHelperGetProvSignerFromChain(
        IntPtr providerData,
        uint signerIndex,
        [MarshalAs(UnmanagedType.Bool)] bool counterSigner,
        uint counterSignerIndex);

    [DllImport("wintrust.dll", EntryPoint = "WTHelperGetProvCertFromChain")]
    private static extern IntPtr WTHelperGetProvCertFromChain(
        IntPtr signer,
        uint certificateIndex);

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileTime
    {
        public uint LowDateTime;
        public uint HighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptProviderSigner
    {
        public uint Size;
        public NativeFileTime VerifyAsOf;
        public uint CertificateChainCount;
        public IntPtr CertificateChain;
        public uint SignerType;
        public IntPtr SignerInfo;
        public uint Error;
        public uint CounterSignerCount;
        public IntPtr CounterSigners;
        public IntPtr ChainContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptProviderCertificate
    {
        public uint Size;
        public IntPtr CertificateContext;
        public int Commercial;
        public int TrustedRoot;
        public int SelfSigned;
        public int TestCertificate;
        public uint RevokedReason;
        public uint Confidence;
        public uint Error;
        public IntPtr TrustListContext;
        public int TrustListSignerCertificate;
        public IntPtr CertificateTrustListContext;
        public uint CertificateTrustListError;
        public int Cyclic;
        public IntPtr ChainElement;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeCertificateContext
    {
        public uint EncodingType;
        public IntPtr EncodedBytes;
        public uint EncodedByteCount;
        public IntPtr CertificateInfo;
        public IntPtr CertificateStore;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo : IDisposable
    {
        public uint Size;
        public IntPtr FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;

        public WinTrustFileInfo(string filePath, SafeFileHandle fileHandle)
        {
            Size = (uint)Marshal.SizeOf<WinTrustFileInfo>();
            FilePath = Marshal.StringToCoTaskMemUni(filePath);
            FileHandle = fileHandle.DangerousGetHandle();
            KnownSubject = IntPtr.Zero;
        }

        public void Dispose()
        {
            if (FilePath != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(FilePath);
                FilePath = IntPtr.Zero;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public uint Size;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfo;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;

        public WinTrustData(IntPtr fileInfo)
        {
            Size = (uint)Marshal.SizeOf<WinTrustData>();
            PolicyCallbackData = IntPtr.Zero;
            SipClientData = IntPtr.Zero;
            UiChoice = WtdUiNone;
            RevocationChecks = WtdRevokeWholeChain;
            UnionChoice = WtdChoiceFile;
            FileInfo = fileInfo;
            StateAction = WtdStateActionVerify;
            StateData = IntPtr.Zero;
            UrlReference = IntPtr.Zero;
            ProviderFlags = WtdRevocationCheckChainExcludeRoot;
            UiContext = 0;
            SignatureSettings = IntPtr.Zero;
        }
    }
}
