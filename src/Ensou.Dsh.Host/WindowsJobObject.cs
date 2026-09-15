namespace Ensou.Dsh.Host
{
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

internal sealed class WindowsJobObject : IDisposable
{
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const int JobObjectBasicAccountingInformationClass = 1;
    private const int JobObjectExtendedLimitInformationClass = 9;
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint CreateNoWindow = 0x08000000;
    private const uint ExtendedStartupInfoPresent = 0x00080000;
    private const uint StartfUseShowWindow = 0x00000001;
    private const uint StartfUseStdHandles = 0x00000100;
    private const uint ResumeThreadFailed = uint.MaxValue;
    private const uint HandleFlagInherit = 0x00000001;
    private const nuint ProcThreadAttributeHandleList = 0x00020002;
    private const nuint ProcThreadAttributeJobList = 0x0002000D;
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint ContainmentExitCode = 0xE0000001;
    private const uint WaitObject0 = 0;
    private const int MaximumLegacyPathCharacters = 260;
    private const int FailedProcessExitWaitMilliseconds = 5_000;
    private readonly SafeFileHandle _handle;
    private readonly Action? _onJobEmpty;
    private bool _admissionClosed;
    private bool _emptyRecorded;

    private WindowsJobObject(SafeFileHandle handle, Action? onJobEmpty)
    {
        _handle = handle;
        _onJobEmpty = onJobEmpty;
    }

    public static WindowsJobObject CreateKillOnClose(string? name = null, Action? onJobEmpty = null)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The DSH host process supervisor requires Windows.");
        }

        var handle = CreateJobObject(IntPtr.Zero, name);
        var creationError = Marshal.GetLastWin32Error();
        if (handle.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObject failed.");
        }

        if (creationError == 183)
        {
            handle.Dispose();
            throw new InvalidOperationException("The requested DSH Job Object name already exists.");
        }
        var information = new JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new JobObjectBasicLimitInformation
            {
                LimitFlags = JobObjectLimitKillOnJobClose
            }
        };
        var length = Marshal.SizeOf<JobObjectExtendedLimitInformation>();
        var pointer = Marshal.AllocHGlobal(length);
        try
        {
            Marshal.StructureToPtr(information, pointer, fDeleteOld: false);
            if (!SetInformationJobObject(handle, JobObjectExtendedLimitInformationClass, pointer, (uint)length))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "SetInformationJobObject(KILL_ON_JOB_CLOSE) failed.");
            }
        }
        catch
        {
            handle.Dispose();
            throw;
        }
        finally
        {
            Marshal.FreeHGlobal(pointer);
        }

        return new WindowsJobObject(handle, onJobEmpty);
    }

    public void Assign(Process process)
    {
        ArgumentNullException.ThrowIfNull(process);
        lock (_handle)
        {
        ThrowIfDisposed();
        if (!AssignProcessToJobObject(_handle, process.Handle))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "AssignProcessToJobObject failed.");
        }
        }
    }

    public WindowsJobStartedProcess StartSuspended(
        ProcessStartInfo startInfo,
        Action<Process> validateBeforeResume)
    {
        lock (_handle)
        {
            ThrowIfDisposed();
            return StartSuspendedCore(startInfo, validateBeforeResume, atomicJob: false);
        }
    }

    public WindowsJobStartedProcess StartAtomicSuspended(
        ProcessStartInfo startInfo,
        Action<Process> validateBeforeResume) =>
        StartAtomicSuspendedCore(startInfo, validateBeforeResume, afterNativeCreate: null);

    internal WindowsJobStartedProcess StartAtomicSuspendedForTest(
        ProcessStartInfo startInfo,
        Action<Process> validateBeforeResume,
        Action<int> afterNativeCreate) =>
        StartAtomicSuspendedCore(startInfo, validateBeforeResume, afterNativeCreate);

    private WindowsJobStartedProcess StartAtomicSuspendedCore(
        ProcessStartInfo startInfo,
        Action<Process> validateBeforeResume,
        Action<int>? afterNativeCreate)
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10))
        {
            throw new PlatformNotSupportedException(
                "Atomic DSH Job containment requires Windows 10 or later.");
        }
        // Disposal must not record an empty Job while a creation is in flight.
        lock (_handle)
        {
            ThrowIfDisposed();
            return StartSuspendedCore(
                startInfo, validateBeforeResume, atomicJob: true, afterNativeCreate);
        }
    }

    private WindowsJobStartedProcess StartSuspendedCore(
        ProcessStartInfo startInfo,
        Action<Process> validateBeforeResume,
        bool atomicJob,
        Action<int>? afterNativeCreate = null)
    {
        ArgumentNullException.ThrowIfNull(startInfo);
        ArgumentNullException.ThrowIfNull(validateBeforeResume);
        ValidateDirectStartInfo(startInfo);

        var commandLine = new StringBuilder(BuildCommandLine(startInfo));
        var applicationName = ToCreateProcessApplicationName(startInfo.FileName);
        var environment = IntPtr.Zero;
        SafeFileHandle? standardOutputRead = null;
        SafeFileHandle? standardOutputWrite = null;
        SafeFileHandle? standardErrorRead = null;
        SafeFileHandle? standardErrorWrite = null;
        SafeFileHandle? nullInput = null;
        SafeFileHandle? nullOutput = null;
        StreamReader? standardOutput = null;
        StreamReader? standardError = null;
        var startup = default(StartupInfoEx);
        var inheritHandles = false;
        IntPtr attributeList = IntPtr.Zero;
        IntPtr inheritedHandleList = IntPtr.Zero;
        IntPtr jobHandleList = IntPtr.Zero;
        IntPtr[] inheritedHandles = Array.Empty<IntPtr>();
        var attributeListInitialized = false;
        try
        {
            environment = BuildEnvironmentBlock(startInfo);
            startup = new StartupInfoEx
            {
                StartupInfo = new StartupInfo
                {
                    Size = checked((uint)Marshal.SizeOf<StartupInfoEx>()),
                    Flags = StartfUseShowWindow,
                    ShowWindow = 0,
                },
            };
            if (startInfo.RedirectStandardOutput || startInfo.RedirectStandardError)
            {
                var security = new SecurityAttributes
                {
                    Length = checked((uint)Marshal.SizeOf<SecurityAttributes>()),
                    InheritHandle = 1,
                };
                if (startInfo.RedirectStandardOutput)
                {
                    CreateReadPipe(
                        ref security,
                        out standardOutputRead,
                        out standardOutputWrite);
                    startup.StartupInfo.StandardOutput =
                        standardOutputWrite.DangerousGetHandle();
                }
                else
                {
                    nullOutput = OpenNullHandle(GenericWrite, ref security);
                    startup.StartupInfo.StandardOutput =
                        nullOutput.DangerousGetHandle();
                }
                if (startInfo.RedirectStandardError)
                {
                    CreateReadPipe(
                        ref security,
                        out standardErrorRead,
                        out standardErrorWrite);
                    startup.StartupInfo.StandardError =
                        standardErrorWrite.DangerousGetHandle();
                }
                else
                {
                    nullOutput ??= OpenNullHandle(GenericWrite, ref security);
                    startup.StartupInfo.StandardError =
                        nullOutput.DangerousGetHandle();
                }
                nullInput = OpenNullHandle(GenericRead, ref security);
                startup.StartupInfo.StandardInput = nullInput.DangerousGetHandle();
                startup.StartupInfo.Flags |= StartfUseStdHandles;
                inheritHandles = true;

                inheritedHandles = new SafeFileHandle[]
                    {
                        nullInput,
                        standardOutputWrite ?? nullOutput!,
                        standardErrorWrite ?? nullOutput!,
                    }
                    .Select(handle => handle.DangerousGetHandle())
                    .ToArray();
            }
            var attributeCount = (inheritHandles ? 1 : 0) + (atomicJob ? 1 : 0);
            if (attributeCount > 0)
            {
                nuint attributeListSize = 0;
                _ = InitializeProcThreadAttributeList(
                    IntPtr.Zero,
                    attributeCount,
                    0,
                    ref attributeListSize);
                if (attributeListSize == 0)
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "The DSH startup attribute size could not be determined.");
                }
                attributeList = Marshal.AllocHGlobal(checked((int)attributeListSize));
                if (!InitializeProcThreadAttributeList(
                        attributeList,
                        attributeCount,
                        0,
                        ref attributeListSize))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "The DSH startup attributes could not be initialized.");
                }
                attributeListInitialized = true;
                if (inheritHandles)
                {
                    inheritedHandleList = Marshal.AllocHGlobal(
                        checked(IntPtr.Size * inheritedHandles.Length));
                    Marshal.Copy(
                        inheritedHandles,
                        0,
                        inheritedHandleList,
                        inheritedHandles.Length);
                    if (!UpdateProcThreadAttribute(
                            attributeList,
                            0,
                            ProcThreadAttributeHandleList,
                            inheritedHandleList,
                            checked((nuint)(IntPtr.Size * inheritedHandles.Length)),
                            IntPtr.Zero,
                            IntPtr.Zero))
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "The DSH inherited-handle allowlist could not be installed.");
                    }
                }
                if (atomicJob)
                {
                    // The enclosing lock retains this non-inheritable Job handle through CreateProcess.
                    jobHandleList = Marshal.AllocHGlobal(IntPtr.Size);
                    Marshal.WriteIntPtr(jobHandleList, _handle.DangerousGetHandle());
                    if (!UpdateProcThreadAttribute(
                            attributeList, 0, ProcThreadAttributeJobList,
                            jobHandleList, checked((nuint)IntPtr.Size), IntPtr.Zero, IntPtr.Zero))
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "The DSH atomic Job-list attribute could not be installed.");
                    }
                }
                startup.AttributeList = attributeList;
            }
            startup.StartupInfo.Size = attributeCount > 0
                ? checked((uint)Marshal.SizeOf<StartupInfoEx>())
                : checked((uint)Marshal.SizeOf<StartupInfo>());
        }
        catch
        {
            standardOutputRead?.Dispose();
            standardOutputWrite?.Dispose();
            standardErrorRead?.Dispose();
            standardErrorWrite?.Dispose();
            nullInput?.Dispose();
            nullOutput?.Dispose();
            if (attributeListInitialized)
            {
                DeleteProcThreadAttributeList(attributeList);
            }
            if (attributeList != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(attributeList);
            }
            if (inheritedHandleList != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(inheritedHandleList);
            }
            if (jobHandleList != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(jobHandleList);
            }
            if (environment != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(environment);
            }
            throw;
        }

        var processInformation = default(ProcessInformation);
        Process? process = null;
        var created = false;
        var assigned = false;
        try
        {
            if (!CreateProcess(
                    applicationName,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    inheritHandles,
                    CreateSuspended
                    | CreateUnicodeEnvironment
                    | CreateNoWindow
                    | (inheritHandles || atomicJob ? ExtendedStartupInfoPresent : 0),
                    environment,
                    Path.GetFullPath(startInfo.WorkingDirectory),
                    ref startup,
                    out processInformation))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "CreateProcessW(CREATE_SUSPENDED) failed for the DSH host.");
            }
            created = true;
            // Successful atomic creation is contained before PID lookup or any managed callback.
            assigned = atomicJob;
            afterNativeCreate?.Invoke(checked((int)processInformation.ProcessId));
            process = Process.GetProcessById(
                checked((int)processInformation.ProcessId));
            _ = process.Handle;
            standardOutputWrite?.Dispose();
            standardOutputWrite = null;
            standardErrorWrite?.Dispose();
            standardErrorWrite = null;

            if (!atomicJob && !AssignProcessToJobObject(_handle, processInformation.ProcessHandle))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "The suspended DSH host could not enter its Job Object.");
            }
            assigned = true;
            if (atomicJob
                && (!IsProcessInJob(processInformation.ProcessHandle, _handle, out var inExactJob)
                    || !inExactJob))
            {
                throw new InvalidOperationException(
                    "The atomically created DSH process is not in its exact Job.");
            }
            if (ReadActiveProcessCount() != 1)
            {
                throw new InvalidOperationException(
                    "The suspended DSH Job Object did not contain exactly one root process before admission.");
            }
            validateBeforeResume(process);
            ThrowIfDisposed();

            var previousSuspendCount = ResumeThread(processInformation.ThreadHandle);
            if (previousSuspendCount == ResumeThreadFailed
                || previousSuspendCount != 1)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "The DSH host primary thread was not resumed exactly once.");
            }

            standardOutput = CreateReader(
                standardOutputRead,
                startInfo.StandardOutputEncoding);
            standardOutputRead = null;
            standardError = CreateReader(
                standardErrorRead,
                startInfo.StandardErrorEncoding);
            standardErrorRead = null;
            var result = new WindowsJobStartedProcess(
                process,
                standardOutput,
                standardError);
            process = null;
            standardOutput = null;
            standardError = null;
            return result;
        }
        catch (Exception launchFailure)
        {
            var containmentSucceeded = false;
            try
            {
                if (assigned)
                {
                    if (!TerminateJobObject(_handle, ContainmentExitCode))
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "TerminateJobObject failed for the rejected DSH host.");
                    }
                    if (WaitForSingleObject(
                            processInformation.ProcessHandle,
                            FailedProcessExitWaitMilliseconds) != WaitObject0)
                    {
                        throw new TimeoutException(
                            "The rejected suspended DSH host did not exit in time.");
                    }
                    WaitForJobEmpty();
                }
                else if (created)
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
                            "The unassigned suspended DSH host could not be terminated.");
                    }
                }
                containmentSucceeded = true;
            }
            catch (Exception containmentFailure)
            {
                var retainedProcess = process
                    ?? throw new InvalidOperationException(
                        "DSH suspended launch containment failed before the exact process handle could be retained.");
                process = null;
                throw new WindowsSuspendedProcessContainmentException(
                    retainedProcess,
                    "DSH suspended launch containment failed; the exact process and Job Object require retained cleanup.",
                    new AggregateException(launchFailure, containmentFailure));
            }
            if (containmentSucceeded)
            {
                ExceptionDispatchInfo.Capture(launchFailure).Throw();
            }
            throw;
        }
        finally
        {
            process?.Dispose();
            standardOutput?.Dispose();
            standardError?.Dispose();
            standardOutputRead?.Dispose();
            standardOutputWrite?.Dispose();
            standardErrorRead?.Dispose();
            standardErrorWrite?.Dispose();
            nullInput?.Dispose();
            nullOutput?.Dispose();
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
            if (attributeListInitialized)
            {
                DeleteProcThreadAttributeList(attributeList);
            }
            if (attributeList != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(attributeList);
            }
            if (inheritedHandleList != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(inheritedHandleList);
            }
            if (jobHandleList != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(jobHandleList);
            }
        }
    }

    public void Dispose()
    {
        lock (_handle)
        {
            if (_handle.IsClosed)
            {
                return;
            }
            _admissionClosed = true;
            if (ReadActiveProcessCount() != 0)
            {
                if (!TerminateJobObject(_handle, ContainmentExitCode))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "The DSH Job Object could not be terminated during disposal.");
                }
                WaitForJobEmpty();
            }
            if (!_emptyRecorded)
            {
                _onJobEmpty?.Invoke();
                _emptyRecorded = true;
            }
            _handle.Dispose();
        }
    }

    private void WaitForJobEmpty()
    {
        var timeout = Stopwatch.StartNew();
        while (timeout.ElapsedMilliseconds < FailedProcessExitWaitMilliseconds)
        {
            if (ReadActiveProcessCount() == 0)
            {
                return;
            }
            Thread.Sleep(10);
        }
        throw new TimeoutException(
            "The rejected DSH Job Object retained active processes.");
    }

    private uint ReadActiveProcessCount()
    {
        if (!QueryInformationJobObject(
                _handle,
                JobObjectBasicAccountingInformationClass,
                out var accounting,
                checked((uint)Marshal.SizeOf<JobObjectBasicAccountingInformation>()),
                IntPtr.Zero))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "The DSH Job Object process count could not be read.");
        }
        return accounting.ActiveProcesses;
    }

    internal uint ReadActiveProcessCountForTest() => ReadActiveProcessCount();

    private void ThrowIfDisposed()
    {
        if (_admissionClosed || _handle.IsClosed)
        {
            throw new ObjectDisposedException(GetType().FullName);
        }
    }

    private static void ValidateDirectStartInfo(ProcessStartInfo startInfo)
    {
        if (string.IsNullOrWhiteSpace(startInfo.FileName)
            || string.IsNullOrWhiteSpace(startInfo.WorkingDirectory)
            || startInfo.UseShellExecute
            || !startInfo.CreateNoWindow
            || startInfo.RedirectStandardInput
            || startInfo.RedirectStandardOutput != startInfo.RedirectStandardError
            || !string.IsNullOrEmpty(startInfo.Arguments))
        {
            throw new InvalidOperationException(
                "DSH suspended launch requires a direct no-window executable and ArgumentList-only command line.");
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

    private static string ToCreateProcessApplicationName(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (fullPath.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase)
            || fullPath.StartsWith("\\\\.\\", StringComparison.OrdinalIgnoreCase)
            || fullPath.Length < MaximumLegacyPathCharacters)
        {
            return fullPath;
        }

        var root = Path.GetPathRoot(fullPath);
        if (!string.IsNullOrEmpty(root)
            && root.Length == 3
            && root[1] == ':'
            && root[2] == Path.DirectorySeparatorChar)
        {
            return "\\\\?\\" + fullPath;
        }
        if (!string.IsNullOrEmpty(root)
            && root.StartsWith("\\\\", StringComparison.Ordinal)
            && root.IndexOf('\\', 2) is var serverSeparator
            && serverSeparator > 2
            && serverSeparator < root.TrimEnd('\\').Length - 1)
        {
            return "\\\\?\\UNC\\" + fullPath.Substring(2);
        }
        return fullPath;
    }

    private static string QuoteWindowsArgument(string value)
    {
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
                    "DSH suspended launch environment contains an invalid entry.");
            }
            environment.Append(pair.Key);
            environment.Append('=');
            environment.Append(pair.Value ?? string.Empty);
            environment.Append('\0');
        }
        environment.Append('\0');
        return Marshal.StringToHGlobalUni(environment.ToString());
    }

    private static void CreateReadPipe(
        ref SecurityAttributes security,
        out SafeFileHandle read,
        out SafeFileHandle write)
    {
        if (!CreatePipe(out read, out write, ref security, 0))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "CreatePipe failed for suspended DSH output capture.");
        }
        if (!SetHandleInformation(read, HandleFlagInherit, 0))
        {
            read.Dispose();
            write.Dispose();
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "The parent DSH pipe handle could not be made non-inheritable.");
        }
    }

    private static SafeFileHandle OpenNullHandle(
        uint desiredAccess,
        ref SecurityAttributes security)
    {
        var handle = CreateFile(
            "NUL",
            desiredAccess,
            FileShareRead | FileShareWrite,
            ref security,
            OpenExisting,
            FileAttributeNormal,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(
                error,
                "A valid inheritable NUL handle could not be opened for DSH.");
        }
        return handle;
    }

    private static StreamReader? CreateReader(
        SafeFileHandle? handle,
        Encoding? encoding)
    {
        if (handle is null)
        {
            return null;
        }
        var stream = new FileStream(
            handle,
            FileAccess.Read,
            bufferSize: 4096,
            isAsync: false);
        return new StreamReader(
            stream,
            encoding ?? Encoding.UTF8,
            detectEncodingFromByteOrderMarks: true,
            bufferSize: 4096,
            leaveOpen: false);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateJobObject(IntPtr jobAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
        SafeFileHandle job,
        int informationClass,
        IntPtr information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsProcessInJob(
        IntPtr process,
        SafeFileHandle job,
        [MarshalAs(UnmanagedType.Bool)] out bool result);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryInformationJobObject(
        SafeFileHandle job,
        int informationClass,
        out JobObjectBasicAccountingInformation information,
        uint informationLength,
        IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateJobObject(SafeFileHandle job, uint exitCode);

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
        ref StartupInfoEx startupInfo,
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

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreatePipe(
        out SafeFileHandle readPipe,
        out SafeFileHandle writePipe,
        ref SecurityAttributes pipeAttributes,
        uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetHandleInformation(
        SafeFileHandle handle,
        uint mask,
        uint flags);

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        ref SecurityAttributes securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(
        IntPtr attributeList,
        int attributeCount,
        int flags,
        ref nuint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(
        IntPtr attributeList,
        uint flags,
        nuint attribute,
        IntPtr value,
        nuint size,
        IntPtr previousValue,
        IntPtr returnSize);

    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

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
    private struct StartupInfoEx
    {
        public StartupInfo StartupInfo;
        public IntPtr AttributeList;
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
    private struct SecurityAttributes
    {
        public uint Length;
        public IntPtr SecurityDescriptor;
        public int InheritHandle;
    }
}

internal sealed class WindowsJobStartedProcess : IDisposable
{
    private StreamReader? _standardOutput;
    private StreamReader? _standardError;

    internal WindowsJobStartedProcess(
        Process process,
        StreamReader? standardOutput,
        StreamReader? standardError)
    {
        Process = process ?? throw new ArgumentNullException(nameof(process));
        _standardOutput = standardOutput;
        _standardError = standardError;
    }

    internal Process Process { get; }

    internal (StreamReader? Output, StreamReader? Error) DetachReaders()
    {
        var output = Interlocked.Exchange(ref _standardOutput, null);
        var error = Interlocked.Exchange(ref _standardError, null);
        return (output, error);
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _standardOutput, null)?.Dispose();
        Interlocked.Exchange(ref _standardError, null)?.Dispose();
    }
}

internal sealed class WindowsSuspendedProcessContainmentException : InvalidOperationException
{
    internal WindowsSuspendedProcessContainmentException(
        Process process,
        string message,
        Exception innerException)
        : base(message, innerException)
    {
        Process = process ?? throw new ArgumentNullException(nameof(process));
    }

    internal Process Process { get; }
}

}
