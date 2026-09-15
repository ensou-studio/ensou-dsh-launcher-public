using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.UpdateEngine;

public sealed class PersonalInstallerExecutableLease : IDisposable
{
    private readonly object _sync = new();
    private FileStream? _stream;
    private int _activeUses;
    private bool _disposeRequested;

    internal PersonalInstallerExecutableLease(string path, FileStream stream)
    {
        Path = path;
        _stream = stream;
    }

    public string Path { get; }

    internal void RequireLive()
    {
        lock (_sync)
        {
            var stream = _stream
                ?? throw new ObjectDisposedException(nameof(PersonalInstallerExecutableLease));
            if (!stream.CanRead || stream.Length <= 0)
            {
                throw new InvalidDataException(
                    "Personal Installer executable identity lease is no longer valid.");
            }
        }
    }

    internal IDisposable Retain()
    {
        lock (_sync)
        {
            RequireLive();
            _activeUses = checked(_activeUses + 1);
            return new RetainedUse(this);
        }
    }

    public void Dispose()
    {
        FileStream? dispose = null;
        lock (_sync)
        {
            _disposeRequested = true;
            if (_activeUses == 0)
            {
                dispose = _stream;
                _stream = null;
            }
        }
        dispose?.Dispose();
    }

    private void Release()
    {
        FileStream? dispose = null;
        lock (_sync)
        {
            _activeUses--;
            if (_activeUses < 0)
            {
                throw new InvalidOperationException(
                    "Personal Installer executable lease use count underflowed.");
            }
            if (_activeUses == 0 && _disposeRequested)
            {
                dispose = _stream;
                _stream = null;
            }
        }
        dispose?.Dispose();
    }

    private sealed class RetainedUse(PersonalInstallerExecutableLease owner) : IDisposable
    {
        private PersonalInstallerExecutableLease? _owner = owner;

        public void Dispose() => Interlocked.Exchange(ref _owner, null)?.Release();
    }
}

internal sealed record PersonalExecutableFileIdentity(
    uint VolumeSerialNumber,
    ulong FileIndex,
    long Length);

/// <summary>
/// Keeps the exact Personal executable that passed Authenticode and compiled-trust
/// admission locked until process creation and the started image identity have
/// both been proved. Personal and Enterprise release trust intentionally remain
/// separate even though their Windows file-identity rules are equivalent.
/// </summary>
public sealed class PersonalTrustedExecutableLaunchLease : IDisposable
{
    private const int MaximumProcessImagePathCharacters = 32_768;
    private const int FailedProcessExitWaitMilliseconds = 5_000;

    private static readonly object RetainedRejectedProcessesSync = new();
    private static readonly HashSet<PersonalTrustedExecutableLaunchLease>
        RetainedRejectedProcesses = [];

    private readonly object _launchAdmissionSync = new();
    private readonly object _rejectedProcessSync = new();
    private readonly List<RetainedRejectedProcess> _rejectedProcesses = [];
    private FileStream? _lockedExecutable;
    private bool _disposeRequested;

    private sealed record RetainedRejectedProcess(
        Process Process,
        Exception RejectionFailure);

    internal PersonalTrustedExecutableLaunchLease(
        string executablePath,
        FileStream lockedExecutable,
        PersonalExecutableFileIdentity identity)
    {
        ExecutablePath = executablePath;
        _lockedExecutable = lockedExecutable;
        Identity = identity;
    }

    public string ExecutablePath { get; }

    internal PersonalExecutableFileIdentity Identity { get; }

    public Process Start(ProcessStartInfo startInfo) =>
        StartCore(
            startInfo,
            value => Process.Start(value)
                ?? throw new InvalidOperationException(
                    "Personal trusted executable process did not start."),
            InspectProcessImage,
            TerminateRejectedProcess,
            admissionAttempted: null);

    public void RequireProcessImage(Process process) =>
        RequireProcessImageCore(
            process,
            TerminateRejectedProcess,
            terminatePreviouslyRejectedProcess: null,
            admissionFailureObserved: null);

    internal void RequireProcessImageForTests(
        Process process,
        Func<Process, TimeSpan, bool> terminateRejectedProcess,
        Func<Process, TimeSpan, bool>? terminatePreviouslyRejectedProcess = null,
        Action? admissionFailureObserved = null) =>
        RequireProcessImageCore(
            process,
            terminateRejectedProcess,
            terminatePreviouslyRejectedProcess,
            admissionFailureObserved);

    internal bool RetainsRejectedProcess(Process process)
    {
        ArgumentNullException.ThrowIfNull(process);
        lock (_rejectedProcessSync)
        {
            return _rejectedProcesses.Any(retained =>
                ReferenceEquals(retained.Process, process));
        }
    }

    private void RequireProcessImageCore(
        Process process,
        Func<Process, TimeSpan, bool> terminateRejectedProcess,
        Func<Process, TimeSpan, bool>? terminatePreviouslyRejectedProcess,
        Action? admissionFailureObserved)
    {
        ArgumentNullException.ThrowIfNull(process);
        ArgumentNullException.ThrowIfNull(terminateRejectedProcess);
        lock (_launchAdmissionSync)
        {
            try
            {
                // External receiver ownership begins at this lease gate. Keep
                // global/local retry, locked identity validation, and rejected
                // process containment within the same admission so no second
                // process can start in the exception-unwind gap.
                RetryRetainedRejectedProcessTerminations(
                    terminatePreviouslyRejectedProcess);
                RetryRejectedProcessTermination(TerminateRejectedProcess);
                var lockedExecutable = _lockedExecutable
                    ?? throw new ObjectDisposedException(
                        nameof(PersonalTrustedExecutableLaunchLease));
                RequireIdentity(
                    GetFileIdentity(lockedExecutable.SafeFileHandle),
                    "before external process image validation");
                var processImage = InspectProcessImage(process);
                RequireIdentity(
                    processImage.Identity,
                    $"for started process image '{processImage.Path}'");
            }
            catch (Exception admissionFailure)
            {
                Exception? observationFailure = null;
                try
                {
                    admissionFailureObserved?.Invoke();
                }
                catch (Exception exception)
                {
                    observationFailure = exception;
                }
                var rejectionFailure = observationFailure is null
                    ? admissionFailure
                    : new AggregateException(
                        admissionFailure,
                        observationFailure);
                try
                {
                    RequireRejectedProcessTerminated(
                        process,
                        rejectionFailure,
                        terminateRejectedProcess,
                        disposeOnConfirmedTermination: false);
                }
                catch (Exception containmentFailure)
                {
                    throw new InvalidOperationException(
                        "Personal rejected process image could not be proven terminated.",
                        containmentFailure);
                }
                if (observationFailure is not null)
                {
                    throw new InvalidOperationException(
                        "Personal process image admission observation failed after the exact rejected process was contained.",
                        rejectionFailure);
                }
                throw;
            }
        }
    }

    internal Process StartForTests(
        ProcessStartInfo startInfo,
        Func<ProcessStartInfo, Process> startProcess,
        Func<Process, PersonalExecutableFileIdentity> inspectProcessImage,
        Func<Process, TimeSpan, bool>? terminateRejectedProcess = null,
        Action? admissionAttempted = null) =>
        StartCore(
            startInfo,
            startProcess,
            process => (inspectProcessImage(process), "test process image"),
            terminateRejectedProcess ?? TerminateRejectedProcess,
            admissionAttempted);

    internal void RetryRejectedProcessTerminationForTests(
        Func<Process, TimeSpan, bool> terminateRejectedProcess) =>
        RetryRejectedProcessTermination(terminateRejectedProcess);

    internal void DisposeForTests(
        Func<Process, TimeSpan, bool> terminateRejectedProcess,
        Action? disposalAttempted = null) =>
        DisposeCore(terminateRejectedProcess, disposalAttempted);

    internal bool HasRetainedRejectedProcessForTests
    {
        get
        {
            lock (_rejectedProcessSync)
            {
                return _rejectedProcesses.Count != 0;
            }
        }
    }

    internal Process? RetainedRejectedProcessForTests
    {
        get
        {
            lock (_rejectedProcessSync)
            {
                return _rejectedProcesses.Count == 1
                    ? _rejectedProcesses[0].Process
                    : null;
            }
        }
    }

    internal Exception? RetainedRejectedProcessFailureForTests
    {
        get
        {
            lock (_rejectedProcessSync)
            {
                return _rejectedProcesses.Count == 1
                    ? _rejectedProcesses[0].RejectionFailure
                    : null;
            }
        }
    }

    internal static int RetainedRejectedProcessCountForTests
    {
        get
        {
            lock (RetainedRejectedProcessesSync)
            {
                return RetainedRejectedProcesses.Count;
            }
        }
    }

    internal PersonalExecutableFileIdentity InspectProcessImageIdentityForTests(
        Process process)
    {
        ArgumentNullException.ThrowIfNull(process);
        return InspectProcessImage(process).Identity;
    }

    public void Dispose() => DisposeCore(
        TerminateRejectedProcess,
        disposalAttempted: null);

    private void DisposeCore(
        Func<Process, TimeSpan, bool> terminateRejectedProcess,
        Action? disposalAttempted)
    {
        ArgumentNullException.ThrowIfNull(terminateRejectedProcess);
        disposalAttempted?.Invoke();
        lock (_launchAdmissionSync)
        {
            FileStream? lockedExecutable = null;
            var requiresContainmentRetry = false;
            lock (_rejectedProcessSync)
            {
                _disposeRequested = true;
                requiresContainmentRetry = _rejectedProcesses.Count != 0;
                if (!requiresContainmentRetry)
                {
                    lockedExecutable = _lockedExecutable;
                    _lockedExecutable = null;
                }
            }
            if (requiresContainmentRetry)
            {
                RetryRejectedProcessTermination(terminateRejectedProcess);
                return;
            }
            lockedExecutable?.Dispose();
        }
    }

    private Process StartCore(
        ProcessStartInfo startInfo,
        Func<ProcessStartInfo, Process> startProcess,
        Func<Process, (PersonalExecutableFileIdentity Identity, string Path)>
            inspectProcessImage,
        Func<Process, TimeSpan, bool> terminateRejectedProcess,
        Action? admissionAttempted)
    {
        ArgumentNullException.ThrowIfNull(startInfo);
        ArgumentNullException.ThrowIfNull(startProcess);
        ArgumentNullException.ThrowIfNull(inspectProcessImage);
        ArgumentNullException.ThrowIfNull(terminateRejectedProcess);
        RetryRetainedRejectedProcessTerminations();
        admissionAttempted?.Invoke();
        lock (_launchAdmissionSync)
        {
            // A concurrent Start may have completed the global empty snapshot
            // before waiting on this lease. Recheck this exact lease only after
            // entering its admission gate so no second process can start while
            // the first rejected process remains uncontained.
            RetryRejectedProcessTermination(TerminateRejectedProcess);
            return StartCoreUnderAdmission(
                startInfo,
                startProcess,
                inspectProcessImage,
                terminateRejectedProcess);
        }
    }

    private Process StartCoreUnderAdmission(
        ProcessStartInfo startInfo,
        Func<ProcessStartInfo, Process> startProcess,
        Func<Process, (PersonalExecutableFileIdentity Identity, string Path)>
            inspectProcessImage,
        Func<Process, TimeSpan, bool> terminateRejectedProcess)
    {
        var lockedExecutable = _lockedExecutable
            ?? throw new ObjectDisposedException(
                nameof(PersonalTrustedExecutableLaunchLease));
        if (string.IsNullOrWhiteSpace(startInfo.FileName)
            || !string.Equals(
                Path.GetFullPath(startInfo.FileName),
                ExecutablePath,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Personal trusted process start must use the verified executable path.");
        }

        RequireIdentity(
            GetFileIdentity(lockedExecutable.SafeFileHandle),
            "before process creation");

        Process? process = null;
        try
        {
            process = startProcess(startInfo)
                ?? throw new InvalidOperationException(
                    "Personal trusted executable process did not start.");
            var processImage = inspectProcessImage(process);
            RequireIdentity(
                processImage.Identity,
                $"for started process image '{processImage.Path}'");
            return process;
        }
        catch (Exception admissionFailure)
        {
            if (process is not null)
            {
                try
                {
                    RequireRejectedProcessTerminated(
                        process,
                        admissionFailure,
                        terminateRejectedProcess);
                }
                catch (Exception containmentFailure)
                {
                    throw new InvalidOperationException(
                        "Personal rejected process image could not be proven terminated.",
                        containmentFailure);
                }
            }
            throw;
        }
    }

    internal void RequireRejectedProcessTerminated(
        Process process,
        Exception rejectionFailure,
        Func<Process, TimeSpan, bool>? terminateRejectedProcess = null,
        bool disposeOnConfirmedTermination = true)
    {
        ArgumentNullException.ThrowIfNull(process);
        ArgumentNullException.ThrowIfNull(rejectionFailure);
        var terminate = terminateRejectedProcess ?? TerminateRejectedProcess;
        ArgumentNullException.ThrowIfNull(terminate);

        Exception? terminationFailure = null;
        var terminationReported = false;
        try
        {
            terminationReported = terminate(
                process,
                TimeSpan.FromMilliseconds(FailedProcessExitWaitMilliseconds));
        }
        catch (Exception exception)
        {
            terminationFailure = exception;
        }

        Exception? confirmationFailure = null;
        var exited = false;
        try
        {
            exited = process.WaitForExit(0) && process.HasExited;
        }
        catch (Exception exception)
        {
            confirmationFailure = exception;
        }
        if (exited)
        {
            if (disposeOnConfirmedTermination)
            {
                process.Dispose();
            }
            return;
        }

        RetainRejectedProcess(process, rejectionFailure);
        var failures = new List<Exception> { rejectionFailure };
        if (terminationFailure is not null)
        {
            failures.Add(terminationFailure);
        }
        if (confirmationFailure is not null)
        {
            failures.Add(confirmationFailure);
        }
        if (!terminationReported)
        {
            failures.Add(new TimeoutException(
                "Personal rejected process termination was not confirmed within the containment bound."));
        }
        else
        {
            failures.Add(new InvalidOperationException(
                "Personal rejected process termination reported success while the exact process was still active."));
        }
        throw new InvalidOperationException(
            "Personal rejected process remains retained for fail-closed termination retry.",
            new AggregateException(failures));
    }

    private void RetainRejectedProcess(
        Process process,
        Exception rejectionFailure)
    {
        ArgumentNullException.ThrowIfNull(rejectionFailure);
        lock (_rejectedProcessSync)
        {
            if (!_rejectedProcesses.Any(retained =>
                    ReferenceEquals(retained.Process, process)))
            {
                _rejectedProcesses.Add(new RetainedRejectedProcess(
                    process,
                    rejectionFailure));
            }
            lock (RetainedRejectedProcessesSync)
            {
                RetainedRejectedProcesses.Add(this);
            }
        }
    }

    private void RetryRejectedProcessTermination(
        Func<Process, TimeSpan, bool> terminateRejectedProcess)
    {
        ArgumentNullException.ThrowIfNull(terminateRejectedProcess);
        FileStream? lockedExecutable = null;
        List<Exception>? failures = null;
        lock (_rejectedProcessSync)
        {
            if (_rejectedProcesses.Count == 0)
            {
                return;
            }

            foreach (var retained in _rejectedProcesses.ToArray())
            {
                try
                {
                    RequireRejectedProcessTerminated(
                        retained.Process,
                        retained.RejectionFailure,
                        terminateRejectedProcess);
                    _rejectedProcesses.Remove(retained);
                }
                catch (Exception exception)
                {
                    (failures ??= []).Add(exception);
                }
            }
            if (_rejectedProcesses.Count == 0)
            {
                if (_disposeRequested)
                {
                    lockedExecutable = _lockedExecutable;
                    _lockedExecutable = null;
                }
                lock (RetainedRejectedProcessesSync)
                {
                    RetainedRejectedProcesses.Remove(this);
                }
            }
        }
        lockedExecutable?.Dispose();
        if (failures is not null)
        {
            throw new InvalidOperationException(
                "One or more rejected Personal processes remain retained for containment retry.",
                new AggregateException(failures));
        }
    }

    private static void RetryRetainedRejectedProcessTerminations(
        Func<Process, TimeSpan, bool>? terminateRejectedProcess = null)
    {
        var terminate = terminateRejectedProcess ?? TerminateRejectedProcess;
        PersonalTrustedExecutableLaunchLease[] retained;
        lock (RetainedRejectedProcessesSync)
        {
            retained = [.. RetainedRejectedProcesses];
        }
        List<Exception>? failures = null;
        foreach (var lease in retained)
        {
            try
            {
                lease.RetryRejectedProcessTermination(terminate);
            }
            catch (Exception exception)
            {
                (failures ??= []).Add(exception);
            }
        }
        if (failures is not null)
        {
            throw new InvalidOperationException(
                "Personal trusted launch is blocked by an unterminated rejected process.",
                new AggregateException(failures));
        }
    }

    private static bool TerminateRejectedProcess(Process process, TimeSpan timeout)
    {
        if (!process.HasExited)
        {
            process.Kill(entireProcessTree: true);
        }
        return process.WaitForExit(checked((int)timeout.TotalMilliseconds))
            && process.HasExited;
    }

    private void RequireIdentity(
        PersonalExecutableFileIdentity actual,
        string stage)
    {
        if (actual.VolumeSerialNumber != Identity.VolumeSerialNumber
            || actual.FileIndex != Identity.FileIndex
            || actual.Length != Identity.Length)
        {
            throw new InvalidDataException(
                $"Personal started process image identity does not match the verified executable {stage}. Expected path: {ExecutablePath}");
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
                "Unable to inspect the Personal process image path.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }
        return Path.GetFullPath(path.ToString(0, checked((int)length)));
    }

    private static (PersonalExecutableFileIdentity Identity, string Path)
        InspectProcessImage(Process process)
    {
        var processImagePath = ReadProcessImagePath(process);
        using var processImage = PersonalAuthenticodeVerifier
            .OpenLockedExecutable(processImagePath);
        PersonalAuthenticodeVerifier.RequireSingleLinkExecutableHandle(
            processImage.SafeFileHandle);
        return (
            GetFileIdentity(processImage.SafeFileHandle),
            processImagePath);
    }

    internal static PersonalExecutableFileIdentity GetFileIdentity(
        SafeFileHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Personal process image identity requires Windows file handles.");
        }
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw new IOException(
                "Unable to read the Personal executable file identity.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }
        if ((information.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0
            || information.NumberOfLinks != 1)
        {
            throw new InvalidDataException(
                "Personal executable identity must be a single-link regular file.");
        }

        var length = checked((long)(
            ((ulong)information.FileSizeHigh << 32)
            | information.FileSizeLow));
        if (length <= 0)
        {
            throw new InvalidDataException(
                "Personal executable identity is empty.");
        }
        return new PersonalExecutableFileIdentity(
            information.VolumeSerialNumber,
            ((ulong)information.FileIndexHigh << 32)
                | information.FileIndexLow,
            length);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        IntPtr process,
        uint flags,
        StringBuilder executableName,
        ref uint size);

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

public static partial class PersonalAuthenticodeVerifier
{
    private const uint WtdUiNone = 2;
    private const uint WtdRevokeWholeChain = 1;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionIgnore = 0;
    private const uint WtdRevocationCheckChainExcludeRoot = 0x00000080;
    private const uint WtdCacheOnlyUrlRetrieval = 0x00001000;
    private static readonly Guid GenericVerifyAction =
        new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    public static void RequireTrustedEnsouExecutable(string filePath)
    {
        var metadata = typeof(PersonalAuthenticodeVerifier).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .ToDictionary(attribute => attribute.Key, attribute => attribute.Value, StringComparer.Ordinal);
        var production = metadata.TryGetValue("PersonalProductionBuild", out var build)
            && string.Equals(build, "true", StringComparison.OrdinalIgnoreCase);
        if (!production)
        {
            return;
        }
        if (!metadata.TryGetValue(
                "PersonalAuthenticodeSignerSha256Thumbprint",
                out var expected)
            || string.IsNullOrWhiteSpace(expected))
        {
            throw new InvalidOperationException(
                "Production Personal Authenticode signer trust is not compiled into this build.");
        }
        RequireTrustedSignature(filePath, expected);
    }

    public static string RequireSha256Thumbprint(string value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || !Sha256ThumbprintPattern().IsMatch(value))
        {
            throw new InvalidDataException(
                "Personal Authenticode signer must be one SHA-256 certificate thumbprint.");
        }
        return value.ToUpperInvariant();
    }

    public static void RequireTrustedSignature(string filePath, string expectedThumbprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Personal production executable verification requires Windows Authenticode.");
        }
        expectedThumbprint = RequireSha256Thumbprint(expectedThumbprint);
        var absolutePath = Path.GetFullPath(filePath);
        RejectLinkAncestors(Path.GetDirectoryName(absolutePath)!);
        if (!File.Exists(absolutePath)
            || (File.GetAttributes(absolutePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Personal executable path is missing or linked.");
        }

        using var lockedFile = OpenLockedExecutable(absolutePath);
        PersonalManagedOperationLockHandleSafety.RequireSingleLinkHandle(
            lockedFile.SafeFileHandle);
        VerifyTrustedSignatureOnLockedFile(
            absolutePath,
            lockedFile,
            expectedThumbprint);
    }

    public static PersonalInstallerExecutableLease AcquireCurrentInstallerExecutableLease(
        Assembly entryAssembly,
        string expectedExecutableName,
        PersonalInstallerTrustConfiguration entryTrust)
    {
        ArgumentNullException.ThrowIfNull(entryAssembly);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedExecutableName);
        ArgumentNullException.ThrowIfNull(entryTrust);
        if (!ReferenceEquals(Assembly.GetEntryAssembly(), entryAssembly)
            || !string.Equals(
                Path.GetFileName(expectedExecutableName),
                expectedExecutableName,
                StringComparison.Ordinal)
            || !string.Equals(
                Path.GetExtension(expectedExecutableName),
                ".exe",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Personal Installer entry assembly or expected executable name is invalid.");
        }
        var processPath = Environment.ProcessPath
            ?? throw new InvalidOperationException(
                "Unable to identify the current Personal Installer executable.");
        var absolutePath = Path.GetFullPath(processPath);
        if (!string.Equals(
                Path.GetFileName(absolutePath),
                expectedExecutableName,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal Installer process path has an unexpected executable name.");
        }
        RejectLinkAncestors(Path.GetDirectoryName(absolutePath)!);
        if (!File.Exists(absolutePath)
            || (File.GetAttributes(absolutePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Personal Installer process executable is missing or linked.");
        }

        var lockedFile = OpenLockedExecutable(absolutePath);
        try
        {
            PersonalManagedOperationLockHandleSafety.RequireSingleLinkHandle(
                lockedFile.SafeFileHandle);
            var engineTrust = PersonalInstallerTrustConfiguration.ReadCompiled(
                typeof(PersonalAuthenticodeVerifier).Assembly);
            RequireMatchingCompiledTrust(entryTrust, engineTrust);
            if (entryTrust.ProductionBuild)
            {
                VerifyTrustedSignatureOnLockedFile(
                    absolutePath,
                    lockedFile,
                    entryTrust.AuthenticodeSignerSha256Thumbprint
                        ?? throw new InvalidOperationException(
                            "Production Personal Installer signer trust is missing."));
            }
            return new PersonalInstallerExecutableLease(absolutePath, lockedFile);
        }
        catch
        {
            lockedFile.Dispose();
            throw;
        }
    }

    internal static void RequireMatchingCompiledTrust(
        PersonalInstallerTrustConfiguration entry,
        PersonalInstallerTrustConfiguration engine)
    {
        var left = entry.ReleasePolicy;
        var right = engine.ReleasePolicy;
        if (entry.ProductionBuild != engine.ProductionBuild
            || entry.ManifestOrigin != engine.ManifestOrigin
            || left.ArtifactOrigin != right.ArtifactOrigin
            || !string.Equals(left.Product, right.Product, StringComparison.Ordinal)
            || !string.Equals(left.Environment, right.Environment, StringComparison.Ordinal)
            || !string.Equals(left.Channel, right.Channel, StringComparison.Ordinal)
            || !string.Equals(
                left.StartupStubVersion,
                right.StartupStubVersion,
                StringComparison.Ordinal)
            || left.CanonicalLowSFromSequence != right.CanonicalLowSFromSequence
            || !string.Equals(
                entry.AuthenticodeSignerSha256Thumbprint,
                engine.AuthenticodeSignerSha256Thumbprint,
                StringComparison.Ordinal)
            || left.TrustedKeys.Count != 1
            || right.TrustedKeys.Count != 1
            || !string.Equals(left.TrustedKeys[0].KeyId, right.TrustedKeys[0].KeyId, StringComparison.Ordinal)
            || !string.Equals(left.TrustedKeys[0].X, right.TrustedKeys[0].X, StringComparison.Ordinal)
            || !string.Equals(left.TrustedKeys[0].Y, right.TrustedKeys[0].Y, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Personal Installer and UpdateEngine compiled release trust metadata disagree.");
        }
    }

    internal static void RequireMatchingCompiledTrustForTests(
        PersonalInstallerTrustConfiguration entry,
        PersonalInstallerTrustConfiguration engine) =>
        RequireMatchingCompiledTrust(entry, engine);

    internal static PersonalInstallerExecutableLease AcquireExecutableIdentityLeaseForTests(
        string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        var absolutePath = Path.GetFullPath(filePath);
        RejectLinkAncestors(Path.GetDirectoryName(absolutePath)!);
        if (!File.Exists(absolutePath)
            || (File.GetAttributes(absolutePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Personal Installer test executable is missing or linked.");
        }

        var lockedFile = OpenLockedExecutable(absolutePath);
        try
        {
            PersonalManagedOperationLockHandleSafety.RequireSingleLinkHandle(
                lockedFile.SafeFileHandle);
            return new PersonalInstallerExecutableLease(absolutePath, lockedFile);
        }
        catch
        {
            lockedFile.Dispose();
            throw;
        }
    }

    internal static PersonalInstallerExecutableLease AcquireTrustedExecutableLease(
        string filePath,
        PersonalCompiledTrustFingerprint expectedTrust)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        ArgumentNullException.ThrowIfNull(expectedTrust);
        var absolutePath = Path.GetFullPath(filePath);
        RejectLinkAncestors(Path.GetDirectoryName(absolutePath)!);
        if (!File.Exists(absolutePath)
            || (File.GetAttributes(absolutePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Personal executable is missing or linked before its trust lease.");
        }

        var lockedFile = OpenLockedExecutable(absolutePath);
        try
        {
            PersonalManagedOperationLockHandleSafety.RequireSingleLinkHandle(
                lockedFile.SafeFileHandle);
            if (expectedTrust.ProductionBuild)
            {
                VerifyTrustedSignatureOnLockedFile(
                    absolutePath,
                    lockedFile,
                    expectedTrust.AuthenticodeSignerSha256Thumbprint
                        ?? throw new InvalidOperationException(
                            "Production Personal executable trust has no signer identity."));
            }
            return new PersonalInstallerExecutableLease(absolutePath, lockedFile);
        }
        catch
        {
            lockedFile.Dispose();
            throw;
        }
    }

    internal static PersonalTrustedExecutableLaunchLease
        OpenTrustedExecutableForLaunch(
            string filePath,
            PersonalCompiledTrustFingerprint expectedTrust)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        ArgumentNullException.ThrowIfNull(expectedTrust);
        var absolutePath = Path.GetFullPath(filePath);
        RejectLinkAncestors(Path.GetDirectoryName(absolutePath)!);
        if (!File.Exists(absolutePath)
            || (File.GetAttributes(absolutePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Personal executable is missing or linked before its trusted launch lease.");
        }

        var lockedFile = OpenLockedExecutable(absolutePath);
        try
        {
            RequireSingleLinkExecutableHandle(lockedFile.SafeFileHandle);
            var identity = PersonalTrustedExecutableLaunchLease.GetFileIdentity(
                lockedFile.SafeFileHandle);
            if (identity.Length != lockedFile.Length)
            {
                throw new IOException(
                    "Personal executable identity length is inconsistent.");
            }
            if (expectedTrust.ProductionBuild)
            {
                VerifyTrustedSignatureOnLockedFile(
                    absolutePath,
                    lockedFile,
                    expectedTrust.AuthenticodeSignerSha256Thumbprint
                        ?? throw new InvalidOperationException(
                            "Production Personal executable trust has no signer identity."));
            }
            if (PersonalTrustedExecutableLaunchLease.GetFileIdentity(
                    lockedFile.SafeFileHandle) != identity)
            {
                throw new IOException(
                    "Personal executable changed while its trusted launch identity was verified.");
            }
            return new PersonalTrustedExecutableLaunchLease(
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

    internal static PersonalTrustedExecutableLaunchLease
        OpenExecutableForLaunchForTests(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        var absolutePath = Path.GetFullPath(filePath);
        RejectLinkAncestors(Path.GetDirectoryName(absolutePath)!);
        if (!File.Exists(absolutePath)
            || (File.GetAttributes(absolutePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Personal test executable is missing or linked.");
        }

        var lockedFile = OpenLockedExecutable(absolutePath);
        try
        {
            RequireSingleLinkExecutableHandle(lockedFile.SafeFileHandle);
            var identity = PersonalTrustedExecutableLaunchLease.GetFileIdentity(
                lockedFile.SafeFileHandle);
            return new PersonalTrustedExecutableLaunchLease(
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

    internal static void RequireSingleLinkExecutableHandle(SafeFileHandle handle) =>
        PersonalManagedOperationLockHandleSafety.RequireSingleLinkHandle(handle);

    private static void VerifyTrustedSignatureOnLockedFile(
        string absolutePath,
        FileStream lockedFile,
        string expectedThumbprint)
    {
        expectedThumbprint = RequireSha256Thumbprint(expectedThumbprint);
        var lockedLength = lockedFile.Length;

        var fileInfo = new WinTrustFileInfo(absolutePath, lockedFile.SafeFileHandle);
        var fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, fDeleteOld: false);
            var trustData = new WinTrustData(fileInfoPointer);
            var status = WinVerifyTrust(IntPtr.Zero, GenericVerifyAction, ref trustData);
            if (status != 0)
            {
                throw new InvalidDataException(
                    $"Personal executable Authenticode verification failed: 0x{status:X8}");
            }

#pragma warning disable SYSLIB0057
            using var signer = new X509Certificate2(
                X509Certificate.CreateFromSignedFile(absolutePath));
#pragma warning restore SYSLIB0057
            var actual = signer.GetCertHashString(HashAlgorithmName.SHA256);
            if (!string.Equals(actual, expectedThumbprint, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "Personal executable signer does not match the compiled Ensou signer identity.");
            }
            if (lockedFile.Length != lockedLength)
            {
                throw new IOException(
                    "Personal executable changed while its signature was verified.");
            }
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPointer);
            Marshal.FreeHGlobal(fileInfoPointer);
            fileInfo.Dispose();
        }
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
            throw new InvalidDataException("Personal executable is empty.");
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
                    "Personal executable path may not cross a filesystem link.");
            }
        }
    }

    [DllImport("wintrust.dll", EntryPoint = "WinVerifyTrust", SetLastError = true)]
    private static extern int WinVerifyTrust(
        IntPtr window,
        in Guid actionId,
        ref WinTrustData trustData);

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
            StateAction = WtdStateActionIgnore;
            StateData = IntPtr.Zero;
            UrlReference = IntPtr.Zero;
            ProviderFlags = WtdRevocationCheckChainExcludeRoot
                | WtdCacheOnlyUrlRetrieval;
            UiContext = 0;
            SignatureSettings = IntPtr.Zero;
        }
    }

    [GeneratedRegex("^[0-9A-Fa-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256ThumbprintPattern();
}
