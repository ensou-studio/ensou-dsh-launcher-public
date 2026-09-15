using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.ExceptionServices;

namespace Ensou.Dsh.Host;

internal sealed class DshUnassignedProcessContainment
{
    private static readonly TimeSpan DefaultTerminationTimeout =
        TimeSpan.FromSeconds(5);
    private static readonly object RegistrySync = new();
    private static readonly List<RetainedLaunch> RetainedLaunches = [];

    private readonly Func<Process, TimeSpan, bool> _terminateAndConfirm;
    private readonly Action<Process> _disposeProcess;
    private readonly Func<Process, bool> _confirmExited;

    public DshUnassignedProcessContainment()
        : this(TerminateAndConfirm)
    {
    }

    internal DshUnassignedProcessContainment(
        Func<Process, TimeSpan, bool> terminateAndConfirm,
        Action<Process>? disposeProcess = null,
        Func<Process, bool>? confirmExited = null)
    {
        _terminateAndConfirm = terminateAndConfirm
            ?? throw new ArgumentNullException(nameof(terminateAndConfirm));
        _disposeProcess = disposeProcess
            ?? (static process => process.Dispose());
        _confirmExited = confirmExited ?? ConfirmExited;
    }

    internal bool HasRetainedProcess
    {
        get
        {
            lock (RegistrySync)
            {
                return RetainedLaunches.Count > 0;
            }
        }
    }

    internal IReadOnlyList<Process> RetainedProcessesForTests
    {
        get
        {
            lock (RegistrySync)
            {
                return RetainedLaunches
                    .Where(static retained => retained.Process is not null)
                    .Select(static retained => retained.Process!)
                    .ToArray();
            }
        }
    }

    [DoesNotReturn]
    internal void ThrowAfterLaunchFailure(
        Process? process,
        Exception launchFailure,
        IDisposable? jobObject = null,
        IDisposable? runtimeLaunchLease = null)
    {
        ArgumentNullException.ThrowIfNull(launchFailure);
        var retained = new RetainedLaunch(
            process,
            jobObject,
            runtimeLaunchLease,
            _terminateAndConfirm,
            _disposeProcess,
            _confirmExited);

        List<Exception> cleanupFailures;
        lock (RegistrySync)
        {
            RetainExactLaunch(retained);
            cleanupFailures = AdvanceCleanup(retained);
            if (retained.IsFullyReleased)
            {
                RemoveExactLaunchAfterCleanup(retained);
            }
        }

        if (cleanupFailures.Count == 0)
        {
            ExceptionDispatchInfo.Capture(launchFailure).Throw();
        }

        var failures = new List<Exception> { launchFailure };
        failures.AddRange(cleanupFailures);
        throw new AggregateException(
            retained.IsFullyReleased
                ? "DSH launch failed and one or more exact launch resources reported cleanup failures."
                : "DSH launch containment failed; the exact job, process, and runtime lease bundle was retained process-wide for a later retry.",
            failures);
    }

    internal void RetryTerminationOrThrow()
    {
        List<Exception> failures = [];
        lock (RegistrySync)
        {
            foreach (var retained in RetainedLaunches.ToArray())
            {
                failures.AddRange(AdvanceCleanup(retained));
                if (retained.IsFullyReleased)
                {
                    RemoveExactLaunchAfterCleanup(retained);
                }
            }
        }

        if (failures.Count > 0)
        {
            throw new AggregateException(
                "One or more exact unassigned DSH launch bundles remain retained process-wide for another stop retry.",
                failures);
        }
    }

    private static void RetainExactLaunch(RetainedLaunch retained)
    {
        if (RetainedLaunches.Any(candidate =>
                retained.Process is not null
                && ReferenceEquals(candidate.Process, retained.Process)))
        {
            throw new InvalidOperationException(
                "The exact unassigned DSH process handle was already retained.");
        }
        if (RetainedLaunches.Any(candidate =>
                retained.JobObject is not null
                && ReferenceEquals(candidate.JobObject, retained.JobObject)))
        {
            throw new InvalidOperationException(
                "The exact DSH launch job handle was already retained.");
        }
        if (RetainedLaunches.Any(candidate =>
                retained.RuntimeLaunchLease is not null
                && ReferenceEquals(
                    candidate.RuntimeLaunchLease,
                    retained.RuntimeLaunchLease)))
        {
            throw new InvalidOperationException(
                "The exact DSH runtime launch lease was already retained.");
        }

        RetainedLaunches.Add(retained);
    }

    private static void RemoveExactLaunchAfterCleanup(RetainedLaunch retained)
    {
        if (!retained.IsFullyReleased)
        {
            throw new InvalidOperationException(
                "An incomplete DSH launch containment bundle cannot be removed.");
        }
        var index = RetainedLaunches.FindIndex(candidate =>
            ReferenceEquals(candidate, retained));
        if (index < 0)
        {
            throw new InvalidOperationException(
                "The released DSH launch bundle did not match the process-wide retained record.");
        }

        RetainedLaunches.RemoveAt(index);
    }

    private static List<Exception> AdvanceCleanup(RetainedLaunch retained)
    {
        List<Exception> failures = [];

        if (!retained.JobClosed)
        {
            try
            {
                retained.JobObject?.Dispose();
                retained.JobClosed = true;
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
        }

        if (!retained.ExitConfirmed)
        {
            var process = retained.Process;
            if (process is null)
            {
                retained.ExitConfirmed = true;
            }
            else
            {
                Exception? terminationFailure = null;
                var terminationReported = false;
                try
                {
                    terminationReported = retained.TerminateAndConfirm(
                        process,
                        DefaultTerminationTimeout);
                }
                catch (Exception exception)
                {
                    terminationFailure = exception;
                }

                Exception? confirmationFailure = null;
                var exitConfirmed = false;
                try
                {
                    exitConfirmed = retained.ConfirmExited(process);
                }
                catch (Exception exception)
                {
                    confirmationFailure = exception;
                }
                if (exitConfirmed)
                {
                    retained.ExitConfirmed = true;
                }
                else
                {
                    if (terminationFailure is not null)
                    {
                        failures.Add(terminationFailure);
                    }
                    if (confirmationFailure is not null)
                    {
                        failures.Add(confirmationFailure);
                    }
                    if (terminationFailure is null
                        && confirmationFailure is null)
                    {
                        failures.Add(terminationReported
                            ? new InvalidOperationException(
                                $"Termination of unassigned DSH process {ReadProcessId(process)} was reported but the exact process was still active.")
                            : new TimeoutException(
                                $"Termination of unassigned DSH process {ReadProcessId(process)} was not confirmed."));
                    }
                    return failures;
                }
            }
        }

        if (!retained.RuntimeLeaseDisposed)
        {
            try
            {
                retained.RuntimeLaunchLease?.Dispose();
                retained.RuntimeLeaseDisposed = true;
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
        }

        if (!retained.ProcessDisposed)
        {
            try
            {
                if (retained.Process is not null)
                {
                    retained.DisposeProcess(retained.Process);
                }
                retained.ProcessDisposed = true;
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
        }

        return failures;
    }

    private static bool TerminateAndConfirm(Process process, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(process);
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }
        if (process.HasExited)
        {
            return true;
        }

        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException) when (process.HasExited)
        {
            return true;
        }

        return process.WaitForExit(checked((int)timeout.TotalMilliseconds))
            && process.HasExited;
    }

    private static bool ConfirmExited(Process process) =>
        process.WaitForExit(milliseconds: 0) && process.HasExited;

    private static int ReadProcessId(Process process)
    {
        try
        {
            return process.Id;
        }
        catch (InvalidOperationException)
        {
            return -1;
        }
    }

    private sealed class RetainedLaunch(
        Process? process,
        IDisposable? jobObject,
        IDisposable? runtimeLaunchLease,
        Func<Process, TimeSpan, bool> terminateAndConfirm,
        Action<Process> disposeProcess,
        Func<Process, bool> confirmExited)
    {
        internal Process? Process { get; } = process;

        internal IDisposable? JobObject { get; } = jobObject;

        internal IDisposable? RuntimeLaunchLease { get; } = runtimeLaunchLease;

        internal Func<Process, TimeSpan, bool> TerminateAndConfirm { get; } =
            terminateAndConfirm;

        internal Action<Process> DisposeProcess { get; } = disposeProcess;

        internal Func<Process, bool> ConfirmExited { get; } = confirmExited;

        internal bool JobClosed { get; set; }

        internal bool ExitConfirmed { get; set; }

        internal bool RuntimeLeaseDisposed { get; set; }

        internal bool ProcessDisposed { get; set; }

        internal bool IsFullyReleased =>
            JobClosed
            && ExitConfirmed
            && RuntimeLeaseDisposed
            && ProcessDisposed;
    }
}
