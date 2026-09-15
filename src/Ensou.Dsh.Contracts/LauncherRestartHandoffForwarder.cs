using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.Contracts;

[SupportedOSPlatform("windows")]
public static class LauncherRestartHandoffForwarder
{
    public static void WaitForFinalReceiver(
        PersonalLauncherRestartHandoffCommand command,
        Process forwardedProcess,
        TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(forwardedProcess);
        var effectiveTimeout = timeout ?? TimeSpan.FromMinutes(3);
        if (effectiveTimeout < TimeSpan.FromSeconds(1)
            || effectiveTimeout > TimeSpan.FromMinutes(3))
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        try
        {
            WaitForFinalReceiverCore(command, forwardedProcess, effectiveTimeout);
        }
        catch (Exception forwardingFailure)
        {
            // This forwarder owns the child until the receiver is armed. It must
            // not exit first and leave a detached child racing the parent's retry.
            try
            {
                if (!forwardedProcess.HasExited)
                {
                    forwardedProcess.Kill(entireProcessTree: true);
                }
                if (!forwardedProcess.WaitForExit(5000))
                {
                    throw new TimeoutException(
                        "Cancelled restart forwarding did not confirm child exit.");
                }
            }
            catch (Exception cleanupFailure)
            {
                throw new AggregateException(
                    "Restart forwarding failed and owned child cleanup was not confirmed.",
                    forwardingFailure,
                    cleanupFailure);
            }
            throw;
        }
    }

    private static void WaitForFinalReceiverCore(
        PersonalLauncherRestartHandoffCommand command,
        Process forwardedProcess,
        TimeSpan effectiveTimeout)
    {
        using var armed = EventWaitHandle.OpenExisting(command.ArmedEventName);
        using var failure = EventWaitHandle.OpenExisting(
            command.FailureEventName);
        using var cancellation = EventWaitHandle.OpenExisting(
            command.CancellationEventName);
        using var forwardedExit = new ForwardedProcessWaitHandle(
            forwardedProcess);
        var result = WaitHandle.WaitAny(
            [armed, failure, cancellation, forwardedExit],
            effectiveTimeout);
        if (result == 0)
        {
            return;
        }
        if (result == 1)
        {
            throw new InvalidOperationException(
                "The final Launcher rejected restart handoff forwarding.");
        }
        if (result == 2)
        {
            throw new OperationCanceledException(
                "Restart handoff forwarding was cancelled before final Launcher connection.");
        }
        if (result == 3)
        {
            if (armed.WaitOne(0))
            {
                return;
            }
            throw new InvalidOperationException(
                $"Restart handoff forwarder exited before final Launcher connection (exit {forwardedProcess.ExitCode}).");
        }
        if (result == WaitHandle.WaitTimeout)
        {
            throw new TimeoutException(
                "Restart handoff forwarding timed out before final Launcher connection.");
        }

        throw new InvalidOperationException(
            "Restart handoff forwarding returned an invalid wait result.");
    }

    private sealed class ForwardedProcessWaitHandle : WaitHandle
    {
        internal ForwardedProcessWaitHandle(Process process)
        {
            SafeWaitHandle = new SafeWaitHandle(
                process.Handle,
                ownsHandle: false);
        }
    }
}
