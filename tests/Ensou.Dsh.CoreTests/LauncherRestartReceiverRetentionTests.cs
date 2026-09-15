using System.Diagnostics;
using Ensou.Dsh.Host;
using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.CoreTests;

internal static partial class Program
{
    private static Task PersonalLauncherRestartRetainsRejectedReceiverHandleAsync()
    {
        var root = Path.Combine(
            TempRoot,
            "launcher-restart-retained-receiver",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var source = Environment.GetEnvironmentVariable("ComSpec")
            ?? throw new InvalidOperationException("ComSpec is unavailable.");
        var expectedExecutable = Path.Combine(root, "expected-launcher.exe");
        var mismatchedExecutable = Path.Combine(root, "mismatched-launcher.exe");
        var replacementExecutable = Path.Combine(root, "replacement-launcher.exe");
        File.Copy(source, expectedExecutable);
        File.Copy(source, mismatchedExecutable);
        File.Copy(source, replacementExecutable);

        var lease = PersonalAuthenticodeVerifier
            .OpenExecutableForLaunchForTests(expectedExecutable);
        Process? rejectedProcess = null;
        try
        {
            rejectedProcess = Process.Start(CreateRetainedReceiverStartInfo(
                    mismatchedExecutable,
                    root))
                ?? throw new InvalidOperationException(
                    "Rejected Launcher receiver test process did not start.");
            var rejectedProcessId = rejectedProcess.Id;
            var exactHandleObserved = false;
            Exception? validationFailure = null;
            try
            {
                lease.RequireProcessImageForTests(
                    rejectedProcess,
                    (process, _) =>
                    {
                        exactHandleObserved = ReferenceEquals(
                            process,
                            rejectedProcess);
                        // A positive delegate result is never sufficient proof:
                        // the exact OS process must independently be observed exited.
                        return true;
                    });
            }
            catch (InvalidOperationException exception)
            {
                validationFailure = exception;
            }

            AssertTrue(validationFailure is not null);
            AssertTrue(exactHandleObserved);
            AssertFalse(rejectedProcess.HasExited);
            AssertTrue(lease.RetainsRejectedProcess(rejectedProcess));

            var marker = new LauncherRestartReceiverProcessRetainedException(
                rejectedProcess,
                validationFailure!);
            LauncherRestartCoordinator
                .DisposeReceiverAfterValidationFailureForTests(
                    rejectedProcess,
                    marker);
            AssertEqual(rejectedProcessId, rejectedProcess.Id);
            AssertFalse(rejectedProcess.HasExited);

            var unrelatedProcessHandle = Process.GetProcessById(
                Environment.ProcessId);
            LauncherRestartCoordinator
                .DisposeReceiverAfterValidationFailureForTests(
                    unrelatedProcessHandle,
                    marker);
            var unrelatedHandleDisposed = false;
            try
            {
                _ = unrelatedProcessHandle.HasExited;
            }
            catch (InvalidOperationException)
            {
                unrelatedHandleDisposed = true;
            }
            AssertTrue(unrelatedHandleDisposed);

            var disposeFailedClosed = false;
            try
            {
                lease.DisposeForTests((_, _) => false);
            }
            catch (InvalidOperationException)
            {
                disposeFailedClosed = true;
            }
            AssertTrue(disposeFailedClosed);
            AssertTrue(lease.RetainsRejectedProcess(rejectedProcess));
            AssertRetainedReceiverMutationDenied(() => File.Move(
                replacementExecutable,
                expectedExecutable,
                overwrite: true));

            lease.RetryRejectedProcessTerminationForTests(
                TerminateRetainedReceiverProcess);
            AssertTrue(WaitForRetainedReceiverExit(rejectedProcessId));
            AssertFalse(lease.RetainsRejectedProcess(rejectedProcess));
            File.Move(
                replacementExecutable,
                expectedExecutable,
                overwrite: true);
        }
        finally
        {
            StopRetainedReceiverProcess(rejectedProcess);
            try
            {
                lease.RetryRejectedProcessTerminationForTests(
                    TerminateRetainedReceiverProcess);
            }
            catch
            {
                // Preserve the primary assertion while retaining the exact handle.
            }
            try
            {
                lease.Dispose();
            }
            catch
            {
                // A containment failure must remain visible through the primary test.
            }
            rejectedProcess?.Dispose();
        }
        return Task.CompletedTask;
    }

    private static ProcessStartInfo CreateRetainedReceiverStartInfo(
        string executable,
        string workingDirectory)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        startInfo.ArgumentList.Add("/d");
        startInfo.ArgumentList.Add("/c");
        startInfo.ArgumentList.Add("ping -t 127.0.0.1 > nul");
        return startInfo;
    }

    private static bool TerminateRetainedReceiverProcess(
        Process process,
        TimeSpan timeout)
    {
        if (!process.HasExited)
        {
            process.Kill(entireProcessTree: true);
        }
        return process.WaitForExit(checked((int)timeout.TotalMilliseconds))
            && process.HasExited;
    }

    private static void StopRetainedReceiverProcess(Process? process)
    {
        try
        {
            if (process is not null && !process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5_000);
            }
        }
        catch
        {
            // Preserve the test failure while containing only its helper process.
        }
    }

    private static bool WaitForRetainedReceiverExit(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return process.HasExited
                || (process.WaitForExit(5_000) && process.HasExited);
        }
        catch (ArgumentException)
        {
            return true;
        }
    }

    private static void AssertRetainedReceiverMutationDenied(Action mutation)
    {
        try
        {
            mutation();
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            return;
        }
        throw new InvalidOperationException(
            "Expected the retained receiver file lease to deny mutation.");
    }
}
