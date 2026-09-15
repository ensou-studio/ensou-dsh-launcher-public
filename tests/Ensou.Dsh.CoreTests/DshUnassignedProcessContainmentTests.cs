using System.ComponentModel;
using System.Diagnostics;
using Ensou.Dsh.Host;

namespace Ensou.Dsh.CoreTests;

internal static class DshUnassignedProcessContainmentTests
{
    internal static async Task RunAsync()
    {
        using var process = StartHiddenPingProcess();
        using var observer = Process.GetProcessById(process.Id);
        var terminationAttempts = 0;
        var containment = new DshUnassignedProcessContainment(
            (candidate, timeout) =>
            {
                AssertTrue(ReferenceEquals(candidate, process));
                AssertTrue(timeout == TimeSpan.FromSeconds(5));
                terminationAttempts++;
                if (terminationAttempts == 1)
                {
                    throw new Win32Exception(
                        5,
                        "Synthetic unassigned-process Kill failure.");
                }
                if (terminationAttempts == 2)
                {
                    return true;
                }
                if (terminationAttempts == 3)
                {
                    return false;
                }

                candidate.Kill(entireProcessTree: true);
                return candidate.WaitForExit(checked((int)timeout.TotalMilliseconds))
                    && candidate.HasExited;
            });
        var independentContainment = new DshUnassignedProcessContainment(
            static (_, _) => throw new InvalidOperationException(
                "A process-wide retry must use the cleanup policy retained with the exact launch bundle."));
        var assignmentFailure = new Win32Exception(
            5,
            "Synthetic AssignProcessToJobObject failure.");
        var runtimeLaunchLease = new TrackingDisposable();

        try
        {
            var launchException = AssertThrows<AggregateException>(() =>
                containment.ThrowAfterLaunchFailure(
                    process,
                    assignmentFailure,
                    runtimeLaunchLease: runtimeLaunchLease));
            AssertTrue(launchException.Flatten().InnerExceptions.Any(exception =>
                ReferenceEquals(exception, assignmentFailure)));
            AssertEqual(1, terminationAttempts);
            AssertTrue(containment.HasRetainedProcess);
            AssertTrue(independentContainment.HasRetainedProcess);
            AssertEqual(1, containment.RetainedProcessesForTests.Count);
            AssertTrue(ReferenceEquals(
                process,
                containment.RetainedProcessesForTests.Single()));
            AssertFalse(observer.HasExited);
            AssertFalse(runtimeLaunchLease.IsDisposed);

            var falselyReportedTermination = AssertThrows<AggregateException>(
                independentContainment.RetryTerminationOrThrow);
            AssertEqual(2, terminationAttempts);
            AssertTrue(falselyReportedTermination.Flatten().InnerExceptions.Any(exception =>
                exception is InvalidOperationException
                && exception.Message.Contains("was reported", StringComparison.Ordinal)));
            AssertTrue(containment.HasRetainedProcess);
            AssertTrue(ReferenceEquals(
                process,
                containment.RetainedProcessesForTests.Single()));
            AssertFalse(observer.HasExited);
            AssertFalse(runtimeLaunchLease.IsDisposed);

            var unconfirmedTermination = AssertThrows<AggregateException>(
                independentContainment.RetryTerminationOrThrow);
            AssertEqual(3, terminationAttempts);
            AssertTrue(unconfirmedTermination.Flatten().InnerExceptions.Any(exception =>
                exception is TimeoutException));
            AssertTrue(containment.HasRetainedProcess);
            AssertTrue(ReferenceEquals(
                process,
                containment.RetainedProcessesForTests.Single()));
            AssertFalse(observer.HasExited);
            AssertFalse(runtimeLaunchLease.IsDisposed);

            independentContainment.RetryTerminationOrThrow();
            AssertEqual(4, terminationAttempts);
            await observer.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            AssertTrue(observer.HasExited);
            AssertFalse(containment.HasRetainedProcess);
            AssertFalse(independentContainment.HasRetainedProcess);
            AssertEqual(0, containment.RetainedProcessesForTests.Count);
            AssertTrue(runtimeLaunchLease.IsDisposed);
        }
        finally
        {
            if (!observer.HasExited)
            {
                observer.Kill(entireProcessTree: true);
                await observer.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            }
        }

        await RealRuntimeLeaseRemainsLockedUntilExitConfirmedAsync();
        await CleanupFailuresRetainExactBundleAsync();
        await ExitInspectionFailuresRemainRetainedAsync();
    }

    private static async Task RealRuntimeLeaseRemainsLockedUntilExitConfirmedAsync()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "ensou-dsh-retained-runtime-lease-tests",
            Guid.NewGuid().ToString("N"));
        var runtime = Path.Combine(root, "runtime");
        var node = Path.Combine(runtime, "node.exe");
        var entry = Path.Combine(
            runtime,
            "node_modules",
            "@deepseek-ai",
            "dsh",
            "lib",
            "bin.js");
        var trustMetadata = Path.Combine(runtime, ".ensou-release.json");
        Directory.CreateDirectory(Path.GetDirectoryName(entry)!);
        File.Copy(Path.Combine(Environment.SystemDirectory, "cmd.exe"), node);
        File.WriteAllText(entry, "console.log('retained');");
        File.WriteAllText(trustMetadata, "{\"schemaVersion\":1}");
        using var process = StartHiddenPingProcess();
        using var observer = Process.GetProcessById(process.Id);
        var attempts = 0;
        var containment = new DshUnassignedProcessContainment(
            (candidate, timeout) =>
            {
                attempts++;
                if (attempts == 1)
                {
                    return false;
                }
                candidate.Kill(entireProcessTree: true);
                return candidate.WaitForExit(checked((int)timeout.TotalMilliseconds))
                    && candidate.HasExited;
            });
        var lease = DshRuntimeLaunchLease.Acquire(
            new DshRuntimeOptions(runtime, root, root),
            static () => { });
        var ownershipTransferred = false;
        try
        {
            ownershipTransferred = true;
            _ = AssertThrows<AggregateException>(() =>
                containment.ThrowAfterLaunchFailure(
                    process,
                    new Win32Exception(
                        5,
                        "Synthetic job assignment failure with a real runtime lease."),
                    runtimeLaunchLease: lease));
            AssertMutationDenied(() => File.Move(node, node + ".replaced"));
            AssertMutationDenied(() => File.WriteAllText(
                entry,
                "console.log('attacker');"));
            AssertMutationDenied(() => File.Delete(trustMetadata));

            containment.RetryTerminationOrThrow();
            await observer.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            AssertTrue(observer.HasExited);
            File.Move(node, node + ".released");
            File.WriteAllText(entry, "console.log('released');");
            File.Delete(trustMetadata);
            AssertTrue(File.Exists(node + ".released"));
            AssertFalse(File.Exists(trustMetadata));
        }
        finally
        {
            if (!ownershipTransferred)
            {
                lease.Dispose();
            }
            if (!observer.HasExited)
            {
                observer.Kill(entireProcessTree: true);
                await observer.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            }
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static async Task CleanupFailuresRetainExactBundleAsync()
    {
        var process = StartHiddenPingProcess();
        using var observer = Process.GetProcessById(process.Id);
        var terminationAttempts = 0;
        var processDisposeAttempts = 0;
        var containment = new DshUnassignedProcessContainment(
            (candidate, timeout) =>
            {
                terminationAttempts++;
                candidate.Kill(entireProcessTree: true);
                return candidate.WaitForExit(
                        checked((int)timeout.TotalMilliseconds))
                    && candidate.HasExited;
            },
            candidate =>
            {
                processDisposeAttempts++;
                if (processDisposeAttempts == 1)
                {
                    throw new IOException(
                        "Synthetic exact Process wrapper disposal failure.");
                }
                candidate.Dispose();
            });
        var independentContainment = new DshUnassignedProcessContainment(
            static (_, _) => throw new InvalidOperationException(
                "A different service must use the cleanup policy retained with the process-wide bundle."));
        var jobObject = new RetryingDisposable(
            "Synthetic exact job-handle close failure.");
        var runtimeLaunchLease = new RetryingDisposable(
            "Synthetic exact runtime-lease disposal failure.");

        try
        {
            var launchException = AssertThrows<AggregateException>(() =>
                containment.ThrowAfterLaunchFailure(
                    process,
                    new Win32Exception(
                        5,
                        "Synthetic post-launch admission failure."),
                    jobObject,
                    runtimeLaunchLease));
            AssertTrue(launchException.Flatten().InnerExceptions.Any(
                exception => exception.Message.Contains(
                    "job-handle close failure",
                    StringComparison.Ordinal)));
            await observer.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            AssertTrue(observer.HasExited);
            AssertEqual(1, terminationAttempts);
            AssertEqual(1, jobObject.DisposeAttempts);
            AssertEqual(1, runtimeLaunchLease.DisposeAttempts);
            AssertEqual(1, processDisposeAttempts);
            AssertFalse(jobObject.IsDisposed);
            AssertFalse(runtimeLaunchLease.IsDisposed);
            AssertTrue(containment.HasRetainedProcess);
            AssertTrue(independentContainment.HasRetainedProcess);
            AssertTrue(ReferenceEquals(
                process,
                independentContainment.RetainedProcessesForTests.Single()));

            independentContainment.RetryTerminationOrThrow();
            AssertEqual(1, terminationAttempts);
            AssertEqual(2, jobObject.DisposeAttempts);
            AssertEqual(2, runtimeLaunchLease.DisposeAttempts);
            AssertEqual(2, processDisposeAttempts);
            AssertTrue(jobObject.IsDisposed);
            AssertTrue(runtimeLaunchLease.IsDisposed);
            AssertFalse(containment.HasRetainedProcess);
            AssertFalse(independentContainment.HasRetainedProcess);
        }
        finally
        {
            if (!observer.HasExited)
            {
                observer.Kill(entireProcessTree: true);
                await observer.WaitForExitAsync().WaitAsync(
                    TimeSpan.FromSeconds(5));
            }
            try
            {
                independentContainment.RetryTerminationOrThrow();
            }
            catch
            {
                // Preserve the primary test failure; the process is already
                // confirmed exited and all synthetic resources retry once.
            }
            process.Dispose();
        }
    }

    private static async Task ExitInspectionFailuresRemainRetainedAsync()
    {
        using var process = StartHiddenPingProcess();
        using var observer = Process.GetProcessById(process.Id);
        var terminationAttempts = 0;
        var confirmationAttempts = 0;
        var containment = new DshUnassignedProcessContainment(
            (candidate, timeout) =>
            {
                terminationAttempts++;
                if (!candidate.HasExited)
                {
                    candidate.Kill(entireProcessTree: true);
                }
                return candidate.WaitForExit(
                        checked((int)timeout.TotalMilliseconds))
                    && candidate.HasExited;
            },
            confirmExited: candidate =>
            {
                confirmationAttempts++;
                if (confirmationAttempts == 1)
                {
                    throw new Win32Exception(
                        6,
                        "Synthetic exact-process exit inspection failure.");
                }
                return candidate.WaitForExit(milliseconds: 0)
                    && candidate.HasExited;
            });
        var independentContainment = new DshUnassignedProcessContainment(
            static (_, _) => throw new InvalidOperationException(
                "The retry must use the exact retained exit-confirmation policy."));
        var runtimeLaunchLease = new TrackingDisposable();

        var launchFailure = new InvalidDataException(
            "Synthetic launch identity failure.");
        var aggregate = AssertThrows<AggregateException>(() =>
            containment.ThrowAfterLaunchFailure(
                process,
                launchFailure,
                runtimeLaunchLease: runtimeLaunchLease));
        AssertTrue(aggregate.Flatten().InnerExceptions.Any(exception =>
            ReferenceEquals(exception, launchFailure)));
        AssertTrue(aggregate.Flatten().InnerExceptions.Any(exception =>
            exception is Win32Exception
            && exception.Message.Contains(
                "exit inspection failure",
                StringComparison.Ordinal)));
        await observer.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
        AssertTrue(observer.HasExited);
        AssertTrue(independentContainment.HasRetainedProcess);
        AssertFalse(runtimeLaunchLease.IsDisposed);
        AssertEqual(1, terminationAttempts);
        AssertEqual(1, confirmationAttempts);

        independentContainment.RetryTerminationOrThrow();
        AssertEqual(2, terminationAttempts);
        AssertEqual(2, confirmationAttempts);
        AssertTrue(runtimeLaunchLease.IsDisposed);
        AssertFalse(containment.HasRetainedProcess);
    }

    private static Process StartHiddenPingProcess()
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "ping.exe"),
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        startInfo.ArgumentList.Add("-t");
        startInfo.ArgumentList.Add("127.0.0.1");
        return Process.Start(startInfo)
            ?? throw new InvalidOperationException(
                "Windows did not start the unassigned-process containment probe.");
    }

    private static TException AssertThrows<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException exception)
        {
            return exception;
        }

        throw new InvalidOperationException(
            $"Expected {typeof(TException).Name} was not thrown.");
    }

    private static void AssertMutationDenied(Action mutation)
    {
        try
        {
            mutation();
        }
        catch (Exception exception) when (exception is
            IOException or UnauthorizedAccessException)
        {
            return;
        }
        throw new InvalidOperationException(
            "A retained runtime launch lease released before exact process exit confirmation.");
    }

    private static void AssertTrue(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Expected condition to be true.");
        }
    }

    private static void AssertFalse(bool condition) => AssertTrue(!condition);

    private static void AssertEqual<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException(
                $"Expected '{expected}', actual '{actual}'.");
        }
    }

    private sealed class TrackingDisposable : IDisposable
    {
        private int _disposed;

        internal bool IsDisposed => Volatile.Read(ref _disposed) != 0;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                throw new InvalidOperationException(
                    "The retained runtime launch lease was disposed more than once.");
            }
        }
    }

    private sealed class RetryingDisposable(string firstFailure) : IDisposable
    {
        private int _disposeAttempts;
        private int _disposed;

        internal int DisposeAttempts => Volatile.Read(ref _disposeAttempts);

        internal bool IsDisposed => Volatile.Read(ref _disposed) != 0;

        public void Dispose()
        {
            var attempt = Interlocked.Increment(ref _disposeAttempts);
            if (attempt == 1)
            {
                throw new IOException(firstFailure);
            }
            Interlocked.Exchange(ref _disposed, 1);
        }
    }
}
