using System.Diagnostics;
using System.Text.Json.Nodes;
using Ensou.Dsh.Host;
using Ensou.Dsh.UpdateEngine;

internal static class AtomicJobStartupTests
{
    internal static IReadOnlyList<(string Name, Action Run)> Cases(string privateRoot) =>
    [
        ("atomic containment exists before managed admission with capture off and on", CaptureIsExactBeforeResume),
        ("atomic native callback rejection terminates its exact child", CallbackFailureTerminatesOwnedChild),
        ("atomic Job name collision is rejected", UniqueNameCollision),
        ("atomic disposal serializes with native admission", DisposeWaitsForAdmission),
        ("atomic owner crash before managed PID recording permits evidenced same-boot recovery", () => OwnerCrash(privateRoot)),
    ];

    public static bool TryHandleCommand(string[] args)
    {
        if (args is ["--atomic-idle"]) { Thread.Sleep(30000); return true; }
        if (args is ["--atomic-crash-owner", var home, var receipt, var capture])
        {
            RequirePrivatePath(home);
            RequirePrivatePath(receipt);
            using var lease = new PersonalHarnessHomeCoordinator(home).AcquireLease();
            lease.AdmitHealthAttempt("native-crash", "native-crash-token");
            using var session = lease.BeginAtomicRuntimeSession();
            using var job = WindowsJobObject.CreateKillOnClose(session.JobName, session.RecordJobEmpty);
            using var started = job.StartAtomicSuspendedForTest(Start(capture == "true", "--atomic-idle"),
                _ => throw new InvalidOperationException("Managed admission must not run in the crash window."),
                nativePid =>
                {
                    Assert(job.ReadActiveProcessCountForTest() == 1, "Atomic Job did not already contain the suspended child.");
                    using var exactChild = Process.GetProcessById(nativePid);
                    _ = exactChild.Handle;
                    var staging = receipt + ".new";
                    File.WriteAllText(staging, nativePid + "|" + exactChild.StartTime.ToFileTimeUtc());
                    File.Move(staging, receipt);
                    // The test parent kills only this retained owner handle, without running finally.
                    Thread.Sleep(Timeout.Infinite);
                });
            throw new InvalidOperationException("The atomic crash owner was unexpectedly resumed.");
        }
        return false;
    }

    private static ProcessStartInfo Start(bool capture, params string[] args)
    {
        var start = new ProcessStartInfo(Environment.ProcessPath!)
        { UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden,
          WorkingDirectory = AppContext.BaseDirectory, RedirectStandardOutput = capture, RedirectStandardError = capture };
        if (Path.GetFileNameWithoutExtension(start.FileName).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            start.ArgumentList.Add(typeof(AtomicJobStartupTests).Assembly.Location);
        foreach (var arg in args) start.ArgumentList.Add(arg);
        return start;
    }

    private static void CaptureIsExactBeforeResume()
    {
        foreach (var capture in new[] { false, true })
        {
            using var job = WindowsJobObject.CreateKillOnClose("Local\\atomic-capture-" + Guid.NewGuid().ToString("N"));
            using var started = job.StartAtomicSuspendedForTest(Start(capture, "--atomic-idle"), _ => { }, _ =>
                Assert(job.ReadActiveProcessCountForTest() == 1, "Child was not Job-contained before managed admission."));
            using var process = started.Process;
            var readers = started.DetachReaders();
            using var output = readers.Output;
            using var error = readers.Error;
            try
            {
                Assert((output is not null) == capture && (error is not null) == capture, "Capture handle ownership mismatch.");
                job.Dispose();
                Assert(process.WaitForExit(5000), "Atomic idle child did not exit after Job disposal.");
                if (capture)
                {
                    Assert(output!.ReadToEndAsync().Wait(5000), "Owned output did not close.");
                    Assert(error!.ReadToEndAsync().Wait(5000), "Owned error output did not close.");
                }
                Console.WriteLine($"Atomic capture={capture}: exact child {process.Id} exit confirmed.");
            }
            finally { job.Dispose(); }
        }
    }

    private static void CallbackFailureTerminatesOwnedChild()
    {
        using var job = WindowsJobObject.CreateKillOnClose("Local\\atomic-reject-" + Guid.NewGuid().ToString("N"));
        var expected = new InvalidOperationException("Reject the native-created atomic child.");
        Process? child = null;
        try
        {
            try
            {
                using var unexpected = job.StartAtomicSuspendedForTest(Start(false, "--atomic-idle"), _ => { }, nativePid =>
                {
                    child = Process.GetProcessById(nativePid);
                    _ = child.Handle;
                    throw expected;
                });
                using var unexpectedProcess = unexpected.Process;
                throw new InvalidOperationException("The rejected native callback returned a child.");
            }
            catch (InvalidOperationException e) when (ReferenceEquals(e, expected)) { }
            Assert(child is not null && child.WaitForExit(5000), "Rejected atomic callback left its owned child alive.");
            Assert(job.ReadActiveProcessCountForTest() == 0, "Rejected Job retained a process.");
            Console.WriteLine($"Atomic rejection: exact child {child!.Id} exit confirmed.");
        }
        finally
        {
            try { job.Dispose(); }
            finally { child?.Dispose(); }
        }
    }

    private static void UniqueNameCollision()
    {
        var name = "Local\\atomic-collision-" + Guid.NewGuid(); using var first = WindowsJobObject.CreateKillOnClose(name);
        try { using var second = WindowsJobObject.CreateKillOnClose(name); throw new Exception("Expected Job collision."); }
        catch (InvalidOperationException e) when (e.Message.Contains("already exists", StringComparison.Ordinal)) { }
        Assert(first.ReadActiveProcessCountForTest() == 0, "Collision changed the first Job.");
    }

    private static void DisposeWaitsForAdmission()
    {
        using var job = WindowsJobObject.CreateKillOnClose("Local\\atomic-dispose-" + Guid.NewGuid().ToString("N"));
        using var entered = new ManualResetEventSlim(false);
        using var release = new ManualResetEventSlim(false);
        using var disposalEntered = new ManualResetEventSlim(false);
        var startTask = Task.Run(() => job.StartAtomicSuspendedForTest(Start(false, "--atomic-idle"), _ =>
        {
            entered.Set();
            Assert(release.Wait(10000), "Admission release timed out.");
        }, _ => { }));
        Task? disposeTask = null;
        WindowsJobStartedProcess? started = null;
        try
        {
            Assert(entered.Wait(5000), "Atomic admission was not entered.");
            disposeTask = Task.Run(() => { disposalEntered.Set(); job.Dispose(); });
            Assert(disposalEntered.Wait(5000), "Disposal task was not scheduled.");
            Assert(!disposeTask.Wait(150), "Dispose crossed active atomic admission.");
            release.Set();
            Assert(startTask.Wait(10000), "Atomic startup did not complete.");
            started = startTask.GetAwaiter().GetResult();
            Assert(disposeTask.Wait(10000), "Dispose did not complete.");
            Assert(started.Process.WaitForExit(5000), "Dispose did not terminate its exact owned child.");
            Console.WriteLine($"Atomic concurrent disposal: exact child {started.Process.Id} exit confirmed.");
        }
        finally
        {
            release.Set();
            try
            {
                if (started is null && startTask.Wait(15000)) started = startTask.GetAwaiter().GetResult();
                if (disposeTask is not null) Assert(disposeTask.Wait(15000), "Concurrent disposal cleanup did not finish.");
                job.Dispose();
            }
            finally
            {
                started?.Dispose();
                started?.Process.Dispose();
            }
        }
    }

    private static void OwnerCrash(string root)
    {
        RequirePrivatePath(root);
        foreach (var capture in new[] { false, true })
        {
            var home = Path.Combine(root, "atomic-crash-" + Guid.NewGuid().ToString("N"), "home");
            using (var initial = new PersonalHarnessHomeCoordinator(home).AcquireLease()) initial.RequireQuiescent();
            Directory.CreateDirectory(home);
            var sentinel = Path.Combine(home, "synthetic-history.txt");
            File.WriteAllText(sentinel, "native-crash-preserve");
            var receipt = Path.Combine(Path.GetDirectoryName(home)!, "child.txt");
            using var owner = Process.Start(Start(false, "--atomic-crash-owner", home, receipt, capture ? "true" : "false"))!;
            Process? child = null;
            try
            {
                var timer = Stopwatch.StartNew();
                while (!File.Exists(receipt) && !owner.HasExited && timer.ElapsedMilliseconds < 10000) Thread.Sleep(20);
                Assert(File.Exists(receipt), "Atomic owner did not reach the native-created crash window.");
                var identity = File.ReadAllText(receipt).Split('|');
                child = Process.GetProcessById(int.Parse(identity[0]));
                _ = child.Handle;
                Assert(child.StartTime.ToFileTimeUtc() == long.Parse(identity[1]), "Atomic child PID identity mismatch.");
                owner.Kill();
                Assert(owner.WaitForExit(10000), "Exact atomic owner did not exit.");
                Assert(child.WaitForExit(10000), "Atomic Job did not terminate its suspended child when the owner died.");
                using var retry = new PersonalHarnessHomeCoordinator(home).AcquireLease();
                retry.RequireMutationAdmission(home);
                var stateFile = Directory.GetFiles(Path.Combine(Path.GetDirectoryName(home)!, ".ensou-dsh-home-coordination"),
                    "state.v1.json", SearchOption.AllDirectories).Single();
                var state = JsonNode.Parse(File.ReadAllText(stateFile))!;
                Assert(state["runtime"]!["runtimePid"] is null, "Managed PID recording unexpectedly ran before the crash.");
                var evidence = state["runtime"]!["cleanEvidence"]!.GetValue<string>();
                Assert(evidence is "recovered-atomic-job-empty" or "recovered-atomic-job-absent", "No actual atomic recovery evidence.");
                Assert(File.ReadAllText(sentinel) == "native-crash-preserve", "Recovery altered the synthetic history.");
                var rejected = false;
                try { retry.CompleteHealthAttempt("native-crash", "native-crash-token"); }
                catch (InvalidOperationException) { rejected = true; }
                Assert(rejected, "Crash recovery incorrectly completed application health.");
                retry.AbortHealthAttempt("native-crash");
                Console.WriteLine($"Atomic crash capture={capture}: owner {owner.Id}, child {child.Id}, {evidence}; both exited.");
            }
            finally
            {
                try
                {
                    if (!owner.HasExited) owner.Kill();
                    Assert(owner.WaitForExit(10000), "Atomic owner cleanup was not confirmed.");
                    if (child is not null) Assert(child.WaitForExit(10000), "Atomic child cleanup was not confirmed.");
                }
                finally { child?.Dispose(); }
            }
        }
    }

    private static void RequirePrivatePath(string path)
    {
        const string prefix = "C:\\Users\\ensou\\Documents\\Codex\\2026-08-22\\q\\.tmp\\";
        Assert(Path.IsPathFullyQualified(path) && Path.GetFullPath(path).StartsWith(prefix, StringComparison.OrdinalIgnoreCase),
            "Native tests require the explicit task-private .tmp root.");
        for (var item = new DirectoryInfo(Path.GetDirectoryName(path)!); item is not null; item = item.Parent)
            Assert(!item.Exists || (item.Attributes & FileAttributes.ReparsePoint) == 0, "Native test path crosses a link.");
    }

    private static void Assert(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}
