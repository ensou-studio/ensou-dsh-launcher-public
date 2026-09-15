using System.Diagnostics;
using System.Text.Json.Nodes;
using Ensou.Dsh.Host;
using Ensou.Dsh.UpdateEngine;

internal static class Program
{
    private static string Exe => Environment.ProcessPath!;
    private static readonly List<string> Results = [];
    public static async Task<int> Main(string[] args)
    {
        if (AtomicJobStartupTests.TryHandleCommand(args)) return 0;
        if (args is ["--idle"]) { Thread.Sleep(30000); return 0; }
        if (args is ["--root-child", var childReceipt])
        {
            using var child = Process.Start(Start("--idle"))!;
            File.WriteAllText(childReceipt, child.Id.ToString());
            Thread.Sleep(30000);
            return 0;
        }
        if (args is ["--crash-owner", var home, var receipt])
        {
            using var lease = new PersonalHarnessHomeCoordinator(home).AcquireLease();
            using var session = lease.BeginRuntimeSession();
            using var job = WindowsJobObject.CreateKillOnClose(session.JobName, session.RecordJobEmpty);
            using var child = job.StartSuspended(Start("--idle"), p => session.RecordAssignedProcess(p.Id, p.StartTime.ToFileTimeUtc()));
            using var childProcess = child.Process;
            File.WriteAllText(receipt, child.Process.Id + "|" + child.Process.StartTime.ToFileTimeUtc());
            // The test parent terminates this exact Process handle without running finally blocks.
            Thread.Sleep(Timeout.Infinite);
        }
        var root = Path.Combine(AppContext.BaseDirectory, "coordination-probes-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            foreach (var test in AtomicHomeRecoveryPolicyTests.Cases) Test(test.Name, test.Run);
            foreach (var test in AtomicHomeRecoveryPolicyTests.StateCases(root)) Test(test.Name, test.Run);
            foreach (var test in AtomicJobStartupTests.Cases(root)) Test(test.Name, test.Run);
            foreach (var test in VerifiedRollbackCompatibilityTests.StateCases(root)) Test(test.Name, test.Run);
            Test("same-home contention and independent homes", () =>
            {
                Throws("absolute", () => new PersonalHarnessHomeCoordinator("relative-home"));
                var home = Path.Combine(root, "contention", "home");
                using var first = new PersonalHarnessHomeCoordinator(home).AcquireLease();
                Throws("PERSONAL_HOME_BUSY", () => new PersonalHarnessHomeCoordinator(home.ToUpperInvariant() + "\\").AcquireLease());
                using var other = new PersonalHarnessHomeCoordinator(Path.Combine(root, "other-home")).AcquireLease();
                Throws("different home", () => first.RequireMutationAdmission(Path.Combine(root, "other-home")));
            });
            Test("legacy enrollment is one-time and empty homes need no callback", () =>
            {
                var home = Path.Combine(root, "legacy"); Directory.CreateDirectory(home); File.WriteAllText(Path.Combine(home, "history.txt"), "preserve");
                Throws("LEGACY", () => new PersonalHarnessHomeCoordinator(home).AcquireLease());
                var calls = 0;
                using (var lease = new PersonalHarnessHomeCoordinator(home).AcquireLease(() => calls++)) lease.RequireQuiescent();
                using (var lease = new PersonalHarnessHomeCoordinator(home).AcquireLease(() => throw new Exception("Callback repeated"))) lease.RequireQuiescent();
                Assert(calls == 1 && File.ReadAllText(Path.Combine(home, "history.txt")) == "preserve", "Legacy data or admission changed.");
            });
            Test("session retains lease and disposal does not assert clean", () =>
            {
                var home = Path.Combine(root, "retained");
                var lease = new PersonalHarnessHomeCoordinator(home).AcquireLease();
                var session = lease.BeginRuntimeSession(); lease.Dispose();
                Throws("BUSY", () => new PersonalHarnessHomeCoordinator(home).AcquireLease());
                session.Dispose();
                using var retry = new PersonalHarnessHomeCoordinator(home).AcquireLease();
                Throws("SHUTDOWN_UNCONFIRMED", retry.RequireQuiescent);
            });
            Test("one-way native uptime recovery", () =>
            {
                var home = Path.Combine(root, "ticks", "home");
                using (var lease = new PersonalHarnessHomeCoordinator(home).AcquireLease()) { using var session = lease.BeginRuntimeSession(); }
                var statePath = Directory.GetFiles(Path.GetDirectoryName(home)!, "state.v1.json", SearchOption.AllDirectories).Single();
                var state = JsonNode.Parse(File.ReadAllText(statePath))!;
                state["runtime"]!["maximumObservedNativeTickCount64"] = 0UL;
                File.WriteAllText(statePath, state.ToJsonString());
                using (var retry = new PersonalHarnessHomeCoordinator(home).AcquireLease()) Throws("SHUTDOWN_UNCONFIRMED", retry.RequireQuiescent);
                state = JsonNode.Parse(File.ReadAllText(statePath))!;
                state["runtime"]!["maximumObservedNativeTickCount64"] = PersonalHomeCoordinationNative.GetTickCount64() + 60000UL;
                File.WriteAllText(statePath, state.ToJsonString());
                using var reset = new PersonalHarnessHomeCoordinator(home).AcquireLease(); reset.RequireQuiescent();
            });
            Test("health attempt requires started clean exact generation", () =>
            {
                var home = Path.Combine(root, "health");
                using var lease = new PersonalHarnessHomeCoordinator(home).AcquireLease();
                lease.AdmitHealthAttempt("tx-a", "token-a");
                Throws("CONFLICT", () => lease.AdmitHealthAttempt("tx-a", "token-a"));
                Throws("CONFLICT", () => lease.CompleteHealthAttempt("tx-a", "token-a"));
                using (var session = lease.BeginRuntimeSession())
                using (var job = WindowsJobObject.CreateKillOnClose(session.JobName, session.RecordJobEmpty))
                {
                    using var child = job.StartSuspended(Start("--idle"), p => session.RecordAssignedProcess(p.Id, p.StartTime.ToFileTimeUtc()));
                    using var childProcess = child.Process;
                    Throws("BUSY", lease.RequireQuiescent);
                    job.Dispose();
                }
                lease.RequireMutationAdmission(home);
                lease.CompleteHealthAttempt("tx-a", "token-a");
                lease.RequireCompletedHealthAttempt("tx-a", "token-a");
                Throws("CONFLICT", () => lease.RequireCompletedHealthAttempt("tx-a", "wrong"));
                lease.AbortHealthAttempt("tx-b");
                lease.RequireCompletedHealthAttempt("tx-a", "token-a");
                lease.AbortHealthAttempt("tx-a");
                lease.AdmitHealthAttempt("tx-b", "token-b");
                Throws("CONFLICT", () => lease.AbortHealthAttempt("tx-a"));
                lease.AbortHealthAttempt("tx-b");
            });
            Test("job collision and descendant lifetime", () =>
            {
                var home = Path.Combine(root, "descendants");
                using var lease = new PersonalHarnessHomeCoordinator(home).AcquireLease();
                using var session = lease.BeginRuntimeSession();
                using var job = WindowsJobObject.CreateKillOnClose(session.JobName, session.RecordJobEmpty);
                Throws("already exists", () => WindowsJobObject.CreateKillOnClose(session.JobName));
                var path = Path.Combine(root, "descendant-pid.txt");
                using var started = job.StartSuspended(Start("--root-child", path), p => session.RecordAssignedProcess(p.Id, p.StartTime.ToFileTimeUtc()));
                using var rootProcess = started.Process;
                WaitFile(path);
                using var child = Process.GetProcessById(int.Parse(File.ReadAllText(path)));
                started.Process.Kill(); started.Process.WaitForExit(5000);
                Assert(job.ReadActiveProcessCountForTest() > 0, "Descendant did not survive the root.");
                Throws("BUSY", lease.RequireQuiescent);
                job.Dispose();
                Assert(child.WaitForExit(5000), "Exact job child did not stop.");
                lease.RequireQuiescent();
                Throws("disposed", () => job.StartSuspended(Start("--idle"), _ => { }));
            });
            Test("parent crash leaves missing job unknown", () =>
            {
                var home = Path.Combine(root, "crash");
                var path = Path.Combine(root, "crash-child-pid.txt");
                using var owner = Process.Start(Start("--crash-owner", home, path))!;
                Process? child = null;
                try
                {
                    WaitFile(path);
                    var identity = File.ReadAllText(path).Split('|');
                    child = Process.GetProcessById(int.Parse(identity[0]));
                    Assert(child.StartTime.ToFileTimeUtc() == long.Parse(identity[1]), "Child PID was reused.");
                    owner.Kill();
                    Assert(owner.WaitForExit(10000), "Crash owner did not terminate.");
                    Assert(child.WaitForExit(10000), "Crash owner's exact job child did not terminate.");
                    Console.WriteLine($"Crash probe owner {owner.Id} and child {child.Id}: exit confirmed.");
                }
                finally
                {
                    if (!owner.HasExited) owner.Kill();
                    Assert(owner.WaitForExit(10000), "Crash owner cleanup did not terminate.");
                    if (child is not null)
                    {
                        var exited = child.WaitForExit(10000);
                        child.Dispose();
                        Assert(exited, "Crash child cleanup did not terminate.");
                    }
                }
                using var lease = new PersonalHarnessHomeCoordinator(home).AcquireLease();
                Throws("SHUTDOWN_UNCONFIRMED", lease.RequireQuiescent);
            });
            await TestAsync("host pre-process validation failure is clean", async () =>
            {
                var home = Path.Combine(root, "host-never-started");
                var runtime = Path.Combine(root, "absent-runtime");
                using var lease = new PersonalHarnessHomeCoordinator(home).AcquireLease();
                await using var host = new DshHostService(new DshRuntimeOptions(runtime, home, Path.Combine(root, "logs")),
                    () => throw new InvalidOperationException("Expected invalid runtime."), acquireHomeWriterSession: lease.BeginRuntimeSession);
                try { await host.EnsureStartedAsync(); throw new Exception("Invalid runtime was admitted."); }
                catch (Exception e) when (e is FileNotFoundException or DirectoryNotFoundException or InvalidOperationException) { }
                lease.RequireQuiescent();
            });
            Console.WriteLine(string.Join("\n", Results));
            Console.WriteLine("PASS " + Results.Count + "; isolated artifacts: " + root);
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine(e); Console.Error.WriteLine("Artifacts: " + root); return 1; }
    }
    private static ProcessStartInfo Start(params string[] args)
    {
        var info = new ProcessStartInfo(Exe) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = AppContext.BaseDirectory };
        if (Path.GetFileNameWithoutExtension(Exe).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            info.ArgumentList.Add(typeof(Program).Assembly.Location);
        foreach (var arg in args) info.ArgumentList.Add(arg);
        return info;
    }
    private static void WaitFile(string path) { var sw = Stopwatch.StartNew(); while (!File.Exists(path) && sw.ElapsedMilliseconds < 10000) Thread.Sleep(20); Assert(File.Exists(path), "Child receipt missing."); }
    private static void Test(string name, Action action) { action(); Results.Add("PASS " + name); }
    private static async Task TestAsync(string name, Func<Task> action) { await action(); Results.Add("PASS " + name); }
    private static void Assert(bool condition, string message) { if (!condition) throw new Exception(message); }
    private static void Throws(string text, Action action)
    { try { action(); } catch (Exception e) when (e.Message.Contains(text, StringComparison.OrdinalIgnoreCase)) { return; } throw new Exception("Expected failure containing: " + text); }
}
