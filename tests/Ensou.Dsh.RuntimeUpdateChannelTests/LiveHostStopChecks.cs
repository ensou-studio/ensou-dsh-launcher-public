using System.Diagnostics;
using System.Reflection;
using System.Text;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.Host;

internal static class LiveHostStopChecks
{
    internal static async Task RunAsync()
    {
        var source = RequiredFileRoot(
            "ENSOU_TEST_DSH_SOURCE",
            "apps/cli/tests/fixtures/managed-update-process.ts");
        var node = Environment.GetEnvironmentVariable("ENSOU_TEST_NODE")
            ?? throw new InvalidOperationException("Explicit isolated Node path is required.");
        if (!Path.IsPathFullyQualified(node) || !File.Exists(node))
            throw new InvalidOperationException("Invalid isolated Node path.");

        await OrdinaryCancellationRetainsExactPipeAsync(source, node);
        await PriorityStopPreemptsAndTerminatesExactChildAsync(source, node);
        await EofCannotBecomeReadyAsync(source, node);
        await PostCommitCancellationStillReportsStoppedAsync(source, node);
        await CleanupFailureReportsExactStoppedOutcomeAsync(source, node);
    }

    private static async Task OrdinaryCancellationRetainsExactPipeAsync(
        string source,
        string node)
    {
        await using var fixture = await HostFixture.StartAsync(source, node);
        var originalBinding = fixture.RuntimeBinding;
        using var cancellation = new CancellationTokenSource();
        var firstStop = fixture.Host.StopForManagedUpdateAsync(
            Guid.NewGuid(),
            cancellation.Token);
        await fixture.WaitForDrainingAsync();
        cancellation.Cancel();
        await ThrowsAsync<OperationCanceledException>(() => firstStop);

        Assert(ReferenceEquals(originalBinding, fixture.RuntimeBinding),
            "Ordinary cancellation did not retain the exact channel binding.");
        await fixture.CommandAsync("assert-open", "fixture:open-active-preserved");

        var retry = fixture.Host.StopForManagedUpdateAsync(Guid.NewGuid());
        await fixture.WaitForDrainingAsync();
        await fixture.CommandAsync("release", "fixture:completed");
        await retry.WaitAsync(fixture.Token);
        Assert(fixture.Observer.HasExited && fixture.Observer.ExitCode == 0,
            "Natural managed shutdown did not confirm exact child exit 0.");
        Assert(fixture.RuntimeBinding is null,
            "Natural managed shutdown retained a stale channel binding.");
        await fixture.AssertCleanNaturalExitAsync();
        Console.WriteLine(
            "PASS  live Host ordinary cancellation: owners resumed, exact pipe retained, retry shutdown exit0");
    }

    private static async Task PriorityStopPreemptsAndTerminatesExactChildAsync(
        string source,
        string node)
    {
        await using var fixture = await HostFixture.StartAsync(source, node);
        var graceful = fixture.Host.StopForManagedUpdateAsync(Guid.NewGuid());
        await fixture.WaitForDrainingAsync();
        var priority = fixture.Host.StopOwnedProcessAsync();
        await ThrowsAsync<OperationCanceledException>(() => graceful);
        await priority.WaitAsync(fixture.Token);

        Assert(fixture.Observer.HasExited,
            "Priority stop did not terminate the exact retained child.");
        Assert(fixture.RuntimeBinding is null,
            "Priority stop retained the preempted control channel.");
        Console.WriteLine(
            "PASS  live Host priority stop: pending drain preempted and exact child terminated");
    }

    private static async Task EofCannotBecomeReadyAsync(string source, string node)
    {
        await using var fixture = await HostFixture.StartAsync(source, node);
        var graceful = fixture.Host.StopForManagedUpdateAsync(Guid.NewGuid());
        await fixture.WaitForDrainingAsync();
        fixture.Child.Kill(entireProcessTree: true);
        await fixture.Child.WaitForExitAsync(fixture.Token);
        await ThrowsAnyAsync(
            () => graceful,
            typeof(EndOfStreamException),
            typeof(IOException),
            typeof(UnauthorizedAccessException),
            typeof(InvalidOperationException));
        Assert(fixture.RuntimeBinding is null,
            "EOF after drain retained a terminal channel.");
        Console.WriteLine("PASS  live Host unexpected exit: ownership loss or EOF cannot become ready");
    }

    private static async Task PostCommitCancellationStillReportsStoppedAsync(string source, string node)
    {
        await using var fixture = await HostFixture.StartAsync(source, node, "shutdown-hold");
        using var cancellation = new CancellationTokenSource();
        var stop = fixture.Host.StopForManagedUpdateAsync(Guid.NewGuid(), cancellation.Token);
        await fixture.WaitForDrainingAsync();
        await fixture.CommandAsync("release", "fixture:completed");
        await fixture.ExpectOutputAsync("fixture:shutdown-held");
        cancellation.Cancel();
        await fixture.AllowExitAsync();
        await stop.WaitAsync(fixture.Token);
        Assert(fixture.Observer.HasExited && fixture.Observer.ExitCode == 0,
            "Post-commit cancellation lost the exact successful stop outcome.");
        await fixture.AssertCleanNaturalExitAsync();
        Console.WriteLine("PASS  live Host post-commit cancellation: exact shutdown exit0 retained");
    }

    private static async Task CleanupFailureReportsExactStoppedOutcomeAsync(string source, string node)
    {
        await using var fixture = await HostFixture.StartAsync(source, node);
        var operation = Guid.NewGuid();
        var sentinel = new InvalidOperationException("fixture writer cleanup sentinel");
        fixture.InjectHomeWriterSession(new ThrowingWriterSession(sentinel));
        var stop = fixture.Host.StopForManagedUpdateAsync(operation);
        await fixture.WaitForDrainingAsync();
        await fixture.CommandAsync("release", "fixture:completed");
        var failure = await CaptureAsync<DshRuntimeUpdateStoppedException>(() => stop);
        Assert(failure.OperationId == operation && failure.ProcessId == fixture.ChildId,
            "Stopped outcome did not preserve exact operation and process identities.");
        Assert(ContainsReference(failure.InnerException, sentinel),
            "Stopped outcome did not preserve the cleanup sentinel.");
        Assert(fixture.Observer.HasExited && fixture.Observer.ExitCode == 0,
            "Cleanup failure lacked independently confirmed child exit 0.");
        Assert(fixture.RuntimeBinding is null,
            "Cleanup failure retained a ready-installation channel binding.");
        await fixture.AssertCleanNaturalExitAsync();
        Console.WriteLine("PASS  live Host cleanup failure: typed exact stopped outcome");
    }

    private sealed class HostFixture : IAsyncDisposable
    {
        private static readonly BindingFlags PrivateInstance =
            BindingFlags.Instance | BindingFlags.NonPublic;
        private readonly DirectoryInfo _directory;
        private readonly DshRuntimeUpdateChannel _channel;
        private readonly object _job;
        private readonly Task<string> _stderr;
        private readonly Task<Exception?> _exitCallback;
        private readonly CancellationTokenSource _timeout;

        private HostFixture(
            DirectoryInfo directory,
            DshHostService host,
            Process child,
            Process observer,
            DshRuntimeUpdateChannel channel,
            object job,
            Task<string> stderr,
            Task<Exception?> exitCallback,
            CancellationTokenSource timeout)
        {
            _directory = directory;
            Host = host;
            Child = child;
            Observer = observer;
            _channel = channel;
            _job = job;
            _stderr = stderr;
            _exitCallback = exitCallback;
            _timeout = timeout;
            ChildId = child.Id;
        }

        internal DshHostService Host { get; }
        internal Process Child { get; }
        internal Process Observer { get; }
        internal int ChildId { get; }
        internal CancellationToken Token => _timeout.Token;
        internal object? RuntimeBinding => Field("_runtimeUpdateChannel").GetValue(Host);

        internal static async Task<HostFixture> StartAsync(
            string source,
            string node,
            string mode = "normal")
        {
            var directory = Directory.CreateTempSubdirectory("ensou-dsh-live-host-");
            DshRuntimeUpdateChannel? channel = null;
            Process? expectedChild = null;
            Process? observer = null;
            DshHostService? host = null;
            object? job = null;
            CancellationTokenSource? timeout = null;
            try
            {
                channel = DshRuntimeUpdateChannel.Create(
                    process => ReferenceEquals(process, expectedChild) && !process.HasExited);
                var start = CreateNodeStartInfo(
                    source, node, directory.FullName, mode, channel);
                expectedChild = Process.Start(start)
                    ?? throw new InvalidOperationException("Node fixture did not start.");
                observer = Process.GetProcessById(expectedChild.Id);
                // GetProcessById is lazy: retain a query handle before the child
                // exits so independent exit-code evidence survives Host disposal.
                _ = observer.SafeHandle;
                expectedChild.StandardInput.AutoFlush = true;
                timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
                var stderr = ReadBoundedAsync(expectedChild.StandardError, timeout.Token);
                await channel.AttachAsync(expectedChild, timeout.Token);
                await ExpectLineAsync(
                    expectedChild,
                    $"fixture:ready:{expectedChild.Id}",
                    timeout.Token);

                host = new DshHostService(
                    CreateEnterpriseOptions(directory.FullName),
                    static () => { });
                job = CreateAndAssignJob(expectedChild);
                var exitCallback = AttachExactOwnedRuntime(
                    host, expectedChild, channel, job);
                var fixture = new HostFixture(
                    directory, host, expectedChild, observer, channel, job, stderr,
                    exitCallback, timeout!);
                return fixture;
            }
            catch (Exception startFailure)
            {
                var cleanupFailures = await CleanupFailedStartAsync(
                    directory, host, expectedChild, observer, channel, job, timeout);
                if (cleanupFailures.Count != 0)
                    throw new AggregateException(
                        "Live Host fixture startup and cleanup both failed.",
                        new[] { startFailure }.Concat(cleanupFailures));
                throw;
            }
        }

        internal Task WaitForDrainingAsync() =>
            CommandAsync("wait-draining", "fixture:draining-active-preserved");

        internal async Task CommandAsync(string command, string expected)
        {
            await Child.StandardInput.WriteLineAsync(command.AsMemory(), Token);
            await ExpectLineAsync(Child, expected, Token);
        }

        internal Task ExpectOutputAsync(string expected) =>
            ExpectLineAsync(Child, expected, Token);

        internal Task AllowExitAsync() => File.WriteAllTextAsync(
            Path.Combine(_directory.FullName, "allow-exit"), "allow", Token);

        internal void InjectHomeWriterSession(IDshHomeWriterSession session) =>
            Field("_homeWriterSession").SetValue(Host, session);

        internal async Task AssertCleanNaturalExitAsync()
        {
            var stderr = await _stderr.WaitAsync(TimeSpan.FromSeconds(5));
            Assert(stderr.Length == 0, $"Node fixture stderr was not empty: {stderr}");
            var callbackFailure = await _exitCallback.WaitAsync(TimeSpan.FromSeconds(5));
            if (callbackFailure is not null)
                throw new InvalidOperationException(
                    "The Host process-exit callback failed.", callbackFailure);
        }

        public async ValueTask DisposeAsync()
        {
            var failures = new List<Exception>();
            try
            {
                if (!Observer.HasExited)
                {
                    using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                    try { await Host.StopOwnedProcessAsync(cleanup.Token); }
                    catch (Exception exception)
                    {
                        failures.Add(exception);
                        try { if (!Observer.HasExited) Observer.Kill(entireProcessTree: true); }
                        catch (Exception killFailure) when (killFailure is InvalidOperationException or System.ComponentModel.Win32Exception)
                        { failures.Add(killFailure); }
                    }
                    try { await Observer.WaitForExitAsync(cleanup.Token); }
                    catch (Exception exception) { failures.Add(exception); }
                }
                try { await Host.DisposeAsync(); }
                catch (Exception exception) { failures.Add(exception); }
                try
                {
                    var stderr = await _stderr.WaitAsync(TimeSpan.FromSeconds(5));
                    if (stderr.Length != 0)
                        failures.Add(new InvalidOperationException(
                            $"Node fixture stderr was not empty: {stderr}"));
                }
                catch (Exception exception) { failures.Add(exception); }
                try
                {
                    var callbackFailure = await _exitCallback.WaitAsync(TimeSpan.FromSeconds(5));
                    if (callbackFailure is not null) failures.Add(callbackFailure);
                }
                catch (Exception exception) { failures.Add(exception); }
            }
            finally
            {
                _channel.Dispose();
                DisposeObject(_job);
                Child.Dispose();
                Observer.Dispose();
                _timeout.Dispose();
                try { DeleteOwnedDirectory(_directory); }
                catch (Exception exception) { failures.Add(exception); }
            }
            if (failures.Count != 0)
                throw new AggregateException("Live Host fixture cleanup failed.", failures);
        }

        private FieldInfo Field(string name) => typeof(DshHostService).GetField(
            name, PrivateInstance)
            ?? throw new InvalidOperationException($"Host field {name} is unavailable.");
    }

    private static ProcessStartInfo CreateNodeStartInfo(
        string source,
        string node,
        string root,
        string mode,
        DshRuntimeUpdateChannel channel)
    {
        var start = new ProcessStartInfo(node)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = source,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        start.ArgumentList.Add("--import");
        start.ArgumentList.Add(new Uri(
            Path.Combine(source, "node_modules/tsx/dist/loader.mjs")).AbsoluteUri);
        start.ArgumentList.Add(Path.Combine(
            source, "apps/cli/tests/fixtures/managed-update-process.ts"));
        start.ArgumentList.Add(root);
        start.ArgumentList.Add(mode);
        start.Environment["TSX_TSCONFIG_PATH"] = Path.Combine(source, "tsconfig.base.json");
        start.Environment["TSX_DISABLE_CACHE"] = "1";
        foreach (var pair in channel.CreateBootstrapEnvironment())
            start.Environment[pair.Key] = pair.Value;
        return start;
    }

    private static DshRuntimeOptions CreateEnterpriseOptions(string root) => new(
        root,
        root,
        root,
        Host: "127.0.0.1",
        Port: 3191,
        Mode: DshRuntimeMode.EnterpriseManaged,
        WorkingDirectory: root,
        Profile: DshRuntimeOptions.EnterpriseManagedProfile,
        EnterpriseManagedFixedPort: 3191,
        EnterpriseManagedPluginRoot: root,
        EnterpriseManagedSkillsRoot: root);

    private static object CreateAndAssignJob(Process child)
    {
        var type = typeof(DshHostService).Assembly.GetType("Ensou.Dsh.Host.WindowsJobObject")
            ?? throw new InvalidOperationException("Windows job type is unavailable.");
        var job = type.GetMethod("CreateKillOnClose", BindingFlags.Static | BindingFlags.Public)!
            .Invoke(null, new object?[] { null, null })
            ?? throw new InvalidOperationException("Windows job could not be created.");
        type.GetMethod("Assign", BindingFlags.Instance | BindingFlags.Public)!
            .Invoke(job, new object[] { child });
        return job;
    }

    private static Task<Exception?> AttachExactOwnedRuntime(
        DshHostService host,
        Process child,
        DshRuntimeUpdateChannel channel,
        object job)
    {
        var hostType = typeof(DshHostService);
        var bindingType = hostType.GetNestedType(
            "RuntimeUpdateChannelBinding", BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Runtime binding type is unavailable.");
        var binding = Activator.CreateInstance(bindingType, child, channel)
            ?? throw new InvalidOperationException("Runtime binding could not be created.");
        SetField(host, "_ownedProcess", child);
        SetField(host, "_runtimeUpdateChannel", binding);
        SetField(host, "_jobObject", job);

        var exitMethod = hostType.GetMethod(
            "HandleOwnedProcessExited", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Host exit handler is unavailable.");
        var callback = new TaskCompletionSource<Exception?>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        EventHandler handler = (_, _) =>
        {
            try
            {
                exitMethod.Invoke(host, new[] { child, job });
                callback.TrySetResult(null);
            }
            catch (Exception exception)
            {
                callback.TrySetResult(exception);
            }
        };
        SetField(host, "_ownedProcessExitHandler", handler);
        child.EnableRaisingEvents = true;
        child.Exited += handler;
        return callback.Task;
    }

    private static async Task<List<Exception>> CleanupFailedStartAsync(
        DirectoryInfo directory,
        DshHostService? host,
        Process? child,
        Process? observer,
        DshRuntimeUpdateChannel? channel,
        object? job,
        CancellationTokenSource? timeout)
    {
        var failures = new List<Exception>();
        using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try { channel?.Dispose(); } catch (Exception exception) { failures.Add(exception); }
        var exitHandle = observer ?? child;
        try { if (exitHandle is { HasExited: false }) exitHandle.Kill(entireProcessTree: true); }
        catch (Exception exception) { failures.Add(exception); }
        try { if (exitHandle is not null) await exitHandle.WaitForExitAsync(cleanup.Token); }
        catch (Exception exception) { failures.Add(exception); }
        try { if (host is not null) await host.DisposeAsync(); }
        catch (Exception exception) { failures.Add(exception); }
        try { DisposeObject(job); } catch (Exception exception) { failures.Add(exception); }
        try { child?.Dispose(); } catch (Exception exception) { failures.Add(exception); }
        try { observer?.Dispose(); } catch (Exception exception) { failures.Add(exception); }
        timeout?.Dispose();
        try { DeleteOwnedDirectory(directory); } catch (Exception exception) { failures.Add(exception); }
        return failures;
    }

    private static void DeleteOwnedDirectory(DirectoryInfo directory)
    {
        directory.Refresh();
        var temp = Path.GetFullPath(Path.GetTempPath())
            .TrimEnd(Path.DirectorySeparatorChar);
        if (directory.LinkTarget is not null
            || directory.Parent?.FullName != temp
            || !directory.Name.StartsWith("ensou-dsh-live-host-", StringComparison.Ordinal))
            throw new InvalidOperationException(
                "Refusing cleanup outside the owned fixture root.");
        directory.Delete(recursive: true);
    }

    private static void SetField(DshHostService host, string name, object? value) =>
        (typeof(DshHostService).GetField(
            name, BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException($"Host field {name} is unavailable."))
        .SetValue(host, value);

    private static async Task ExpectLineAsync(
        Process child,
        string expected,
        CancellationToken token)
    {
        var line = await child.StandardOutput.ReadLineAsync(token);
        Assert(line == expected, $"Unexpected fixture response: {line ?? "EOF"}.");
    }

    private static async Task<string> ReadBoundedAsync(
        StreamReader reader,
        CancellationToken token)
    {
        var output = new StringBuilder();
        var buffer = new char[1024];
        int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory(), token)) != 0)
        {
            if (output.Length + count > 32 * 1024)
                throw new InvalidDataException("Fixture stderr exceeded its bound.");
            output.Append(buffer, 0, count);
        }
        return output.ToString();
    }

    private static string RequiredFileRoot(string name, string relative)
    {
        var root = Environment.GetEnvironmentVariable(name);
        if (root is null
            || !Path.IsPathFullyQualified(root)
            || !File.Exists(Path.Combine(root, relative)))
            throw new InvalidOperationException($"Explicit {name} source fixture is required.");
        return Path.GetFullPath(root);
    }

    private static void DisposeObject(object? value)
    {
        if (value is IDisposable disposable) disposable.Dispose();
    }

    private static bool ContainsReference(Exception? current, Exception expected)
    {
        if (ReferenceEquals(current, expected)) return true;
        if (current is AggregateException aggregate
            && aggregate.InnerExceptions.Any(inner => ContainsReference(inner, expected)))
            return true;
        return current?.InnerException is { } inner
            && ContainsReference(inner, expected);
    }

    private sealed class ThrowingWriterSession(Exception failure) : IDshHomeWriterSession
    {
        public string JobName => "fixture-managed-update-job";
        public void RecordAssignedProcess(int processId, long creationFileTimeUtc) { }
        public void RecordJobEmpty() { }
        public void RecordNeverStarted() { }
        public void Dispose() => throw failure;
    }

    private static void Assert(bool passed, string message)
    {
        if (!passed) throw new InvalidOperationException(message);
    }

    private static async Task ThrowsAsync<T>(Func<Task> action) where T : Exception
    {
        try { await action(); }
        catch (T) { return; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }

    private static async Task ThrowsAnyAsync(Func<Task> action, params Type[] expected)
    {
        try { await action(); }
        catch (Exception exception) when (expected.Contains(exception.GetType())) { return; }
        throw new InvalidOperationException(
            $"Expected one of: {string.Join(", ", expected.Select(type => type.Name))}.");
    }

    private static async Task<T> CaptureAsync<T>(Func<Task> action) where T : Exception
    {
        try { await action(); }
        catch (T exception) { return exception; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }
}
