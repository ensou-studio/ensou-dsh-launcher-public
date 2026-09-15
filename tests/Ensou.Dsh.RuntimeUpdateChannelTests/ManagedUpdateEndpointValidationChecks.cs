using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.Host;

internal static class ManagedUpdateEndpointValidationChecks
{
    internal static async Task ExactRetainedPipeAllowsSuspendedListenerAsync()
    {
        var port = GetUnusedLoopbackPort();
        using var listener = new TcpListener(IPAddress.Loopback, port);
        listener.Start();
        await using var fixture = HostValidationFixture.Create(port, acquireLease: true);
        var process = fixture.OwnedProcess;
        var instance = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var operation = Guid.Parse("22222222-2222-2222-2222-222222222222");
        using var channel = DshRuntimeUpdateChannel.Create(
            fixture.ValidateExactManagedRuntime,
            instance);
        var listenerSuspended = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var client = ConnectCurrentProcessAsync(channel.PipeName, async stream =>
        {
            var drain = ParseRequest(await ReadLineAsync(
                stream,
                CancellationToken.None));
            Assert(drain.Action == "drain" && drain.OperationId == operation,
                "The retained-pipe fixture did not receive the exact drain request.");
            listener.Stop();
            listenerSuspended.TrySetResult();
            await WriteReceiptAsync(
                stream,
                instance,
                operation,
                process.Id,
                phase: "draining",
                activeOperations: 1,
                persistenceFlushed: false);

            var resume = ParseRequest(await ReadLineAsync(
                stream,
                CancellationToken.None));
            Assert(resume.Action == "resume" && resume.OperationId == operation,
                "The retained-pipe fixture did not receive the exact Resume request.");
            listener.Start();
            await WriteReceiptAsync(
                stream,
                instance,
                operation,
                process.Id,
                phase: "resumed",
                activeOperations: 0,
                persistenceFlushed: false);
        });

        // No managed-update lease exists during attachment, so this succeeds
        // only while the exact current process owns the real listener.
        fixture.BindRuntimeUpdateChannel(channel);
        var retainedBinding = fixture.RuntimeUpdateChannelBinding;
        await channel.AttachAsync(process);
        Assert(fixture.ValidateExactManagedRuntime(process),
            "Initial channel attachment did not require the exact live listener.");

        using var cancellation = new CancellationTokenSource();
        var stop = fixture.Host.StopForManagedUpdateAsync(
            operation,
            cancellation.Token);
        var suspensionOwner = await Task.WhenAny(
                listenerSuspended.Task,
                client)
            .WaitAsync(TimeSpan.FromSeconds(5));
        if (ReferenceEquals(suspensionOwner, client))
        {
            await client;
            throw new InvalidOperationException(
                "The pipe fixture ended before suspending HTTP admission.");
        }
        await listenerSuspended.Task;
        await WaitForListenerReleaseAsync(process, port);
        cancellation.Cancel();
        await ThrowsAsync<OperationCanceledException>(() => stop);
        await client;
        Assert(ReferenceEquals(
                retainedBinding,
                fixture.RuntimeUpdateChannelBinding),
            "Managed-update cancellation did not retain the exact pipe binding.");
        Assert(fixture.ManagedUpdateChannelLeaseProcess is null,
            "Managed-update cancellation retained a stale channel lease.");
        Assert(OwnsLoopbackListener(process, port)
            && fixture.ValidateExactManagedRuntime(process),
            "Resume did not restore the exact process's loopback endpoint.");
    }

    internal static Task MissingRuntimeLeaseRejectsAsync()
    {
        return RunFixtureAsync(acquireLease: false, fixture =>
        {
            fixture.RetainManagedUpdateChannelLease();
            Throws<InvalidOperationException>(() =>
                fixture.ValidateExactManagedRuntime(fixture.OwnedProcess));
        });
    }

    internal static Task MissingManagedChannelLeaseRejectsClosedListenerAsync()
    {
        return RunFixtureAsync(acquireLease: true, fixture =>
        {
            Assert(!fixture.ValidateExactManagedRuntime(fixture.OwnedProcess),
                "A closed listener passed without an exact managed-update channel lease.");
        });
    }

    internal static Task DifferentProcessIdentityRejectsAsync()
    {
        return RunFixtureAsync(acquireLease: true, fixture =>
        {
            fixture.RetainManagedUpdateChannelLease();
            using var differentProcessObject = Process.GetProcessById(
                fixture.OwnedProcess.Id);
            Assert(!ReferenceEquals(
                    differentProcessObject,
                    fixture.OwnedProcess)
                && !fixture.ValidateExactManagedRuntime(differentProcessObject),
                "A different Process identity passed the retained-runtime validator.");
        });
    }

    internal static Task TamperedRuntimeInventoryRejectsAsync()
    {
        return RunFixtureAsync(acquireLease: true, fixture =>
        {
            fixture.RetainManagedUpdateChannelLease();
            fixture.AddUnadmittedRuntimeFile();
            Throws<InvalidDataException>(() =>
                fixture.ValidateExactManagedRuntime(fixture.OwnedProcess));
        });
    }

    private static async Task RunFixtureAsync(
        bool acquireLease,
        Action<HostValidationFixture> assertion)
    {
        await using var fixture = HostValidationFixture.Create(
            GetUnusedLoopbackPort(),
            acquireLease);
        assertion(fixture);
    }

    private static int GetUnusedLoopbackPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static async Task WaitForListenerReleaseAsync(Process process, int port)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (OwnsLoopbackListener(process, port))
        {
            await Task.Delay(TimeSpan.FromMilliseconds(5), timeout.Token);
        }
    }

    private static bool OwnsLoopbackListener(Process process, int port)
    {
        var type = typeof(DshHostService).Assembly.GetType(
            "Ensou.Dsh.Host.DshLoopbackListenerOwnership")
            ?? throw new InvalidOperationException(
                "The loopback listener ownership validator is unavailable.");
        var method = type.GetMethod(
            "IsExactProcessListeningOnIpv4Loopback",
            BindingFlags.Static | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "The exact loopback listener ownership method is unavailable.");
        return (bool)(method.Invoke(null, [process, port])
            ?? throw new InvalidOperationException(
                "The loopback listener ownership validator returned no result."));
    }

    private static async Task ConnectCurrentProcessAsync(
        string pipeName,
        Func<Stream, Task> exchange)
    {
        await using var client = new NamedPipeClientStream(
            ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await client.ConnectAsync(5_000);
        await exchange(client);
    }

    private static RuntimeUpdateRequest ParseRequest(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        return new RuntimeUpdateRequest(
            root.GetProperty("action").GetString()
                ?? throw new InvalidDataException("The fixture action is missing."),
            root.GetProperty("operationId").GetGuid());
    }

    private static async Task WriteReceiptAsync(
        Stream stream,
        Guid runtimeInstanceId,
        Guid operationId,
        int processId,
        string phase,
        int activeOperations,
        bool persistenceFlushed)
    {
        var response = $"{{\"protocol\":\"ensou.dsh.runtime-update.v1\",\"runtimeInstanceId\":\"{runtimeInstanceId:D}\",\"operationId\":\"{operationId:D}\",\"processId\":{processId},\"phase\":\"{phase}\",\"activeOperations\":{activeOperations},\"persistenceFlushed\":{persistenceFlushed.ToString().ToLowerInvariant()}}}\n";
        await stream.WriteAsync(Encoding.UTF8.GetBytes(response));
        await stream.FlushAsync();
    }

    private static async Task<string> ReadLineAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        using var bytes = new MemoryStream();
        var next = new byte[1];
        while (true)
        {
            var count = await stream.ReadAsync(next, cancellationToken);
            if (count == 0) throw new EndOfStreamException();
            if (next[0] == (byte)'\n') return Encoding.UTF8.GetString(bytes.ToArray());
            bytes.WriteByte(next[0]);
        }
    }

    private static void Throws<T>(Action action) where T : Exception
    {
        try { action(); }
        catch (T) { return; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }

    private static async Task ThrowsAsync<T>(Func<Task> action) where T : Exception
    {
        try { await action(); }
        catch (T) { return; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private sealed record RuntimeUpdateRequest(string Action, Guid OperationId);

    private sealed class HostValidationFixture : IAsyncDisposable
    {
        private static readonly BindingFlags PrivateInstance =
            BindingFlags.Instance | BindingFlags.NonPublic;
        private readonly DirectoryInfo _root;
        private readonly string _runtimeRoot;
        private readonly MethodInfo _validator;
        private IDisposable? _runtimeLease;

        private HostValidationFixture(
            DirectoryInfo root,
            string runtimeRoot,
            DshHostService host,
            Process ownedProcess,
            MethodInfo validator,
            IDisposable? runtimeLease)
        {
            _root = root;
            _runtimeRoot = runtimeRoot;
            Host = host;
            OwnedProcess = ownedProcess;
            _validator = validator;
            _runtimeLease = runtimeLease;
        }

        internal DshHostService Host { get; }
        internal Process OwnedProcess { get; }
        internal object? RuntimeUpdateChannelBinding =>
            Field("_runtimeUpdateChannel").GetValue(Host);
        internal Process? ManagedUpdateChannelLeaseProcess =>
            (Process?)Field("_managedUpdateChannelLeaseProcess").GetValue(Host);

        internal static HostValidationFixture Create(int port, bool acquireLease)
        {
            var root = Directory.CreateTempSubdirectory(
                "ensou-dsh-update-validator-");
            DshHostService? host = null;
            Process? process = null;
            IDisposable? runtimeLease = null;
            try
            {
                var runtime = Directory.CreateDirectory(
                    Path.Combine(root.FullName, "runtime")).FullName;
                var entry = Path.Combine(
                    runtime,
                    "node_modules",
                    "@deepseek-ai",
                    "dsh",
                    "lib",
                    "bin.js");
                Directory.CreateDirectory(Path.GetDirectoryName(entry)!);
                File.WriteAllText(Path.Combine(runtime, "node.exe"), "fixture-node");
                File.WriteAllText(entry, "fixture-entry");
                File.WriteAllText(
                    Path.Combine(runtime, DshRuntimeMetadata.FileName),
                    "{\"schemaVersion\":2,\"webAuthProtocol\":\"browser-launch-cookie-v1\",\"managedUpdateProtocol\":\"personal-web-v1\"}");
                var data = Directory.CreateDirectory(
                    Path.Combine(root.FullName, "data")).FullName;
                var logs = Directory.CreateDirectory(
                    Path.Combine(root.FullName, "logs")).FullName;
                var options = DshRuntimeOptions.CreatePersonalManagedWeb(
                    runtime,
                    data,
                    logs,
                    port);
                host = new DshHostService(options, options.Validate);
                process = Process.GetCurrentProcess();

                if (acquireLease)
                {
                    var leaseType = typeof(DshHostService).Assembly.GetType(
                        "Ensou.Dsh.Host.DshRuntimeLaunchLease")
                        ?? throw new InvalidOperationException(
                            "The runtime launch lease type is unavailable.");
                    var acquire = leaseType.GetMethod(
                        "Acquire",
                        BindingFlags.Static | BindingFlags.NonPublic)
                        ?? throw new InvalidOperationException(
                            "The runtime launch lease acquisition method is unavailable.");
                    runtimeLease = (IDisposable)(acquire.Invoke(
                        null,
                        [options, (Action)options.Validate])
                        ?? throw new InvalidOperationException(
                            "The runtime launch lease was not acquired."));
                    SetField(host, "_runtimeLaunchLease", runtimeLease);
                }

                SetField(host, "_ownedProcess", process);
                var validator = typeof(DshHostService).GetMethod(
                    "IsExactManagedUpdateRuntime",
                    PrivateInstance)
                    ?? throw new InvalidOperationException(
                        "The managed runtime validator is unavailable.");
                return new HostValidationFixture(
                    root,
                    runtime,
                    host,
                    process,
                    validator,
                    runtimeLease);
            }
            catch
            {
                if (host is not null)
                {
                    SetField(host, "_managedUpdateChannelLeaseProcess", null);
                    SetField(host, "_ownedProcess", null);
                    SetField(host, "_runtimeLaunchLease", null);
                }
                runtimeLease?.Dispose();
                process?.Dispose();
                if (host is not null) host.DisposeAsync().AsTask().GetAwaiter().GetResult();
                DeleteOwnedRoot(root);
                throw;
            }
        }

        internal bool ValidateExactManagedRuntime(Process candidate)
        {
            try
            {
                return (bool)(_validator.Invoke(Host, [candidate])
                    ?? throw new InvalidOperationException(
                        "The managed runtime validator returned no result."));
            }
            catch (TargetInvocationException exception)
                when (exception.InnerException is not null)
            {
                ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
                throw;
            }
        }

        internal void RetainManagedUpdateChannelLease() =>
            SetField(Host, "_managedUpdateChannelLeaseProcess", OwnedProcess);

        internal void BindRuntimeUpdateChannel(DshRuntimeUpdateChannel channel)
        {
            var bindingType = typeof(DshHostService).GetNestedType(
                "RuntimeUpdateChannelBinding",
                BindingFlags.NonPublic)
                ?? throw new InvalidOperationException(
                    "The runtime update binding type is unavailable.");
            var binding = Activator.CreateInstance(
                bindingType,
                OwnedProcess,
                channel)
                ?? throw new InvalidOperationException(
                    "The runtime update binding could not be created.");
            SetField(Host, "_runtimeUpdateChannel", binding);
        }

        internal void AddUnadmittedRuntimeFile() => File.WriteAllText(
            Path.Combine(_runtimeRoot, "unadmitted-after-lease.txt"),
            "tamper");

        public async ValueTask DisposeAsync()
        {
            var failures = new List<Exception>();
            try
            {
                SetField(Host, "_managedUpdateChannelLeaseProcess", null);
                SetField(Host, "_runtimeUpdateChannel", null);
                SetField(Host, "_ownedProcess", null);
                SetField(Host, "_runtimeLaunchLease", null);
                try { _runtimeLease?.Dispose(); }
                catch (Exception exception) { failures.Add(exception); }
                _runtimeLease = null;
                try { await Host.DisposeAsync(); }
                catch (Exception exception) { failures.Add(exception); }
            }
            finally
            {
                OwnedProcess.Dispose();
                try { DeleteOwnedRoot(_root); }
                catch (Exception exception) { failures.Add(exception); }
            }
            if (failures.Count != 0)
            {
                throw new AggregateException(
                    "Managed-update validator fixture cleanup failed.",
                    failures);
            }
        }

        private static void SetField(
            DshHostService host,
            string name,
            object? value) =>
            (typeof(DshHostService).GetField(name, PrivateInstance)
                ?? throw new InvalidOperationException(
                    $"Host field {name} is unavailable."))
            .SetValue(host, value);

        private static FieldInfo Field(string name) =>
            typeof(DshHostService).GetField(name, PrivateInstance)
                ?? throw new InvalidOperationException(
                    $"Host field {name} is unavailable.");

        private static void DeleteOwnedRoot(DirectoryInfo root)
        {
            root.Refresh();
            var temp = Path.GetFullPath(Path.GetTempPath())
                .TrimEnd(Path.DirectorySeparatorChar);
            if (root.LinkTarget is not null
                || (root.Attributes & FileAttributes.ReparsePoint) != 0
                || !string.Equals(
                    root.Parent?.FullName,
                    temp,
                    StringComparison.OrdinalIgnoreCase)
                || !root.Name.StartsWith(
                    "ensou-dsh-update-validator-",
                    StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "Refusing cleanup outside the owned validator fixture root.");
            }
            root.Delete(recursive: true);
        }
    }
}
