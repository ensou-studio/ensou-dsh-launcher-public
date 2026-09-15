using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using Ensou.Dsh.Host;

/// <summary>
/// Runs an opt-in normal Host smoke against one complete packaged enterprise runtime.
/// </summary>
internal static class NormalManagedHostSmoke
{
    /// <summary>
    /// Starts the supplied packaged runtime through the public Host API, proves its
    /// authenticated health and retained ownership, then requests graceful update shutdown.
    /// </summary>
    /// <param name="runtimeRoot">Absolute packaged runtime root.</param>
    /// <returns>A task that completes after the Host releases the exited runtime.</returns>
    internal static async Task RunAsync(string runtimeRoot)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("The normal managed Host smoke requires Windows.");

        var runtime = RequirePackagedRuntime(runtimeRoot);
        var root = Directory.CreateTempSubdirectory("ensou-dsh-normal-managed-host-");
        DshHostService? host = null;
        Process? launchedProcessObserver = null;
        LoopbackModelSink? modelSink = null;
        Exception? operationFailure = null;
        var cleanupFailures = new List<Exception>();
        var observedPhases = new ConcurrentQueue<string>();
        var mayDeleteOwnedRoot = true;
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        try
        {
            var data = Directory.CreateDirectory(Path.Combine(root.FullName, "dsh-home")).FullName;
            var workspace = Directory.CreateDirectory(Path.Combine(data, "workspaces")).FullName;
            var pluginRoot = Directory.CreateDirectory(Path.Combine(root.FullName, "plugin-policy")).FullName;
            var skills = Directory.CreateDirectory(Path.Combine(pluginRoot, "skills")).FullName;
            var logs = Directory.CreateDirectory(Path.Combine(root.FullName, "logs")).FullName;
            // Let Windows select a bindable port: a random number may be in a
            // Hyper-V or other OS-excluded range even when no listener exists.
            // The listener is released before DSH starts; Host ownership and
            // health checks still reject any process that wins that small race.
            var fixedPort = AllocateLoopbackPort();
            Console.WriteLine($"HOST-SMOKE isolated-loopback-port={fixedPort}");
            DshRuntimeOptions options;
            if (DshRuntimeMetadata.ReadSupportsEnterpriseDirectLocal(runtime))
            {
                options = DshRuntimeOptions.CreateEnterpriseDirectLocal(
                    runtime,
                    data,
                    logs,
                    workspace,
                    fixedPort,
                    pluginRoot,
                    skills);
            }
            else
            {
                modelSink = new LoopbackModelSink();
                options = DshRuntimeOptions.CreateEnterpriseManaged(
                    runtime,
                    data,
                    logs,
                    workspace,
                    fixedPort,
                    pluginRoot,
                    skills,
                    ControlledEnvironment(modelSink.BaseUri));
            }
            options.Validate();
            Assert(!options.CaptureRawProcessOutput,
                "The normal managed Host smoke must not retain raw runtime output.");
            Assert(options.WebAuthProtocol == DshRuntimeWebAuthProtocol.BrowserLaunchCookieV1,
                "The packaged runtime does not declare browser-launch cookie authentication.");

            // Keep the Host's public pre-launch callback meaningful: this repeats the
            // physical packaged-layout validation immediately before the real process
            // is allowed to start, rather than bypassing the production start seam.
            host = new DshHostService(
                options,
                validateBeforeProcessStart: options.Validate,
                httpClient: null,
                healthProbeTimeout: null,
                candidateHealthRetryTimeout: null,
                validateBeforeResume: null,
                acquireHomeWriterSession: null,
                diagnostic: (phase, _) => observedPhases.Enqueue(phase));
            var launch = await host.EnsureStartedAsync(timeout.Token);
            Assert(launch.State == DshLaunchState.Started && launch.ProcessId is > 0,
                "The Host did not report a newly started exact runtime process.");
            var processId = launch.ProcessId
                ?? throw new InvalidOperationException("The normal Host returned no process identity.");
            launchedProcessObserver = Process.GetProcessById(processId);
            // Open and retain the query handle before shutdown. A PID-only observer
            // could otherwise try to open its handle after the process has exited.
            Assert(!launchedProcessObserver.SafeHandle.IsInvalid,
                "The exact process query handle could not be retained.");
            Assert(launchedProcessObserver.Id == processId
                && !launchedProcessObserver.HasExited,
                "The independent observer could not retain the exact running Host process.");
            Assert(host.OwnsRunningProcess,
                "The Host did not retain ownership of its healthy runtime process.");
            // The public health call applies the private browser-launch cookie before
            // reading the root document and independently rechecks exact PID ownership.
            Assert(await host.IsHealthyAsync(timeout.Token),
                "The Host could not prove cookie-authenticated health for its exact runtime.");
            var phases = observedPhases.ToArray();
            foreach (var required in new[]
            {
                "host_job_create_end", "host_runtime_lease_end", "host_inventory_end",
                "host_suspended_start_assigned", "host_suspended_start_validated",
                "host_suspended_start_end", "host_health_passed",
            })
            {
                Assert(phases.Contains(required, StringComparer.Ordinal),
                    $"The normal Host did not observe its required {required} phase.");
            }

            await host.StopForManagedUpdateAsync(Guid.NewGuid(), timeout.Token);
            launchedProcessObserver.Refresh();
            Assert(launchedProcessObserver.HasExited,
                "Managed update shutdown did not naturally exit the independently observed process.");
            Assert(launchedProcessObserver.ExitCode == 0,
                "Managed update shutdown did not naturally exit the exact process with code zero.");
            Assert(!host.OwnsRunningProcess,
                "Graceful managed update shutdown retained a process ownership claim.");
            Assert(!await host.IsHealthyAsync(timeout.Token),
                "The released runtime remained healthy through the Host API.");
            Console.WriteLine("PASS  normal managed Host: real runtime lease and suspended job start, cookie health, exact ownership, graceful drain exit");
            Console.WriteLine("SCOPE Host integration only: no enterprise release-store/authentication callback or personal atomic home-writer session.");
        }
        catch (Exception exception)
        {
            operationFailure = exception;
        }
        finally
        {
            if (host is not null)
            {
                try
                {
                    if (host.OwnsRunningProcess)
                    {
                        using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                        await host.StopOwnedProcessAsync(cleanup.Token);
                    }
                }
                catch (Exception exception)
                {
                    cleanupFailures.Add(exception);
                    mayDeleteOwnedRoot = false;
                }
                try
                {
                    await host.DisposeAsync();
                }
                catch (Exception exception)
                {
                    cleanupFailures.Add(exception);
                    mayDeleteOwnedRoot = false;
                }
            }
            if (launchedProcessObserver is not null)
            {
                try
                {
                    launchedProcessObserver.Refresh();
                    if (!launchedProcessObserver.HasExited)
                    {
                        throw new InvalidOperationException(
                            "The independently observed Host process did not exit during cleanup.");
                    }
                }
                catch (Exception exception)
                {
                    cleanupFailures.Add(exception);
                    mayDeleteOwnedRoot = false;
                }
                finally
                {
                    launchedProcessObserver.Dispose();
                }
            }
            if (modelSink is not null)
            {
                try
                {
                    await modelSink.DisposeAsync();
                }
                catch (Exception exception)
                {
                    cleanupFailures.Add(exception);
                }
            }
            if (mayDeleteOwnedRoot)
            {
                try
                {
                    DeleteOwnedRoot(root);
                }
                catch (Exception exception)
                {
                    cleanupFailures.Add(exception);
                }
            }
        }

        if (operationFailure is not null)
        {
            if (cleanupFailures.Count > 0)
            {
                throw new AggregateException(
                    "Normal managed Host smoke failed and cleanup did not complete.",
                    [operationFailure, .. cleanupFailures]);
            }
            ExceptionDispatchInfo.Capture(operationFailure).Throw();
        }
        if (cleanupFailures.Count > 0)
        {
            throw new AggregateException("Normal managed Host smoke cleanup failed.", cleanupFailures);
        }
    }

    private static int AllocateLoopbackPort()
    {
        using var reservation = new TcpListener(IPAddress.Loopback, 0);
        reservation.ExclusiveAddressUse = true;
        reservation.Start();
        return ((IPEndPoint)reservation.LocalEndpoint).Port;
    }

    private static IReadOnlyDictionary<string, string> ControlledEnvironment(Uri modelProxy)
    {
        var endpoint = modelProxy.AbsoluteUri.TrimEnd('/');
        return new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["DEEPSEEK_BASE_URL"] = endpoint,
            ["DEEPSEEK_SEARCH_BASE_URL"] = endpoint,
            ["DEEPSEEK_API_KEY"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_'),
        };
    }

    private static string RequirePackagedRuntime(string runtimeRoot)
    {
        if (string.IsNullOrWhiteSpace(runtimeRoot) || !Path.IsPathFullyQualified(runtimeRoot))
            throw new InvalidOperationException("The packaged runtime root must be an absolute path.");
        var root = Path.GetFullPath(runtimeRoot).TrimEnd(Path.DirectorySeparatorChar);
        if (!Directory.Exists(root) || new DirectoryInfo(root).LinkTarget is not null)
            throw new InvalidOperationException("The packaged runtime root must be an existing physical directory.");
        RequireFile(Path.Combine(root, "node.exe"), "packaged node.exe");
        RequireFile(Path.Combine(root, "node_modules", "@deepseek-ai", "dsh", "lib", "bin.js"),
            "deployed DSH CLI entry point");
        RequireFile(Path.Combine(root, DshRuntimeMetadata.FileName), "runtime metadata");
        return root;
    }

    private static void RequireFile(string path, string description)
    {
        if (!File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException($"The {description} must be a physical file in the packaged runtime.");
    }

    private static void DeleteOwnedRoot(DirectoryInfo root)
    {
        root.Refresh();
        var temp = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar);
        if (root.LinkTarget is not null
            || (root.Attributes & FileAttributes.ReparsePoint) != 0
            || !string.Equals(root.Parent?.FullName, temp, StringComparison.OrdinalIgnoreCase)
            || !root.Name.StartsWith("ensou-dsh-normal-managed-host-", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Refusing cleanup outside the normal Host smoke's owned temp root.");
        }
        RequireNoReparseDescendants(root);
        root.Refresh();
        if ((root.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Refusing cleanup through a reparse-point temp root.");
        root.Delete(recursive: true);
    }

    private static void RequireNoReparseDescendants(DirectoryInfo root)
    {
        var directories = new Stack<DirectoryInfo>();
        directories.Push(root);
        while (directories.Count > 0)
        {
            var current = directories.Pop();
            current.Refresh();
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Refusing cleanup through a reparse-point descendant.");
            foreach (var path in Directory.EnumerateFileSystemEntries(current.FullName))
            {
                var attributes = File.GetAttributes(path);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException("Refusing cleanup through a reparse-point descendant.");
                if ((attributes & FileAttributes.Directory) != 0)
                    directories.Push(new DirectoryInfo(path));
            }
        }
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private sealed class LoopbackModelSink : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _serve;

        internal LoopbackModelSink()
        {
            _listener.Start();
            BaseUri = new Uri($"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}/v1", UriKind.Absolute);
            _serve = ServeAsync();
        }

        internal Uri BaseUri { get; }

        public async ValueTask DisposeAsync()
        {
            _stop.Cancel();
            _listener.Stop();
            try { await _serve; }
            catch (OperationCanceledException) { }
            catch (ObjectDisposedException) { }
            _stop.Dispose();
        }

        private async Task ServeAsync()
        {
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    using var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                    await RespondAsync(client, _stop.Token);
                }
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
            catch (ObjectDisposedException) when (_stop.IsCancellationRequested) { }
        }

        private static async Task RespondAsync(TcpClient client, CancellationToken token)
        {
            await using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
            var bytes = 0;
            while (true)
            {
                var line = await reader.ReadLineAsync(token);
                if (line is null || line.Length == 0) break;
                bytes += line.Length + 2;
                if (bytes > 8 * 1024)
                    throw new InvalidDataException("Model proxy request headers exceeded 8 KiB.");
            }
            const string body = "{\"object\":\"list\",\"data\":[]}";
            var response = Encoding.UTF8.GetBytes(
                $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {Encoding.UTF8.GetByteCount(body)}\r\nConnection: close\r\n\r\n{body}");
            await stream.WriteAsync(response, token);
            await stream.FlushAsync(token);
        }
    }
}
