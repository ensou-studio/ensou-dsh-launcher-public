using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Host;

namespace Ensou.Dsh.CoreTests;

internal static class DshRuntimeAdmissionTests
{
    internal static async Task RunAsync()
    {
        await RuntimeFilesRemainBoundThroughProcessAdmissionAsync();
        FreshDirectoryPreparationStillRequiresWatchedAdmission();
        RuntimeWatcherRejectsNoncriticalTreeChanges();
        await HealthRequiresTheSameOwnedProcessAsync();
        await HealthRejectsListenerLossDuringRequestAsync();
        await BrowserAuthenticationRejectsListenerLossAsync();
        await OrdinaryHealthUsesOnlyFastRuntimeChecksAsync();
        await CandidateFullBarrierRejectsProcessFlipAsync();
    }

    private static async Task RuntimeFilesRemainBoundThroughProcessAdmissionAsync()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "ensou-dsh-runtime-admission-tests",
            Guid.NewGuid().ToString("N"));
        var runtime = Path.Combine(root, "runtime");
        var entryPoint = Path.Combine(
            runtime,
            "node_modules",
            "@deepseek-ai",
            "dsh",
            "lib",
            "bin.js");
        var node = Path.Combine(runtime, "node.exe");
        var dependency = Path.Combine(
            runtime,
            "node_modules",
            "@deepseek-ai",
            "dsh",
            "lib",
            "dependency.js");
        var trustMetadata = Path.Combine(runtime, ".ensou-release.json");
        Directory.CreateDirectory(Path.GetDirectoryName(entryPoint)!);
        File.Copy(Path.Combine(Environment.SystemDirectory, "cmd.exe"), node);
        File.WriteAllText(entryPoint, "console.log('admitted');", Encoding.UTF8);
        File.WriteAllText(dependency, "export const admitted = true;", Encoding.UTF8);
        File.WriteAllText(trustMetadata, "{\"schemaVersion\":1}", Encoding.UTF8);
        var options = new DshRuntimeOptions(runtime, root, root);
        var validationCalls = 0;

        Process? admittedProcess = null;
        Process? mismatchedProcess = null;
        try
        {
            using (var lease = DshRuntimeLaunchLease.Acquire(
                       options,
                       () =>
                       {
                           validationCalls++;
                           AssertMutationDenied(() => File.Move(
                               node,
                               node + ".replaced"));
                           AssertMutationDenied(() => File.WriteAllText(
                               entryPoint,
                               "console.log('attacker');",
                               Encoding.UTF8));
                           AssertMutationDenied(() => File.WriteAllText(
                               trustMetadata,
                               "{\"schemaVersion\":2}",
                               Encoding.UTF8));
                       }))
            {
                AssertEqual(1, validationCalls);
                AssertMutationDenied(() => File.Move(
                    node,
                    node + ".late-replaced"));
                AssertMutationDenied(() => File.WriteAllText(
                    entryPoint,
                    "console.log('late-attacker');",
                    Encoding.UTF8));
                AssertMutationDenied(() => File.Delete(trustMetadata));
                lease.RequireFilesStillCurrent();

                var admittedStart = new ProcessStartInfo
                {
                    FileName = node,
                    WorkingDirectory = runtime,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                };
                admittedStart.ArgumentList.Add("/d");
                admittedStart.ArgumentList.Add("/c");
                admittedStart.ArgumentList.Add("ping -n 6 127.0.0.1 >nul");
                admittedProcess = Process.Start(admittedStart)
                    ?? throw new InvalidOperationException(
                        "Windows did not start the admitted runtime image probe.");
                lease.RequireProcessImage(admittedProcess);

                mismatchedProcess = StartHiddenPingProcess();
                AssertThrows<InvalidDataException>(() =>
                    lease.RequireProcessImage(mismatchedProcess));

                // Remove the Windows image-section lock while the admission
                // lease is still held, so the post-dispose move below proves
                // release of our file handle rather than process exit timing.
                await StopProcessAsync(admittedProcess);
                admittedProcess = null;

                AssertMutationDenied(() => File.WriteAllText(
                    dependency,
                    "export const admitted = false;",
                    Encoding.UTF8));
                lease.RequireFilesStillCurrent();
                File.WriteAllText(
                    Path.Combine(runtime, "late-added.js"),
                    "export {};",
                    Encoding.UTF8);
                AssertThrows<InvalidDataException>(
                    lease.RequireCompleteInventoryStillCurrent);
                AssertThrows<InvalidDataException>(
                    lease.RequireFilesStillCurrent);
            }

            // Releasing the health-bound lease must release both critical files.
            File.WriteAllText(
                entryPoint,
                "console.log('released');",
                Encoding.UTF8);
            File.Move(node, node + ".released");
            AssertTrue(File.Exists(node + ".released"));
            File.WriteAllText(trustMetadata, "{\"released\":true}", Encoding.UTF8);
        }
        finally
        {
            await StopProcessAsync(admittedProcess);
            await StopProcessAsync(mismatchedProcess);
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static void FreshDirectoryPreparationStillRequiresWatchedAdmission()
    {
        using var fixture = RuntimeFixture.Create();
        for (var index = 0; index < 256; index++)
        {
            var directory = Path.Combine(fixture.RuntimeDirectory, "fresh", index.ToString("D3"));
            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, "dependency.js"), "export {};", Encoding.UTF8);
        }

        var validationCalls = 0;
        using (var lease = DshRuntimeLaunchLease.Acquire(fixture.Options, () =>
               {
                   validationCalls++;
                   AssertMutationDenied(() => File.WriteAllText(
                       Path.Combine(fixture.RuntimeDirectory, "fresh", "127", "dependency.js"),
                       "export const replaced = true;", Encoding.UTF8));
               }))
        {
            AssertEqual(1, validationCalls);
            lease.RequireCompleteInventoryStillCurrent();
            // A complete post-validation scan must not clear a subsequent
            // watcher failure merely because the preparation already ran.
            lease.ReportWatcherErrorForTests();
            AssertThrows<InvalidDataException>(lease.RequireFilesStillCurrent);
            AssertThrows<InvalidDataException>(lease.RequireCompleteInventoryStillCurrent);
        }

        AssertThrows<InvalidDataException>(() => DshRuntimeLaunchLease.Acquire(
            fixture.Options,
            () =>
            {
                var transient = Path.Combine(fixture.RuntimeDirectory, "after-preparation.js");
                File.WriteAllText(transient, "export {};", Encoding.UTF8);
                File.Delete(transient);
            }));
        File.AppendAllText(fixture.DependencyPath, "released-after-refusal", Encoding.UTF8);
    }

    private static void RuntimeWatcherRejectsNoncriticalTreeChanges()
    {
        RunLockedInventoryMutationCase((_, dependency) => File.WriteAllText(
            dependency,
            "export const changed = true;",
            Encoding.UTF8));
        RunCompleteInventoryAdditionCase((runtime, _) => File.WriteAllText(
            Path.Combine(runtime, "late-added.js"),
            "export {};",
            Encoding.UTF8));
        RunCompleteInventoryAdditionCase((runtime, _) => Directory.CreateDirectory(
            Path.Combine(runtime, "late-added-directory")));
        RunLockedInventoryMutationCase((_, dependency) => File.Delete(dependency));
        RunLockedInventoryMutationCase((_, dependency) => File.Move(
            dependency,
            dependency + ".renamed"));

        using (var fixture = RuntimeFixture.Create())
        {
            using var lease = DshRuntimeLaunchLease.Acquire(
                fixture.Options,
                static () => { });
            lease.ReportWatcherErrorForTests();
            AssertThrows<InvalidDataException>(lease.RequireFilesStillCurrent);
        }

        using (var fixture = RuntimeFixture.Create())
        {
            AssertThrows<InvalidDataException>(() =>
                DshRuntimeLaunchLease.Acquire(
                    fixture.Options,
                    () =>
                    {
                        var transient = Path.Combine(
                            fixture.RuntimeDirectory,
                            "transient.js");
                        File.WriteAllText(
                            transient,
                            "export const transient = true;",
                            Encoding.UTF8);
                        File.Delete(transient);
                    }));
        }
    }

    private static void RunLockedInventoryMutationCase(
        Action<string, string> mutation)
    {
        using var fixture = RuntimeFixture.Create();
        using var lease = DshRuntimeLaunchLease.Acquire(
            fixture.Options,
            static () => { });
        AssertMutationDenied(() =>
            mutation(fixture.RuntimeDirectory, fixture.DependencyPath));
        lease.RequireFilesStillCurrent();
    }

    private static void RunCompleteInventoryAdditionCase(
        Action<string, string> mutation)
    {
        using var fixture = RuntimeFixture.Create();
        using var lease = DshRuntimeLaunchLease.Acquire(
            fixture.Options,
            static () => { });
        lease.DisableWatcherNotificationsForTests();
        mutation(fixture.RuntimeDirectory, fixture.DependencyPath);
        AssertEqual(0, lease.FullInventoryScanCountForTests);
        AssertThrows<InvalidDataException>(
            lease.RequireCompleteInventoryStillCurrent);
        AssertEqual(1, lease.FullInventoryScanCountForTests);
    }

    private static async Task HealthRequiresTheSameOwnedProcessAsync()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "ensou-dsh-owned-health-tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var options = new DshRuntimeOptions(root, root, root, Port: 3191);
        var requestCount = 0;
        var takeoverRequestEntered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseTakeoverResponse = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        using var client = new HttpClient(new AsyncDelegateHandler(
            async (_, cancellationToken) =>
            {
                var request = Interlocked.Increment(ref requestCount);
                if (request == 2)
                {
                    takeoverRequestEntered.TrySetResult();
                    await releaseTakeoverResponse.Task.WaitAsync(cancellationToken)
                        .ConfigureAwait(false);
                }
                return CreateHealthyWebUiResponse();
            }));
        var productionRequestCount = 0;
        using var productionClient = new HttpClient(new AsyncDelegateHandler(
            (_, _) =>
            {
                Interlocked.Increment(ref productionRequestCount);
                return Task.FromResult(CreateHealthyWebUiResponse());
            }));
        using (var unleasedProcess = StartHiddenPingProcess())
        {
            await using var productionService = new DshHostService(
                options,
                validateBeforeProcessStart: static () => { },
                httpClient: productionClient);
            AttachOwnedProcess(productionService, unleasedProcess);
            await AssertThrowsAsync<InvalidOperationException>(
                () => productionService.IsHealthyAsync());
            AssertEqual(0, productionRequestCount);
        }

        var service = new DshHostService(
            options,
            client,
            validateBeforeProcessStart: null,
            healthProbeTimeout: null,
            candidateHealthRetryTimeout: null,
            ownsLoopbackListener: static (_, _) => true);
        Process? ownedProcess = null;
        try
        {
            AssertFalse(await service.IsHealthyAsync());
            AssertEqual(0, requestCount);
            await AssertThrowsAsync<InvalidOperationException>(
                () => service.OpenWebUiAsync());
            AssertEqual(0, requestCount);

            ownedProcess = StartHiddenPingProcess();
            AttachOwnedProcess(service, ownedProcess);
            AssertTrue(await service.IsHealthyAsync());
            AssertEqual(1, requestCount);

            var takeoverProbe = service.IsHealthyAsync();
            await takeoverRequestEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            ownedProcess.Kill(entireProcessTree: true);
            await ownedProcess.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            releaseTakeoverResponse.TrySetResult();
            AssertFalse(await takeoverProbe.WaitAsync(TimeSpan.FromSeconds(5)));
            AssertEqual(2, requestCount);
        }
        finally
        {
            releaseTakeoverResponse.TrySetResult();
            try
            {
                await service.DisposeAsync();
            }
            finally
            {
                ownedProcess?.Dispose();
                if (Directory.Exists(root))
                {
                    Directory.Delete(root, recursive: true);
                }
            }
        }
    }

    private static async Task HealthRejectsListenerLossDuringRequestAsync()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "ensou-dsh-listener-loss-health-tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var options = new DshRuntimeOptions(root, root, root, Port: 3191);
        var requestCount = 0;
        var listenerChecks = 0;
        using var client = new HttpClient(new AsyncDelegateHandler(
            (_, _) =>
            {
                Interlocked.Increment(ref requestCount);
                return Task.FromResult(CreateHealthyWebUiResponse());
            }));
        var service = new DshHostService(
            options,
            client,
            validateBeforeProcessStart: null,
            healthProbeTimeout: null,
            candidateHealthRetryTimeout: null,
            ownsLoopbackListener: (_, _) =>
                Interlocked.Increment(ref listenerChecks) == 1);
        var ownedProcess = StartHiddenPingProcess();
        try
        {
            AttachOwnedProcess(service, ownedProcess);
            AssertFalse(await service.IsHealthyAsync());
            AssertEqual(1, requestCount);
            AssertEqual(2, listenerChecks);
            AssertFalse(ownedProcess.HasExited);
        }
        finally
        {
            await service.DisposeAsync();
            ownedProcess.Dispose();
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static async Task BrowserAuthenticationRejectsListenerLossAsync()
    {
        using var fixture = RuntimeFixture.Create();
        File.WriteAllBytes(
            Path.Combine(
                fixture.RuntimeDirectory,
                DshRuntimeMetadata.FileName),
            Encoding.UTF8.GetBytes(
                "{\"schemaVersion\":1,\"webAuthProtocol\":\"browser-launch-cookie-v1\"}"));
        var token = EncodeBase64Url(RandomNumberGenerator.GetBytes(32));
        var launchUri = new Uri(
            $"{fixture.Options.WebUiUri.AbsoluteUri}?token={token}");
        var cookieName = "dsh-auth-" + EncodeBase64Url(SHA256.HashData(
            Encoding.UTF8.GetBytes("127.0.0.1:3080")));
        var cookieSignature = EncodeBase64Url(
            RandomNumberGenerator.GetBytes(32));
        var setCookie = $"{cookieName}=v1.e30.{cookieSignature}; "
            + "Max-Age=2592000; Path=/; "
            + "Expires=Tue, 29 Sep 2026 12:00:00 GMT; HttpOnly; SameSite=Strict";
        var requestCount = 0;
        var listenerChecks = 0;
        using var client = new HttpClient(new AsyncDelegateHandler(
            (_, _) =>
            {
                Interlocked.Increment(ref requestCount);
                var response = new HttpResponseMessage(
                    HttpStatusCode.SeeOther);
                response.Headers.Location = new Uri("/", UriKind.Relative);
                response.Headers.TryAddWithoutValidation(
                    "Cache-Control",
                    "no-store");
                response.Headers.TryAddWithoutValidation(
                    "Referrer-Policy",
                    "no-referrer");
                response.Headers.TryAddWithoutValidation(
                    "Set-Cookie",
                    setCookie);
                return Task.FromResult(response);
            }));
        var service = new DshHostService(
            fixture.Options,
            client,
            validateBeforeProcessStart: null,
            healthProbeTimeout: null,
            candidateHealthRetryTimeout: null,
            ownsLoopbackListener: (_, _) =>
                Interlocked.Increment(ref listenerChecks) == 1);
        var ownedProcess = StartHiddenPingProcess();
        try
        {
            AttachOwnedProcess(service, ownedProcess);
            InitializeBrowserAuthState(service, ownedProcess);
            await AssertThrowsAsync<InvalidOperationException>(() =>
                InvokeEstablishBrowserSessionAsync(
                    service,
                    ownedProcess,
                    launchUri));
            AssertEqual(1, requestCount);
            AssertEqual(2, listenerChecks);
            AssertTrue(ReadBrowserSession(service) is null);
            AssertFalse(ownedProcess.HasExited);

            await AssertThrowsAsync<InvalidOperationException>(() =>
                InvokeEstablishBrowserSessionAsync(
                    service,
                    ownedProcess,
                    launchUri));
            AssertEqual(1, requestCount);
            AssertEqual(3, listenerChecks);
            AssertTrue(ReadBrowserSession(service) is null);
            AssertFalse(ownedProcess.HasExited);
        }
        finally
        {
            await service.DisposeAsync();
            ownedProcess.Dispose();
        }
    }

    private static async Task OrdinaryHealthUsesOnlyFastRuntimeChecksAsync()
    {
        using var fixture = RuntimeFixture.Create();
        var lease = DshRuntimeLaunchLease.Acquire(
            fixture.Options,
            static () => { });
        var process = StartHiddenPingProcess();
        using var client = new HttpClient(new AsyncDelegateHandler(
            (_, _) => Task.FromResult(CreateHealthyWebUiResponse())));
        var service = new DshHostService(
            fixture.Options,
            client,
            validateBeforeProcessStart: null,
            healthProbeTimeout: null,
            candidateHealthRetryTimeout: null,
            ownsLoopbackListener: static (_, _) => true);
        var leaseTransferred = false;
        try
        {
            AttachOwnedProcess(service, process);
            AttachRuntimeLaunchLease(service, lease);
            leaseTransferred = true;
            AssertEqual(0, lease.FullInventoryScanCountForTests);
            AssertTrue(await service.IsHealthyAsync());
            AssertTrue(await service.IsHealthyAsync());
            AssertEqual(0, lease.FullInventoryScanCountForTests);
        }
        finally
        {
            await service.DisposeAsync();
            if (!leaseTransferred)
            {
                lease.Dispose();
            }
            process.Dispose();
        }
    }

    private static async Task CandidateFullBarrierRejectsProcessFlipAsync()
    {
        using var fixture = RuntimeFixture.Create();
        var lease = DshRuntimeLaunchLease.Acquire(
            fixture.Options,
            static () => { });
        var originalProcess = StartHiddenPingProcess();
        var replacementProcess = StartHiddenPingProcess();
        using var originalObserver = Process.GetProcessById(originalProcess.Id);
        using var replacementObserver = Process.GetProcessById(
            replacementProcess.Id);
        using var client = new HttpClient(new AsyncDelegateHandler(
            CreateCandidateHealthResponseAsync));
        var service = new DshHostService(
            fixture.Options,
            client,
            validateBeforeProcessStart: null,
            healthProbeTimeout: null,
            candidateHealthRetryTimeout: null,
            ownsLoopbackListener: static (_, _) => true);
        var leaseTransferred = false;
        try
        {
            AttachOwnedProcess(service, originalProcess);
            AttachRuntimeLaunchLease(service, lease);
            leaseTransferred = true;
            lease.BeforeCompleteInventoryScanForTests = () =>
            {
                lease.BeforeCompleteInventoryScanForTests = null;
                AttachOwnedProcess(service, replacementProcess);
            };

            AssertFalse(await InvokeCandidateHealthProbeOnceAsync(service));
            AssertEqual(1, lease.FullInventoryScanCountForTests);
            AssertFalse(originalObserver.HasExited);
            AssertFalse(replacementObserver.HasExited);
        }
        finally
        {
            lease.BeforeCompleteInventoryScanForTests = null;
            await service.DisposeAsync();
            if (!leaseTransferred)
            {
                lease.Dispose();
            }
            await StopProcessAsync(originalProcess);
            replacementProcess.Dispose();
        }
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
                "Windows did not start the runtime admission probe.");
    }

    private static async Task StopProcessAsync(Process? process)
    {
        if (process is null)
        {
            return;
        }
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
        }
        finally
        {
            process.Dispose();
        }
    }

    private static void AttachOwnedProcess(
        DshHostService service,
        Process process)
    {
        var field = typeof(DshHostService).GetField(
            "_ownedProcess",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "DshHostService owned Process field was not found.");
        field.SetValue(service, process);
    }

    private static void AttachRuntimeLaunchLease(
        DshHostService service,
        DshRuntimeLaunchLease lease)
    {
        var field = typeof(DshHostService).GetField(
            "_runtimeLaunchLease",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "DshHostService runtime launch lease field was not found.");
        field.SetValue(service, lease);
    }

    private static async Task<bool> InvokeCandidateHealthProbeOnceAsync(
        DshHostService service)
    {
        var method = typeof(DshHostService).GetMethod(
            "ProbeCandidateInstallHealthOnceAsync",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "DshHostService candidate health probe was not found.");
        return await ((Task<bool>)(method.Invoke(
                service,
                [CancellationToken.None])
            ?? throw new InvalidOperationException(
                "DshHostService candidate health probe returned no task.")))
            .ConfigureAwait(false);
    }

    private static void InitializeBrowserAuthState(
        DshHostService service,
        Process process)
    {
        var method = typeof(DshHostService).GetMethod(
            "InitializeBrowserAuthState",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "DshHostService browser-auth initializer was not found.");
        _ = method.Invoke(service, [process]);
    }

    private static async Task InvokeEstablishBrowserSessionAsync(
        DshHostService service,
        Process process,
        Uri launchUri)
    {
        var method = typeof(DshHostService).GetMethod(
            "EstablishBrowserSessionAsync",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "DshHostService browser-auth exchange was not found.");
        var task = method.Invoke(
                service,
                [process, launchUri, CancellationToken.None]) as Task
            ?? throw new InvalidOperationException(
                "DshHostService browser-auth exchange returned no task.");
        await task.ConfigureAwait(false);
    }

    private static DshBrowserSession? ReadBrowserSession(
        DshHostService service)
    {
        var field = typeof(DshHostService).GetField(
            "_browserSession",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "DshHostService browser session field was not found.");
        return field.GetValue(service) as DshBrowserSession;
    }

    private static string EncodeBase64Url(byte[] value) =>
        Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static async Task<HttpResponseMessage>
        CreateCandidateHealthResponseAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
    {
        if (request.Method == HttpMethod.Get)
        {
            return CreateHealthyWebUiResponse();
        }
        if (request.Method != HttpMethod.Post || request.Content is null)
        {
            return new HttpResponseMessage(HttpStatusCode.BadRequest);
        }

        var requestBytes = await request.Content.ReadAsByteArrayAsync(
                cancellationToken)
            .ConfigureAwait(false);
        using var document = JsonDocument.Parse(requestBytes);
        var rpcId = document.RootElement.GetProperty("rpcId").GetString()
            ?? throw new InvalidDataException(
                "Synthetic candidate request omitted its RPC id.");
        var responseJson = JsonSerializer.Serialize(new
        {
            type = "server-response",
            rpcId,
            result = new
            {
                ok = true,
                value = new
                {
                    items = Array.Empty<object>(),
                },
            },
        });
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                responseJson,
                Encoding.UTF8,
                "application/json"),
        };
    }

    private static HttpResponseMessage CreateHealthyWebUiResponse() => new(
        HttpStatusCode.OK)
    {
        Content = new StringContent(
            "<html><head><title>DeepSeek Harness</title></head>"
                + "<body><script>window.__DSH_BOOT__={};</script></body></html>",
            Encoding.UTF8,
            "text/html"),
    };

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
            "A locked DSH runtime file was modified or replaced.");
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

    private static async Task AssertThrowsAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (TException)
        {
            return;
        }
        throw new InvalidOperationException(
            $"Expected {typeof(TException).Name} was not thrown.");
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

    private sealed class RuntimeFixture : IDisposable
    {
        private RuntimeFixture(
            string root,
            string runtimeDirectory,
            string dependencyPath,
            DshRuntimeOptions options)
        {
            Root = root;
            RuntimeDirectory = runtimeDirectory;
            DependencyPath = dependencyPath;
            Options = options;
        }

        internal string Root { get; }

        internal string RuntimeDirectory { get; }

        internal string DependencyPath { get; }

        internal DshRuntimeOptions Options { get; }

        internal static RuntimeFixture Create()
        {
            var root = Path.Combine(
                Path.GetTempPath(),
                "ensou-dsh-runtime-watcher-tests",
                Guid.NewGuid().ToString("N"));
            var runtime = Path.Combine(root, "runtime");
            var entryPoint = Path.Combine(
                runtime,
                "node_modules",
                "@deepseek-ai",
                "dsh",
                "lib",
                "bin.js");
            var dependency = Path.Combine(
                Path.GetDirectoryName(entryPoint)!,
                "dependency.js");
            Directory.CreateDirectory(Path.GetDirectoryName(entryPoint)!);
            File.Copy(
                Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                Path.Combine(runtime, "node.exe"));
            File.WriteAllText(
                entryPoint,
                "console.log('watcher');",
                Encoding.UTF8);
            File.WriteAllText(
                dependency,
                "export const original = true;",
                Encoding.UTF8);
            return new RuntimeFixture(
                root,
                runtime,
                dependency,
                new DshRuntimeOptions(runtime, root, root));
        }

        public void Dispose()
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }

    private sealed class AsyncDelegateHandler(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>>
            responseFactory) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            responseFactory(request, cancellationToken);
    }
}
