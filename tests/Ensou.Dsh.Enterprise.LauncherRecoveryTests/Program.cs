using System.Reflection;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.IO;
using System.Windows.Threading;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.Enterprise.Client;
using Ensou.Dsh.Enterprise.Contracts;
using Ensou.Dsh.Enterprise.Launcher;
using Ensou.Dsh.Enterprise.Installation;

internal static class Program
{
    [STAThread]
    private static int Main()
    {
        SynchronizationContext.SetSynchronizationContext(
            new DispatcherSynchronizationContext(Dispatcher.CurrentDispatcher));
        var application = new App();
        application.InitializeComponent();
        application.ShutdownMode = System.Windows.ShutdownMode.OnExplicitShutdown;
        var temp = Path.GetFullPath(Path.GetTempPath());
        var root = Path.GetFullPath(Path.Combine(temp, $"ensou-launcher-recovery-{Guid.NewGuid():N}"));
        Directory.CreateDirectory(root);
        try
        {
            RunLockedSessionRefresh(root);
            RunBoundSessionRecovery(root);
            RunCancelledLockedSession(root);
            RunBoundFailures(root);
            Console.WriteLine("PASS locked Launcher dispatcher re-enters protected refresh and remains fail-closed");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"FAIL {exception.GetType().Name}: {exception.Message}");
            return 1;
        }
        finally
        {
            var name = Path.GetFileName(root);
            if (!string.Equals(Path.GetDirectoryName(root), temp.TrimEnd(Path.DirectorySeparatorChar),
                    StringComparison.OrdinalIgnoreCase)
                || !name.StartsWith("ensou-launcher-recovery-", StringComparison.Ordinal)
                || name.Length != "ensou-launcher-recovery-".Length + 32
                || new DirectoryInfo(root).Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new InvalidOperationException("Refusing to clean an unowned recovery-test directory.");
            Directory.Delete(root, recursive: true);
            application.Shutdown();
        }
    }

    private static void RunBoundFailures(string root)
    {
        foreach (var mode in new[] { BoundMode.Revoked, BoundMode.InvalidLease, BoundMode.Cancel })
        {
            RunSingleBoundFailure(Path.Combine(root, mode.ToString().ToLowerInvariant()), mode);
        }
    }

    private static void RunSingleBoundFailure(string root, BoundMode mode)
    {
        using var fixture = CreateBoundWindow(Path.Combine(root, "bound"));
        Equal(AutomaticUpdatePipelineResult.Failure,
            InvokeAutomaticUpdate(fixture.Window, CancellationToken.None), $"{mode} initial auth-loss result");
        True(ReadRestartRequired(fixture.Window),
            $"{mode} actual auth-loss marker ({ReadText(fixture.Window, "LastActivityText")})");
        if (mode == BoundMode.Revoked)
            fixture.RefreshClient.Failure = CreateRevokedFailure();
        else if (mode == BoundMode.InvalidLease)
            fixture.RefreshClient.CorruptSignatureOnNext = true;
        else
        {
            using var cancellation = new CancellationTokenSource();
            fixture.RefreshClient.CancelOnRefresh = cancellation;
            Equal(AutomaticUpdatePipelineResult.Success,
                InvokeAutomaticUpdate(fixture.Window, cancellation.Token), "bound cancellation result");
            AssertBoundFailure(fixture, mode);
            return;
        }
        Equal(AutomaticUpdatePipelineResult.Failure,
            InvokeAutomaticUpdate(fixture.Window, CancellationToken.None), $"{mode} result");
        AssertBoundFailure(fixture, mode);
    }

    private static void AssertBoundFailure(Fixture fixture, BoundMode mode)
    {
        True(ReadRestartRequired(fixture.Window), $"{mode} marker remains locked");
        True(!fixture.Session.CurrentDecision.MayStartHarness, $"{mode} session remains locked");
        True(!fixture.TokenVault.HasUsableToken(LeaseSigner.BindingId, DateTimeOffset.Parse("2026-08-24T06:01:00Z")),
            $"{mode} token vault cleared");
        Equal(0, fixture.Host.StartCalls, $"{mode} Runtime start count");
        Equal(2, fixture.RefreshClient.Calls,
            $"{mode} actual refresh count ({ReadText(fixture.Window, "LastActivityText")}; prepare={fixture.DeviceKeys.PrepareCalls})");
        Equal(1, fixture.FeedProbeCalls, $"{mode} must not reach another update probe");
        if (mode == BoundMode.Revoked)
            Equal(EnterpriseClientState.AccountLocked, fixture.Session.CurrentDecision.ClientState,
                "administrator revocation remains authoritative");
        Console.WriteLine($"PASS bound-{mode.ToString().ToLowerInvariant()} refresh=2 probe=1 host-start=0");
    }

    private static Exception CreateRevokedFailure() =>
        new EnterpriseControlPlaneException(new EnterpriseApiError {
            Code = EnterpriseErrorCodes.EmployeeRevoked, Message = "contact administrator",
            ClientState = EnterpriseClientState.AccountLocked, Retryable = false,
            ContactDisplay = "IT", RequestId = "launcher-recovery-revoked",
            ResetScope = EnterpriseResetScope.SecurityCredentials });

    private static void RunBoundSessionRecovery(string root)
    {
        using var fixture = CreateBoundWindow(Path.Combine(root, "bound"));
        True(!ReadRestartRequired(fixture.Window), "bound fixture begins without marker");
        var loss = InvokeAutomaticUpdate(fixture.Window, CancellationToken.None);
        Equal(AutomaticUpdatePipelineResult.Failure, loss, "authentication-loss result");
        Equal(1, fixture.RefreshClient.Calls, "authentication-loss refresh count");
        True(ReadRestartRequired(fixture.Window), "actual Unauthorized result sets marker");
        True(!fixture.Session.CurrentDecision.MayStartHarness,
            "authentication-loss decision must prohibit Runtime");
        True(!fixture.TokenVault.HasUsableToken(LeaseSigner.BindingId,
                DateTimeOffset.Parse("2026-08-24T06:01:00Z")),
            "actual authentication loss clears the real token vault");

        var recovered = InvokeAutomaticUpdate(fixture.Window, CancellationToken.None);
        Equal(AutomaticUpdatePipelineResult.Failure, recovered, "safe denied feed result");
        Equal(2, fixture.RefreshClient.Calls, "bound recovery refresh count");
        Equal(EnterpriseClientState.Ready, fixture.Session.CurrentDecision.ClientState,
            "verified recovery decision");
        True(!ReadRestartRequired(fixture.Window), "verified recovery clears marker");
        Equal(0, fixture.Host.StartCalls, "recovery must not start Runtime");

        var next = InvokeAutomaticUpdate(fixture.Window, CancellationToken.None);
        Equal(AutomaticUpdatePipelineResult.Success, next, "next bound cycle current-release result");
        Equal(3, fixture.RefreshClient.Calls, "next bound cycle refresh count");
        Equal(3, fixture.FeedProbeCalls, "third round must reach the current-release probe");
        Equal(EnterpriseClientState.Ready, fixture.Session.CurrentDecision.ClientState,
            "current-release decision remains ready");
        Equal(0, fixture.Host.StartCalls, "next cycle must not start Runtime");
        Console.WriteLine("PASS bound401-recovery-three-round refresh=3 probe=3 host-start=0");
    }

    private static void RunLockedSessionRefresh(string root)
    {
        using var fixture = CreateWindow(Path.Combine(root, "refresh"));
        SetRestartRequired(fixture.Window, true);

        var result = InvokeAutomaticUpdate(fixture.Window, CancellationToken.None);

        Equal(AutomaticUpdatePipelineResult.Success, result,
            $"unbound refresh disposition ({ReadText(fixture.Window, "LastActivityText")})");
        Equal(1, fixture.DeviceKeys.PrepareCalls, "protected device preparation count");
        Equal(0, fixture.RefreshClient.Calls, "transport must not run without a committed binding");
        Equal(EnterpriseClientState.QrRequired, fixture.Session.CurrentDecision.ClientState,
            "unbound refresh decision");
        True(ReadRestartRequired(fixture.Window), "unbound refresh must not unlock the marker");
        Console.WriteLine("PASS unbound refresh=0 host-start=0");
    }

    private static void RunCancelledLockedSession(string root)
    {
        using var fixture = CreateWindow(Path.Combine(root, "cancel"));
        SetRestartRequired(fixture.Window, true);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        try
        {
            _ = InvokeAutomaticUpdate(fixture.Window, cancellation.Token);
            throw new InvalidOperationException("Cancelled dispatcher unexpectedly completed.");
        }
        catch (OperationCanceledException)
        {
        }

        Equal(0, fixture.DeviceKeys.PrepareCalls, "cancelled preparation count");
        Equal(0, fixture.RefreshClient.Calls, "cancelled transport count");
        True(ReadRestartRequired(fixture.Window), "cancellation must not unlock the marker");
        Console.WriteLine("PASS pre-cancel refresh=0 host-start=0");
    }

    private static Fixture CreateWindow(string root)
    {
        Directory.CreateDirectory(root);
        var paths = EnterpriseManagedPaths.Create(
            Path.Combine(root, "local"), Path.Combine(root, "profile"));
        var protectedStore = new EnterpriseProtectedArtifactStore(paths);
        var trustedTime = new EnterpriseTrustedTimeStore(protectedStore);
        var host = new FakeHost();
        var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(TimeProvider.System),
            host,
            EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot(),
            trustedTimeStore: trustedTime);
        var deviceKeys = new CountingDeviceKeyStore();
        var preparation = new EnterpriseDeviceEnrollmentPreparation(
            new EnterpriseInstallationIdentityStore(paths), deviceKeys);
        var refreshClient = new CountingRefreshClient();
        var lifecycle = new EnterpriseAuthorizationLifecycle(
            refreshClient,
            new EnterpriseAuthorizationLeaseVerifier(CreateTrustPolicy()),
            new EnterpriseBindingCredentialStore(paths, protectedStore),
            new EnterprisePendingRefreshTransactionStore(protectedStore),
            new EmptyTokenVault(),
            session,
            trustedTime,
            new PassthroughUpdateGate());
        var window = new MainWindow(
            paths,
            session,
            host.WebUiUri,
            preparation,
            enrollmentCoordinator: null,
            authorizationLifecycle: lifecycle);
        return new Fixture(window, session, deviceKeys, refreshClient, host, null);
    }

    private static Fixture CreateBoundWindow(
        string root)
    {
        Directory.CreateDirectory(root);
        var now = DateTimeOffset.Parse("2026-08-24T06:01:00Z");
        var paths = EnterpriseManagedPaths.Create(Path.Combine(root, "local"), Path.Combine(root, "profile"));
        var protectedStore = new EnterpriseProtectedArtifactStore(paths);
        var trustedTime = new EnterpriseTrustedTimeStore(protectedStore);
        var host = new FakeHost();
        var deviceKeys = new CountingDeviceKeyStore();
        var preparation = new EnterpriseDeviceEnrollmentPreparation(
            new EnterpriseInstallationIdentityStore(paths, new FixedTimeProvider(now.AddMinutes(-2))),
            deviceKeys);
        var device = preparation.PrepareAsync().GetAwaiter().GetResult();
        var signer = new LeaseSigner(device.Installation.InstallId.ToString("D"), device.DeviceKey.Thumbprint);
        var verifier = new EnterpriseAuthorizationLeaseVerifier(signer.TrustPolicy);
        var credentials = new EnterpriseBindingCredentialStore(paths, protectedStore);
        var initial = signer.CreateResponse(now.AddMinutes(-1), LeaseSigner.InitialLeaseId, LeaseSigner.InitialRefreshToken, 'a');
        var verified = verifier.Verify(initial.AuthorizationLease,
            new EnterpriseAuthorizationLeaseVerificationContext(initial.BindingId,
                device.Installation.InstallId.ToString("D"), device.DeviceKey.Thumbprint,
                initial.ServerTimeUtc, initial.ServerTimeUtc));
        credentials.CommitOrConfirmAsync(initial, verified).GetAwaiter().GetResult();
        var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(now)), host,
            verified.AccessSnapshot,
            trustedTimeStore: trustedTime);
        var responses = new List<EnterpriseDeviceBindingCompleteResponse>
            {
                signer.CreateResponse(now, LeaseSigner.RotatedLeaseId, LeaseSigner.RotatedRefreshToken, 'b',
                    corruptSignature: false),
                signer.CreateResponse(now, "bbbbbbbb-0000-4000-8000-000000000021", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXphYmNkZWY", 'c',
                    corruptSignature: false),
                signer.CreateResponse(now, "bbbbbbbb-0000-4000-8000-000000000022", "YmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5emFiY2RlZmc", 'd'),
            };
        var refreshClient = new CountingRefreshClient(
            responses,
            [LeaseSigner.InitialRefreshToken, LeaseSigner.RotatedRefreshToken,
                "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXphYmNkZWY"]);
        var tokenVault = new EnterpriseAccessTokenVault();
        tokenVault.Install(initial.BindingId, initial.AccessToken, initial.AccessTokenExpiresAtUtc);
        var lifecycle = new EnterpriseAuthorizationLifecycle(
            refreshClient, verifier, credentials,
            new EnterprisePendingRefreshTransactionStore(protectedStore),
            tokenVault, session, trustedTime, new PassthroughUpdateGate(),
            new FixedTimeProvider(now));
        var probeCalls = 0;
        var updateCoordinator = new EnterpriseAuthenticatedReleaseUpdateCoordinator(
            session,
            () => new HttpClient(new RejectNetworkHandler()),
            (_, _) => throw new InvalidOperationException("Exclusive update stage is forbidden."),
            () => throw new InvalidOperationException("Restart is forbidden."),
            () => throw new InvalidOperationException("Shutdown is forbidden."),
            (_, _) =>
            {
                probeCalls++;
                if (probeCalls == 1)
                    return Task.FromException<EnterpriseReleaseUpdatePreflight>(
                        new EnterpriseUpdateFeedAuthorizationDeniedException(
                            HttpStatusCode.Unauthorized, tokenCleared: true));
                if (probeCalls == 2)
                    return Task.FromException<EnterpriseReleaseUpdatePreflight>(
                        new EnterpriseUpdateFeedAuthorizationDeniedException(
                            HttpStatusCode.Forbidden, tokenCleared: false));
                return Task.FromResult(EnterpriseReleaseUpdatePreflight.Terminal(
                    CreateCurrentReleaseOutcome(now)));
            });
        var window = new MainWindow(paths, session, host.WebUiUri, preparation,
            enrollmentCoordinator: null, authorizationLifecycle: lifecycle,
            authenticatedReleaseUpdateCoordinator: updateCoordinator);
        return new Fixture(window, session, deviceKeys, refreshClient, host, tokenVault, () => probeCalls);
    }

    private static EnterpriseReleaseUpdateOutcome CreateCurrentReleaseOutcome(DateTimeOffset now)
    {
        var component = new EnterpriseReleaseComponentPointer(
            "qa-release", "qa-directory", new string('a', 64), new string('b', 64));
        var current = new EnterpriseReleaseSetReference(
            "qa-release-set", 1, 1, 1,
            new EnterpriseStartupStubCompatibility { MinimumProtocol = 1, MaximumProtocol = 1 },
            component, component, null, EnterpriseReleaseHealthStates.Healthy, null, now);
        return new EnterpriseReleaseUpdateOutcome(
            "CURRENT", "QA release is already current.",
            new EnterpriseReleaseSetPointer(1, "ensou-dsh-enterprise", "qa", current, null, now),
            RequiresBootstrapHealthCheck: false);
    }

    private static EnterpriseAuthorizationLeaseTrustPolicy CreateTrustPolicy()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var point = key.ExportParameters(includePrivateParameters: false).Q;
        static string Encode(byte[] bytes) => Convert.ToBase64String(bytes)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return new EnterpriseAuthorizationLeaseTrustPolicy(
            new Uri("https://issuer.example.test"),
            new Uri("https://gateway.example.test"),
            new Uri("https://artifact.example.test"),
            [new EnterpriseAuthorizationLeasePublicKey("test-key", Encode(point.X!), Encode(point.Y!))]);
    }

    private static AutomaticUpdatePipelineResult InvokeAutomaticUpdate(
        MainWindow window,
        CancellationToken cancellationToken)
    {
        var method = typeof(MainWindow).GetMethod(
            "RunAutomaticUpdateOnDispatcherAsync",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new MissingMethodException(typeof(MainWindow).FullName,
                "RunAutomaticUpdateOnDispatcherAsync");
        var task = (Task<AutomaticUpdatePipelineResult>)(method.Invoke(
            window, [AutomaticUpdateTrigger.Retry, cancellationToken])
            ?? throw new InvalidOperationException("Dispatcher returned no task."));
        return AwaitOnDispatcher(task);
    }

    private static T AwaitOnDispatcher<T>(Task<T> task)
    {
        var frame = new DispatcherFrame();
        _ = task.ContinueWith(
            _ => frame.Continue = false,
            CancellationToken.None,
            TaskContinuationOptions.None,
            TaskScheduler.FromCurrentSynchronizationContext());
        Dispatcher.PushFrame(frame);
        return task.GetAwaiter().GetResult();
    }

    private static readonly FieldInfo RestartRequired = typeof(MainWindow).GetField(
        "_updateAuthenticationRestartRequired", BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new MissingFieldException(typeof(MainWindow).FullName,
            "_updateAuthenticationRestartRequired");

    private static void SetRestartRequired(MainWindow window, bool value) =>
        RestartRequired.SetValue(window, value);

    private static bool ReadRestartRequired(MainWindow window) =>
        (bool)(RestartRequired.GetValue(window) ?? false);

    private static string ReadText(MainWindow window, string fieldName)
    {
        var field = typeof(MainWindow).GetField(
            fieldName, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
        var control = field?.GetValue(window);
        return control?.GetType().GetProperty("Text")?.GetValue(control)?.ToString() ?? "no status";
    }

    private static void True(bool value, string label)
    {
        if (!value) throw new InvalidOperationException($"Expected true: {label}.");
    }

    private static void Equal<T>(T expected, T actual, string label) where T : notnull
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new InvalidOperationException($"{label}: expected {expected}, got {actual}.");
    }

    private sealed class Fixture(
        MainWindow window,
        EnterpriseHarnessSession session,
        CountingDeviceKeyStore deviceKeys,
        CountingRefreshClient refreshClient,
        FakeHost host,
        EnterpriseAccessTokenVault? tokenVault,
        Func<int>? feedProbeCalls = null) : IDisposable
    {
        public MainWindow Window { get; } = window;
        public EnterpriseHarnessSession Session { get; } = session;
        public CountingDeviceKeyStore DeviceKeys { get; } = deviceKeys;
        public CountingRefreshClient RefreshClient { get; } = refreshClient;
        public FakeHost Host { get; } = host;
        public EnterpriseAccessTokenVault TokenVault { get; } = tokenVault ?? new EnterpriseAccessTokenVault();
        public int FeedProbeCalls => feedProbeCalls?.Invoke() ?? 0;

        public void Dispose()
        {
            Window.Close();
            Session.DisposeAsync().AsTask().GetAwaiter().GetResult();
            DeviceKeys.Dispose();
            TokenVault.Dispose();
        }
    }

    private sealed class FakeHost : IEnterpriseHarnessHost
    {
        public int StartCalls { get; private set; }
        public Uri WebUiUri { get; } = new("http://127.0.0.1:5099/");
        public Task EnsureStartedAsync(CancellationToken cancellationToken = default)
        {
            StartCalls++;
            throw new InvalidOperationException("Runtime start is forbidden in this test.");
        }
        public Task OpenWebUiAsync(CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("UI opening is forbidden in this test.");
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(false);
        public Task StopOwnedProcessAsync(CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class RejectNetworkHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Network access is forbidden in this test.");
    }

    private sealed class CountingDeviceKeyStore : IEnterpriseDeviceProofKeyStore, IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public int PrepareCalls { get; private set; }
        public EnterpriseDevicePublicIdentity GetOrCreatePublicIdentity()
        {
            PrepareCalls++;
            var point = _key.ExportParameters(false).Q;
            static string Encode(byte[] bytes) => Convert.ToBase64String(bytes)
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
            var x = Encode(point.X!);
            var y = Encode(point.Y!);
            var canonicalJwk = Encoding.UTF8.GetBytes(
                $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
            return new EnterpriseDevicePublicIdentity(
                "EC", "P-256", x, y, Encode(SHA256.HashData(canonicalJwk)));
        }
        public byte[] Sign(ReadOnlySpan<byte> payload) => _key.SignData(payload, HashAlgorithmName.SHA256);
        public void DeleteForSecurityReset() { }
        public void Dispose() => _key.Dispose();
    }

    private sealed class CountingRefreshClient(
        IReadOnlyList<EnterpriseDeviceBindingCompleteResponse>? responses = null,
        IReadOnlyList<string>? expectedTokens = null,
        Exception? failure = null,
        CancellationTokenSource? cancelOnRefresh = null) : IEnterpriseRefreshClient
    {
        public int Calls { get; private set; }
        public Exception? Failure { get; set; } = failure;
        public CancellationTokenSource? CancelOnRefresh { get; set; } = cancelOnRefresh;
        public bool CorruptSignatureOnNext { get; set; }
        public Task<EnterpriseDeviceBindingCompleteResponse> RefreshAsync(
            EnterpriseRefreshRequest request, string refreshToken, string idempotencyKey,
            CancellationToken cancellationToken = default) => Throw();
        public Task<EnterpriseDeviceBindingCompleteResponse> RefreshExactAsync(
            ReadOnlyMemory<byte> exactRequestBody, string refreshToken, string idempotencyKey,
            CancellationToken cancellationToken = default)
        {
            Calls++;
            if (CancelOnRefresh is not null)
                CancelOnRefresh.Cancel();
            cancellationToken.ThrowIfCancellationRequested();
            if (Failure is not null)
                return Task.FromException<EnterpriseDeviceBindingCompleteResponse>(Failure);
            if (responses is null)
                throw new InvalidOperationException("Transport is forbidden without a committed binding.");
            var index = Calls - 1;
            if (index >= responses.Count || expectedTokens is null || index >= expectedTokens.Count)
                throw new InvalidOperationException("Unexpected extra refresh transaction.");
            Equal(expectedTokens[index], refreshToken, "persisted refresh token rotation");
            using var request = JsonDocument.Parse(exactRequestBody);
            var expectedPreviousLease = index switch
            {
                0 => LeaseSigner.InitialLeaseId,
                1 => LeaseSigner.RotatedLeaseId,
                2 => "bbbbbbbb-0000-4000-8000-000000000021",
                _ => throw new InvalidOperationException("Unexpected refresh index."),
            };
            Equal(expectedPreviousLease,
                request.RootElement.GetProperty("previous_lease_id").GetString()!,
                "persisted previous lease rotation");
            var selected = responses[index];
            if (CorruptSignatureOnNext)
            {
                CorruptSignatureOnNext = false;
                selected = new EnterpriseDeviceBindingCompleteResponse {
                    SchemaVersion = selected.SchemaVersion, BindingId = selected.BindingId,
                    RefreshToken = selected.RefreshToken, AccessToken = selected.AccessToken,
                    AccessTokenExpiresAtUtc = selected.AccessTokenExpiresAtUtc,
                    AuthorizationLease = CorruptSignature(selected.AuthorizationLease),
                    LeaseExpiresAtUtc = selected.LeaseExpiresAtUtc,
                    ServerTimeUtc = selected.ServerTimeUtc };
            }
            return Task.FromResult(selected);
        }
        private Task<EnterpriseDeviceBindingCompleteResponse> Throw()
        {
            Calls++;
            throw new InvalidOperationException("Transport is forbidden without a committed binding.");
        }
    }

    private enum BoundMode { Revoked, InvalidLease, Cancel }

    private static string CorruptSignature(string compact)
    {
        // Mutate actual signature bits while preserving canonical Base64url encoding.
        var index = compact.LastIndexOf('.') + 1;
        return compact[..index] + (compact[index] == 'A' ? "B" : "A") + compact[(index + 1)..];
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class LeaseSigner
    {
        public const string BindingId = "22222222-2222-4222-8222-222222222222";
        public const string InitialLeaseId = "bbbbbbbb-0000-4000-8000-000000000001";
        public const string RotatedLeaseId = "bbbbbbbb-0000-4000-8000-000000000020";
        public const string InitialRefreshToken = "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8";
        public const string RotatedRefreshToken = "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8";
        private const string KeyId = "lease-test-2026-01";
        private const string X = "2N_Gf2Sd2psMzflS-3tMN3Zj5p1AScLHHVblKgA9GzQ";
        private const string Y = "T86eGwq3Hm-vFYCErjH-5xaReKY1dYL7mm2KYS93iWc";
        private const string D = "AuuVW5E6Rvs3d021A1_kavYr9-TbWQSThZa0E9_PEY0";
        private const string Header = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImxlYXNlLXRlc3QtMjAyNi0wMSIsInR5cCI6ImVuc291LWRzaC1sZWFzZStqd3QifQ";
        private readonly string _installationId;
        private readonly string _thumbprint;
        public EnterpriseAuthorizationLeaseTrustPolicy TrustPolicy { get; } = new(
            new Uri("https://control.example.com/"), new Uri("https://gateway.example.com/"),
            new Uri("https://artifacts.example.com/"),
            [new EnterpriseAuthorizationLeasePublicKey(KeyId, X, Y)]);

        public LeaseSigner(string installationId, string thumbprint)
        {
            _installationId = installationId;
            _thumbprint = thumbprint;
        }

        public EnterpriseDeviceBindingCompleteResponse CreateResponse(
            DateTimeOffset issuedAt, string leaseId, string refreshToken, char tokenChar,
            bool corruptSignature = false)
        {
            var payload = $"{{\"schema_version\":1,\"jti\":\"{leaseId}\",\"iss\":\"https://control.example.com/\",\"aud\":\"ensou-dsh-enterprise-launcher\",\"sub\":\"aaaaaaaa-0000-4000-8000-000000000001\",\"binding_id\":\"22222222-2222-4222-8222-222222222222\",\"installation_id\":\"{_installationId}\",\"device_key_thumbprint\":\"{_thumbprint}\",\"employee_state\":\"ACTIVE\",\"device_state\":\"ACTIVE\",\"api_allocation_state\":\"ACTIVE\",\"auth_epoch\":1,\"entitlement_epoch\":1,\"binding_epoch\":1,\"api_allocation_id\":\"33333333-3333-4333-8333-333333333333\",\"allocation_epoch\":1,\"api_profile_id\":\"44444444-4444-4444-8444-444444444444\",\"api_profile_version\":1,\"plugin_policy_id\":\"55555555-5555-4555-8555-555555555555\",\"plugin_policy_generation\":7,\"plugin_policy_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"rollout_channel\":\"PILOT\",\"gateway_origin\":\"https://gateway.example.com/\",\"artifact_origin\":\"https://artifacts.example.com/\",\"support_display\":\"ENSOU IT\",\"iat\":{issuedAt.ToUnixTimeSeconds()},\"nbf\":{issuedAt.ToUnixTimeSeconds()},\"exp\":{issuedAt.AddMinutes(15).ToUnixTimeSeconds()}}}";
            var payloadSegment = Encode(Encoding.UTF8.GetBytes(payload));
            var input = Encoding.ASCII.GetBytes($"{Header}.{payloadSegment}");
            using var key = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256,
                D = Decode(D), Q = new ECPoint { X = Decode(X), Y = Decode(Y) } });
            var signature = key.SignData(input, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            var compact = $"{Header}.{payloadSegment}.{Encode(signature)}";
            if (corruptSignature)
                compact = CorruptSignature(compact);
            return new EnterpriseDeviceBindingCompleteResponse {
                SchemaVersion = 1, BindingId = BindingId,
                RefreshToken = refreshToken, AccessToken = new string(tokenChar, 43),
                AccessTokenExpiresAtUtc = issuedAt.AddMinutes(10),
                AuthorizationLease = compact,
                LeaseExpiresAtUtc = issuedAt.AddMinutes(15), ServerTimeUtc = issuedAt };
        }

        private static string Encode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        private static byte[] Decode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
    }

    private sealed class EmptyTokenVault : IEnterpriseAccessTokenVault
    {
        public void Install(string bindingId, string accessToken, DateTimeOffset expiresAtUtc) { }
        public bool HasUsableToken(string bindingId, DateTimeOffset nowUtc) => false;
        public EnterpriseAccessTokenLease Acquire(DateTimeOffset nowUtc) =>
            throw new InvalidOperationException("No token is installed.");
        public void Clear() { }
    }

    private sealed class PassthroughUpdateGate : IEnterpriseDeviceUpdateGate
    {
        public Task<EnterpriseAccessSnapshot> EvaluateBeforeReadyAsync(
            EnterpriseAccessSnapshot authorizedSnapshot, string bindingId,
            CancellationToken cancellationToken = default) => Task.FromResult(authorizedSnapshot);
    }
}
