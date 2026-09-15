using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Enterprise.Client;
using Ensou.Dsh.Enterprise.Contracts;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.ClientUpdateGateTests;

internal static class Program
{
    private const string BindingId = "22222222-3333-4444-8555-666666666666";
    private const string OtherBindingId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    private const string AccessToken =
        "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8";
    private const string ManifestSha256 =
        "1111111111111111111111111111111111111111111111111111111111111111";
    private const string PolicyReceiptSha256 =
        "2222222222222222222222222222222222222222222222222222222222222222";
    private static readonly DateTimeOffset Now =
        DateTimeOffset.Parse("2026-08-26T02:00:00Z");

    public static async Task<int> Main()
    {
        var tests = new (string Name, Func<Task> Run)[]
        {
            ("initial signed release gate orders staging, policy binding and health fail-closed", EnterpriseInitialReleaseDeviceUpdateGateTests.RunAsync),
            ("authenticated Stable feed transport is exact and fail-closed", EnterpriseUpdateFeedAuthorizationHandlerTests.RunAsync),
            ("authenticated Stable update capability probe is exact and bounded", EnterpriseAuthenticatedUpdateCapabilityProbeTests.RunAsync),
            ("authenticated update failures map without mandatory-update deadlock", EnterpriseAuthenticatedReleaseUpdateCoordinatorTests.MappingAsync),
            ("authenticated update uses one disposable client per check", EnterpriseAuthenticatedReleaseUpdateCoordinatorTests.FactoryCountAsync),
            ("authenticated update 401 locks the current session", EnterpriseAuthenticatedReleaseUpdateCoordinatorTests.SessionLockAsync),
            ("authenticated read-only preflight gates exclusive staging exactly", EnterpriseAuthenticatedReleaseUpdateCoordinatorTests.PreflightAsync),
            ("automatic verified update ordering preserves authorization and runtime recovery", EnterpriseAuthenticatedReleaseUpdateCoordinatorTests.AutomaticPipelineAsync),
            ("HTTP policy and receipt are DPoP-bound and exact", HttpContractAsync),
            ("duplicate policy JSON fails closed", DuplicatePolicyJsonRejectedAsync),
            ("access token binding is exact", AccessTokenBindingIsExactAsync),
            ("signed feed channel path is exact", SignedFeedChannelPathIsExactAsync),
            ("matching signed local evidence reports installed", MatchingEvidenceReportsAsync),
            ("enforced mismatch blocks before Ready", EnforcedMismatchBlocksAsync),
            ("minimum accepted sequence blocks before grace", MinimumFloorBlocksBeforeGraceAsync),
            ("pre-grace mismatch does not claim installed", GraceMismatchDoesNotClaimAsync),
            ("policy transport failure blocks before Ready", PolicyFailureBlocksAsync),
            ("HTTP timeout blocks but caller cancellation propagates", TimeoutAndCancellationAsync),
            ("receipt failure blocks before Ready", ReceiptFailureBlocksAsync),
            ("lost receipt acknowledgement replays exact durable request", LostAcknowledgementReplaysExactAsync),
            ("health rollback reports durable rolled-back state", HealthRollbackReportsAsync),
            ("policy race in receipt response blocks when enforced", ReceiptPolicyRaceBlocksAsync),
        };

        var failures = 0;
        foreach (var test in tests)
        {
            try
            {
                await test.Run().ConfigureAwait(false);
                Console.WriteLine($"PASS  {test.Name}");
            }
            catch (Exception exception)
            {
                failures++;
                Console.Error.WriteLine($"FAIL  {test.Name}");
                Console.Error.WriteLine(exception);
            }
        }

        Console.WriteLine($"{tests.Length - failures}/{tests.Length} update-gate checks passed.");
        return failures == 0 ? 0 : 1;
    }

    private static async Task HttpContractAsync()
    {
        var requests = 0;
        var receiptId = "01234567-89ab-4cde-8fab-0123456789ab";
        var handler = new DelegateHandler(async request =>
        {
            requests++;
            AssertEqual("DPoP", request.Headers.Authorization?.Scheme);
            AssertEqual(AccessToken, request.Headers.Authorization?.Parameter);
            var proof = AssertSingleHeader(request, "DPoP");
            AssertDpopAth(proof, request.Method, request.RequestUri!);
            if (request.Method == HttpMethod.Get)
            {
                AssertEqual(
                    "https://control.example.test/v1/device-update-policy",
                    request.RequestUri?.AbsoluteUri);
                return JsonResponse(PolicyJson());
            }

            AssertEqual(HttpMethod.Post, request.Method);
            AssertEqual(
                "https://control.example.test/v1/device-update-receipts",
                request.RequestUri?.AbsoluteUri);
            AssertEqual(43, AssertSingleHeader(request, "Idempotency-Key").Length);
            AssertEqual("application/json", request.Content?.Headers.ContentType?.MediaType);
            AssertEqual("utf-8", request.Content?.Headers.ContentType?.CharSet);
            var exactBody = await request.Content!.ReadAsByteArrayAsync().ConfigureAwait(false);
            using var document = JsonDocument.Parse(exactBody);
            var root = document.RootElement;
            AssertEqual(13, root.EnumerateObject().Count());
            AssertEqual(1, root.GetProperty("schema_version").GetInt32());
            AssertEqual(receiptId, root.GetProperty("receipt_id").GetString());
            AssertEqual("stable", root.GetProperty("channel").GetString());
            AssertEqual("managed-v1", root.GetProperty("release_set_id").GetString());
            AssertEqual("managed-v1", root.GetProperty("active_release_set_id").GetString());
            AssertEqual("INSTALLED", root.GetProperty("outcome").GetString());
            return JsonResponse(ReceiptAcceptedJson(receiptId, PolicyJson()));
        });

        using var keyStore = new EphemeralKeyStore();
        using var vault = new EnterpriseAccessTokenVault();
        vault.Install(BindingId, AccessToken, Now.AddMinutes(5));
        using var httpClient = new HttpClient(handler);
        var client = new EnterpriseDeviceUpdateManagementClient(
            httpClient,
            new EnterpriseControlPlaneOptions(
                new Uri("https://control.example.test/"),
                new Uri("https://login.example.test/")),
            new EnterpriseDpopProofFactory(keyStore, new FixedTimeProvider(Now)),
            vault,
            new FixedTimeProvider(Now));
        var policy = await client.GetPolicyAsync(BindingId).ConfigureAwait(false);
        AssertEqual("managed-v1", policy.ReleaseSetId);
        var receipt = Receipt(receiptId);
        var accepted = await client.ReportAsync(
                BindingId,
                EnterpriseDeviceUpdateManagementClient.SerializeExactReceipt(receipt),
                Base64Url(Enumerable.Range(0, 32).Select(value => (byte)value).ToArray()))
            .ConfigureAwait(false);
        AssertEqual(receiptId, accepted.ReceiptId);
        AssertEqual(2, requests);
    }

    private static async Task DuplicatePolicyJsonRejectedAsync()
    {
        var duplicate = PolicyJson().Replace(
            "\"channel\":\"stable\"",
            "\"channel\":\"stable\",\"channel\":\"stable\"",
            StringComparison.Ordinal);
        using var keyStore = new EphemeralKeyStore();
        using var vault = new EnterpriseAccessTokenVault();
        vault.Install(BindingId, AccessToken, Now.AddMinutes(5));
        using var client = new HttpClient(new DelegateHandler(
            _ => Task.FromResult(JsonResponse(duplicate))));
        var management = new EnterpriseDeviceUpdateManagementClient(
            client,
            new EnterpriseControlPlaneOptions(
                new Uri("https://control.example.test/"),
                new Uri("https://login.example.test/")),
            new EnterpriseDpopProofFactory(keyStore, new FixedTimeProvider(Now)),
            vault,
            new FixedTimeProvider(Now));
        await AssertThrowsAsync<InvalidDataException>(
            () => management.GetPolicyAsync(BindingId)).ConfigureAwait(false);
    }

    private static async Task AccessTokenBindingIsExactAsync()
    {
        var calls = 0;
        using var keyStore = new EphemeralKeyStore();
        using var vault = new EnterpriseAccessTokenVault();
        vault.Install(BindingId, AccessToken, Now.AddMinutes(5));
        using var httpClient = new HttpClient(new DelegateHandler(request =>
        {
            calls++;
            return Task.FromResult(JsonResponse(PolicyJson()));
        }));
        var management = new EnterpriseDeviceUpdateManagementClient(
            httpClient,
            new EnterpriseControlPlaneOptions(
                new Uri("https://control.example.test/"),
                new Uri("https://login.example.test/")),
            new EnterpriseDpopProofFactory(keyStore, new FixedTimeProvider(Now)),
            vault,
            new FixedTimeProvider(Now));
        await AssertThrowsAsync<EnterpriseAccessTokenUnavailableException>(
            () => management.GetPolicyAsync(OtherBindingId)).ConfigureAwait(false);
        AssertEqual(0, calls);
    }

    private static async Task MatchingEvidenceReportsAsync()
    {
        var management = new FakeManagementClient(Policy());
        var snapshot = ReadySnapshot();
        var gate = Gate(management, Evidence());
        var result = await gate.EvaluateBeforeReadyAsync(snapshot, BindingId)
            .ConfigureAwait(false);
        AssertTrue(ReferenceEquals(snapshot, result));
        AssertEqual(1, management.PolicyCalls);
        AssertEqual(1, management.ReceiptCalls);
        AssertEqual("INSTALLED", management.LastReceipt?.Outcome);
        AssertEqual(43, management.LastIdempotencyKey?.Length);
    }

    private static Task SignedFeedChannelPathIsExactAsync()
    {
        var root = Path.Combine(Path.GetTempPath(), "ensou-update-channel-tests", Guid.NewGuid().ToString("N"));
        var layout = EnterpriseInstallationLayout.Create(
            Path.Combine(root, "local"),
            Path.Combine(root, "profile"));
        _ = new EnterpriseInstalledReleaseEvidenceProvider(
            layout,
            new Uri("https://updates.example.test/v2/channels/stable/release-set.v2.json"),
            EnterpriseReleaseSetContract.StableChannel);
        AssertThrows<InvalidDataException>(() =>
            _ = new EnterpriseInstalledReleaseEvidenceProvider(
                layout,
                new Uri("https://updates.example.test/stable/release-set.v2.json"),
                EnterpriseReleaseSetContract.StableChannel));
        AssertThrows<InvalidDataException>(() =>
            _ = new EnterpriseInstalledReleaseEvidenceProvider(
                layout,
                new Uri("https://updates.example.test/prefix/v2/channels/stable/release-set.v2.json"),
                EnterpriseReleaseSetContract.StableChannel));
        AssertThrows<InvalidDataException>(() =>
            _ = new EnterpriseInstalledReleaseEvidenceProvider(
                layout,
                new Uri("https://updates.example.test/v2/channels/stable/release-set.v2.json"),
                EnterpriseReleaseSetContract.LabChannel));
        return Task.CompletedTask;
    }

    private static async Task EnforcedMismatchBlocksAsync()
    {
        var management = new FakeManagementClient(Policy() with
        {
            ReleaseSetId = "managed-v2",
            Generation = 2,
            Sequence = 2,
            ServerTimeUtc = Now,
            GraceUntilUtc = Now.AddMinutes(-1),
            EnforcementRequired = true,
        });
        var result = await Gate(management, Evidence() with
            {
                LatestVerifiedGeneration = 2,
                LatestVerifiedSequence = 2,
            })
            .EvaluateBeforeReadyAsync(ReadySnapshot(), BindingId)
            .ConfigureAwait(false);
        AssertTrue(result.ClientUpdateRequired);
        AssertEqual(0, management.ReceiptCalls);
    }

    private static async Task GraceMismatchDoesNotClaimAsync()
    {
        var management = new FakeManagementClient(Policy() with
        {
            ReleaseSetId = "managed-v2",
            Generation = 2,
            Sequence = 2,
        });
        var snapshot = ReadySnapshot();
        var result = await Gate(management, Evidence() with
            {
                LatestVerifiedGeneration = 2,
                LatestVerifiedSequence = 2,
            })
            .EvaluateBeforeReadyAsync(snapshot, BindingId)
            .ConfigureAwait(false);
        AssertTrue(ReferenceEquals(snapshot, result));
        AssertEqual(0, management.ReceiptCalls);
    }

    private static async Task MinimumFloorBlocksBeforeGraceAsync()
    {
        var management = new FakeManagementClient(Policy() with
        {
            ReleaseSetId = "managed-v2",
            Generation = 2,
            Sequence = 2,
            MinAcceptedSequence = 2,
            GraceUntilUtc = Now.AddHours(1),
            EnforcementRequired = false,
        });
        var result = await Gate(management, Evidence() with
            {
                LatestVerifiedGeneration = 2,
                LatestVerifiedSequence = 2,
                LatestVerifiedMinAcceptedSequence = 2,
            })
            .EvaluateBeforeReadyAsync(ReadySnapshot(), BindingId)
            .ConfigureAwait(false);
        AssertTrue(result.ClientUpdateRequired);
        AssertEqual(0, management.ReceiptCalls);
    }

    private static async Task PolicyFailureBlocksAsync()
    {
        var management = new FakeManagementClient(Policy())
        {
            PolicyException = new HttpRequestException("offline"),
        };
        var result = await Gate(management, Evidence())
            .EvaluateBeforeReadyAsync(ReadySnapshot(), BindingId)
            .ConfigureAwait(false);
        AssertTrue(result.ClientUpdateRequired);
        AssertEqual(0, management.ReceiptCalls);
    }

    private static async Task ReceiptFailureBlocksAsync()
    {
        var management = new FakeManagementClient(Policy())
        {
            ReceiptException = new HttpRequestException("lost acknowledgement"),
        };
        var result = await Gate(management, Evidence())
            .EvaluateBeforeReadyAsync(ReadySnapshot(), BindingId)
            .ConfigureAwait(false);
        AssertTrue(result.ClientUpdateRequired);
        AssertEqual(1, management.ReceiptCalls);
    }

    private static async Task LostAcknowledgementReplaysExactAsync()
    {
        var management = new FakeManagementClient(Policy())
        {
            ReceiptFailuresRemaining = 1,
        };
        using var store = new MemoryReceiptStore();
        var gate = Gate(management, Evidence(), store);
        var first = await gate.EvaluateBeforeReadyAsync(ReadySnapshot(), BindingId)
            .ConfigureAwait(false);
        AssertTrue(first.ClientUpdateRequired);
        using (var pending = await store.ReadAsync().ConfigureAwait(false))
        {
            AssertTrue(pending is not null && !pending.IsAcknowledged);
        }

        var second = await gate.EvaluateBeforeReadyAsync(ReadySnapshot(), BindingId)
            .ConfigureAwait(false);
        AssertTrue(!second.ClientUpdateRequired);
        AssertEqual(2, management.ReceiptCalls);
        AssertEqual(2, management.ExactBodies.Count);
        AssertTrue(CryptographicOperations.FixedTimeEquals(
            management.ExactBodies[0],
            management.ExactBodies[1]));
        AssertEqual(management.IdempotencyKeys[0], management.IdempotencyKeys[1]);
        using (var acknowledged = await store.ReadAsync().ConfigureAwait(false))
        {
            AssertTrue(acknowledged is not null && acknowledged.IsAcknowledged);
        }

        var third = await gate.EvaluateBeforeReadyAsync(ReadySnapshot(), BindingId)
            .ConfigureAwait(false);
        AssertTrue(!third.ClientUpdateRequired);
        AssertEqual(2, management.ReceiptCalls);
    }

    private static async Task HealthRollbackReportsAsync()
    {
        var policy = Policy() with
        {
            ReleaseSetId = "managed-v2",
            Generation = 2,
            Sequence = 2,
            ManifestSha256 = PolicyReceiptSha256,
        };
        var evidence = Evidence() with
        {
            LatestVerifiedGeneration = 2,
            LatestVerifiedSequence = 2,
        };
        var management = new FakeManagementClient(policy);
        using var store = new MemoryReceiptStore();
        var gate = Gate(
            management,
            evidence,
            store,
            new HashSet<string>(["managed-v2"], StringComparer.Ordinal));
        var result = await gate.EvaluateBeforeReadyAsync(ReadySnapshot(), BindingId)
            .ConfigureAwait(false);
        AssertTrue(!result.ClientUpdateRequired);
        AssertEqual(1, management.ReceiptCalls);
        AssertEqual("ROLLED_BACK", management.LastReceipt?.Outcome);
        AssertEqual("managed-v2", management.LastReceipt?.ReleaseSetId);
        AssertEqual(2L, management.LastReceipt?.ManifestSequence);
        AssertEqual("managed-v1", management.LastReceipt?.ActiveReleaseSetId);
        AssertEqual(1L, management.LastReceipt?.ActiveSequence);

        _ = await gate.EvaluateBeforeReadyAsync(ReadySnapshot(), BindingId)
            .ConfigureAwait(false);
        AssertEqual(1, management.ReceiptCalls);
    }

    private static async Task TimeoutAndCancellationAsync()
    {
        var timeoutClient = new FakeManagementClient(Policy())
        {
            PolicyException = new TaskCanceledException("HTTP timeout"),
        };
        var blocked = await Gate(timeoutClient, Evidence())
            .EvaluateBeforeReadyAsync(ReadySnapshot(), BindingId)
            .ConfigureAwait(false);
        AssertTrue(blocked.ClientUpdateRequired);

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await AssertThrowsAsync<OperationCanceledException>(() =>
            Gate(new FakeManagementClient(Policy()), Evidence())
                .EvaluateBeforeReadyAsync(
                    ReadySnapshot(),
                    BindingId,
                    cancellation.Token)).ConfigureAwait(false);
    }

    private static async Task ReceiptPolicyRaceBlocksAsync()
    {
        var management = new FakeManagementClient(Policy())
        {
            AcceptedPolicy = Policy() with
            {
                ReleaseSetId = "managed-v2",
                ServerTimeUtc = Now,
                GraceUntilUtc = Now.AddMinutes(-1),
                EnforcementRequired = true,
            },
        };
        var result = await Gate(management, Evidence())
            .EvaluateBeforeReadyAsync(ReadySnapshot(), BindingId)
            .ConfigureAwait(false);
        AssertTrue(result.ClientUpdateRequired);
        AssertEqual(1, management.ReceiptCalls);
    }

    private static EnterpriseDeviceUpdateGate Gate(
        IEnterpriseDeviceUpdateManagementClient management,
        EnterpriseInstalledReleaseEvidence evidence,
        IEnterprisePendingUpdateReceiptTransactionStore? receiptStore = null,
        IReadOnlySet<string>? rejectedReleaseSetIds = null) => new(
            management,
            new FixedEvidenceProvider(evidence, rejectedReleaseSetIds),
            receiptStore ?? new MemoryReceiptStore(),
            new FixedTimeProvider(Now));

    private static EnterpriseInstalledReleaseEvidence Evidence() => new(
        "stable",
        "managed-v1",
        1,
        1,
        0,
        1,
        1,
        0,
        ManifestSha256,
        "launcher-v1",
        "runtime-v1",
        "plugin-v1");

    private static EnterpriseDeviceUpdatePolicy Policy() => new()
    {
        SchemaVersion = 1,
        Channel = "stable",
        ReleaseSetId = "managed-v1",
        Generation = 1,
        Sequence = 1,
        MinAcceptedSequence = 0,
        ManifestSha256 = ManifestSha256,
        PolicyReceiptSha256 = PolicyReceiptSha256,
        IssuedAtUtc = Now.AddMinutes(-5),
        ExpiresAtUtc = Now.AddHours(1),
        GraceUntilUtc = Now.AddMinutes(5),
        ServerTimeUtc = Now,
        EnforcementRequired = false,
    };

    private static EnterpriseInstalledUpdateReceiptRequest Receipt(string receiptId) => new()
    {
        SchemaVersion = 1,
        ReceiptId = receiptId,
        Channel = "stable",
        ReleaseSetId = "managed-v1",
        ManifestSequence = 1,
        ManifestSha256 = ManifestSha256,
        ActiveReleaseSetId = "managed-v1",
        ActiveSequence = 1,
        LauncherReleaseId = "launcher-v1",
        RuntimeReleaseId = "runtime-v1",
        PluginPolicyReleaseId = "plugin-v1",
        Outcome = "INSTALLED",
        ClientObservedAtUtc = Now,
    };

    private static EnterpriseAccessSnapshot ReadySnapshot() => new()
    {
        Employee = EmployeeAuthorizationState.Active,
        Device = DeviceBindingState.Active,
        ApiAllocation = ApiAllocationState.Active,
        ControlPlane = ControlPlaneConnectivity.Available,
        LeaseSignatureValid = true,
        AuthorizationEpochMatches = true,
        ClockTrusted = true,
        TrustedTimeFloorUtc = Now.AddMinutes(-1),
        LeaseIssuedAtUtc = Now.AddMinutes(-1),
        LeaseExpiresAtUtc = Now.AddMinutes(5),
        PluginPolicyId = "01234567-89ab-4cde-8fab-0123456789ab",
        PluginPolicyGeneration = 1,
        PluginPolicySha256 = ManifestSha256,
    };

    private static string PolicyJson() =>
        "{" +
        "\"schema_version\":1," +
        "\"channel\":\"stable\"," +
        "\"release_set_id\":\"managed-v1\"," +
        "\"generation\":1," +
        "\"sequence\":1," +
        "\"min_accepted_sequence\":0," +
        $"\"manifest_sha256\":\"{ManifestSha256}\"," +
        $"\"policy_receipt_sha256\":\"{PolicyReceiptSha256}\"," +
        "\"issued_at\":\"2026-08-26T01:55:00Z\"," +
        "\"expires_at\":\"2026-08-26T03:00:00Z\"," +
        "\"grace_until\":\"2026-08-26T02:05:00Z\"," +
        "\"server_time\":\"2026-08-26T02:00:00Z\"," +
        "\"enforcement_required\":false}";

    private static string ReceiptAcceptedJson(string receiptId, string policyJson) =>
        "{" +
        "\"schema_version\":1," +
        $"\"receipt_id\":\"{receiptId}\"," +
        "\"accepted_at\":\"2026-08-26T02:00:00Z\"," +
        $"\"update_policy\":{policyJson}" +
        "}";

    private static HttpResponseMessage JsonResponse(string json) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json"),
    };

    private static string AssertSingleHeader(HttpRequestMessage request, string name)
    {
        var values = request.Headers.GetValues(name).ToArray();
        AssertEqual(1, values.Length);
        return values[0];
    }

    private static void AssertDpopAth(string compactJws, HttpMethod method, Uri uri)
    {
        var segments = compactJws.Split('.');
        AssertEqual(3, segments.Length);
        using var payload = JsonDocument.Parse(Base64UrlDecode(segments[1]));
        AssertEqual(method.Method, payload.RootElement.GetProperty("htm").GetString());
        AssertEqual(uri.GetLeftPart(UriPartial.Path), payload.RootElement.GetProperty("htu").GetString());
        var expectedAth = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(AccessToken)));
        AssertEqual(expectedAth, payload.RootElement.GetProperty("ath").GetString());
    }

    private static byte[] Base64UrlDecode(string value)
    {
        var padding = (value.Length % 4) switch
        {
            0 => string.Empty,
            2 => "==",
            3 => "=",
            _ => throw new FormatException("Invalid base64url."),
        };
        return Convert.FromBase64String(
            value.Replace('-', '+').Replace('_', '/') + padding);
    }

    private static string Base64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

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

        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }

    private static void AssertThrows<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }

    private static void AssertTrue(bool value)
    {
        if (!value)
        {
            throw new InvalidOperationException("Expected true.");
        }
    }

    private static void AssertEqual<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected '{expected}', actual '{actual}'.");
        }
    }

    private sealed class FixedEvidenceProvider(
        EnterpriseInstalledReleaseEvidence evidence,
        IReadOnlySet<string>? rejectedReleaseSetIds = null)
        : IEnterpriseInstalledReleaseEvidenceProvider
    {
        public EnterpriseInstalledReleaseEvidence ReadRequired() => evidence;

        public bool IsRejected(string releaseSetId) =>
            rejectedReleaseSetIds?.Contains(releaseSetId) == true;
    }

    private sealed class FakeManagementClient(EnterpriseDeviceUpdatePolicy policy)
        : IEnterpriseDeviceUpdateManagementClient
    {
        public int PolicyCalls { get; private set; }

        public int ReceiptCalls { get; private set; }

        public Exception? PolicyException { get; init; }

        public Exception? ReceiptException { get; init; }

        public EnterpriseDeviceUpdatePolicy? AcceptedPolicy { get; init; }

        public EnterpriseInstalledUpdateReceiptRequest? LastReceipt { get; private set; }

        public string? LastIdempotencyKey { get; private set; }

        public int ReceiptFailuresRemaining { get; set; }

        public List<byte[]> ExactBodies { get; } = [];

        public List<string> IdempotencyKeys { get; } = [];

        public Task<EnterpriseDeviceUpdatePolicy> GetPolicyAsync(
            string bindingId,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AssertEqual(BindingId, bindingId);
            PolicyCalls++;
            return PolicyException is null
                ? Task.FromResult(policy)
                : Task.FromException<EnterpriseDeviceUpdatePolicy>(PolicyException);
        }

        public Task<EnterpriseDeviceUpdateReceiptAccepted> ReportAsync(
            string bindingId,
            ReadOnlyMemory<byte> exactReceiptBody,
            string idempotencyKey,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AssertEqual(BindingId, bindingId);
            var receipt = EnterpriseDeviceUpdateManagementClient.DeserializeExactReceipt(
                exactReceiptBody);
            ReceiptCalls++;
            LastReceipt = receipt;
            LastIdempotencyKey = idempotencyKey;
            ExactBodies.Add(exactReceiptBody.ToArray());
            IdempotencyKeys.Add(idempotencyKey);
            if (ReceiptFailuresRemaining > 0)
            {
                ReceiptFailuresRemaining--;
                return Task.FromException<EnterpriseDeviceUpdateReceiptAccepted>(
                    new HttpRequestException("lost acknowledgement"));
            }
            if (ReceiptException is not null)
            {
                return Task.FromException<EnterpriseDeviceUpdateReceiptAccepted>(
                    ReceiptException);
            }

            return Task.FromResult(new EnterpriseDeviceUpdateReceiptAccepted
            {
                SchemaVersion = 1,
                ReceiptId = receipt.ReceiptId,
                AcceptedAtUtc = Now,
                UpdatePolicy = AcceptedPolicy ?? policy,
            });
        }
    }

    private sealed class MemoryReceiptStore
        : IEnterprisePendingUpdateReceiptTransactionStore, IDisposable
    {
        private EnterprisePendingUpdateReceiptTransaction? _transaction;

        public Task WriteNewAsync(
            ReadOnlyMemory<byte> exactRequestBody,
            string idempotencyKey,
            DateTimeOffset createdAtUtc,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_transaction is not null)
            {
                throw new IOException("Receipt transaction already exists.");
            }
            _transaction = new EnterprisePendingUpdateReceiptTransaction(
                exactRequestBody.Span,
                idempotencyKey,
                createdAtUtc);
            return Task.CompletedTask;
        }

        public Task<EnterprisePendingUpdateReceiptTransaction?> ReadAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_transaction is null)
            {
                return Task.FromResult<EnterprisePendingUpdateReceiptTransaction?>(null);
            }
            return Task.FromResult<EnterprisePendingUpdateReceiptTransaction?>(new(
                _transaction.ExactRequestBody.Span,
                _transaction.IdempotencyKey,
                _transaction.CreatedAtUtc,
                _transaction.AcknowledgedAtUtc));
        }

        public Task MarkAcknowledgedAsync(
            EnterprisePendingUpdateReceiptTransaction transaction,
            DateTimeOffset acknowledgedAtUtc,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_transaction is null
                || _transaction.IsAcknowledged
                || !string.Equals(
                    _transaction.IdempotencyKey,
                    transaction.IdempotencyKey,
                    StringComparison.Ordinal)
                || !CryptographicOperations.FixedTimeEquals(
                    _transaction.ExactRequestBody.Span,
                    transaction.ExactRequestBody.Span))
            {
                throw new InvalidDataException("Receipt acknowledgement did not match pending state.");
            }
            _transaction.Dispose();
            _transaction = new EnterprisePendingUpdateReceiptTransaction(
                transaction.ExactRequestBody.Span,
                transaction.IdempotencyKey,
                transaction.CreatedAtUtc,
                acknowledgedAtUtc);
            return Task.CompletedTask;
        }

        public void Delete()
        {
            _transaction?.Dispose();
            _transaction = null;
        }

        public void Dispose() => Delete();
    }

    private sealed class DelegateHandler(
        Func<HttpRequestMessage, Task<HttpResponseMessage>> responseFactory)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return responseFactory(request);
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset nowUtc) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => nowUtc;
    }

    private sealed class EphemeralKeyStore : IEnterpriseDeviceProofKeyStore, IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly EnterpriseDevicePublicIdentity _identity;

        public EphemeralKeyStore()
        {
            var parameters = _key.ExportParameters(false);
            var x = Base64Url(parameters.Q.X!);
            var y = Base64Url(parameters.Q.Y!);
            var canonical = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
            _identity = new EnterpriseDevicePublicIdentity(
                "EC",
                "P-256",
                x,
                y,
                Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))));
        }

        public EnterpriseDevicePublicIdentity GetOrCreatePublicIdentity() => _identity;

        public byte[] Sign(ReadOnlySpan<byte> payload) => _key.SignData(
            payload,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        public void DeleteForSecurityReset()
        {
        }

        public void Dispose() => _key.Dispose();
    }
}
