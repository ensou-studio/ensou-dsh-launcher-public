using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Contracts;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.Client;

public sealed record EnterpriseInstalledReleaseEvidence(
    string Channel,
    string ReleaseSetId,
    long Generation,
    long Sequence,
    long MinAcceptedSequence,
    long LatestVerifiedGeneration,
    long LatestVerifiedSequence,
    long LatestVerifiedMinAcceptedSequence,
    string ManifestSha256,
    string LauncherReleaseId,
    string RuntimeReleaseId,
    string PluginPolicyReleaseId);

public interface IEnterpriseInstalledReleaseEvidenceProvider
{
    EnterpriseInstalledReleaseEvidence ReadRequired();

    bool IsRejected(string releaseSetId);
}

/// <summary>
/// Reads only state that was produced by the signed release-feed verifier and
/// the atomic release-set pointer. Control-plane scalar policy is deliberately
/// excluded from this provider and can never authorize an installation.
/// </summary>
public sealed class EnterpriseInstalledReleaseEvidenceProvider
    : IEnterpriseInstalledReleaseEvidenceProvider
{
    private readonly EnterpriseReleaseSetPointerStore _pointerStore;
    private readonly EnterpriseReleaseFeedStateStore _feedStateStore;
    private readonly EnterpriseReleaseHealthQuarantineStore _quarantineStore;
    private readonly EnterpriseCompiledReleaseTrust? _compiledTrust;
    private readonly string _channel;

    public EnterpriseInstalledReleaseEvidenceProvider(
        EnterpriseInstallationLayout layout,
        Uri signedManifestUri,
        string expectedChannel,
        EnterpriseReleaseTrustPolicy? trustPolicy = null)
    {
        ArgumentNullException.ThrowIfNull(layout);
        _channel = ParseSignedFeedChannel(signedManifestUri);
        EnterpriseReleaseSetValidator.ValidateToken(
            expectedChannel,
            "expected channel",
            64);
        if (!EnterpriseReleaseSetContract.IsSupportedChannel(expectedChannel)
            || !string.Equals(_channel, expectedChannel, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise signed-feed URI does not match the expected channel.");
        }
        _compiledTrust = trustPolicy is null
            ? null
            : new EnterpriseCompiledReleaseTrust(signedManifestUri, trustPolicy);
        _compiledTrust?.Validate(layout);
        _pointerStore = new EnterpriseReleaseSetPointerStore(layout, _compiledTrust);
        _feedStateStore = new EnterpriseReleaseFeedStateStore(layout, expectedChannel);
        _quarantineStore = new EnterpriseReleaseHealthQuarantineStore(layout);
    }

    public bool IsRejected(string releaseSetId) =>
        _quarantineStore.IsRejected(releaseSetId);

    public EnterpriseInstalledReleaseEvidence ReadRequired()
    {
        var pointer = _pointerStore.ReadRequired();
        var current = pointer.Current;
        var feedState = _feedStateStore.TryRead()
            ?? throw new InvalidDataException(
                "Enterprise signed release-feed state is missing.");
        var accepted = _feedStateStore.ReadAcceptedIdentityRequired(
            current,
            _compiledTrust);
        if (current.HealthState != EnterpriseReleaseHealthStates.Healthy
            || current.Sequence <= 0
            || current.Generation <= 0
            || current.PluginPolicy is null
            || current.Generation > feedState.HighestGeneration
            || current.Sequence > feedState.HighestSequence
            || current.Sequence < feedState.MinAcceptedSequence
            || feedState.RevokedReleaseSetIds.Contains(
                current.ReleaseSetId,
                StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise active release-set does not match its verified signed-feed state.");
        }

        return new EnterpriseInstalledReleaseEvidence(
            feedState.Channel,
            current.ReleaseSetId,
            current.Generation,
            current.Sequence,
            current.MinAcceptedSequence,
            feedState.HighestGeneration,
            feedState.HighestSequence,
            feedState.MinAcceptedSequence,
            accepted.ManifestSha256,
            current.Launcher.ReleaseId,
            current.Runtime.ReleaseId,
            current.PluginPolicy.ReleaseId);
    }

    internal static string ParseSignedFeedChannel(Uri signedManifestUri)
    {
        ArgumentNullException.ThrowIfNull(signedManifestUri);
        if (!signedManifestUri.IsAbsoluteUri
            || !string.Equals(
                signedManifestUri.Scheme,
                Uri.UriSchemeHttps,
                StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(signedManifestUri.UserInfo)
            || !string.IsNullOrEmpty(signedManifestUri.Query)
            || !string.IsNullOrEmpty(signedManifestUri.Fragment))
        {
            throw new InvalidDataException(
                "Enterprise signed manifest URI must be an absolute HTTPS feed path.");
        }

        var segments = signedManifestUri.AbsolutePath.Split(
            '/',
            StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length != 4
            || !string.Equals(segments[0], "v2", StringComparison.Ordinal)
            || !string.Equals(segments[1], "channels", StringComparison.Ordinal)
            || !string.Equals(
                segments[^1],
                "release-set.v2.json",
                StringComparison.Ordinal)
            || segments[^2] is not "lab" and not "pilot" and not "stable")
        {
            throw new InvalidDataException(
                "Enterprise signed manifest URI must identify the lab, pilot, or stable channel.");
        }

        return segments[^2];
    }
}

public sealed record EnterpriseDeviceUpdatePolicy
{
    [JsonPropertyName("schema_version")]
    public required int SchemaVersion { get; init; }

    [JsonPropertyName("channel")]
    public required string Channel { get; init; }

    [JsonPropertyName("release_set_id")]
    public required string ReleaseSetId { get; init; }

    [JsonPropertyName("generation")]
    public required long Generation { get; init; }

    [JsonPropertyName("sequence")]
    public required long Sequence { get; init; }

    [JsonPropertyName("min_accepted_sequence")]
    public required long MinAcceptedSequence { get; init; }

    [JsonPropertyName("manifest_sha256")]
    public required string ManifestSha256 { get; init; }

    [JsonPropertyName("policy_receipt_sha256")]
    public required string PolicyReceiptSha256 { get; init; }

    [JsonPropertyName("issued_at")]
    public required DateTimeOffset IssuedAtUtc { get; init; }

    [JsonPropertyName("expires_at")]
    public required DateTimeOffset ExpiresAtUtc { get; init; }

    [JsonPropertyName("grace_until")]
    public required DateTimeOffset GraceUntilUtc { get; init; }

    [JsonPropertyName("server_time")]
    public required DateTimeOffset ServerTimeUtc { get; init; }

    [JsonPropertyName("enforcement_required")]
    public required bool EnforcementRequired { get; init; }
}

public sealed record EnterpriseInstalledUpdateReceiptRequest
{
    [JsonPropertyName("schema_version")]
    public required int SchemaVersion { get; init; }

    [JsonPropertyName("receipt_id")]
    public required string ReceiptId { get; init; }

    [JsonPropertyName("channel")]
    public required string Channel { get; init; }

    [JsonPropertyName("release_set_id")]
    public required string ReleaseSetId { get; init; }

    [JsonPropertyName("manifest_sequence")]
    public required long ManifestSequence { get; init; }

    [JsonPropertyName("manifest_sha256")]
    public required string ManifestSha256 { get; init; }

    [JsonPropertyName("active_release_set_id")]
    public required string ActiveReleaseSetId { get; init; }

    [JsonPropertyName("active_sequence")]
    public required long ActiveSequence { get; init; }

    [JsonPropertyName("launcher_release_id")]
    public required string LauncherReleaseId { get; init; }

    [JsonPropertyName("runtime_release_id")]
    public required string RuntimeReleaseId { get; init; }

    [JsonPropertyName("plugin_policy_release_id")]
    public required string PluginPolicyReleaseId { get; init; }

    [JsonPropertyName("outcome")]
    public required string Outcome { get; init; }

    [JsonPropertyName("client_observed_at")]
    public required DateTimeOffset ClientObservedAtUtc { get; init; }
}

public sealed record EnterpriseDeviceUpdateReceiptAccepted
{
    [JsonPropertyName("schema_version")]
    public required int SchemaVersion { get; init; }

    [JsonPropertyName("receipt_id")]
    public required string ReceiptId { get; init; }

    [JsonPropertyName("accepted_at")]
    public required DateTimeOffset AcceptedAtUtc { get; init; }

    [JsonPropertyName("update_policy")]
    public required EnterpriseDeviceUpdatePolicy UpdatePolicy { get; init; }
}

public interface IEnterpriseDeviceUpdateManagementClient
{
    Task<EnterpriseDeviceUpdatePolicy> GetPolicyAsync(
        string bindingId,
        CancellationToken cancellationToken = default);

    Task<EnterpriseDeviceUpdateReceiptAccepted> ReportAsync(
        string bindingId,
        ReadOnlyMemory<byte> exactReceiptBody,
        string idempotencyKey,
        CancellationToken cancellationToken = default);
}

public sealed class EnterpriseDeviceUpdateManagementClient
    : IEnterpriseDeviceUpdateManagementClient
{
    private const int MaximumResponseBytes = 64 * 1024;
    private const long MaximumSafeInteger = 9_007_199_254_740_991;
    private static readonly TimeSpan MaximumServerClockDifference = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MaximumPolicyLifetime = TimeSpan.FromDays(31);
    private static readonly JsonSerializerOptions StrictJson = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new EnterpriseWholeSecondUtcDateTimeOffsetConverter() },
    };

    private readonly HttpClient _httpClient;
    private readonly EnterpriseControlPlaneOptions _options;
    private readonly EnterpriseDpopProofFactory _proofFactory;
    private readonly IEnterpriseAccessTokenVault _accessTokenVault;
    private readonly TimeProvider _timeProvider;

    public EnterpriseDeviceUpdateManagementClient(
        HttpClient httpClient,
        EnterpriseControlPlaneOptions options,
        EnterpriseDpopProofFactory proofFactory,
        IEnterpriseAccessTokenVault accessTokenVault,
        TimeProvider? timeProvider = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _proofFactory = proofFactory ?? throw new ArgumentNullException(nameof(proofFactory));
        _accessTokenVault = accessTokenVault
            ?? throw new ArgumentNullException(nameof(accessTokenVault));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<EnterpriseDeviceUpdatePolicy> GetPolicyAsync(
        string bindingId,
        CancellationToken cancellationToken = default)
    {
        EnterpriseBindingValidation.CanonicalizeUuid(bindingId, nameof(bindingId));
        var requestUri = new Uri(_options.ApiOrigin, "v1/device-update-policy");
        using var token = _accessTokenVault.Acquire(_timeProvider.GetUtcNow());
        if (!string.Equals(token.BindingId, bindingId, StringComparison.Ordinal))
        {
            throw new EnterpriseAccessTokenUnavailableException();
        }
        var tokenValue = token.Materialize();
        using var message = CreateAuthorizedRequest(HttpMethod.Get, requestUri, tokenValue);
        try
        {
            using var response = await _httpClient.SendAsync(
                    message,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken)
                .ConfigureAwait(false);
            EnsureExpectedResponse(response, requestUri, HttpStatusCode.OK);
            var policy = await ReadJsonAsync<EnterpriseDeviceUpdatePolicy>(
                    response,
                    cancellationToken)
                .ConfigureAwait(false);
            ValidatePolicy(policy, _timeProvider.GetUtcNow());
            return policy;
        }
        finally
        {
            ZeroString(tokenValue);
        }
    }

    public async Task<EnterpriseDeviceUpdateReceiptAccepted> ReportAsync(
        string bindingId,
        ReadOnlyMemory<byte> exactReceiptBody,
        string idempotencyKey,
        CancellationToken cancellationToken = default)
    {
        EnterpriseBindingValidation.CanonicalizeUuid(bindingId, nameof(bindingId));
        var receipt = DeserializeExactReceipt(exactReceiptBody);
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            idempotencyKey,
            nameof(idempotencyKey),
            32);
        var exactBody = exactReceiptBody.ToArray();
        var requestUri = new Uri(_options.ApiOrigin, "v1/device-update-receipts");
        using var token = _accessTokenVault.Acquire(_timeProvider.GetUtcNow());
        if (!string.Equals(token.BindingId, bindingId, StringComparison.Ordinal))
        {
            throw new EnterpriseAccessTokenUnavailableException();
        }
        var tokenValue = token.Materialize();
        using var message = CreateAuthorizedRequest(HttpMethod.Post, requestUri, tokenValue);
        message.Headers.TryAddWithoutValidation("Idempotency-Key", idempotencyKey);
        message.Content = new ByteArrayContent(exactBody);
        message.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json")
        {
            CharSet = "utf-8",
        };
        try
        {
            using var response = await _httpClient.SendAsync(
                    message,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken)
                .ConfigureAwait(false);
            EnsureExpectedResponse(response, requestUri, HttpStatusCode.OK);
            var accepted = await ReadJsonAsync<EnterpriseDeviceUpdateReceiptAccepted>(
                    response,
                    cancellationToken)
                .ConfigureAwait(false);
            ValidateAccepted(accepted, receipt.ReceiptId, _timeProvider.GetUtcNow());
            return accepted;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactBody);
            ZeroString(tokenValue);
        }
    }

    private HttpRequestMessage CreateAuthorizedRequest(
        HttpMethod method,
        Uri requestUri,
        string token)
    {
        var message = new HttpRequestMessage(method, requestUri);
        message.Headers.Authorization = new AuthenticationHeaderValue("DPoP", token);
        message.Headers.TryAddWithoutValidation(
            "DPoP",
            _proofFactory.Create(method, requestUri, authorizationSecret: token));
        return message;
    }

    internal static void ValidateAccepted(
        EnterpriseDeviceUpdateReceiptAccepted accepted,
        string expectedReceiptId,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(accepted);
        if (accepted.SchemaVersion != 1
            || !string.Equals(accepted.ReceiptId, expectedReceiptId, StringComparison.Ordinal)
            || !IsCanonicalLowercaseUuid(accepted.ReceiptId)
            || (accepted.AcceptedAtUtc - nowUtc).Duration() > MaximumServerClockDifference)
        {
            throw new InvalidDataException(
                "Enterprise update receipt acknowledgement is invalid.");
        }

        ValidatePolicy(accepted.UpdatePolicy, nowUtc);
    }

    internal static void ValidatePolicy(
        EnterpriseDeviceUpdatePolicy policy,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (nowUtc.Offset != TimeSpan.Zero
            || policy.SchemaVersion != 1
            || policy.Channel is not "lab" and not "pilot" and not "stable"
            || !IsReleaseToken(policy.ReleaseSetId)
            || policy.Generation is <= 0 or > MaximumSafeInteger
            || policy.Sequence is <= 0 or > MaximumSafeInteger
            || policy.MinAcceptedSequence is < 0 or > MaximumSafeInteger
            || policy.MinAcceptedSequence > policy.Sequence
            || !IsSha256(policy.ManifestSha256)
            || !IsSha256(policy.PolicyReceiptSha256)
            || policy.IssuedAtUtc >= policy.ExpiresAtUtc
            || policy.ExpiresAtUtc - policy.IssuedAtUtc > MaximumPolicyLifetime
            || policy.GraceUntilUtc < policy.IssuedAtUtc
            || policy.GraceUntilUtc > policy.ExpiresAtUtc
            || policy.ServerTimeUtc < policy.IssuedAtUtc
            || policy.ServerTimeUtc >= policy.ExpiresAtUtc
            || (policy.ServerTimeUtc - nowUtc).Duration() > MaximumServerClockDifference
            || policy.EnforcementRequired != (policy.ServerTimeUtc >= policy.GraceUntilUtc))
        {
            throw new InvalidDataException(
                "Enterprise device update policy is invalid or stale.");
        }
    }

    public static byte[] SerializeExactReceipt(
        EnterpriseInstalledUpdateReceiptRequest receipt)
    {
        ValidateReceipt(receipt);
        return JsonSerializer.SerializeToUtf8Bytes(receipt, StrictJson);
    }

    public static EnterpriseInstalledUpdateReceiptRequest DeserializeExactReceipt(
        ReadOnlyMemory<byte> exactReceiptBody)
    {
        try
        {
            if (exactReceiptBody.IsEmpty || exactReceiptBody.Length > 64 * 1024)
            {
                throw new InvalidDataException(
                    "Enterprise update receipt body is empty or too large.");
            }
            EnterpriseStrictJson.ValidateNoDuplicateProperties(exactReceiptBody);
            var receipt = JsonSerializer.Deserialize<EnterpriseInstalledUpdateReceiptRequest>(
                    exactReceiptBody.Span,
                    StrictJson)
                ?? throw new InvalidDataException(
                    "Enterprise update receipt body is empty.");
            ValidateReceipt(receipt);
            return receipt;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Enterprise update receipt JSON is invalid.",
                exception);
        }
    }

    private static void ValidateReceipt(EnterpriseInstalledUpdateReceiptRequest receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        var installedTupleMatches = string.Equals(
                receipt.Outcome,
                "INSTALLED",
                StringComparison.Ordinal)
            && receipt.ActiveSequence == receipt.ManifestSequence
            && string.Equals(
                receipt.ActiveReleaseSetId,
                receipt.ReleaseSetId,
                StringComparison.Ordinal);
        var failedTupleIsSafe = receipt.Outcome is "FAILED" or "QUARANTINED"
            && receipt.ActiveSequence <= receipt.ManifestSequence;
        var rollbackTupleIsSafe = string.Equals(
                receipt.Outcome,
                "ROLLED_BACK",
                StringComparison.Ordinal)
            && receipt.ActiveSequence < receipt.ManifestSequence;
        if (receipt.SchemaVersion != 1
            || !IsCanonicalLowercaseUuid(receipt.ReceiptId)
            || receipt.Channel is not "lab" and not "pilot" and not "stable"
            || !IsReleaseToken(receipt.ReleaseSetId)
            || receipt.ManifestSequence is <= 0 or > MaximumSafeInteger
            || !IsSha256(receipt.ManifestSha256)
            || !IsReleaseToken(receipt.ActiveReleaseSetId)
            || receipt.ActiveSequence is <= 0 or > MaximumSafeInteger
            || !IsReleaseToken(receipt.LauncherReleaseId)
            || !IsReleaseToken(receipt.RuntimeReleaseId)
            || !IsReleaseToken(receipt.PluginPolicyReleaseId)
            || receipt.ClientObservedAtUtc.Offset != TimeSpan.Zero
            || receipt.ClientObservedAtUtc.Ticks % TimeSpan.TicksPerSecond != 0
            || (!installedTupleMatches && !failedTupleIsSafe && !rollbackTupleIsSafe))
        {
            throw new InvalidDataException(
                "Enterprise update receipt is invalid.");
        }
    }

    private static void EnsureExpectedResponse(
        HttpResponseMessage response,
        Uri requestUri,
        HttpStatusCode expectedStatus)
    {
        if ((int)response.StatusCode is >= 300 and < 400
            || response.RequestMessage?.RequestUri is { } finalUri
                && !string.Equals(
                    finalUri.AbsoluteUri,
                    requestUri.AbsoluteUri,
                    StringComparison.Ordinal))
        {
            throw new HttpRequestException(
                "Enterprise device update management redirects are forbidden.",
                inner: null,
                response.StatusCode);
        }

        if (response.StatusCode != expectedStatus)
        {
            throw new HttpRequestException(
                $"Enterprise device update management returned HTTP {(int)response.StatusCode}.",
                inner: null,
                response.StatusCode);
        }
    }

    private static async Task<T> ReadJsonAsync<T>(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentType?.MediaType is not "application/json"
            || response.Content.Headers.ContentLength is > MaximumResponseBytes)
        {
            throw new InvalidDataException(
                "Enterprise device update management response must be bounded application/json.");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        using var bounded = new MemoryStream();
        var buffer = new byte[4096];
        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                if (bounded.Length + read > MaximumResponseBytes)
                {
                    throw new InvalidDataException(
                        "Enterprise device update management response is too large.");
                }

                await bounded.WriteAsync(buffer.AsMemory(0, read), cancellationToken)
                    .ConfigureAwait(false);
            }

            var payload = bounded.GetBuffer().AsMemory(0, checked((int)bounded.Length));
            EnterpriseStrictJson.ValidateNoDuplicateProperties(payload);
            return JsonSerializer.Deserialize<T>(payload.Span, StrictJson)
                ?? throw new InvalidDataException(
                    "Enterprise device update management response is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Enterprise device update management response JSON is invalid.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            CryptographicOperations.ZeroMemory(bounded.GetBuffer());
        }
    }

    private static bool IsCanonicalLowercaseUuid(string value) =>
        Guid.TryParseExact(value, "D", out var parsed)
        && parsed != Guid.Empty
        && string.Equals(parsed.ToString("D"), value, StringComparison.Ordinal);

    private static bool IsSha256(string value) => value is { Length: 64 }
        && value.All(character => char.IsAsciiDigit(character)
            || character is >= 'a' and <= 'f');

    private static bool IsReleaseToken(string value) => value is { Length: >= 1 and <= 128 }
        && char.IsAsciiLetterOrDigit(value[0])
        && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '.' or '_' or '+' or '-');

    private static void ZeroString(string value)
    {
        // Strings cannot be reliably zeroed. Keep materialization scoped to one
        // request; the owning token lease and vault remain explicitly zeroed.
        GC.KeepAlive(value);
    }
}

public interface IEnterpriseDeviceUpdateGate
{
    Task<EnterpriseAccessSnapshot> EvaluateBeforeReadyAsync(
        EnterpriseAccessSnapshot authorizedSnapshot,
        string bindingId,
        CancellationToken cancellationToken = default);
}

public sealed class EnterpriseDeviceUpdateGate : IEnterpriseDeviceUpdateGate
{
    private const long MaximumSafeInteger = 9_007_199_254_740_991;
    private readonly IEnterpriseDeviceUpdateManagementClient _managementClient;
    private readonly IEnterpriseInstalledReleaseEvidenceProvider _evidenceProvider;
    private readonly IEnterprisePendingUpdateReceiptTransactionStore _receiptStore;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _receiptGate = new(1, 1);

    public EnterpriseDeviceUpdateGate(
        IEnterpriseDeviceUpdateManagementClient managementClient,
        IEnterpriseInstalledReleaseEvidenceProvider evidenceProvider,
        IEnterprisePendingUpdateReceiptTransactionStore receiptStore,
        TimeProvider? timeProvider = null)
    {
        _managementClient = managementClient
            ?? throw new ArgumentNullException(nameof(managementClient));
        _evidenceProvider = evidenceProvider
            ?? throw new ArgumentNullException(nameof(evidenceProvider));
        _receiptStore = receiptStore
            ?? throw new ArgumentNullException(nameof(receiptStore));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<EnterpriseAccessSnapshot> EvaluateBeforeReadyAsync(
        EnterpriseAccessSnapshot authorizedSnapshot,
        string bindingId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authorizedSnapshot);
        EnterpriseBindingValidation.CanonicalizeUuid(bindingId, nameof(bindingId));
        await _receiptGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var nowUtc = _timeProvider.GetUtcNow();
            var policy = await _managementClient.GetPolicyAsync(bindingId, cancellationToken)
                .ConfigureAwait(false);
            EnterpriseDeviceUpdateManagementClient.ValidatePolicy(policy, nowUtc);
            var evidence = _evidenceProvider.ReadRequired();
            ValidateEvidence(evidence);
            EnterpriseInstalledUpdateReceiptRequest? durableReceipt = null;
            var durableReceiptAcknowledged = false;
            using (var transaction = await _receiptStore.ReadAsync(cancellationToken)
                       .ConfigureAwait(false))
            {
                if (transaction is not null)
                {
                    durableReceipt = EnterpriseDeviceUpdateManagementClient
                        .DeserializeExactReceipt(transaction.ExactRequestBody);
                    if (!transaction.IsAcknowledged)
                    {
                        var replayAccepted = await _managementClient.ReportAsync(
                                bindingId,
                                transaction.ExactRequestBody,
                                transaction.IdempotencyKey,
                                cancellationToken)
                            .ConfigureAwait(false);
                        EnterpriseDeviceUpdateManagementClient.ValidateAccepted(
                            replayAccepted,
                            durableReceipt.ReceiptId,
                            _timeProvider.GetUtcNow());
                        await _receiptStore.MarkAcknowledgedAsync(
                                transaction,
                                WholeSecondNow(),
                                cancellationToken)
                            .ConfigureAwait(false);
                        policy = replayAccepted.UpdatePolicy;
                    }
                    durableReceiptAcknowledged = true;
                }
            }

            if (!Matches(policy, evidence))
            {
                if (CanReportRollback(policy, evidence)
                    && _evidenceProvider.IsRejected(policy.ReleaseSetId)
                    && !(durableReceiptAcknowledged
                        && IsSameRollbackReceipt(durableReceipt!, policy, evidence)))
                {
                    policy = (await PersistAndReportAsync(
                            bindingId,
                            CreateReceipt(policy, evidence, "ROLLED_BACK"),
                            cancellationToken)
                        .ConfigureAwait(false)).UpdatePolicy;
                }
                return RequiresUpdate(policy, evidence)
                    ? RequireUpdate(authorizedSnapshot)
                    : authorizedSnapshot;
            }

            if (!(durableReceiptAcknowledged
                && IsSameInstalledReceipt(durableReceipt!, evidence)))
            {
                policy = (await PersistAndReportAsync(
                        bindingId,
                        CreateReceipt(policy, evidence, "INSTALLED"),
                        cancellationToken)
                    .ConfigureAwait(false)).UpdatePolicy;
            }
            if (!Matches(policy, evidence)
                && RequiresUpdate(policy, evidence))
            {
                return RequireUpdate(authorizedSnapshot);
            }

            return authorizedSnapshot;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is
            InvalidDataException
            or IOException
            or UnauthorizedAccessException
            or CryptographicException
            or HttpRequestException
            or OperationCanceledException
            or EnterpriseAccessTokenUnavailableException)
        {
            // Management cross-check and acknowledgement are mandatory before
            // Ready. This never changes installed bytes; the signed feed remains
            // the sole installation authority.
            return RequireUpdate(authorizedSnapshot);
        }
        finally
        {
            _receiptGate.Release();
        }
    }

    private async Task<EnterpriseDeviceUpdateReceiptAccepted> PersistAndReportAsync(
        string bindingId,
        EnterpriseInstalledUpdateReceiptRequest receipt,
        CancellationToken cancellationToken)
    {
        var exactBody = EnterpriseDeviceUpdateManagementClient.SerializeExactReceipt(receipt);
        var idempotencyBytes = RandomNumberGenerator.GetBytes(32);
        try
        {
            var idempotencyKey = EnterpriseBindingValidation.Base64UrlEncode(idempotencyBytes);
            // Any existing file reached this point only after an exact server
            // acknowledgement. Replacing that marker with a new create-only
            // pending request cannot discard an unacknowledged operation.
            _receiptStore.Delete();
            await _receiptStore.WriteNewAsync(
                    exactBody,
                    idempotencyKey,
                    WholeSecondNow(),
                    cancellationToken)
                .ConfigureAwait(false);
            using var persisted = await _receiptStore.ReadAsync(cancellationToken)
                .ConfigureAwait(false)
                ?? throw new IOException(
                    "Enterprise update receipt was not durable before transmission.");
            var persistedReceipt = EnterpriseDeviceUpdateManagementClient.DeserializeExactReceipt(
                persisted.ExactRequestBody);
            if (persisted.IsAcknowledged
                || !string.Equals(
                    persistedReceipt.ReceiptId,
                    receipt.ReceiptId,
                    StringComparison.Ordinal)
                || !CryptographicOperations.FixedTimeEquals(
                    persisted.ExactRequestBody.Span,
                    exactBody))
            {
                throw new InvalidDataException(
                    "Enterprise durable update receipt does not match the request to send.");
            }
            var accepted = await _managementClient.ReportAsync(
                    bindingId,
                    persisted.ExactRequestBody,
                    persisted.IdempotencyKey,
                    cancellationToken)
                .ConfigureAwait(false);
            EnterpriseDeviceUpdateManagementClient.ValidateAccepted(
                accepted,
                persistedReceipt.ReceiptId,
                _timeProvider.GetUtcNow());
            await _receiptStore.MarkAcknowledgedAsync(
                    persisted,
                    WholeSecondNow(),
                    cancellationToken)
                .ConfigureAwait(false);
            return accepted;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactBody);
            CryptographicOperations.ZeroMemory(idempotencyBytes);
        }
    }

    private EnterpriseInstalledUpdateReceiptRequest CreateReceipt(
        EnterpriseDeviceUpdatePolicy policy,
        EnterpriseInstalledReleaseEvidence evidence,
        string outcome) => new()
    {
        SchemaVersion = 1,
        ReceiptId = Guid.NewGuid().ToString("D"),
        Channel = policy.Channel,
        ReleaseSetId = policy.ReleaseSetId,
        ManifestSequence = policy.Sequence,
        ManifestSha256 = policy.ManifestSha256,
        ActiveReleaseSetId = evidence.ReleaseSetId,
        ActiveSequence = evidence.Sequence,
        LauncherReleaseId = evidence.LauncherReleaseId,
        RuntimeReleaseId = evidence.RuntimeReleaseId,
        PluginPolicyReleaseId = evidence.PluginPolicyReleaseId,
        Outcome = outcome,
        ClientObservedAtUtc = WholeSecondNow(),
    };

    private DateTimeOffset WholeSecondNow() => DateTimeOffset.FromUnixTimeSeconds(
        _timeProvider.GetUtcNow().ToUnixTimeSeconds());

    private static bool CanReportRollback(
        EnterpriseDeviceUpdatePolicy policy,
        EnterpriseInstalledReleaseEvidence evidence) =>
        string.Equals(policy.Channel, evidence.Channel, StringComparison.Ordinal)
        && policy.Sequence > evidence.Sequence
        && policy.Sequence <= evidence.LatestVerifiedSequence;

    private static bool IsSameInstalledReceipt(
        EnterpriseInstalledUpdateReceiptRequest receipt,
        EnterpriseInstalledReleaseEvidence evidence) =>
        string.Equals(receipt.Outcome, "INSTALLED", StringComparison.Ordinal)
        && string.Equals(receipt.Channel, evidence.Channel, StringComparison.Ordinal)
        && string.Equals(receipt.ReleaseSetId, evidence.ReleaseSetId, StringComparison.Ordinal)
        && receipt.ManifestSequence == evidence.Sequence
        && string.Equals(receipt.ManifestSha256, evidence.ManifestSha256, StringComparison.Ordinal)
        && string.Equals(receipt.ActiveReleaseSetId, evidence.ReleaseSetId, StringComparison.Ordinal)
        && receipt.ActiveSequence == evidence.Sequence
        && string.Equals(receipt.LauncherReleaseId, evidence.LauncherReleaseId, StringComparison.Ordinal)
        && string.Equals(receipt.RuntimeReleaseId, evidence.RuntimeReleaseId, StringComparison.Ordinal)
        && string.Equals(
            receipt.PluginPolicyReleaseId,
            evidence.PluginPolicyReleaseId,
            StringComparison.Ordinal);

    private static bool IsSameRollbackReceipt(
        EnterpriseInstalledUpdateReceiptRequest receipt,
        EnterpriseDeviceUpdatePolicy policy,
        EnterpriseInstalledReleaseEvidence evidence) =>
        string.Equals(receipt.Outcome, "ROLLED_BACK", StringComparison.Ordinal)
        && string.Equals(receipt.Channel, policy.Channel, StringComparison.Ordinal)
        && string.Equals(receipt.ReleaseSetId, policy.ReleaseSetId, StringComparison.Ordinal)
        && receipt.ManifestSequence == policy.Sequence
        && string.Equals(receipt.ManifestSha256, policy.ManifestSha256, StringComparison.Ordinal)
        && string.Equals(receipt.ActiveReleaseSetId, evidence.ReleaseSetId, StringComparison.Ordinal)
        && receipt.ActiveSequence == evidence.Sequence
        && string.Equals(receipt.LauncherReleaseId, evidence.LauncherReleaseId, StringComparison.Ordinal)
        && string.Equals(receipt.RuntimeReleaseId, evidence.RuntimeReleaseId, StringComparison.Ordinal)
        && string.Equals(
            receipt.PluginPolicyReleaseId,
            evidence.PluginPolicyReleaseId,
            StringComparison.Ordinal);

    internal static bool Matches(
        EnterpriseDeviceUpdatePolicy policy,
        EnterpriseInstalledReleaseEvidence evidence) =>
        string.Equals(policy.Channel, evidence.Channel, StringComparison.Ordinal)
        && string.Equals(policy.ReleaseSetId, evidence.ReleaseSetId, StringComparison.Ordinal)
        && policy.Generation == evidence.Generation
        && policy.Sequence == evidence.Sequence
        && policy.MinAcceptedSequence == evidence.MinAcceptedSequence
        && evidence.LatestVerifiedGeneration == evidence.Generation
        && evidence.LatestVerifiedSequence == evidence.Sequence
        && evidence.LatestVerifiedMinAcceptedSequence == evidence.MinAcceptedSequence
        && string.Equals(
            policy.ManifestSha256,
            evidence.ManifestSha256,
            StringComparison.Ordinal)
        && evidence.Sequence >= policy.MinAcceptedSequence;

    internal static bool RequiresUpdate(
        EnterpriseDeviceUpdatePolicy policy,
        EnterpriseInstalledReleaseEvidence evidence) =>
        policy.EnforcementRequired || evidence.Sequence < policy.MinAcceptedSequence;

    internal static EnterpriseAccessSnapshot ValidateGateResult(
        EnterpriseAccessSnapshot authorizedSnapshot,
        EnterpriseAccessSnapshot gateResult)
    {
        ArgumentNullException.ThrowIfNull(authorizedSnapshot);
        ArgumentNullException.ThrowIfNull(gateResult);
        var updateRequired = authorizedSnapshot with { ClientUpdateRequired = true };
        if (gateResult != authorizedSnapshot && gateResult != updateRequired)
        {
            throw new InvalidDataException(
                "Enterprise update gate may only assert ClientUpdateRequired.");
        }

        return gateResult;
    }

    private static void ValidateEvidence(EnterpriseInstalledReleaseEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        if (evidence.Channel is not "lab" and not "pilot" and not "stable"
            || evidence.Generation <= 0
            || evidence.Sequence <= 0
            || evidence.Generation > MaximumSafeInteger
            || evidence.Sequence > MaximumSafeInteger
            || evidence.MinAcceptedSequence < 0
            || evidence.MinAcceptedSequence > evidence.Sequence
            || evidence.LatestVerifiedGeneration > MaximumSafeInteger
            || evidence.LatestVerifiedSequence > MaximumSafeInteger
            || evidence.LatestVerifiedMinAcceptedSequence > MaximumSafeInteger
            || evidence.LatestVerifiedGeneration < evidence.Generation
            || evidence.LatestVerifiedSequence < evidence.Sequence
            || evidence.LatestVerifiedMinAcceptedSequence < 0
            || evidence.LatestVerifiedMinAcceptedSequence > evidence.LatestVerifiedSequence
            || evidence.ManifestSha256 is not { Length: 64 }
            || evidence.ManifestSha256.Any(character => !char.IsAsciiDigit(character)
                && character is not (>= 'a' and <= 'f'))
            || new[]
            {
                evidence.ReleaseSetId,
                evidence.LauncherReleaseId,
                evidence.RuntimeReleaseId,
                evidence.PluginPolicyReleaseId,
            }.Any(value => value is not { Length: >= 1 and <= 128 }
                || !char.IsAsciiLetterOrDigit(value[0])
                || value.Any(character => !char.IsAsciiLetterOrDigit(character)
                    && character is not ('.' or '_' or '+' or '-'))))
        {
            throw new InvalidDataException(
                "Enterprise signed local release evidence is invalid.");
        }
    }

    private static EnterpriseAccessSnapshot RequireUpdate(
        EnterpriseAccessSnapshot snapshot) => snapshot with
        {
            ClientUpdateRequired = true,
        };
}
