using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Contracts;

namespace Ensou.Dsh.Enterprise.Client;

public interface IEnterpriseDeviceBindingClient
{
    Task<EnterpriseDeviceBindingCompleteResponse> CompleteAsync(
        EnterpriseDeviceBindingCompleteRequest request,
        string idempotencyKey,
        CancellationToken cancellationToken = default);
}

public interface IEnterpriseDeviceBindingReplayClient : IEnterpriseDeviceBindingClient
{
    Task<EnterpriseDeviceBindingCompleteResponse> CompleteExactAsync(
        ReadOnlyMemory<byte> exactRequestBody,
        string idempotencyKey,
        CancellationToken cancellationToken = default);
}

public sealed class EnterpriseDeviceBindingClient : IEnterpriseDeviceBindingReplayClient
{
    private const int MaximumResponseBytes = 64 * 1024;
    private static readonly TimeSpan MaximumBindingChallengeLifetime = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan MaximumAccessTokenLifetime = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan MaximumAuthorizationLeaseLifetime = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan MaximumServerClockDifference = TimeSpan.FromMinutes(5);

    private static readonly JsonSerializerOptions StrictJson = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new EnterpriseWholeSecondUtcDateTimeOffsetConverter() },
    };

    private static readonly HashSet<string> AllowedBindingErrorCodes = new(StringComparer.Ordinal)
    {
        EnterpriseErrorCodes.QrStateInvalid,
        EnterpriseErrorCodes.DeviceProofInvalid,
        EnterpriseErrorCodes.EmployeeSuspended,
        EnterpriseErrorCodes.EmployeeRevoked,
        EnterpriseErrorCodes.EmployeeEntitlementMissing,
        EnterpriseErrorCodes.DeviceAlreadyBound,
        EnterpriseErrorCodes.DeviceReplacementNotAuthorized,
        EnterpriseErrorCodes.ApiProfileUnassigned,
        EnterpriseErrorCodes.ApiProfileDisabled,
        EnterpriseErrorCodes.QrSessionConsumed,
        EnterpriseErrorCodes.QrSessionExpired,
        EnterpriseErrorCodes.IdempotencyKeyReused,
        EnterpriseErrorCodes.RateLimited,
        EnterpriseErrorCodes.ControlPlaneUnavailable,
    };

    private readonly HttpClient _httpClient;
    private readonly EnterpriseControlPlaneOptions _options;
    private readonly EnterpriseDpopProofFactory _proofFactory;
    private readonly TimeProvider _timeProvider;

    public EnterpriseDeviceBindingClient(
        HttpClient httpClient,
        EnterpriseControlPlaneOptions options,
        EnterpriseDpopProofFactory proofFactory,
        TimeProvider? timeProvider = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _proofFactory = proofFactory ?? throw new ArgumentNullException(nameof(proofFactory));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<EnterpriseDeviceBindingCompleteResponse> CompleteAsync(
        EnterpriseDeviceBindingCompleteRequest request,
        string idempotencyKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateRequest(request, requireLiveChallenge: true);
        var exactRequestBody = SerializeExactRequest(request);
        try
        {
            var response = await CompleteExactAsync(
                    exactRequestBody,
                    idempotencyKey,
                    cancellationToken)
                .ConfigureAwait(false);
            ValidateResponseFreshness(response);
            return response;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactRequestBody);
        }
    }

    public async Task<EnterpriseDeviceBindingCompleteResponse> CompleteExactAsync(
        ReadOnlyMemory<byte> exactRequestBody,
        string idempotencyKey,
        CancellationToken cancellationToken = default)
    {
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            idempotencyKey,
            nameof(idempotencyKey),
            32);
        var request = DeserializeExactRequest(exactRequestBody);
        ValidateRequest(request, requireLiveChallenge: false);

        var requestUri = new Uri(_options.ApiOrigin, "v1/device-bindings/complete");
        var requestBytes = exactRequestBody.ToArray();
        using var message = new HttpRequestMessage(HttpMethod.Post, requestUri)
        {
            Content = new ByteArrayContent(requestBytes),
        };
        message.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(
            "application/json")
        {
            CharSet = "utf-8",
        };
        message.Headers.TryAddWithoutValidation("Idempotency-Key", idempotencyKey);
        message.Headers.TryAddWithoutValidation(
            "DPoP",
            _proofFactory.Create(
                HttpMethod.Post,
                requestUri,
                request.BindingChallenge,
                request.BindGrant));

        try
        {
            using var response = await _httpClient.SendAsync(
                    message,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken)
                .ConfigureAwait(false);
            EnsureNoRedirect(response, requestUri);
            await ThrowIfErrorAsync(response, cancellationToken).ConfigureAwait(false);
            EnsureExpectedSuccessStatus(response, HttpStatusCode.Created);
            var result = await ReadJsonAsync<EnterpriseDeviceBindingCompleteResponse>(
                    response,
                    cancellationToken)
                .ConfigureAwait(false);
            ValidateResponse(result);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(requestBytes);
        }
    }

    internal static byte[] SerializeExactRequest(
        EnterpriseDeviceBindingCompleteRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return JsonSerializer.SerializeToUtf8Bytes(request, StrictJson);
    }

    internal static EnterpriseDeviceBindingCompleteRequest DeserializeExactRequest(
        ReadOnlyMemory<byte> exactRequestBody)
    {
        if (exactRequestBody.IsEmpty || exactRequestBody.Length > MaximumResponseBytes)
        {
            throw new InvalidDataException(
                "Enterprise binding replay body has an invalid size.");
        }

        EnterpriseStrictJson.ValidateNoDuplicateProperties(exactRequestBody);
        return JsonSerializer.Deserialize<EnterpriseDeviceBindingCompleteRequest>(
                exactRequestBody.Span,
                StrictJson)
            ?? throw new InvalidDataException(
                "Enterprise binding replay body is empty.");
    }

    private void ValidateRequest(
        EnterpriseDeviceBindingCompleteRequest request,
        bool requireLiveChallenge)
    {
        if (request.SchemaVersion != 1
            || request.BindingPayloadVersion != EnterpriseBindingPayloadBuilder.PayloadVersion)
        {
            throw new InvalidDataException("Enterprise binding request version is unsupported.");
        }

        EnterpriseBindingValidation.CanonicalizeUuid(request.SessionId, nameof(request.SessionId));
        EnterpriseBindingValidation.CanonicalizeUuid(request.InstallId, nameof(request.InstallId));
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            request.BindGrant,
            nameof(request.BindGrant),
            32);
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            request.DeviceKeyThumbprint,
            nameof(request.DeviceKeyThumbprint),
            32);
        EnterpriseBindingValidation.ValidateDeviceLabel(
            request.DeviceLabel,
            nameof(request.DeviceLabel));
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            request.BindingChallenge,
            nameof(request.BindingChallenge),
            32);
        EnterpriseBindingValidation.ValidateCanonicalUtcSecond(
            request.BindingChallengeExpiresAtUtc,
            nameof(request.BindingChallengeExpiresAtUtc));

        var nowUtc = _timeProvider.GetUtcNow();
        if (requireLiveChallenge
            && (request.BindingChallengeExpiresAtUtc <= nowUtc
                || request.BindingChallengeExpiresAtUtc
                    > nowUtc + MaximumBindingChallengeLifetime))
        {
            throw new InvalidDataException("Enterprise binding challenge is expired or overlong.");
        }

        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            request.DeviceSignature,
            nameof(request.DeviceSignature),
            64);

        var proofIdentity = _proofFactory.GetOrCreatePublicIdentity();
        EnterpriseBindingValidation.ValidateP256PublicIdentity(
            proofIdentity,
            "device_proof_key");
        if (!string.Equals(
                request.DeviceKeyThumbprint,
                proofIdentity.Thumbprint,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise binding request does not match the DPoP device key.");
        }

        var canonicalPayload = EnterpriseBindingPayloadBuilder.Build(
            new EnterpriseBindingChallenge(
                request.SessionId,
                request.BindGrant,
                request.BindingChallenge,
                request.BindingChallengeExpiresAtUtc),
            request.InstallId,
            request.DeviceKeyThumbprint);
        try
        {
            EnterpriseBindingValidation.VerifyP256Signature(
                proofIdentity,
                canonicalPayload,
                request.DeviceSignature,
                nameof(request.DeviceSignature));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonicalPayload);
        }
    }

    private void ValidateResponse(EnterpriseDeviceBindingCompleteResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.SchemaVersion != 1)
        {
            throw new InvalidDataException("Enterprise binding response version is unsupported.");
        }

        EnterpriseBindingValidation.CanonicalizeUuid(
            response.BindingId,
            nameof(response.BindingId));
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            response.RefreshToken,
            nameof(response.RefreshToken),
            32);
        ValidateAccessToken(response.AccessToken);
        EnterpriseBindingValidation.ValidateCanonicalUtcSecond(
            response.AccessTokenExpiresAtUtc,
            nameof(response.AccessTokenExpiresAtUtc));
        EnterpriseBindingValidation.ValidateCanonicalUtcSecond(
            response.LeaseExpiresAtUtc,
            nameof(response.LeaseExpiresAtUtc));
        EnterpriseBindingValidation.ValidateCanonicalUtcSecond(
            response.ServerTimeUtc,
            nameof(response.ServerTimeUtc));

        if (response.AccessTokenExpiresAtUtc <= response.ServerTimeUtc
            || response.AccessTokenExpiresAtUtc > response.ServerTimeUtc + MaximumAccessTokenLifetime
            || response.LeaseExpiresAtUtc < response.AccessTokenExpiresAtUtc
            || response.LeaseExpiresAtUtc > response.ServerTimeUtc + MaximumAuthorizationLeaseLifetime)
        {
            throw new InvalidDataException("Enterprise binding response lifetimes are inconsistent.");
        }

        _ = EnterpriseSignedLeaseEnvelopeParser.Parse(response.AuthorizationLease);
    }

    private void ValidateResponseFreshness(
        EnterpriseDeviceBindingCompleteResponse response)
    {
        if ((response.ServerTimeUtc - _timeProvider.GetUtcNow()).Duration()
            > MaximumServerClockDifference)
        {
            throw new InvalidDataException(
                "Enterprise binding response server time is outside the live request window.");
        }
    }

    private static void ValidateAccessToken(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length is < 32 or > 4096
            || value.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '-' and not '.' and not '_' and not '~'))
        {
            throw new InvalidDataException("Enterprise access token is not a bounded bearer token.");
        }
    }

    private static void EnsureNoRedirect(HttpResponseMessage response, Uri requestUri)
    {
        if ((int)response.StatusCode is >= 300 and < 400)
        {
            throw new HttpRequestException(
                "Enterprise control plane redirects are forbidden.",
                inner: null,
                response.StatusCode);
        }

        if (response.RequestMessage?.RequestUri is { } finalUri
            && !string.Equals(
                finalUri.AbsoluteUri,
                requestUri.AbsoluteUri,
                StringComparison.Ordinal))
        {
            throw new HttpRequestException(
                "Enterprise control plane redirect following is forbidden.",
                inner: null,
                response.StatusCode);
        }
    }

    private static void EnsureExpectedSuccessStatus(
        HttpResponseMessage response,
        HttpStatusCode expectedStatus)
    {
        if (response.StatusCode != expectedStatus)
        {
            throw new InvalidDataException(
                $"Enterprise control plane returned unexpected success status {(int)response.StatusCode}.");
        }
    }

    private static async Task ThrowIfErrorAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var envelope = await ReadJsonAsync<EnterpriseErrorEnvelope>(response, cancellationToken)
            .ConfigureAwait(false);
        ValidateBindingError(envelope.Error);
        throw new EnterpriseControlPlaneException(envelope.Error);
    }

    private static async Task<T> ReadJsonAsync<T>(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentType?.MediaType is not "application/json")
        {
            throw new InvalidDataException("Enterprise control plane response must be application/json.");
        }

        if (response.Content.Headers.ContentLength is > MaximumResponseBytes)
        {
            throw new InvalidDataException("Enterprise control plane response is too large.");
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
                    throw new InvalidDataException("Enterprise control plane response is too large.");
                }

                await bounded.WriteAsync(buffer.AsMemory(0, read), cancellationToken)
                    .ConfigureAwait(false);
            }

            var payload = bounded.GetBuffer().AsMemory(0, checked((int)bounded.Length));
            EnterpriseStrictJson.ValidateNoDuplicateProperties(payload);
            return JsonSerializer.Deserialize<T>(
                    payload.Span,
                    StrictJson)
                ?? throw new InvalidDataException("Enterprise control plane response is empty.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            CryptographicOperations.ZeroMemory(bounded.GetBuffer());
        }
    }

    private static void ValidateBindingError(EnterpriseApiError error)
    {
        ArgumentNullException.ThrowIfNull(error);
        if (!AllowedBindingErrorCodes.Contains(error.Code)
            || error.ResetScope != EnterpriseResetScope.None
            || error.ClientState is EnterpriseClientState.Ready or EnterpriseClientState.OfflineGrace)
        {
            throw new InvalidDataException(
                "Enterprise control plane returned an untrusted binding error contract.");
        }

        EnterpriseBindingValidation.ValidateBoundedText(
            error.RequestId,
            nameof(error.RequestId),
            1,
            128);
        EnterpriseBindingValidation.ValidateBoundedText(
            error.Message,
            nameof(error.Message),
            1,
            512);
        if (error.ContactDisplay is not null)
        {
            EnterpriseBindingValidation.ValidateBoundedText(
                error.ContactDisplay,
                nameof(error.ContactDisplay),
                1,
                128);
        }
    }
}

public static class EnterpriseSignedLeaseEnvelopeParser
{
    private const int MinimumCompactJwsLength = 128;
    private const int MaximumCompactJwsLength = 8192;
    private const string ExpectedType = "ensou-dsh-lease+jwt";

    public static EnterpriseSignedLeaseEnvelope Parse(string compactJws)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(compactJws);
        if (compactJws.Length is < MinimumCompactJwsLength or > MaximumCompactJwsLength
            || compactJws.Any(character => character > 0x7f
                || char.IsControl(character)
                || char.IsWhiteSpace(character)))
        {
            throw new InvalidDataException("Enterprise authorization lease is not a bounded compact JWS.");
        }

        var segments = compactJws.Split('.');
        if (segments.Length != 3 || segments.Any(string.IsNullOrEmpty))
        {
            throw new InvalidDataException("Enterprise authorization lease must be a compact JWS.");
        }

        ValidateProtectedHeader(segments[0]);
        ValidateJsonSegment(segments[1], "authorization_lease.payload", 8192);
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            segments[2],
            "authorization_lease.signature",
            64);

        return new EnterpriseSignedLeaseEnvelope(
            compactJws,
            segments[0],
            segments[1],
            segments[2]);
    }

    private static void ValidateProtectedHeader(string segment)
    {
        var decoded = EnterpriseBindingValidation.Base64UrlDecode(
            segment,
            "authorization_lease.header",
            2048);
        try
        {
            using var document = JsonDocument.Parse(decoded, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 4,
            });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException(
                    "Enterprise authorization lease protected header is outside the v1 profile.");
            }

            var hasAlgorithm = root.TryGetProperty("alg", out var algorithm);
            var hasType = root.TryGetProperty("typ", out var type);
            var hasKeyId = root.TryGetProperty("kid", out var keyId);
            if (root.EnumerateObject().Count() != 3
                || !hasAlgorithm
                || algorithm.ValueKind != JsonValueKind.String
                || algorithm.GetString() != "ES256"
                || !hasType
                || type.ValueKind != JsonValueKind.String
                || type.GetString() != ExpectedType
                || !hasKeyId
                || keyId.ValueKind != JsonValueKind.String)
            {
                throw new InvalidDataException(
                    "Enterprise authorization lease protected header is outside the v1 profile.");
            }

            var keyIdValue = keyId.GetString()
                ?? throw new InvalidDataException("Authorization lease key ID is missing.");
            EnterpriseBindingValidation.ValidateBoundedText(
                keyIdValue,
                "authorization_lease.kid",
                1,
                128);
            if (keyIdValue.Any(character => character > 0x7f))
            {
                throw new InvalidDataException("Authorization lease key ID must be printable ASCII.");
            }
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Enterprise authorization lease header must be an exact JSON object.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decoded);
        }
    }

    private static void ValidateJsonSegment(string segment, string parameterName, int maximumBytes)
    {
        var decoded = EnterpriseBindingValidation.Base64UrlDecode(
            segment,
            parameterName,
            maximumBytes);
        try
        {
            using var document = JsonDocument.Parse(decoded, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16,
            });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException(
                    $"{parameterName} must decode to a JSON object.");
            }
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                $"{parameterName} must decode to a JSON object.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decoded);
        }
    }
}
