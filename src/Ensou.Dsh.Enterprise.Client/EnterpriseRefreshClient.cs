using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Contracts;

namespace Ensou.Dsh.Enterprise.Client;

public interface IEnterpriseRefreshClient
{
    Task<EnterpriseDeviceBindingCompleteResponse> RefreshAsync(
        EnterpriseRefreshRequest request,
        string refreshToken,
        string idempotencyKey,
        CancellationToken cancellationToken = default);

    Task<EnterpriseDeviceBindingCompleteResponse> RefreshExactAsync(
        ReadOnlyMemory<byte> exactRequestBody,
        string refreshToken,
        string idempotencyKey,
        CancellationToken cancellationToken = default);
}

public sealed class EnterpriseRefreshClient : IEnterpriseRefreshClient
{
    private const int MaximumResponseBytes = 64 * 1024;
    private static readonly TimeSpan MaximumAccessTokenLifetime = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan MaximumAuthorizationLeaseLifetime = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan MaximumServerClockDifference = TimeSpan.FromMinutes(5);
    private static readonly JsonSerializerOptions StrictJson = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new EnterpriseWholeSecondUtcDateTimeOffsetConverter() },
    };

    private readonly HttpClient _httpClient;
    private readonly EnterpriseControlPlaneOptions _options;
    private readonly EnterpriseDpopProofFactory _proofFactory;
    private readonly TimeProvider _timeProvider;

    public EnterpriseRefreshClient(
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

    public async Task<EnterpriseDeviceBindingCompleteResponse> RefreshAsync(
        EnterpriseRefreshRequest request,
        string refreshToken,
        string idempotencyKey,
        CancellationToken cancellationToken = default)
    {
        ValidateRequest(request);
        var exactRequestBody = SerializeExactRequest(request);
        try
        {
            var response = await RefreshExactAsync(
                    exactRequestBody,
                    refreshToken,
                    idempotencyKey,
                    cancellationToken)
                .ConfigureAwait(false);
            if ((response.ServerTimeUtc - _timeProvider.GetUtcNow()).Duration()
                > MaximumServerClockDifference)
            {
                throw new InvalidDataException(
                    "Enterprise refresh response server time is outside the live request window.");
            }

            return response;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactRequestBody);
        }
    }

    public async Task<EnterpriseDeviceBindingCompleteResponse> RefreshExactAsync(
        ReadOnlyMemory<byte> exactRequestBody,
        string refreshToken,
        string idempotencyKey,
        CancellationToken cancellationToken = default)
    {
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            refreshToken,
            nameof(refreshToken),
            32);
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            idempotencyKey,
            nameof(idempotencyKey),
            32);
        var request = DeserializeExactRequest(exactRequestBody);
        ValidateRequest(request);

        var requestUri = new Uri(_options.ApiOrigin, "v1/auth/refresh");
        var requestBytes = exactRequestBody.ToArray();
        using var message = new HttpRequestMessage(HttpMethod.Post, requestUri)
        {
            Content = new ByteArrayContent(requestBytes),
        };
        message.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json")
        {
            CharSet = "utf-8",
        };
        message.Headers.Authorization = new AuthenticationHeaderValue("Refresh", refreshToken);
        message.Headers.TryAddWithoutValidation("Idempotency-Key", idempotencyKey);
        message.Headers.TryAddWithoutValidation(
            "DPoP",
            _proofFactory.Create(
                HttpMethod.Post,
                requestUri,
                authorizationSecret: refreshToken));

        try
        {
            using var response = await _httpClient.SendAsync(
                    message,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken)
                .ConfigureAwait(false);
            EnsureNoRedirect(response, requestUri);
            await ThrowIfErrorAsync(response, cancellationToken).ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.OK)
            {
                throw new InvalidDataException(
                    $"Enterprise refresh returned unexpected success status {(int)response.StatusCode}.");
            }

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

    internal static byte[] SerializeExactRequest(EnterpriseRefreshRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return JsonSerializer.SerializeToUtf8Bytes(request, StrictJson);
    }

    internal static EnterpriseRefreshRequest DeserializeExactRequest(
        ReadOnlyMemory<byte> exactRequestBody)
    {
        if (exactRequestBody.IsEmpty || exactRequestBody.Length > MaximumResponseBytes)
        {
            throw new InvalidDataException("Enterprise refresh replay body has an invalid size.");
        }

        EnterpriseStrictJson.ValidateNoDuplicateProperties(exactRequestBody);
        return JsonSerializer.Deserialize<EnterpriseRefreshRequest>(
                exactRequestBody.Span,
                StrictJson)
            ?? throw new InvalidDataException("Enterprise refresh replay body is empty.");
    }

    internal static void ValidateRequest(EnterpriseRefreshRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.SchemaVersion != 1)
        {
            throw new InvalidDataException("Enterprise refresh request version is unsupported.");
        }

        EnterpriseBindingValidation.CanonicalizeUuid(request.BindingId, nameof(request.BindingId));
        EnterpriseBindingValidation.CanonicalizeUuid(request.InstallId, nameof(request.InstallId));
        EnterpriseBindingValidation.CanonicalizeUuid(
            request.PreviousLeaseId,
            nameof(request.PreviousLeaseId));
        if (request.AuthorizationEpoch <= 0
            || request.EntitlementEpoch <= 0
            || request.BindingEpoch <= 0)
        {
            throw new InvalidDataException("Enterprise refresh request epochs must be positive.");
        }
    }

    private static void ValidateResponse(EnterpriseDeviceBindingCompleteResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.SchemaVersion != 1)
        {
            throw new InvalidDataException("Enterprise refresh response version is unsupported.");
        }

        EnterpriseBindingValidation.CanonicalizeUuid(response.BindingId, nameof(response.BindingId));
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
            throw new InvalidDataException("Enterprise refresh response lifetimes are inconsistent.");
        }

        _ = EnterpriseSignedLeaseEnvelopeParser.Parse(response.AuthorizationLease);
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
        if ((int)response.StatusCode is >= 300 and < 400
            || response.RequestMessage?.RequestUri is { } finalUri
                && !string.Equals(finalUri.AbsoluteUri, requestUri.AbsoluteUri, StringComparison.Ordinal))
        {
            throw new HttpRequestException(
                "Enterprise refresh redirects are forbidden.",
                inner: null,
                response.StatusCode);
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
        ValidateRefreshError(envelope.Error);
        throw new EnterpriseControlPlaneException(envelope.Error);
    }

    private static void ValidateRefreshError(EnterpriseApiError error)
    {
        ArgumentNullException.ThrowIfNull(error);
        if (error.Code.Length is < 3 or > 64
            || error.Code.Any(character => !char.IsAsciiLetterUpper(character)
                && !char.IsAsciiDigit(character)
                && character != '_')
            || error.ClientState is EnterpriseClientState.Ready or EnterpriseClientState.OfflineGrace
            || !IsTrustedRefreshErrorContract(error))
        {
            throw new InvalidDataException(
                "Enterprise control plane returned an untrusted refresh error contract.");
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

    private static bool IsTrustedRefreshErrorContract(EnterpriseApiError error) =>
        (error.Code, error.ClientState, error.Retryable, error.ResetScope) switch
        {
            (EnterpriseErrorCodes.DeviceProofInvalid,
                EnterpriseClientState.Binding,
                false,
                EnterpriseResetScope.None) => true,
            (EnterpriseErrorCodes.RefreshTokenInvalid,
                EnterpriseClientState.Binding,
                false,
                EnterpriseResetScope.None) => true,
            (EnterpriseErrorCodes.IdempotencyKeyReused,
                EnterpriseClientState.Binding,
                false,
                EnterpriseResetScope.None) => true,
            (EnterpriseErrorCodes.AuthorizationStale,
                EnterpriseClientState.Binding,
                false,
                EnterpriseResetScope.None) => true,
            (EnterpriseErrorCodes.ControlPlaneUnavailable,
                EnterpriseClientState.QrRequired,
                true,
                EnterpriseResetScope.None) => true,
            (EnterpriseErrorCodes.EmployeeSuspended,
                EnterpriseClientState.AccountLocked,
                false,
                EnterpriseResetScope.ManagedConfig) => true,
            (EnterpriseErrorCodes.EmployeeRevoked,
                EnterpriseClientState.AccountLocked,
                false,
                EnterpriseResetScope.SecurityCredentials) => true,
            (EnterpriseErrorCodes.DeviceBindingRevoked,
                EnterpriseClientState.DeviceRevokedResetRequired,
                false,
                EnterpriseResetScope.SecurityCredentials) => true,
            (EnterpriseErrorCodes.RefreshTokenReused,
                EnterpriseClientState.SecurityQuarantined,
                false,
                EnterpriseResetScope.SecurityCredentials) => true,
            (EnterpriseErrorCodes.PluginPolicyDenied,
                EnterpriseClientState.ApiDisabled,
                false,
                EnterpriseResetScope.ManagedConfig) => true,
            (EnterpriseErrorCodes.ApiProfileUnassigned,
                EnterpriseClientState.ApiDisabled,
                false,
                EnterpriseResetScope.ManagedConfig) => true,
            (EnterpriseErrorCodes.ApiProfileDisabled,
                EnterpriseClientState.ApiDisabled,
                false,
                EnterpriseResetScope.ManagedConfig) => true,
            _ => false,
        };

    private static async Task<T> ReadJsonAsync<T>(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentType?.MediaType is not "application/json"
            || response.Content.Headers.ContentLength is > MaximumResponseBytes)
        {
            throw new InvalidDataException(
                "Enterprise refresh response must be bounded application/json.");
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
                    throw new InvalidDataException("Enterprise refresh response is too large.");
                }

                await bounded.WriteAsync(buffer.AsMemory(0, read), cancellationToken)
                    .ConfigureAwait(false);
            }

            var payload = bounded.GetBuffer().AsMemory(0, checked((int)bounded.Length));
            EnterpriseStrictJson.ValidateNoDuplicateProperties(payload);
            return JsonSerializer.Deserialize<T>(payload.Span, StrictJson)
                ?? throw new InvalidDataException("Enterprise refresh response is empty.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            CryptographicOperations.ZeroMemory(bounded.GetBuffer());
        }
    }
}
