using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Contracts;

namespace Ensou.Dsh.Enterprise.Client;

public interface IEnterpriseQrEnrollmentClient
{
    Task<EnterpriseQrSessionCreateResponse> CreateSessionAsync(
        EnterpriseQrSessionCreateRequest request,
        string idempotencyKey,
        CancellationToken cancellationToken = default);

    Task<EnterpriseQrSessionPollResponse> PollSessionAsync(
        EnterpriseQrSessionCreateResponse session,
        string nonce,
        EnterpriseEnrollmentAuthorizationMethod authorizationMethod,
        CancellationToken cancellationToken = default);

    Task ClaimActivationAsync(
        EnterpriseQrSessionCreateResponse session,
        string nonce,
        string activationCode,
        CancellationToken cancellationToken = default);
}

public sealed class EnterpriseQrEnrollmentClient : IEnterpriseQrEnrollmentClient
{
    private const int MaximumResponseBytes = 64 * 1024;
    private static readonly TimeSpan MaximumQrSessionLifetime = TimeSpan.FromSeconds(120);
    private static readonly TimeSpan MaximumBindingChallengeLifetime = TimeSpan.FromSeconds(60);

    private static readonly JsonSerializerOptions StrictJson = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new EnterpriseWholeSecondUtcDateTimeOffsetConverter() },
    };

    private static readonly HashSet<string> AllowedQrErrorCodes = new(StringComparer.Ordinal)
    {
        EnterpriseErrorCodes.QrStateInvalid,
        EnterpriseErrorCodes.DeviceProofInvalid,
        EnterpriseErrorCodes.EnrollmentActivationInvalid,
        EnterpriseErrorCodes.WeComIdentityNotPreregistered,
        EnterpriseErrorCodes.WeComEnterpriseMemberRequired,
        EnterpriseErrorCodes.EmployeeSuspended,
        EnterpriseErrorCodes.EmployeeRevoked,
        EnterpriseErrorCodes.EmployeeEntitlementMissing,
        EnterpriseErrorCodes.DeviceAlreadyBound,
        EnterpriseErrorCodes.DeviceConfirmationRejected,
        EnterpriseErrorCodes.QrSessionConsumed,
        EnterpriseErrorCodes.QrSessionExpired,
        EnterpriseErrorCodes.QrSessionCancelled,
        EnterpriseErrorCodes.IdempotencyKeyReused,
        EnterpriseErrorCodes.RateLimited,
        EnterpriseErrorCodes.ControlPlaneUnavailable,
    };

    private readonly HttpClient _httpClient;
    private readonly EnterpriseControlPlaneOptions _options;
    private readonly EnterpriseDpopProofFactory _proofFactory;
    private readonly TimeProvider _timeProvider;

    public EnterpriseQrEnrollmentClient(
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

    public async Task<EnterpriseQrSessionCreateResponse> CreateSessionAsync(
        EnterpriseQrSessionCreateRequest request,
        string idempotencyKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            idempotencyKey,
            nameof(idempotencyKey),
            32);
        var requestedDeviceDisplayName = ValidateCreateRequest(request);

        var requestUri = new Uri(_options.ApiOrigin, "v1/auth/qr-sessions");
        using var message = new HttpRequestMessage(HttpMethod.Post, requestUri)
        {
            Content = new StringContent(
                JsonSerializer.Serialize(request, StrictJson),
                Encoding.UTF8,
                "application/json"),
        };
        message.Headers.TryAddWithoutValidation("Idempotency-Key", idempotencyKey);
        message.Headers.TryAddWithoutValidation(
            "DPoP",
            _proofFactory.Create(HttpMethod.Post, requestUri, request.Nonce));

        using var response = await _httpClient.SendAsync(
                message,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken)
            .ConfigureAwait(false);
        EnsureNoRedirect(response, requestUri);
        await ThrowIfErrorAsync(response, cancellationToken).ConfigureAwait(false);
        EnsureExpectedSuccessStatus(response, HttpStatusCode.Created);
        var result = await ReadJsonAsync<EnterpriseQrSessionCreateResponse>(
                response,
                cancellationToken)
            .ConfigureAwait(false);
        ValidateCreatedSession(result, requestedDeviceDisplayName);
        return result;
    }

    public async Task<EnterpriseQrSessionPollResponse> PollSessionAsync(
        EnterpriseQrSessionCreateResponse session,
        string nonce,
        EnterpriseEnrollmentAuthorizationMethod authorizationMethod,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        if (!Enum.IsDefined(authorizationMethod))
        {
            throw new ArgumentOutOfRangeException(
                nameof(authorizationMethod),
                authorizationMethod,
                "Enterprise enrollment authorization method is invalid.");
        }

        ValidateCreatedSession(session, expectedDeviceDisplayName: null);
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            nonce,
            nameof(nonce),
            32);

        var sessionId = Uri.EscapeDataString(session.SessionId);
        var requestUri = new Uri(_options.ApiOrigin, $"v1/auth/qr-sessions/{sessionId}");
        using var message = new HttpRequestMessage(HttpMethod.Get, requestUri);
        message.Headers.Authorization = new AuthenticationHeaderValue("QR-Poll", session.PollSecret);
        message.Headers.TryAddWithoutValidation(
            "DPoP",
            _proofFactory.Create(HttpMethod.Get, requestUri, nonce, session.PollSecret));

        using var response = await _httpClient.SendAsync(
                message,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken)
            .ConfigureAwait(false);
        EnsureNoRedirect(response, requestUri);
        await ThrowIfErrorAsync(response, cancellationToken).ConfigureAwait(false);
        EnsureExpectedSuccessStatus(response, HttpStatusCode.OK);
        var result = await ReadJsonAsync<EnterpriseQrSessionPollResponse>(
                response,
                cancellationToken)
            .ConfigureAwait(false);
        ValidatePollResponse(result, session.SessionId, authorizationMethod);
        return result;
    }

    public async Task ClaimActivationAsync(
        EnterpriseQrSessionCreateResponse session,
        string nonce,
        string activationCode,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        ValidateCreatedSession(session, expectedDeviceDisplayName: null);
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            nonce,
            nameof(nonce),
            32);
        EnterpriseQrProtocol.ValidateActivationCode(activationCode);

        var requestUri = new Uri(_options.ApiOrigin, "v1/auth/activation/claim");
        var request = new EnterpriseActivationClaimRequest
        {
            SessionId = session.SessionId,
            ActivationCode = activationCode,
        };
        var requestBytes = JsonSerializer.SerializeToUtf8Bytes(request, StrictJson);
        try
        {
            using var message = new HttpRequestMessage(HttpMethod.Post, requestUri)
            {
                Content = new ByteArrayContent(requestBytes),
            };
            message.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json")
            {
                CharSet = "utf-8",
            };
            message.Headers.TryAddWithoutValidation(
                "DPoP",
                _proofFactory.Create(
                    HttpMethod.Post,
                    requestUri,
                    nonce,
                    activationCode));

            using var response = await _httpClient.SendAsync(
                    message,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken)
                .ConfigureAwait(false);
            EnsureNoRedirect(response, requestUri);
            await ThrowIfErrorAsync(response, cancellationToken).ConfigureAwait(false);
            EnsureExpectedSuccessStatus(response, HttpStatusCode.NoContent);
            await EnsureEmptySuccessContentAsync(response, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(requestBytes);
        }
    }

    private string ValidateCreateRequest(EnterpriseQrSessionCreateRequest request)
    {
        if (request.SchemaVersion != 2
            || !Enum.IsDefined(request.AuthorizationMethod)
            || request.DeviceJwk.KeyType != "EC"
            || request.DeviceJwk.Curve != "P-256")
        {
            throw new InvalidDataException("Enterprise QR request identity is invalid.");
        }

        EnterpriseBindingValidation.CanonicalizeUuid(
            request.InstallId,
            nameof(request.InstallId));
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            request.DeviceJwk.X,
            nameof(request.DeviceJwk.X),
            32);
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            request.DeviceJwk.Y,
            nameof(request.DeviceJwk.Y),
            32);
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            request.DeviceKeyThumbprint,
            nameof(request.DeviceKeyThumbprint),
            32);
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            request.Nonce,
            nameof(request.Nonce),
            32);
        var deviceDisplayName = ValidateCanonicalDeviceDisplayName(
            request.DeviceDisplayName,
            nameof(request.DeviceDisplayName));
        var requestIdentity = new EnterpriseDevicePublicIdentity(
            request.DeviceJwk.KeyType,
            request.DeviceJwk.Curve,
            request.DeviceJwk.X,
            request.DeviceJwk.Y,
            request.DeviceKeyThumbprint);
        EnterpriseBindingValidation.ValidateP256PublicIdentity(
            requestIdentity,
            nameof(request.DeviceJwk));
        var proofIdentity = _proofFactory.GetOrCreatePublicIdentity();
        EnterpriseBindingValidation.ValidateP256PublicIdentity(
            proofIdentity,
            "device_proof_key");
        if (!EnterpriseBindingValidation.MatchesPublicIdentity(requestIdentity, proofIdentity))
        {
            throw new InvalidDataException(
                "Enterprise QR request identity does not match the DPoP device key.");
        }

        ValidateReleaseVersion(request.LauncherVersion, nameof(request.LauncherVersion));
        ValidateReleaseVersion(request.RuntimeVersion, nameof(request.RuntimeVersion));
        if (!string.Equals(request.Platform, "windows-x64", StringComparison.Ordinal))
        {
            throw new InvalidDataException("Enterprise QR platform is unsupported.");
        }

        return deviceDisplayName;
    }

    private void ValidateCreatedSession(
        EnterpriseQrSessionCreateResponse session,
        string? expectedDeviceDisplayName)
    {
        EnterpriseBindingValidation.CanonicalizeUuid(
            session.SessionId,
            nameof(session.SessionId));
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            session.PollSecret,
            nameof(session.PollSecret),
            32);
        EnterpriseBindingValidation.ValidateCanonicalUtcSecond(
            session.ExpiresAtUtc,
            nameof(session.ExpiresAtUtc));
        var deviceDisplayName = ValidateCanonicalDeviceDisplayName(
            session.DeviceDisplayName,
            nameof(session.DeviceDisplayName));
        ValidateConfirmationCode(session.ConfirmationCode, nameof(session.ConfirmationCode));
        if (expectedDeviceDisplayName is not null
            && !string.Equals(
                deviceDisplayName,
                expectedDeviceDisplayName,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise QR session response changed the requested device display name.");
        }
        var nowUtc = _timeProvider.GetUtcNow();
        if (!_options.IsAllowedAuthorizationUrl(session.AuthorizationUrl)
            || session.PollAfterSeconds is < 2 or > 15)
        {
            throw new InvalidDataException("Enterprise QR session response violates the trust policy.");
        }
        // Keep all admission limits unchanged. Classify only otherwise-valid responses;
        // a local validity failure does not establish which clock or response is wrong.
        if (session.ExpiresAtUtc <= nowUtc)
        {
            throw new InvalidDataException(
                "Enterprise QR session response violates the trust policy.",
                new EnterpriseQrSessionValidityException(EnterpriseQrSessionValidityReason.Expired));
        }
        if (session.ExpiresAtUtc > nowUtc + MaximumQrSessionLifetime)
        {
            throw new InvalidDataException(
                "Enterprise QR session response violates the trust policy.",
                new EnterpriseQrSessionValidityException(EnterpriseQrSessionValidityReason.ExceedsLocalMaximum));
        }
    }

    private void ValidatePollResponse(
        EnterpriseQrSessionPollResponse response,
        string sessionId,
        EnterpriseEnrollmentAuthorizationMethod authorizationMethod)
    {
        ArgumentNullException.ThrowIfNull(response);
        var inProgress = response.Status is QrSessionState.Issued
            or QrSessionState.CallbackVerified
            or QrSessionState.EligibilityVerified;
        if (inProgress)
        {
            if (response.BindGrant is not null
                || response.BindingChallenge is not null
                || response.BindingChallengeExpiresAtUtc is not null
                || response.Error is not null
                || response.PollAfterSeconds is < 2 or > 15)
            {
                throw new InvalidDataException("In-progress QR response is inconsistent.");
            }

            return;
        }

        if (response.Status == QrSessionState.Approved)
        {
            if (response.Error is not null
                || response.PollAfterSeconds is not null
                || response.BindGrant is null
                || response.BindingChallenge is null
                || response.BindingChallengeExpiresAtUtc is null)
            {
                throw new InvalidDataException("Approved QR response is missing its binding grant contract.");
            }

            EnterpriseBindingValidation.CanonicalizeUuid(sessionId, nameof(sessionId));
            EnterpriseBindingValidation.ValidateCanonicalBase64Url(
                response.BindGrant,
                nameof(response.BindGrant),
                32);
            EnterpriseBindingValidation.ValidateCanonicalBase64Url(
                response.BindingChallenge,
                nameof(response.BindingChallenge),
                32);
            if (string.Equals(
                    response.BindGrant,
                    response.BindingChallenge,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Approved QR response must use distinct grant and challenge values.");
            }

            var expiresAtUtc = response.BindingChallengeExpiresAtUtc.Value;
            var nowUtc = _timeProvider.GetUtcNow();
            if (expiresAtUtc.Offset != TimeSpan.Zero
                || expiresAtUtc.Ticks % TimeSpan.TicksPerSecond != 0
                || expiresAtUtc <= nowUtc
                || expiresAtUtc > nowUtc + MaximumBindingChallengeLifetime)
            {
                throw new InvalidDataException(
                    "Approved QR response has an invalid binding challenge lifetime.");
            }

            return;
        }

        if (response.BindGrant is not null
            || response.BindingChallenge is not null
            || response.BindingChallengeExpiresAtUtc is not null
            || response.Error is null
            || response.PollAfterSeconds is not null)
        {
            throw new InvalidDataException("Terminal QR response is missing a known stable error.");
        }

        ValidateQrTerminalError(response.Status, response.Error, authorizationMethod);
    }

    private static async Task ThrowIfErrorAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if ((int)response.StatusCode is >= 300 and < 400)
        {
            throw new HttpRequestException(
                "Enterprise control plane redirects are forbidden.",
                inner: null,
                response.StatusCode);
        }

        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var envelope = await ReadJsonAsync<EnterpriseErrorEnvelope>(response, cancellationToken)
            .ConfigureAwait(false);
        ValidateQrError(envelope.Error);

        throw new EnterpriseControlPlaneException(envelope.Error);
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
            && !string.Equals(finalUri.AbsoluteUri, requestUri.AbsoluteUri, StringComparison.Ordinal))
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

    private static async Task EnsureEmptySuccessContentAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentType is not null
            || response.Content.Headers.ContentLength is > 0)
        {
            throw new InvalidDataException(
                "Enterprise activation claim response must be empty 204 No Content.");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        var probe = new byte[1];
        try
        {
            if (await stream.ReadAsync(probe, cancellationToken).ConfigureAwait(false) != 0)
            {
                throw new InvalidDataException(
                    "Enterprise activation claim response must be empty 204 No Content.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(probe);
        }
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

    private static void ValidateQrError(EnterpriseApiError error)
    {
        ArgumentNullException.ThrowIfNull(error);
        if (!AllowedQrErrorCodes.Contains(error.Code)
            || error.ResetScope != EnterpriseResetScope.None
            || error.ClientState is EnterpriseClientState.Ready or EnterpriseClientState.OfflineGrace)
        {
            throw new InvalidDataException("Enterprise control plane returned an untrusted QR error contract.");
        }

        ValidateBoundedText(error.RequestId, nameof(error.RequestId), 1, 128);
        ValidateBoundedText(error.Message, nameof(error.Message), 1, 512);
        if (error.ContactDisplay is not null)
        {
            ValidateBoundedText(error.ContactDisplay, nameof(error.ContactDisplay), 1, 128);
        }
    }

    private static void ValidateQrTerminalError(
        QrSessionState status,
        EnterpriseApiError error,
        EnterpriseEnrollmentAuthorizationMethod authorizationMethod)
    {
        var expected = (status, authorizationMethod) switch
        {
            (QrSessionState.Consumed, _) => (
                EnterpriseErrorCodes.QrSessionConsumed,
                EnterpriseClientState.QrRequired,
                Retryable: false),
            (QrSessionState.Expired, _) => (
                EnterpriseErrorCodes.QrSessionExpired,
                EnterpriseClientState.QrRequired,
                Retryable: true),
            (QrSessionState.Cancelled, _) => (
                EnterpriseErrorCodes.QrSessionCancelled,
                EnterpriseClientState.QrRequired,
                Retryable: true),
            (QrSessionState.DeniedNotPreregistered,
                EnterpriseEnrollmentAuthorizationMethod.AdminInvite) => (
                EnterpriseErrorCodes.EnrollmentActivationInvalid,
                EnterpriseClientState.QrRequired,
                Retryable: false),
            (QrSessionState.DeniedNotPreregistered,
                EnterpriseEnrollmentAuthorizationMethod.WeCom) => (
                EnterpriseErrorCodes.WeComIdentityNotPreregistered,
                EnterpriseClientState.QrRequired,
                Retryable: false),
            (QrSessionState.DeniedEmployeeSuspended, _) => (
                EnterpriseErrorCodes.EmployeeSuspended,
                EnterpriseClientState.AccountLocked,
                Retryable: false),
            (QrSessionState.DeniedEmployeeRevoked, _) => (
                EnterpriseErrorCodes.EmployeeRevoked,
                EnterpriseClientState.AccountLocked,
                Retryable: false),
            (QrSessionState.DeniedAlreadyBound, _) => (
                EnterpriseErrorCodes.DeviceAlreadyBound,
                EnterpriseClientState.QrRequired,
                Retryable: false),
            (QrSessionState.DeniedEnterpriseMemberRequired,
                EnterpriseEnrollmentAuthorizationMethod.WeCom) => (
                EnterpriseErrorCodes.WeComEnterpriseMemberRequired,
                EnterpriseClientState.QrRequired,
                Retryable: false),
            (QrSessionState.DeniedEnterpriseMemberRequired,
                EnterpriseEnrollmentAuthorizationMethod.AdminInvite) => (
                EnterpriseErrorCodes.EnrollmentActivationInvalid,
                EnterpriseClientState.QrRequired,
                Retryable: false),
            (QrSessionState.DeniedEntitlementMissing, _) => (
                EnterpriseErrorCodes.EmployeeEntitlementMissing,
                EnterpriseClientState.QrRequired,
                Retryable: false),
            (QrSessionState.DeniedUserRejected, _) => (
                EnterpriseErrorCodes.DeviceConfirmationRejected,
                EnterpriseClientState.QrRequired,
                Retryable: true),
            _ => throw new InvalidDataException(
                "Enterprise QR response is not a recognized terminal state."),
        };

        ValidateQrError(error);
        if (!string.Equals(error.Code, expected.Item1, StringComparison.Ordinal)
            || error.ClientState != expected.Item2
            || error.Retryable != expected.Retryable)
        {
            throw new InvalidDataException(
                "Enterprise QR terminal status and error tuple do not match.");
        }
    }

    private static void ValidateOpaqueToken(
        string value,
        string parameterName,
        int minimumLength,
        int maximumLength)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length < minimumLength
            || value.Length > maximumLength
            || value.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '-' and not '_'))
        {
            throw new InvalidDataException($"{parameterName} is not a canonical opaque token.");
        }
    }

    private static void ValidateBoundedText(
        string value,
        string parameterName,
        int minimumLength,
        int maximumLength)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length < minimumLength
            || value.Length > maximumLength
            || value.Any(char.IsControl))
        {
            throw new InvalidDataException($"{parameterName} is not valid bounded text.");
        }
    }

    private static void ValidateReleaseVersion(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length > 64
            || !char.IsAsciiLetterOrDigit(value[0])
            || value.Skip(1).Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '.' and not '_' and not '+' and not '-'))
        {
            throw new InvalidDataException(
                $"{parameterName} does not match the enterprise release-version contract.");
        }
    }

    private static string ValidateCanonicalDeviceDisplayName(
        string value,
        string parameterName)
    {
        try
        {
            var normalized = EnterpriseQrProtocol.NormalizeDeviceDisplayName(value);
            if (!string.Equals(normalized, value, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"{parameterName} is not a canonical enterprise device display name.");
            }

            return normalized;
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException(
                $"{parameterName} is not a valid enterprise device display name.",
                exception);
        }
    }

    private static void ValidateConfirmationCode(string value, string parameterName)
    {
        try
        {
            EnterpriseQrProtocol.ValidateConfirmationCode(value);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException(
                $"{parameterName} is not a valid enterprise device confirmation code.",
                exception);
        }
    }
}
