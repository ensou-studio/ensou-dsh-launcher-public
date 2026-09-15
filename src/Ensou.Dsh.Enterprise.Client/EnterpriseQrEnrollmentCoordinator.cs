using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Contracts;

namespace Ensou.Dsh.Enterprise.Client;

public interface IEnterpriseSystemBrowser
{
    void Open(Uri authorizationUrl);
}

public sealed class EnterpriseEnrollmentMethodConflictException : InvalidOperationException
{
    public EnterpriseEnrollmentMethodConflictException(
        EnterpriseEnrollmentAuthorizationMethod activeMethod,
        EnterpriseEnrollmentAuthorizationMethod requestedMethod)
        : base("A different enterprise enrollment method already has an unfinished session.")
    {
        ActiveMethod = activeMethod;
        RequestedMethod = requestedMethod;
    }

    public EnterpriseEnrollmentAuthorizationMethod ActiveMethod { get; }

    public EnterpriseEnrollmentAuthorizationMethod RequestedMethod { get; }
}

public sealed record EnterpriseQrEnrollmentProgress(
    QrSessionState State,
    EnterpriseEnrollmentAuthorizationMethod AuthorizationMethod,
    DateTimeOffset ExpiresAtUtc,
    string DeviceDisplayName,
    string ConfirmationCode)
{
    public override string ToString() =>
        $"QR enrollment progress {State}, expires {ExpiresAtUtc:O}";
}

public sealed class EnterpriseQrEnrollmentOutcome
{
    private EnterpriseQrEnrollmentOutcome(
        QrSessionState state,
        EnterpriseBindingChallenge? bindingChallenge,
        EnterpriseBindingCompletionResult? bindingCompletion,
        EnterpriseApiError? error)
    {
        State = state;
        BindingChallenge = bindingChallenge;
        BindingCompletion = bindingCompletion;
        Error = error;
    }

    public QrSessionState State { get; }

    public EnterpriseBindingChallenge? BindingChallenge { get; }

    public string? BindGrant => BindingChallenge?.BindGrant;

    public EnterpriseBindingCompletionResult? BindingCompletion { get; }

    public bool BindingCompleted => BindingCompletion is not null;

    public EnterpriseApiError? Error { get; }

    public bool IdentityApproved => State == QrSessionState.Approved;

    public static EnterpriseQrEnrollmentOutcome Approved(
        EnterpriseBindingChallenge bindingChallenge)
    {
        ArgumentNullException.ThrowIfNull(bindingChallenge);
        return new EnterpriseQrEnrollmentOutcome(
            QrSessionState.Approved,
            bindingChallenge,
            bindingCompletion: null,
            error: null);
    }

    public static EnterpriseQrEnrollmentOutcome Bound(
        EnterpriseBindingChallenge? bindingChallenge,
        EnterpriseBindingCompletionResult bindingCompletion)
    {
        ArgumentNullException.ThrowIfNull(bindingCompletion);
        return new EnterpriseQrEnrollmentOutcome(
            QrSessionState.Approved,
            bindingChallenge,
            bindingCompletion,
            error: null);
    }

    public static EnterpriseQrEnrollmentOutcome Denied(
        QrSessionState state,
        EnterpriseApiError error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return new EnterpriseQrEnrollmentOutcome(
            state,
            bindingChallenge: null,
            bindingCompletion: null,
            error);
    }

    public override string ToString() => $"QR enrollment outcome {State}";
}

public sealed class EnterpriseQrEnrollmentCoordinator
{
    private static readonly JsonSerializerOptions SessionJson = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly EnterpriseDeviceEnrollmentPreparation _devicePreparation;
    private readonly IEnterpriseQrEnrollmentClient _client;
    private readonly EnterpriseProtectedArtifactStore _protectedStore;
    private readonly IEnterpriseSystemBrowser? _systemBrowser;
    private readonly EnterpriseHarnessSession _harnessSession;
    private readonly IEnterpriseDeviceBindingWorkflow? _bindingWorkflow;
    private readonly TimeProvider _timeProvider;
    private readonly string _launcherVersion;
    private readonly string _runtimeVersion;
    private readonly string _platform;
    private readonly string _deviceLabel;
    private readonly SemaphoreSlim _beginGate = new(1, 1);

    public EnterpriseQrEnrollmentCoordinator(
        EnterpriseDeviceEnrollmentPreparation devicePreparation,
        IEnterpriseQrEnrollmentClient client,
        EnterpriseProtectedArtifactStore protectedStore,
        EnterpriseHarnessSession harnessSession,
        string launcherVersion,
        string runtimeVersion,
        string platform,
        TimeProvider? timeProvider = null,
        IEnterpriseDeviceBindingWorkflow? bindingWorkflow = null,
        string deviceLabel = "Ensou DSH device",
        IEnterpriseSystemBrowser? systemBrowser = null)
    {
        _devicePreparation = devicePreparation
            ?? throw new ArgumentNullException(nameof(devicePreparation));
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _protectedStore = protectedStore ?? throw new ArgumentNullException(nameof(protectedStore));
        _systemBrowser = systemBrowser;
        _harnessSession = harnessSession ?? throw new ArgumentNullException(nameof(harnessSession));
        _launcherVersion = ValidateVersion(launcherVersion, nameof(launcherVersion));
        _runtimeVersion = ValidateVersion(runtimeVersion, nameof(runtimeVersion));
        _platform = ValidateVersion(platform, nameof(platform));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _bindingWorkflow = bindingWorkflow;
        _deviceLabel = EnterpriseQrProtocol.NormalizeDeviceDisplayName(deviceLabel);
        EnterpriseBindingValidation.ValidateDeviceLabel(_deviceLabel, nameof(deviceLabel));
    }

    public async Task<EnterpriseQrEnrollmentOutcome> BeginAsync(
        string activationCode,
        IProgress<EnterpriseQrEnrollmentProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        EnterpriseQrProtocol.ValidateActivationCode(activationCode);
        await _beginGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await BeginCoreAsync(activationCode, progress, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _beginGate.Release();
        }
    }

    public async Task<EnterpriseQrEnrollmentOutcome> BeginWithWeComAsync(
        IProgress<EnterpriseQrEnrollmentProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (_systemBrowser is null)
        {
            throw new InvalidOperationException(
                "Enterprise WeCom enrollment requires the trusted system-browser adapter.");
        }

        await _beginGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await BeginCoreAsync(
                    activationCode: null,
                    progress,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _beginGate.Release();
        }
    }

    private async Task<EnterpriseQrEnrollmentOutcome> BeginCoreAsync(
        string? activationCode,
        IProgress<EnterpriseQrEnrollmentProgress>? progress,
        CancellationToken cancellationToken)
    {
        var enrollmentMethod = activationCode is null
            ? EnterpriseEnrollmentAuthorizationMethod.WeCom
            : EnterpriseEnrollmentAuthorizationMethod.AdminInvite;
        var device = await _devicePreparation.PrepareAsync(cancellationToken)
            .ConfigureAwait(false);
        if (_bindingWorkflow is not null)
        {
            try
            {
                var resumed = await _bindingWorkflow.TryResumeAsync(device, cancellationToken)
                    .ConfigureAwait(false);
                if (resumed is not null)
                {
                    TryDeleteEnrollmentSession();
                    return EnterpriseQrEnrollmentOutcome.Bound(
                        bindingChallenge: null,
                        resumed);
                }
            }
            catch (EnterpriseControlPlaneException exception)
            {
                await ApplyTerminalStateAsync(exception.Error, CancellationToken.None)
                    .ConfigureAwait(false);
                throw;
            }
        }

        var persisted = await ReadPersistedSessionAsync(
                device,
                enrollmentMethod,
                cancellationToken)
            .ConfigureAwait(false);
        if (persisted is not null && _timeProvider.GetUtcNow() >= persisted.Session.ExpiresAtUtc)
        {
            _protectedStore.Delete(EnterpriseManagedArtifact.EnrollmentSessionDpapi);
            await RestoreQrRequiredAsync(cancellationToken).ConfigureAwait(false);
            persisted = null;
        }

        var resumedSession = persisted is not null;
        EnterpriseQrSessionCreateResponse created;
        string nonce;
        if (persisted is not null)
        {
            created = persisted.Session;
            nonce = persisted.Nonce;
        }
        else
        {
            nonce = CreateOpaqueSecret();
            var request = new EnterpriseQrSessionCreateRequest
            {
                AuthorizationMethod = enrollmentMethod,
                InstallId = device.Installation.InstallId.ToString("D"),
                DeviceJwk = new EnterpriseEcPublicJwk
                {
                    KeyType = device.DeviceKey.KeyType,
                    Curve = device.DeviceKey.Curve,
                    X = device.DeviceKey.X,
                    Y = device.DeviceKey.Y,
                },
                DeviceKeyThumbprint = device.DeviceKey.Thumbprint,
                DeviceDisplayName = _deviceLabel,
                LauncherVersion = _launcherVersion,
                RuntimeVersion = _runtimeVersion,
                Platform = _platform,
                Nonce = nonce,
            };
            created = await _client.CreateSessionAsync(
                    request,
                    CreateOpaqueSecret(),
                    cancellationToken)
                .ConfigureAwait(false);

            await PersistSessionAsync(
                    created,
                    nonce,
                    device,
                    enrollmentMethod,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        try
        {
            await _harnessSession.ApplyAccessAsync(
                    EnterpriseStartupGate.CreateEnrollmentPendingSnapshot(),
                    cancellationToken)
                .ConfigureAwait(false);

            var pollAfterSeconds = created.PollAfterSeconds;
            EnterpriseQrSessionPollResponse? response;
            if (resumedSession)
            {
                response = await _client.PollSessionAsync(
                        created,
                        nonce,
                        enrollmentMethod,
                        cancellationToken)
                    .ConfigureAwait(false);
                ReportProgress(progress, created, enrollmentMethod, response.Status);
                if (response.Status == QrSessionState.Issued
                    && enrollmentMethod == EnterpriseEnrollmentAuthorizationMethod.AdminInvite)
                {
                    pollAfterSeconds = response.PollAfterSeconds!.Value;
                    response = await ClaimWithAmbiguousResponseRecoveryAsync(
                            created,
                            nonce,
                            activationCode!,
                            enrollmentMethod,
                            cancellationToken)
                        .ConfigureAwait(false);
                    if (response is not null)
                    {
                        ReportProgress(progress, created, enrollmentMethod, response.Status);
                    }
                }
                else if (response.Status == QrSessionState.Issued)
                {
                    _systemBrowser!.Open(created.AuthorizationUrl);
                    response = null;
                }
            }
            else if (enrollmentMethod == EnterpriseEnrollmentAuthorizationMethod.AdminInvite)
            {
                ReportProgress(
                    progress,
                    created,
                    enrollmentMethod,
                    QrSessionState.Issued);
                response = await ClaimWithAmbiguousResponseRecoveryAsync(
                        created,
                        nonce,
                        activationCode!,
                        enrollmentMethod,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (response is not null)
                {
                    ReportProgress(progress, created, enrollmentMethod, response.Status);
                }
            }
            else
            {
                ReportProgress(
                    progress,
                    created,
                    enrollmentMethod,
                    QrSessionState.Issued);
                _systemBrowser!.Open(created.AuthorizationUrl);
                response = null;
            }

            while (true)
            {
                if (response is null)
                {
                    var nowUtc = _timeProvider.GetUtcNow();
                    if (nowUtc >= created.ExpiresAtUtc)
                    {
                        return await ExpireSessionAsync(cancellationToken).ConfigureAwait(false);
                    }

                    var delay = TimeSpan.FromSeconds(pollAfterSeconds);
                    if (nowUtc + delay > created.ExpiresAtUtc)
                    {
                        delay = created.ExpiresAtUtc - nowUtc;
                    }

                    await Task.Delay(delay, _timeProvider, cancellationToken).ConfigureAwait(false);
                    if (_timeProvider.GetUtcNow() >= created.ExpiresAtUtc)
                    {
                        return await ExpireSessionAsync(cancellationToken).ConfigureAwait(false);
                    }

                    response = await _client.PollSessionAsync(
                            created,
                            nonce,
                            enrollmentMethod,
                            cancellationToken)
                        .ConfigureAwait(false);
                    ReportProgress(progress, created, enrollmentMethod, response.Status);
                }

                if (response.Status is QrSessionState.Issued
                    or QrSessionState.CallbackVerified
                    or QrSessionState.EligibilityVerified)
                {
                    pollAfterSeconds = response.PollAfterSeconds!.Value;
                    response = null;
                    continue;
                }

                if (response.Status == QrSessionState.Approved)
                {
                    var bindingChallenge = response.ToBindingChallenge(created.SessionId);
                    var canonicalPayload = EnterpriseBindingPayloadBuilder.Build(
                        bindingChallenge,
                        device.Installation.InstallId.ToString("D"),
                        device.DeviceKey.Thumbprint);
                    CryptographicOperations.ZeroMemory(canonicalPayload);
                    if (_bindingWorkflow is null)
                    {
                        _protectedStore.Delete(EnterpriseManagedArtifact.EnrollmentSessionDpapi);
                        return EnterpriseQrEnrollmentOutcome.Approved(bindingChallenge);
                    }

                    var binding = await _bindingWorkflow.CompleteAsync(
                            bindingChallenge,
                            device,
                            _deviceLabel,
                            cancellationToken)
                        .ConfigureAwait(false);
                    TryDeleteEnrollmentSession();
                    return EnterpriseQrEnrollmentOutcome.Bound(bindingChallenge, binding);
                }

                _protectedStore.Delete(EnterpriseManagedArtifact.EnrollmentSessionDpapi);
                await ApplyTerminalStateAsync(response.Error!, cancellationToken)
                    .ConfigureAwait(false);
                return EnterpriseQrEnrollmentOutcome.Denied(response.Status, response.Error!);
            }
        }
        catch (EnterpriseBindingRecoveryRequiredException)
        {
            await _harnessSession.ApplyAccessAsync(
                    EnterpriseStartupGate.CreateEnrollmentPendingSnapshot(),
                    CancellationToken.None)
                .ConfigureAwait(false);
            throw;
        }
        catch
        {
            await RestoreQrRequiredAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    private async Task<EnterpriseQrSessionPollResponse?> ClaimWithAmbiguousResponseRecoveryAsync(
        EnterpriseQrSessionCreateResponse session,
        string nonce,
        string activationCode,
        EnterpriseEnrollmentAuthorizationMethod authorizationMethod,
        CancellationToken cancellationToken)
    {
        try
        {
            await _client.ClaimActivationAsync(
                    session,
                    nonce,
                    activationCode,
                    cancellationToken)
                .ConfigureAwait(false);
            return null;
        }
        catch (Exception exception) when (
            exception is HttpRequestException
            || exception is OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            var recovered = await _client.PollSessionAsync(
                    session,
                    nonce,
                    authorizationMethod,
                    cancellationToken)
                .ConfigureAwait(false);
            if (recovered.Status == QrSessionState.Issued)
            {
                throw;
            }

            return recovered;
        }
    }

    private async Task<EnterpriseQrEnrollmentOutcome> ExpireSessionAsync(
        CancellationToken cancellationToken)
    {
        _protectedStore.Delete(EnterpriseManagedArtifact.EnrollmentSessionDpapi);
        await RestoreQrRequiredAsync(cancellationToken).ConfigureAwait(false);
        return EnterpriseQrEnrollmentOutcome.Denied(
            QrSessionState.Expired,
            CreateLocalTerminalError(
                EnterpriseErrorCodes.QrSessionExpired,
                "企业设备激活已过期，请重新开始。"));
    }

    private async Task PersistSessionAsync(
        EnterpriseQrSessionCreateResponse session,
        string nonce,
        EnterpriseEnrollmentDeviceContext device,
        EnterpriseEnrollmentAuthorizationMethod enrollmentMethod,
        CancellationToken cancellationToken)
    {
        var document = new PersistedEnrollmentSession
        {
            SchemaVersion = 2,
            EnrollmentMethod = ToWireValue(enrollmentMethod),
            InstallId = device.Installation.InstallId.ToString("D"),
            DeviceKeyThumbprint = device.DeviceKey.Thumbprint,
            SessionId = session.SessionId,
            PollSecret = session.PollSecret,
            Nonce = nonce,
            AuthorizationUrl = session.AuthorizationUrl.AbsoluteUri,
            DeviceDisplayName = session.DeviceDisplayName,
            ConfirmationCode = session.ConfirmationCode,
            ExpiresAtUtc = session.ExpiresAtUtc,
            PollAfterSeconds = session.PollAfterSeconds,
        };
        var bytes = JsonSerializer.SerializeToUtf8Bytes(document, SessionJson);
        try
        {
            await _protectedStore.WriteAsync(
                    EnterpriseManagedArtifact.EnrollmentSessionDpapi,
                    bytes,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private async Task<ResumableEnrollmentSession?> ReadPersistedSessionAsync(
        EnterpriseEnrollmentDeviceContext device,
        EnterpriseEnrollmentAuthorizationMethod expectedMethod,
        CancellationToken cancellationToken)
    {
        var bytes = await _protectedStore.ReadAsync(
                EnterpriseManagedArtifact.EnrollmentSessionDpapi,
                cancellationToken)
            .ConfigureAwait(false);
        if (bytes is null)
        {
            return null;
        }

        try
        {
            PersistedEnrollmentSession document;
            try
            {
                document = JsonSerializer.Deserialize<PersistedEnrollmentSession>(
                        bytes,
                        SessionJson)
                    ?? throw new InvalidDataException(
                        "Enterprise enrollment journal is empty.");
            }
            catch (JsonException exception)
            {
                throw new InvalidDataException(
                    "Enterprise enrollment journal is malformed.",
                    exception);
            }

            if (document.SchemaVersion is not (1 or 2))
            {
                throw new InvalidDataException(
                    "Enterprise enrollment journal schema is unsupported.");
            }

            var persistedMethod = document.SchemaVersion == 1
                ? EnterpriseEnrollmentAuthorizationMethod.AdminInvite
                : ParseEnrollmentMethod(document.EnrollmentMethod);
            EnterpriseBindingValidation.ValidateCanonicalUtcSecond(
                document.ExpiresAtUtc,
                "enrollment_session.expires_at");
            if (_timeProvider.GetUtcNow() >= document.ExpiresAtUtc)
            {
                _protectedStore.Delete(EnterpriseManagedArtifact.EnrollmentSessionDpapi);
                return null;
            }

            if (persistedMethod != expectedMethod)
            {
                throw new EnterpriseEnrollmentMethodConflictException(
                    persistedMethod,
                    expectedMethod);
            }

            return ValidatePersistedSession(document, device, persistedMethod);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static ResumableEnrollmentSession ValidatePersistedSession(
        PersistedEnrollmentSession document,
        EnterpriseEnrollmentDeviceContext device,
        EnterpriseEnrollmentAuthorizationMethod enrollmentMethod)
    {
        if (document.SchemaVersion is not (1 or 2))
        {
            throw new InvalidDataException(
                "Enterprise enrollment journal schema is unsupported.");
        }

        var installIdValue = RequirePersistedValue(
            document.InstallId,
            "enrollment_session.install_id");
        var deviceKeyThumbprint = RequirePersistedValue(
            document.DeviceKeyThumbprint,
            "enrollment_session.device_key_thumbprint");
        var deviceDisplayNameValue = RequirePersistedValue(
            document.DeviceDisplayName,
            "enrollment_session.device_display_name");
        var confirmationCode = RequirePersistedValue(
            document.ConfirmationCode,
            "enrollment_session.confirmation_code");
        var installId = EnterpriseBindingValidation.CanonicalizeUuid(
            installIdValue,
            "enrollment_session.install_id");
        var expectedInstallId = device.Installation.InstallId.ToString("D");
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            deviceKeyThumbprint,
            "enrollment_session.device_key_thumbprint",
            32);
        if (!string.Equals(installId, expectedInstallId, StringComparison.Ordinal)
            || !string.Equals(
                deviceKeyThumbprint,
                device.DeviceKey.Thumbprint,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise enrollment journal belongs to a different installation or device key.");
        }

        EnterpriseBindingValidation.CanonicalizeUuid(
            document.SessionId,
            "enrollment_session.session_id");
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            document.PollSecret,
            "enrollment_session.poll_secret",
            32);
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            document.Nonce,
            "enrollment_session.nonce",
            32);
        EnterpriseBindingValidation.ValidateCanonicalUtcSecond(
            document.ExpiresAtUtc,
            "enrollment_session.expires_at");
        if (document.PollAfterSeconds is < 2 or > 15)
        {
            throw new InvalidDataException(
                "Enterprise enrollment journal polling interval is invalid.");
        }

        if (!Uri.TryCreate(document.AuthorizationUrl, UriKind.Absolute, out var authorizationUrl)
            || !string.Equals(
                authorizationUrl.AbsoluteUri,
                document.AuthorizationUrl,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise enrollment journal authorization URL is invalid.");
        }

        var deviceDisplayName = EnterpriseQrProtocol.NormalizeDeviceDisplayName(
            deviceDisplayNameValue);
        if (!string.Equals(
            deviceDisplayName,
            deviceDisplayNameValue,
            StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise enrollment journal device label is not canonical.");
        }

        EnterpriseQrProtocol.ValidateConfirmationCode(confirmationCode);
        return new ResumableEnrollmentSession(
            new EnterpriseQrSessionCreateResponse
            {
                SessionId = document.SessionId,
                PollSecret = document.PollSecret,
                AuthorizationUrl = authorizationUrl,
                DeviceDisplayName = deviceDisplayNameValue,
                ConfirmationCode = confirmationCode,
                ExpiresAtUtc = document.ExpiresAtUtc,
                PollAfterSeconds = document.PollAfterSeconds,
            },
            document.Nonce,
            enrollmentMethod);
    }

    private static string ToWireValue(EnterpriseEnrollmentAuthorizationMethod value) =>
        EnterpriseEnrollmentAuthorizationMethodContract.ToWireValue(value);

    private static EnterpriseEnrollmentAuthorizationMethod ParseEnrollmentMethod(string? value)
    {
        try
        {
            return EnterpriseEnrollmentAuthorizationMethodContract.ParseWireValue(
                value ?? string.Empty);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException(
                "Enterprise enrollment journal method is invalid.",
                exception);
        }
    }

    private static string RequirePersistedValue(string? value, string fieldName)
    {
        if (value is null)
        {
            throw new InvalidDataException(
                $"Enterprise enrollment journal is missing {fieldName}.");
        }

        return value;
    }

    private static void ReportProgress(
        IProgress<EnterpriseQrEnrollmentProgress>? progress,
        EnterpriseQrSessionCreateResponse session,
        EnterpriseEnrollmentAuthorizationMethod authorizationMethod,
        QrSessionState state) =>
        progress?.Report(new EnterpriseQrEnrollmentProgress(
            state,
            authorizationMethod,
            session.ExpiresAtUtc,
            session.DeviceDisplayName,
            session.ConfirmationCode));

    private Task<EnterpriseAccessDecision> RestoreQrRequiredAsync(
        CancellationToken cancellationToken) =>
        _harnessSession.ApplyAccessAsync(
            EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot(),
            cancellationToken);

    private Task<EnterpriseAccessDecision> ApplyTerminalStateAsync(
        EnterpriseApiError error,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(error);
        var snapshot = error.ClientState switch
        {
            EnterpriseClientState.QrRequired =>
                EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot(),
            EnterpriseClientState.AccountLocked when
                error.Code == EnterpriseErrorCodes.EmployeeSuspended =>
                EnterpriseStartupGate.CreateEnrollmentAccountLockedSnapshot(
                    EmployeeAuthorizationState.Suspended),
            EnterpriseClientState.AccountLocked when
                error.Code == EnterpriseErrorCodes.EmployeeRevoked =>
                EnterpriseStartupGate.CreateEnrollmentAccountLockedSnapshot(
                    EmployeeAuthorizationState.Revoked),
            _ => throw new InvalidDataException(
                "Enterprise QR terminal response cannot be applied to the client state."),
        };

        return _harnessSession.ApplyAccessAsync(snapshot, cancellationToken);
    }

    private static string CreateOpaqueSecret() => Base64UrlEncode(
        RandomNumberGenerator.GetBytes(32));

    private bool TryDeleteEnrollmentSession()
    {
        try
        {
            _protectedStore.Delete(EnterpriseManagedArtifact.EnrollmentSessionDpapi);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static string ValidateVersion(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length > 64 || value.Any(char.IsControl))
        {
            throw new ArgumentException("Enterprise build value is invalid.", parameterName);
        }

        return value;
    }

    private static EnterpriseApiError CreateLocalTerminalError(string code, string message) => new()
    {
        Code = code,
        Message = message,
        ClientState = EnterpriseClientState.QrRequired,
        Retryable = true,
        ContactDisplay = null,
        RequestId = "LOCAL-QR-EXPIRY",
        ResetScope = EnterpriseResetScope.None,
    };

    private sealed class PersistedEnrollmentSession
    {
        [JsonPropertyName("schema_version")]
        public required int SchemaVersion { get; init; }

        [JsonPropertyName("enrollment_method")]
        public string? EnrollmentMethod { get; init; }

        [JsonPropertyName("install_id")]
        public string? InstallId { get; init; }

        [JsonPropertyName("device_key_thumbprint")]
        public string? DeviceKeyThumbprint { get; init; }

        [JsonPropertyName("session_id")]
        public required string SessionId { get; init; }

        [JsonPropertyName("poll_secret")]
        public required string PollSecret { get; init; }

        [JsonPropertyName("nonce")]
        public required string Nonce { get; init; }

        [JsonPropertyName("authorization_url")]
        public required string AuthorizationUrl { get; init; }

        [JsonPropertyName("device_display_name")]
        public string? DeviceDisplayName { get; init; }

        [JsonPropertyName("confirmation_code")]
        public string? ConfirmationCode { get; init; }

        [JsonPropertyName("expires_at")]
        public required DateTimeOffset ExpiresAtUtc { get; init; }

        [JsonPropertyName("poll_after_seconds")]
        public required int PollAfterSeconds { get; init; }
    }

    private sealed record ResumableEnrollmentSession(
        EnterpriseQrSessionCreateResponse Session,
        string Nonce,
        EnterpriseEnrollmentAuthorizationMethod EnrollmentMethod);
}
