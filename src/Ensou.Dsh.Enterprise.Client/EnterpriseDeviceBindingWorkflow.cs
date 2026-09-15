using System.Security.Cryptography;
using Ensou.Dsh.Enterprise.Contracts;

namespace Ensou.Dsh.Enterprise.Client;

public interface IEnterpriseDeviceBindingWorkflow
{
    Task<EnterpriseBindingCompletionResult> CompleteAsync(
        EnterpriseBindingChallenge challenge,
        EnterpriseEnrollmentDeviceContext device,
        string deviceLabel,
        CancellationToken cancellationToken = default);

    Task<EnterpriseBindingCompletionResult?> TryResumeAsync(
        EnterpriseEnrollmentDeviceContext device,
        CancellationToken cancellationToken = default);
}

public sealed class EnterpriseBindingCompletionResult
{
    internal EnterpriseBindingCompletionResult(
        string bindingId,
        DateTimeOffset accessTokenExpiresAtUtc,
        DateTimeOffset leaseExpiresAtUtc,
        EnterpriseAccessDecision accessDecision,
        bool recoveryJournalCleared)
    {
        BindingId = bindingId;
        AccessTokenExpiresAtUtc = accessTokenExpiresAtUtc;
        LeaseExpiresAtUtc = leaseExpiresAtUtc;
        AccessDecision = accessDecision;
        RecoveryJournalCleared = recoveryJournalCleared;
    }

    public string BindingId { get; }

    public DateTimeOffset AccessTokenExpiresAtUtc { get; }

    public DateTimeOffset LeaseExpiresAtUtc { get; }

    public EnterpriseAccessDecision AccessDecision { get; }

    public bool RecoveryJournalCleared { get; }

    public override string ToString() => "Enterprise binding completion [REDACTED]";
}

public sealed class EnterpriseDeviceBindingWorkflow : IEnterpriseDeviceBindingWorkflow
{
    private static readonly TimeSpan MaximumAccessTokenLifetime = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan MaximumBindingChallengeLifetime = TimeSpan.FromSeconds(60);
    private readonly IEnterpriseDeviceBindingReplayClient _client;
    private readonly IEnterpriseDeviceProofKeyStore _deviceKeyStore;
    private readonly EnterpriseAuthorizationLeaseVerifier _leaseVerifier;
    private readonly EnterpriseBindingCredentialStore _credentialStore;
    private readonly EnterprisePendingBindingTransactionStore _pendingStore;
    private readonly IEnterpriseAccessTokenVault _accessTokenVault;
    private readonly EnterpriseHarnessSession _harnessSession;
    private readonly IEnterpriseDeviceUpdateGate _deviceUpdateGate;
    private readonly TimeProvider _timeProvider;

    public EnterpriseDeviceBindingWorkflow(
        IEnterpriseDeviceBindingReplayClient client,
        IEnterpriseDeviceProofKeyStore deviceKeyStore,
        EnterpriseAuthorizationLeaseVerifier leaseVerifier,
        EnterpriseBindingCredentialStore credentialStore,
        EnterprisePendingBindingTransactionStore pendingStore,
        IEnterpriseAccessTokenVault accessTokenVault,
        EnterpriseHarnessSession harnessSession,
        IEnterpriseDeviceUpdateGate deviceUpdateGate,
        TimeProvider? timeProvider = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _deviceKeyStore = deviceKeyStore ?? throw new ArgumentNullException(nameof(deviceKeyStore));
        _leaseVerifier = leaseVerifier ?? throw new ArgumentNullException(nameof(leaseVerifier));
        _credentialStore = credentialStore ?? throw new ArgumentNullException(nameof(credentialStore));
        _pendingStore = pendingStore ?? throw new ArgumentNullException(nameof(pendingStore));
        _accessTokenVault = accessTokenVault
            ?? throw new ArgumentNullException(nameof(accessTokenVault));
        _harnessSession = harnessSession
            ?? throw new ArgumentNullException(nameof(harnessSession));
        _deviceUpdateGate = deviceUpdateGate
            ?? throw new ArgumentNullException(nameof(deviceUpdateGate));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _harnessSession.DecisionChanged += OnDecisionChanged;
    }

    public async Task<EnterpriseBindingCompletionResult> CompleteAsync(
        EnterpriseBindingChallenge challenge,
        EnterpriseEnrollmentDeviceContext device,
        string deviceLabel,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(device);
        ValidateFreshChallenge(challenge);
        await _harnessSession.ApplyAccessAsync(
                EnterpriseStartupGate.CreateEnrollmentPendingSnapshot(),
                cancellationToken)
            .ConfigureAwait(false);
        var installationId = device.Installation.InstallId.ToString("D");
        var request = EnterpriseBindingPayloadBuilder.CreateSignedRequest(
            challenge,
            installationId,
            device.DeviceKey.Thumbprint,
            deviceLabel,
            _deviceKeyStore);
        var exactRequestBody = EnterpriseDeviceBindingClient.SerializeExactRequest(request);
        try
        {
            var createdAtUtc = DateTimeOffset.FromUnixTimeSeconds(
                _timeProvider.GetUtcNow().ToUnixTimeSeconds());
            var idempotencyKey = EnterpriseBindingValidation.Base64UrlEncode(
                RandomNumberGenerator.GetBytes(32));
            try
            {
                await _pendingStore.WriteNewAsync(
                        exactRequestBody,
                        idempotencyKey,
                        createdAtUtc,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                throw new EnterpriseBindingRecoveryRequiredException(exception);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactRequestBody);
        }

        using var pending = await ReadPendingForRecoveryAsync(cancellationToken)
            .ConfigureAwait(false)
            ?? throw new EnterpriseBindingRecoveryRequiredException(
                new InvalidDataException(
                    "Enterprise pending binding transaction was not durably committed."));
        return await ExecutePendingAsync(pending, device, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<EnterpriseBindingCompletionResult?> TryResumeAsync(
        EnterpriseEnrollmentDeviceContext device,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        using var pending = await ReadPendingForRecoveryAsync(cancellationToken)
            .ConfigureAwait(false);
        if (pending is null)
        {
            return null;
        }

        await _harnessSession.ApplyAccessAsync(
                EnterpriseStartupGate.CreateEnrollmentPendingSnapshot(),
                cancellationToken)
            .ConfigureAwait(false);
        return await ExecutePendingAsync(pending, device, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<EnterpriseBindingCompletionResult> ExecutePendingAsync(
        EnterprisePendingBindingTransaction pending,
        EnterpriseEnrollmentDeviceContext device,
        CancellationToken cancellationToken)
    {
        var request = EnterpriseDeviceBindingClient.DeserializeExactRequest(
            pending.ExactRequestBody);
        var installationId = device.Installation.InstallId.ToString("D");
        if (!string.Equals(request.InstallId, installationId, StringComparison.Ordinal)
            || !string.Equals(
                request.DeviceKeyThumbprint,
                device.DeviceKey.Thumbprint,
                StringComparison.Ordinal))
        {
            throw new EnterpriseBindingRecoveryRequiredException(
                new InvalidDataException(
                    "Pending enterprise binding belongs to another installation or device key."));
        }

        EnterpriseDeviceBindingCompleteResponse response;
        try
        {
            response = await _client.CompleteExactAsync(
                    pending.ExactRequestBody,
                    pending.IdempotencyKey,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (EnterpriseControlPlaneException exception) when (IsDefinitiveNoCommit(exception.Error))
        {
            try
            {
                _pendingStore.Delete();
            }
            catch (Exception cleanupException)
            {
                throw new EnterpriseBindingRecoveryRequiredException(
                    new AggregateException(exception, cleanupException));
            }

            throw;
        }

        catch (Exception exception)
        {
            throw new EnterpriseBindingRecoveryRequiredException(exception);
        }

        try
        {
            var evaluationTimeUtc = ValidateResponseAndClock(response);
            var verifiedLease = _leaseVerifier.Verify(
                response.AuthorizationLease,
                new EnterpriseAuthorizationLeaseVerificationContext(
                    response.BindingId,
                    installationId,
                    device.DeviceKey.Thumbprint,
                    response.ServerTimeUtc,
                    response.ServerTimeUtc));
            ValidateSignedResponseConsistency(response, verifiedLease);
            var runtimeAccessSnapshot = verifiedLease.AccessSnapshot with
            {
                LeaseExpiresAtUtc = response.AccessTokenExpiresAtUtc,
            };
            var prospectiveDecision = EnterpriseAccessEvaluator.Evaluate(
                runtimeAccessSnapshot,
                evaluationTimeUtc);
            await _credentialStore.CommitOrConfirmAsync(
                    response,
                    verifiedLease,
                    cancellationToken)
                .ConfigureAwait(false);
            EnsureReadyDecision(prospectiveDecision);
            _accessTokenVault.Install(
                response.BindingId,
                response.AccessToken,
                response.AccessTokenExpiresAtUtc);
            if (!_accessTokenVault.HasUsableToken(response.BindingId, evaluationTimeUtc))
            {
                throw new InvalidDataException(
                    "Enterprise access token was not installed in the in-memory vault.");
            }

            runtimeAccessSnapshot = EnterpriseDeviceUpdateGate.ValidateGateResult(
                runtimeAccessSnapshot,
                await _deviceUpdateGate.EvaluateBeforeReadyAsync(
                        runtimeAccessSnapshot,
                        response.BindingId,
                        cancellationToken)
                    .ConfigureAwait(false));
            var appliedDecision = await _harnessSession.ApplyAccessAsync(
                    runtimeAccessSnapshot,
                    cancellationToken)
                .ConfigureAwait(false);
            EnsureGatedDecision(runtimeAccessSnapshot, appliedDecision, evaluationTimeUtc);
            if (!TryDeletePendingJournal())
            {
                await _harnessSession.ApplyAccessAsync(
                        EnterpriseStartupGate.CreateEnrollmentPendingSnapshot(),
                        CancellationToken.None)
                    .ConfigureAwait(false);
                throw new IOException(
                    "Enterprise pending binding transaction could not be cleared after commit.");
            }

            return new EnterpriseBindingCompletionResult(
                response.BindingId,
                response.AccessTokenExpiresAtUtc,
                response.LeaseExpiresAtUtc,
                appliedDecision,
                recoveryJournalCleared: true);
        }
        catch (Exception exception)
        {
            _accessTokenVault.Clear();
            throw new EnterpriseBindingRecoveryRequiredException(exception);
        }
    }

    private bool TryDeletePendingJournal()
    {
        try
        {
            _pendingStore.Delete();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private async Task<EnterprisePendingBindingTransaction?> ReadPendingForRecoveryAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            return await _pendingStore.ReadAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            throw new EnterpriseBindingRecoveryRequiredException(exception);
        }
    }

    private static bool IsDefinitiveNoCommit(EnterpriseApiError error) => error.Code is
        EnterpriseErrorCodes.QrStateInvalid
        or EnterpriseErrorCodes.DeviceProofInvalid
        or EnterpriseErrorCodes.EmployeeSuspended
        or EnterpriseErrorCodes.EmployeeRevoked
        or EnterpriseErrorCodes.EmployeeEntitlementMissing
        or EnterpriseErrorCodes.DeviceReplacementNotAuthorized
        or EnterpriseErrorCodes.ApiProfileUnassigned
        or EnterpriseErrorCodes.ApiProfileDisabled
        or EnterpriseErrorCodes.QrSessionExpired;

    private DateTimeOffset ValidateResponseAndClock(
        EnterpriseDeviceBindingCompleteResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.SchemaVersion != 1)
        {
            throw new InvalidDataException(
                "Enterprise binding response version is unsupported.");
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

        var nowUtc = _timeProvider.GetUtcNow();
        if (nowUtc.Offset != TimeSpan.Zero
            || nowUtc < response.ServerTimeUtc
            || response.AccessTokenExpiresAtUtc <= response.ServerTimeUtc
            || response.AccessTokenExpiresAtUtc > response.ServerTimeUtc + MaximumAccessTokenLifetime
            || response.AccessTokenExpiresAtUtc > response.LeaseExpiresAtUtc)
        {
            throw new InvalidDataException(
                "Enterprise binding response clock or token lifetime is inconsistent.");
        }

        return nowUtc;
    }

    private void ValidateFreshChallenge(EnterpriseBindingChallenge challenge)
    {
        EnterpriseBindingValidation.ValidateCanonicalUtcSecond(
            challenge.ExpiresAtUtc,
            nameof(challenge.ExpiresAtUtc));
        var nowUtc = _timeProvider.GetUtcNow();
        if (nowUtc.Offset != TimeSpan.Zero
            || challenge.ExpiresAtUtc <= nowUtc
            || challenge.ExpiresAtUtc > nowUtc + MaximumBindingChallengeLifetime)
        {
            throw new InvalidDataException(
                "Enterprise binding challenge is expired or overlong.");
        }
    }

    private static void ValidateSignedResponseConsistency(
        EnterpriseDeviceBindingCompleteResponse response,
        EnterpriseVerifiedAuthorizationLease verifiedLease)
    {
        var claims = verifiedLease.Claims;
        if (!string.Equals(response.BindingId, claims.BindingId, StringComparison.Ordinal)
            || response.ServerTimeUtc != claims.IssuedAtUtc
            || response.LeaseExpiresAtUtc != claims.ExpiresAtUtc
            || response.AccessTokenExpiresAtUtc > claims.ExpiresAtUtc)
        {
            throw new InvalidDataException(
                "Enterprise binding response fields do not match the signed authorization lease.");
        }
    }

    private static void EnsureReadyDecision(EnterpriseAccessDecision decision)
    {
        if (decision.ClientState != EnterpriseClientState.Ready
            || !decision.MayStartHarness
            || !decision.MayCallManagedApi
            || decision.ResetScope != EnterpriseResetScope.None
            || decision.ErrorCode is not null)
        {
            throw new InvalidDataException(
                "Enterprise binding authorization did not produce an exact Ready decision.");
        }
    }

    private static void EnsureGatedDecision(
        EnterpriseAccessSnapshot snapshot,
        EnterpriseAccessDecision appliedDecision,
        DateTimeOffset evaluationTimeUtc)
    {
        var expected = EnterpriseAccessEvaluator.Evaluate(snapshot, evaluationTimeUtc);
        if (appliedDecision != expected
            || (appliedDecision.ClientState != EnterpriseClientState.Ready
                && !(snapshot.ClientUpdateRequired
                    && appliedDecision.ClientState == EnterpriseClientState.UpdateRequired
                    && appliedDecision.ErrorCode == EnterpriseErrorCodes.ClientUpdateRequired)))
        {
            throw new InvalidDataException(
                "Enterprise binding update gate produced an unexpected access decision.");
        }
    }

    private static void ValidateAccessToken(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length is < 32 or > 4096
            || value.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '-' and not '.' and not '_' and not '~'))
        {
            throw new InvalidDataException(
                "Enterprise access token is not a bounded in-memory bearer token.");
        }
    }

    private void OnDecisionChanged(EnterpriseAccessDecision decision)
    {
        if (!decision.MayCallManagedApi)
        {
            _accessTokenVault.Clear();
        }
    }
}
