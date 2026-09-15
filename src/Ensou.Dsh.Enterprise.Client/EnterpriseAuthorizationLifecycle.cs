using System.Security.Cryptography;
using Ensou.Dsh.Enterprise.Contracts;

namespace Ensou.Dsh.Enterprise.Client;

public sealed record EnterpriseAuthorizationHydrationResult(
    bool HasCommittedBinding,
    bool RefreshCompleted,
    EnterpriseAccessDecision AccessDecision)
{
    public override string ToString() => "Enterprise authorization hydration result [REDACTED]";
}

public sealed class EnterpriseAuthorizationLifecycle
{
    private readonly IEnterpriseRefreshClient _refreshClient;
    private readonly EnterpriseAuthorizationLeaseVerifier _leaseVerifier;
    private readonly EnterpriseBindingCredentialStore _credentialStore;
    private readonly EnterprisePendingRefreshTransactionStore _pendingStore;
    private readonly IEnterpriseAccessTokenVault _accessTokenVault;
    private readonly EnterpriseHarnessSession _harnessSession;
    private readonly EnterpriseTrustedTimeStore _trustedTimeStore;
    private readonly IEnterpriseDeviceUpdateGate _deviceUpdateGate;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public EnterpriseAuthorizationLifecycle(
        IEnterpriseRefreshClient refreshClient,
        EnterpriseAuthorizationLeaseVerifier leaseVerifier,
        EnterpriseBindingCredentialStore credentialStore,
        EnterprisePendingRefreshTransactionStore pendingStore,
        IEnterpriseAccessTokenVault accessTokenVault,
        EnterpriseHarnessSession harnessSession,
        EnterpriseTrustedTimeStore trustedTimeStore,
        IEnterpriseDeviceUpdateGate deviceUpdateGate,
        TimeProvider? timeProvider = null)
    {
        _refreshClient = refreshClient ?? throw new ArgumentNullException(nameof(refreshClient));
        _leaseVerifier = leaseVerifier ?? throw new ArgumentNullException(nameof(leaseVerifier));
        _credentialStore = credentialStore ?? throw new ArgumentNullException(nameof(credentialStore));
        _pendingStore = pendingStore ?? throw new ArgumentNullException(nameof(pendingStore));
        _accessTokenVault = accessTokenVault
            ?? throw new ArgumentNullException(nameof(accessTokenVault));
        _harnessSession = harnessSession ?? throw new ArgumentNullException(nameof(harnessSession));
        _trustedTimeStore = trustedTimeStore
            ?? throw new ArgumentNullException(nameof(trustedTimeStore));
        _deviceUpdateGate = deviceUpdateGate
            ?? throw new ArgumentNullException(nameof(deviceUpdateGate));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _harnessSession.DecisionChanged += OnDecisionChanged;
    }

    public async Task<EnterpriseAuthorizationHydrationResult> HydrateAndRefreshAsync(
        EnterpriseEnrollmentDeviceContext device,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _accessTokenVault.Clear();
            var credential = await _credentialStore.ReadCommittedAsync(cancellationToken)
                .ConfigureAwait(false);
            if (credential is null)
            {
                var decision = await _harnessSession.ApplyAccessAsync(
                        EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot(),
                        cancellationToken)
                    .ConfigureAwait(false);
                return new EnterpriseAuthorizationHydrationResult(false, false, decision);
            }

            var cachedLease = VerifyPersistedCredential(credential, device);
            var cachedSnapshot = CreateRestartLockedSnapshot(cachedLease.AccessSnapshot with
            {
                ControlPlane = ControlPlaneConnectivity.Unavailable,
                LeaseExpiresAtUtc = credential.Receipt.LeaseExpiresAtUtc,
            });
            await _harnessSession.ApplyAccessAsync(cachedSnapshot, cancellationToken)
                .ConfigureAwait(false);

            try
            {
                var result = await RefreshCommittedCredentialAsync(
                        credential,
                        cancellationToken)
                    .ConfigureAwait(false);
                return result;
            }
            catch (EnterpriseControlPlaneException exception)
            {
                _accessTokenVault.Clear();
                if (exception.Error.ResetScope == EnterpriseResetScope.SecurityCredentials)
                {
                    TryDeletePending();
                }

                await _harnessSession.ApplyAccessAsync(
                        CreateDeniedSnapshot(exception.Error, cachedSnapshot),
                        CancellationToken.None)
                    .ConfigureAwait(false);
                throw;
            }
            catch
            {
                _accessTokenVault.Clear();
                throw;
            }
        }
        catch (EnterpriseBindingRecoveryRequiredException)
        {
            _accessTokenVault.Clear();
            await LockForRecoveryAsync().ConfigureAwait(false);
            throw;
        }
        catch (Exception exception) when (
            exception is InvalidDataException
                or CryptographicException
                or IOException
                or UnauthorizedAccessException)
        {
            _accessTokenVault.Clear();
            await LockForRecoveryAsync().ConfigureAwait(false);
            throw new EnterpriseBindingRecoveryRequiredException(exception);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Refreshes an already hydrated live session without applying the restart-only
    /// lock snapshot first. The current session and token remain governed by their
    /// existing expirations while transport is in flight; only a verified response
    /// can replace them.
    /// </summary>
    public async Task<EnterpriseAuthorizationHydrationResult> RefreshInPlaceAsync(
        EnterpriseEnrollmentDeviceContext device,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnterprisePersistedBindingCredential? credential;
            EnterpriseVerifiedAuthorizationLease persistedLease;
            try
            {
                credential = await _credentialStore.ReadCommittedAsync(cancellationToken)
                    .ConfigureAwait(false);
                if (credential is null)
                {
                    _accessTokenVault.Clear();
                    var qrRequired = await _harnessSession.ApplyAccessAsync(
                            EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot(),
                            CancellationToken.None)
                        .ConfigureAwait(false);
                    return new EnterpriseAuthorizationHydrationResult(
                        false,
                        false,
                        qrRequired);
                }

                // Rebind the persisted lease to the caller's exact installation and
                // device key before reading or replaying any pending refresh journal.
                persistedLease = VerifyPersistedCredential(credential, device);
            }
            catch (EnterpriseBindingRecoveryRequiredException)
            {
                _accessTokenVault.Clear();
                await LockForRecoveryAsync().ConfigureAwait(false);
                throw;
            }
            catch (Exception exception) when (
                exception is InvalidDataException
                    or CryptographicException
                    or IOException
                    or UnauthorizedAccessException)
            {
                _accessTokenVault.Clear();
                await LockForRecoveryAsync().ConfigureAwait(false);
                throw new EnterpriseBindingRecoveryRequiredException(exception);
            }

            try
            {
                return await RefreshCommittedCredentialAsync(credential, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (EnterpriseControlPlaneException exception)
            {
                // An authenticated denial is authoritative immediately. A transport
                // exception takes the generic path below and leaves the existing
                // lease/token untouched so their original expiry remains decisive.
                _accessTokenVault.Clear();
                if (exception.Error.ResetScope == EnterpriseResetScope.SecurityCredentials)
                {
                    TryDeletePending();
                }

                var currentSnapshot = persistedLease.AccessSnapshot with
                {
                    LeaseExpiresAtUtc = credential.Receipt.LeaseExpiresAtUtc,
                };
                await _harnessSession.ApplyAccessAsync(
                        CreateDeniedSnapshot(exception.Error, currentSnapshot),
                        CancellationToken.None)
                    .ConfigureAwait(false);
                throw;
            }
            catch (EnterpriseBindingRecoveryRequiredException)
            {
                _accessTokenVault.Clear();
                await LockForRecoveryAsync().ConfigureAwait(false);
                throw;
            }
            catch (Exception exception) when (
                exception is InvalidDataException
                    or CryptographicException
                    or IOException
                    or UnauthorizedAccessException)
            {
                _accessTokenVault.Clear();
                await LockForRecoveryAsync().ConfigureAwait(false);
                throw new EnterpriseBindingRecoveryRequiredException(exception);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private EnterpriseVerifiedAuthorizationLease VerifyPersistedCredential(
        EnterprisePersistedBindingCredential credential,
        EnterpriseEnrollmentDeviceContext device) =>
        _leaseVerifier.VerifyPersistedCredential(credential, device);

    private async Task<EnterpriseAuthorizationHydrationResult> RefreshCommittedCredentialAsync(
        EnterprisePersistedBindingCredential credential,
        CancellationToken cancellationToken)
    {
        using var pending = await _pendingStore.ReadAsync(cancellationToken).ConfigureAwait(false);
        if (pending is not null)
        {
            var pendingRequest = EnterpriseRefreshClient.DeserializeExactRequest(
                pending.ExactRequestBody);
            ValidatePendingBinding(pendingRequest, credential);
            if (!string.Equals(
                    pendingRequest.PreviousLeaseId,
                    credential.Receipt.LeaseId,
                    StringComparison.Ordinal))
            {
                // A marker-first rotation already committed; only the stale journal survived.
                _pendingStore.Delete();
                return await CreateAndExecuteRefreshAsync(
                        credential,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            return await ExecutePendingAsync(
                    pending,
                    pendingRequest,
                    credential,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        return await CreateAndExecuteRefreshAsync(
                credential,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<EnterpriseAuthorizationHydrationResult> CreateAndExecuteRefreshAsync(
        EnterprisePersistedBindingCredential credential,
        CancellationToken cancellationToken)
    {
        var request = new EnterpriseRefreshRequest
        {
            BindingId = credential.Receipt.BindingId,
            InstallId = credential.Receipt.InstallationId,
            PreviousLeaseId = credential.Receipt.LeaseId,
            AuthorizationEpoch = credential.Receipt.EpochState.AuthorizationEpoch,
            EntitlementEpoch = credential.Receipt.EpochState.EntitlementEpoch,
            BindingEpoch = credential.Receipt.EpochState.BindingEpoch,
        };
        var exactRequestBody = EnterpriseRefreshClient.SerializeExactRequest(request);
        try
        {
            var idempotencyKey = EnterpriseBindingValidation.Base64UrlEncode(
                RandomNumberGenerator.GetBytes(32));
            var createdAtUtc = DateTimeOffset.FromUnixTimeSeconds(
                _timeProvider.GetUtcNow().ToUnixTimeSeconds());
            await _pendingStore.WriteNewAsync(
                    exactRequestBody,
                    idempotencyKey,
                    createdAtUtc,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactRequestBody);
        }

        using var pending = await _pendingStore.ReadAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new EnterpriseBindingRecoveryRequiredException(
                new InvalidDataException(
                    "Enterprise pending refresh transaction was not durably committed."));
        return await ExecutePendingAsync(pending, request, credential, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<EnterpriseAuthorizationHydrationResult> ExecutePendingAsync(
        EnterprisePendingRefreshTransaction pending,
        EnterpriseRefreshRequest request,
        EnterprisePersistedBindingCredential credential,
        CancellationToken cancellationToken)
    {
        ValidatePendingIdentity(request, credential);
        if (!string.Equals(
                request.PreviousLeaseId,
                credential.Receipt.LeaseId,
                StringComparison.Ordinal))
        {
            throw new EnterpriseBindingRecoveryRequiredException(
                new InvalidDataException(
                    "Enterprise refresh journal does not match the committed previous lease."));
        }

        var response = await _refreshClient.RefreshExactAsync(
                pending.ExactRequestBody,
                credential.RefreshToken,
                pending.IdempotencyKey,
                cancellationToken)
            .ConfigureAwait(false);
        var verifiedLease = _leaseVerifier.Verify(
            response.AuthorizationLease,
            new EnterpriseAuthorizationLeaseVerificationContext(
                credential.Receipt.BindingId,
                credential.Receipt.InstallationId,
                credential.Receipt.DeviceKeyThumbprint,
                response.ServerTimeUtc,
                response.ServerTimeUtc));
        ValidateResponseConsistency(response, verifiedLease, credential);
        var runtimeSnapshot = verifiedLease.AccessSnapshot with
        {
            LeaseExpiresAtUtc = response.AccessTokenExpiresAtUtc,
        };
        var nowUtc = _timeProvider.GetUtcNow();
        if (nowUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException("Enterprise refresh requires a UTC local clock.");
        }

        var prospectiveDecision = EnterpriseAccessEvaluator.Evaluate(runtimeSnapshot, nowUtc);
        await _credentialStore.RotateOrConfirmAsync(
                response,
                verifiedLease,
                cancellationToken)
            .ConfigureAwait(false);
        var reconciledFloorUtc = _trustedTimeStore.ReconcileVerifiedServerTime(
            response.ServerTimeUtc,
            nowUtc,
            response.LeaseExpiresAtUtc,
            localClockAccepted: prospectiveDecision.ClientState == EnterpriseClientState.Ready
                && prospectiveDecision.MayCallManagedApi);
        if (reconciledFloorUtc > runtimeSnapshot.TrustedTimeFloorUtc)
        {
            runtimeSnapshot = runtimeSnapshot with
            {
                TrustedTimeFloorUtc = reconciledFloorUtc,
            };
        }
        try
        {
            _pendingStore.Delete();
        }
        catch (Exception exception)
        {
            await LockForRecoveryAsync().ConfigureAwait(false);
            throw new EnterpriseBindingRecoveryRequiredException(exception);
        }

        if (prospectiveDecision.ClientState != EnterpriseClientState.Ready
            || !prospectiveDecision.MayCallManagedApi)
        {
            _accessTokenVault.Clear();
            var applied = await _harnessSession.ApplyAccessAsync(
                    runtimeSnapshot,
                    cancellationToken)
                .ConfigureAwait(false);
            return new EnterpriseAuthorizationHydrationResult(true, true, applied);
        }

        _accessTokenVault.Install(
            response.BindingId,
            response.AccessToken,
            response.AccessTokenExpiresAtUtc);
        try
        {
            runtimeSnapshot = EnterpriseDeviceUpdateGate.ValidateGateResult(
                runtimeSnapshot,
                await _deviceUpdateGate.EvaluateBeforeReadyAsync(
                        runtimeSnapshot,
                        response.BindingId,
                        cancellationToken)
                    .ConfigureAwait(false));
            var applied = await _harnessSession.ApplyAccessAsync(
                    runtimeSnapshot,
                    cancellationToken)
                .ConfigureAwait(false);
            var updateLocked = runtimeSnapshot.ClientUpdateRequired
                && applied.ClientState == EnterpriseClientState.UpdateRequired
                && !applied.MayStartHarness
                && !applied.MayCallManagedApi
                && applied.ErrorCode == EnterpriseErrorCodes.ClientUpdateRequired;
            if (!updateLocked
                && (applied.ClientState != EnterpriseClientState.Ready
                    || !applied.MayCallManagedApi
                    || !_accessTokenVault.HasUsableToken(response.BindingId, nowUtc)))
            {
                throw new InvalidDataException(
                    "Enterprise refreshed authorization did not produce an exact Ready state.");
            }

            return new EnterpriseAuthorizationHydrationResult(true, true, applied);
        }
        catch
        {
            _accessTokenVault.Clear();
            await LockForRecoveryAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static void ValidatePendingIdentity(
        EnterpriseRefreshRequest request,
        EnterprisePersistedBindingCredential credential)
    {
        if (!string.Equals(request.BindingId, credential.Receipt.BindingId, StringComparison.Ordinal)
            || !string.Equals(
                request.InstallId,
                credential.Receipt.InstallationId,
                StringComparison.Ordinal)
            || request.AuthorizationEpoch != credential.Receipt.EpochState.AuthorizationEpoch
            || request.EntitlementEpoch != credential.Receipt.EpochState.EntitlementEpoch
            || request.BindingEpoch != credential.Receipt.EpochState.BindingEpoch)
        {
            throw new EnterpriseBindingRecoveryRequiredException(
                new InvalidDataException(
                    "Enterprise refresh journal identity or audit epochs do not match local state."));
        }
    }

    private static void ValidatePendingBinding(
        EnterpriseRefreshRequest request,
        EnterprisePersistedBindingCredential credential)
    {
        if (!string.Equals(request.BindingId, credential.Receipt.BindingId, StringComparison.Ordinal)
            || !string.Equals(
                request.InstallId,
                credential.Receipt.InstallationId,
                StringComparison.Ordinal))
        {
            throw new EnterpriseBindingRecoveryRequiredException(
                new InvalidDataException(
                    "Enterprise refresh journal belongs to another binding or installation."));
        }
    }

    private static void ValidateResponseConsistency(
        EnterpriseDeviceBindingCompleteResponse response,
        EnterpriseVerifiedAuthorizationLease verifiedLease,
        EnterprisePersistedBindingCredential previous)
    {
        var claims = verifiedLease.Claims;
        if (!string.Equals(response.BindingId, claims.BindingId, StringComparison.Ordinal)
            || !string.Equals(
                response.AuthorizationLease,
                verifiedLease.Envelope.CompactJws,
                StringComparison.Ordinal)
            || !string.Equals(
                claims.Subject,
                previous.Receipt.EmployeeAuthorizationId,
                StringComparison.Ordinal)
            || response.ServerTimeUtc != claims.IssuedAtUtc
            || response.LeaseExpiresAtUtc != claims.ExpiresAtUtc
            || response.AccessTokenExpiresAtUtc > claims.ExpiresAtUtc
            || response.ServerTimeUtc < previous.Receipt.ServerTimeUtc
            || claims.AuthorizationEpoch < previous.Receipt.EpochState.AuthorizationEpoch
            || claims.EntitlementEpoch < previous.Receipt.EpochState.EntitlementEpoch
            || claims.BindingEpoch < previous.Receipt.EpochState.BindingEpoch)
        {
            throw new InvalidDataException(
                "Enterprise refresh response conflicts with its signed lease or previous binding.");
        }
    }

    private static EnterpriseAccessSnapshot CreateDeniedSnapshot(
        EnterpriseApiError error,
        EnterpriseAccessSnapshot cachedSnapshot) => error.ClientState switch
        {
            EnterpriseClientState.AccountLocked => cachedSnapshot with
            {
                Employee = error.ResetScope == EnterpriseResetScope.SecurityCredentials
                    ? EmployeeAuthorizationState.Revoked
                    : EmployeeAuthorizationState.Suspended,
            },
            EnterpriseClientState.DeviceRevokedResetRequired => cachedSnapshot with
            {
                Device = DeviceBindingState.RevokedAdmin,
            },
            EnterpriseClientState.ApiDisabled => cachedSnapshot with
            {
                ApiAllocation = error.Code == EnterpriseErrorCodes.ApiProfileUnassigned
                    ? ApiAllocationState.Unassigned
                    : ApiAllocationState.Suspended,
            },
            EnterpriseClientState.LeaseExpiredLocked => cachedSnapshot with
            {
                LeaseExpiresAtUtc = cachedSnapshot.LeaseIssuedAtUtc,
            },
            EnterpriseClientState.QrRequired =>
                EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot(),
            EnterpriseClientState.Binding =>
                EnterpriseStartupGate.CreateEnrollmentPendingSnapshot(),
            EnterpriseClientState.UpdateRequired => cachedSnapshot with
            {
                ClientUpdateRequired = true,
            },
            _ => cachedSnapshot with
            {
                Device = DeviceBindingState.QuarantinedCompromise,
            },
        };

    private EnterpriseAccessSnapshot CreateRestartLockedSnapshot(
        EnterpriseAccessSnapshot snapshot)
    {
        var persistedFloorUtc = _trustedTimeStore.ReadFloorUtc();
        if (persistedFloorUtc is { } floorUtc
            && floorUtc > snapshot.TrustedTimeFloorUtc)
        {
            snapshot = snapshot with { TrustedTimeFloorUtc = floorUtc };
        }

        // The process-local monotonic anchor cannot prove how much time elapsed
        // while the Launcher was stopped, and a same-user actor can delete local
        // state. Therefore a committed credential is never sufficient for
        // OfflineGrace after restart. Refresh remains available and a newly
        // verified server response can recreate or reconcile trusted time.
        return snapshot with { ClockTrusted = false };
    }

    private async Task LockForRecoveryAsync() => await _harnessSession.ApplyAccessAsync(
            EnterpriseStartupGate.CreateEnrollmentPendingSnapshot(),
            CancellationToken.None)
        .ConfigureAwait(false);

    private void TryDeletePending()
    {
        try
        {
            _pendingStore.Delete();
        }
        catch
        {
            // The locked state remains authoritative; reset can retry exact-file cleanup.
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
