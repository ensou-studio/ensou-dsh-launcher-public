using System.Net;
using Ensou.Dsh.Enterprise.Contracts;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.Client;

public enum EnterpriseAuthenticatedReleaseUpdateDisposition
{
    NotEligible,
    Completed,
    Restarting,
    SessionLocked,
    ContinueVerifiedStable,
    UpdateRemainsLocked,
    RequiresExclusiveStage,
}

public enum EnterpriseAuthenticatedReleaseUpdateFailureKind
{
    None,
    Unauthorized,
    Forbidden,
    AccessTokenUnavailable,
    FeedUnavailable,
    Protocol,
}

public sealed record EnterpriseAuthenticatedReleaseUpdateResult(
    EnterpriseAuthenticatedReleaseUpdateDisposition Disposition,
    EnterpriseAuthenticatedReleaseUpdateFailureKind FailureKind,
    EnterpriseReleaseUpdateOutcome? UpdateOutcome)
{
    public bool SessionLocked =>
        Disposition == EnterpriseAuthenticatedReleaseUpdateDisposition.SessionLocked;

    public bool MayContinueVerifiedStable =>
        Disposition == EnterpriseAuthenticatedReleaseUpdateDisposition.ContinueVerifiedStable;

    public bool RequiresRestart =>
        Disposition == EnterpriseAuthenticatedReleaseUpdateDisposition.Restarting;
}

/// <summary>
/// Runs one authenticated Stable-feed transaction only after the caller has
/// completed a fresh binding or refresh. A transaction client is never reused.
/// </summary>
public sealed class EnterpriseAuthenticatedReleaseUpdateCoordinator
{
    private readonly EnterpriseHarnessSession _session;
    private readonly Func<HttpClient> _transactionClientFactory;
    private readonly Func<
        HttpClient,
        CancellationToken,
        Task<EnterpriseReleaseUpdateOutcome>> _releaseStartupCheck;
    private readonly Func<
        HttpClient,
        CancellationToken,
        Task<EnterpriseReleaseUpdatePreflight>>? _releaseStartupProbe;
    private readonly Func<Task> _restartThroughStableBootstrapper;
    private readonly Action _shutdown;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public EnterpriseAuthenticatedReleaseUpdateCoordinator(
        EnterpriseHarnessSession session,
        Func<HttpClient> transactionClientFactory,
        Func<HttpClient, CancellationToken, Task<EnterpriseReleaseUpdateOutcome>>
            releaseStartupCheck,
        Func<Task> restartThroughStableBootstrapper,
        Action shutdown)
    {
        _session = session ?? throw new ArgumentNullException(nameof(session));
        _transactionClientFactory = transactionClientFactory
            ?? throw new ArgumentNullException(nameof(transactionClientFactory));
        _releaseStartupCheck = releaseStartupCheck
            ?? throw new ArgumentNullException(nameof(releaseStartupCheck));
        _restartThroughStableBootstrapper = restartThroughStableBootstrapper
            ?? throw new ArgumentNullException(nameof(restartThroughStableBootstrapper));
        _shutdown = shutdown ?? throw new ArgumentNullException(nameof(shutdown));
    }

    /// <summary>
    /// Creates a coordinator with an explicit read-only preflight operation.
    /// The supplied probe is used only by
    /// <see cref="ProbeAfterFreshAuthorizationAsync"/>; the existing check
    /// remains the exclusive staging operation.
    /// </summary>
    public EnterpriseAuthenticatedReleaseUpdateCoordinator(
        EnterpriseHarnessSession session,
        Func<HttpClient> transactionClientFactory,
        Func<HttpClient, CancellationToken, Task<EnterpriseReleaseUpdateOutcome>>
            releaseStartupCheck,
        Func<Task> restartThroughStableBootstrapper,
        Action shutdown,
        Func<HttpClient, CancellationToken, Task<EnterpriseReleaseUpdatePreflight>>
            releaseStartupProbe)
        : this(
            session,
            transactionClientFactory,
            releaseStartupCheck,
            restartThroughStableBootstrapper,
            shutdown)
    {
        _releaseStartupProbe = releaseStartupProbe
            ?? throw new ArgumentNullException(nameof(releaseStartupProbe));
    }

    public static EnterpriseAuthenticatedReleaseUpdateCoordinator Create(
        EnterpriseHarnessSession session,
        EnterpriseInstallationLayout installationLayout,
        Uri manifestUri,
        EnterpriseReleaseTrustPolicy trustPolicy,
        Func<HttpClient> transactionClientFactory,
        Func<Task> restartThroughStableBootstrapper,
        Action shutdown,
        int harnessPort)
    {
        ArgumentNullException.ThrowIfNull(installationLayout);
        ArgumentNullException.ThrowIfNull(manifestUri);
        ArgumentNullException.ThrowIfNull(trustPolicy);
        return new EnterpriseAuthenticatedReleaseUpdateCoordinator(
            session,
            transactionClientFactory,
            (httpClient, cancellationToken) =>
                new EnterpriseReleaseStartupCoordinator(
                    installationLayout,
                    manifestUri,
                    trustPolicy,
                    httpClient,
                    harnessPort: harnessPort)
                .CheckOnEveryStartupAsync(cancellationToken),
            restartThroughStableBootstrapper,
            shutdown,
            (httpClient, cancellationToken) =>
                new EnterpriseReleaseStartupCoordinator(
                    installationLayout,
                    manifestUri,
                    trustPolicy,
                    httpClient,
                    harnessPort: harnessPort)
                .ProbeVerifiedReleaseAsync(cancellationToken));
    }

    /// <summary>
    /// Performs one authenticated, read-only release preflight. The caller may
    /// enter a runtime drain only when the returned disposition is
    /// <see cref="EnterpriseAuthenticatedReleaseUpdateDisposition.RequiresExclusiveStage"/>.
    /// The subsequent stage must call <see cref="CheckAfterFreshAuthorizationAsync"/>
    /// so it uses a separate authenticated transaction client.
    /// </summary>
    public async Task<EnterpriseAuthenticatedReleaseUpdateResult>
        ProbeAfterFreshAuthorizationAsync(
            bool freshAuthorizationCompleted,
            EnterpriseAccessDecision accessDecision,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accessDecision);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!IsAdmitted(freshAuthorizationCompleted, accessDecision))
            {
                return NotEligible();
            }

            var probe = _releaseStartupProbe
                ?? throw new InvalidOperationException(
                    "This authenticated update coordinator does not support read-only preflight.");
            using var transactionClient = _transactionClientFactory()
                ?? throw new InvalidOperationException(
                    "Enterprise authenticated update client factory returned null.");
            try
            {
                var preflight = await probe(transactionClient, cancellationToken)
                    .ConfigureAwait(false);
                ArgumentNullException.ThrowIfNull(preflight);
                if (preflight.RequiresExclusiveStage)
                {
                    return new EnterpriseAuthenticatedReleaseUpdateResult(
                        EnterpriseAuthenticatedReleaseUpdateDisposition.RequiresExclusiveStage,
                        EnterpriseAuthenticatedReleaseUpdateFailureKind.None,
                        UpdateOutcome: null);
                }

                return new EnterpriseAuthenticatedReleaseUpdateResult(
                    EnterpriseAuthenticatedReleaseUpdateDisposition.Completed,
                    EnterpriseAuthenticatedReleaseUpdateFailureKind.None,
                    preflight.TerminalOutcome
                        ?? throw new InvalidDataException(
                            "Enterprise update preflight returned neither a terminal outcome nor a stage request."));
            }
            catch (EnterpriseUpdateFeedAuthorizationDeniedException exception)
                when (exception.StatusCode == HttpStatusCode.Unauthorized
                    || exception.TokenCleared)
            {
                await LockSessionAfterAuthenticationLossAsync().ConfigureAwait(false);
                return new EnterpriseAuthenticatedReleaseUpdateResult(
                    EnterpriseAuthenticatedReleaseUpdateDisposition.SessionLocked,
                    EnterpriseAuthenticatedReleaseUpdateFailureKind.Unauthorized,
                    UpdateOutcome: null);
            }
            catch (EnterpriseUpdateFeedAuthorizationDeniedException exception)
                when (exception.StatusCode == HttpStatusCode.Forbidden)
            {
                return SafeDowngrade(
                    accessDecision,
                    EnterpriseAuthenticatedReleaseUpdateFailureKind.Forbidden);
            }
            catch (EnterpriseAccessTokenUnavailableException)
            {
                await LockSessionAfterAuthenticationLossAsync().ConfigureAwait(false);
                return new EnterpriseAuthenticatedReleaseUpdateResult(
                    EnterpriseAuthenticatedReleaseUpdateDisposition.SessionLocked,
                    EnterpriseAuthenticatedReleaseUpdateFailureKind.AccessTokenUnavailable,
                    UpdateOutcome: null);
            }
            catch (EnterpriseUpdateFeedUnavailableException)
            {
                return SafeDowngrade(
                    accessDecision,
                    EnterpriseAuthenticatedReleaseUpdateFailureKind.FeedUnavailable);
            }
            catch (Exception exception) when (exception is
                EnterpriseUpdateFeedProtocolException
                or EnterpriseUpdateFeedTransactionConsumedException)
            {
                return SafeDowngrade(
                    accessDecision,
                    EnterpriseAuthenticatedReleaseUpdateFailureKind.Protocol);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Rechecks the exact authorization snapshot before a caller stops an
    /// already-running managed Runtime for an authenticated update stage.
    /// </summary>
    public async Task<bool> IsStillAdmittedAsync(
        bool freshAuthorizationCompleted,
        EnterpriseAccessDecision accessDecision,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accessDecision);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return IsAdmitted(freshAuthorizationCompleted, accessDecision);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<EnterpriseAuthenticatedReleaseUpdateResult>
        CheckAfterFreshAuthorizationAsync(
            bool freshAuthorizationCompleted,
            EnterpriseAccessDecision accessDecision,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accessDecision);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!IsAdmitted(freshAuthorizationCompleted, accessDecision))
            {
                return NotEligible();
            }

            using var transactionClient = _transactionClientFactory()
                ?? throw new InvalidOperationException(
                    "Enterprise authenticated update client factory returned null.");
            try
            {
                var outcome = await _releaseStartupCheck(
                        transactionClient,
                        cancellationToken)
                    .ConfigureAwait(false);
                ArgumentNullException.ThrowIfNull(outcome);
                if (outcome.RequiresBootstrapHealthCheck)
                {
                    await _restartThroughStableBootstrapper().ConfigureAwait(false);
                    _shutdown();
                    return new EnterpriseAuthenticatedReleaseUpdateResult(
                        EnterpriseAuthenticatedReleaseUpdateDisposition.Restarting,
                        EnterpriseAuthenticatedReleaseUpdateFailureKind.None,
                        outcome);
                }

                return new EnterpriseAuthenticatedReleaseUpdateResult(
                    EnterpriseAuthenticatedReleaseUpdateDisposition.Completed,
                    EnterpriseAuthenticatedReleaseUpdateFailureKind.None,
                    outcome);
            }
            catch (EnterpriseUpdateFeedAuthorizationDeniedException exception)
                when (exception.StatusCode == HttpStatusCode.Unauthorized
                    || exception.TokenCleared)
            {
                await LockSessionAfterAuthenticationLossAsync().ConfigureAwait(false);
                return new EnterpriseAuthenticatedReleaseUpdateResult(
                    EnterpriseAuthenticatedReleaseUpdateDisposition.SessionLocked,
                    EnterpriseAuthenticatedReleaseUpdateFailureKind.Unauthorized,
                    UpdateOutcome: null);
            }
            catch (EnterpriseUpdateFeedAuthorizationDeniedException exception)
                when (exception.StatusCode == HttpStatusCode.Forbidden)
            {
                return SafeDowngrade(
                    accessDecision,
                    EnterpriseAuthenticatedReleaseUpdateFailureKind.Forbidden);
            }
            catch (EnterpriseAccessTokenUnavailableException)
            {
                await LockSessionAfterAuthenticationLossAsync().ConfigureAwait(false);
                return new EnterpriseAuthenticatedReleaseUpdateResult(
                    EnterpriseAuthenticatedReleaseUpdateDisposition.SessionLocked,
                    EnterpriseAuthenticatedReleaseUpdateFailureKind.AccessTokenUnavailable,
                    UpdateOutcome: null);
            }
            catch (EnterpriseUpdateFeedUnavailableException)
            {
                return SafeDowngrade(
                    accessDecision,
                    EnterpriseAuthenticatedReleaseUpdateFailureKind.FeedUnavailable);
            }
            catch (Exception exception) when (exception is
                EnterpriseUpdateFeedProtocolException
                or EnterpriseUpdateFeedTransactionConsumedException)
            {
                return SafeDowngrade(
                    accessDecision,
                    EnterpriseAuthenticatedReleaseUpdateFailureKind.Protocol);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private bool IsAdmitted(
        bool freshAuthorizationCompleted,
        EnterpriseAccessDecision accessDecision) =>
        freshAuthorizationCompleted
        && accessDecision == _session.CurrentDecision
        && _session.CurrentAccessSnapshot.ControlPlane
            == ControlPlaneConnectivity.Available
        && accessDecision.ClientState is
            EnterpriseClientState.Ready or EnterpriseClientState.UpdateRequired;

    private static EnterpriseAuthenticatedReleaseUpdateResult NotEligible() =>
        new(
            EnterpriseAuthenticatedReleaseUpdateDisposition.NotEligible,
            EnterpriseAuthenticatedReleaseUpdateFailureKind.None,
            UpdateOutcome: null);

    private async Task LockSessionAfterAuthenticationLossAsync()
    {
        var lockedSnapshot = _session.CurrentAccessSnapshot with
        {
            ControlPlane = ControlPlaneConnectivity.Unknown,
        };
        _ = await _session.ApplyAccessAsync(lockedSnapshot, CancellationToken.None)
            .ConfigureAwait(false);
    }

    private static EnterpriseAuthenticatedReleaseUpdateResult SafeDowngrade(
        EnterpriseAccessDecision accessDecision,
        EnterpriseAuthenticatedReleaseUpdateFailureKind failureKind) =>
        new(
            accessDecision.ClientState == EnterpriseClientState.Ready
                ? EnterpriseAuthenticatedReleaseUpdateDisposition.ContinueVerifiedStable
                : EnterpriseAuthenticatedReleaseUpdateDisposition.UpdateRemainsLocked,
            failureKind,
            UpdateOutcome: null);
}
