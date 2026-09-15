using Ensou.Dsh.Enterprise.Contracts;

namespace Ensou.Dsh.Enterprise.Client;

/// <summary>
/// Describes whether automatic update admission stopped the exact managed
/// Runtime that was already owned by the Launcher.
/// </summary>
public enum EnterpriseManagedRuntimeDrainDisposition
{
    /// <summary>No owned Runtime needed to be stopped.</summary>
    NoRuntimeToStop,

    /// <summary>The exact owned Runtime stopped after graceful drain.</summary>
    StoppedExactRuntime,
}

/// <summary>
/// Proves that the exact managed Runtime stopped for the identified automatic
/// update operation before the Host reported a subsequent failure.
/// </summary>
public sealed class EnterpriseManagedRuntimeStoppedException : Exception
{
    /// <summary>
    /// Creates stopped-Runtime evidence with the exact operation identity and
    /// the Host failure that followed the confirmed process exit.
    /// </summary>
    public EnterpriseManagedRuntimeStoppedException(
        Guid operationId,
        Exception innerException)
        : base(
            "The managed Runtime stopped before automatic update admission completed.",
            innerException)
    {
        if (operationId == Guid.Empty)
        {
            throw new ArgumentException(
                "Managed update operation identity must be non-empty.",
                nameof(operationId));
        }
        OperationId = operationId;
    }

    /// <summary>Gets the exact automatic-update operation that stopped Runtime.</summary>
    public Guid OperationId { get; }
}

/// <summary>
/// Coordinates the bounded automatic-update transaction after a caller has
/// refreshed enterprise authorization. It never discovers, stops, or starts a
/// Runtime itself; those actions remain explicit caller-provided capabilities.
/// </summary>
public sealed class EnterpriseAutomaticReleaseUpdateCoordinator
{
    private readonly EnterpriseAuthenticatedReleaseUpdateCoordinator _updates;
    private readonly Func<
        Guid,
        CancellationToken,
        Task<EnterpriseManagedRuntimeDrainDisposition>> _drainRuntime;
    private readonly Action _requireQuiescentLoopback;
    private readonly Func<CancellationToken, Task> _restoreThroughCurrentAuthorization;

    /// <summary>
    /// Creates an automatic-update coordinator with explicit host admission,
    /// loopback exclusion, and authorization-governed recovery capabilities.
    /// </summary>
    public EnterpriseAutomaticReleaseUpdateCoordinator(
        EnterpriseAuthenticatedReleaseUpdateCoordinator updates,
        Func<Guid, CancellationToken, Task<EnterpriseManagedRuntimeDrainDisposition>>
            drainRuntime,
        Action requireQuiescentLoopback,
        Func<CancellationToken, Task> restoreThroughCurrentAuthorization)
    {
        _updates = updates ?? throw new ArgumentNullException(nameof(updates));
        _drainRuntime = drainRuntime ?? throw new ArgumentNullException(nameof(drainRuntime));
        _requireQuiescentLoopback = requireQuiescentLoopback
            ?? throw new ArgumentNullException(nameof(requireQuiescentLoopback));
        _restoreThroughCurrentAuthorization = restoreThroughCurrentAuthorization
            ?? throw new ArgumentNullException(nameof(restoreThroughCurrentAuthorization));
    }

    /// <summary>
    /// Runs one read-only probe and, only for a verified change that remains
    /// currently authorized, drains the owned Runtime, requires loopback
    /// exclusion, and enters the existing exclusive stage. A Runtime stopped
    /// by this transaction is restored through the supplied current-
    /// authorization capability after any non-restarting stage outcome or
    /// failure. Recovery intentionally ignores caller cancellation.
    /// </summary>
    public async Task<EnterpriseAuthenticatedReleaseUpdateResult> RunAsync(
        bool freshAuthorizationCompleted,
        EnterpriseAccessDecision accessDecision,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accessDecision);
        var preflight = await _updates.ProbeAfterFreshAuthorizationAsync(
                freshAuthorizationCompleted,
                accessDecision,
                cancellationToken)
            .ConfigureAwait(false);
        if (preflight.Disposition
            != EnterpriseAuthenticatedReleaseUpdateDisposition.RequiresExclusiveStage)
        {
            return preflight;
        }

        if (!await _updates.IsStillAdmittedAsync(
                freshAuthorizationCompleted,
                accessDecision,
                cancellationToken).ConfigureAwait(false))
        {
            return new EnterpriseAuthenticatedReleaseUpdateResult(
                EnterpriseAuthenticatedReleaseUpdateDisposition.NotEligible,
                EnterpriseAuthenticatedReleaseUpdateFailureKind.None,
                UpdateOutcome: null);
        }

        var restoreStoppedRuntime = false;
        try
        {
            try
            {
                var drain = await _drainRuntime(Guid.NewGuid(), cancellationToken)
                    .ConfigureAwait(false);
                restoreStoppedRuntime = drain
                    == EnterpriseManagedRuntimeDrainDisposition.StoppedExactRuntime;
            }
            catch (EnterpriseManagedRuntimeStoppedException)
            {
                restoreStoppedRuntime = true;
                throw;
            }

            _requireQuiescentLoopback();
            var stage = await _updates.CheckAfterFreshAuthorizationAsync(
                    freshAuthorizationCompleted,
                    accessDecision,
                    cancellationToken)
                .ConfigureAwait(false);
            if (stage.RequiresRestart)
            {
                // The Stable Bootstrapper owns successor Runtime launch.
                restoreStoppedRuntime = false;
            }
            return stage;
        }
        finally
        {
            if (restoreStoppedRuntime)
            {
                await _restoreThroughCurrentAuthorization(CancellationToken.None)
                    .ConfigureAwait(false);
            }
        }
    }
}
