using System.Security.Cryptography;
using Ensou.Dsh.Enterprise.Contracts;

namespace Ensou.Dsh.Enterprise.Client;

public sealed class EnterpriseHarnessSession : IAsyncDisposable
{
    private static readonly TimeSpan StopOwnedHostTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan StopRetryDelay = TimeSpan.FromSeconds(1);
    private readonly EnterpriseStartupGate _startupGate;
    private readonly IEnterpriseHarnessHost _host;
    private readonly IEnterpriseResetExecutor? _resetExecutor;
    private readonly EnterpriseTrustedTimeStore? _trustedTimeStore;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly ITimer _leaseEnforcementTimer;
    private EnterpriseAccessSnapshot _snapshot;
    private EnterpriseAccessDecision _decision;
    private DateTimeOffset _anchoredLeaseIssuedAtUtc;
    private long _leaseAnchorTimestamp;
    private TimeSpan _leaseDurationFromAnchor;
    private bool _hasLeaseAnchor;
    private bool _ownedHostStopPending;
    private bool _ownedHostPreservedForUpdate;
    private EnterpriseResetScope _resetPendingScope;
    private EnterpriseAccessDecision? _resetLockedDecision;
    private EnterpriseAccessDecision? _lastCompletedResetDecision;
    private bool _disposed;

    public EnterpriseHarnessSession(
        EnterpriseStartupGate startupGate,
        IEnterpriseHarnessHost host,
        EnterpriseAccessSnapshot initialSnapshot,
        IEnterpriseResetExecutor? resetExecutor = null,
        EnterpriseTrustedTimeStore? trustedTimeStore = null)
    {
        _startupGate = startupGate ?? throw new ArgumentNullException(nameof(startupGate));
        _host = host ?? throw new ArgumentNullException(nameof(host));
        _resetExecutor = resetExecutor;
        _trustedTimeStore = trustedTimeStore;
        _snapshot = initialSnapshot ?? throw new ArgumentNullException(nameof(initialSnapshot));
        var evaluated = EvaluateCurrentAccess();
        AcceptAppliedLease(evaluated);
        evaluated = EnforceMonotonicLeaseDeadline(evaluated);
        var persistedReset = _resetExecutor?.ReadBarrier();
        if (persistedReset is not null)
        {
            _resetLockedDecision = persistedReset.Decision;
            if (persistedReset.ResetCompleted)
            {
                _lastCompletedResetDecision = persistedReset.Decision;
            }
            else
            {
                _resetPendingScope = persistedReset.Decision.ResetScope;
            }
        }

        _decision = _resetLockedDecision ?? evaluated;
        if (persistedReset is null)
        {
            RegisterResetIfRequired(evaluated);
            _decision = _resetLockedDecision ?? evaluated;
        }
        _leaseEnforcementTimer = _startupGate.CreateTimer(
            static state => ((EnterpriseHarnessSession)state!).OnLeaseEnforcementTimer(),
            this);
        ScheduleLeaseEnforcement();
    }

    public EnterpriseAccessDecision CurrentDecision => _decision;

    public EnterpriseAccessSnapshot CurrentAccessSnapshot => Volatile.Read(ref _snapshot);

    public event Action<EnterpriseAccessDecision>? DecisionChanged;

    public async Task<EnterpriseAccessDecision> ApplyAccessAsync(
        EnterpriseAccessSnapshot snapshot,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(snapshot);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _snapshot = snapshot;
            return await ReevaluateAccessAsync(acceptAppliedLease: true).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<Uri> EnsureStartedAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var decision = await ReevaluateAccessAsync().ConfigureAwait(false);
            ThrowIfStartDenied(decision);
            await _host.EnsureStartedAsync(cancellationToken).ConfigureAwait(false);
            decision = await ReevaluateAccessAsync().ConfigureAwait(false);
            ThrowIfStartDenied(decision);
            return _host.WebUiUri;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var decision = await ReevaluateAccessAsync().ConfigureAwait(false);
            if (!decision.MayStartHarness)
            {
                return false;
            }

            var healthy = await _host.IsHealthyAsync(cancellationToken).ConfigureAwait(false);
            decision = await ReevaluateAccessAsync().ConfigureAwait(false);
            return decision.MayStartHarness && healthy;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<EnterpriseAccessDecision> EnsureManagedApiAllowedAsync(
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var decision = await ReevaluateAccessAsync().ConfigureAwait(false);
            if (!decision.MayCallManagedApi)
            {
                throw new EnterpriseAccessDeniedException(decision);
            }

            return decision;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<Uri> GetWebUiUriAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var decision = await ReevaluateAccessAsync().ConfigureAwait(false);
            ThrowIfStartDenied(decision);
            if (!await _host.IsHealthyAsync(cancellationToken).ConfigureAwait(false))
            {
                throw new InvalidOperationException(
                    "The enterprise WebUI is unavailable because no authorized owned Harness process is healthy.");
            }

            decision = await ReevaluateAccessAsync().ConfigureAwait(false);
            ThrowIfStartDenied(decision);
            return _host.WebUiUri;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task OpenWebUiAsync(
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var decision = await ReevaluateAccessAsync().ConfigureAwait(false);
            ThrowIfStartDenied(decision);
            if (!await _host.IsHealthyAsync(cancellationToken).ConfigureAwait(false))
            {
                throw new InvalidOperationException(
                    "The enterprise WebUI is unavailable because no authorized owned Harness process is healthy.");
            }

            decision = await ReevaluateAccessAsync().ConfigureAwait(false);
            ThrowIfStartDenied(decision);
            await _host.OpenWebUiAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        var disposeTimer = false;
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _leaseEnforcementTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            disposeTimer = true;
            await _host.DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
            if (disposeTimer)
            {
                await _leaseEnforcementTimer.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private static void ThrowIfStartDenied(EnterpriseAccessDecision decision)
    {
        if (!decision.MayStartHarness)
        {
            throw new EnterpriseAccessDeniedException(decision);
        }
    }

    private async Task<EnterpriseAccessDecision> ReevaluateAccessAsync(
        bool acceptAppliedLease = false)
    {
        var previous = _decision;
        var evaluated = EvaluateCurrentAccess();
        if (acceptAppliedLease)
        {
            AcceptAppliedLease(evaluated);
        }

        evaluated = EnforceMonotonicLeaseDeadline(evaluated);
        RegisterResetIfRequired(evaluated);
        var next = _resetLockedDecision ?? evaluated;
        var previouslyAllowedOrPreserved = previous.MayStartHarness
            || _ownedHostPreservedForUpdate;
        // An update-only deny blocks starts and managed API calls, but it is not
        // authority to terminate a live process and lose in-flight local work.
        // Keep tracking that process so a later security deny or lease deadline
        // still stops it even though the previous decision was already a deny.
        _ownedHostPreservedForUpdate = previouslyAllowedOrPreserved
            && IsUpdateOnlyHold(next);
        if (previouslyAllowedOrPreserved
            && !next.MayStartHarness
            && !_ownedHostPreservedForUpdate)
        {
            _ownedHostStopPending = true;
        }

        if (_resetPendingScope != EnterpriseResetScope.None)
        {
            // A reset is never allowed to race an owned Harness process. This also
            // reasserts the stop before every retry after a partial reset failure.
            _ownedHostStopPending = true;
        }

        _decision = next;
        try
        {
            if (_ownedHostStopPending)
            {
                using var stopTimeout = new CancellationTokenSource(StopOwnedHostTimeout);
                await _host.StopOwnedProcessAsync(stopTimeout.Token).ConfigureAwait(false);
                _ownedHostStopPending = false;
            }

            if (_resetPendingScope != EnterpriseResetScope.None)
            {
                var completedDecision = _resetLockedDecision ?? next;
                _resetExecutor!.Execute(_resetPendingScope);
                _resetExecutor.PersistBarrier(new EnterpriseResetBarrier(
                    completedDecision,
                    ResetCompleted: true));
                _lastCompletedResetDecision = completedDecision;
                _resetPendingScope = EnterpriseResetScope.None;
            }
        }
        finally
        {
            ScheduleLeaseEnforcement();
            if (previous != next)
            {
                NotifyDecisionChanged(next);
            }
        }

        return next;
    }

    private EnterpriseAccessDecision EvaluateCurrentAccess()
    {
        var snapshot = _snapshot;
        if (_trustedTimeStore is null || !RequiresTrustedTime(snapshot))
        {
            return _startupGate.Evaluate(snapshot);
        }

        try
        {
            var persistedFloorUtc = _trustedTimeStore.ReadFloorUtc();
            if (persistedFloorUtc is { } floorUtc
                && floorUtc > snapshot.TrustedTimeFloorUtc)
            {
                snapshot = snapshot with { TrustedTimeFloorUtc = floorUtc };
            }

            var nowUtc = _startupGate.GetUtcNow();
            var evaluated = EnterpriseAccessEvaluator.Evaluate(snapshot, nowUtc);
            if ((evaluated.MayStartHarness || IsUpdateOnlyHold(evaluated))
                && snapshot.LeaseExpiresAtUtc is { } leaseDeadlineUtc)
            {
                var advancedFloorUtc = _trustedTimeStore.Advance(nowUtc, leaseDeadlineUtc);
                if (advancedFloorUtc > snapshot.TrustedTimeFloorUtc)
                {
                    snapshot = snapshot with { TrustedTimeFloorUtc = advancedFloorUtc };
                }
            }

            _snapshot = snapshot;
            return evaluated;
        }
        catch (Exception exception) when (exception is
            CryptographicException
            or InvalidDataException
            or IOException
            or UnauthorizedAccessException)
        {
            // Missing state is valid before the first authorized observation, but
            // unreadable, unauthenticated, or non-atomic state must never preserve
            // an earlier allow decision.
            _snapshot = snapshot with { ClockTrusted = false };
            return new EnterpriseAccessDecision(
                EnterpriseClientState.SecurityQuarantined,
                MayStartHarness: false,
                MayCallManagedApi: false,
                EnterpriseResetScope.None,
                EnterpriseErrorCodes.ClockUntrusted);
        }
    }

    private static bool RequiresTrustedTime(EnterpriseAccessSnapshot snapshot) =>
        snapshot.ClockTrusted
        && snapshot.Employee == EmployeeAuthorizationState.Active
        && snapshot.Device == DeviceBindingState.Active
        && snapshot.LeaseSignatureValid
        && snapshot.AuthorizationEpochMatches
        && snapshot.LeaseExpiresAtUtc is not null;

    private void NotifyDecisionChanged(EnterpriseAccessDecision decision)
    {
        var handlers = DecisionChanged;
        if (handlers is null)
        {
            return;
        }

        foreach (Action<EnterpriseAccessDecision> handler in handlers.GetInvocationList())
        {
            try
            {
                handler(decision);
            }
            catch
            {
                // UI observers cannot interrupt lease enforcement or owned-host shutdown.
            }
        }
    }

    private void ScheduleLeaseEnforcement()
    {
        if (_disposed)
        {
            return;
        }

        var dueTime = Timeout.InfiniteTimeSpan;
        if (_ownedHostStopPending || _resetPendingScope != EnterpriseResetScope.None)
        {
            dueTime = StopRetryDelay;
        }
        else if (_decision.MayStartHarness || _ownedHostPreservedForUpdate)
        {
            dueTime = GetMonotonicLeaseRemaining();
            if (dueTime < TimeSpan.Zero)
            {
                dueTime = TimeSpan.Zero;
            }
        }

        _leaseEnforcementTimer.Change(dueTime, Timeout.InfiniteTimeSpan);
    }

    private void AcceptAppliedLease(EnterpriseAccessDecision evaluatedDecision)
    {
        if ((!evaluatedDecision.MayStartHarness && !IsUpdateOnlyHold(evaluatedDecision))
            || _snapshot.LeaseExpiresAtUtc is not { } expiresAtUtc)
        {
            return;
        }

        var incomingRemaining = expiresAtUtc - _startupGate.GetUtcNow();
        if (incomingRemaining <= TimeSpan.Zero)
        {
            return;
        }

        if (!_hasLeaseAnchor || _snapshot.LeaseIssuedAtUtc > _anchoredLeaseIssuedAtUtc)
        {
            SetLeaseAnchor(_snapshot.LeaseIssuedAtUtc, incomingRemaining);
            return;
        }

        if (incomingRemaining < GetMonotonicLeaseRemaining())
        {
            SetLeaseAnchor(_anchoredLeaseIssuedAtUtc, incomingRemaining);
        }
    }

    private void RegisterResetIfRequired(EnterpriseAccessDecision decision)
    {
        if (_resetExecutor is null)
        {
            return;
        }

        if (decision.ResetScope == EnterpriseResetScope.None)
        {
            if (_resetLockedDecision is not null
                && _resetPendingScope == EnterpriseResetScope.None
                && _lastCompletedResetDecision is not null
                && IsFreshOnlineReady(decision))
            {
                _resetExecutor.ClearBarrier();
                _resetLockedDecision = null;
                _lastCompletedResetDecision = null;
            }
            return;
        }

        if (decision.MayStartHarness || decision.MayCallManagedApi)
        {
            throw new InvalidDataException(
                "An enterprise reset decision cannot retain Harness or managed API access.");
        }

        var lockedScope = _resetLockedDecision?.ResetScope ?? EnterpriseResetScope.None;
        if (_resetPendingScope == EnterpriseResetScope.None
            && _lastCompletedResetDecision is not null
            && ResetScopeRank(lockedScope) >= ResetScopeRank(decision.ResetScope))
        {
            return;
        }

        var pendingScope = MostRestrictiveResetScope(
            _resetPendingScope,
            decision.ResetScope);
        var lockedDecision = _resetLockedDecision is null
            || ResetScopeRank(decision.ResetScope) >= ResetScopeRank(lockedScope)
                ? decision
                : _resetLockedDecision;
        if (_resetPendingScope == pendingScope && _resetLockedDecision == lockedDecision)
        {
            return;
        }

        _resetLockedDecision = lockedDecision;
        _resetPendingScope = pendingScope;
        _lastCompletedResetDecision = null;
        try
        {
            // Persist before stopping the owned Host or deleting any managed state.
            // A crash or restart can therefore never turn a known reset decision
            // back into cached OfflineGrace authorization.
            _resetExecutor.PersistBarrier(new EnterpriseResetBarrier(
                lockedDecision,
                ResetCompleted: false));
        }
        catch
        {
            _decision = lockedDecision;
            _ownedHostStopPending = true;
            throw;
        }
    }

    private bool IsFreshOnlineReady(EnterpriseAccessDecision decision) =>
        _snapshot.ControlPlane == ControlPlaneConnectivity.Available
        && decision.ClientState == EnterpriseClientState.Ready
        && decision.MayStartHarness
        && decision.MayCallManagedApi
        && decision.ResetScope == EnterpriseResetScope.None;

    private static EnterpriseResetScope MostRestrictiveResetScope(
        EnterpriseResetScope current,
        EnterpriseResetScope requested) => (current, requested) switch
        {
            (EnterpriseResetScope.SecurityCredentials, _) =>
                EnterpriseResetScope.SecurityCredentials,
            (_, EnterpriseResetScope.SecurityCredentials) =>
                EnterpriseResetScope.SecurityCredentials,
            (EnterpriseResetScope.ManagedConfig, _) => EnterpriseResetScope.ManagedConfig,
            (_, EnterpriseResetScope.ManagedConfig) => EnterpriseResetScope.ManagedConfig,
            (EnterpriseResetScope.None, EnterpriseResetScope.None) => EnterpriseResetScope.None,
            _ => throw new ArgumentOutOfRangeException(
                nameof(requested),
                requested,
                "Unknown enterprise reset scope."),
        };

    private static int ResetScopeRank(EnterpriseResetScope scope) => scope switch
    {
        EnterpriseResetScope.None => 0,
        EnterpriseResetScope.ManagedConfig => 1,
        EnterpriseResetScope.SecurityCredentials => 2,
        _ => throw new ArgumentOutOfRangeException(
            nameof(scope),
            scope,
            "Unknown enterprise reset scope."),
    };

    private void SetLeaseAnchor(DateTimeOffset issuedAtUtc, TimeSpan duration)
    {
        _anchoredLeaseIssuedAtUtc = issuedAtUtc;
        _leaseAnchorTimestamp = _startupGate.GetTimestamp();
        _leaseDurationFromAnchor = duration;
        _hasLeaseAnchor = true;
    }

    private TimeSpan GetMonotonicLeaseRemaining() => _hasLeaseAnchor
        ? _leaseDurationFromAnchor - _startupGate.GetElapsedTime(_leaseAnchorTimestamp)
        : TimeSpan.Zero;

    private EnterpriseAccessDecision EnforceMonotonicLeaseDeadline(
        EnterpriseAccessDecision evaluatedDecision)
    {
        if ((!evaluatedDecision.MayStartHarness && !IsUpdateOnlyHold(evaluatedDecision))
            || (_hasLeaseAnchor && GetMonotonicLeaseRemaining() > TimeSpan.Zero))
        {
            return evaluatedDecision;
        }

        return new EnterpriseAccessDecision(
            EnterpriseClientState.LeaseExpiredLocked,
            MayStartHarness: false,
            MayCallManagedApi: false,
            EnterpriseResetScope.None,
            EnterpriseErrorCodes.LeaseExpired);
    }

    private static bool IsUpdateOnlyHold(EnterpriseAccessDecision decision) =>
        decision.ClientState == EnterpriseClientState.UpdateRequired
        && !decision.MayStartHarness
        && !decision.MayCallManagedApi
        && decision.ResetScope == EnterpriseResetScope.None;

    private void OnLeaseEnforcementTimer() => _ = EnforceLeaseFromTimerAsync();

    private async Task EnforceLeaseFromTimerAsync()
    {
        try
        {
            await _gate.WaitAsync().ConfigureAwait(false);
            try
            {
                if (_disposed)
                {
                    return;
                }

                await ReevaluateAccessAsync().ConfigureAwait(false);
            }
            finally
            {
                _gate.Release();
            }
        }
        catch
        {
            // ReevaluateAccessAsync keeps a failed stop pending and schedules a bounded retry.
        }
    }
}
