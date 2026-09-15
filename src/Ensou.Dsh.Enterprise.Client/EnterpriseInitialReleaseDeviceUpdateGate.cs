using Ensou.Dsh.Enterprise.Contracts;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.Client;

/// <summary>
/// Completes the first signed release only after binding or refresh has durably
/// committed the verified lease and installed its process-local access token.
/// The ordinary device policy/receipt gate remains the only path to Ready.
/// </summary>
public sealed class EnterpriseInitialReleaseDeviceUpdateGate : IEnterpriseDeviceUpdateGate
{
    private readonly IEnterpriseDeviceUpdateGate _inner;
    private readonly Func<EnterpriseReleaseSetPointer> _readPointer;
    private readonly Func<CancellationToken, Task> _stageAsync;
    private readonly Func<EnterpriseReleaseSetPointer, EnterpriseActivePluginPolicy> _readPolicy;
    private readonly Func<CancellationToken, Task> _completePendingHealthAsync;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private int _requiresLauncherRestart;

    public EnterpriseInitialReleaseDeviceUpdateGate(
        EnterpriseInstallationLayout layout,
        EnterpriseCompiledReleaseTrust compiledTrust,
        IEnterpriseDeviceUpdateGate inner,
        Func<HttpClient> authenticatedTransactionClientFactory,
        Func<CancellationToken, Task> completePendingHealthAsync,
        int harnessPort = 3080,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(compiledTrust);
        ArgumentNullException.ThrowIfNull(authenticatedTransactionClientFactory);
        compiledTrust.Validate(layout);
        var store = new EnterpriseReleaseSetPointerStore(layout, compiledTrust);
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _readPointer = store.ReadRequired;
        _readPolicy = store.ReadActivePluginPolicyRequired;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _completePendingHealthAsync = completePendingHealthAsync
            ?? throw new ArgumentNullException(nameof(completePendingHealthAsync));
        _stageAsync = async cancellationToken =>
        {
            using var client = authenticatedTransactionClientFactory()
                ?? throw new InvalidOperationException("Initial release requires an authenticated transaction client.");
            _ = await new EnterpriseReleaseStartupCoordinator(
                    layout, compiledTrust.ManifestUri, compiledTrust.Policy, client,
                    _timeProvider, harnessPort)
                .CheckOnEveryStartupAsync(cancellationToken).ConfigureAwait(false);
        };
    }

    internal EnterpriseInitialReleaseDeviceUpdateGate(
        IEnterpriseDeviceUpdateGate inner,
        Func<EnterpriseReleaseSetPointer> readPointer,
        Func<CancellationToken, Task> stageAsync,
        Func<EnterpriseReleaseSetPointer, EnterpriseActivePluginPolicy> readPolicy,
        Func<CancellationToken, Task> completePendingHealthAsync,
        TimeProvider? timeProvider = null)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _readPointer = readPointer ?? throw new ArgumentNullException(nameof(readPointer));
        _stageAsync = stageAsync ?? throw new ArgumentNullException(nameof(stageAsync));
        _readPolicy = readPolicy ?? throw new ArgumentNullException(nameof(readPolicy));
        _completePendingHealthAsync = completePendingHealthAsync
            ?? throw new ArgumentNullException(nameof(completePendingHealthAsync));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    // A process that opened the enrollment shell at sequence zero captured no
    // usable policy/Host. It must restart through the stable entry after success.
    public bool RequiresLauncherRestart => Volatile.Read(ref _requiresLauncherRestart) != 0;

    public async Task<EnterpriseAccessSnapshot> EvaluateBeforeReadyAsync(
        EnterpriseAccessSnapshot authorizedSnapshot,
        string bindingId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authorizedSnapshot);
        EnterpriseBindingValidation.CanonicalizeUuid(bindingId, nameof(bindingId));
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var before = _readPointer();
            var isInitial = IsInitial(before.Current) && before.Previous is null;
            var isInitialPending = IsFirstPending(before);
            if (isInitial || isInitialPending)
            {
                RequireOnlineDirectAuthorization(authorizedSnapshot);
                // Remember the stale enrollment shell before any commit can
                // race cancellation. This is not approval: the UI restarts only
                // after the unchanged inner gate has produced a Ready session.
                Interlocked.Exchange(ref _requiresLauncherRestart, 1);
                if (isInitial)
                {
                    await _stageAsync(cancellationToken).ConfigureAwait(false);
                }
                cancellationToken.ThrowIfCancellationRequested();
                var staged = _readPointer();
                if (!IsFirstPending(staged))
                {
                    throw new InvalidDataException("Initial signed release was not staged for real health verification.");
                }
                RequirePolicyBinding(staged, authorizedSnapshot);
                await _completePendingHealthAsync(cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                var healthy = _readPointer();
                if (healthy.Current.HealthState != EnterpriseReleaseHealthStates.Healthy
                    || healthy.Current.HealthToken is not null
                    || !SameRelease(staged.Current, healthy.Current))
                {
                    throw new InvalidDataException("Initial release health did not confirm the exact staged release.");
                }
                RequirePolicyBinding(healthy, authorizedSnapshot);
            }
            // Never manufacture update-policy approval or an installed receipt.
            return await _inner.EvaluateBeforeReadyAsync(
                authorizedSnapshot, bindingId, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    private void RequireOnlineDirectAuthorization(EnterpriseAccessSnapshot snapshot)
    {
        var decision = EnterpriseAccessEvaluator.Evaluate(snapshot, _timeProvider.GetUtcNow());
        if (snapshot.RuntimeProfile != "enterprise-direct-local"
            || snapshot.ApiProvider != "deepseek"
            || snapshot.ControlPlane != ControlPlaneConnectivity.Available
            || decision.ClientState != EnterpriseClientState.Ready
            || !decision.MayStartHarness || !decision.MayCallManagedApi)
        {
            throw new InvalidDataException("Initial release preparation requires a freshly verified online direct-local authorization.");
        }
    }

    private void RequirePolicyBinding(
        EnterpriseReleaseSetPointer pointer, EnterpriseAccessSnapshot snapshot)
    {
        _readPolicy(pointer).RequireLeaseBinding(
            snapshot.PluginPolicyId ?? throw new InvalidDataException("Signed plugin policy identity is missing."),
            snapshot.PluginPolicyGeneration ?? throw new InvalidDataException("Signed plugin policy generation is missing."),
            snapshot.PluginPolicySha256 ?? throw new InvalidDataException("Signed plugin policy digest is missing."));
    }

    private static bool IsFirstPending(EnterpriseReleaseSetPointer pointer) =>
        pointer.Current.HealthState == EnterpriseReleaseHealthStates.Pending
        && pointer.Current.Generation > 0 && pointer.Current.Sequence > 0
        && pointer.Current.PluginPolicy is not null
        && pointer.Current.HealthToken is not null
        && pointer.Previous is { } previous && IsInitial(previous);

    private static bool IsInitial(EnterpriseReleaseSetReference current) =>
        current.Generation == 0 && current.Sequence == 0 && current.MinAcceptedSequence == 0
        && current.PluginPolicy is null
        && current.HealthState == EnterpriseReleaseHealthStates.Healthy
        && current.HealthToken is null;

    private static bool SameRelease(EnterpriseReleaseSetReference left, EnterpriseReleaseSetReference right) =>
        left.ReleaseSetId == right.ReleaseSetId && left.Generation == right.Generation
        && left.Sequence == right.Sequence && left.MinAcceptedSequence == right.MinAcceptedSequence
        && left.StartupStub == right.StartupStub && left.Launcher == right.Launcher
        && left.Runtime == right.Runtime && left.PluginPolicy == right.PluginPolicy;
}
