using Ensou.Dsh.Enterprise.Client;
using Ensou.Dsh.Enterprise.Launcher;

namespace Ensou.Dsh.Enterprise.DevelopmentE2ETests;

/// <summary>
/// Test-local view of a Harness host that records calls while always delegating
/// process ownership to the production enterprise Host adapter.
/// </summary>
internal interface IRuntimeHarnessHost : IEnterpriseHarnessHost
{
    int StartCount { get; }

    int StopCount { get; }
}

/// <summary>
/// Defers creating the production adapter until the real gateway-controlled
/// environment is available. It never supplies a substitute process or health
/// result.
/// </summary>
internal sealed class ActualRuntimeHarnessHost(
    Func<DshHostAdapter> createAdapter) : IRuntimeHarnessHost
{
    private readonly Func<DshHostAdapter> _createAdapter = createAdapter
        ?? throw new ArgumentNullException(nameof(createAdapter));
    private DshHostAdapter? _adapter;
    private bool _disposed;

    public int StartCount { get; private set; }

    public int StopCount { get; private set; }

    public Uri WebUiUri => RequireAdapter().WebUiUri;

    public void ConfigureControlledEnvironment(
        IReadOnlyDictionary<string, string> controlledEnvironment)
    {
        ArgumentNullException.ThrowIfNull(controlledEnvironment);
        RequireAdapter().ConfigureControlledEnvironment(controlledEnvironment);
    }

    public async Task EnsureStartedAsync(CancellationToken cancellationToken = default)
    {
        await RequireAdapter().EnsureStartedAsync(cancellationToken).ConfigureAwait(false);
        StartCount++;
    }

    public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) =>
        RequireAdapter().IsHealthyAsync(cancellationToken);

    public Task OpenWebUiAsync(CancellationToken cancellationToken = default) =>
        RequireAdapter().OpenWebUiAsync(cancellationToken);

    public async Task StopOwnedProcessAsync(CancellationToken cancellationToken = default)
    {
        await RequireAdapter().StopOwnedProcessAsync(cancellationToken).ConfigureAwait(false);
        StopCount++;
    }

    public async Task<EnterpriseManagedRuntimeDrainDisposition>
        StopForManagedUpdateAsync(Guid operationId, CancellationToken cancellationToken = default)
    {
        var result = await RequireAdapter().TryStopForManagedUpdateAsync(
                operationId,
                cancellationToken)
            .ConfigureAwait(false);
        if (result == ManagedRuntimeUpdateDrainDisposition.StoppedExactRuntime)
        {
            StopCount++;
            return EnterpriseManagedRuntimeDrainDisposition.StoppedExactRuntime;
        }
        return EnterpriseManagedRuntimeDrainDisposition.NoRuntimeToStop;
    }

    public ValueTask DisposeAsync()
    {
        _disposed = true;
        return _adapter?.DisposeAsync() ?? ValueTask.CompletedTask;
    }

    private DshHostAdapter RequireAdapter()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _adapter ??= _createAdapter();
    }
}
