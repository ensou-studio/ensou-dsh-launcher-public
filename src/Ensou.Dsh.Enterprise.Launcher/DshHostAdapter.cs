using System.Collections.ObjectModel;
using Ensou.Dsh.Enterprise.Client;
using Ensou.Dsh.Enterprise.Installation;
using Ensou.Dsh.Host;

namespace Ensou.Dsh.Enterprise.Launcher;

/// <summary>
/// Exact outcome of automatic managed-runtime drain admission. A missing or
/// already-exited owned Runtime is not a drain failure: exclusive staging must
/// still rely on its existing writer and loopback guards.
/// </summary>
public enum ManagedRuntimeUpdateDrainDisposition
{
    NoRuntimeToStop,
    StoppedExactRuntime,
}

internal sealed class DshHostAdapter : IEnterpriseHarnessHost
{
    private readonly object _gate = new();
    private readonly Action _validateRuntime;
    private readonly EnterpriseInstallationLayout _installationLayout;
    private readonly Action<string, Exception?>? _diagnostic;
    private DshRuntimeOptions _runtimeOptions;
    private DshHostService? _hostService;
    private bool _controlledEnvironmentConfigured;
    private bool _disposed;

    public DshHostAdapter(
        DshRuntimeOptions runtimeOptions,
        Action validateRuntime,
        EnterpriseInstallationLayout installationLayout,
        Action<string, Exception?>? diagnostic = null)
    {
        _runtimeOptions = runtimeOptions ?? throw new ArgumentNullException(nameof(runtimeOptions));
        _validateRuntime = validateRuntime
            ?? throw new ArgumentNullException(nameof(validateRuntime));
        _installationLayout = installationLayout
            ?? throw new ArgumentNullException(nameof(installationLayout));
        _diagnostic = diagnostic;
    }

    public Uri WebUiUri
    {
        get
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                return _runtimeOptions.WebUiUri;
            }
        }
    }

    public void ConfigureControlledEnvironment(
        IReadOnlyDictionary<string, string> controlledEnvironment)
    {
        ArgumentNullException.ThrowIfNull(controlledEnvironment);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_hostService is not null || _controlledEnvironmentConfigured)
            {
                throw new InvalidOperationException(
                    "Enterprise DSH provider environment must be configured exactly once before Host creation.");
            }

            _runtimeOptions = _runtimeOptions with
            {
                ControlledEnvironment = new ReadOnlyDictionary<string, string>(
                    new Dictionary<string, string>(
                        controlledEnvironment,
                        StringComparer.Ordinal)),
            };
            _controlledEnvironmentConfigured = true;
        }
    }

    public async Task EnsureStartedAsync(CancellationToken cancellationToken = default)
    {
        _validateRuntime();
        var hostService = GetOrCreateHostService();
        var result = await hostService.EnsureStartedAsync(cancellationToken).ConfigureAwait(false);
        if (!hostService.OwnsRunningProcess)
        {
            throw new InvalidOperationException(
                result.State == DshLaunchState.AlreadyHealthy
                    ? $"Port {_runtimeOptions.Port} is occupied by a DSH process that is not owned by this enterprise Launcher."
                    : "The enterprise Harness process exited before ownership could be confirmed.");
        }
    }

    public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
    {
        var hostService = GetExistingHostService();
        if (hostService is null || !hostService.OwnsRunningProcess)
        {
            return false;
        }

        var healthy = await hostService.IsHealthyAsync(cancellationToken).ConfigureAwait(false);
        return healthy && hostService.OwnsRunningProcess;
    }

    public async Task OpenWebUiAsync(
        CancellationToken cancellationToken = default)
    {
        var hostService = GetExistingHostService();
        if (hostService is null || !hostService.OwnsRunningProcess)
        {
            throw new InvalidOperationException(
                "The enterprise Harness has no healthy Launcher-owned browser session.");
        }

        await hostService.OpenWebUiAsync(cancellationToken).ConfigureAwait(false);
        if (!hostService.OwnsRunningProcess)
        {
            throw new InvalidOperationException(
                "The enterprise Harness exited before its browser session could be opened.");
        }
    }

    public Task StopOwnedProcessAsync(CancellationToken cancellationToken = default)
    {
        var hostService = GetExistingHostService();
        return hostService is null
            ? Task.CompletedTask
            : hostService.StopOwnedProcessAsync(cancellationToken);
    }

    /// <summary>
    /// Attempts the managed update protocol only for the already-retained,
    /// exact Launcher-owned Runtime. This never creates a Host and never falls
    /// back to the manual/security termination path.
    /// </summary>
    internal async Task<ManagedRuntimeUpdateDrainDisposition> TryStopForManagedUpdateAsync(
        Guid operationId,
        CancellationToken cancellationToken = default)
    {
        if (operationId == Guid.Empty)
        {
            throw new ArgumentException(
                "Managed update operation identity must be non-empty.",
                nameof(operationId));
        }

        var hostService = GetExistingHostService();
        if (hostService is null || !hostService.OwnsRunningProcess)
        {
            return ManagedRuntimeUpdateDrainDisposition.NoRuntimeToStop;
        }

        try
        {
            await hostService.StopForManagedUpdateAsync(operationId, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (DshRuntimeUpdateStoppedException exception)
        {
            throw new EnterpriseManagedRuntimeStoppedException(
                exception.OperationId,
                exception);
        }
        return ManagedRuntimeUpdateDrainDisposition.StoppedExactRuntime;
    }

    public ValueTask DisposeAsync()
    {
        DshHostService? hostService;
        lock (_gate)
        {
            if (_disposed)
            {
                return ValueTask.CompletedTask;
            }

            _disposed = true;
            hostService = _hostService;
        }

        return hostService?.DisposeAsync() ?? ValueTask.CompletedTask;
    }

    private DshHostService GetOrCreateHostService()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _hostService ??= new DshHostService(
                _runtimeOptions,
                _validateRuntime,
                httpClient: null,
                healthProbeTimeout: null,
                candidateHealthRetryTimeout: null,
                validateBeforeResume: _ => EnterpriseLegacySqliteUpgradeGuard
                    .RequireJsonlOnlyHarnessHome(_installationLayout),
                acquireHomeWriterSession: null,
                diagnostic: _diagnostic);
        }
    }

    private DshHostService? GetExistingHostService()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _hostService;
        }
    }
}
