using System.Runtime.ExceptionServices;
using Ensou.Dsh.Host;

namespace Ensou.Dsh.Launcher;

internal enum PersonalManagedRuntimeUpdateDisposition
{
    Staged,
    DeferredUnsupportedRuntime,
    DeferredStageBoundary,
}

/// <summary>
/// Coordinates the Personal Launcher-owned runtime drain around an already
/// authenticated, signed release stage. The Host owns the drain protocol;
/// this class only restores the prior exact runtime when staging does not
/// complete after a successful stop.
/// </summary>
internal sealed class PersonalManagedRuntimeUpdateCoordinator
{
    private readonly bool _runtimeSupportsManagedUpdate;
    private readonly Func<bool> _ownsRuntime;
    private readonly Func<Guid, CancellationToken, Task> _drainRuntime;
    private readonly Func<CancellationToken, Task> _restoreRuntime;

    internal PersonalManagedRuntimeUpdateCoordinator(
        bool runtimeSupportsManagedUpdate,
        Func<bool> ownsRuntime,
        Func<Guid, CancellationToken, Task> drainRuntime,
        Func<CancellationToken, Task> restoreRuntime)
    {
        _runtimeSupportsManagedUpdate = runtimeSupportsManagedUpdate;
        _ownsRuntime = ownsRuntime ?? throw new ArgumentNullException(nameof(ownsRuntime));
        _drainRuntime = drainRuntime ?? throw new ArgumentNullException(nameof(drainRuntime));
        _restoreRuntime = restoreRuntime ?? throw new ArgumentNullException(nameof(restoreRuntime));
    }

    internal async Task<PersonalManagedRuntimeUpdateDisposition> RunAsync(
        Func<CancellationToken, Task<bool>> stage,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stage);

        if (!_ownsRuntime())
        {
            return await RunStageAsync(stage, cancellationToken).ConfigureAwait(false);
        }
        if (!_runtimeSupportsManagedUpdate)
        {
            return PersonalManagedRuntimeUpdateDisposition.DeferredUnsupportedRuntime;
        }

        var restoreStoppedRuntime = false;
        Exception? failure = null;
        PersonalManagedRuntimeUpdateDisposition? disposition = null;
        try
        {
            try
            {
                await _drainRuntime(Guid.NewGuid(), cancellationToken).ConfigureAwait(false);
                restoreStoppedRuntime = true;
            }
            catch (DshRuntimeUpdateStoppedException)
            {
                // The Host observed the exact process exit despite a late
                // protocol failure, so recovery must restart it.
                restoreStoppedRuntime = true;
                throw;
            }

            disposition = await RunStageAsync(stage, cancellationToken).ConfigureAwait(false);
            if (disposition == PersonalManagedRuntimeUpdateDisposition.Staged)
            {
                // The successful stage owns the successor through the stable
                // Launcher restart path; never reopen the old Runtime.
                restoreStoppedRuntime = false;
            }
        }
        catch (Exception exception)
        {
            failure = exception;
        }

        if (restoreStoppedRuntime)
        {
            try
            {
                await _restoreRuntime(CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception recoveryFailure)
            {
                if (failure is not null)
                {
                    throw new AggregateException(
                        "Personal managed-update recovery could not restart the prior exact runtime.",
                        failure,
                        recoveryFailure);
                }
                throw;
            }
        }

        if (failure is not null)
        {
            ExceptionDispatchInfo.Capture(failure).Throw();
        }
        return disposition ?? throw new InvalidOperationException(
            "Personal managed-update stage did not produce a disposition.");
    }

    private static async Task<PersonalManagedRuntimeUpdateDisposition> RunStageAsync(
        Func<CancellationToken, Task<bool>> stage,
        CancellationToken cancellationToken) =>
        await stage(cancellationToken).ConfigureAwait(false)
            ? PersonalManagedRuntimeUpdateDisposition.Staged
            : PersonalManagedRuntimeUpdateDisposition.DeferredStageBoundary;
}
