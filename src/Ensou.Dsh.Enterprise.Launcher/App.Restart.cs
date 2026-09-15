using System.Diagnostics;
using System.IO;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.Enterprise.Installation;
using Ensou.Dsh.Host;

namespace Ensou.Dsh.Enterprise.Launcher;

public partial class App
{
    private LauncherRestartReceiverLease? _incomingRestartHandoff;
    private LauncherRestartHandoffLease? _outgoingRestartHandoff;
    private readonly LauncherRestartOperationGate _restartOperationGate = new();
#if ENTERPRISE_DEVELOPMENT_E2E
    private EnterpriseDevelopmentHealthDiagnostics? _restartDiagnostics;
#endif

    [Conditional("ENTERPRISE_DEVELOPMENT_E2E")]
    private void TraceEnterpriseRestart(string stage, Exception? exception = null)
    {
#if ENTERPRISE_DEVELOPMENT_E2E
        try
        {
            _restartDiagnostics ??= new EnterpriseDevelopmentHealthDiagnostics(
                EnterpriseBuildProfile.CreateInstallationLayout(), "launcher");
            _restartDiagnostics.Mark(stage, exception);
        }
        catch
        {
            // Development observations must not alter restart ownership or admission.
        }
#endif
    }

    private async Task RestartThroughStableBootstrapperAsync(EnterpriseInstallationLayout layout)
    {
        if (!_restartOperationGate.TryEnter(out var operation))
        {
            throw new InvalidOperationException("Enterprise restart handoff is already running.");
        }
        using var activeOperation = operation!;
        TraceEnterpriseRestart("restart-begin");
        EnterpriseStableBootstrapperVerifier.RequireTrusted(layout);
        using var trustedEntry = EnterpriseAuthenticodeVerifier.OpenTrustedExecutableForLaunch(
            layout.BootstrapperPath, layout);

        // Health runs before the receiver handshake so the handshake budget does
        // not include cold-start Runtime validation or a pending-release rollback.
        TraceEnterpriseRestart("restart-health-begin");
        await CompletePendingHealthAsync(layout, trustedEntry);
        TraceEnterpriseRestart("restart-health-complete");
        var profile = EnterpriseBuildProfile.CreateReleaseUpdateProfile()
            ?? throw new InvalidOperationException("Enterprise restart requires compiled release trust.");
        var store = new EnterpriseReleaseSetPointerStore(layout,
            new EnterpriseCompiledReleaseTrust(profile.ManifestUri, profile.TrustPolicy));
        var pointer = store.ReadRequired();
        if (pointer.Current.HealthState != EnterpriseReleaseHealthStates.Healthy)
        {
            throw new InvalidDataException("Enterprise restart requires a healthy active release.");
        }
        var launcherPath = Path.Combine(pointer.Current.Launcher.Directory,
            EnterpriseInstallationLayout.LauncherExecutableName);
        using var expectedReceiver = EnterpriseAuthenticodeVerifier.OpenTrustedExecutableForLaunch(
            launcherPath, layout);
        TraceEnterpriseRestart("restart-handoff-begin");
        var attempt = await LauncherRestartCoordinator.TryStartAsync(
            () => layout.BootstrapperPath,
            () => Task.CompletedTask,
            startInfo => EnterpriseLegacySqliteUpgradeGuard.StartProcessWithJsonlOnlyHarnessHomeAdmission(
                layout, () => trustedEntry.Start(startInfo)),
            ReleaseSingleInstanceForHandoff,
            TryReacquireSingleInstance,
            Environment.ProcessId,
            validateReceiverProcess: expectedReceiver.RequireProcessImage,
            backgroundStartup: _backgroundStartup || _launcherWindow?.IsVisible != true,
            handoffScope: LauncherRestartHandoffScope.Enterprise);
        if (!attempt.ReadyForParentExit)
        {
            TraceEnterpriseRestart(attempt.ParentOwnershipProven
                ? "restart-handoff-refused-owner-retained"
                : "restart-handoff-refused-owner-unproven");
            if (!attempt.ParentOwnershipProven)
            {
                // No callback may restore managed access without singleton ownership.
                _shutdownRequested = true;
                Shutdown(1);
            }
            throw new InvalidOperationException(attempt.Failure ?? "Enterprise restart receiver did not become ready.");
        }
        _outgoingRestartHandoff = attempt.Handoff;
        TraceEnterpriseRestart("restart-handoff-ready");
    }

    private static async Task CompletePendingHealthAsync(
        EnterpriseInstallationLayout layout,
        EnterpriseTrustedExecutableLaunchLease trustedEntry,
        CancellationToken cancellationToken = default)
    {
        EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHomeAndNoWriter(layout);
        var startInfo = new ProcessStartInfo
        {
            FileName = layout.BootstrapperPath,
            WorkingDirectory = layout.ManagedRoot,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        startInfo.ArgumentList.Add("--complete-pending-health");
        using var started = trustedEntry.StartContained(startInfo,
            _ => EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHome(layout));
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(EnterpriseBootstrapHealthGate.ColdStartTimeout + TimeSpan.FromMinutes(2));
        try
        {
            await started.Process.WaitForExitAsync(timeout.Token);
        }
        catch
        {
            started.TerminateRequired();
            throw;
        }
        var exitCode = started.Process.ExitCode;
        started.CompleteRequired();
        if (exitCode != 0)
        {
            throw new InvalidOperationException("Enterprise pending-release health did not complete successfully.");
        }
    }

    private void CommitRestartAndShutdown()
    {
        if (_outgoingRestartHandoff is null)
        {
            throw new InvalidOperationException("Enterprise shutdown has no admitted restart receiver.");
        }
        _shutdownRequested = true;
        TraceEnterpriseRestart("restart-parent-shutdown");
        try
        {
            // OnExit commits the lease. A rejected shutdown can still cancel the
            // uncommitted receiver and restore the old instance's ownership.
            Shutdown(0);
        }
        catch
        {
            var ownership = _outgoingRestartHandoff.CancelAndReacquire();
            _outgoingRestartHandoff.Dispose();
            _outgoingRestartHandoff = null;
            _shutdownRequested = !ownership.ParentOwnershipProven;
            if (!ownership.ParentOwnershipProven) Shutdown(1);
            throw;
        }
    }

    private void ReleaseSingleInstanceForHandoff() => Dispatcher.Invoke(() =>
    {
        if (_singleInstanceMutex is null || !_ownsSingleInstanceMutex)
        {
            throw new InvalidOperationException("Enterprise Launcher does not own the singleton mutex.");
        }
        _singleInstanceMutex.ReleaseMutex();
        _ownsSingleInstanceMutex = false;
    });

    private bool TryReacquireSingleInstance(TimeSpan timeout) => Dispatcher.Invoke(() =>
    {
        if (_ownsSingleInstanceMutex) return true;
        if (_singleInstanceMutex is null) return false;
        try { _ownsSingleInstanceMutex = _singleInstanceMutex.WaitOne(timeout); }
        catch (AbandonedMutexException) { _ownsSingleInstanceMutex = true; }
        return _ownsSingleInstanceMutex;
    });

    private void BeginIncomingRestartHandoff()
    {
        var receiver = _incomingRestartHandoff
            ?? throw new InvalidOperationException("Enterprise incoming restart receiver is missing.");
        TraceEnterpriseRestart("restart-receiver-ready");
        receiver.MarkReady();
        _ = CompleteIncomingRestartHandoffAsync(receiver);
    }

    private async Task CompleteIncomingRestartHandoffAsync(LauncherRestartReceiverLease receiver)
    {
        try
        {
            var outcome = await receiver.WaitForParentExitAsync();
            TraceEnterpriseRestart(outcome == LauncherRestartReceiverOutcome.AbortRequested
                ? "restart-receiver-abort" : "restart-receiver-parent-exited");
            if (outcome == LauncherRestartReceiverOutcome.AbortRequested)
            {
                ReleaseSingleInstanceForHandoff();
                receiver.SignalReleased();
                var rollback = await receiver.WaitForRollbackOwnedOrParentExitAsync();
                if (rollback == LauncherRestartRollbackOutcome.RollbackOwned)
                {
                    Shutdown(1);
                    return;
                }
                if (!TryReacquireSingleInstance(Timeout.InfiniteTimeSpan))
                {
                    throw new InvalidOperationException("Enterprise receiver could not acquire ownership after parent exit.");
                }
            }
            if (!ReferenceEquals(_incomingRestartHandoff, receiver))
            {
                throw new InvalidOperationException("Enterprise incoming restart receiver changed before takeover.");
            }
            _incomingRestartHandoff = null;
            receiver.Dispose();
            TraceEnterpriseRestart("restart-receiver-takeover");
            if (_trayIcon is not null) _trayIcon.Visible = true;
#if ENTERPRISE_DEVELOPMENT_E2E
            EnterpriseDevelopmentRestartDiagnostics.EmitAfterParentExit(
                EnterpriseBuildProfile.CreateInstallationLayout(),
                _backgroundStartup,
                receiver.ParentProcessId);
            TraceEnterpriseRestart("restart-receiver-receipt-written");
#endif
            if (_backgroundStartup) BeginBackgroundInitialization();
            else ShowLauncher();
        }
        catch (Exception exception)
        {
            TraceEnterpriseRestart("restart-receiver-failed", exception);
            receiver.TrySignalFailure();
            Shutdown(1);
        }
    }
}
