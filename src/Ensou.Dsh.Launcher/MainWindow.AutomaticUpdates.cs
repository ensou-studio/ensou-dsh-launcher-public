using System.Net.NetworkInformation;
using System.Diagnostics;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.Launcher;

public partial class MainWindow
{
    private AutomaticUpdateScheduler? _automaticUpdateScheduler;
    private PersonalUpdateCheckOutcomeV2? _automaticPendingOutcome;
    private PersonalAcquiredReleaseSet? _automaticPendingPackages;
    private long _automaticNextDiscoveryTimestamp;
    private long _automaticOperationGeneration;
    private int _automaticUpdatesClosed;

    private void InitializeAutomaticUpdates()
    {
        if (Volatile.Read(ref _automaticUpdatesClosed) != 0
            || _automaticUpdateScheduler is not null)
            return;

        var scheduler = new AutomaticUpdateScheduler(
            RunAutomaticUpdateAsync,
            new AutomaticUpdateSchedulerOptions { Period = TimeSpan.FromMinutes(5) });
        _automaticUpdateScheduler = scheduler;
        var subscribed = false;
        try
        {
            NetworkChange.NetworkAvailabilityChanged += OnNetworkAvailabilityChanged;
            subscribed = true;
            scheduler.Start();
        }
        catch
        {
            if (subscribed)
                NetworkChange.NetworkAvailabilityChanged -= OnNetworkAvailabilityChanged;
            scheduler.Dispose();
            _automaticUpdateScheduler = null;
            throw;
        }
    }

    private void OnNetworkAvailabilityChanged(object? sender, NetworkAvailabilityEventArgs args)
    {
        if (args.IsAvailable && Volatile.Read(ref _automaticUpdatesClosed) == 0)
            _automaticUpdateScheduler?.NotifyReconnect();
    }

    private void ShutdownAutomaticUpdates()
    {
        Interlocked.Exchange(ref _automaticUpdatesClosed, 1);
        NetworkChange.NetworkAvailabilityChanged -= OnNetworkAvailabilityChanged;
        _automaticUpdateScheduler?.Dispose();
        _automaticUpdateScheduler = null;
    }

    private async Task<AutomaticUpdatePipelineResult> RunAutomaticUpdateAsync(
        AutomaticUpdateTrigger trigger,
        CancellationToken cancellationToken)
    {
        var ownsUiOperation = false;
        var operationGeneration = Interlocked.Increment(ref _automaticOperationGeneration);
        try
        {
            if (Volatile.Read(ref _automaticUpdatesClosed) != 0)
                return AutomaticUpdatePipelineResult.Success;
            ownsUiOperation = await Dispatcher.InvokeAsync(() =>
            {
                if (_operationRunning)
                    return false;
                _operationRunning = true;
                PrimaryActionButton.IsEnabled = false;
                return true;
            }, System.Windows.Threading.DispatcherPriority.Normal, cancellationToken);
            if (!ownsUiOperation)
                return AutomaticUpdatePipelineResult.DeferredBusy;

            var restartRequired = await Dispatcher.InvokeAsync(
                () => _restartRequired,
                System.Windows.Threading.DispatcherPriority.Normal,
                cancellationToken);
            if (restartRequired)
            {
                if (_developmentLiveUpdate is not null)
                {
                    if (_hostService.OwnsRunningProcess)
                    {
                        throw new InvalidOperationException(
                            "Personal development live-update retry reopened the old Runtime.");
                    }
                    _developmentLiveUpdate.RecordPhase("retry-old-runtime-still-stopped");
                }
                var restartDisposition = await _managedRuntimeUpdate.RunAsync(
                        stageCancellationToken =>
                            RequireAutomaticStageBoundaryAsync(stageCancellationToken),
                        cancellationToken)
                    .ConfigureAwait(false);
                if (restartDisposition is not PersonalManagedRuntimeUpdateDisposition.Staged)
                    return AutomaticUpdatePipelineResult.DeferredBusy;
                return await RestartAutomaticallyAsync(cancellationToken).ConfigureAwait(false);
            }

            if (_developmentLiveUpdate is null
                && !TrustedReleaseKeyProvider.IsProductionTrustCompiled
                && string.IsNullOrWhiteSpace(_settings.ManifestUrl))
            {
                var releaseDecision = await EvaluateActiveReleaseAsync().ConfigureAwait(false);
                await Dispatcher.InvokeAsync(() =>
                {
                    AvailableVersionText.Text = "更新源待配置";
                    SetStatus(
                        releaseDecision is { Allowed: false }
                            ? "当前版本需要受信更新源确认"
                            : "可以启动本机 DSH",
                        releaseDecision is { Allowed: false }
                            ? releaseDecision.Reason
                            : $"个人版更新源尚未写入配置：{LauncherSettings.SettingsPath()}",
                        0);
                    LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} 已跳过在线检查";
                }, System.Windows.Threading.DispatcherPriority.Normal, cancellationToken);
                return AutomaticUpdatePipelineResult.Success;
            }

            var pendingOutcome = _automaticPendingOutcome;
            var pendingPackages = _automaticPendingPackages;
            if (trigger == AutomaticUpdateTrigger.Retry
                && pendingOutcome is not null
                && pendingPackages is not null
                && Stopwatch.GetTimestamp() < Volatile.Read(ref _automaticNextDiscoveryTimestamp)
                && _hostService.OwnsRunningProcess)
            {
                await ShowWaitingForStoppedDshAsync(cancellationToken).ConfigureAwait(false);
                return AutomaticUpdatePipelineResult.DeferredBusy;
            }

            var outcome = await CheckPersonalUpdateAsync(cancellationToken)
                .ConfigureAwait(false);
            Volatile.Write(
                ref _automaticNextDiscoveryTimestamp,
                Stopwatch.GetTimestamp() + (long)(Stopwatch.Frequency * TimeSpan.FromMinutes(5).TotalSeconds));
            await Dispatcher.InvokeAsync(() =>
            {
                AvailableVersionText.Text = outcome.AvailableVersion;
                SetStatus(outcome.Title, outcome.Detail, outcome.UpdateAvailable ? 35 : 100);
                PrimaryActionButton.Content = outcome.UpdateAvailable ? "下载更新" : "启动 DSH";
                PrimaryActionButton.Tag = outcome.UpdateAvailable ? outcome : null;
                LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} 自动检查完成";
            }, System.Windows.Threading.DispatcherPriority.Normal, cancellationToken);

            if (!outcome.UpdateAvailable)
            {
                _automaticPendingOutcome = null;
                _automaticPendingPackages = null;
                return AutomaticUpdatePipelineResult.Success;
            }

            var samePendingRelease = pendingOutcome is not null
                && pendingPackages is not null
                && string.Equals(
                    pendingOutcome.Verified.CanonicalSignedManifestSha256,
                    outcome.Verified.CanonicalSignedManifestSha256,
                    StringComparison.Ordinal);
            var downloadProgress = new Progress<double>(value => PostAutomaticUi(operationGeneration, cancellationToken, () =>
            {
                UpdateProgress.Value = Math.Clamp(value * 50, 0, 50);
                StatusDetailText.Text = $"更新包已下载 {value * 100:N0}%";
            }));
            var packages = samePendingRelease
                ? pendingPackages!
                : await DownloadPersonalUpdateAsync(
                        outcome, downloadProgress, cancellationToken)
                    .ConfigureAwait(false);
            _automaticPendingOutcome = outcome;
            _automaticPendingPackages = packages;

            var installProgress = new Progress<double>(value => PostAutomaticUi(operationGeneration, cancellationToken, () =>
            {
                UpdateProgress.Value = Math.Clamp(50 + (value * 50), 50, 100);
                StatusDetailText.Text = $"正在安装不可变 release-set {outcome.Verified.Manifest.ReleaseSetId}…";
            }));

            PersonalReleaseSetInstallationResult? installation = null;
            var stageDisposition = await _managedRuntimeUpdate.RunAsync(
                    async stageCancellationToken =>
                    {
                        if (!await RequireAutomaticStageBoundaryAsync(stageCancellationToken)
                                .ConfigureAwait(false))
                        {
                            return false;
                        }

                        // StageAsync revalidates authenticated metadata and owns the
                        // update/home/port writer gates. Foreign live writers fail closed.
                        installation = await StagePersonalUpdateAsync(
                                outcome,
                                packages,
                                installProgress,
                                stageCancellationToken)
                            .ConfigureAwait(false);
                        return true;
                    },
                    cancellationToken)
                .ConfigureAwait(false);
            if (stageDisposition is PersonalManagedRuntimeUpdateDisposition.DeferredUnsupportedRuntime
                or PersonalManagedRuntimeUpdateDisposition.DeferredStageBoundary)
            {
                await ShowWaitingForStoppedDshAsync(cancellationToken).ConfigureAwait(false);
                return AutomaticUpdatePipelineResult.DeferredBusy;
            }
            if (installation is null)
            {
                throw new InvalidOperationException(
                    "Personal managed-update stage completed without an installation result.");
            }
            _automaticPendingOutcome = null;
            _automaticPendingPackages = null;

            await Dispatcher.InvokeAsync(() =>
            {
                _restartRequired = true;
                PrimaryActionButton.Content = "重启并应用";
                PrimaryActionButton.Tag = installation;
                SetStatus(
                    "更新已安装，正在安全重启",
                    "Startup Stub 将重新验证 Runtime/WebUI 后再原子提交。",
                    100);
            }, System.Windows.Threading.DispatcherPriority.Normal, cancellationToken);

            return await RestartAutomaticallyAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return AutomaticUpdatePipelineResult.Success;
        }
        catch
        {
            _automaticPendingOutcome = null;
            _automaticPendingPackages = null;
            await ShowAutomaticFailureAsync();
            return AutomaticUpdatePipelineResult.Failure;
        }
        finally
        {
            Interlocked.CompareExchange(
                ref _automaticOperationGeneration,
                operationGeneration + 1,
                operationGeneration);
            if (ownsUiOperation)
            {
                try
                {
                    await Dispatcher.InvokeAsync(() =>
                    {
                        _operationRunning = false;
                        PrimaryActionButton.IsEnabled = true;
                    });
                }
                catch
                {
                    // Window shutdown owns final cleanup.
                }
            }
        }
    }

    private async Task<AutomaticUpdatePipelineResult> RestartAutomaticallyAsync(
        CancellationToken cancellationToken)
    {
        var restarted = await Dispatcher.InvokeAsync(
            () => ((App)System.Windows.Application.Current).RestartLauncherAsync(),
            System.Windows.Threading.DispatcherPriority.Normal,
            cancellationToken).Task.Unwrap().ConfigureAwait(false);
        return restarted
            ? AutomaticUpdatePipelineResult.Success
            : AutomaticUpdatePipelineResult.Failure;
    }

    private async Task<bool> RequireAutomaticStageBoundaryAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            RequireAutomaticStageBoundary(
                _settings.DshDataDirectory,
                _settings.Port);
            return true;
        }
        catch (InvalidOperationException)
        {
            await ShowWaitingForStoppedDshAsync(cancellationToken).ConfigureAwait(false);
            return false;
        }
    }

    internal static void RequireAutomaticStageBoundary(
        string harnessHome,
        int port,
        Action<int>? requireAvailableLoopbackPort = null,
        Action<int>? requireLegacyWriterQuiescence = null)
    {
        requireAvailableLoopbackPort ??=
            PersonalHarnessWriterGuard.RequireAvailableLoopbackPort;
        requireLegacyWriterQuiescence ??=
            PersonalHarnessWriterGuard.RequireQuiescentLoopbackPort;

        using var lease = new PersonalHarnessHomeCoordinator(harnessHome)
            .AcquireLease(() => requireLegacyWriterQuiescence(port));
        lease.RequireMutationAdmission(harnessHome);
        requireAvailableLoopbackPort(port);
    }

    private async Task ShowWaitingForStoppedDshAsync(CancellationToken cancellationToken) =>
        await Dispatcher.InvokeAsync(() => SetStatus(
            "更新已下载，等待 DSH 停止",
            "不会强制停止正在运行的 DSH；支持的版本会先安全排空，否则等待其停止。",
            50), System.Windows.Threading.DispatcherPriority.Normal, cancellationToken);

    private async Task ShowAutomaticFailureAsync()
    {
        try
        {
            await Dispatcher.InvokeAsync(() =>
            {
                SetStatus("自动更新暂时失败", "已保留当前版本，将按退避策略重试。", 0);
                LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} 自动更新等待重试";
            });
        }
        catch
        {
            // Window shutdown owns final cleanup.
        }
    }

    private void PostAutomaticUi(
        long operationGeneration,
        CancellationToken cancellationToken,
        Action action)
    {
        if (cancellationToken.IsCancellationRequested
            || operationGeneration != Volatile.Read(ref _automaticOperationGeneration)
            || Volatile.Read(ref _automaticUpdatesClosed) != 0
            || Dispatcher.HasShutdownStarted
            || Dispatcher.HasShutdownFinished)
            return;
        try
        {
            _ = Dispatcher.BeginInvoke(() =>
            {
                if (cancellationToken.IsCancellationRequested
                    || operationGeneration != Volatile.Read(ref _automaticOperationGeneration)
                    || Volatile.Read(ref _automaticUpdatesClosed) != 0
                    || _automaticUpdateScheduler is null
                    || Dispatcher.HasShutdownStarted
                    || Dispatcher.HasShutdownFinished)
                    return;
                try
                {
                    action();
                }
                catch
                {
                    // Progress is advisory and must never fault the Dispatcher.
                }
            });
        }
        catch (InvalidOperationException) when (
            Dispatcher.HasShutdownStarted || Dispatcher.HasShutdownFinished)
        {
        }
    }
}
