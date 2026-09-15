using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.Host;
using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.Launcher;

public partial class MainWindow : Window
{
    private static readonly System.Windows.Media.Brush HealthyBrush =
        new SolidColorBrush(System.Windows.Media.Color.FromRgb(37, 214, 149));
    private static readonly System.Windows.Media.Brush IdleBrush =
        new SolidColorBrush(System.Windows.Media.Color.FromRgb(108, 120, 129));

    private readonly LauncherSettings _settings;
    private readonly DshHostService _hostService;
    private readonly PersonalManagedRuntimeUpdateCoordinator _managedRuntimeUpdate;
    private readonly PersonalDevelopmentLiveUpdateContext? _developmentLiveUpdate;
    private readonly PersonalInstallationLayout _installationLayout;
    private bool _operationRunning;
    private bool _restartRequired;
    private Task? _initializationTask;
    private int _windowClosed;

    public MainWindow(
        LauncherSettings settings,
        DshHostService hostService,
        bool runtimeSupportsManagedUpdate = false)
        : this(settings, hostService, runtimeSupportsManagedUpdate, developmentLiveUpdate: null)
    {
    }

    internal MainWindow(
        LauncherSettings settings,
        DshHostService hostService,
        bool runtimeSupportsManagedUpdate,
        PersonalDevelopmentLiveUpdateContext? developmentLiveUpdate = null)
    {
        _settings = settings;
        _hostService = hostService;
        _developmentLiveUpdate = developmentLiveUpdate;
        _installationLayout = developmentLiveUpdate?.Layout
            ?? PersonalInstallationLayout.CreateDefault();
        if (developmentLiveUpdate is not null && !runtimeSupportsManagedUpdate)
        {
            throw new InvalidDataException(
                "Personal development live-update requires a schema-2 personal-web-v1 Runtime.");
        }
        _managedRuntimeUpdate = new PersonalManagedRuntimeUpdateCoordinator(
            runtimeSupportsManagedUpdate,
            () => _hostService.OwnsRunningProcess,
            async (operationId, cancellationToken) =>
            {
                _developmentLiveUpdate?.RecordPhase("managed-drain-begin");
                await _hostService.StopForManagedUpdateAsync(operationId, cancellationToken)
                    .ConfigureAwait(false);
                _developmentLiveUpdate?.RecordPhase("managed-drain-end");
            },
            async cancellationToken =>
            {
                var restored = await _hostService.EnsureStartedAsync(cancellationToken)
                    .ConfigureAwait(false);
                if (restored.State is not DshLaunchState.Started and not DshLaunchState.AlreadyHealthy
                    || !_hostService.OwnsRunningProcess)
                {
                    throw new InvalidOperationException(
                        "Personal managed-update recovery did not restore the Launcher-owned Runtime.");
                }
            });
        InitializeComponent();

        Icon = LauncherBrandAssets.LoadWindowIcon();
        if (_developmentLiveUpdate is null)
        {
            InitializeAccountMonitor();
        }

        InstalledVersionText.Text = RuntimeInventory.ReadInstalledDshVersion(
            settings.ResolveRuntimeDirectory(_installationLayout));
        ChannelText.Text = settings.Channel.ToUpperInvariant();
        Loaded += async (_, _) => await RunUiEventAsync(EnsureInitializedAsync);
    }

    public bool AllowClose { get; set; }

    internal Task EnsureInitializedAsync() =>
        Volatile.Read(ref _windowClosed) != 0
            ? Task.CompletedTask
            : _initializationTask ??= InitializeOnceAsync();

    private async Task InitializeOnceAsync()
    {
        await InitializeAsync();
        var enableAutomaticUpdates = true;
        if (_developmentLiveUpdate is not null)
        {
            enableAutomaticUpdates = await StartDevelopmentLiveUpdateRuntimeAsync()
                .ConfigureAwait(true);
        }
        if (enableAutomaticUpdates && Volatile.Read(ref _windowClosed) == 0)
        {
            InitializeAutomaticUpdates();
        }
    }

    private async Task<bool> StartDevelopmentLiveUpdateRuntimeAsync()
    {
        var context = _developmentLiveUpdate
            ?? throw new InvalidOperationException(
                "Personal development live-update context is unavailable.");
        var pointer = new PersonalReleaseSetPointerStore(_installationLayout).ReadRequired();
        var initial = pointer.Current.Sequence == context.InitialSequence;
        var target = pointer.Current.Sequence == context.TargetSequence;
        if ((!initial && !target)
            || pointer.Current.HealthState != PersonalReleaseHealthStates.Healthy)
        {
            throw new InvalidDataException(
                "Personal development live-update Launcher did not start from an expected healthy sequence.");
        }
        var restoredBaseline = initial
            && context.RequireRestoredBaselineObservation(pointer);

        // This compiled E2E path deliberately proves Launcher/Host ownership and update
        // mechanics only. It does not forge or claim Personal account authentication.
        var result = await _hostService.EnsureStartedAsync().ConfigureAwait(true);
        if (result.State is not DshLaunchState.Started and not DshLaunchState.AlreadyHealthy
            || !_hostService.OwnsRunningProcess
            || result.ProcessId is null)
        {
            throw new InvalidOperationException(
                "Personal development live-update Runtime was not owned by this Launcher.");
        }
        context.RecordPhase(
            restoredBaseline
                ? "rollback-baseline-runtime-owned"
                : initial ? "baseline-runtime-owned" : "successor-target-runtime-owned",
            result.ProcessId.Value);
        return initial && !restoredBaseline;
    }

    internal void ReportRestartFailure(string failure)
    {
        _restartRequired = true;
        _operationRunning = false;
        PrimaryActionButton.IsEnabled = true;
        PrimaryActionButton.Content = "重试重启";
        SetHealth(healthy: false, "等待重启");
        SetStatus(
            "Launcher 未能重启",
            $"{failure} 请重试；本机对话历史和工作区未被删除。",
            0);
        LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} 重启失败";
    }

    internal void ReportBackgroundOperationFailure(string failure)
    {
        SetHealth(healthy: false, "需要处理");
        SetStatus("后台操作未完成", failure, 0);
        LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} 后台操作失败";
    }

    public async Task StartDshAsync()
    {
        if (_restartRequired)
        {
            await ((App)System.Windows.Application.Current).RestartLauncherAsync();
            return;
        }

        if (_operationRunning)
        {
            return;
        }

        await RunOperationAsync(async () =>
        {
            var releaseDecision = await EvaluateActiveReleaseAsync();
            if (releaseDecision is { Allowed: false })
            {
                throw new InvalidOperationException(releaseDecision.Reason);
            }
            await RequireAccountAccessAsync();
            SetStatus("正在启动 DSH", "首次启动可能需要几十秒，请不要重复点击。", 18);
            var result = await _hostService.EnsureStartedAsync();
            if (!_hostService.OwnsRunningProcess)
                throw new InvalidOperationException("已有其他程序管理的 DSH 正在运行。请先关闭该实例，再由本 Launcher 启动。");
            _accountRuntimeActive = true;
            await RequireAccountAccessAsync();
            SetHealth(healthy: true, result.State == DshLaunchState.Started ? "运行中" : "已在运行");
            SetStatus("DSH 已就绪", result.WebUiUri.AbsoluteUri, 100);

            if (_settings.OpenWebUiAfterStart)
            {
                await _hostService.OpenWebUiAsync();
            }
        });
    }

    public async Task OpenWebUiAsync()
    {
        if (_operationRunning)
        {
            return;
        }

        await RunOperationAsync(async () =>
        {
            await RequireAccountAccessAsync();
            if (!_hostService.OwnsRunningProcess)
                throw new InvalidOperationException("请先通过本 Launcher 启动 DSH。");
            await _hostService.OpenWebUiAsync();
        }, markHealthFailure: false);
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!AllowClose)
        {
            e.Cancel = true;
            ((App)System.Windows.Application.Current).HideLauncher();
        }

        base.OnClosing(e);
    }

    protected override void OnClosed(EventArgs e)
    {
        Interlocked.Exchange(ref _windowClosed, 1);
        ShutdownAutomaticUpdates();
        ShutdownAccountMonitor();
        base.OnClosed(e);
    }

    private async Task InitializeAsync()
    {
        var personalV2 = new PersonalReleaseSetPointerStore(_installationLayout).TryRead();
        var legacyPointer = personalV2 is null
            ? RuntimePointer.TryRead(RuntimePointer.StatePath())
            : null;
        if (legacyPointer is { PendingHealthValidation: true })
        {
            await ValidatePendingRuntimeAsync(legacyPointer);
            return;
        }

        var healthy = await _hostService.IsHealthyAsync();
        SetHealth(healthy, healthy ? "运行中" : "未启动");
    }

    private async Task ValidatePendingRuntimeAsync(RuntimePointer pointer)
    {
        _operationRunning = true;
        PrimaryActionButton.IsEnabled = false;
        try
        {
            SetStatus(
                "正在验证新版本",
                "先创建本机数据恢复点，再启动新版进行健康检查。失败会自动恢复上一个版本。",
                8);

            var snapshotDirectory = pointer.SnapshotDirectory;
            if (string.IsNullOrWhiteSpace(snapshotDirectory))
            {
                snapshotDirectory = await DataSnapshotService.CreateAsync(
                    _settings.DshDataDirectory,
                    pointer.ReleaseId);
                pointer = pointer with
                {
                    SnapshotDirectory = snapshotDirectory,
                    UpdatedAtUtc = DateTimeOffset.UtcNow
                };
                RuntimePointer.WriteAtomically(pointer);
            }

            UpdateProgress.Value = 45;
            StatusDetailText.Text = "数据恢复点已创建，正在启动新版 DSH。";
            var launch = await _hostService.EnsureStartedAsync();
            if (launch.State == DshLaunchState.AlreadyHealthy && !_hostService.OwnsRunningProcess)
            {
                throw new InvalidOperationException(
                    "端口上已有非本 Launcher 管理的 DSH，无法证明新版本已启动。");
            }

            // Health verification is account-independent, but must not leave an unadmitted interactive runtime.
            await _hostService.StopOwnedProcessAsync();
            RuntimePointer.MarkHealthy(pointer.ReleaseId);
            SetStatus("新版本验证通过", $"{pointer.ReleaseId} 已成为当前已知可用版本。", 100);
            SetHealth(healthy: false, "验证完成");
            LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} 新版本健康检查通过";
        }
        catch (Exception exception)
        {
            try
            {
                await _hostService.StopOwnedProcessAsync();
                if (!string.IsNullOrWhiteSpace(pointer.SnapshotDirectory))
                {
                    await DataSnapshotService.RestoreAsync(
                        pointer.SnapshotDirectory,
                        _settings.DshDataDirectory);
                }

                RuntimePointer.RollbackPending(pointer.ReleaseId);
            }
            catch (Exception rollbackException)
            {
                SetHealth(healthy: false, "恢复失败");
                SetStatus(
                    "新版失败，且自动恢复未完成",
                    $"启动错误：{exception.Message} 恢复错误：{rollbackException.Message}",
                    0);
                return;
            }

            SetHealth(healthy: false, "已回退");
            SetStatus("新版健康检查失败", $"已恢复本机数据和上一个版本：{exception.Message}", 0);
            await ((App)System.Windows.Application.Current).RestartLauncherAsync();
        }
        finally
        {
            PrimaryActionButton.IsEnabled = true;
            _operationRunning = false;
        }
    }

    private async Task CheckForUpdatesAsync()
    {
        if (_operationRunning)
        {
            return;
        }

        if (!TrustedReleaseKeyProvider.IsProductionTrustCompiled
            && string.IsNullOrWhiteSpace(_settings.ManifestUrl))
        {
            AvailableVersionText.Text = "更新源待配置";
            var releaseDecision = await EvaluateActiveReleaseAsync();
            SetStatus(
                releaseDecision is { Allowed: false }
                    ? "当前版本需要受信更新源确认"
                    : "可以启动本机 DSH",
                releaseDecision is { Allowed: false }
                    ? releaseDecision.Reason
                    : $"个人版更新源尚未写入配置：{LauncherSettings.SettingsPath()}",
                0);
            LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} 已跳过在线检查";
            return;
        }

        await RunOperationAsync(async () =>
        {
            SetStatus("正在检查更新", "正在验证通道清单和数字签名。", 12);
            try
            {
                var outcome = await CheckPersonalUpdateAsync(CancellationToken.None);
                AvailableVersionText.Text = outcome.AvailableVersion;
                SetStatus(outcome.Title, outcome.Detail, outcome.UpdateAvailable ? 35 : 100);
                PrimaryActionButton.Content = outcome.UpdateAvailable ? "下载更新" : "启动 DSH";
                PrimaryActionButton.Tag = outcome;
            }
            catch (Exception exception)
            {
                var releaseDecision = await EvaluateActiveReleaseAsync();
                AvailableVersionText.Text = "暂时不可用";
                SetStatus(
                    releaseDecision is { Allowed: false }
                        ? "更新检查不可用，当前版本已闭锁"
                        : "更新检查不可用，已保留当前版本",
                    releaseDecision is { Allowed: false }
                        ? $"{exception.Message} {releaseDecision.Reason}"
                        : $"{exception.Message} 当前已验证版本仍可启动。",
                    0);
                PrimaryActionButton.Content = "启动 DSH";
                PrimaryActionButton.Tag = null;
            }
        }, markHealthFailure: false);
    }

    private async Task<PersonalInstalledReleaseDecision?> EvaluateActiveReleaseAsync()
    {
        var layout = _installationLayout;
        var pointer = new PersonalReleaseSetPointerStore(layout).TryRead();
        if (pointer is null)
        {
            var existingState = await new PersonalReleaseSecurityStateStore(
                layout.UpdateSecurityStatePath,
                new PersonalReleaseStateIdentity(
                    PersonalReleaseSetContract.Product,
                    PersonalReleaseSetContract.ProductionEnvironment,
                    _settings.Channel),
                layout.UpdateSecurityWitnessPath).TryReadAsync();
            return existingState is null
                ? null
                : new PersonalInstalledReleaseDecision(
                    false,
                    "Authenticated personal update state exists, but its managed release-set pointer is missing.",
                    null);
        }
        if (pointer.Current.HealthState != PersonalReleaseHealthStates.Healthy)
        {
            return new PersonalInstalledReleaseDecision(
                false,
                "Personal release is pending Startup Stub health verification.",
                null);
        }
        var security = new PersonalReleaseSecurityStateStore(
            layout.UpdateSecurityStatePath,
            new PersonalReleaseStateIdentity(
                PersonalReleaseSetContract.Product,
                PersonalReleaseSetContract.ProductionEnvironment,
                pointer.Channel),
            layout.UpdateSecurityWitnessPath);
        return await security.EvaluateInstalledReleaseAsync(
            pointer.Current.ReleaseSetId,
            pointer.Current.Sequence,
            DateTimeOffset.UtcNow);
    }

    private async Task DownloadUpdateAsync(PersonalUpdateCheckOutcomeV2 outcome)
    {
        await RunOperationAsync(async () =>
        {
            var downloadProgress = new Progress<double>(value =>
            {
                UpdateProgress.Value = Math.Clamp(value * 50, 0, 50);
                StatusDetailText.Text = $"更新包已下载 {value * 100:N0}%";
            });

            SetStatus("正在下载更新", "支持断点续传；关闭后下次会继续。", 0);
            var packages = await DownloadPersonalUpdateAsync(
                outcome,
                downloadProgress,
                CancellationToken.None);
            var installProgress = new Progress<double>(value =>
            {
                UpdateProgress.Value = Math.Clamp(50 + (value * 50), 50, 100);
                StatusDetailText.Text =
                    $"正在安装不可变 release-set {outcome.Verified.Manifest.ReleaseSetId}…";
            });
            PersonalReleaseSetInstallationResult? installation = null;
            var stageDisposition = await _managedRuntimeUpdate.RunAsync(
                    async stageCancellationToken =>
                    {
                        if (!await RequireAutomaticStageBoundaryAsync(stageCancellationToken)
                                .ConfigureAwait(false))
                        {
                            return false;
                        }

                        SetStatus(
                            "正在安装更新",
                            "正在解压到新的版本目录；当前版本仍可继续回退。",
                            50);
                        installation = await StagePersonalUpdateAsync(
                            outcome,
                            packages,
                            installProgress,
                            stageCancellationToken);
                        return true;
                    },
                    cancellationToken: default)
                .ConfigureAwait(false);

            if (stageDisposition is PersonalManagedRuntimeUpdateDisposition.DeferredUnsupportedRuntime
                or PersonalManagedRuntimeUpdateDisposition.DeferredStageBoundary)
            {
                await ShowWaitingForStoppedDshAsync(CancellationToken.None).ConfigureAwait(false);
                return;
            }
            var staged = installation ?? throw new InvalidOperationException(
                "Personal managed update staged without returning an installation result.");
            _restartRequired = true;
            SetStatus(
                "更新已安装，等待重启",
                $"{staged.Pointer.Current.ReleaseSetId} 已暂存；Startup Stub 将先验证真实 Runtime/WebUI，再原子提交。",
                100);
            PrimaryActionButton.Content = "重启并应用";
            PrimaryActionButton.Tag = staged;
            _accountRuntimeActive = false;
        }, markHealthFailure: false);
    }

    private async Task<PersonalUpdateCheckOutcomeV2> CheckPersonalUpdateAsync(
        CancellationToken cancellationToken)
    {
        if (_developmentLiveUpdate is null)
        {
            return await PersonalUpdateCoordinatorV2.CheckAsync(_settings, cancellationToken)
                .ConfigureAwait(false);
        }
        _developmentLiveUpdate.RecordPhase("update-check-begin");
        var outcome = await _developmentLiveUpdate.CheckAsync(_settings, cancellationToken)
            .ConfigureAwait(false);
        if (!outcome.UpdateAvailable
            || outcome.Verified.Manifest.Sequence != _developmentLiveUpdate.TargetSequence)
        {
            throw new InvalidDataException(
                "Personal development live-update manifest did not admit the expected target sequence.");
        }
        _developmentLiveUpdate.RecordPhase("update-check-authenticated");
        return outcome;
    }

    private async Task<PersonalAcquiredReleaseSet> DownloadPersonalUpdateAsync(
        PersonalUpdateCheckOutcomeV2 outcome,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        if (_developmentLiveUpdate is null)
        {
            return await PersonalUpdateCoordinatorV2.DownloadAsync(
                _settings,
                outcome,
                progress,
                cancellationToken).ConfigureAwait(false);
        }
        _developmentLiveUpdate.RecordPhase("download-begin");
        var download = await _developmentLiveUpdate.DownloadAsync(
            outcome,
            progress,
            cancellationToken).ConfigureAwait(false);
        _developmentLiveUpdate.RecordPhase("download-complete");
        return download;
    }

    private async Task<PersonalReleaseSetInstallationResult> StagePersonalUpdateAsync(
        PersonalUpdateCheckOutcomeV2 outcome,
        PersonalAcquiredReleaseSet download,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        if (_developmentLiveUpdate is null)
        {
            return await PersonalUpdateCoordinatorV2.StageAsync(
                _settings,
                outcome,
                download,
                progress,
                cancellationToken).ConfigureAwait(false);
        }
        _developmentLiveUpdate.RecordPhase("stage-begin");
        var result = await _developmentLiveUpdate.StageAsync(
            _settings,
            outcome,
            download,
            progress,
            cancellationToken).ConfigureAwait(false);
        if (result.Pointer.Current.Sequence != _developmentLiveUpdate.TargetSequence
            || result.Pointer.Current.HealthState != PersonalReleaseHealthStates.Pending
            || string.IsNullOrWhiteSpace(result.Pointer.Current.HealthToken))
        {
            throw new InvalidDataException(
                "Personal development live-update stage did not produce the expected pending target.");
        }
        _developmentLiveUpdate.RecordPhase("stage-authenticated-complete");
        return result;
    }

    private async Task RunOperationAsync(Func<Task> operation, bool markHealthFailure = true)
    {
        _operationRunning = true;
        PrimaryActionButton.IsEnabled = false;
        try
        {
            await operation();
            LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} 操作完成";
        }
        catch (Exception exception)
        {
            if (markHealthFailure)
            {
                SetHealth(healthy: false, "需要处理");
            }
            SetStatus("操作未完成", exception.Message, 0);
            LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} {exception.GetType().Name}";
        }
        finally
        {
            PrimaryActionButton.IsEnabled = true;
            _operationRunning = false;
        }
    }

    private async Task RunUiEventAsync(Func<Task> operation)
    {
        try
        {
            await operation();
        }
        catch (Exception exception)
        {
            try
            {
                SetHealth(healthy: false, "需要处理");
                SetStatus(
                    "操作未完成",
                    LauncherRestartCoordinator.NormalizeFailure(exception),
                    0);
                LastActivityText.Text =
                    $"{DateTime.Now:HH:mm:ss} {exception.GetType().Name}";
            }
            catch
            {
                // An async-void WPF event must never escape into the dispatcher
                // even if the window is already being torn down.
            }
        }
    }

    private void SetStatus(string title, string detail, double progress)
    {
        StatusTitleText.Text = title;
        StatusDetailText.Text = detail;
        UpdateProgress.Value = progress;
    }

    private void SetHealth(bool healthy, string text)
    {
        HealthDot.Fill = healthy ? HealthyBrush : IdleBrush;
        HealthText.Text = text;
    }

    private async void PrimaryActionButton_Click(object sender, RoutedEventArgs e)
        => await RunUiEventAsync(HandlePrimaryActionAsync);

    private async Task HandlePrimaryActionAsync()
    {
        if (PrimaryActionButton.Tag is PersonalReleaseSetInstallationResult)
        {
            await ((App)System.Windows.Application.Current).RestartLauncherAsync();
            return;
        }

        if (PrimaryActionButton.Tag is PersonalUpdateCheckOutcomeV2 { UpdateAvailable: true } outcome)
        {
            await DownloadUpdateAsync(outcome);
            return;
        }

        await StartDshAsync();
    }

    private async void OpenWebUiButton_Click(object sender, RoutedEventArgs e) =>
        await RunUiEventAsync(OpenWebUiAsync);

    private async void CheckUpdateButton_Click(object sender, RoutedEventArgs e) =>
        await RunUiEventAsync(CheckForUpdatesAsync);
}
