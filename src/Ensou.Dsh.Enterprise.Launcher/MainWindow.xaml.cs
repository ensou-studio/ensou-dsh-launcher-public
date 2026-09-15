using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Ensou.Dsh.Enterprise.Client;
using Ensou.Dsh.Enterprise.Contracts;
using Ensou.Dsh.Host;
using MediaBrush = System.Windows.Media.Brush;
using MediaColor = System.Windows.Media.Color;

namespace Ensou.Dsh.Enterprise.Launcher;

public partial class MainWindow : Window
{
    private static readonly MediaBrush HealthyBrush = new SolidColorBrush(MediaColor.FromRgb(37, 214, 149));
    private static readonly MediaBrush WarningBrush = new SolidColorBrush(MediaColor.FromRgb(244, 184, 96));
    private static readonly MediaBrush LockedBrush = new SolidColorBrush(MediaColor.FromRgb(222, 102, 102));

    private readonly EnterpriseManagedPaths _paths;
    private readonly EnterpriseHarnessSession _session;
    private readonly EnterpriseDeviceEnrollmentPreparation _devicePreparation;
    private readonly EnterpriseQrEnrollmentCoordinator? _enrollmentCoordinator;
    private readonly EnterpriseAuthorizationLifecycle? _authorizationLifecycle;
    private readonly EnterpriseAuthenticatedReleaseUpdateCoordinator?
        _authenticatedReleaseUpdateCoordinator;
    private readonly Func<Guid, CancellationToken, Task<ManagedRuntimeUpdateDrainDisposition>>?
        _tryStopRuntimeForManagedUpdate;
    private readonly string? _runtimeUnavailableMessage;
    private readonly Func<CancellationToken, Task<bool>>? _restartAfterInitialRelease;
    private CancellationTokenSource? _authenticationCancellation;
    private bool _operationRunning;
    private bool _updateAuthenticationRestartRequired;
    private Task? _initializationTask;
    private int _windowClosed;

    public MainWindow(
        EnterpriseManagedPaths paths,
        EnterpriseHarnessSession session,
        Uri webUiUri,
        EnterpriseDeviceEnrollmentPreparation devicePreparation,
        EnterpriseQrEnrollmentCoordinator? enrollmentCoordinator,
        EnterpriseAuthorizationLifecycle? authorizationLifecycle = null,
        string? runtimeUnavailableMessage = null,
        string? updateStatusMessage = null,
        EnterpriseAuthenticatedReleaseUpdateCoordinator?
            authenticatedReleaseUpdateCoordinator = null,
        Func<Guid, CancellationToken, Task<ManagedRuntimeUpdateDrainDisposition>>?
            tryStopRuntimeForManagedUpdate = null,
        Func<CancellationToken, Task<bool>>? restartAfterInitialRelease = null)
    {
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _session = session ?? throw new ArgumentNullException(nameof(session));
        ArgumentNullException.ThrowIfNull(webUiUri);
        if (!webUiUri.IsLoopback || webUiUri.Port is < 1 or > 65535)
        {
            throw new ArgumentException(
                "Enterprise WebUI URI must use a valid loopback port.",
                nameof(webUiUri));
        }
        _devicePreparation = devicePreparation
            ?? throw new ArgumentNullException(nameof(devicePreparation));
        _enrollmentCoordinator = enrollmentCoordinator;
        _authorizationLifecycle = authorizationLifecycle;
        _authenticatedReleaseUpdateCoordinator = authenticatedReleaseUpdateCoordinator;
        _tryStopRuntimeForManagedUpdate = tryStopRuntimeForManagedUpdate;
        _runtimeUnavailableMessage = runtimeUnavailableMessage;
        _restartAfterInitialRelease = restartAfterInitialRelease;
        _automaticHarnessPort = webUiUri.Port;
        InitializeComponent();
        RuntimeEndpointText.Text = $"{webUiUri.Port} · 本机回环";
        if (!string.IsNullOrWhiteSpace(updateStatusMessage))
        {
            UpdateStatusText.Text = updateStatusMessage;
        }

        var iconPath = Path.Combine(AppContext.BaseDirectory, "dsh-official-whale.ico");
        if (File.Exists(iconPath))
        {
            Icon = BitmapFrame.Create(new Uri(iconPath, UriKind.Absolute));
        }

        _session.DecisionChanged += OnSessionDecisionChanged;
        ApplyDecision(_session.CurrentDecision);
        Loaded += async (_, _) => await EnsureInitializedAsync();
    }

    public event Action? AuthorizationChanged;

    public bool AllowClose { get; set; }

    internal Task EnsureInitializedAsync() =>
        Volatile.Read(ref _windowClosed) != 0
            ? Task.CompletedTask
            : _initializationTask ??= InitializeOnceAsync();

    private async Task InitializeOnceAsync()
    {
        await InitializeAuthorizationAsync();
        if (Volatile.Read(ref _windowClosed) == 0)
        {
            InitializeAutomaticUpdates();
        }
    }

    public bool CanStartHarness =>
        _runtimeUnavailableMessage is null
        && _session.CurrentDecision.MayStartHarness;

    public void FocusEnterpriseLogin() => WeComAuthenticateButton.Focus();

    public Task BeginAuthenticationAsync(string activationCode) =>
        BeginAuthenticationCoreAsync(activationCode);

    public Task BeginWeComAuthenticationAsync() => BeginAuthenticationCoreAsync(
        activationCode: null);

    private async Task BeginAuthenticationCoreAsync(string? activationCode)
    {
        if (_operationRunning)
        {
            return;
        }

        CancelAuthenticationButton.Visibility = Visibility.Visible;
        CancelAuthenticationButton.IsEnabled = true;
        try
        {
            await RunOperationAsync(async () =>
            {
                _authenticationCancellation?.Dispose();
                _authenticationCancellation = new CancellationTokenSource();
                var cancellationToken = _authenticationCancellation.Token;
                if (_enrollmentCoordinator is null)
                {
                    var device = await _devicePreparation.PrepareAsync(cancellationToken);
                    ApplyDecision(_session.CurrentDecision);
                    StatusTitleText.Text = "本机设备身份已安全建立";
                    StatusDetailText.Text =
                        $"安装 ID …{device.Installation.InstallId.ToString("N")[^8..]} · " +
                        $"设备密钥 …{device.DeviceKey.Thumbprint[^8..]}。公司 HTTPS 控制面尚未写入此签名构建，未发送任何数据。";
                    LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} 等待管理员配置企业认证服务";
                    return;
                }

                if (activationCode is not null)
                {
                    try
                    {
                        EnterpriseQrProtocol.ValidateActivationCode(activationCode);
                    }
                    catch (ArgumentException)
                    {
                        StatusTitleText.Text = "一次性激活码格式无效";
                        StatusDetailText.Text = "请粘贴管理员分配的完整 43 字符一次性激活码。";
                        LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} ACTIVATION_CODE_INVALID";
                        return;
                    }
                }

                StatusTitleText.Text = activationCode is null
                    ? "正在打开企业微信登录"
                    : "正在激活企业设备";
                StatusDetailText.Text = activationCode is null
                    ? "请在系统浏览器中使用企业微信扫码，并核对本机设备名和确认码。"
                    : "正在创建与本机设备密钥绑定的一次性激活会话。";
                var progress = new Progress<EnterpriseQrEnrollmentProgress>(update =>
                {
                    StatusTitleText.Text = DescribeQrState(update);
                    StatusDetailText.Text = DescribeQrProgress(update);
                    LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} {QrSessionStateContract.ToWireValue(update.State)}";
                });
                var outcome = activationCode is null
                    ? await _enrollmentCoordinator.BeginWithWeComAsync(
                        progress,
                        cancellationToken)
                    : await _enrollmentCoordinator.BeginAsync(
                        activationCode,
                        progress,
                        cancellationToken);
                if (outcome.BindingCompleted)
                {
                    var completion = outcome.BindingCompletion!;
                    if (await RestartAfterInitialReleaseIfRequiredAsync(cancellationToken))
                    {
                        return;
                    }
                    ApplyDecision(completion.AccessDecision);
                    var bindingDetail =
                        $"当前在线授权有效至 {completion.AccessTokenExpiresAtUtc.ToLocalTime():HH:mm:ss}，设备租约有效至 {completion.LeaseExpiresAtUtc.ToLocalTime():HH:mm:ss}。";
                    if (await CheckAuthenticatedReleaseUpdateAsync(
                            freshAuthorizationCompleted: true,
                            completion.AccessDecision,
                            "企业设备绑定完成",
                            bindingDetail,
                            cancellationToken))
                    {
                        return;
                    }

                    StatusTitleText.Text = completion.AccessDecision.ClientState
                        == EnterpriseClientState.Ready
                            ? "企业设备绑定完成"
                            : "企业设备已绑定，当前保持锁定";
                    StatusDetailText.Text = completion.AccessDecision.ClientState
                        == EnterpriseClientState.Ready
                            ? $"{bindingDetail} 现在可以启动 DSH。"
                            : $"{bindingDetail} {DescribeDecision(completion.AccessDecision)}";
                    LastActivityText.Text =
                        $"{DateTime.Now:HH:mm:ss} 设备绑定与授权租约已验证";
                    return;
                }

                if (outcome.IdentityApproved)
                {
                    StatusTitleText.Text = "企业身份与设备已确认";
                    StatusDetailText.Text =
                        "身份已由控制面确认；设备绑定与授权租约尚未完成，DSH 继续保持锁定。";
                    LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} 等待设备绑定闭环";
                    return;
                }

                StatusTitleText.Text = "企业身份验证未通过";
                StatusDetailText.Text = DescribeEnrollmentError(outcome.Error!);
                LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} {outcome.Error!.Code}";
            });
        }
        finally
        {
            CancelAuthenticationButton.IsEnabled = false;
            CancelAuthenticationButton.Visibility = Visibility.Collapsed;
        }
    }

    public async Task StartDshAsync()
    {
        if (_operationRunning)
        {
            return;
        }

        await RunOperationAsync(async () =>
        {
            EnsureRuntimeAvailable();
            StatusTitleText.Text = "正在启动本机 DSH";
            StatusDetailText.Text = "正在再次校验企业授权并启动受管运行时。";
            var webUiUri = await _session.EnsureStartedAsync();
            StatusTitleText.Text = "DSH 已就绪";
            StatusDetailText.Text = webUiUri.AbsoluteUri;
            LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} 本机服务已启动";
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
            EnsureRuntimeAvailable();
            await _session.OpenWebUiAsync();
            LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} 已打开本机 WebUI";
        });
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
        _authenticationCancellation?.Cancel();
        _authenticationCancellation?.Dispose();
        _session.DecisionChanged -= OnSessionDecisionChanged;
        base.OnClosed(e);
    }

    private async Task RefreshHealthAsync()
    {
        var healthy = await _session.IsHealthyAsync();
        ApplyDecision(_session.CurrentDecision);
        if (healthy)
        {
            StatusTitleText.Text = "DSH 正在本机运行";
            StatusDetailText.Text = $"数据目录：{_paths.HarnessHome}";
        }
    }

    private async Task InitializeAuthorizationAsync()
    {
        if (_authorizationLifecycle is null)
        {
            await RefreshHealthAsync();
            return;
        }

        await RunOperationAsync(async () =>
        {
            StatusTitleText.Text = "正在恢复企业授权";
            StatusDetailText.Text = "正在验证本机 DPAPI 凭据并安全轮换在线授权。";
            var device = await _devicePreparation.PrepareAsync();
            var result = await _authorizationLifecycle.HydrateAndRefreshAsync(device);
            if (await RestartAfterInitialReleaseIfRequiredAsync(CancellationToken.None))
            {
                return;
            }
            ApplyDecision(result.AccessDecision);
            if (!result.HasCommittedBinding)
            {
                StatusTitleText.Text = "需要企业微信登录";
                StatusDetailText.Text =
                    "此设备尚未绑定，请使用企业微信扫码；仅在管理员要求时使用备用激活码。";
                LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} 等待首次设备绑定";
                return;
            }

            if (result.AccessDecision.ClientState == EnterpriseClientState.Ready)
            {
                StatusTitleText.Text = "企业授权已恢复";
                StatusDetailText.Text = "refresh 凭据已通过 DPAPI 轮换，模型访问令牌仅保留在当前进程内存中。";
                LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} 在线授权轮换完成";
                return;
            }

            StatusTitleText.Text = "企业授权保持锁定";
            StatusDetailText.Text = DescribeDecision(result.AccessDecision);
            LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} 授权凭据已恢复但当前不可使用";
        });
    }

    private async Task<bool> RestartAfterInitialReleaseIfRequiredAsync(CancellationToken cancellationToken)
    {
        if (_restartAfterInitialRelease is null)
        {
            return false;
        }
        // The sequence-zero enrollment shell has no usable captured Host. Only
        // the existing stable-entry handoff may load the newly verified policy.
        return await _restartAfterInitialRelease(cancellationToken);
    }

    private async Task<bool> CheckAuthenticatedReleaseUpdateAsync(
        bool freshAuthorizationCompleted,
        EnterpriseAccessDecision accessDecision,
        string successTitle,
        string successDetail,
        CancellationToken cancellationToken = default)
    {
        if (_authenticatedReleaseUpdateCoordinator is null)
        {
            return false;
        }

        StatusTitleText.Text = "正在检查企业签名更新";
        StatusDetailText.Text = "正在使用本次在线授权检查设备专用 Stable 更新通道。";
        LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} AUTHENTICATED_STABLE_UPDATE_CHECK";
        var result = await _authenticatedReleaseUpdateCoordinator
            .CheckAfterFreshAuthorizationAsync(
                freshAuthorizationCompleted,
                accessDecision,
                cancellationToken);
        if (Volatile.Read(ref _automaticUpdatesClosed) != 0)
        {
            return true;
        }
        cancellationToken.ThrowIfCancellationRequested();
        return ApplyAuthenticatedReleaseUpdateResult(result, successTitle, successDetail);
    }

    private bool ApplyAuthenticatedReleaseUpdateResult(
        EnterpriseAuthenticatedReleaseUpdateResult result,
        string successTitle,
        string successDetail)
    {
        if (result.SessionLocked)
        {
            _updateAuthenticationRestartRequired = true;
        }
        ApplyDecision(_session.CurrentDecision);

        if (result.Disposition
            == EnterpriseAuthenticatedReleaseUpdateDisposition.NotEligible)
        {
            return false;
        }

        if (result.UpdateOutcome is { } updateOutcome)
        {
            UpdateStatusText.Text = $"受管更新：{updateOutcome.Message}";
        }
        else
        {
            UpdateStatusText.Text = DescribeAuthenticatedUpdateStatus(result);
        }

        switch (result.Disposition)
        {
            case EnterpriseAuthenticatedReleaseUpdateDisposition.Completed:
                if (_session.CurrentDecision.ClientState == EnterpriseClientState.Ready)
                {
                    StatusTitleText.Text = successTitle;
                    StatusDetailText.Text =
                        $"{successDetail} {result.UpdateOutcome!.Message} 现在可以启动 DSH。";
                    LastActivityText.Text =
                        $"{DateTime.Now:HH:mm:ss} 在线授权与签名更新检查完成";
                }
                else
                {
                    StatusTitleText.Text = "企业更新要求尚未解除";
                    StatusDetailText.Text =
                        $"{DescribeDecision(_session.CurrentDecision)} 更新检查结果：{result.UpdateOutcome!.Message}";
                    LastActivityText.Text =
                        $"{DateTime.Now:HH:mm:ss} UPDATE_REQUIREMENT_REMAINS_LOCKED";
                }
                break;
            case EnterpriseAuthenticatedReleaseUpdateDisposition.Restarting:
                StatusTitleText.Text = "企业更新已安装";
                StatusDetailText.Text = "正在通过 Stable Bootstrapper 重启并完成健康确认。";
                LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} UPDATE_BOOTSTRAP_RESTART";
                break;
            case EnterpriseAuthenticatedReleaseUpdateDisposition.SessionLocked:
                ShowUpdateAuthenticationRestartRequired();
                break;
            case EnterpriseAuthenticatedReleaseUpdateDisposition.ContinueVerifiedStable:
                StatusTitleText.Text = successTitle;
                StatusDetailText.Text =
                    $"{successDetail} {DescribeAuthenticatedUpdateFailure(result.FailureKind)} 当前继续使用本机已验证的 Stable 版本。";
                LastActivityText.Text =
                    $"{DateTime.Now:HH:mm:ss} VERIFIED_STABLE_CONTINUES";
                break;
            case EnterpriseAuthenticatedReleaseUpdateDisposition.UpdateRemainsLocked:
                StatusTitleText.Text = "必须更新，当前保持锁定";
                StatusDetailText.Text =
                    $"{DescribeAuthenticatedUpdateFailure(result.FailureKind)} 当前授权要求更新，DSH 与模型调用继续保持锁定。";
                LastActivityText.Text =
                    $"{DateTime.Now:HH:mm:ss} REQUIRED_UPDATE_REMAINS_LOCKED";
                break;
            default:
                throw new InvalidOperationException(
                    "Enterprise authenticated update result is unsupported.");
        }

        return true;
    }

    private static string DescribeAuthenticatedUpdateStatus(
        EnterpriseAuthenticatedReleaseUpdateResult result) =>
        result.Disposition switch
        {
            EnterpriseAuthenticatedReleaseUpdateDisposition.SessionLocked =>
                "受管更新授权失效；需要重启 Launcher 重新刷新",
            EnterpriseAuthenticatedReleaseUpdateDisposition.ContinueVerifiedStable =>
                "本次认证更新不可用；继续使用已验证 Stable",
            EnterpriseAuthenticatedReleaseUpdateDisposition.UpdateRemainsLocked =>
                "强制更新尚未完成；启动保持锁定",
            _ => "受管更新状态未知；启动保持锁定",
        };

    private static string DescribeAuthenticatedUpdateFailure(
        EnterpriseAuthenticatedReleaseUpdateFailureKind failureKind) => failureKind switch
        {
            EnterpriseAuthenticatedReleaseUpdateFailureKind.Forbidden =>
                "服务器拒绝了本次设备专用更新通道。",
            EnterpriseAuthenticatedReleaseUpdateFailureKind.FeedUnavailable =>
                "企业更新服务暂时不可用。",
            EnterpriseAuthenticatedReleaseUpdateFailureKind.Protocol =>
                "企业更新服务返回了不符合安全协议的响应。",
            EnterpriseAuthenticatedReleaseUpdateFailureKind.Unauthorized =>
                "本次在线授权已失效。",
            EnterpriseAuthenticatedReleaseUpdateFailureKind.AccessTokenUnavailable =>
                "当前进程没有可用的在线授权令牌。",
            _ => "企业更新检查未完成。",
        };

    private void ShowUpdateAuthenticationRestartRequired()
    {
        StatusTitleText.Text = "企业更新授权已失效";
        StatusDetailText.Text =
            "后台将使用本机已保护的设备绑定自动重试授权；认证恢复前 DSH 与模型调用均保持锁定，无需手动重启 Launcher。";
        LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} UPDATE_AUTH_SESSION_LOCKED";
    }

    public void OpenWorkspace()
    {
        _ = Process.Start(_paths.CreateOpenWorkspaceStartInfo());
        LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} 已打开本地工作区";
    }

    private async Task RunOperationAsync(Func<Task> operation)
    {
        _operationRunning = true;
        WeComAuthenticateButton.IsEnabled = false;
        AuthenticateButton.IsEnabled = false;
        ActivationCodeInput.IsEnabled = false;
        StartButton.IsEnabled = false;
        OpenWebUiButton.IsEnabled = false;
        try
        {
            await operation();
        }
        catch (EnterpriseAccessDeniedException exception)
        {
            ApplyDecision(exception.Decision);
            StatusTitleText.Text = "企业授权尚未满足";
            StatusDetailText.Text = DescribeDecision(exception.Decision);
            LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} 已阻止未授权操作";
        }
        catch (EnterpriseControlPlaneException exception)
        {
            ApplyDecision(_session.CurrentDecision);
            StatusTitleText.Text = "企业认证未完成";
            StatusDetailText.Text = DescribeEnrollmentError(exception.Error);
            LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} {exception.Error.Code}";
        }
        catch (EnterpriseBindingRecoveryRequiredException exception)
        {
            ApplyDecision(_session.CurrentDecision);
            StatusTitleText.Text = "正在恢复设备绑定";
            StatusDetailText.Text = exception.Message;
            LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} BINDING_RECOVERY_REQUIRED";
        }
        catch (EnterpriseEnrollmentMethodConflictException exception)
        {
            ApplyDecision(_session.CurrentDecision);
            StatusTitleText.Text = "已有未完成的企业登录";
            StatusDetailText.Text = exception.ActiveMethod
                == EnterpriseEnrollmentAuthorizationMethod.AdminInvite
                    ? "请继续使用管理员备用激活码完成当前会话，或等待本次会话在两分钟内失效后再扫码。"
                    : "请继续完成已打开的企业微信扫码会话，或等待本次会话在两分钟内失效后再使用备用激活码。";
            LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} ENROLLMENT_METHOD_CONFLICT";
        }
        catch (InvalidDataException exception)
            when (exception.InnerException is EnterpriseQrSessionValidityException)
        {
            ApplyDecision(_session.CurrentDecision);
            var validity = (EnterpriseQrSessionValidityException)exception.InnerException!;
            StatusTitleText.Text = validity.UserTitle;
            StatusDetailText.Text = validity.UserMessage;
            LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} QR_VALIDITY_{validity.Reason}";
        }
        catch (HttpRequestException)
        {
            ApplyDecision(_session.CurrentDecision);
            StatusTitleText.Text = "企业认证服务暂时不可用";
            StatusDetailText.Text = _session.CurrentDecision.ClientState == EnterpriseClientState.OfflineGrace
                ? "无法安全连接公司认证服务；有效租约内仅允许本地界面，模型调用已禁用。"
                : "无法安全连接公司认证服务，请检查网络后重试；DSH 仍保持锁定。";
            LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} CONTROL_PLANE_UNAVAILABLE";
        }
        catch (OperationCanceledException)
        {
            ApplyDecision(_session.CurrentDecision);
            StatusTitleText.Text = "已停止等待企业登录";
            StatusDetailText.Text =
                "未完成的安全会话已保留；可继续同一种登录方式，或等待本次会话在两分钟内失效。";
            LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} ENROLLMENT_WAIT_CANCELLED";
        }
        catch (Exception exception)
        {
            StatusTitleText.Text = "操作未完成";
            StatusDetailText.Text = exception.Message;
            LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} {exception.GetType().Name}";
        }
        finally
        {
            _operationRunning = false;
            ApplyDecision(_session.CurrentDecision);
        }
    }

    private void ApplyDecision(EnterpriseAccessDecision decision)
    {
        var mayStart = decision.MayStartHarness
            && _runtimeUnavailableMessage is null
            && !_operationRunning;
        WeComAuthenticateButton.IsEnabled = !_operationRunning;
        AuthenticateButton.IsEnabled = !_operationRunning;
        ActivationCodeInput.IsEnabled = !_operationRunning;
        StartButton.IsEnabled = mayStart;
        OpenWebUiButton.IsEnabled = mayStart;

        switch (decision.ClientState)
        {
            case EnterpriseClientState.Ready:
                SetAuthorizationVisual("已授权", HealthyBrush, "已验证", "已绑定");
                break;
            case EnterpriseClientState.OfflineGrace:
                SetAuthorizationVisual("离线宽限", WarningBrush, "已验证", "离线可用");
                break;
            case EnterpriseClientState.QrRequired:
                SetAuthorizationVisual("尚未验证", WarningBrush, "尚未验证", "尚未绑定");
                break;
            case EnterpriseClientState.Binding:
                SetAuthorizationVisual("正在绑定", WarningBrush, "验证中", "绑定中");
                break;
            default:
                SetAuthorizationVisual("已锁定", LockedBrush, "不可用", "需管理员处理");
                break;
        }

        AuthorizationChanged?.Invoke();
        if (_runtimeUnavailableMessage is not null && !_operationRunning)
        {
            StatusTitleText.Text = "需要安装或修复企业运行时";
            StatusDetailText.Text = _runtimeUnavailableMessage;
            LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} RUNTIME_INSTALL_REQUIRED";
        }
    }

    private void EnsureRuntimeAvailable()
    {
        if (_runtimeUnavailableMessage is not null)
        {
            throw new InvalidOperationException(_runtimeUnavailableMessage);
        }
    }

    private void SetAuthorizationVisual(
        string authorization,
        MediaBrush brush,
        string identity,
        string device)
    {
        AuthorizationText.Text = authorization;
        AuthorizationText.Foreground = brush;
        AuthorizationDot.Fill = brush;
        IdentityStateText.Text = identity;
        DeviceStateText.Text = device;
    }

    private void OnSessionDecisionChanged(EnterpriseAccessDecision decision)
    {
        if (Dispatcher.HasShutdownStarted)
        {
            return;
        }

        _ = Dispatcher.BeginInvoke(() =>
        {
            ApplyDecision(decision);
            if (_updateAuthenticationRestartRequired)
            {
                ShowUpdateAuthenticationRestartRequired();
            }
            else if (_runtimeUnavailableMessage is null && !decision.MayStartHarness)
            {
                StatusTitleText.Text = "企业授权已锁定";
                StatusDetailText.Text = DescribeDecision(decision);
                LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} 已执行本机授权状态更新";
            }
        });
    }

    private static string DescribeDecision(EnterpriseAccessDecision decision) =>
        decision.ClientState switch
        {
            EnterpriseClientState.QrRequired =>
                "当前设备尚未完成企业身份验证。请先联系管理员登记账号，再使用企业微信扫码登录。",
            EnterpriseClientState.Binding => "正在等待企业身份与设备绑定结果，请不要关闭 Launcher。",
            EnterpriseClientState.ApiDisabled => "管理员尚未分配可用 API，或当前 API 已停用。",
            EnterpriseClientState.DeviceRevokedResetRequired => "此设备授权已作废，请联系管理员。",
            EnterpriseClientState.AccountLocked => "此企业账号当前不可用，请联系管理员。",
            EnterpriseClientState.UpdateRequired => "必须先完成企业要求的签名更新。",
            EnterpriseClientState.LeaseExpiredLocked => "企业授权租约已过期，请恢复网络后重试。",
            EnterpriseClientState.SecurityQuarantined => "本机授权状态无法安全确认，已停止启动 DSH。",
            EnterpriseClientState.OfflineGrace => "控制面暂时不可用；仅允许使用本地界面，模型调用已禁用。",
            EnterpriseClientState.Ready => "企业授权有效。",
            _ => "企业授权状态未知，已停止启动 DSH。",
        };

    private static string DescribeQrState(EnterpriseQrEnrollmentProgress progress) =>
        (progress.State, progress.AuthorizationMethod) switch
        {
            (QrSessionState.Issued, EnterpriseEnrollmentAuthorizationMethod.WeCom) =>
                "等待企业微信扫码确认",
            (QrSessionState.Issued, EnterpriseEnrollmentAuthorizationMethod.AdminInvite) =>
                "正在验证管理员备用激活码",
            (QrSessionState.CallbackVerified, EnterpriseEnrollmentAuthorizationMethod.WeCom) =>
                "企业微信身份已确认，正在核对设备",
            (QrSessionState.CallbackVerified, EnterpriseEnrollmentAuthorizationMethod.AdminInvite) =>
                "备用激活码已确认，正在核对设备",
            (QrSessionState.EligibilityVerified, _) => "正在核对企业授权",
            (QrSessionState.Approved, _) => "企业身份验证通过",
            _ => "企业设备激活状态已更新",
        };

    private static string DescribeQrProgress(EnterpriseQrEnrollmentProgress progress) =>
        (progress.State, progress.AuthorizationMethod) switch
        {
            (QrSessionState.Issued, EnterpriseEnrollmentAuthorizationMethod.WeCom) =>
                $"请在系统浏览器完成企业微信扫码；设备名“{progress.DeviceDisplayName}”，确认码 {progress.ConfirmationCode}。本次验证将于 {progress.ExpiresAtUtc.ToLocalTime():HH:mm:ss} 失效。",
            (QrSessionState.Issued, EnterpriseEnrollmentAuthorizationMethod.AdminInvite) =>
                $"正在验证管理员提供的一次性激活码；设备名“{progress.DeviceDisplayName}”，确认码 {progress.ConfirmationCode}。本次验证将于 {progress.ExpiresAtUtc.ToLocalTime():HH:mm:ss} 失效。",
            (QrSessionState.CallbackVerified, EnterpriseEnrollmentAuthorizationMethod.WeCom) =>
                $"企业身份已确认，正在核对设备名“{progress.DeviceDisplayName}”和确认码 {progress.ConfirmationCode}。",
            (QrSessionState.CallbackVerified, EnterpriseEnrollmentAuthorizationMethod.AdminInvite) =>
                $"备用激活码已确认，正在核对设备名“{progress.DeviceDisplayName}”和确认码 {progress.ConfirmationCode}。",
            (QrSessionState.EligibilityVerified, _) =>
                $"设备确认已提交，正在核对企业授权；本次验证将于 {progress.ExpiresAtUtc.ToLocalTime():HH:mm:ss} 失效。",
            _ => $"本次验证将于 {progress.ExpiresAtUtc.ToLocalTime():HH:mm:ss} 失效。",
        };

    private static string DescribeEnrollmentError(EnterpriseApiError error) => error.Code switch
    {
        EnterpriseErrorCodes.EnrollmentActivationInvalid =>
            $"一次性激活码无效、已过期或已使用，请联系 {error.ContactDisplay ?? "管理员"}重新获取。",
        EnterpriseErrorCodes.WeComIdentityNotPreregistered =>
            $"该企业微信身份尚未登记，请联系 {error.ContactDisplay ?? "管理员"}开通。",
        EnterpriseErrorCodes.WeComEnterpriseMemberRequired =>
            $"当前账号不是本企业成员，请使用企业成员账号，或联系 {error.ContactDisplay ?? "管理员"}。",
        EnterpriseErrorCodes.EmployeeSuspended or EnterpriseErrorCodes.EmployeeRevoked =>
            $"当前企业账号不可用，请联系 {error.ContactDisplay ?? "管理员"}。",
        EnterpriseErrorCodes.EmployeeEntitlementMissing or EnterpriseErrorCodes.ApiProfileUnassigned =>
            $"管理员尚未分配使用权限，请联系 {error.ContactDisplay ?? "管理员"}。",
        EnterpriseErrorCodes.DeviceAlreadyBound =>
            $"该账号已有绑定设备，请联系 {error.ContactDisplay ?? "管理员"}处理设备更换。",
        EnterpriseErrorCodes.DeviceConfirmationRejected =>
            "你已拒绝本次设备授权；如需继续，请重新发起并核对设备名和确认码。",
        EnterpriseErrorCodes.QrSessionExpired or EnterpriseErrorCodes.QrSessionCancelled =>
            "本次验证已失效，请重新开始。",
        _ => $"企业认证未完成，请联系 {error.ContactDisplay ?? "管理员"}并提供请求编号 {error.RequestId}。",
    };

    private async void AuthenticateButton_Click(object sender, RoutedEventArgs e) =>
        await SubmitActivationCodeAsync();

    private async void WeComAuthenticateButton_Click(object sender, RoutedEventArgs e) =>
        await BeginWeComAuthenticationAsync();

    private void CancelAuthenticationButton_Click(object sender, RoutedEventArgs e)
    {
        CancelAuthenticationButton.IsEnabled = false;
        _authenticationCancellation?.Cancel();
    }

    private async Task SubmitActivationCodeAsync()
    {
        var activationCode = ActivationCodeInput.Password.Trim();
        ActivationCodeInput.Clear();
        try
        {
            await BeginAuthenticationAsync(activationCode);
        }
        finally
        {
            activationCode = string.Empty;
        }
    }

    private async void StartButton_Click(object sender, RoutedEventArgs e) =>
        await StartDshAsync();

    private async void OpenWebUiButton_Click(object sender, RoutedEventArgs e) =>
        await OpenWebUiAsync();

    private void OpenWorkspaceButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            OpenWorkspace();
        }
        catch (Exception exception)
        {
            StatusTitleText.Text = "本地工作区未能打开";
            StatusDetailText.Text = exception.Message;
            LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} WORKSPACE_OPEN_FAILED";
        }
    }
}
