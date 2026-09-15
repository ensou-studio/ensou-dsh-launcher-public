using System.Drawing;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.Enterprise.Client;
using Ensou.Dsh.Enterprise.Contracts;
using Ensou.Dsh.Enterprise.Installation;
using Ensou.Dsh.Host;
using Forms = System.Windows.Forms;

namespace Ensou.Dsh.Enterprise.Launcher;

public partial class App : System.Windows.Application
{
    private Forms.NotifyIcon? _trayIcon;
    private Forms.ToolStripMenuItem? _startMenuItem;
    private Forms.ToolStripMenuItem? _webUiMenuItem;
    private Icon? _applicationIcon;
    private EnterpriseHarnessSession? _session;
    private EnterpriseAccessTokenVault? _accessTokenVault;
    private EnterpriseAuthorizationLifecycle? _authorizationLifecycle;
    private HttpClient? _controlPlaneHttpClient;
    private HttpClient? _gatewayHttpClient;
    private EnterpriseLoopbackModelProxy? _modelProxy;
    private MainWindow? _launcherWindow;
    private Mutex? _singleInstanceMutex;
    private EventWaitHandle? _activationEvent;
    private CancellationTokenSource? _activationCancellation;
    private Task? _activationTask;
    private bool _ownsSingleInstanceMutex;
    private bool _shutdownRequested;
    private bool _backgroundStartup;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var isHealthProbe = e.Args.Length == 3
            && string.Equals(
                e.Args[0],
                "--installation-self-check",
                StringComparison.Ordinal)
            && string.Equals(
                e.Args[1],
                "--release-health-token",
                StringComparison.Ordinal);
        var isProductionTrustProbe = e.Args.Length == 2
            && string.Equals(
                e.Args[0],
                "--production-trust-self-check",
                StringComparison.Ordinal);
        var isReleaseManifestTrustProbeIntent = e.Args.Length > 0
            && string.Equals(
                e.Args[0],
                EnterpriseReleaseManifestTrustProbeContract.Command,
                StringComparison.Ordinal);
        var isReleaseManifestTrustProbe =
            EnterpriseReleaseManifestTrustProbeContract.IsExactCommand(e.Args);
        var isAuthenticatedUpdateCapabilityProbeIntent = e.Args.Length > 0
            && string.Equals(
                e.Args[0],
                EnterpriseAuthenticatedUpdateCapabilityProbeContract.Command,
                StringComparison.Ordinal);
        var isAuthenticatedUpdateCapabilityProbe =
            EnterpriseAuthenticatedUpdateCapabilityProbeContract.IsExactCommand(e.Args);
        var isBrandProbe = e.Args.Length == 2
            && string.Equals(
                e.Args[0],
                "--brand-self-check",
                StringComparison.Ordinal);
        Action<string>? markHealthStage = null;
        Action<string, Exception?>? observeRuntimeHealth = null;
#if ENTERPRISE_DEVELOPMENT_E2E
        EnterpriseDevelopmentHealthDiagnostics? healthDiagnostics = null;
        if (isHealthProbe)
        {
            try
            {
                // Resolve filesystem inputs independently of profile initialization.
                var local = Environment.GetEnvironmentVariable("ENSOU_DSH_E2E_LOCAL_APP_DATA_ROOT");
                var userProfile = Environment.GetEnvironmentVariable("ENSOU_DSH_E2E_USER_PROFILE_ROOT");
                if (!string.IsNullOrEmpty(local) && !string.IsNullOrEmpty(userProfile))
                {
                    healthDiagnostics = new(
                        EnterpriseInstallationLayout.CreateDevelopmentE2E(local, userProfile),
                        "launcher");
                    markHealthStage = stage => healthDiagnostics.Mark(stage);
                    observeRuntimeHealth = (stage, exception) => healthDiagnostics.Mark(stage, exception);
                    markHealthStage("entry");
                }
            }
            catch
            {
                // Diagnostic setup must never change health admission or exit behavior.
            }
        }
#endif
        if ((e.Args.Length == 1
                && e.Args[0] is "--self-check" or "--installation-self-check")
            || isHealthProbe
            || isProductionTrustProbe
            || isReleaseManifestTrustProbeIntent
            || isAuthenticatedUpdateCapabilityProbeIntent
            || isBrandProbe)
        {
            try
            {
                EnterpriseClientPlatform.RequireSupported();
                if (isBrandProbe)
                {
                    RunBrandSelfCheck(e.Args[1]);
                }
                else if (isAuthenticatedUpdateCapabilityProbeIntent)
                {
                    if (!isAuthenticatedUpdateCapabilityProbe)
                    {
                        throw new ArgumentException(
                            "Enterprise authenticated update capability probe arguments are invalid.");
                    }
                    RunAuthenticatedUpdateCapabilityProbe();
                }
                else if (isReleaseManifestTrustProbeIntent)
                {
                    if (!isReleaseManifestTrustProbe)
                    {
                        throw new ArgumentException(
                            "Enterprise release manifest trust probe arguments are invalid.");
                    }
                    RunReleaseManifestTrustProbe();
                }
                else if (isProductionTrustProbe)
                {
                    RunProductionTrustSelfCheck(e.Args[1]);
                }
                else if (string.Equals(
                        e.Args[0],
                        "--installation-self-check",
                        StringComparison.Ordinal))
                {
                    RunInstallationSelfCheck(markHealthStage);
                }
                else
                {
                    RunSelfCheck();
                }
                if (isHealthProbe)
                {
                    markHealthStage?.Invoke("runtime-health-start");
                    RunRuntimeInstallationHealthCheckAsync(markHealthStage, observeRuntimeHealth)
                        .GetAwaiter()
                        .GetResult();
                    markHealthStage?.Invoke("health-signal-start");
                    var healthLayout = EnterpriseBuildProfile.CreateInstallationLayout();
                    var healthProfile = EnterpriseBuildProfile.CreateReleaseUpdateProfile()
                        ?? throw new InvalidOperationException(
                            "Enterprise health probe has no compiled release trust.");
                    new EnterpriseReleaseHealthCoordinator(
                        healthLayout,
                        new EnterpriseCompiledReleaseTrust(
                            healthProfile.ManifestUri,
                            healthProfile.TrustPolicy))
                        .WriteSignal(e.Args[2]);
                    markHealthStage?.Invoke("health-signal-written");
                }
                Shutdown(0);
            }
            catch (Exception exception)
            {
#if ENTERPRISE_DEVELOPMENT_E2E
                healthDiagnostics?.Mark("failed", exception);
#endif
                _ = exception;
                if (isAuthenticatedUpdateCapabilityProbeIntent)
                {
                    EnterpriseAuthenticatedUpdateCapabilityProbeContract
                        .WriteBoundedFailureToStandardError();
                }
                else if (isReleaseManifestTrustProbeIntent)
                {
                    EnterpriseReleaseManifestTrustProbeContract
                        .WriteBoundedFailureToStandardError();
                }
#if ENTERPRISE_DEVELOPMENT_E2E
                else
                {
                    WriteDevelopmentMachineFailure(exception);
                }
#endif
                Shutdown(1);
            }
            return;
        }

        if (PersonalLauncherRestartHandoffCommand.IsIntent(
                e.Args, LauncherRestartHandoffScope.Enterprise))
        {
            PersonalLauncherRestartHandoffCommand? handoff = null;
            try
            {
                handoff = PersonalLauncherRestartHandoffCommand.ParseRequired(
                    e.Args, LauncherRestartHandoffScope.Enterprise);
                var accepted = LauncherRestartCoordinator.AcceptHandoff(
                    handoff, EnterpriseBuildProfile.SingleInstanceMutexName);
                _singleInstanceMutex = accepted.Singleton;
                _incomingRestartHandoff = accepted.Receiver;
                _ownsSingleInstanceMutex = true;
                _backgroundStartup = handoff.BackgroundStartup;
                TraceEnterpriseRestart("restart-receiver-accepted");
            }
            catch (Exception exception)
            {
                TraceEnterpriseRestart("restart-receiver-accept-failed", exception);
                handoff?.TrySignalFailure();
                Shutdown(1);
                return;
            }
        }
        else if (e.Args is ["--background-startup"])
        {
            _backgroundStartup = true;
        }
        else if (e.Args.Length > 0)
        {
            System.Windows.MessageBox.Show(
                "企业 Launcher 不接受此启动参数。",
                EnterpriseProductIdentity.ProductName,
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown(2);
            return;
        }

        try
        {
            EnterpriseClientPlatform.RequireSupported();
            WindowsShellIdentity.ApplyCurrentProcessAppUserModelId(
                EnterpriseBuildProfile.AppUserModelId);
        }
        catch (Exception exception)
        {
            if (_incomingRestartHandoff is not null || _backgroundStartup)
            {
                // A hidden receiver must release the parent through the handoff
                // protocol rather than wait for a user to dismiss a dialog.
                _incomingRestartHandoff?.TrySignalFailure();
#if ENTERPRISE_DEVELOPMENT_E2E
                WriteDevelopmentMachineFailure(exception);
#endif
                Shutdown(1);
                return;
            }
            System.Windows.MessageBox.Show(
                exception.Message,
                "Ensou DSH Enterprise Launcher 任务栏身份错误",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown(1);
            return;
        }

        if (_incomingRestartHandoff is null)
        {
            _singleInstanceMutex = new Mutex(
                initiallyOwned: true,
                EnterpriseBuildProfile.SingleInstanceMutexName,
                out var isFirstInstance);
            _ownsSingleInstanceMutex = isFirstInstance;
            if (!isFirstInstance)
            {
                if (!_backgroundStartup)
                {
                    ActivateExistingInstance();
                }
                Shutdown();
                return;
            }
        }

        _activationEvent = new EventWaitHandle(
            initialState: false,
            EventResetMode.AutoReset,
            EnterpriseBuildProfile.ActivationEventName);
        _activationCancellation = new CancellationTokenSource();
        _activationTask = Task.Run(() => WaitForActivation(_activationCancellation.Token));

        try
        {
            var paths = EnterpriseBuildProfile.CreateManagedPaths();
            var installationLayout = EnterpriseBuildProfile.CreateInstallationLayout();
            EnterpriseBuildProfileMarker.ReadAndValidate(
                Path.Combine(
                    AppContext.BaseDirectory,
                    EnterpriseInstallationLayout.BuildProfileMarkerFileName),
                installationLayout.LayoutProfile);
            if (!string.Equals(
                    paths.ManagedRoot,
                    installationLayout.ManagedRoot,
                    StringComparison.OrdinalIgnoreCase)
                || !string.Equals(
                    paths.HarnessHome,
                    installationLayout.HarnessHome,
                    StringComparison.OrdinalIgnoreCase)
                || !string.Equals(
                    paths.PluginRoot,
                    installationLayout.PluginPolicyVersionsRoot,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "企业安装布局与 Launcher 数据边界不一致。");
            }
            EnterpriseLegacySqliteUpgradeGuard
                .RequireJsonlOnlyHarnessHomeAndNoWriter(installationLayout);
            paths.EnsureWorkspaceRoot();

            EnterpriseReleaseComponentPointer? runtimePointer = null;
            string enrollmentRuntimeReleaseId = "runtime-unavailable";
            EnterpriseActivePluginPolicy? activePluginPolicy = null;
            string? runtimeUnavailableMessage = null;
            string? updateStatusMessage = null;
            var releaseUpdateProfile = EnterpriseBuildProfile.CreateReleaseUpdateProfile();
            var compiledReleaseTrust = releaseUpdateProfile is null
                ? null
                : new EnterpriseCompiledReleaseTrust(
                    releaseUpdateProfile.ManifestUri,
                    releaseUpdateProfile.TrustPolicy);
            var releaseSetStore = new EnterpriseReleaseSetPointerStore(
                installationLayout,
                compiledReleaseTrust);
            if (releaseUpdateProfile is null)
            {
                updateStatusMessage = "此构建尚未写入受信更新源。";
#if !ENTERPRISE_DEVELOPMENT_E2E
                runtimeUnavailableMessage =
                    "生产企业版未写入受信更新源与 ES256 公钥，启动已安全锁定。";
#endif
            }
            else
            {
                updateStatusMessage = "受管更新将在企业登录并刷新授权后检查。";
            }
            try
            {
                var releaseSetPointer = releaseSetStore.TryRead();
                if (releaseSetPointer is null)
                {
                    runtimeUnavailableMessage =
                        "企业 DSH 运行时尚未安装。请重新运行企业安装器并选择修复。";
                }
                else if (releaseSetPointer.Current.HealthState
                    != EnterpriseReleaseHealthStates.Healthy)
                {
                    runtimeUnavailableMessage =
                        "企业更新尚未通过 Bootstrapper 健康确认；请从企业快捷方式重新启动。";
                }
                else if (!new EnterpriseReleaseFeedStateStore(
                        installationLayout,
                        EnterpriseBuildProfile.ExpectedReleaseChannel)
                    .IsCurrentAllowedOffline(releaseSetPointer.Current, out var releaseBlockReason))
                {
                    runtimeUnavailableMessage =
                        $"企业更新策略已阻止当前版本：{releaseBlockReason}";
                }
                else
                {
                    var executableDirectory = Path.TrimEndingDirectorySeparator(
                        Path.GetFullPath(AppContext.BaseDirectory));
                    var activeLauncherDirectory = Path.TrimEndingDirectorySeparator(
                        Path.GetFullPath(releaseSetPointer.Current.Launcher.Directory));
                    if (!string.Equals(
                            executableDirectory,
                            activeLauncherDirectory,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        runtimeUnavailableMessage =
                            "当前进程不是原子 release-set 指针选定的 Launcher；请从企业快捷方式重启。";
                    }
                    else
                    {
                        enrollmentRuntimeReleaseId = releaseSetPointer.Current.Runtime.ReleaseId;
                        if (runtimeUnavailableMessage is null)
                        {
                            runtimePointer = releaseSetPointer.Current.Runtime;
                            try
                            {
                                activePluginPolicy = releaseSetStore
                                    .ReadActivePluginPolicyRequired(releaseSetPointer);
                                paths.ValidateManagedSkillsRoot(
                                    activePluginPolicy.SkillsRoot);
                            }
                            catch (Exception exception) when (
                                exception is InvalidDataException
                                    or IOException
                                    or UnauthorizedAccessException)
                            {
                                runtimeUnavailableMessage =
                                    $"企业托管插件策略无法验证：{exception.Message}";
                                runtimePointer = null;
                                activePluginPolicy = null;
                            }
                        }
                    }
                }
            }
            catch (Exception exception) when (
                exception is InvalidDataException
                    or IOException
                    or UnauthorizedAccessException)
            {
                runtimeUnavailableMessage =
                    $"企业 DSH 运行时状态无法验证：{exception.Message} 请重新运行企业安装器修复。";
            }

            try
            {
                var updateStatus = EnterpriseReleaseUpdateStatusReader.TryRead(
                    installationLayout);
                updateStatusMessage ??= updateStatus is null
                    ? "受管更新尚未检查"
                    : $"受管更新：{updateStatus.Message}";
            }
            catch (Exception exception) when (
                exception is InvalidDataException
                    or IOException
                    or UnauthorizedAccessException)
            {
                updateStatusMessage = "受管更新状态无法验证；启动保持安全锁定。";
                runtimeUnavailableMessage ??= updateStatusMessage;
            }

            var capturedRuntime = runtimePointer;
            if (_incomingRestartHandoff is not null && runtimeUnavailableMessage is not null)
            {
                throw new InvalidOperationException(
                    "Enterprise restart receiver has no verified active Runtime and Launcher.");
            }
            var capturedPluginPolicy = activePluginPolicy;
            var runtimeDirectory = capturedRuntime?.Directory
                ?? Path.Combine(paths.RuntimeRoot, ".runtime-unavailable");
            var skillsRoot = capturedPluginPolicy?.SkillsRoot
                ?? Path.Combine(paths.PluginRoot, ".policy-unavailable", "skills");
#if ENTERPRISE_DIRECT_LOCAL_DEVELOPMENT_E2E || ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
            var runtimeOptions = DshRuntimeOptions.CreateEnterpriseDirectLocal(
                runtimeDirectory,
                paths.HarnessHome,
                paths.LogDirectory,
                paths.WorkspaceRoot,
                EnterpriseBuildProfile.DefaultPort,
                paths.PluginRoot,
                skillsRoot);
#else
            var runtimeOptions = DshRuntimeOptions.CreateEnterpriseManaged(
                runtimeDirectory,
                paths.HarnessHome,
                paths.LogDirectory,
                paths.WorkspaceRoot,
                EnterpriseBuildProfile.DefaultPort,
                paths.PluginRoot,
                skillsRoot);
#endif
            var host = new DshHostAdapter(
                runtimeOptions,
                () => ValidateActiveReleaseSet(
                    releaseSetStore,
                    capturedRuntime,
                    capturedPluginPolicy,
                    paths,
                    _session?.CurrentAccessSnapshot,
                    installationLayout),
                installationLayout);
            var deviceKeyStore = EnterpriseBuildProfile.CreateDeviceKeyStore();
            var protectedStore = EnterpriseBuildProfile.CreateProtectedStore(paths);
            var trustedTimeStore = new EnterpriseTrustedTimeStore(protectedStore);
            _session = new EnterpriseHarnessSession(
                new EnterpriseStartupGate(TimeProvider.System),
                host,
                EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot(),
                new EnterpriseResetExecutor(paths, deviceKeyStore, protectedStore),
                trustedTimeStore);

            var devicePreparation = new EnterpriseDeviceEnrollmentPreparation(
                new EnterpriseInstallationIdentityStore(paths),
                deviceKeyStore);
            EnterpriseQrEnrollmentCoordinator? enrollmentCoordinator = null;
            EnterpriseAuthenticatedReleaseUpdateCoordinator?
                authenticatedReleaseUpdateCoordinator = null;
            EnterpriseInitialReleaseDeviceUpdateGate? initialReleaseGate = null;
            var controlPlaneOptions = EnterpriseBuildProfile.CreateControlPlaneOptions();
            if (controlPlaneOptions is not null)
            {
                if (releaseUpdateProfile is null)
                {
                    throw new InvalidOperationException(
                        "Enterprise authentication requires a pinned signed release-feed channel.");
                }
                var leaseTrustPolicy = EnterpriseBuildProfile.CreateLeaseTrustPolicy(
                    controlPlaneOptions)
                    ?? throw new InvalidOperationException(
                        "Enterprise lease trust profile is missing.");
                _controlPlaneHttpClient = EnterpriseControlPlaneTransportFactory.Create();
                var proofFactory = new EnterpriseDpopProofFactory(deviceKeyStore);
                var enrollmentClient = new EnterpriseQrEnrollmentClient(
                    _controlPlaneHttpClient,
                    controlPlaneOptions,
                    proofFactory);
                var bindingClient = new EnterpriseDeviceBindingClient(
                    _controlPlaneHttpClient,
                    controlPlaneOptions,
                    proofFactory);
                _accessTokenVault = new EnterpriseAccessTokenVault();
                var leaseVerifier = new EnterpriseAuthorizationLeaseVerifier(leaseTrustPolicy);
                var credentialStore = new EnterpriseBindingCredentialStore(paths, protectedStore);
                IEnterpriseDeviceUpdateGate deviceUpdateGate = new EnterpriseDeviceUpdateGate(
                    new EnterpriseDeviceUpdateManagementClient(
                        _controlPlaneHttpClient,
                        controlPlaneOptions,
                        proofFactory,
                        _accessTokenVault),
                    new EnterpriseInstalledReleaseEvidenceProvider(
                        installationLayout,
                        releaseUpdateProfile.ManifestUri,
                        releaseUpdateProfile.TrustPolicy.ExpectedChannel,
                        releaseUpdateProfile.TrustPolicy),
                    new EnterprisePendingUpdateReceiptTransactionStore(protectedStore));
#if ENTERPRISE_DIRECT_LOCAL_DEVELOPMENT_E2E || ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
                initialReleaseGate = new EnterpriseInitialReleaseDeviceUpdateGate(
                    installationLayout,
                    new EnterpriseCompiledReleaseTrust(
                        releaseUpdateProfile.ManifestUri, releaseUpdateProfile.TrustPolicy),
                    deviceUpdateGate,
                    () => EnterpriseUpdateFeedTransport.CreateTransactionClient(
                        releaseUpdateProfile.ManifestUri,
                        releaseUpdateProfile.TrustPolicy.ArtifactOrigin,
                        proofFactory,
                        _accessTokenVault),
                    async cancellationToken =>
                    {
                        EnterpriseStableBootstrapperVerifier.RequireTrusted(installationLayout);
                        using var trustedEntry = EnterpriseAuthenticodeVerifier.OpenTrustedExecutableForLaunch(
                            installationLayout.BootstrapperPath, installationLayout);
                        await CompletePendingHealthAsync(
                            installationLayout, trustedEntry, cancellationToken).ConfigureAwait(false);
                    },
                    EnterpriseBuildProfile.DefaultPort);
                deviceUpdateGate = initialReleaseGate;
#endif
                var bindingWorkflow = new EnterpriseDeviceBindingWorkflow(
                    bindingClient,
                    deviceKeyStore,
                    leaseVerifier,
                    credentialStore,
                    new EnterprisePendingBindingTransactionStore(protectedStore),
                    _accessTokenVault,
                    _session,
                    deviceUpdateGate);
                _authorizationLifecycle = new EnterpriseAuthorizationLifecycle(
                    new EnterpriseRefreshClient(
                        _controlPlaneHttpClient,
                        controlPlaneOptions,
                        proofFactory),
                    leaseVerifier,
                    credentialStore,
                    new EnterprisePendingRefreshTransactionStore(protectedStore),
                    _accessTokenVault,
                    _session,
                    trustedTimeStore,
                    deviceUpdateGate);
                authenticatedReleaseUpdateCoordinator =
                    EnterpriseAuthenticatedReleaseUpdateCoordinator.Create(
                        _session,
                        installationLayout,
                        releaseUpdateProfile.ManifestUri,
                        releaseUpdateProfile.TrustPolicy,
                        () => EnterpriseUpdateFeedTransport.CreateTransactionClient(
                            releaseUpdateProfile.ManifestUri,
                            releaseUpdateProfile.TrustPolicy.ArtifactOrigin,
                            proofFactory,
                            _accessTokenVault),
                        () => Dispatcher.InvokeAsync(
                            () => RestartThroughStableBootstrapperAsync(installationLayout)).Task.Unwrap(),
                        () => Dispatcher.Invoke(CommitRestartAndShutdown),
                        EnterpriseBuildProfile.DefaultPort);
#if !ENTERPRISE_DIRECT_LOCAL_DEVELOPMENT_E2E && !ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
                var gatewayRoutes = EnterprisePhase1GatewayProfile.Routes;
                _gatewayHttpClient = EnterpriseControlPlaneTransportFactory.CreateGateway(
                    leaseTrustPolicy.GatewayOrigin,
                    proofFactory,
                    _accessTokenVault,
                    _session,
                    gatewayRoutes);
                _modelProxy = new EnterpriseLoopbackModelProxy(
                    leaseTrustPolicy.GatewayOrigin,
                    gatewayRoutes,
                    _gatewayHttpClient);
                _modelProxy.StartAsync().GetAwaiter().GetResult();
                host.ConfigureControlledEnvironment(
                    _modelProxy.CreateDshControlledEnvironment());
#endif
                enrollmentCoordinator = new EnterpriseQrEnrollmentCoordinator(
                    devicePreparation,
                    enrollmentClient,
                    protectedStore,
                    _session,
                    GetLauncherVersion(),
                    enrollmentRuntimeReleaseId,
                    EnterpriseClientPlatform.ProtocolPlatform,
                    bindingWorkflow: bindingWorkflow,
                    deviceLabel: Environment.MachineName,
                    systemBrowser: new SystemBrowser());
            }

            _launcherWindow = new MainWindow(
                paths,
                _session,
                host.WebUiUri,
                devicePreparation,
                enrollmentCoordinator,
                _authorizationLifecycle,
                runtimeUnavailableMessage,
                updateStatusMessage,
                authenticatedReleaseUpdateCoordinator,
                (operationId, cancellationToken) =>
                    host.TryStopForManagedUpdateAsync(operationId, cancellationToken),
                async cancellationToken =>
                {
                    if (initialReleaseGate?.RequiresLauncherRestart != true
                        || _session.CurrentDecision.ClientState != EnterpriseClientState.Ready)
                    {
                        return false;
                    }
                    cancellationToken.ThrowIfCancellationRequested();
                    await Dispatcher.InvokeAsync(
                        () => RestartThroughStableBootstrapperAsync(installationLayout)).Task.Unwrap();
                    Dispatcher.Invoke(CommitRestartAndShutdown);
                    return true;
                });
            _launcherWindow.AuthorizationChanged += UpdateTrayAuthorization;
            MainWindow = _launcherWindow;
            CreateTrayIcon(visible: _incomingRestartHandoff is null);
            UpdateTrayAuthorization();
            if (_incomingRestartHandoff is not null)
            {
                BeginIncomingRestartHandoff();
            }
            else if (!_backgroundStartup)
            {
                ShowLauncher();
            }
            else
            {
                _ = Dispatcher.BeginInvoke(BeginBackgroundInitialization);
            }
        }
        catch (Exception exception)
        {
            if (_incomingRestartHandoff is not null || _backgroundStartup)
            {
                _incomingRestartHandoff?.TrySignalFailure();
                TraceEnterpriseRestart("restart-app-initialization-failed", exception);
#if ENTERPRISE_DEVELOPMENT_E2E
                WriteDevelopmentMachineFailure(exception);
#endif
                Shutdown(1);
                return;
            }
            System.Windows.MessageBox.Show(
                exception.Message,
                "Ensou DSH Enterprise Launcher 配置错误",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _shutdownRequested = true;
        TryCleanup(() => _outgoingRestartHandoff?.Commit());
        TryCleanup(() => _outgoingRestartHandoff?.Dispose());
        _outgoingRestartHandoff = null;
        TryCleanup(() => _activationCancellation?.Cancel());
        TryCleanup(() => _activationEvent?.Set());
        TryCleanup(() =>
        {
            if (_trayIcon is not null)
            {
                _trayIcon.Visible = false;
                _trayIcon.Dispose();
            }
        });
        TryCleanup(() => _applicationIcon?.Dispose());
        TryCleanup(() => _session?.DisposeAsync().AsTask().GetAwaiter().GetResult());
        _session = null;
        TryCleanup(() => _modelProxy?.DisposeAsync().AsTask().GetAwaiter().GetResult());
        _modelProxy = null;
        TryCleanup(() => _gatewayHttpClient?.Dispose());
        _gatewayHttpClient = null;
        TryCleanup(() => _controlPlaneHttpClient?.Dispose());
        _controlPlaneHttpClient = null;
        TryCleanup(() => _accessTokenVault?.Dispose());
        _accessTokenVault = null;
        TryCleanup(() => _activationTask?.Wait(TimeSpan.FromSeconds(2)));
        TryCleanup(() => _activationEvent?.Dispose());
        TryCleanup(() => _activationCancellation?.Dispose());
        if (_ownsSingleInstanceMutex)
        {
            TryCleanup(() => _singleInstanceMutex?.ReleaseMutex());
        }

        TryCleanup(() => _singleInstanceMutex?.Dispose());
        TryCleanup(() => _incomingRestartHandoff?.Dispose());
        _incomingRestartHandoff = null;
        base.OnExit(e);
    }

    internal void HideLauncher()
    {
        if (!_shutdownRequested)
        {
            _launcherWindow?.Hide();
        }
    }

    private static void RunSelfCheck()
    {
        var paths = EnterpriseBuildProfile.CreateManagedPaths();
        var gate = new EnterpriseStartupGate(TimeProvider.System);
        var decision = gate.Evaluate(EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot());
        if (decision.ClientState != EnterpriseClientState.QrRequired
            || decision.MayStartHarness
            || decision.MayCallManagedApi
            || paths.IsInsideHarnessHome(paths.ManagedRoot)
            || !EnterpriseClientPlatform.IsSupported)
        {
            throw new InvalidOperationException("Enterprise Launcher self-check failed closed-state validation.");
        }
    }

#if ENTERPRISE_DEVELOPMENT_E2E
    private const string DevelopmentMachineFailurePrefix =
        "ENSOU_DSH_E2E_MACHINE_FAILURE_V1";
    private const int MaximumDevelopmentMachineFailureMessageLength = 512;

    private static void WriteDevelopmentMachineFailure(Exception exception)
    {
        var exceptionType = exception.GetType().Name;
        if (exceptionType.Length is < 1 or > 128
            || exceptionType.Any(character => !char.IsAsciiLetterOrDigit(character)))
        {
            exceptionType = "Exception";
        }
        Console.Error.WriteLine(
            $"{DevelopmentMachineFailurePrefix}\t{exceptionType}\t"
            + SanitizeDevelopmentMachineFailureMessage(exception.Message));
    }

    private static string SanitizeDevelopmentMachineFailureMessage(string? message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return "No diagnostic message was provided.";
        }
        foreach (var sensitiveLabel in new[]
        {
            "api key", "api_key", "api-key", "authorization", "bearer",
            "cookie", "password", "private key", "secret",
        })
        {
            if (message.Contains(sensitiveLabel, StringComparison.OrdinalIgnoreCase))
            {
                return "Diagnostic message was redacted.";
            }
        }

        var normalized = new StringBuilder(
            Math.Min(message.Length, MaximumDevelopmentMachineFailureMessageLength));
        var previousWasSpace = false;
        foreach (var character in message)
        {
            if (normalized.Length >= MaximumDevelopmentMachineFailureMessageLength)
            {
                break;
            }
            if (char.IsControl(character) || char.IsWhiteSpace(character))
            {
                if (!previousWasSpace && normalized.Length > 0)
                {
                    normalized.Append(' ');
                }
                previousWasSpace = true;
                continue;
            }
            normalized.Append(character);
            previousWasSpace = false;
        }
        var bounded = normalized.ToString().Trim();
        if (bounded.Length == 0)
        {
            return "No diagnostic message was provided.";
        }

        var redacted = new StringBuilder(bounded.Length);
        for (var index = 0; index < bounded.Length;)
        {
            if (!IsPotentialDiagnosticSecretCharacter(bounded[index]))
            {
                redacted.Append(bounded[index++]);
                continue;
            }
            var end = index + 1;
            while (end < bounded.Length
                && IsPotentialDiagnosticSecretCharacter(bounded[end]))
            {
                end++;
            }
            if (end - index >= 32)
            {
                redacted.Append("<redacted>");
            }
            else
            {
                redacted.Append(bounded, index, end - index);
            }
            index = end;
        }
        return redacted.ToString();
    }

    private static bool IsPotentialDiagnosticSecretCharacter(char value) =>
        char.IsAsciiLetterOrDigit(value) || value is '_' or '-' or '+' or '=';
#endif

    private static string GetLauncherVersion() =>
        Assembly.GetExecutingAssembly().GetName().Version?.ToString()
        ?? throw new InvalidOperationException("Enterprise Launcher version metadata is missing.");

    private static void ValidateActiveReleaseSet(
        EnterpriseReleaseSetPointerStore store,
        EnterpriseReleaseComponentPointer? capturedRuntime,
        EnterpriseActivePluginPolicy? capturedPluginPolicy,
        EnterpriseManagedPaths paths,
        EnterpriseAccessSnapshot? accessSnapshot,
        EnterpriseInstallationLayout installationLayout)
    {
        ArgumentNullException.ThrowIfNull(paths);
        paths.ValidateWorkspaceRoot();
        EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHome(
            installationLayout);
        if (capturedRuntime is null)
        {
            throw new InvalidOperationException(
                "企业 DSH 运行时尚未安装；请运行企业安装器修复。");
        }
        if (capturedPluginPolicy is null)
        {
            throw new InvalidOperationException(
                "企业托管插件策略尚未安装；请等待管理员发布受信策略。");
        }

        var current = store.ReadRequired();
        if (current.Current.HealthState != EnterpriseReleaseHealthStates.Healthy
            || !string.Equals(
                current.Current.Runtime.ReleaseId,
                capturedRuntime.ReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                current.Current.Runtime.Directory,
                capturedRuntime.Directory,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "企业 DSH 运行时已更新；请退出并重新打开 Launcher。");
        }
        if (!new EnterpriseReleaseFeedStateStore(
                installationLayout,
                EnterpriseBuildProfile.ExpectedReleaseChannel)
            .IsCurrentAllowedOffline(current.Current, out var releaseReason))
        {
            throw new InvalidOperationException(
                $"企业更新策略已阻止启动 DSH：{releaseReason}");
        }

        var activePolicy = store.ReadActivePluginPolicyRequired(current);
        if (!string.Equals(
                activePolicy.ReleaseId,
                capturedPluginPolicy.ReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                activePolicy.PolicyId,
                capturedPluginPolicy.PolicyId,
                StringComparison.Ordinal)
            || activePolicy.Generation != capturedPluginPolicy.Generation
            || !string.Equals(
                activePolicy.PolicySha256,
                capturedPluginPolicy.PolicySha256,
                StringComparison.Ordinal)
            || !string.Equals(
                activePolicy.SkillsRoot,
                capturedPluginPolicy.SkillsRoot,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "企业托管插件策略已更新；请退出并重新打开 Launcher。");
        }

        paths.ValidateManagedSkillsRoot(activePolicy.SkillsRoot);
        EnterpriseBuildProfile.RequireVerifiedLeaseRuntimeProfile(accessSnapshot);
        if (accessSnapshot?.PluginPolicyId is not { } policyId
            || accessSnapshot.PluginPolicyGeneration is not { } policyGeneration
            || accessSnapshot.PluginPolicySha256 is not { } policySha256)
        {
            throw new InvalidOperationException(
                "当前会话没有经过验证的企业插件策略授权。");
        }
        activePolicy.RequireLeaseBinding(policyId, policyGeneration, policySha256);
    }

    private static void RunInstallationSelfCheck(Action<string>? mark = null)
    {
        mark?.Invoke("self-check-start");
        RunSelfCheck();
        mark?.Invoke("profile-layout-start");
        var layout = EnterpriseBuildProfile.CreateInstallationLayout();
        mark?.Invoke("profile-marker-start");
        EnterpriseBuildProfileMarker.ReadAndValidate(
            Path.Combine(
                AppContext.BaseDirectory,
                EnterpriseInstallationLayout.BuildProfileMarkerFileName),
            layout.LayoutProfile);
        var profile = EnterpriseBuildProfile.CreateReleaseUpdateProfile()
            ?? throw new InvalidOperationException(
                "Enterprise installation self-check has no compiled release trust.");
        var releaseSetStore = new EnterpriseReleaseSetPointerStore(
            layout,
            new EnterpriseCompiledReleaseTrust(profile.ManifestUri, profile.TrustPolicy));
        mark?.Invoke("release-pointer-validation-start");
        var releaseSet = releaseSetStore.ReadRequired();
        mark?.Invoke("active-policy-validation-start");
        _ = releaseSetStore.ReadActivePluginPolicyRequired(releaseSet);
        mark?.Invoke("active-policy-validated");
        var executableDirectory = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(AppContext.BaseDirectory));
        if (!string.Equals(
                executableDirectory,
                Path.TrimEndingDirectorySeparator(
                    Path.GetFullPath(releaseSet.Current.Launcher.Directory)),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Enterprise Launcher is not running from the active installed release.");
        }

        if (releaseSet.Current.HealthState is not EnterpriseReleaseHealthStates.Healthy
            and not EnterpriseReleaseHealthStates.Pending)
        {
            throw new InvalidOperationException(
                "Enterprise release-set health state is invalid.");
        }
    }

    private static async Task RunRuntimeInstallationHealthCheckAsync(
        Action<string>? mark = null,
        Action<string, Exception?>? observe = null)
    {
        mark?.Invoke("runtime-profile-start");
        var layout = EnterpriseBuildProfile.CreateInstallationLayout();
        var paths = EnterpriseBuildProfile.CreateManagedPaths();
        var profile = EnterpriseBuildProfile.CreateReleaseUpdateProfile()
            ?? throw new InvalidOperationException(
                "Enterprise runtime health check has no compiled release trust.");
        var store = new EnterpriseReleaseSetPointerStore(
            layout,
            new EnterpriseCompiledReleaseTrust(profile.ManifestUri, profile.TrustPolicy));
        var pending = store.ReadRequired();
        mark?.Invoke("runtime-pending-pointer-read");
        if (pending.Current.HealthState != EnterpriseReleaseHealthStates.Pending)
        {
            throw new InvalidOperationException(
                "Enterprise runtime installation health may run only for a pending release-set.");
        }
        new EnterpriseReleaseFeedStateStore(
            layout,
            profile.TrustPolicy.ExpectedChannel)
            .RequirePendingHealthAllowed(pending.Current);

        mark?.Invoke("runtime-policy-validation-start");
        var activePluginPolicy = store.ReadActivePluginPolicyRequired(pending);
        mark?.Invoke("runtime-home-validation-start");
        EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHome(layout);
        mark?.Invoke("runtime-workspace-validation-start");
        paths.EnsureWorkspaceRoot();
        paths.ValidateWorkspaceRoot();
        mark?.Invoke("runtime-skills-validation-start");
        paths.ValidateManagedSkillsRoot(activePluginPolicy.SkillsRoot);
        mark?.Invoke("runtime-port-validation-start");
        EnterpriseHarnessWriterGuard.RequireQuiescentLoopbackPort(
            EnterpriseBuildProfile.DefaultPort);

        var captured = pending.Current;
        mark?.Invoke("runtime-options-start");
#if ENTERPRISE_DIRECT_LOCAL_DEVELOPMENT_E2E || ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
        var controlPlaneOptions = EnterpriseBuildProfile.CreateControlPlaneOptions()
            ?? throw new InvalidOperationException(
                "Enterprise direct-local runtime health requires compiled control-plane trust.");
        var leaseTrustPolicy = EnterpriseBuildProfile.CreateLeaseTrustPolicy(
            controlPlaneOptions)
            ?? throw new InvalidOperationException(
                "Enterprise direct-local runtime health requires compiled lease trust.");
        var deviceKeyStore = EnterpriseBuildProfile.CreateDeviceKeyStore();
        var protectedStore = EnterpriseBuildProfile.CreateProtectedStore(paths);
        var credentialStore = new EnterpriseBindingCredentialStore(paths, protectedStore);
        var credential = await credentialStore.ReadCommittedAsync().ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                "Enterprise direct-local runtime health requires a committed signed lease.");
        var device = await new EnterpriseDeviceEnrollmentPreparation(
                new EnterpriseInstallationIdentityStore(paths),
                deviceKeyStore)
            .PrepareAsync()
            .ConfigureAwait(false);
        var trustedTimeStore = new EnterpriseTrustedTimeStore(protectedStore);
        var persistedFloorUtc = trustedTimeStore.ReadFloorUtc();
        var minimumTrustedTimeUtc = persistedFloorUtc is { } floorUtc
            && floorUtc > credential.Receipt.ServerTimeUtc
                ? floorUtc
                : credential.Receipt.ServerTimeUtc;
        var leaseVerifier = new EnterpriseAuthorizationLeaseVerifier(leaseTrustPolicy);
        var verifiedLease = leaseVerifier.VerifyPersistedCredential(
            credential,
            device,
            DateTimeOffset.UtcNow,
            minimumTrustedTimeUtc);
        EnterpriseBuildProfile.RequireVerifiedLeaseRuntimeProfile(
            verifiedLease.AccessSnapshot);
        if (verifiedLease.AccessSnapshot.PluginPolicyId is not { } policyId
            || verifiedLease.AccessSnapshot.PluginPolicyGeneration is not { } policyGeneration
            || verifiedLease.AccessSnapshot.PluginPolicySha256 is not { } policySha256)
        {
            throw new InvalidOperationException(
                "Enterprise direct-local runtime health requires a signed plugin policy binding.");
        }
        activePluginPolicy.RequireLeaseBinding(
            policyId,
            policyGeneration,
            policySha256);
        var runtimeOptions = DshRuntimeOptions.CreateEnterpriseDirectLocal(
            captured.Runtime.Directory,
            layout.HarnessHome,
            Path.Combine(layout.ManagedRoot, "logs", "release-health"),
            paths.WorkspaceRoot,
            EnterpriseBuildProfile.DefaultPort,
            activePluginPolicy.PolicyDirectory,
            activePluginPolicy.SkillsRoot);
#else
        var localEndpoint =
            $"http://127.0.0.1:{EnterpriseBuildProfile.DefaultPort}/v1";
        var controlledEnvironment = new Dictionary<string, string>(
            StringComparer.Ordinal)
        {
            ["DEEPSEEK_BASE_URL"] = localEndpoint,
            ["DEEPSEEK_SEARCH_BASE_URL"] = localEndpoint,
            ["DEEPSEEK_API_KEY"] = Convert.ToBase64String(
                    RandomNumberGenerator.GetBytes(32))
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_'),
        };
        var runtimeOptions = DshRuntimeOptions.CreateEnterpriseManaged(
            captured.Runtime.Directory,
            layout.HarnessHome,
            Path.Combine(layout.ManagedRoot, "logs", "release-health"),
            paths.WorkspaceRoot,
            EnterpriseBuildProfile.DefaultPort,
            activePluginPolicy.PolicyDirectory,
            activePluginPolicy.SkillsRoot,
            controlledEnvironment);
#endif

        mark?.Invoke("runtime-host-create-start");
        await using var host = new DshHostService(
            runtimeOptions,
            validateBeforeProcessStart: () =>
            {
#if ENTERPRISE_DIRECT_LOCAL_DEVELOPMENT_E2E || ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
                mark?.Invoke("runtime-callback-lease-validation-start");
                var callbackFloorUtc = trustedTimeStore.ReadFloorUtc();
                var callbackMinimumTrustedTimeUtc = callbackFloorUtc is { } callbackFloorValueUtc
                    && callbackFloorValueUtc > credential.Receipt.ServerTimeUtc
                        ? callbackFloorValueUtc
                        : credential.Receipt.ServerTimeUtc;
                var callbackLease = leaseVerifier.VerifyPersistedCredential(
                    credential,
                    device,
                    DateTimeOffset.UtcNow,
                    callbackMinimumTrustedTimeUtc);
                EnterpriseBuildProfile.RequireVerifiedLeaseRuntimeProfile(
                    callbackLease.AccessSnapshot);
                activePluginPolicy.RequireLeaseBinding(
                    callbackLease.Claims.PluginPolicyId,
                    callbackLease.Claims.PluginPolicyGeneration,
                    callbackLease.Claims.PluginPolicySha256);
#endif
                mark?.Invoke("runtime-callback-home-validation-start");
                EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHome(layout);
                mark?.Invoke("runtime-callback-port-validation-start");
                EnterpriseHarnessWriterGuard.RequireQuiescentLoopbackPort(
                    EnterpriseBuildProfile.DefaultPort);
                mark?.Invoke("runtime-callback-pointer-validation-start");
                var current = store.ReadRequired();
                mark?.Invoke("runtime-callback-tuple-validation-start");
                if (current.Current.HealthState != EnterpriseReleaseHealthStates.Pending
                    || !string.Equals(
                        current.Current.ReleaseSetId,
                        captured.ReleaseSetId,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        current.Current.Runtime.ReleaseId,
                        captured.Runtime.ReleaseId,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        current.Current.Runtime.Directory,
                        captured.Runtime.Directory,
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(
                        "Enterprise release-set changed during runtime installation health validation.");
                }

                mark?.Invoke("runtime-callback-policy-validation-start");
                var currentPluginPolicy = store.ReadActivePluginPolicyRequired(current);
                if (!string.Equals(
                        currentPluginPolicy.ReleaseId,
                        activePluginPolicy.ReleaseId,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        currentPluginPolicy.PolicySha256,
                        activePluginPolicy.PolicySha256,
                        StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "Enterprise plugin policy changed during runtime installation health validation.");
                }
                mark?.Invoke("runtime-callback-validated");
            },
            httpClient: null,
            healthProbeTimeout: null,
            candidateHealthRetryTimeout: null,
            validateBeforeResume: _ =>
                EnterpriseLegacySqliteUpgradeGuard
                    .RequireJsonlOnlyHarnessHome(layout),
            acquireHomeWriterSession: null,
            diagnostic: observe);
        mark?.Invoke("runtime-host-launch-start");
        var launchResult = await host.EnsureStartedAsync().ConfigureAwait(false);
        mark?.Invoke("runtime-host-launch-returned");
        if (launchResult.State != DshLaunchState.Started
            || launchResult.ProcessId is not int candidateProcessId)
        {
            throw new InvalidOperationException(
                "Enterprise candidate runtime, WebUI, and read-only session API did not pass owned-process health validation.");
        }

        mark?.Invoke("runtime-candidate-health-start");
        if (!await host.CompleteCandidateInstallHealthAsync(candidateProcessId)
                .ConfigureAwait(false))
        {
            throw new InvalidOperationException(
                "Enterprise candidate runtime, WebUI, and read-only session API did not pass owned-process health validation.");
        }

        mark?.Invoke("runtime-final-validation-start");
        paths.ValidateWorkspaceRoot();
        _ = store.ReadActivePluginPolicyRequired(store.ReadRequired());
        mark?.Invoke("runtime-health-completed");
    }

    private static void RunProductionTrustSelfCheck(string expectedSha256)
    {
#if ENTERPRISE_DEVELOPMENT_E2E
        throw new InvalidOperationException(
            "Development-E2E Launcher cannot satisfy production Pilot readiness.");
#else
        var layout = EnterpriseBuildProfile.CreateInstallationLayout();
        EnterpriseBuildProfileMarker.ReadAndValidate(
            Path.Combine(
                AppContext.BaseDirectory,
                EnterpriseInstallationLayout.BuildProfileMarkerFileName),
            EnterpriseInstallationLayout.ProductionLayoutProfile);
        EnterpriseAuthenticodeVerifier.RequireTrustedSignature(
            Environment.ProcessPath
                ?? throw new InvalidOperationException(
                    "Enterprise Launcher process path is unavailable."),
            layout);
        EnterpriseBuildProfile.RequireProductionTrustFingerprint(expectedSha256);
#endif
    }

    private async void BeginBackgroundInitialization()
    {
        try
        {
            if (_launcherWindow is not null && !_shutdownRequested)
            {
                await _launcherWindow.EnsureInitializedAsync();
            }
        }
        catch
        {
            Shutdown(1);
        }
    }

    private static void RunReleaseManifestTrustProbe()
    {
        var layout = EnterpriseBuildProfile.CreateInstallationLayout();
        var processPath = Environment.ProcessPath
            ?? throw new InvalidOperationException(
                "Enterprise Launcher process path is unavailable.");
        EnterpriseAuthenticodeVerifier.RequireTrustedSignature(processPath, layout);
        EnterpriseBuildProfileMarker.ReadAndValidate(
            Path.Combine(
                AppContext.BaseDirectory,
                EnterpriseInstallationLayout.BuildProfileMarkerFileName),
            layout.LayoutProfile);
        EnterpriseBrandContract.RequireCurrentBinary(
            Assembly.GetExecutingAssembly(),
            processPath,
            EnterpriseBrandContract.LauncherComponent,
            EnterpriseBrandContract.ProfileSha256);
        EnterpriseReleaseManifestTrustProbeRoleIdentity.RequireCurrent(
            Assembly.GetExecutingAssembly(),
            processPath,
            EnterpriseReleaseManifestTrustProbeRole.Launcher);
        var canonical = EnterpriseReleaseManifestTrustProbeContract.LoadCanonicalBytes(
            Assembly.GetExecutingAssembly(),
            layout);
        EnterpriseReleaseManifestTrustProbeContract.WriteCanonicalToStandardOutput(
            canonical);
    }

    private static void RunAuthenticatedUpdateCapabilityProbe() =>
        EnterpriseAuthenticatedUpdateCapabilityProbeContract
            .WriteCanonicalToStandardOutput();

    internal static byte[] CreateReleaseManifestTrustProbeBytesForTests(
        EnterpriseCompiledReleaseTrust trust,
        string authenticodeSignerSha256Thumbprint) =>
        EnterpriseReleaseManifestTrustProbeContract.SerializeCanonical(
            EnterpriseReleaseManifestTrustProbeContract.Create(
                trust,
                authenticodeSignerSha256Thumbprint));

    private static void RunBrandSelfCheck(string expectedBrandProfileSha256)
    {
#if ENTERPRISE_DEVELOPMENT_E2E
        throw new InvalidOperationException(
            "Development-E2E Launcher cannot satisfy production brand authorization.");
#else
        var layout = EnterpriseBuildProfile.CreateInstallationLayout();
        var processPath = Environment.ProcessPath
            ?? throw new InvalidOperationException(
                "Enterprise Launcher process path is unavailable.");
        EnterpriseAuthenticodeVerifier.RequireTrustedSignature(processPath, layout);
        EnterpriseBrandContract.RequireCurrentBinary(
            Assembly.GetExecutingAssembly(),
            processPath,
            EnterpriseBrandContract.LauncherComponent,
            expectedBrandProfileSha256);
#endif
    }

    private void CreateTrayIcon(bool visible = true)
    {
        var iconPath = Path.Combine(AppContext.BaseDirectory, "dsh-official-whale.ico");
        _applicationIcon = File.Exists(iconPath)
            ? new Icon(iconPath)
            : (Icon)SystemIcons.Application.Clone();

        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("打开企业 Launcher", null, (_, _) => ShowLauncher());
        menu.Items.Add("企业微信登录", null, async (_, _) => await BeginAuthenticationFromTrayAsync());
        _startMenuItem = new Forms.ToolStripMenuItem("启动 DSH");
        _startMenuItem.Click += async (_, _) => await StartDshFromTrayAsync();
        menu.Items.Add(_startMenuItem);
        _webUiMenuItem = new Forms.ToolStripMenuItem("打开 WebUI");
        _webUiMenuItem.Click += async (_, _) => await OpenWebUiFromTrayAsync();
        menu.Items.Add(_webUiMenuItem);
        menu.Items.Add("打开本地工作区", null, (_, _) => OpenWorkspaceFromTray());
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("退出", null, async (_, _) => await ExitFromTrayAsync());

        _trayIcon = new Forms.NotifyIcon
        {
            Text = "Ensou DSH Enterprise",
            Icon = _applicationIcon,
            ContextMenuStrip = menu,
            Visible = visible,
        };
        _trayIcon.DoubleClick += (_, _) => ShowLauncher();
    }

    private void UpdateTrayAuthorization()
    {
        var mayStart = _launcherWindow?.CanStartHarness == true;
        if (_startMenuItem is not null)
        {
            _startMenuItem.Enabled = mayStart;
        }

        if (_webUiMenuItem is not null)
        {
            _webUiMenuItem.Enabled = mayStart;
        }
    }

    private void ShowLauncher()
    {
        Dispatcher.Invoke(() =>
        {
            if (_launcherWindow is null || _incomingRestartHandoff is not null || _shutdownRequested)
            {
                return;
            }

            _launcherWindow.Show();
            if (_launcherWindow.WindowState == WindowState.Minimized)
            {
                _launcherWindow.WindowState = WindowState.Normal;
            }

            _launcherWindow.Activate();
            _launcherWindow.Topmost = true;
            _launcherWindow.Topmost = false;
            _launcherWindow.Focus();
        });
    }

    private void ActivateExistingInstance()
    {
        try
        {
            using var activationEvent = EventWaitHandle.OpenExisting(
                EnterpriseBuildProfile.ActivationEventName);
            activationEvent.Set();
        }
        catch (WaitHandleCannotBeOpenedException)
        {
            // The first process may still be creating its activation event.
        }
    }

    private void WaitForActivation(CancellationToken cancellationToken)
    {
        if (_activationEvent is null)
        {
            return;
        }

        var handles = new WaitHandle[] { _activationEvent, cancellationToken.WaitHandle };
        while (!cancellationToken.IsCancellationRequested)
        {
            var signaled = WaitHandle.WaitAny(handles);
            if (signaled == 0 && !cancellationToken.IsCancellationRequested)
            {
                Dispatcher.BeginInvoke(ShowLauncher);
            }
        }
    }

    private Task BeginAuthenticationFromTrayAsync()
    {
        ShowLauncher();
        _launcherWindow?.FocusEnterpriseLogin();
        return Task.CompletedTask;
    }

    private async Task StartDshFromTrayAsync()
    {
        ShowLauncher();
        if (_launcherWindow is not null)
        {
            await _launcherWindow.StartDshAsync();
        }
    }

    private async Task OpenWebUiFromTrayAsync()
    {
        ShowLauncher();
        if (_launcherWindow is not null)
        {
            await _launcherWindow.OpenWebUiAsync();
        }
    }

    private void OpenWorkspaceFromTray()
    {
        try
        {
            _launcherWindow?.OpenWorkspace();
        }
        catch (Exception exception)
        {
            System.Windows.MessageBox.Show(
                exception.Message,
                "Ensou DSH Enterprise 本地工作区",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private async Task ExitFromTrayAsync()
    {
        if (_shutdownRequested)
        {
            return;
        }

        _shutdownRequested = true;
        if (_launcherWindow is not null)
        {
            _launcherWindow.AllowClose = true;
        }

        if (_trayIcon is not null)
        {
            _trayIcon.Visible = false;
        }

        try
        {
            if (_session is not null)
            {
                await _session.DisposeAsync();
                _session = null;
            }
        }
        catch
        {
            // Shutdown still closes the Launcher-owned Job Object and its child process.
        }
        finally
        {
            Shutdown();
        }
    }

    private static void TryCleanup(Action cleanup)
    {
        try
        {
            cleanup();
        }
        catch
        {
            // Process exit closes the Host Job Object; cleanup remains best-effort and exhaustive.
        }
    }
}
