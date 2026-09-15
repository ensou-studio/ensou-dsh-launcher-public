using System.Drawing;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Reflection;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.Host;
using Ensou.Dsh.Personal.Client;
using Ensou.Dsh.UpdateEngine;
using Forms = System.Windows.Forms;

namespace Ensou.Dsh.Launcher;

public partial class App : System.Windows.Application
{
    private const string DefaultSingleInstanceMutexName = "Local\\Ensou.Dsh.Launcher.SingleInstance";
    private const string DefaultActivationEventName = "Local\\Ensou.Dsh.Launcher.Activate";
    private Forms.NotifyIcon? _trayIcon;
    private Icon? _applicationIcon;
    private DshHostService? _hostService;
    private MainWindow? _launcherWindow;
    private bool _shutdownRequested;
    private Mutex? _singleInstanceMutex;
    private EventWaitHandle? _activationEvent;
    private CancellationTokenSource? _activationCancellation;
    private bool _ownsSingleInstanceMutex;
    private LauncherRestartReceiverLease? _incomingRestartHandoff;
    private readonly LauncherRestartOperationGate _restartOperationGate = new();
    private bool _backgroundStartup;
    private string _singleInstanceMutexName = DefaultSingleInstanceMutexName;
    private string _activationEventName = DefaultActivationEventName;
    private PersonalDevelopmentLiveUpdateContext? _developmentLiveUpdate;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        PersonalDevelopmentE2ELayoutArguments? developmentArguments;
        PersonalDevelopmentLiveUpdateArguments? developmentLiveUpdateArguments;
        string[] commandArguments;
        var developmentE2ECompiled = false;
        try
        {
            developmentE2ECompiled = PersonalDevelopmentE2ELayoutArguments.IsCompiled(
                Assembly.GetExecutingAssembly());
            developmentArguments = PersonalDevelopmentE2ELayoutArguments.ParseAndStrip(
                e.Args,
                developmentE2ECompiled,
                out commandArguments);
            developmentLiveUpdateArguments =
                PersonalDevelopmentLiveUpdateArguments.ParseAndStrip(
                    commandArguments,
                    developmentE2ECompiled,
                    developmentArguments,
                    out commandArguments);
        }
        catch
        {
            Shutdown(2);
            return;
        }

        if (developmentLiveUpdateArguments is not null)
        {
            var exactBackgroundStartup = commandArguments is ["--background-startup"];
            var exactPersonalHandoff =
                PersonalLauncherRestartHandoffCommand.TryParse(
                    commandArguments,
                    out _);
            if (developmentArguments is null
                || (!exactBackgroundStartup && !exactPersonalHandoff))
            {
                developmentLiveUpdateArguments.Dispose();
                Shutdown(2);
                return;
            }

            try
            {
                _developmentLiveUpdate = PersonalDevelopmentLiveUpdateContext.Create(
                    developmentLiveUpdateArguments,
                    developmentArguments);
                _singleInstanceMutexName = _developmentLiveUpdate.SingleInstanceMutexName;
                _activationEventName = _developmentLiveUpdate.ActivationEventName;
            }
            catch
            {
                developmentLiveUpdateArguments.Dispose();
                Shutdown(2);
                return;
            }
        }

        if (commandArguments is ["--binary-self-check"] && developmentArguments is null)
        {
            try
            {
                var fingerprint = PersonalBinarySelfCheck
                    .RequireCurrentProcessCompiledTrust(
                        PersonalInstallationLayout.LauncherExecutableName,
                        Assembly.GetExecutingAssembly());
                PersonalBinarySelfCheck.WriteCanonicalCompiledTrust(fingerprint);
                Shutdown(0);
            }
            catch
            {
                Shutdown(1);
            }
            return;
        }

        if (commandArguments is ["--personal-account-self-check"] && developmentArguments is null)
        {
            try
            {
                using var output = Console.OpenStandardOutput();
                PersonalAccountBuildSelfCheck.Write(
                    output,
                    Assembly.GetExecutingAssembly().GetCustomAttributes<AssemblyMetadataAttribute>());
                Shutdown(0);
            }
            catch
            {
                Shutdown(1);
            }
            return;
        }

        if (developmentE2ECompiled && developmentArguments is null)
        {
            Shutdown(2);
            return;
        }

        if (commandArguments is ["--release-health-token", var healthToken,
                PersonalHealthBudgetV1.ActiveDeadlineArgument, var activeDeadlineText])
        {
            var healthTrace = new HealthProbeDiagnostics(
                "launcher", developmentE2ECompiled && developmentArguments is not null);
            try
            {
                healthTrace.Mark("command_begin");
                var activeDeadline = PersonalHealthBudgetV1.ParseDeadlineTickCount64(
                    activeDeadlineText, PersonalHealthBudgetV1.ActiveHealthEnvelope);
                RunReleaseHealthProbeAsync(
                        healthToken,
                        developmentArguments?.Layout,
                        healthTrace,
                        activeDeadline)
                    .GetAwaiter()
                    .GetResult();
                healthTrace.Mark("command_passed");
                Shutdown(0);
            }
            catch (Exception exception)
            {
                healthTrace.Mark("command_failed", exception);
                if (developmentArguments is not null)
                {
                    try
                    {
                        var cause = exception.GetBaseException();
                        // Never emit exception messages, paths, or the health token.
                        Console.Error.WriteLine(
                            $"PERSONAL_DEVELOPMENT_HEALTH_FAILED:{cause.GetType().Name}:{cause.HResult}");
                    }
                    catch
                    {
                        // A diagnostic stream failure must not change health exit behavior.
                    }
                }
                Shutdown(1);
            }
            return;
        }
        if (developmentArguments is not null && _developmentLiveUpdate is null)
        {
            Shutdown(2);
            return;
        }

        if (PersonalLauncherRestartHandoffCommand.IsIntent(commandArguments))
        {
            PersonalLauncherRestartHandoffCommand? handoff = null;
            try
            {
                handoff = PersonalLauncherRestartHandoffCommand.ParseRequired(
                    commandArguments);
                var accepted = LauncherRestartCoordinator.AcceptHandoff(
                    handoff,
                    _singleInstanceMutexName);
                _singleInstanceMutex = accepted.Singleton;
                _incomingRestartHandoff = accepted.Receiver;
                _ownsSingleInstanceMutex = true;
                _backgroundStartup = handoff.BackgroundStartup;
            }
            catch
            {
                handoff?.TrySignalFailure();
                Shutdown(1);
                return;
            }
        }
        else
        {
            if (commandArguments is ["--background-startup"])
            {
                _backgroundStartup = true;
            }
            else if (commandArguments.Length != 0)
            {
                Shutdown(2);
                return;
            }

            _singleInstanceMutex = new Mutex(
                initiallyOwned: true,
                _singleInstanceMutexName,
                out var isFirstInstance);
            _ownsSingleInstanceMutex = isFirstInstance;
            if (!isFirstInstance)
            {
                try
                {
                    if (!_backgroundStartup)
                    {
                        using var activationEvent = EventWaitHandle.OpenExisting(
                            _activationEventName);
                        activationEvent.Set();
                    }
                }
                catch (WaitHandleCannotBeOpenedException)
                {
                    // The first process may still be between mutex creation and event creation.
                }

                Shutdown();
                return;
            }
        }

        _activationEvent = new EventWaitHandle(
            initialState: false,
            EventResetMode.AutoReset,
            _activationEventName);
        _activationCancellation = new CancellationTokenSource();
        _ = Task.Run(() => WaitForActivation(_activationCancellation.Token));

        try
        {
            var installationLayout = _developmentLiveUpdate?.Layout
                ?? PersonalInstallationLayout.CreateDefault();
            var settings = _developmentLiveUpdate?.CreateSettings()
                ?? LauncherSettings.LoadOrCreate();
            _developmentLiveUpdate?.RequireCurrentExpectedSequence();
            var admittedRuntimeDirectory = settings.ResolveRuntimeDirectory(
                installationLayout);
            var runtimeSupportsManagedUpdate =
                DshRuntimeMetadata.ReadSupportsPersonalManagedUpdate(admittedRuntimeDirectory);
            if (_developmentLiveUpdate is not null && !runtimeSupportsManagedUpdate)
            {
                throw new InvalidDataException(
                    "Personal development live-update requires a schema-2 personal-web-v1 Runtime.");
            }
            var runtimeOptions = runtimeSupportsManagedUpdate
                ? DshRuntimeOptions.CreatePersonalManagedWeb(
                    admittedRuntimeDirectory,
                    settings.DshDataDirectory,
                    settings.LogDirectory,
                    settings.Port)
                : new DshRuntimeOptions(
                    admittedRuntimeDirectory,
                    settings.DshDataDirectory,
                    settings.LogDirectory,
                    Port: settings.Port);

            _hostService = new DshHostService(
                runtimeOptions,
                validateBeforeProcessStart: () =>
                    RequireSamePersonalRuntimeForLaunch(
                        settings,
                        admittedRuntimeDirectory,
                        installationLayout),
                acquireHomeWriterSession: () =>
                    AcquirePersonalHomeWriterSession(
                        settings,
                        admittedRuntimeDirectory,
                        installationLayout));
            _launcherWindow = new MainWindow(
                settings,
                _hostService,
                runtimeSupportsManagedUpdate,
                _developmentLiveUpdate);
            MainWindow = _launcherWindow;
            if (_developmentLiveUpdate is null)
            {
                CreateTrayIcon(visible: _incomingRestartHandoff is null);
            }
            DispatchStartupAction();
        }
        catch (Exception exception)
        {
            if (_incomingRestartHandoff is not null)
            {
                _incomingRestartHandoff.TrySignalFailure();
                Shutdown(1);
                return;
            }

            if (_developmentLiveUpdate is null)
            {
                System.Windows.MessageBox.Show(
                    exception.Message,
                    "Ensou DSH Launcher 配置错误",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
            Shutdown(1);
        }
    }

    private void DispatchStartupAction()
    {
        switch (LauncherStartupPolicy.SelectAction(
            _incomingRestartHandoff is not null,
            _backgroundStartup))
        {
            case LauncherStartupAction.CompleteRestartHandoff:
                _ = Dispatcher.BeginInvoke(
                    DispatcherPriority.ApplicationIdle,
                    BeginIncomingRestartHandoff);
                break;
            case LauncherStartupAction.InitializeBackground:
                _ = Dispatcher.BeginInvoke(BeginBackgroundInitialization);
                break;
            case LauncherStartupAction.ShowLauncher:
                ShowLauncher();
                break;
            default:
                throw new InvalidOperationException("Unknown Launcher startup action.");
        }
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

    private static IDshHomeWriterSession AcquirePersonalHomeWriterSession(
        LauncherSettings settings,
        string admittedRuntimeDirectory,
        PersonalInstallationLayout layout)
    {
        using var lease = new PersonalHarnessHomeCoordinator(settings.DshDataDirectory)
            .AcquireLease(() =>
                PersonalHarnessWriterGuard.RequireQuiescentLoopbackPort(settings.Port));
        lease.RequireMutationAdmission(settings.DshDataDirectory);
        var atomicAdmission = RequireSamePersonalRuntimeForLaunch(
            settings,
            admittedRuntimeDirectory,
            layout);
        return atomicAdmission ? lease.BeginAtomicRuntimeSession() : lease.BeginRuntimeSession();
    }

    private static bool RequireSamePersonalRuntimeForLaunch(
        LauncherSettings settings,
        string admittedRuntimeDirectory,
        PersonalInstallationLayout layout)
    {
        var allowDevelopmentRuntime = string.Equals(
            Environment.GetEnvironmentVariable(
                "ENSOU_DSH_ALLOW_DEVELOPMENT_RUNTIME"),
            "1",
            StringComparison.Ordinal);
        var releaseSet = new PersonalReleaseSetPointerStore(layout).TryRead();
        // An environment flag cannot bypass an already-present managed installation.
        var unmanagedDevelopmentRuntime = allowDevelopmentRuntime && releaseSet is null;
        string currentRuntimeDirectory;
        if (unmanagedDevelopmentRuntime)
        {
            currentRuntimeDirectory = settings.ResolveRuntimeDirectory(layout);
        }
        else
        {
            if (!string.Equals(
                    Path.TrimEndingDirectorySeparator(Path.GetFullPath(settings.DshDataDirectory)),
                    layout.HarnessHome,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "Personal v2 启动需要使用受管数据目录；请先恢复 Launcher 的数据目录配置。");
            }
            if (releaseSet is null)
                throw new InvalidDataException(
                    "当前 Personal 安装仍是旧版运行时，不能作为可信源码运行时启动。请运行最新的已签名 Ensou DSH Personal Installer；安装程序会自动迁移旧版并保留本地对话与工作区。若迁移中断，请再次运行同一安装程序并选择修复。");
            if (releaseSet.Current.HealthState
                    != PersonalReleaseHealthStates.Healthy
                || new PersonalHarnessHomeTransaction(layout.HarnessHome, layout.HarnessRecoveryRoot)
                    .TryReadActive() is not null)
            {
                throw new InvalidDataException(
                    "[PERSONAL_HOME_UPDATE_PENDING] Personal release-set 尚未完成健康验证或数据恢复；请通过稳定启动器重新启动，或运行最新的已签名安装程序进行修复。");
            }
            PersonalAtomicHomeCompatibility.RequireCompatibleStartupStub(releaseSet.Current.StartupStub);
            currentRuntimeDirectory = releaseSet.Current.Runtime.Directory;
        }
        if (!string.Equals(
                Path.TrimEndingDirectorySeparator(
                    Path.GetFullPath(currentRuntimeDirectory)),
                Path.TrimEndingDirectorySeparator(
                    Path.GetFullPath(admittedRuntimeDirectory)),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Personal DSH runtime changed after Launcher startup; restart Launcher before starting DSH.");
        }
        // An explicitly unmanaged development runtime retains the legacy protocol; it has no signed Stub floor.
        return !unmanagedDevelopmentRuntime;
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _shutdownRequested = true;
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
        TryCleanup(() =>
        {
            _hostService?.DisposeAsync().AsTask().GetAwaiter().GetResult();
            _hostService = null;
        });
        TryCleanup(() => _activationEvent?.Dispose());
        TryCleanup(() => _activationCancellation?.Dispose());
        if (_ownsSingleInstanceMutex)
        {
            TryCleanup(() => _singleInstanceMutex?.ReleaseMutex());
        }

        TryCleanup(() => _incomingRestartHandoff?.Dispose());
        _incomingRestartHandoff = null;
        TryCleanup(() => _developmentLiveUpdate?.Arguments.Dispose());
        _developmentLiveUpdate = null;
        TryCleanup(() => _singleInstanceMutex?.Dispose());
        base.OnExit(e);
    }

    private static void TryCleanup(Action cleanup)
    {
        try
        {
            cleanup();
        }
        catch
        {
            // Process exit closes the Host Job Object; shutdown cleanup remains
            // best-effort and exhaustive without surfacing a dotnet error box.
        }
    }

    internal void HideLauncher()
    {
        if (!_shutdownRequested)
        {
            TryCleanup(() => _launcherWindow?.Hide());
        }
    }

    internal async Task<bool> RestartLauncherAsync()
    {
        if (!_restartOperationGate.TryEnter(out var restartOperation))
        {
            TryCleanup(() => _launcherWindow?.ReportRestartFailure(
                "Launcher 重启已在进行。"));
            return false;
        }
        using var activeRestartOperation = restartOperation!;

        try
        {
            var target = ResolveRestartTarget();
            using var expectedReceiver = PersonalCompiledTrustProcessVerifier
                .AcquireExecutableLaunchLease(
                    target.ExpectedLauncherPath,
                    PersonalInstallationLayout.LauncherExecutableName,
                    target.ExpectedTrust);
            using var trustedEntry = PersonalCompiledTrustProcessVerifier
                .AcquireExecutableLaunchLease(
                    target.EntryExecutablePath,
                    target.EntryExecutableName,
                    target.ExpectedTrust);
            var attempt = await LauncherRestartCoordinator.TryStartAsync(
                () => target.EntryExecutablePath,
                PrepareHostForRestartAsync,
                startInfo =>
                {
                    if (_developmentLiveUpdate is not null)
                    {
                        foreach (var argument in _developmentLiveUpdate.LayoutArguments)
                        {
                            startInfo.ArgumentList.Add(argument);
                        }
                        foreach (var argument in _developmentLiveUpdate.Arguments.ToArguments())
                        {
                            startInfo.ArgumentList.Add(argument);
                        }
                    }
                    return trustedEntry.Start(startInfo);
                },
                ReleaseSingleInstanceForHandoff,
                TryReacquireSingleInstance,
                Environment.ProcessId,
                receiverConnectionTimeout: string.Equals(
                    target.EntryExecutableName,
                    PersonalInstallationLayout.StartupStubExecutableName,
                    StringComparison.Ordinal)
                    ? PersonalHealthBudgetV1.OverallHealthEnvelope
                        + LauncherRestartCoordinator.DefaultHandoffTimeout
                    : null,
                backgroundStartup: _backgroundStartup || _launcherWindow?.IsVisible != true,
                validateReceiverProcess: process =>
                    ValidateRestartReceiver(process, expectedReceiver));
            if (!attempt.ReadyForParentExit)
            {
                var failure = attempt.Failure ?? "Launcher 重启失败。";
                if (attempt.ParentOwnershipProven)
                {
                    RecoverRestartFailure(failure);
                }
                else
                {
                    FailClosedRestartWithoutParentOwnership(failure);
                }
                return false;
            }
            using var handoff = attempt.Handoff!;

            _shutdownRequested = true;
            TryCleanup(() =>
            {
                if (_launcherWindow is not null)
                {
                    _launcherWindow.AllowClose = true;
                }
            });
            TryCleanup(() =>
            {
                if (_trayIcon is not null)
                {
                    _trayIcon.Visible = false;
                }
            });

            try
            {
                handoff.Commit();
                Shutdown();
                return true;
            }
            catch (Exception exception)
            {
                var ownership = handoff.CancelAndReacquire();
                var failure = ownership.Failure
                    ?? LauncherRestartCoordinator.NormalizeFailure(exception);
                if (ownership.ParentOwnershipProven)
                {
                    RecoverRestartFailure(failure);
                }
                else
                {
                    FailClosedRestartWithoutParentOwnership(failure);
                }
                return false;
            }
        }
        catch (Exception exception)
        {
            RecoverRestartFailure(
                LauncherRestartCoordinator.NormalizeFailure(exception));
            return false;
        }
    }

    private LauncherRestartTarget ResolveRestartTarget()
    {
        var layout = _developmentLiveUpdate?.Layout
            ?? PersonalInstallationLayout.CreateDefault();
        var currentTrust = PersonalBinarySelfCheck
            .RequireCurrentRuntimeProcessCompiledTrust(
                PersonalInstallationLayout.LauncherExecutableName,
                Assembly.GetExecutingAssembly());
        var currentLauncherPath = Environment.ProcessPath
            ?? throw new InvalidOperationException(
                "无法确定当前 Launcher 可执行文件路径。");
        var pointer = new PersonalReleaseSetPointerStore(layout).TryRead();
        if (File.Exists(layout.StartupStubPath) && pointer is not null)
        {
            var activeClientExecutables = PersonalMaintenanceIntegrity
                .RequireActiveClientBundle(layout, pointer.Current);
            return new LauncherRestartTarget(
                layout.StartupStubPath,
                PersonalInstallationLayout.StartupStubExecutableName,
                activeClientExecutables[1],
                currentTrust);
        }

        return new LauncherRestartTarget(
            currentLauncherPath,
            PersonalInstallationLayout.LauncherExecutableName,
            currentLauncherPath,
            currentTrust);
    }

    private static void ValidateRestartReceiver(
        Process process,
        PersonalTrustedExecutableLaunchLease expectedReceiver)
    {
        ArgumentNullException.ThrowIfNull(process);
        ArgumentNullException.ThrowIfNull(expectedReceiver);
        try
        {
            expectedReceiver.RequireProcessImage(process);
        }
        catch (Exception validationFailure) when (
            expectedReceiver.RetainsRejectedProcess(process))
        {
            throw new LauncherRestartReceiverProcessRetainedException(
                process,
                validationFailure);
        }
    }

    private void ReleaseSingleInstanceForHandoff()
    {
        Dispatcher.Invoke(() =>
        {
            if (_singleInstanceMutex is null || !_ownsSingleInstanceMutex)
            {
                throw new InvalidOperationException(
                    "Launcher 无法释放未持有的单实例所有权。");
            }

            _singleInstanceMutex.ReleaseMutex();
            _ownsSingleInstanceMutex = false;
        });
    }

    private bool TryReacquireSingleInstance(TimeSpan timeout) =>
        Dispatcher.Invoke(() =>
        {
            if (_ownsSingleInstanceMutex)
            {
                return true;
            }
            if (_singleInstanceMutex is null)
            {
                return false;
            }

            try
            {
                _ownsSingleInstanceMutex = _singleInstanceMutex.WaitOne(timeout);
            }
            catch (AbandonedMutexException)
            {
                _ownsSingleInstanceMutex = true;
            }
            return _ownsSingleInstanceMutex;
        });

    private static Task PrepareHostForRestartAsync() =>
        // Destructive Host cleanup is deliberately deferred to OnExit. If the
        // replacement fails after READY, the current MainWindow must keep its
        // live DshHostService and remain a coherent rollback target.
        Task.CompletedTask;

    private void BeginIncomingRestartHandoff()
    {
        var handoff = _incomingRestartHandoff;
        if (handoff is null)
        {
            return;
        }

        try
        {
            if (_developmentLiveUpdate?.TryCreateFirstReceiverFailureMarker() == true)
            {
                handoff.TrySignalFailure();
                Shutdown(1);
                return;
            }
            handoff.MarkReady();
            _ = CompleteIncomingRestartHandoffAsync(handoff);
        }
        catch
        {
            handoff.TrySignalFailure();
            Shutdown(1);
        }
    }

    private async Task CompleteIncomingRestartHandoffAsync(
        LauncherRestartReceiverLease handoff)
    {
        try
        {
            var outcome = await handoff.WaitForParentExitAsync();
            if (outcome == LauncherRestartReceiverOutcome.AbortRequested)
            {
                ReleaseSingleInstanceForHandoff();
                handoff.SignalReleased();
                var rollback = await handoff
                    .WaitForRollbackOwnedOrParentExitAsync();
                if (rollback == LauncherRestartRollbackOutcome.RollbackOwned)
                {
                    Shutdown(1);
                    return;
                }

                if (!TryReacquireSingleInstance(Timeout.InfiniteTimeSpan))
                {
                    throw new InvalidOperationException(
                        "替代 Launcher 在旧实例退出后无法重新取得单实例所有权。");
                }
            }

            CompleteIncomingRestartTakeover(handoff);
        }
        catch
        {
            handoff.TrySignalFailure();
            Shutdown(1);
        }
    }

    private void CompleteIncomingRestartTakeover(
        LauncherRestartReceiverLease handoff)
    {
        if (!ReferenceEquals(_incomingRestartHandoff, handoff))
        {
            throw new InvalidOperationException(
                "Launcher restart receiver changed before parent exit.");
        }

        _incomingRestartHandoff = null;
        handoff.Dispose();
        if (_trayIcon is not null && _developmentLiveUpdate is null)
        {
            _trayIcon.Visible = true;
        }
        DispatchStartupAction();
    }

    private void RecoverRestartFailure(string failure)
    {
        if (!_ownsSingleInstanceMutex)
        {
            FailClosedRestartWithoutParentOwnership(failure);
            return;
        }

        _shutdownRequested = false;
        if (_developmentLiveUpdate is not null)
        {
            TryCleanup(() =>
            {
                if (_trayIcon is not null)
                {
                    _trayIcon.Visible = false;
                }
            });
            return;
        }
        TryCleanup(() =>
        {
            if (_trayIcon is not null)
            {
                _trayIcon.Visible = true;
            }
        });
        TryCleanup(() =>
        {
            if (_launcherWindow is not null)
            {
                _launcherWindow.AllowClose = false;
                _launcherWindow.ReportRestartFailure(failure);
            }
        });
        TryCleanup(ShowLauncher);
    }

    private void FailClosedRestartWithoutParentOwnership(string failure)
    {
        _shutdownRequested = true;
        TryCleanup(() => _launcherWindow?.ShutdownAccountMonitor());
        Trace.TraceError(
            "Launcher restart terminated without proven parent ownership: {0}",
            failure);
        TryCleanup(() =>
        {
            if (_trayIcon is not null)
            {
                _trayIcon.Visible = false;
            }
        });
        TryCleanup(() => _launcherWindow?.Hide());
        try
        {
            Shutdown(1);
        }
        catch
        {
            Environment.Exit(1);
        }
    }

    private static async Task RunReleaseHealthProbeAsync(
        string healthToken,
        PersonalInstallationLayout? developmentLayout,
        HealthProbeDiagnostics diagnostic,
        long activeDeadlineTickCount64)
    {
        using var healthDeadline = PersonalHealthBudgetV1.CreateCancellationUntil(
            activeDeadlineTickCount64, PersonalHealthBudgetV1.ActiveHealthEnvelope);
        var cancellationToken = healthDeadline.Token;
        cancellationToken.ThrowIfCancellationRequested();
        var layout = developmentLayout ?? PersonalInstallationLayout.CreateDefault();
        var settings = developmentLayout is null
            ? LauncherSettings.LoadOrCreate()
            : null;
        var healthPort = PersonalDevelopmentE2EHealthPort.Resolve(
            settings?.Port ?? 3080,
            developmentLayoutAdmitted: developmentLayout is not null);
        var healthLogDirectory = settings?.LogDirectory
            ?? Path.Combine(layout.StateRoot, "release-health-logs");
        if (settings is not null
            && !string.Equals(
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(settings.DshDataDirectory)),
                layout.HarnessHome,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Personal v2 health requires the certified default Harness home.");
        }
        var store = new PersonalReleaseSetPointerStore(layout);
        diagnostic.Mark("pointer_initial_begin");
        var pointer = store.ReadRequired(cancellationToken);
        diagnostic.Mark("pointer_initial_end");
        if (pointer.Current.HealthState != PersonalReleaseHealthStates.Pending
            || !string.Equals(pointer.Current.HealthToken, healthToken, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal Launcher health token does not match the pending release.");
        }
        PersonalAtomicHomeCompatibility.RequireCompatibleStartupStub(pointer.Current.StartupStub);
        if (string.Equals(
                pointer.Current.HomeTransactionId,
                PersonalReleaseSetPointerStore.NoHomeTransactionSentinel,
                StringComparison.Ordinal))
        {
            if (PersonalReleaseVersion.Compare(
                    pointer.Current.StartupStub.MinimumVersion,
                    PersonalReleaseArtifactInstaller.NoHomeMinimumStartupStubVersion) < 0)
            {
                throw new InvalidDataException(
                    "Personal no-home health is not fenced to the compatible Startup Stub.");
            }
            var actualLauncherPath = Path.GetFullPath(
                Environment.ProcessPath
                ?? throw new InvalidOperationException(
                    "Personal Launcher health cannot identify its process image."));
            var expectedLauncherPath = Path.GetFullPath(Path.Combine(
                pointer.Current.ClientBundle.Directory,
                PersonalInstallationLayout.LauncherExecutableName));
            if (!string.Equals(
                    actualLauncherPath,
                    expectedLauncherPath,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "Personal no-home health is not running from the active client bundle.");
            }
            PersonalAuthenticodeVerifier.RequireTrustedEnsouExecutable(actualLauncherPath);
            var processId = Environment.ProcessId;
            var launcherOnlySummary = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
                string.Join(
                    '\n',
                    "ensou-personal-launcher-only-health-v1",
                    pointer.Current.ReleaseSetId,
                    pointer.Current.ClientBundle.ReleaseId,
                    pointer.Current.ClientBundle.ArchiveSha256,
                    pointer.Current.Runtime.ReleaseId,
                    processId.ToString(
                        System.Globalization.CultureInfo.InvariantCulture),
                    "active-launcher-process-no-harness-home"))));
            new PersonalReleaseHealthCoordinator(layout).WriteSignal(
                healthToken,
                processId,
                launcherOnlySummary,
                cancellationToken);
            return;
        }
        diagnostic.Mark("home_admission_begin");
        using var homeLease = new PersonalHarnessHomeCoordinator(layout.HarnessHome)
            .AcquireLease(() =>
                PersonalHarnessWriterGuard.RequireQuiescentLoopbackPort(healthPort));
        homeLease.RequireMutationAdmission(layout.HarnessHome);
        diagnostic.Mark("home_admission_end");
        diagnostic.Mark("pointer_admitted_begin");
        pointer = store.ReadRequired(cancellationToken);
        diagnostic.Mark("pointer_admitted_end");
        if (pointer.Current.HealthState != PersonalReleaseHealthStates.Pending
            || !string.Equals(pointer.Current.HealthToken, healthToken, StringComparison.Ordinal)
            || PersonalReleaseSetPointerStore.GetPendingHomeTransactionMode(pointer)
                != PersonalReleaseHomeTransactionMode.Required)
        {
            throw new InvalidDataException(
                "Personal pending release changed before home health admission.");
        }
        var transaction = new PersonalHarnessHomeTransaction(
            layout.HarnessHome,
            layout.HarnessRecoveryRoot,
            homeLease);
        var active = transaction.TryReadActive()
            ?? throw new InvalidDataException(
                "Personal Launcher health has no complete Harness-home recovery generation.");
        if (active.Status != PersonalHarnessHomeTransaction.PreparedStatus
            || !string.Equals(
                active.ReleaseSetId,
                pointer.Current.ReleaseSetId,
                StringComparison.Ordinal)
            || !string.Equals(
                active.TransactionId,
                pointer.Current.HomeTransactionId,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal Launcher health recovery generation is inconsistent.");
        }

        PersonalHarnessWriterGuard.RequireAvailableLoopbackPort(healthPort);
        diagnostic.Mark("home_health_attempt_begin");
        cancellationToken.ThrowIfCancellationRequested();
        homeLease.AdmitHealthAttempt(active.TransactionId, healthToken);
        diagnostic.Mark("home_health_attempt_end");
        var capturedReleaseSetId = pointer.Current.ReleaseSetId;
        var capturedRuntimeReleaseId = pointer.Current.Runtime.ReleaseId;
        var options = new DshRuntimeOptions(
            pointer.Current.Runtime.Directory,
            layout.HarnessHome,
            healthLogDirectory,
            Port: healthPort,
            StartupTimeout: TimeSpan.FromSeconds(90));
        await using var host = new DshHostService(
            options,
            validateBeforeProcessStart: () =>
            {
                PersonalHarnessWriterGuard.RequireAvailableLoopbackPort(healthPort);
                diagnostic.Mark("pointer_before_start_begin");
                var current = store.ReadRequired(cancellationToken);
                diagnostic.Mark("pointer_before_start_end");
                var currentHome = transaction.TryReadActive();
                if (current.Current.HealthState != PersonalReleaseHealthStates.Pending
                    || !string.Equals(
                        current.Current.HealthToken,
                        healthToken,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        current.Current.ReleaseSetId,
                        capturedReleaseSetId,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        current.Current.Runtime.ReleaseId,
                        capturedRuntimeReleaseId,
                        StringComparison.Ordinal)
                    || currentHome is null
                    || currentHome.Status != PersonalHarnessHomeTransaction.PreparedStatus
                    || !string.Equals(
                        currentHome.TransactionId,
                        current.Current.HomeTransactionId,
                        StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "Personal pending release changed before Runtime health start.");
                    }
                },
            httpClient: null,
            healthProbeTimeout: null,
            candidateHealthRetryTimeout: null,
            validateBeforeResume: null,
            acquireHomeWriterSession: homeLease.BeginAtomicRuntimeSession,
            diagnostic: (phase, exception) => diagnostic.Mark(phase, exception));
        diagnostic.Mark("runtime_start_begin", budgetMilliseconds: 90000);
        var launched = await host.EnsureStartedAsync(cancellationToken).ConfigureAwait(false);
        diagnostic.Mark("runtime_start_end", childProcessId: launched.ProcessId);
        if (launched.State != DshLaunchState.Started
            || !host.OwnsRunningProcess)
        {
            throw new InvalidOperationException(
                "Personal candidate Runtime and WebUI did not pass owned-process health.");
        }
        var runtimeProcessId = launched.ProcessId
            ?? throw new InvalidDataException(
                "Personal candidate Runtime health did not report its owned process id.");
        diagnostic.Mark("runtime_api_stop_begin", childProcessId: runtimeProcessId);
        if (!await host.CompleteCandidateInstallHealthAsync(runtimeProcessId, cancellationToken)
                .ConfigureAwait(false))
        {
            throw new InvalidOperationException(
                "Personal candidate Runtime did not remain the same owned process through API health and controlled stop.");
        }
        diagnostic.Mark("runtime_api_stop_end", childProcessId: runtimeProcessId);
        diagnostic.Mark("home_candidate_read_begin");
        cancellationToken.ThrowIfCancellationRequested();
        var homeEvidence = transaction.VerifyCandidateReadable(active.TransactionId);
        cancellationToken.ThrowIfCancellationRequested();
        diagnostic.Mark("home_candidate_read_end");
        homeLease.CompleteHealthAttempt(active.TransactionId, healthToken);
        var summary = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
            string.Join(
                '\n',
                "ensou-personal-release-health-v2",
                pointer.Current.ReleaseSetId,
                pointer.Current.Runtime.ReleaseId,
                runtimeProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "owned-runtime-webui-session-list-exact-pid-controlled-stop",
                homeEvidence.TreeSha256,
                homeEvidence.FileCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
                homeEvidence.SizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture)))));
        diagnostic.Mark("signal_write_begin");
        new PersonalReleaseHealthCoordinator(layout, homeLease).WriteSignal(
            healthToken,
            runtimeProcessId,
            summary,
            cancellationToken);
        diagnostic.Mark("signal_write_end");
    }

    private void CreateTrayIcon(bool visible = true)
    {
        _applicationIcon = LauncherBrandAssets.LoadDrawingIcon();

        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("打开 Launcher", null, (_, _) =>
            RunTrayAction(ShowLauncher));
        menu.Items.Add("启动 DSH", null, async (_, _) =>
            await RunTrayOperationAsync(StartDshFromTrayAsync));
        menu.Items.Add("打开 WebUI", null, async (_, _) =>
            await RunTrayOperationAsync(OpenWebUiAsync));
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("退出", null, async (_, _) =>
            await RunTrayOperationAsync(ExitFromTrayAsync));

        _trayIcon = new Forms.NotifyIcon
        {
            Text = "Ensou DSH Launcher",
            Icon = _applicationIcon,
            ContextMenuStrip = menu,
            Visible = visible
        };
        _trayIcon.DoubleClick += (_, _) => RunTrayAction(ShowLauncher);
    }

    private void RunTrayAction(Action action)
    {
        try
        {
            action();
        }
        catch (Exception exception)
        {
            ReportTrayFailure(exception);
        }
    }

    private async Task RunTrayOperationAsync(Func<Task> operation)
    {
        try
        {
            await operation();
        }
        catch (Exception exception)
        {
            ReportTrayFailure(exception);
        }
    }

    private void ReportTrayFailure(Exception exception)
    {
        try
        {
            var failure = LauncherRestartCoordinator.NormalizeFailure(exception);
            TryCleanup(() => _launcherWindow?.ReportBackgroundOperationFailure(failure));
            TryCleanup(ShowLauncher);
        }
        catch
        {
            // WinForms async event callbacks must not escape into the runtime
            // while the tray or WPF dispatcher is being torn down.
        }
    }

    private void ShowLauncher()
    {
        Dispatcher.Invoke(() =>
        {
            if (_launcherWindow is null)
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
            if (signaled == 0
                && !cancellationToken.IsCancellationRequested
                && _developmentLiveUpdate is null
                && _incomingRestartHandoff is null)
            {
                Dispatcher.BeginInvoke(() => RunTrayAction(ShowLauncher));
            }
        }
    }

    private async Task StartDshFromTrayAsync()
    {
        if (_launcherWindow is null)
        {
            return;
        }

        ShowLauncher();
        await _launcherWindow.StartDshAsync();
    }

    private async Task OpenWebUiAsync()
    {
        if (_launcherWindow is not null)
        {
            await _launcherWindow.OpenWebUiAsync();
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
            if (_hostService is not null)
            {
                await _hostService.DisposeAsync();
                _hostService = null;
            }
        }
        catch
        {
            // Shutdown still closes the Launcher-owned Job Object and process.
        }
        finally
        {
            Shutdown();
        }
    }

    private sealed record LauncherRestartTarget(
        string EntryExecutablePath,
        string EntryExecutableName,
        string ExpectedLauncherPath,
        PersonalCompiledTrustFingerprint ExpectedTrust);
}
