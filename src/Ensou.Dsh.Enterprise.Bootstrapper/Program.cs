using System.Diagnostics;
using System.Reflection;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.Bootstrapper;

internal static class Program
{
    private const string BackgroundStartupCommand = "--background-startup";
    private const string CompletePendingHealthCommand = "--complete-pending-health";
    private const string MachineCommandFailureMessage =
        "Ensou DSH Enterprise Bootstrapper machine command failed.";
    private const int CurrentStartupStubProtocol =
        EnterpriseReleaseSetContract.CurrentStartupStubProtocol;

    [STAThread]
    private static int Main(string[] args)
    {
        var isReleaseManifestTrustProbe =
            EnterpriseReleaseManifestTrustProbeContract.IsExactCommand(args);
        var isMachineCommand = IsMachineCommand(args);
        try
        {
            ApplicationConfiguration.Initialize();
            EnterpriseClientPlatform.RequireSupported();
            if (args is ["--brand-self-check", var expectedBrandProfileSha256])
            {
#if ENTERPRISE_DEVELOPMENT_E2E
                throw new InvalidOperationException(
                    "Development-E2E Bootstrapper cannot satisfy production brand authorization.");
#else
                var processPath = Environment.ProcessPath
                    ?? throw new InvalidOperationException(
                        "无法确认 Bootstrapper 可执行文件。");
                EnterpriseAuthenticodeVerifier.RequireTrustedSignature(
                    processPath,
                    CreateLayout());
                EnterpriseBrandContract.RequireCurrentBinary(
                    Assembly.GetExecutingAssembly(),
                    processPath,
                    EnterpriseBrandContract.BootstrapperComponent,
                    expectedBrandProfileSha256);
                return 0;
#endif
            }
            if (args is ["--binary-self-check"])
            {
                var binaryLayout = CreateLayout();
                EnterpriseAuthenticodeVerifier.RequireTrustedSignature(
                    Environment.ProcessPath
                        ?? throw new InvalidOperationException(
                            "无法确认 Bootstrapper 可执行文件。"),
                    binaryLayout);
                EnterpriseBuildProfileMarker.ReadAndValidate(
                    Path.Combine(
                        AppContext.BaseDirectory,
                        EnterpriseInstallationLayout.BuildProfileMarkerFileName),
                    binaryLayout.LayoutProfile);
                return 0;
            }
            if (isReleaseManifestTrustProbe)
            {
                var probeLayout = CreateLayout();
                var processPath = Environment.ProcessPath
                    ?? throw new InvalidOperationException(
                        "Enterprise Bootstrapper process path is unavailable.");
                EnterpriseAuthenticodeVerifier.RequireTrustedSignature(
                    processPath,
                    probeLayout);
                EnterpriseBuildProfileMarker.ReadAndValidate(
                    Path.Combine(
                        AppContext.BaseDirectory,
                        EnterpriseInstallationLayout.BuildProfileMarkerFileName),
                    probeLayout.LayoutProfile);
                EnterpriseBrandContract.RequireCurrentBinary(
                    Assembly.GetExecutingAssembly(),
                    processPath,
                    EnterpriseBrandContract.BootstrapperComponent,
                    EnterpriseBrandContract.ProfileSha256);
                EnterpriseReleaseManifestTrustProbeRoleIdentity.RequireCurrent(
                    Assembly.GetExecutingAssembly(),
                    processPath,
                    EnterpriseReleaseManifestTrustProbeRole.StableBootstrapper);
                var canonical = EnterpriseReleaseManifestTrustProbeContract.LoadCanonicalBytes(
                    Assembly.GetExecutingAssembly(),
                    probeLayout);
                EnterpriseReleaseManifestTrustProbeContract
                    .WriteCanonicalToStandardOutput(canonical);
                return 0;
            }

            if (!IsAllowedInstalledCommand(args))
            {
                throw new ArgumentException("企业 Bootstrapper 不接受此启动参数。");
            }

            var restartHandoff = PersonalLauncherRestartHandoffCommand.IsIntent(
                    args, LauncherRestartHandoffScope.Enterprise)
                ? PersonalLauncherRestartHandoffCommand.ParseRequired(
                    args, LauncherRestartHandoffScope.Enterprise)
                : null;

            var layout = CreateLayout();
            var installedEntry = EnsureStableInstalledEntry(layout);
            if (installedEntry)
            {
                EnterpriseStableBootstrapperVerifier.RequireTrusted(layout);
            }
            else
            {
                EnterpriseAuthenticodeVerifier.RequireTrustedSignature(
                    Environment.ProcessPath
                        ?? throw new InvalidOperationException("无法确认 Bootstrapper 可执行文件。"),
                    layout);
            }
            EnterpriseBuildProfileMarker.ReadAndValidate(
                installedEntry
                    ? layout.BuildProfileMarkerPath
                    : Path.Combine(
                        AppContext.BaseDirectory,
                        EnterpriseInstallationLayout.BuildProfileMarkerFileName),
                layout.LayoutProfile);
            var compiledReleaseTrust = EnterpriseCompiledReleaseTrustLoader.LoadRequired(
                Assembly.GetExecutingAssembly(),
                layout);
            var store = new EnterpriseReleaseSetPointerStore(
                layout,
                compiledReleaseTrust);
            var command = args.FirstOrDefault();
            if (command == "--rollback")
            {
                _ = new EnterpriseBootstrapHealthGate(
                        layout,
                        EnterpriseBootstrapHealthGate.ColdStartTimeout,
                        compiledReleaseTrust)
                    .RollbackPendingAsync("operator requested pending-release rollback")
                    .GetAwaiter()
                    .GetResult();
            }
            var pointer = store.ReadRequired();
            RequireCompatibleStartupStub(pointer.Current);
            if (command is "--maintenance-repair" or "--maintenance-uninstall")
            {
                var maintenanceExitCode = RunMaintenance(layout, pointer.Current, args);
                if (maintenanceExitCode != 0)
                {
                    throw new InvalidOperationException(
                        "企业版本化维护程序执行失败。");
                }
                return 0;
            }
            if (command == "--self-check")
            {
                if (pointer.Current.HealthState is not EnterpriseReleaseHealthStates.Healthy
                    and not EnterpriseReleaseHealthStates.Pending)
                {
                    throw new InvalidDataException("企业 release-set 健康状态无效。");
                }
                _ = RequireVersionedExecutable(
                    layout,
                    pointer.Current,
                    EnterpriseInstallationLayout.ClientBootstrapperExecutableName);
                _ = RequireVersionedExecutable(
                    layout,
                    pointer.Current,
                    EnterpriseInstallationLayout.MaintenanceExecutableName);
                return 0;
            }

            if (pointer.Current.HealthState == EnterpriseReleaseHealthStates.Pending)
            {
                _ = RunPendingHealthWithProgress(
                    layout,
                    compiledReleaseTrust,
                    command == CompletePendingHealthCommand
                        || restartHandoff is not null
                        || args is [BackgroundStartupCommand]);
                pointer = store.ReadRequired();
                if (pointer.Current.HealthState != EnterpriseReleaseHealthStates.Healthy)
                {
                    throw new InvalidDataException(
                        "企业更新未通过健康确认，且无法安全回退。");
                }
            }

            if (!new EnterpriseReleaseFeedStateStore(
                    layout,
                    compiledReleaseTrust.Policy.ExpectedChannel)
                .IsCurrentAllowedOffline(pointer.Current, out var releaseReason))
            {
                throw new InvalidOperationException(
                    $"企业更新策略已阻止启动：{releaseReason}");
            }
            RequireCompatibleStartupStub(pointer.Current);
            if (command == CompletePendingHealthCommand)
            {
                return 0;
            }
            StartVersionedBootstrapper(
                layout,
                pointer.Current,
                args is [BackgroundStartupCommand],
                restartHandoff);
            return 0;
        }
        catch (Exception exception)
        {
            PersonalLauncherRestartHandoffCommand.TrySignalFailure(
                args, LauncherRestartHandoffScope.Enterprise);
            if (isReleaseManifestTrustProbe)
            {
                EnterpriseReleaseManifestTrustProbeContract
                    .WriteBoundedFailureToStandardError();
                return 1;
            }
            if (isMachineCommand)
            {
                Console.Error.WriteLine(MachineCommandFailureMessage);
                return 1;
            }
            MessageBox.Show(
                exception.Message,
                "Ensou DSH Enterprise 无法启动",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return 1;
        }
    }

    private static void RequireCompatibleStartupStub(
        EnterpriseReleaseSetReference release) =>
        EnterpriseReleaseSetValidator.ValidateStartupStubCompatibility(
            release.StartupStub,
            CurrentStartupStubProtocol);

    internal static byte[] CreateReleaseManifestTrustProbeBytesForTests(
        EnterpriseCompiledReleaseTrust trust,
        string authenticodeSignerSha256Thumbprint) =>
        EnterpriseReleaseManifestTrustProbeContract.SerializeCanonical(
            EnterpriseReleaseManifestTrustProbeContract.Create(
                trust,
                authenticodeSignerSha256Thumbprint));

    private static EnterpriseHealthProbeResult RunPendingHealthWithProgress(
        EnterpriseInstallationLayout layout,
        EnterpriseCompiledReleaseTrust compiledReleaseTrust,
        bool backgroundStartup)
    {
        var gate = new EnterpriseBootstrapHealthGate(
            layout,
            EnterpriseBootstrapHealthGate.ColdStartTimeout,
            compiledReleaseTrust);
#if ENTERPRISE_DEVELOPMENT_E2E
        return gate.EnsureHealthyAsync(RunHealthProbeAsync)
            .GetAwaiter()
            .GetResult();
#else
        if (backgroundStartup)
        {
            return gate.EnsureHealthyAsync(RunHealthProbeAsync)
                .GetAwaiter().GetResult();
        }
        using var progress = new UpdateHealthProgressForm();
        EnterpriseHealthProbeResult? result = null;
        Exception? failure = null;
        progress.Shown += async (_, _) =>
        {
            try
            {
                result = await gate.EnsureHealthyAsync(RunHealthProbeAsync);
            }
            catch (Exception exception)
            {
                failure = exception;
            }
            finally
            {
                progress.Close();
            }
        };
        Application.Run(progress);
        if (failure is not null)
        {
            throw new InvalidOperationException(
                "企业更新健康确认失败。",
                failure);
        }
        return result ?? throw new InvalidOperationException(
            "企业更新健康确认没有返回结果。");
#endif
    }

    private static EnterpriseInstallationLayout CreateLayout()
    {
#if ENTERPRISE_DEVELOPMENT_E2E
        var localAppDataRoot = Environment.GetEnvironmentVariable(
            "ENSOU_DSH_E2E_LOCAL_APP_DATA_ROOT");
        var userProfileRoot = Environment.GetEnvironmentVariable(
            "ENSOU_DSH_E2E_USER_PROFILE_ROOT");
        if (string.IsNullOrEmpty(localAppDataRoot)
            && string.IsNullOrEmpty(userProfileRoot))
        {
            return EnterpriseInstallationLayout.CreateDevelopmentE2E();
        }
        if (string.IsNullOrEmpty(localAppDataRoot)
            || string.IsNullOrEmpty(userProfileRoot))
        {
            throw new InvalidOperationException(
                "Development E2E isolated roots must be supplied as one complete pair.");
        }
        return EnterpriseInstallationLayout.CreateDevelopmentE2E(
            localAppDataRoot,
            userProfileRoot);
#else
        return EnterpriseInstallationLayout.CreateDefault();
#endif
    }

    private static bool EnsureStableInstalledEntry(EnterpriseInstallationLayout layout)
    {
        var executablePath = Environment.ProcessPath
            ?? throw new InvalidOperationException("无法确认企业 Bootstrapper 路径。");
        if (string.Equals(
                Path.GetFullPath(executablePath),
                Path.GetFullPath(layout.BootstrapperPath),
                StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!string.Equals(
                Environment.GetEnvironmentVariable(
                    "ENSOU_DSH_ENTERPRISE_ALLOW_DEVELOPMENT_BOOTSTRAPPER"),
                "1",
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "请从安装后的企业版快捷方式启动；源码调试必须显式启用开发 Bootstrapper。" );
        }

        return false;
    }

    private static async Task<int> RunHealthProbeAsync(
        string launcherPath,
        string healthToken,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var workingDirectory = Path.GetDirectoryName(launcherPath)
            ?? throw new InvalidDataException("企业 Launcher 路径没有父目录。");
        var versionedBootstrapperPath = Path.Combine(
            workingDirectory,
            EnterpriseInstallationLayout.ClientBootstrapperExecutableName);
        if (!File.Exists(versionedBootstrapperPath)
            || (File.GetAttributes(versionedBootstrapperPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new FileNotFoundException(
                "企业 client-bundle 缺少版本化 Bootstrapper。",
                versionedBootstrapperPath);
        }
#if !ENTERPRISE_DEVELOPMENT_E2E
        EnterpriseAuthenticodeVerifier.RequireTrustedSignature(
            versionedBootstrapperPath,
            CreateLayout());
#endif
        var layout = CreateLayout();
        using var executable = EnterpriseAuthenticodeVerifier
            .OpenTrustedExecutableForLaunch(
                versionedBootstrapperPath,
                layout);
        var startInfo = new ProcessStartInfo
        {
            FileName = versionedBootstrapperPath,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        startInfo.ArgumentList.Add("--release-health-token");
        startInfo.ArgumentList.Add(healthToken);
        using var started = executable.StartContained(startInfo);
        var process = started.Process;
        try
        {
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException cancellationFailure)
        {
            try
            {
                started.TerminateRequired();
            }
            catch (Exception containmentFailure)
            {
                throw new InvalidOperationException(
                    "企业版本化 Bootstrapper 健康进程无法被证明已终止。",
                    new AggregateException(
                        cancellationFailure,
                        containmentFailure));
            }
            throw;
        }
        catch (Exception processFailure)
        {
            try
            {
                started.TerminateRequired();
            }
            catch (Exception containmentFailure)
            {
                throw new InvalidOperationException(
                    "企业版本化 Bootstrapper 健康进程失败后无法被证明已终止。",
                    new AggregateException(
                        processFailure,
                        containmentFailure));
            }
            throw;
        }
        var exitCode = process.ExitCode;
        started.CompleteRequired();
        return exitCode;
    }

    private static void StartVersionedBootstrapper(
        EnterpriseInstallationLayout layout,
        EnterpriseReleaseSetReference pointer,
        bool backgroundStartup,
        PersonalLauncherRestartHandoffCommand? restartHandoff)
    {
        var bootstrapperPath = RequireVersionedExecutable(
            layout,
            pointer,
            EnterpriseInstallationLayout.ClientBootstrapperExecutableName);
        using var executable = EnterpriseAuthenticodeVerifier
            .OpenTrustedExecutableForLaunch(bootstrapperPath, layout);
        var startInfo = new ProcessStartInfo
        {
            FileName = bootstrapperPath,
            WorkingDirectory = pointer.Launcher.Directory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = backgroundStartup || restartHandoff is not null
                ? ProcessWindowStyle.Hidden
                : ProcessWindowStyle.Normal,
        };
        if (restartHandoff is not null)
        {
            foreach (var argument in restartHandoff.ToArguments())
            {
                startInfo.ArgumentList.Add(argument);
            }
        }
        else if (backgroundStartup)
        {
            startInfo.ArgumentList.Add(BackgroundStartupCommand);
        }
        using var process = executable.Start(startInfo);
        if (restartHandoff is not null)
        {
            LauncherRestartHandoffForwarder.WaitForFinalReceiver(restartHandoff, process);
        }
    }

    private static int RunMaintenance(
        EnterpriseInstallationLayout layout,
        EnterpriseReleaseSetReference pointer,
        IReadOnlyList<string> args)
    {
        var maintenancePath = RequireVersionedExecutable(
            layout,
            pointer,
            EnterpriseInstallationLayout.MaintenanceExecutableName);
        using var executable = EnterpriseAuthenticodeVerifier
            .OpenTrustedExecutableForLaunch(maintenancePath, layout);
        var startInfo = new ProcessStartInfo
        {
            FileName = maintenancePath,
            WorkingDirectory = pointer.Launcher.Directory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        startInfo.ArgumentList.Add(
            args[0] == "--maintenance-repair" ? "--repair-shell" : "--uninstall");
        if (args[0] == "--maintenance-uninstall")
        {
            startInfo.ArgumentList.Add("--startup-stub-pid");
            startInfo.ArgumentList.Add(Environment.ProcessId.ToString(
                System.Globalization.CultureInfo.InvariantCulture));
        }
        if (args.Contains("--quiet", StringComparer.Ordinal))
        {
            startInfo.ArgumentList.Add("--quiet");
        }
        if (layout.IsDevelopmentE2E)
        {
            startInfo.ArgumentList.Add("--dev-e2e-layout");
        }
        using var started = executable.StartContained(startInfo);
        var process = started.Process;
        try
        {
            process.WaitForExit();
        }
        catch (Exception processFailure)
        {
            try
            {
                started.TerminateRequired();
            }
            catch (Exception containmentFailure)
            {
                throw new InvalidOperationException(
                    "企业版本化维护程序失败后无法被证明已终止。",
                    new AggregateException(
                        processFailure,
                        containmentFailure));
            }
            throw;
        }
        var exitCode = process.ExitCode;
        started.CompleteRequired();
        return exitCode;
    }

    private static string RequireVersionedExecutable(
        EnterpriseInstallationLayout layout,
        EnterpriseReleaseSetReference pointer,
        string fileName)
    {
        var path = Path.GetFullPath(Path.Combine(pointer.Launcher.Directory, fileName));
        var root = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(pointer.Launcher.Directory));
        if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
            || !File.Exists(path)
            || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new FileNotFoundException("企业 client-bundle 组件缺失或路径不安全。", path);
        }
#if !ENTERPRISE_DEVELOPMENT_E2E
        EnterpriseAuthenticodeVerifier.RequireTrustedSignature(path, layout);
#endif
        return path;
    }

    private static bool IsAllowedInstalledCommand(IReadOnlyList<string> args) =>
        args.Count == 0
        || args is [BackgroundStartupCommand]
        || args is [CompletePendingHealthCommand]
        || PersonalLauncherRestartHandoffCommand.TryParse(
            args, out _, LauncherRestartHandoffScope.Enterprise)
        || args is ["--rollback"]
        || args is ["--self-check"]
        || args is ["--maintenance-repair"]
        || args is ["--maintenance-uninstall"]
        || args is ["--maintenance-uninstall", "--quiet"];

    private static bool IsMachineCommand(IReadOnlyList<string> args)
    {
        var command = args.FirstOrDefault();
        return command is "--self-check"
            or "--binary-self-check"
            or "--brand-self-check"
            or BackgroundStartupCommand
            or CompletePendingHealthCommand
            or PersonalLauncherRestartHandoffCommand.EnterpriseCommandSwitch
            or EnterpriseReleaseManifestTrustProbeContract.Command
            or "--rollback"
            || (command == "--maintenance-uninstall"
                && args.Contains("--quiet", StringComparer.Ordinal));
    }

#if !ENTERPRISE_DEVELOPMENT_E2E
    private sealed class UpdateHealthProgressForm : Form
    {
        public UpdateHealthProgressForm()
        {
            Text = "Ensou DSH Enterprise 更新";
            Width = 460;
            Height = 190;
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ControlBox = false;
            ShowInTaskbar = true;
            TopMost = false;

            var title = new Label
            {
                AutoSize = true,
                Font = new Font("Segoe UI", 14, FontStyle.Bold),
                Location = new Point(24, 22),
                Text = "正在验证新版本",
            };
            var detail = new Label
            {
                AutoSize = false,
                Location = new Point(26, 62),
                Size = new Size(390, 42),
                Text = "正在启动 DeepSeek Harness 和 WebUI。首次更新可能需要几分钟，请勿关闭电脑。",
            };
            var bar = new ProgressBar
            {
                Location = new Point(27, 116),
                Size = new Size(388, 7),
                Style = ProgressBarStyle.Marquee,
                MarqueeAnimationSpeed = 24,
            };
            Controls.Add(title);
            Controls.Add(detail);
            Controls.Add(bar);
        }
    }
#endif
}
