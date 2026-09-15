using System.Diagnostics;
using System.Reflection;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.ClientBootstrapper;

internal static class Program
{
    private const string BackgroundStartupCommand = "--background-startup";
    public const string ExecutableName = "Ensou.Dsh.Enterprise.ClientBootstrapper.exe";
    private const string MachineCommandFailureMessage =
        "Ensou DSH Enterprise ClientBootstrapper machine command failed.";

    [STAThread]
    private static int Main(string[] args)
    {
        var isReleaseManifestTrustProbe =
            EnterpriseReleaseManifestTrustProbeContract.IsExactCommand(args);
        var isMachineCommand = IsMachineCommandIntent(args);
#if ENTERPRISE_DEVELOPMENT_E2E
        EnterpriseDevelopmentHealthDiagnostics? healthDiagnostics = null;
        if (args is ["--release-health-token", _])
        {
            try
            {
                healthDiagnostics = new(CreateLayout(), "client-bootstrapper");
                healthDiagnostics.Mark("entry");
            }
            catch
            {
                // Diagnostic setup must never change health admission or exit behavior.
            }
        }
#endif
        try
        {
            ApplicationConfiguration.Initialize();
            EnterpriseClientPlatform.RequireSupported();
            var layout = CreateLayout();
            var restartHandoff = PersonalLauncherRestartHandoffCommand.IsIntent(
                    args, LauncherRestartHandoffScope.Enterprise)
                ? PersonalLauncherRestartHandoffCommand.ParseRequired(
                    args, LauncherRestartHandoffScope.Enterprise)
                : null;
#if ENTERPRISE_DEVELOPMENT_E2E
            healthDiagnostics?.Mark("platform-and-layout-validated");
#endif
            if (args.Length == 0 || args is [BackgroundStartupCommand] || restartHandoff is not null)
            {
                EnterpriseLegacySqliteUpgradeGuard
                    .RequireJsonlOnlyHarnessHomeAndNoWriter(layout);
            }
            if (args is ["--binary-self-check"])
            {
                RequireCurrentBinaryTrusted(layout);
                return 0;
            }
            if (isReleaseManifestTrustProbe)
            {
                RequireCurrentBinaryTrusted(layout);
                var processPath = Environment.ProcessPath
                    ?? throw new InvalidOperationException(
                        "Enterprise ClientBootstrapper process path is unavailable.");
                EnterpriseReleaseManifestTrustProbeRoleIdentity.RequireCurrent(
                    Assembly.GetExecutingAssembly(),
                    processPath,
                    EnterpriseReleaseManifestTrustProbeRole.VersionedClientBootstrapper);
                var canonical = EnterpriseReleaseManifestTrustProbeContract.LoadCanonicalBytes(
                    Assembly.GetExecutingAssembly(),
                    layout);
                EnterpriseReleaseManifestTrustProbeContract
                    .WriteCanonicalToStandardOutput(canonical);
                return 0;
            }
            using var startupOperationLease = args.Length == 0 || args is [BackgroundStartupCommand] || restartHandoff is not null
                ? EnterpriseManagedUpdateOperationLease
                    .AcquireRequiredAsync(layout)
                    .GetAwaiter()
                    .GetResult()
                : null;
            var compiledReleaseTrust = EnterpriseCompiledReleaseTrustLoader.LoadRequired(
                Assembly.GetExecutingAssembly(),
                layout);
#if ENTERPRISE_DEVELOPMENT_E2E
            healthDiagnostics?.Mark("compiled-trust-validated");
#endif
            var pointer = new EnterpriseReleaseSetPointerStore(
                layout,
                compiledReleaseTrust).ReadRequired();
#if ENTERPRISE_DEVELOPMENT_E2E
            healthDiagnostics?.Mark("pointer-validated");
#endif
            RequireActiveBundle(layout, pointer.Current);
#if ENTERPRISE_DEVELOPMENT_E2E
            healthDiagnostics?.Mark("active-bundle-validated");
#endif
            RequireCurrentBinaryTrusted(layout);
#if ENTERPRISE_DEVELOPMENT_E2E
            healthDiagnostics?.Mark("binary-validated");
#endif

            if (args.Length == 0 || args is [BackgroundStartupCommand] || restartHandoff is not null)
            {
                if (pointer.Current.HealthState != EnterpriseReleaseHealthStates.Healthy)
                {
                    throw new InvalidOperationException(
                        "企业 release-set 尚未完成健康确认。");
                }
                if (!new EnterpriseReleaseFeedStateStore(
                        layout,
                        compiledReleaseTrust.Policy.ExpectedChannel)
                    .IsCurrentAllowedOffline(pointer.Current, out var releaseReason))
                {
                    throw new InvalidOperationException(
                        $"企业更新策略已阻止启动 Launcher：{releaseReason}");
                }
                StartLauncher(
                    layout,
                    pointer.Current,
                    args is [BackgroundStartupCommand],
                    restartHandoff);
                return 0;
            }
            if (args is ["--installation-self-check"])
            {
                return 0;
            }
            if (args is ["--release-health-token", var token])
            {
                new EnterpriseReleaseFeedStateStore(
                    layout,
                    compiledReleaseTrust.Policy.ExpectedChannel)
                    .RequirePendingHealthAllowed(pointer.Current);
#if ENTERPRISE_DEVELOPMENT_E2E
                healthDiagnostics?.Mark("pending-health-allowed");
                var exitCode = RunLauncherHealthProbe(layout, pointer.Current, token,
                    stage => healthDiagnostics?.Mark(stage));
                healthDiagnostics?.Mark("launcher-exited", exitCode: exitCode);
                return exitCode;
#else
                return RunLauncherHealthProbe(layout, pointer.Current, token);
#endif
            }
            throw new ArgumentException("企业版本化 Bootstrapper 不接受此启动参数。");
        }
        catch (Exception exception)
        {
            PersonalLauncherRestartHandoffCommand.TrySignalFailure(
                args, LauncherRestartHandoffScope.Enterprise);
#if ENTERPRISE_DEVELOPMENT_E2E
            healthDiagnostics?.Mark("failed", exception);
#endif
            if (isReleaseManifestTrustProbe)
            {
                EnterpriseReleaseManifestTrustProbeContract
                    .WriteBoundedFailureToStandardError();
            }
            else if (isMachineCommand)
            {
                WriteMachineCommandFailure();
            }
            else
            {
                MessageBox.Show(
                    exception.Message,
                    "Ensou DSH Enterprise 无法启动",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
            return 1;
        }
    }

    private static bool IsMachineCommandIntent(IReadOnlyList<string> args) =>
        args.Count > 0
        && args[0] is "--binary-self-check"
            or "--installation-self-check"
            or "--release-health-token"
            or BackgroundStartupCommand
            or PersonalLauncherRestartHandoffCommand.EnterpriseCommandSwitch
            or EnterpriseReleaseManifestTrustProbeContract.Command;

    private static void WriteMachineCommandFailure()
    {
        try
        {
            Console.Error.WriteLine(MachineCommandFailureMessage);
        }
        catch
        {
            // A machine command must terminate without entering a desktop UI,
            // even when its redirected diagnostic stream is unavailable.
        }
    }

    internal static byte[] CreateReleaseManifestTrustProbeBytesForTests(
        EnterpriseCompiledReleaseTrust trust,
        string authenticodeSignerSha256Thumbprint) =>
        EnterpriseReleaseManifestTrustProbeContract.SerializeCanonical(
            EnterpriseReleaseManifestTrustProbeContract.Create(
                trust,
                authenticodeSignerSha256Thumbprint));

    private static EnterpriseInstallationLayout CreateLayout()
    {
#if ENTERPRISE_DEVELOPMENT_E2E
        var local = Environment.GetEnvironmentVariable("ENSOU_DSH_E2E_LOCAL_APP_DATA_ROOT");
        var profile = Environment.GetEnvironmentVariable("ENSOU_DSH_E2E_USER_PROFILE_ROOT");
        return string.IsNullOrEmpty(local) && string.IsNullOrEmpty(profile)
            ? EnterpriseInstallationLayout.CreateDevelopmentE2E()
            : !string.IsNullOrEmpty(local) && !string.IsNullOrEmpty(profile)
                ? EnterpriseInstallationLayout.CreateDevelopmentE2E(local, profile)
                : throw new InvalidOperationException(
                    "Development E2E isolated roots must be supplied as one complete pair.");
#else
        return EnterpriseInstallationLayout.CreateDefault();
#endif
    }

    private static void RequireActiveBundle(
        EnterpriseInstallationLayout layout,
        EnterpriseReleaseSetReference current)
    {
        var currentDirectory = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(AppContext.BaseDirectory));
        var activeDirectory = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(current.Launcher.Directory));
        if (!string.Equals(currentDirectory, activeDirectory, StringComparison.OrdinalIgnoreCase)
            || !File.Exists(Path.Combine(activeDirectory, EnterpriseInstallationLayout.LauncherExecutableName))
            || !File.Exists(Path.Combine(activeDirectory, ExecutableName)))
        {
            throw new InvalidDataException(
                "版本化 Bootstrapper 不是当前原子 client-bundle 的成员。");
        }
        if (!activeDirectory.StartsWith(
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(layout.ManagedRoot))
                    + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase)
            || Directory.EnumerateFileSystemEntries(
                    activeDirectory,
                    "*",
                    SearchOption.AllDirectories)
                .Any(path => (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0))
        {
            throw new InvalidDataException("当前 client-bundle 路径或文件树不受信任。");
        }
    }

    private static void RequireCurrentBinaryTrusted(EnterpriseInstallationLayout layout)
    {
        var processPath = Environment.ProcessPath
            ?? throw new InvalidOperationException("无法确认版本化 Bootstrapper 路径。");
#if !ENTERPRISE_DEVELOPMENT_E2E
        EnterpriseAuthenticodeVerifier.RequireTrustedSignature(processPath, layout);
#endif
        EnterpriseBuildProfileMarker.ReadAndValidate(
            Path.Combine(AppContext.BaseDirectory, EnterpriseInstallationLayout.BuildProfileMarkerFileName),
            layout.LayoutProfile);
    }

    private static int RunLauncherHealthProbe(
        EnterpriseInstallationLayout layout,
        EnterpriseReleaseSetReference current,
        string token,
        Action<string>? mark = null)
    {
        mark?.Invoke("launcher-home-validation-start");
        EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHome(layout);
        var launcher = GetLauncherPath(current);
        mark?.Invoke("launcher-contained-start");
        using var started = EnterpriseTrustedLauncherProcessStarter.StartContained(
            layout,
            launcher,
            current.Launcher.Directory,
            token,
            _ => EnterpriseLegacySqliteUpgradeGuard
                .RequireJsonlOnlyHarnessHome(layout));
        var process = started.Process;
        mark?.Invoke("launcher-running");
        if (!process.WaitForExit((int)EnterpriseBootstrapHealthGate.ColdStartTimeout.TotalMilliseconds))
        {
            var timeoutFailure = new TimeoutException("企业 Launcher 健康进程超时。");
            try
            {
                started.TerminateRequired();
            }
            catch (Exception containmentFailure)
            {
                throw new InvalidOperationException(
                    "企业 Launcher 健康进程无法被证明已终止。",
                    new AggregateException(
                        timeoutFailure,
                        containmentFailure));
            }
            throw timeoutFailure;
        }
        var exitCode = process.ExitCode;
        started.CompleteRequired();
        return exitCode;
    }

    private static void StartLauncher(
        EnterpriseInstallationLayout layout,
        EnterpriseReleaseSetReference current,
        bool backgroundStartup,
        PersonalLauncherRestartHandoffCommand? restartHandoff)
    {
        using var process = StartLauncherProcess(
            layout,
            current,
            backgroundStartup,
            restartHandoff);
        if (restartHandoff is not null)
        {
            LauncherRestartHandoffForwarder.WaitForFinalReceiver(restartHandoff, process);
        }
    }

    internal static Process StartLauncherProcess(
        EnterpriseInstallationLayout layout,
        EnterpriseReleaseSetReference current,
        bool backgroundStartup = false,
        PersonalLauncherRestartHandoffCommand? restartHandoff = null)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(current);
        EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHome(layout);
        var launcher = GetLauncherPath(current);
        return EnterpriseTrustedLauncherProcessStarter.Start(
            layout,
            launcher,
            current.Launcher.Directory,
            healthToken: null,
            additionalArguments: restartHandoff?.ToArguments()
                ?? (backgroundStartup ? [BackgroundStartupCommand] : null),
            validateBeforeResume: _ => EnterpriseLegacySqliteUpgradeGuard
                .RequireJsonlOnlyHarnessHome(layout));
    }

    private static string GetLauncherPath(EnterpriseReleaseSetReference current)
    {
        var path = Path.Combine(
            current.Launcher.Directory,
            EnterpriseInstallationLayout.LauncherExecutableName);
        if (!File.Exists(path)
            || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new FileNotFoundException("当前 client-bundle 缺少 Launcher。", path);
        }
        return path;
    }
}
