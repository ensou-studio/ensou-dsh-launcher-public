using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.Installer;

internal static class Program
{
    private const string MachineCommandFailureMessage =
        "Ensou DSH Enterprise Installer machine command failed.";
    private const string InstallMutexName =
        "Local\\Ensou.Dsh.Enterprise.Installation.Transaction";
#if ENTERPRISE_DEVELOPMENT_E2E
    private const bool DevelopmentE2EEnabled = true;
#else
    private const bool DevelopmentE2EEnabled = false;
#endif

    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            return RunWithApplicationInitializer(
                args,
                static () => ApplicationConfiguration.Initialize());
        }
        catch
        {
            WriteMachineCommandFailure();
            return 1;
        }
    }

    private static int RunWithApplicationInitializer(
        string[] args,
        Action initializeApplication)
    {
        var isMachineCommand = IsMachineCommand(args);
        var quiet = isMachineCommand
            || args.Contains("--quiet", StringComparer.Ordinal);
        try
        {
            initializeApplication();
            if (args is ["--brand-self-check", var expectedBrandProfileSha256])
            {
#if ENTERPRISE_DEVELOPMENT_E2E
                throw new InvalidOperationException(
                    "Development-E2E Installer cannot satisfy production brand authorization.");
#else
                EnterpriseClientPlatform.RequireSupported();
                var processPath = Environment.ProcessPath
                    ?? throw new InvalidOperationException("无法确认企业安装器路径。");
                EnterpriseAuthenticodeVerifier.RequireTrustedSignature(processPath);
                EnterpriseBrandContract.RequireCurrentBinary(
                    Assembly.GetExecutingAssembly(),
                    processPath,
                    EnterpriseBrandContract.InstallerComponent,
                    expectedBrandProfileSha256);
                return 0;
#endif
            }
            if (args is ["--binary-self-check"])
            {
                if (!EnterpriseClientPlatform.IsSupported
                    || Environment.ProcessPath is not { } processPath
                    || !string.Equals(
                        Path.GetExtension(processPath),
                        ".exe",
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(
                        "企业安装器二进制自检失败。");
                }
#if !ENTERPRISE_DEVELOPMENT_E2E
                EnterpriseAuthenticodeVerifier.RequireTrustedSignature(processPath);
#endif
                return 0;
            }
            if (args is
                [
                    var payloadSelfCheckCommand,
                    var launcherReleaseId,
                    var runtimeReleaseId,
                    var manifestSha256,
                    var manifestSizeBytes,
                    var launcherArchiveSha256,
                    var launcherArchiveSizeBytes,
                    var runtimeArchiveSha256,
                    var runtimeArchiveSizeBytes,
                    var bootstrapperSha256,
                    var bootstrapperSizeBytes,
                ]
                && payloadSelfCheckCommand is
                    "--production-payload-self-check"
                    or "--development-production-payload-self-check")
            {
                EnterpriseClientPlatform.RequireSupported();
                var processPath = Environment.ProcessPath
                    ?? throw new InvalidOperationException("无法确认企业安装器路径。");
                var developmentSelfCheck = string.Equals(
                    payloadSelfCheckCommand,
                    "--development-production-payload-self-check",
                    StringComparison.Ordinal);
                if (!developmentSelfCheck && DevelopmentE2EEnabled)
                {
                    throw new InvalidOperationException(
                        "Development-E2E Installer cannot satisfy production payload checks.");
                }
                if (developmentSelfCheck && !DevelopmentE2EEnabled)
                {
                    throw new InvalidOperationException(
                        "Production Installer does not admit development payload checks.");
                }
                if (!developmentSelfCheck)
                {
                    EnterpriseAuthenticodeVerifier.RequireTrustedSignature(processPath);
                }

                var expectation = new EmbeddedProductionPayloadBindingExpectation(
                    launcherReleaseId,
                    runtimeReleaseId,
                    manifestSha256,
                    ParseCanonicalSize(
                        manifestSizeBytes,
                        128L * 1024,
                        "manifest"),
                    launcherArchiveSha256,
                    ParseCanonicalSize(
                        launcherArchiveSizeBytes,
                        1L * 1024 * 1024 * 1024,
                        "launcher archive"),
                    runtimeArchiveSha256,
                    ParseCanonicalSize(
                        runtimeArchiveSizeBytes,
                        8L * 1024 * 1024 * 1024,
                        "runtime archive"),
                    bootstrapperSha256,
                    ParseCanonicalSize(
                        bootstrapperSizeBytes,
                        512L * 1024 * 1024,
                        "Bootstrapper"));
                VerifyEmbeddedProductionPayloadBinding(
                    Assembly.GetExecutingAssembly(),
                    expectation,
                    developmentSelfCheck);
                if (!developmentSelfCheck)
                {
                    EnterpriseLegacyMigrationInstallerFacade
                        .RequireEmbeddedProductionMigrationPayload(
                            EnterpriseInstallationLayout.CreateDefault(),
                            Assembly.GetExecutingAssembly(),
                            processPath);
                }
                WriteProductionPayloadSelfCheckResult(
                    payloadSelfCheckCommand,
                    processPath,
                    expectation);
                return 0;
            }

            if (isMachineCommand)
            {
                throw new ArgumentException("企业安装器机器命令参数无效。");
            }

            EnterpriseClientPlatform.RequireSupported();
            using var singleWriter = new Mutex(initiallyOwned: false, InstallMutexName);
            if (!singleWriter.WaitOne(TimeSpan.FromSeconds(30)))
            {
                throw new TimeoutException("另一个企业版安装、修复或卸载操作正在进行。");
            }

            try
            {
                return RunAsync(args, quiet).GetAwaiter().GetResult();
            }
            finally
            {
                singleWriter.ReleaseMutex();
            }
        }
        catch (Exception exception)
        {
            if (isMachineCommand)
            {
                WriteMachineCommandFailure();
                return 1;
            }
            if (!quiet)
            {
                MessageBox.Show(
                    exception.Message,
                    "Ensou DSH Enterprise 安装未完成",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }

            return 1;
        }
    }

    private static bool IsMachineCommand(IReadOnlyList<string> args)
    {
        var command = args.FirstOrDefault();
        return command is "--brand-self-check"
            or "--binary-self-check"
            or "--production-payload-self-check"
            or "--development-production-payload-self-check";
    }

    private static void VerifyEmbeddedProductionPayloadBinding(
        Assembly installerAssembly,
        EmbeddedProductionPayloadBindingExpectation expected,
        bool developmentE2E)
    {
        ArgumentNullException.ThrowIfNull(installerAssembly);
        ArgumentNullException.ThrowIfNull(expected);
        expected.Validate();

        using var source = new EnterpriseEmbeddedPayloadSource(installerAssembly);
        byte[] manifestBytes;
        using (var manifestStream = source.Open(
                   EnterpriseEmbeddedPayloadSource.ManifestFileName))
        {
            manifestBytes = ReadBounded(
                manifestStream,
                128 * 1024,
                "manifest");
        }

        try
        {
            var actualManifestSha256 = Convert.ToHexStringLower(
                SHA256.HashData(manifestBytes));
            if (manifestBytes.LongLength != expected.ManifestSizeBytes
                || !string.Equals(
                    actualManifestSha256,
                    expected.ManifestSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Embedded Installer manifest bytes do not match the admitted external manifest.");
            }

            var manifest = EnterpriseInstallManifest.Parse(manifestBytes);
            if (!string.Equals(
                    manifest.LayoutProfile,
                    developmentE2E
                        ? EnterpriseInstallationLayout.DevelopmentE2ELayoutProfile
                        : EnterpriseInstallationLayout.ProductionLayoutProfile,
                    StringComparison.Ordinal)
                || !string.Equals(
                    manifest.LauncherArchive,
                    "launcher.zip",
                    StringComparison.Ordinal)
                || !string.Equals(
                    manifest.RuntimeArchive,
                    "runtime.zip",
                    StringComparison.Ordinal)
                || !string.Equals(
                    manifest.BootstrapperFile,
                    EnterpriseInstallationLayout.BootstrapperExecutableName,
                    StringComparison.Ordinal)
                || manifest.LauncherArchiveSizeBytes !=
                    expected.LauncherArchiveSizeBytes
                || manifest.RuntimeArchiveSizeBytes !=
                    expected.RuntimeArchiveSizeBytes
                || manifest.BootstrapperSizeBytes != expected.BootstrapperSizeBytes)
            {
                throw new InvalidDataException(
                    "Embedded Installer manifest descriptors do not match the admitted external payload.");
            }

            var payloadExpectation = new EnterpriseProductionPayloadExpectation(
                    expected.LauncherReleaseId,
                    expected.RuntimeReleaseId,
                    expected.LauncherArchiveSha256,
                    expected.RuntimeArchiveSha256,
                    expected.BootstrapperSha256);
            _ = developmentE2E
                ? EnterpriseEmbeddedProductionPayloadVerifier.VerifyDevelopmentE2E(
                    source,
                    payloadExpectation)
                : EnterpriseEmbeddedProductionPayloadVerifier.Verify(
                    source,
                    payloadExpectation);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(manifestBytes);
        }
    }

    private static long ParseCanonicalSize(
        string text,
        long maximum,
        string field)
    {
        if (string.IsNullOrEmpty(text)
            || (text.Length > 1 && text[0] == '0')
            || text.Any(character => character is < '0' or > '9')
            || !long.TryParse(
                text,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var value)
            || value <= 0
            || value > maximum)
        {
            throw new InvalidDataException(
                $"Production payload {field} size is not one canonical bounded integer.");
        }
        return value;
    }

    private static byte[] ReadBounded(
        Stream stream,
        int maximumBytes,
        string field)
    {
        using var output = new MemoryStream();
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                break;
            }
            if (output.Length + read > maximumBytes)
            {
                throw new InvalidDataException(
                    $"Embedded production payload {field} exceeds its bounded size.");
            }
            output.Write(buffer, 0, read);
        }
        if (output.Length == 0)
        {
            throw new InvalidDataException(
                $"Embedded production payload {field} is empty.");
        }
        return output.ToArray();
    }

    private static void WriteMachineCommandFailure()
    {
        try
        {
            Console.Error.WriteLine(MachineCommandFailureMessage);
        }
        catch
        {
            // The outermost executable boundary must return a fixed failure
            // even when no redirected diagnostic stream is available.
        }
    }

    private static void WriteProductionPayloadSelfCheckResult(
        string command,
        string processPath,
        EmbeddedProductionPayloadBindingExpectation expectation)
    {
        string installerSha256;
        using (var input = new FileStream(
                   processPath,
                   FileMode.Open,
                   FileAccess.Read,
                   FileShare.Read))
        {
            installerSha256 = Convert.ToHexStringLower(SHA256.HashData(input));
        }

        var json = System.Text.Json.JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            resultType =
                "ensou-dsh-enterprise-installer-production-payload-self-check",
            command,
            status = "VERIFIED",
            installerSha256,
            launcherReleaseId = expectation.LauncherReleaseId,
            runtimeReleaseId = expectation.RuntimeReleaseId,
            manifestSha256 = expectation.ManifestSha256,
            manifestSizeBytes = expectation.ManifestSizeBytes,
            launcherArchiveSha256 = expectation.LauncherArchiveSha256,
            launcherArchiveSizeBytes = expectation.LauncherArchiveSizeBytes,
            runtimeArchiveSha256 = expectation.RuntimeArchiveSha256,
            runtimeArchiveSizeBytes = expectation.RuntimeArchiveSizeBytes,
            bootstrapperSha256 = expectation.BootstrapperSha256,
            bootstrapperSizeBytes = expectation.BootstrapperSizeBytes,
        });
        Console.Out.WriteLine(json);
        Console.Out.Flush();
    }

    private sealed record EmbeddedProductionPayloadBindingExpectation(
        string LauncherReleaseId,
        string RuntimeReleaseId,
        string ManifestSha256,
        long ManifestSizeBytes,
        string LauncherArchiveSha256,
        long LauncherArchiveSizeBytes,
        string RuntimeArchiveSha256,
        long RuntimeArchiveSizeBytes,
        string BootstrapperSha256,
        long BootstrapperSizeBytes)
    {
        public void Validate()
        {
            new EnterpriseProductionPayloadExpectation(
                LauncherReleaseId,
                RuntimeReleaseId,
                LauncherArchiveSha256,
                RuntimeArchiveSha256,
                BootstrapperSha256).Validate();
            if (!IsLowerSha256(ManifestSha256)
                || ManifestSizeBytes is <= 0 or > 128L * 1024
                || LauncherArchiveSizeBytes is <= 0 or > 1L * 1024 * 1024 * 1024
                || RuntimeArchiveSizeBytes is <= 0 or > 8L * 1024 * 1024 * 1024
                || BootstrapperSizeBytes is <= 0 or > 512L * 1024 * 1024)
            {
                throw new InvalidDataException(
                    "Production payload binding expectation is invalid.");
            }
        }

        private static bool IsLowerSha256(string value) =>
            value.Length == 64
            && value.All(character => character is >= '0' and <= '9'
                or >= 'a' and <= 'f');
    }

    private static async Task<int> RunAsync(string[] args, bool quiet)
    {
        var options = InstallerOptions.Parse(args);
        var layout = options.DevelopmentE2ELayout
            ? options.CreateDevelopmentE2ELayout()
            : EnterpriseInstallationLayout.CreateDefault();
        if (options.Command == InstallerCommand.Uninstall)
        {
            var uninstallExecutablePath = Environment.ProcessPath
                ?? throw new InvalidOperationException("无法确认企业安装器路径。");
            var operations = new EnterpriseMaintenanceOperations(layout);
            if (IsInsideManagedRoot(uninstallExecutablePath, layout))
            {
                _ = operations.RequireInstalledInstallerSource(uninstallExecutablePath);
                StartInstalledMaintenanceUninstall(layout, quiet);
                return 0;
            }
            EnterpriseUninstallCommitResult commit;
            if (layout.IsDevelopmentE2E)
            {
                _ = operations.RequireExternalInstallerSource(uninstallExecutablePath);
                commit = new EnterpriseInstallationService(layout)
                    .UninstallManagedProgramFiles();
            }
            else
            {
                commit = await EnterpriseLegacyMigrationInstallerFacade
                    .UninstallAfterRecoveringLegacyMigrationAsync(
                        layout,
                        Assembly.GetExecutingAssembly(),
                        uninstallExecutablePath)
                    .ConfigureAwait(false);
            }
            if (!quiet)
            {
                MessageBox.Show(
                    "企业 Launcher 已卸载。"
                    + $"\n\n本地对话、工作区和设置仍保留在：\n{layout.HarnessHome}",
                    "Ensou DSH Enterprise",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }

            return 0;
        }

        var executablePath = Environment.ProcessPath
            ?? throw new InvalidOperationException("无法确认企业安装器路径。");
        var service = new EnterpriseInstallationService(layout);
        EnterpriseInstallResult result;
        if (options.DevelopmentPayloadDirectory is not null)
        {
            result = options.SkipShellRegistration
                ? await service.InstallExternalDevelopmentPayloadAsync(
                    options.DevelopmentPayloadDirectory,
                    executablePath).ConfigureAwait(false)
                : await service.InstallExternalDevelopmentPayloadAndRegisterAsync(
                    options.DevelopmentPayloadDirectory,
                    executablePath).ConfigureAwait(false);
        }
        else if (options.EmbeddedDevelopmentPayload)
        {
            result = await service.InstallEmbeddedDevelopmentPayloadAsync(
                Assembly.GetExecutingAssembly(),
                executablePath).ConfigureAwait(false);
        }
        else
        {
            result = IsInsideManagedRoot(executablePath, layout)
                ? await service.InstallEmbeddedProductionPayloadAndRegisterAsync(
                    Assembly.GetExecutingAssembly(),
                    executablePath).ConfigureAwait(false)
                : await EnterpriseLegacyMigrationInstallerFacade
                    .InstallOrRepairEmbeddedProductionPayloadAndRegisterAsync(
                        layout,
                        Assembly.GetExecutingAssembly(),
                        executablePath)
                    .ConfigureAwait(false);
        }
        if (!quiet)
        {
            var warning = result.DevelopmentUnsignedPayload
                ? "\n\n警告：这是明确启用的未签名开发测试包，不得发给员工。"
                : string.Empty;
            MessageBox.Show(
                $"企业 Launcher 已安装/修复。\nLauncher：{result.LauncherReleaseId}\nDSH：{result.RuntimeReleaseId}{warning}",
                "Ensou DSH Enterprise",
                MessageBoxButtons.OK,
                result.DevelopmentUnsignedPayload
                    ? MessageBoxIcon.Warning
                    : MessageBoxIcon.Information);
            Process.Start(new ProcessStartInfo
            {
                FileName = result.BootstrapperPath,
                UseShellExecute = true,
                WorkingDirectory = layout.ManagedRoot,
            });
        }

        return 0;
    }

    private static bool IsInsideManagedRoot(
        string? processPath,
        EnterpriseInstallationLayout layout)
    {
        if (string.IsNullOrWhiteSpace(processPath))
        {
            return false;
        }

        var candidate = Path.GetFullPath(processPath);
        var root = layout.ManagedRoot.TrimEnd(Path.DirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        return candidate.StartsWith(root, StringComparison.OrdinalIgnoreCase);
    }

    private static void StartInstalledMaintenanceUninstall(
        EnterpriseInstallationLayout layout,
        bool quiet)
    {
        EnterpriseStableBootstrapperVerifier.RequireTrusted(layout);
        var start = new ProcessStartInfo
        {
            FileName = layout.BootstrapperPath,
            WorkingDirectory = layout.ManagedRoot,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        start.ArgumentList.Add("--maintenance-uninstall");
        if (quiet)
        {
            start.ArgumentList.Add("--quiet");
        }
        _ = Process.Start(start)
            ?? throw new InvalidOperationException(
                "无法通过稳定 Startup Stub 启动企业卸载流程。");
    }

    private enum InstallerCommand
    {
        InstallOrRepair,
        Uninstall,
    }

    private sealed record InstallerOptions(
        InstallerCommand Command,
        string? DevelopmentPayloadDirectory,
        bool DevelopmentE2ELayout,
        string? DevelopmentE2ELocalAppDataRoot,
        string? DevelopmentE2EUserProfileRoot,
        bool SkipShellRegistration,
        bool EmbeddedDevelopmentPayload)
    {
        public EnterpriseInstallationLayout CreateDevelopmentE2ELayout() =>
            DevelopmentE2ELocalAppDataRoot is null
                ? EnterpriseInstallationLayout.CreateDevelopmentE2E()
                : EnterpriseInstallationLayout.CreateDevelopmentE2E(
                    DevelopmentE2ELocalAppDataRoot,
                    DevelopmentE2EUserProfileRoot!);

        public static InstallerOptions Parse(string[] args)
        {
            EnterpriseInstallerArgumentPolicy.EnsureBuildAllowsDevelopmentOptions(
                args,
                DevelopmentE2EEnabled);

            // A Development-E2E bundle is deliberately isolated from the
            // employee installation layout. Let a tester double-click the
            // Installer when its exact development payload is shipped in the
            // adjacent `payload` directory; production builds never compile
            // this convenience path and continue to require an embedded,
            // Authenticode-bound payload.
            if (EnterpriseInstallerArgumentPolicy.TryInferAdjacentDevelopmentPayload(
                    args,
                    DevelopmentE2EEnabled,
                    AppContext.BaseDirectory,
                    out var adjacentPayload))
            {
                return new InstallerOptions(
                    InstallerCommand.InstallOrRepair,
                    adjacentPayload,
                    DevelopmentE2ELayout: true,
                    DevelopmentE2ELocalAppDataRoot: null,
                    DevelopmentE2EUserProfileRoot: null,
                    SkipShellRegistration: false,
                    EmbeddedDevelopmentPayload: false);
            }

            var command = InstallerCommand.InstallOrRepair;
            string? payload = null;
            var developmentConsent = false;
            var developmentE2ELayout = false;
            string? developmentE2ELocalAppDataRoot = null;
            string? developmentE2EUserProfileRoot = null;
            var skipShellRegistration = false;
            string? explicitCommand = null;
            var seenOptions = new HashSet<string>(StringComparer.Ordinal);
            for (var index = 0; index < args.Length; index++)
            {
                if (!seenOptions.Add(args[index]))
                {
                    throw new ArgumentException($"重复安装器参数：{args[index]}");
                }
                switch (args[index])
                {
                    case "--install":
                    case "--repair":
                        if (explicitCommand is not null)
                        {
                            throw new ArgumentException("安装器命令不得重复或混用。");
                        }
                        explicitCommand = args[index];
                        command = InstallerCommand.InstallOrRepair;
                        break;
                    case "--quiet":
                        break;
                    case "--uninstall":
                        if (explicitCommand is not null)
                        {
                            throw new ArgumentException("安装器命令不得重复或混用。");
                        }
                        explicitCommand = args[index];
                        command = InstallerCommand.Uninstall;
                        break;
                    case "--dev-unsigned":
                        developmentConsent = true;
                        break;
                    case "--dev-e2e-layout":
                        developmentE2ELayout = true;
                        break;
                    case "--dev-e2e-no-shell-registration":
                        skipShellRegistration = true;
                        break;
                    case "--dev-e2e-local-app-data-root" when index + 1 < args.Length:
                        developmentE2ELocalAppDataRoot = RequireAbsoluteLocalPath(
                            args[++index],
                            "--dev-e2e-local-app-data-root");
                        break;
                    case "--dev-e2e-user-profile-root" when index + 1 < args.Length:
                        developmentE2EUserProfileRoot = RequireAbsoluteLocalPath(
                            args[++index],
                            "--dev-e2e-user-profile-root");
                        break;
                    case "--payload" when index + 1 < args.Length:
                        payload = args[++index];
                        break;
                    default:
                        throw new ArgumentException($"未知安装器参数：{args[index]}");
                }
            }

            if (command == InstallerCommand.Uninstall)
            {
                if (payload is not null || developmentConsent)
                {
                    throw new ArgumentException("卸载操作不接受 payload 参数。");
                }

                if (developmentE2ELocalAppDataRoot is not null
                    || developmentE2EUserProfileRoot is not null
                    || skipShellRegistration)
                {
                    throw new ArgumentException("卸载操作不接受 Development E2E 隔离参数。");
                }

                return new InstallerOptions(
                    command,
                    null,
                    developmentE2ELayout,
                    null,
                    null,
                    false,
                    false);
            }

            if (payload is not null && !developmentConsent)
            {
                throw new ArgumentException(
                    "外部 payload 只能与 --dev-unsigned 同时显式使用。生产安装只接受签名安装器的内嵌 payload。" );
            }

            if (developmentE2ELayout && !developmentConsent)
            {
                throw new ArgumentException(
                    "--dev-e2e-layout 只能与 --dev-unsigned 同时使用。" );
            }

            if (payload is not null && !developmentE2ELayout)
            {
                throw new ArgumentException(
                    "外部开发 payload 只能安装到 --dev-e2e-layout 隔离目录。" );
            }

            if ((developmentE2ELocalAppDataRoot is null)
                    != (developmentE2EUserProfileRoot is null)
                || (developmentE2ELocalAppDataRoot is not null && !developmentE2ELayout))
            {
                throw new ArgumentException(
                    "Development E2E 隔离根必须成对提供，并与 --dev-e2e-layout 同时使用。" );
            }

            if (skipShellRegistration
                && (developmentE2ELocalAppDataRoot is null || !developmentE2ELayout))
            {
                throw new ArgumentException(
                    "--dev-e2e-no-shell-registration 只允许用于显式隔离根的本机 E2E。" );
            }

            if (payload is not null && !Path.IsPathFullyQualified(payload))
            {
                throw new ArgumentException("开发 payload 必须使用绝对目录。");
            }

            var embeddedDevelopmentPayload = developmentConsent && payload is null;
            if (embeddedDevelopmentPayload
                && (!developmentE2ELayout
                    || developmentE2ELocalAppDataRoot is null
                    || developmentE2EUserProfileRoot is null
                    || !skipShellRegistration))
            {
                throw new ArgumentException(
                    "内嵌开发 payload 必须同时显式使用 --dev-e2e-layout、两项绝对隔离根和 --dev-e2e-no-shell-registration。" );
            }

            return new InstallerOptions(
                command,
                payload,
                developmentE2ELayout,
                developmentE2ELocalAppDataRoot,
                developmentE2EUserProfileRoot,
                skipShellRegistration,
                embeddedDevelopmentPayload);
        }

        private static string RequireAbsoluteLocalPath(string value, string option)
        {
            if (!Path.IsPathFullyQualified(value)
                || value.StartsWith("\\\\", StringComparison.Ordinal)
                || value.StartsWith("//", StringComparison.Ordinal))
            {
                throw new ArgumentException($"{option} 必须是绝对本机目录。");
            }

            return Path.GetFullPath(value);
        }
    }
}
