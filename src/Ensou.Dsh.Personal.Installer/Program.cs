using System.Diagnostics;
using System.Reflection;
using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.Personal.Installer;

internal static class Program
{
    private const string InstallerExecutableName = "Ensou.Dsh.Personal.Installer.exe";
    // Keep an unconfirmed exact child handle rooted until this Installer exits.
    // This does not claim that the child has exited or that containment survived our own exit.
    private static Process? _unconfirmedHealthChild;

    [STAThread]
    private static int Main(string[] args)
    {
        var machineSelfCheckIntent =
            PersonalInstallerCommandLine.HasMachineSelfCheckIntent(args);
        var quiet = machineSelfCheckIntent
            || args.Contains(PersonalInstallerCommandLine.QuietArgument, StringComparer.Ordinal);
        var developmentE2ECompiled = false;
        try
        {
            developmentE2ECompiled = PersonalDevelopmentE2ELayoutArguments.IsCompiled(
                Assembly.GetExecutingAssembly());
            if (!machineSelfCheckIntent)
            {
                ApplicationConfiguration.Initialize();
            }
            var command = PersonalInstallerCommandLine.Parse(args);
            quiet = command.Quiet;
            if (command.Kind is PersonalInstallerCommandKind.BinarySelfCheck)
            {
                PersonalBinarySelfCheck.RequireAndConsumeProtocol();
                var trust = PersonalInstallerTrustConfiguration.ReadCompiled(
                    Assembly.GetExecutingAssembly());
                using var executableIdentity =
                    PersonalAuthenticodeVerifier.AcquireCurrentInstallerExecutableLease(
                        Assembly.GetExecutingAssembly(),
                        InstallerExecutableName,
                        trust);
                _ = new PersonalEmbeddedInstallerPayloadSource(Assembly.GetExecutingAssembly());
                PersonalBinarySelfCheck.WriteCanonicalCompiledTrust(
                    PersonalCompiledTrustFingerprint.Create(trust));
                return 0;
            }
            if (command.Kind is PersonalInstallerCommandKind.DevelopmentPayloadSelfCheck)
            {
                var assembly = Assembly.GetExecutingAssembly();
                var trust = PersonalInstallerTrustConfiguration.ReadCompiled(assembly);
                using var executableIdentity =
                    PersonalAuthenticodeVerifier.AcquireCurrentInstallerExecutableLease(
                        assembly,
                        InstallerExecutableName,
                        trust);
                var expected = PersonalProductionPayloadExpectation.Parse(args[1..]);
                PersonalInstallerPayloadSelfCheck.VerifyDevelopmentPayloadAsync(
                        new PersonalEmbeddedInstallerPayloadSource(assembly),
                        trust,
                        executableIdentity,
                        expected)
                    .GetAwaiter()
                    .GetResult();
                return 0;
            }
            if (command.Kind is PersonalInstallerCommandKind.ProductionPayloadSelfCheck)
            {
                using var machineOutput =
                    PersonalInstallerProductionPayloadSelfCheckOutput.Begin();
                var assembly = Assembly.GetExecutingAssembly();
                var trust = PersonalInstallerTrustConfiguration.ReadCompiled(assembly);
                using var executableIdentity =
                    PersonalAuthenticodeVerifier.AcquireCurrentInstallerExecutableLease(
                        assembly,
                        InstallerExecutableName,
                        trust);
                var expected = PersonalProductionPayloadExpectation.Parse(args[1..]);
                PersonalInstallerPayloadSelfCheck.VerifyProductionPayloadAsync(
                        new PersonalEmbeddedInstallerPayloadSource(assembly),
                        trust,
                        executableIdentity,
                        expected)
                    .GetAwaiter()
                    .GetResult();
                machineOutput.WriteVerifiedResult(
                    args[0],
                    executableIdentity,
                    expected);
                return 0;
            }
            return RunAsync(command, quiet).GetAwaiter().GetResult();
        }
        catch (Exception exception)
        {
            if (developmentE2ECompiled)
            {
                WriteDevelopmentFailureCode(exception);
            }
            if (exception is not PersonalInstallerInstallAdmissionException
                && !developmentE2ECompiled
                && !PersonalDevelopmentE2ELayoutArguments.IsIntent(args)
                && !args.Contains(
                    PersonalInstallerCommandLine.DevelopmentNoShellRegistrationArgument,
                    StringComparer.Ordinal))
            {
                WriteMachineFailureLog(exception, args);
            }
            if (!quiet && !developmentE2ECompiled)
            {
                MessageBox.Show(
                    exception.Message,
                    "DeepSeek Harness Launcher 安装未完成",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
            return 1;
        }
    }

    private static void WriteDevelopmentFailureCode(Exception exception)
    {
        try
        {
            var code = exception is PersonalInstallPreflightException preflight
                ? preflight.Code
                : "PERSONAL_DEVELOPMENT_INSTALL_FAILED";
            Console.Error.WriteLine(code);
        }
        catch
        {
            // Development diagnostics must not replace the original failure.
        }
    }

    private static void WriteMachineFailureLog(
        Exception exception,
        IReadOnlyList<string> args)
    {
        try
        {
            var localAppData = Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData);
            var directory = Path.Combine(
                localAppData,
                "Ensou",
                "DshLauncherInstallerLogs");
            Directory.CreateDirectory(directory);
            RejectLinkedAncestors(directory);
            var path = Path.Combine(
                directory,
                $"failure-{DateTimeOffset.UtcNow:yyyyMMddTHHmmssfffffffZ}-{Guid.NewGuid():N}.json");
            var bytes = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                product = "Ensou.Dsh.Personal.Installer",
                command = args.Count == 0 ? "install" : args[0],
                exitCode = 1,
                exceptionType = exception.GetType().FullName,
                message = exception.Message,
                recordedAtUtc = DateTimeOffset.UtcNow,
            });
            using var output = new FileStream(
                path,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.Read,
                16 * 1024,
                FileOptions.WriteThrough);
            output.Write(bytes);
            output.Flush(flushToDisk: true);
        }
        catch
        {
            // Failure reporting must never replace the original Installer failure.
        }
    }

    private static void RejectLinkedAncestors(string path)
    {
        for (var current = new DirectoryInfo(Path.GetFullPath(path));
             current is not null;
             current = current.Parent)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Personal Installer failure-log path crosses a filesystem link.");
            }
        }
    }

    private static async Task<int> RunAsync(
        PersonalInstallerCommand command,
        bool quiet)
    {
        var assembly = Assembly.GetExecutingAssembly();
        var trust = PersonalInstallerTrustConfiguration.ReadCompiled(assembly);
        using var executableIdentity =
            PersonalAuthenticodeVerifier.AcquireCurrentInstallerExecutableLease(
                assembly,
                InstallerExecutableName,
                trust);
        PersonalInstallerCommandLine.RequireInstallAllowed(
            command,
            trust.ProductionBuild,
            IsDevelopmentE2ECompiled(assembly));
        var developmentArguments = command.DevelopmentE2ELayout is { } developmentLayout
            ? PersonalDevelopmentE2ELayoutArguments.Create(
                developmentLayout.ManagedRoot,
                developmentLayout.HarnessHome,
                developmentLayout.UpdateSecurityWitnessPath)
            : null;
        var layout = developmentArguments?.Layout
            ?? PersonalInstallationLayout.CreateDefault();
        var preflight = PersonalInstallPreflight.RequireReady(layout);
        if (!quiet && preflight.IsBelowRecommendedDiskSpace)
        {
            MessageBox.Show(
                "当前磁盘空间满足安装最低要求，但建议至少保留 5 GB 可用空间，以便后续更新和回滚。",
                "DeepSeek Harness Launcher 安装提示",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
        }
        var payload = new PersonalEmbeddedInstallerPayloadSource(assembly);
        var service = command.DevelopmentE2ELayout is { } isolatedLayout
            ? PersonalInstallMigrationService.CreateDevelopmentE2EWithoutShellRegistration(
                layout,
                new PersonalDevelopmentE2EInstallOptions(
                    layout.ManagedRoot,
                    layout.HarnessHome,
                    layout.UpdateSecurityWitnessPath,
                    NoShellRegistration: true))
            : new PersonalInstallMigrationService(layout);
        PersonalInstallPreparationResult prepared;
        try
        {
            prepared = await service.PrepareAsync(
                    payload,
                    trust,
                    executableIdentity)
                .ConfigureAwait(false);
        }
        catch (Exception installFailure)
        {
            await PersonalInstallerHealthProcessExit.RollbackOrAggregateAsync(
                    abandon => service.RollbackStableStubAfterFailureAsync(abandon),
                    installFailure,
                    abandonPendingCandidate: false)
                .ConfigureAwait(false);
            throw new UnreachableException();
        }
        if (prepared.RequiresHealthValidation)
        {
            try
            {
                await RunStartupStubHealthAsync(
                        prepared.StartupStubPath,
                        developmentArguments)
                    .ConfigureAwait(false);
                _ = await service.CompleteAfterHealthAsync(
                        prepared.ReleaseSetId,
                        prepared.ManifestSha256)
                    .ConfigureAwait(false);
            }
            catch (Exception healthFailure)
            {
                var reportedFailure = prepared.LegacyQuarantinePath is null
                    ? healthFailure
                    : new InvalidOperationException(
                        "新版健康验证失败。旧版程序、snapshots 和 settings 仍完整保留在："
                        + prepared.LegacyQuarantinePath
                        + "。为防止绕过 v2 防回滚边界，安装器不会执行旧二进制或导入旧 JSON；请运行更高版本的已签名安装器接管恢复。",
                        healthFailure);
                await PersonalInstallerHealthProcessExit.RollbackOrAggregateAsync(
                        abandon => service.RollbackStableStubAfterFailureAsync(abandon),
                        reportedFailure,
                        abandonPendingCandidate: true)
                    .ConfigureAwait(false);
                throw new UnreachableException();
            }
        }
        if (!quiet)
        {
            StartHealthyLauncher(prepared.StartupStubPath);
        }

        if (!quiet)
        {
            var migration = prepared.LegacyQuarantinePath is null
                ? string.Empty
                : "\n\n旧版程序、snapshots 和 settings 已原样保留在："
                    + $"\n{prepared.LegacyQuarantinePath}"
                    + "\n旧 Launcher 设置不会被当作可信配置导入，请在新版中重新确认设置。";
            MessageBox.Show(
                "DeepSeek Harness Launcher 已安装。"
                + $"\n版本：{prepared.ReleaseSetId}"
                + $"\n本地对话与工作区仍保留在：\n{layout.HarnessHome}"
                + migration,
                "DeepSeek Harness Launcher",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        return 0;
    }

    private static bool IsDevelopmentE2ECompiled(Assembly assembly)
    {
        var values = assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .Where(attribute => string.Equals(
                attribute.Key,
                "PersonalDevelopmentE2E",
                StringComparison.Ordinal))
            .Select(attribute => attribute.Value)
            .ToArray();
        if (values.Length != 1)
        {
            throw new InvalidDataException(
                "Personal Installer development E2E compilation metadata is missing or ambiguous.");
        }
        return string.Equals(values[0], "true", StringComparison.Ordinal);
    }

    private static async Task RunStartupStubHealthAsync(
        string startupStubPath,
        PersonalDevelopmentE2ELayoutArguments? developmentArguments)
    {
        var overallDeadline = PersonalHealthBudgetV1.CreateDeadlineTickCount64(
            PersonalHealthBudgetV1.OverallHealthEnvelope);
        using var timeout = PersonalHealthBudgetV1.CreateCancellationUntil(
            overallDeadline,
            PersonalHealthBudgetV1.OverallHealthEnvelope);
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = startupStubPath,
                WorkingDirectory = Path.GetDirectoryName(startupStubPath)
                    ?? throw new InvalidDataException(
                        "Personal Startup Stub has no working directory."),
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            },
        };
        process.StartInfo.ArgumentList.Add("--installer-health");
        process.StartInfo.ArgumentList.Add(PersonalHealthBudgetV1.OverallDeadlineArgument);
        process.StartInfo.ArgumentList.Add(overallDeadline.ToString(
            System.Globalization.CultureInfo.InvariantCulture));
        if (developmentArguments is not null)
        {
            foreach (var argument in developmentArguments.ToArguments())
            {
                process.StartInfo.ArgumentList.Add(argument);
            }
        }
        try
        {
            if (!process.Start())
            {
                throw new InvalidOperationException(
                    "Personal Installer could not start the stable Startup Stub health gate.");
            }
            try
            {
                await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (Exception waitFailure)
            {
                var failure = waitFailure is OperationCanceledException
                    ? new TimeoutException(
                        "Personal Installer timed out waiting for initial release health validation.", waitFailure)
                    : waitFailure;
                await PersonalInstallerHealthProcessExit.RequireConfirmedHealthExitAsync(
                    failure,
                    () => process.HasExited,
                    () => process.Kill(entireProcessTree: true),
                    token => process.WaitForExitAsync(token),
                    () => _unconfirmedHealthChild = process).ConfigureAwait(false);
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
            }
            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(
                    "The initial Personal release failed Startup Stub health validation. Retry with a newer signed Installer.");
            }
        }
        finally
        {
            if (!ReferenceEquals(_unconfirmedHealthChild, process)) process.Dispose();
        }
    }

    private static void StartHealthyLauncher(string startupStubPath)
    {
        _ = Process.Start(new ProcessStartInfo
        {
            FileName = startupStubPath,
            WorkingDirectory = Path.GetDirectoryName(startupStubPath)
                ?? AppContext.BaseDirectory,
            UseShellExecute = true,
        }) ?? throw new InvalidOperationException(
            "Personal Installer could not start the installed Launcher.");
    }
}
