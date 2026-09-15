using System.Diagnostics;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.Maintenance;

internal static class Program
{
    public const string ExecutableName = "Ensou.Dsh.Enterprise.Maintenance.exe";
#if ENTERPRISE_DEVELOPMENT_E2E
    private const bool DevelopmentE2EEnabled = true;
#else
    private const bool DevelopmentE2EEnabled = false;
#endif

    [STAThread]
    private static int Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        var quiet = args.Contains("--quiet", StringComparer.Ordinal);
        try
        {
            EnterpriseClientPlatform.RequireSupported();
            var command = EnterpriseMaintenanceCommandLine.Parse(
                args,
                DevelopmentE2EEnabled);
            var processPath = Environment.ProcessPath
                ?? throw new InvalidOperationException(
                    "无法确认企业维护程序路径。");
            if (command.Kind == EnterpriseMaintenanceCommandKind.BinarySelfCheck)
            {
#if !ENTERPRISE_DEVELOPMENT_E2E
                EnterpriseAuthenticodeVerifier.RequireTrustedSignature(processPath);
#endif
                return 0;
            }

            var layout = CreateLayout(command.DevelopmentE2ELayout);
            var operations = new EnterpriseMaintenanceOperations(layout);
            if (command.Kind == EnterpriseMaintenanceCommandKind.RepairShell)
            {
                _ = operations.RepairShell(processPath);
                return 0;
            }

            if (!command.Detached)
            {
                var admittedSha256 = operations.RequireActiveMaintenanceSource(processPath);
                StartDetached(processPath, command, admittedSha256);
                return 0;
            }

            EnterpriseMaintenanceOperations.RequireExactDetachedWorkerPath(
                processPath,
                ExecutableName);
            operations.RequireDetachedMaintenanceWorker(
                processPath,
                command.ExpectedWorkerSha256!);
            var active = EnterpriseMaintenanceIntegrity.RequireActiveMaintenance(layout);
            EnterpriseStableBootstrapperVerifier.RequireTrusted(layout);
            using var parent = RequireBoundProcess(
                command.ParentProcessId!.Value,
                active.MaintenancePath,
                "Maintenance parent");
            using var startupStub = RequireBoundProcess(
                command.StartupStubProcessId!.Value,
                layout.BootstrapperPath,
                "Startup Stub");
            if (parent.Id == startupStub.Id)
            {
                throw new InvalidDataException(
                    "Maintenance parent and Startup Stub must be distinct processes.");
            }
            SignalParentReady(
                processPath,
                parent.Id,
                startupStub.Id);
            WaitForProcess(parent, "Maintenance parent");
            WaitForProcess(startupStub, "Startup Stub");
            // Acquire the shared operation lease, recover any interrupted
            // Installer transaction, and rebind the worker inside that same
            // lease immediately before the destructive transaction.
            var commit = operations.UninstallFromDetachedWorker(
                processPath,
                command.ExpectedWorkerSha256!);
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
        catch (Exception exception)
        {
            if (!quiet)
            {
                MessageBox.Show(
                    exception.Message,
                    "Ensou DSH Enterprise 维护未完成",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
            return 1;
        }
    }

    private static EnterpriseInstallationLayout CreateLayout(bool developmentE2E)
    {
        if (!developmentE2E)
        {
            return EnterpriseInstallationLayout.CreateDefault();
        }
        var local = Environment.GetEnvironmentVariable("ENSOU_DSH_E2E_LOCAL_APP_DATA_ROOT");
        var profile = Environment.GetEnvironmentVariable("ENSOU_DSH_E2E_USER_PROFILE_ROOT");
        if (string.IsNullOrEmpty(local) && string.IsNullOrEmpty(profile))
        {
            return EnterpriseInstallationLayout.CreateDevelopmentE2E();
        }
        if (string.IsNullOrEmpty(local) || string.IsNullOrEmpty(profile))
        {
            throw new InvalidOperationException(
                "Development E2E isolated roots must be supplied as one complete pair.");
        }
        return EnterpriseInstallationLayout.CreateDevelopmentE2E(local, profile);
    }

    private static void StartDetached(
        string processPath,
        EnterpriseMaintenanceCommand command,
        string admittedSha256)
    {
        var workerRoot = EnterpriseMaintenanceOperations.GetWorkerRoot();
        RejectLinkedAncestors(workerRoot);
        Directory.CreateDirectory(workerRoot);
        RejectLinkedAncestors(workerRoot);
        DeleteStaleWorkers(workerRoot);
        var workerDirectory = Path.Combine(workerRoot, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(workerDirectory);
        var workerPath = Path.Combine(workerDirectory, ExecutableName);
        File.Copy(processPath, workerPath, overwrite: false);
        if (!string.Equals(
                EnterpriseMaintenanceIntegrity.ComputeSha256(workerPath),
                admittedSha256,
                StringComparison.Ordinal))
        {
            throw new IOException(
                "Detached enterprise Maintenance copy differs from its admitted active bytes.");
        }
#if !ENTERPRISE_DEVELOPMENT_E2E
        EnterpriseAuthenticodeVerifier.RequireTrustedSignature(workerPath);
#endif
        var arguments = new List<string>
        {
            "--uninstall",
            "--detached",
            "--parent-pid",
            Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--startup-stub-pid",
            command.StartupStubProcessId!.Value.ToString(
                System.Globalization.CultureInfo.InvariantCulture),
            "--expected-worker-sha256",
            admittedSha256,
        };
        if (command.Quiet)
        {
            arguments.Add("--quiet");
        }
        if (command.DevelopmentE2ELayout)
        {
            arguments.Add("--dev-e2e-layout");
        }
        var start = new ProcessStartInfo
        {
            FileName = workerPath,
            WorkingDirectory = workerDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }
        using var worker = Process.Start(start)
            ?? throw new InvalidOperationException("无法启动临时企业卸载进程。");
        WaitForWorkerReady(
            worker,
            workerPath,
            Environment.ProcessId,
            command.StartupStubProcessId.Value);
    }

    private static void DeleteStaleWorkers(string workerRoot)
    {
        foreach (var directory in Directory.EnumerateDirectories(workerRoot))
        {
            if (!Guid.TryParseExact(Path.GetFileName(directory), "N", out _)
                || (File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Enterprise uninstall worker root contains an unexpected directory.");
            }
            foreach (var entry in Directory.EnumerateFileSystemEntries(
                         directory,
                         "*",
                         SearchOption.AllDirectories))
            {
                if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0)
                {
                    throw new InvalidDataException(
                        "Enterprise uninstall worker tree contains a filesystem link.");
                }
            }
            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (IOException)
            {
                // A currently running prior worker owns its directory.
            }
            catch (UnauthorizedAccessException)
            {
                // A currently running prior worker owns its directory.
            }
        }
    }

    private static Process RequireBoundProcess(
        int processId,
        string expectedPath,
        string description)
    {
        if (processId == Environment.ProcessId)
        {
            throw new InvalidDataException(
                $"Detached worker cannot wait on itself as the {description}.");
        }
        try
        {
            var process = Process.GetProcessById(processId);
            try
            {
                var actualPath = process.MainModule?.FileName
                    ?? throw new InvalidDataException(
                        $"Enterprise {description} executable path is unavailable.");
                if (!string.Equals(
                        Path.GetFullPath(actualPath),
                        Path.GetFullPath(expectedPath),
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException(
                        $"Enterprise {description} PID is not bound to the expected executable.");
                }
                return process;
            }
            catch
            {
                process.Dispose();
                throw;
            }
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException(
                $"Enterprise {description} exited before detached-worker admission.",
                exception);
        }
    }

    private static void WaitForProcess(Process process, string description)
    {
        if (!process.WaitForExit(30_000))
        {
            throw new TimeoutException(
                $"等待企业 {description} 退出超时。");
        }
    }

    private static void SignalParentReady(
        string workerPath,
        int parentProcessId,
        int startupStubProcessId)
    {
        var readyPath = GetReadyPath(workerPath);
        var contents = GetReadyContents(
            Environment.ProcessId,
            parentProcessId,
            startupStubProcessId);
        using var stream = new FileStream(
            readyPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.Read,
            bufferSize: 4_096,
            FileOptions.WriteThrough);
        using var writer = new StreamWriter(
            stream,
            new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            leaveOpen: true);
        writer.Write(contents);
        writer.Flush();
        stream.Flush(flushToDisk: true);
    }

    private static void WaitForWorkerReady(
        Process worker,
        string workerPath,
        int parentProcessId,
        int startupStubProcessId)
    {
        var readyPath = GetReadyPath(workerPath);
        var expected = GetReadyContents(
            worker.Id,
            parentProcessId,
            startupStubProcessId);
        var deadline = DateTimeOffset.UtcNow.AddSeconds(10);
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (File.Exists(readyPath))
            {
                var actual = File.ReadAllText(readyPath);
                if (!string.Equals(actual, expected, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "Detached enterprise Maintenance readiness binding is invalid.");
                }
                return;
            }
            if (worker.HasExited)
            {
                throw new InvalidOperationException(
                    "Detached enterprise Maintenance exited before parent admission completed.");
            }
            Thread.Sleep(25);
        }
        throw new TimeoutException(
            "等待临时企业卸载进程完成父进程绑定超时。");
    }

    private static string GetReadyPath(string workerPath) => Path.Combine(
        Path.GetDirectoryName(Path.GetFullPath(workerPath))
            ?? throw new InvalidDataException("Detached worker path has no parent."),
        "parent-binding-ready.v1");

    private static string GetReadyContents(
        int workerProcessId,
        int parentProcessId,
        int startupStubProcessId) =>
        $"ready-v1\n{workerProcessId}\n{parentProcessId}\n{startupStubProcessId}\n";

    private static void RejectLinkedAncestors(string path)
    {
        for (var current = new DirectoryInfo(Path.GetFullPath(path));
             current is not null;
             current = current.Parent)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Enterprise uninstall worker path crosses a filesystem link.");
            }
        }
    }
}
