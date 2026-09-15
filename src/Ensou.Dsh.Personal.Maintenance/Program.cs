using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.Personal.Maintenance;

internal static class Program
{
    public const string ExecutableName = "Ensou.Dsh.Personal.Maintenance.exe";
    private const string WorkerRootName = "DshPersonalUninstall";

    [STAThread]
    private static int Main(string[] args)
    {
        var binarySelfCheckRequested = args.Length > 0
            && string.Equals(
                args[0],
                "--binary-self-check",
                StringComparison.Ordinal);
        var quiet = args.Contains("--quiet", StringComparer.Ordinal)
            || binarySelfCheckRequested;
        try
        {
            if (!binarySelfCheckRequested)
            {
                ApplicationConfiguration.Initialize();
            }
            var command = ParseCommand(args);
            var processPath = Environment.ProcessPath
                ?? throw new InvalidOperationException(
                    "Unable to identify the personal maintenance executable.");
            if (command.Kind == MaintenanceCommandKind.BinarySelfCheck)
            {
                var fingerprint = PersonalBinarySelfCheck
                    .RequireCurrentProcessCompiledTrust(
                        ExecutableName,
                        Assembly.GetExecutingAssembly());
                PersonalBinarySelfCheck.WriteCanonicalCompiledTrust(fingerprint);
                return 0;
            }

            var layout = PersonalInstallationLayout.CreateDefault();
            var operations = new PersonalMaintenanceOperations(layout);
            if (command.Kind == MaintenanceCommandKind.RepairShell)
            {
                using var repairOperationLease =
                    PersonalManagedUpdateOperationLease.AcquireRequiredAsync(layout)
                        .GetAwaiter()
                        .GetResult();
                _ = operations.RepairShell(processPath);
                if (!quiet)
                {
                    MessageBox.Show(
                        "Launcher shortcuts and current-user repair/uninstall registration were repaired offline.",
                        "DeepSeek Harness Launcher",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                }
                return 0;
            }

            if (!command.Detached)
            {
                var admittedWorkerSha256 = operations.RequireSafeUninstallSource(processPath);
                StartDetachedUninstall(processPath, command, admittedWorkerSha256);
                return 0;
            }

            RequireDetachedBinaryTrusted(processPath);
            operations.RequireDetachedUninstallWorker(
                processPath,
                command.ExpectedWorkerSha256!);
            WaitForProcess(command.ParentProcessId!.Value, "maintenance parent");
            WaitForProcess(command.StartupStubProcessId!.Value, "Startup Stub");
            using var operationLease =
                PersonalManagedUpdateOperationLease.AcquireRequiredAsync(layout)
                    .GetAwaiter()
                    .GetResult();
            var quarantine = operations.QuarantineManagedProgramFiles();
            var commit = operations.CommitQuarantinedUninstall(quarantine);
            if (!quiet)
            {
                MessageBox.Show(
                    $"DeepSeek Harness Launcher was removed."
                    + (commit.QuarantineDeleted
                        ? string.Empty
                        : " A quarantined program-file cleanup will be retried by a future signed installer.")
                    + $"\n\nLocal conversations, workspaces, and settings remain in:\n{layout.HarnessHome}",
                    "DeepSeek Harness Launcher",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            return 0;
        }
        catch (Exception exception)
        {
            if (binarySelfCheckRequested)
            {
                TryWriteBinarySelfCheckFailure();
            }
            else if (!quiet)
            {
                MessageBox.Show(
                    exception.Message,
                    "DeepSeek Harness Launcher maintenance did not complete",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
            return 1;
        }
    }

    private static void TryWriteBinarySelfCheckFailure()
    {
        try
        {
            using var standardError = Console.OpenStandardError();
            if (!standardError.CanWrite)
            {
                return;
            }
            standardError.Write(
                System.Text.Encoding.ASCII.GetBytes(
                    PersonalBinarySelfCheck.FailureMarker));
            standardError.Flush();
        }
        catch
        {
            // A machine self-check without a writable stderr still fails closed.
        }
    }

    private static void StartDetachedUninstall(
        string processPath,
        MaintenanceCommand command,
        string admittedWorkerSha256)
    {
        var workerRoot = Path.Combine(Path.GetTempPath(), "Ensou", WorkerRootName);
        RejectLinkedAncestors(workerRoot);
        Directory.CreateDirectory(workerRoot);
        RejectLinkedAncestors(workerRoot);
        DeleteStaleWorkers(workerRoot);

        var workerDirectory = Path.Combine(workerRoot, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(workerDirectory);
        var workerPath = Path.Combine(workerDirectory, ExecutableName);
        File.Copy(processPath, workerPath, overwrite: false);
        if (!CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(File.ReadAllBytes(processPath)),
                SHA256.HashData(File.ReadAllBytes(workerPath))))
        {
            throw new IOException("Detached maintenance worker differs from its signed source.");
        }
        PersonalAuthenticodeVerifier.RequireTrustedEnsouExecutable(workerPath);

        var start = new ProcessStartInfo
        {
            FileName = workerPath,
            WorkingDirectory = workerDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        start.ArgumentList.Add("--uninstall");
        start.ArgumentList.Add("--detached");
        start.ArgumentList.Add("--parent-pid");
        start.ArgumentList.Add(Environment.ProcessId.ToString(
            System.Globalization.CultureInfo.InvariantCulture));
        start.ArgumentList.Add("--startup-stub-pid");
        start.ArgumentList.Add(command.StartupStubProcessId!.Value.ToString(
            System.Globalization.CultureInfo.InvariantCulture));
        start.ArgumentList.Add("--expected-worker-sha256");
        start.ArgumentList.Add(admittedWorkerSha256);
        if (command.Quiet)
        {
            start.ArgumentList.Add("--quiet");
        }
        _ = Process.Start(start)
            ?? throw new InvalidOperationException(
                "Unable to start the detached personal uninstall worker.");
    }

    private static void RequireDetachedBinaryTrusted(string processPath)
    {
        var absolutePath = Path.GetFullPath(processPath);
        var expectedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.Combine(
            Path.GetTempPath(),
            "Ensou",
            WorkerRootName)));
        var parent = Path.GetDirectoryName(absolutePath)
            ?? throw new InvalidDataException(
                "Detached maintenance worker has no parent directory.");
        if (!parent.StartsWith(
                expectedRoot + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase)
            || !Guid.TryParseExact(Path.GetFileName(parent), "N", out _)
            || !string.Equals(Path.GetFileName(absolutePath), ExecutableName, StringComparison.Ordinal)
            || !File.Exists(absolutePath)
            || (File.GetAttributes(absolutePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Detached personal maintenance worker path is invalid or linked.");
        }
        RejectLinkedAncestors(parent);
        _ = PersonalBinarySelfCheck.RequireCurrentProcess(ExecutableName);
    }

    private static void DeleteStaleWorkers(string workerRoot)
    {
        foreach (var directory in Directory.EnumerateDirectories(workerRoot))
        {
            if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Personal maintenance worker root contains a filesystem link.");
            }
            foreach (var entry in Directory.EnumerateFileSystemEntries(
                         directory,
                         "*",
                         SearchOption.AllDirectories))
            {
                if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0)
                {
                    throw new InvalidDataException(
                        "Personal maintenance worker tree contains a filesystem link.");
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

    private static void WaitForProcess(int processId, string description)
    {
        if (processId == Environment.ProcessId)
        {
            throw new InvalidDataException(
                $"Detached worker cannot wait on itself as the {description}.");
        }
        try
        {
            using var process = Process.GetProcessById(processId);
            if (!process.WaitForExit(30_000))
            {
                throw new TimeoutException(
                    $"Timed out waiting for the personal {description} to exit.");
            }
        }
        catch (ArgumentException)
        {
            // The parent already exited.
        }
    }

    private static MaintenanceCommand ParseCommand(IReadOnlyList<string> args)
    {
        if (args.Count == 1 && args[0] == "--binary-self-check")
        {
            return new MaintenanceCommand(MaintenanceCommandKind.BinarySelfCheck);
        }
        if (args.Count == 1 && args[0] == "--repair-shell")
        {
            return new MaintenanceCommand(MaintenanceCommandKind.RepairShell);
        }
        if (args.Count < 3 || args[0] != "--uninstall")
        {
            throw new ArgumentException(
                "Personal Maintenance accepts only binary-self-check, offline repair-shell, or uninstall.");
        }

        var quiet = false;
        var detached = false;
        int? parentProcessId = null;
        int? startupStubProcessId = null;
        string? expectedWorkerSha256 = null;
        for (var index = 1; index < args.Count; index++)
        {
            switch (args[index])
            {
                case "--quiet" when !quiet:
                    quiet = true;
                    break;
                case "--detached" when !detached:
                    detached = true;
                    break;
                case "--parent-pid" when parentProcessId is null:
                    parentProcessId = ReadPositiveProcessId(args, ref index, "--parent-pid");
                    break;
                case "--startup-stub-pid" when startupStubProcessId is null:
                    startupStubProcessId = ReadPositiveProcessId(
                        args,
                        ref index,
                        "--startup-stub-pid");
                    break;
                case "--expected-worker-sha256" when expectedWorkerSha256 is null:
                    expectedWorkerSha256 = ReadSha256(
                        args,
                        ref index,
                        "--expected-worker-sha256");
                    break;
                default:
                    throw new ArgumentException(
                        "Personal Maintenance uninstall arguments are duplicated or invalid.");
            }
        }
        if (startupStubProcessId is null
            || detached != (parentProcessId is not null)
            || detached != (expectedWorkerSha256 is not null))
        {
            throw new ArgumentException(
                "Personal Maintenance uninstall process binding is incomplete.");
        }
        return new MaintenanceCommand(
            MaintenanceCommandKind.Uninstall,
            quiet,
            detached,
            parentProcessId,
            startupStubProcessId,
            expectedWorkerSha256);
    }

    private static int ReadPositiveProcessId(
        IReadOnlyList<string> args,
        ref int index,
        string option)
    {
        if (++index >= args.Count
            || !int.TryParse(
                args[index],
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var value)
            || value <= 0)
        {
            throw new ArgumentException($"{option} requires one positive process ID.");
        }
        return value;
    }

    private static string ReadSha256(
        IReadOnlyList<string> args,
        ref int index,
        string option)
    {
        if (++index >= args.Count
            || args[index].Length != 64
            || args[index].Any(character => character is not (>= '0' and <= '9')
                and not (>= 'a' and <= 'f')))
        {
            throw new ArgumentException(
                $"{option} requires one canonical lowercase SHA-256.");
        }
        return args[index];
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
                    "Personal maintenance path crosses a filesystem link.");
            }
        }
    }

    private enum MaintenanceCommandKind
    {
        BinarySelfCheck,
        RepairShell,
        Uninstall,
    }

    private sealed record MaintenanceCommand(
        MaintenanceCommandKind Kind,
        bool Quiet = false,
        bool Detached = false,
        int? ParentProcessId = null,
        int? StartupStubProcessId = null,
        string? ExpectedWorkerSha256 = null);
}
