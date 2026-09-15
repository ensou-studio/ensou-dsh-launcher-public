using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.UpdateEngine;
using Microsoft.Win32;

namespace Ensou.Dsh.Personal.MaintenanceTests;

internal static class Program
{
    private static readonly string TempRoot = Path.Combine(
        Path.GetTempPath(),
        "ensou-personal-maintenance-tests",
        Guid.NewGuid().ToString("N"));

    [STAThread]
    public static int Main()
    {
        Directory.CreateDirectory(TempRoot);
        var tests = new (string Name, Action Run)[]
        {
            ("offline shell repair is idempotent and read back", OfflineRepairIsIdempotent),
            ("maintenance launch admission locks the complete-tree executable identity", MaintenanceLaunchAdmissionLocksExactExecutable),
            ("external and hard-linked maintenance paths are rejected", ExternalAndHardLinkedPathsAreRejected),
            ("damaged client bundle requires original signed installer", DamagedBundleRequiresInstaller),
            ("open managed handle blocks quarantine and preserves registration", OpenHandleBlocksQuarantine),
            ("running managed executable blocks quarantine and preserves registration", RunningExecutableBlocksQuarantine),
            ("uninstall removes only managed program files", UninstallPreservesHarnessData),
            ("quarantine deletion failure preserves data and active absence", QuarantineDeletionFailureIsContained),
            ("partial registration removal rolls back program and shell", PartialRegistrationRemovalRollsBack),
            ("published Maintenance is exact self-contained executable", PublishedBinarySelfCheck),
        };
        var failures = 0;
        try
        {
            foreach (var test in tests)
            {
                try
                {
                    Console.WriteLine($"RUN {test.Name}");
                    test.Run();
                    Console.WriteLine($"PASS {test.Name}");
                }
                catch (Exception exception)
                {
                    failures++;
                    Console.Error.WriteLine($"FAIL {test.Name}: {exception}");
                }
            }
        }
        finally
        {
            if (Directory.Exists(TempRoot))
            {
                Directory.Delete(TempRoot, recursive: true);
            }
        }
        Console.WriteLine($"{tests.Length - failures}/{tests.Length} personal maintenance tests passed.");
        return failures == 0 ? 0 : 1;
    }

    private static void OfflineRepairIsIdempotent()
    {
        using var fixture = new MaintenanceFixture("repair");
        var before = fixture.CaptureProtectedState();
        var operations = fixture.CreateOperations();
        var first = operations.RepairShell(fixture.MaintenancePath);
        var second = operations.RepairShell(fixture.MaintenancePath);

        AssertEqual(first, second);
        AssertEqual(fixture.Layout.StartupStubPath, first.ShortcutTarget);
        AssertEqual(
            $"\"{fixture.Layout.StartupStubPath}\" --maintenance-repair",
            first.ModifyPath);
        AssertEqual(
            $"\"{fixture.Layout.StartupStubPath}\" --maintenance-uninstall",
            first.UninstallString);
        AssertEqual(
            $"\"{fixture.Layout.StartupStubPath}\" --maintenance-uninstall --quiet",
            first.QuietUninstallString);
        _ = PersonalWindowsRegistration.ReadAndValidate(
            fixture.Layout,
            fixture.ReleaseSetId,
            fixture.RegistrationContext);
        AssertProtectedEqual(before, fixture.CaptureProtectedState());
    }

    private static void MaintenanceLaunchAdmissionLocksExactExecutable()
    {
        using var fixture = new MaintenanceFixture("launch-admission");
        var replacement = Path.Combine(fixture.Root, "replacement-maintenance.exe");
        File.WriteAllText(replacement, "replacement-maintenance");
        var admissionObserved = false;
        using (var lease = PersonalMaintenanceIntegrity
            .AcquireActiveMaintenanceExecutableLaunchLeaseForTests(
                fixture.Layout,
                fixture.Current,
                (path, verifyWhileExecutableLocked) =>
                {
                    AssertEqual(
                        Path.GetFullPath(fixture.MaintenancePath),
                        Path.GetFullPath(path));
                    var executable = PersonalAuthenticodeVerifier
                        .OpenExecutableForLaunchForTests(path);
                    try
                    {
                        verifyWhileExecutableLocked();
                        admissionObserved = true;
                        AssertSharingViolation(() => File.Move(
                            replacement,
                            path,
                            overwrite: true));
                        return executable;
                    }
                    catch
                    {
                        executable.Dispose();
                        throw;
                    }
                }))
        {
            AssertTrue(admissionObserved);
            AssertSharingViolation(() => File.Delete(fixture.MaintenancePath));
        }
        File.Move(replacement, fixture.MaintenancePath, overwrite: true);
        AssertEqual("replacement-maintenance", File.ReadAllText(fixture.MaintenancePath));

        AssertThrows<InvalidOperationException>(() =>
            PersonalMaintenanceIntegrity
                .AcquireActiveMaintenanceExecutableLaunchLeaseForTests(
                    fixture.Layout,
                    fixture.Current,
                    (path, _) => PersonalAuthenticodeVerifier
                        .OpenExecutableForLaunchForTests(path))
                .Dispose());
    }

    private static void ExternalAndHardLinkedPathsAreRejected()
    {
        using var fixture = new MaintenanceFixture("external-link");
        var operations = fixture.CreateOperations();
        var external = Path.Combine(fixture.Root, "external-maintenance.exe");
        File.Copy(fixture.MaintenancePath, external, overwrite: false);
        AssertThrows<PersonalBinaryRepairRequiresInstallerException>(() =>
            operations.RepairShell(external));
        var admittedHash = Convert.ToHexStringLower(
            SHA256.HashData(File.ReadAllBytes(fixture.MaintenancePath)));
        operations.RequireDetachedUninstallWorker(external, admittedHash);
        File.AppendAllText(external, "old-or-tampered-worker");
        AssertThrows<PersonalBinaryRepairRequiresInstallerException>(() =>
            operations.RequireDetachedUninstallWorker(external, admittedHash));

        File.Copy(fixture.MaintenancePath, external, overwrite: true);
        File.Delete(fixture.MaintenancePath);
        if (!CreateHardLink(fixture.MaintenancePath, external, IntPtr.Zero))
        {
            throw new IOException(
                "Unable to create the hard-link test fixture.",
                new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
        }
        AssertThrows<PersonalBinaryRepairRequiresInstallerException>(() =>
            operations.RepairShell(fixture.MaintenancePath));
    }

    private static void OpenHandleBlocksQuarantine()
    {
        using var fixture = new MaintenanceFixture("open-handle");
        var operations = fixture.CreateOperations();
        _ = operations.RepairShell(fixture.MaintenancePath);
        using (var locked = new FileStream(
                   fixture.LauncherPath,
                   FileMode.Open,
                   FileAccess.Read,
                   FileShare.None))
        {
            AssertThrows<IOException>(() => operations.QuarantineManagedProgramFiles());
        }
        AssertTrue(Directory.Exists(fixture.Layout.ManagedRoot));
        _ = PersonalWindowsRegistration.ReadAndValidate(
            fixture.Layout,
            fixture.ReleaseSetId,
            fixture.RegistrationContext);
    }

    private static void RunningExecutableBlocksQuarantine()
    {
        using var fixture = new MaintenanceFixture("running-executable", executableLauncher: true);
        var operations = fixture.CreateOperations();
        _ = operations.RepairShell(fixture.MaintenancePath);
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = fixture.LauncherPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            ArgumentList = { "-t", "127.0.0.1" },
        }) ?? throw new InvalidOperationException("Unable to start managed executable fixture.");
        try
        {
            Thread.Sleep(250);
            AssertFalse(process.HasExited);
            AssertEqual(
                Path.GetFullPath(fixture.LauncherPath),
                Path.GetFullPath(process.MainModule?.FileName
                    ?? throw new InvalidOperationException(
                        "Running executable fixture has no process image.")));
            AssertThrows<IOException>(() => operations.QuarantineManagedProgramFiles());
            AssertTrue(Directory.Exists(fixture.Layout.ManagedRoot));
            _ = PersonalWindowsRegistration.ReadAndValidate(
                fixture.Layout,
                fixture.ReleaseSetId,
                fixture.RegistrationContext);
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: false);
                process.WaitForExit();
            }
        }
    }

    private static void DamagedBundleRequiresInstaller()
    {
        using var fixture = new MaintenanceFixture("damaged");
        var before = fixture.CaptureProtectedState();
        File.AppendAllText(fixture.LauncherPath, "tampered");
        var exception = AssertThrows<PersonalBinaryRepairRequiresInstallerException>(() =>
            fixture.CreateOperations().RepairShell(fixture.MaintenancePath));
        AssertTrue(exception.Message.Contains(
            "original Authenticode-signed Ensou installer",
            StringComparison.Ordinal));
        AssertEqual(before.Pointer, File.ReadAllBytes(fixture.Layout.ReleaseSetPointerPath));
        AssertEqual(before.Security, File.ReadAllBytes(fixture.Layout.UpdateSecurityStatePath));
        AssertEqual(before.Witness, File.ReadAllBytes(fixture.Layout.UpdateSecurityWitnessPath));
        AssertFalse(File.Exists(fixture.RegistrationContext.DesktopShortcutPath));
        AssertFalse(File.Exists(fixture.RegistrationContext.StartMenuShortcutPath));
    }

    private static void UninstallPreservesHarnessData()
    {
        using var fixture = new MaintenanceFixture("uninstall");
        var operations = fixture.CreateOperations();
        _ = operations.RepairShell(fixture.MaintenancePath);
        var harnessBefore = SnapshotTree(fixture.Layout.HarnessHome);
        var externalSentinel = Path.Combine(fixture.Root, "outside-managed.txt");
        File.WriteAllText(externalSentinel, "outside");

        _ = operations.RequireSafeUninstallSource(fixture.MaintenancePath);
        var quarantine = operations.QuarantineManagedProgramFiles()
            ?? throw new InvalidOperationException("Expected managed program quarantine.");
        var commit = operations.CommitQuarantinedUninstall(quarantine);
        AssertTrue(commit.ActiveInstallationRemoved);
        AssertTrue(commit.QuarantineDeleted);

        AssertFalse(Directory.Exists(fixture.Layout.ManagedRoot));
        AssertEqual(harnessBefore, SnapshotTree(fixture.Layout.HarnessHome));
        AssertEqual("outside", File.ReadAllText(externalSentinel));
        AssertFalse(File.Exists(fixture.RegistrationContext.DesktopShortcutPath));
        AssertFalse(File.Exists(fixture.RegistrationContext.StartMenuShortcutPath));
        using var key = Registry.CurrentUser.OpenSubKey(
            fixture.RegistrationContext.RegistrySubKey,
            writable: false);
        AssertTrue(key is null);

        AssertTrue(operations.QuarantineManagedProgramFiles() is null);
        operations.RemoveWindowsRegistration();
        AssertEqual(harnessBefore, SnapshotTree(fixture.Layout.HarnessHome));
    }

    private static void QuarantineDeletionFailureIsContained()
    {
        using var fixture = new MaintenanceFixture(
            "delete-failure",
            deleteQuarantine: _ => false);
        var operations = fixture.CreateOperations();
        _ = operations.RepairShell(fixture.MaintenancePath);
        var harnessBefore = SnapshotTree(fixture.Layout.HarnessHome);
        var quarantine = operations.QuarantineManagedProgramFiles()
            ?? throw new InvalidOperationException("Expected managed program quarantine.");
        var commit = operations.CommitQuarantinedUninstall(quarantine);
        AssertTrue(commit.ActiveInstallationRemoved);
        AssertFalse(commit.QuarantineDeleted);
        var lockedPath = Path.Combine(
            quarantine.Directory,
            "client-bundle-versions",
            "client-maintenance-v1",
            PersonalInstallationLayout.LauncherExecutableName);
        using (var locked = new FileStream(
                   lockedPath,
                   FileMode.Open,
                   FileAccess.Read,
                   FileShare.Read))
        {
            AssertFalse(operations.TryDeleteQuarantine(quarantine));
            AssertFalse(Directory.Exists(fixture.Layout.ManagedRoot));
            AssertEqual(harnessBefore, SnapshotTree(fixture.Layout.HarnessHome));
        }
        AssertTrue(operations.TryDeleteQuarantine(quarantine));
        AssertEqual(harnessBefore, SnapshotTree(fixture.Layout.HarnessHome));
    }

    private static void PartialRegistrationRemovalRollsBack()
    {
        var failOnce = true;
        using var fixture = new MaintenanceFixture(
            "registration-rollback",
            removalObserver: stage =>
            {
                if (failOnce
                    && stage == PersonalWindowsRegistrationRemovalStage.DesktopShortcutRemoved)
                {
                    failOnce = false;
                    throw new IOException("injected registration removal failure");
                }
            });
        var operations = fixture.CreateOperations();
        _ = operations.RepairShell(fixture.MaintenancePath);
        var harnessBefore = SnapshotTree(fixture.Layout.HarnessHome);
        var quarantine = operations.QuarantineManagedProgramFiles()
            ?? throw new InvalidOperationException("Expected managed program quarantine.");

        AssertThrows<IOException>(() => operations.CommitQuarantinedUninstall(quarantine));

        AssertTrue(Directory.Exists(fixture.Layout.ManagedRoot));
        AssertFalse(Directory.Exists(quarantine.Directory));
        _ = PersonalWindowsRegistration.ReadAndValidate(
            fixture.Layout,
            fixture.ReleaseSetId,
            fixture.RegistrationContext);
        AssertEqual(harnessBefore, SnapshotTree(fixture.Layout.HarnessHome));
    }

    private static void PublishedBinarySelfCheck()
    {
        var publishDirectory = Environment.GetEnvironmentVariable(
            "ENSOU_PERSONAL_MAINTENANCE_PUBLISH_DIR");
        if (string.IsNullOrWhiteSpace(publishDirectory)
            || !Path.IsPathFullyQualified(publishDirectory))
        {
            throw new InvalidOperationException(
                "ENSOU_PERSONAL_MAINTENANCE_PUBLISH_DIR must identify the tested publish directory.");
        }
        var files = Directory.EnumerateFiles(publishDirectory, "*", SearchOption.AllDirectories)
            .Select(Path.GetFullPath)
            .ToArray();
        var executable = Path.Combine(
            Path.GetFullPath(publishDirectory),
            PersonalInstallationLayout.MaintenanceExecutableName);
        AssertEqual(1, files.Length);
        AssertEqual(executable, files[0]);
        AssertTrue(new FileInfo(executable).Length > 0);

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executable,
                WorkingDirectory = publishDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            },
        };
        process.StartInfo.ArgumentList.Add("--binary-self-check");
        process.StartInfo.Environment["PATH"] = string.Empty;
        process.StartInfo.Environment["DOTNET_ROOT"] = Path.Combine(
            publishDirectory,
            "missing-dotnet-root");
        process.StartInfo.Environment["DOTNET_ROOT_X64"] = Path.Combine(
            publishDirectory,
            "missing-dotnet-root-x64");
        process.StartInfo.Environment["DOTNET_MULTILEVEL_LOOKUP"] = "0";
        process.StartInfo.Environment[
            PersonalBinarySelfCheck.ProtocolEnvironmentVariable] =
            PersonalBinarySelfCheck.ProtocolValue;
        AssertTrue(process.Start());
        if (!process.WaitForExit(30_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("Personal Maintenance binary self-check timed out.");
        }
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"Personal Maintenance binary self-check exited {process.ExitCode}: {output} {error}");
        }
        AssertEqual(string.Empty, error);
        var fingerprint = PersonalCompiledTrustFingerprint.ParseCanonical(
            new UTF8Encoding(false, true).GetBytes(output));
        AssertFalse(fingerprint.ProductionBuild);
        AssertEqual("stable", fingerprint.Channel);
        AssertEqual(1L, fingerprint.CanonicalLowSFromSequence);

        using var extraArgument = StartBinarySelfCheck(
            executable,
            publishDirectory,
            redirectOutput: true,
            PersonalBinarySelfCheck.ProtocolValue,
            "--binary-self-check",
            "--unexpected");
        AssertTrue(extraArgument.WaitForExit(30_000));
        AssertEqual(1, extraArgument.ExitCode);
        AssertEqual(string.Empty, extraArgument.StandardOutput.ReadToEnd());
        AssertEqual(
            PersonalBinarySelfCheck.FailureMarker,
            extraArgument.StandardError.ReadToEnd());

        using var noMachineOutput = StartBinarySelfCheck(
            executable,
            publishDirectory,
            redirectOutput: false,
            protocol: null,
            "--binary-self-check");
        AssertTrue(noMachineOutput.WaitForExit(30_000));
        AssertEqual(1, noMachineOutput.ExitCode);

        using var wrongProtocol = StartBinarySelfCheck(
            executable,
            publishDirectory,
            redirectOutput: true,
            protocol: "ensou-personal-binary-self-check/wrong",
            "--binary-self-check");
        AssertTrue(wrongProtocol.WaitForExit(30_000));
        AssertEqual(1, wrongProtocol.ExitCode);
        AssertEqual(string.Empty, wrongProtocol.StandardOutput.ReadToEnd());
        AssertEqual(
            PersonalBinarySelfCheck.FailureMarker,
            wrongProtocol.StandardError.ReadToEnd());
    }

    private static Process StartBinarySelfCheck(
        string executable,
        string workingDirectory,
        bool redirectOutput,
        string? protocol,
        params string[] arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            WorkingDirectory = workingDirectory,
            UseShellExecute = !redirectOutput,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = redirectOutput,
            RedirectStandardError = redirectOutput,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
        if (redirectOutput)
        {
            startInfo.Environment["PATH"] = string.Empty;
            startInfo.Environment["DOTNET_ROOT"] = Path.Combine(
                workingDirectory,
                "missing-dotnet-root");
            startInfo.Environment["DOTNET_ROOT_X64"] = Path.Combine(
                workingDirectory,
                "missing-dotnet-root-x64");
            startInfo.Environment["DOTNET_MULTILEVEL_LOOKUP"] = "0";
        }
        if (protocol is not null)
        {
            startInfo.Environment[
                PersonalBinarySelfCheck.ProtocolEnvironmentVariable] =
                protocol;
        }
        return Process.Start(startInfo)
            ?? throw new InvalidOperationException(
                "Unable to start Personal Maintenance binary self-check fixture.");
    }

    private static string SnapshotTree(string root)
    {
        var entries = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .Select(path =>
                Path.GetRelativePath(root, path).Replace('\\', '/')
                + ":"
                + Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))));
        return string.Join("\n", entries);
    }

    private static TException AssertThrows<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException exception)
        {
            return exception;
        }
        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }

    private static void AssertSharingViolation(Action action)
    {
        try
        {
            action();
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }
        throw new InvalidOperationException("Expected a Windows file-sharing violation.");
    }

    private static void AssertTrue(bool value)
    {
        if (!value)
        {
            throw new InvalidOperationException("Expected true.");
        }
    }

    private static void AssertFalse(bool value) => AssertTrue(!value);

    private static void AssertEqual<T>(T expected, T actual)
    {
        if (expected is byte[] expectedBytes && actual is byte[] actualBytes)
        {
            if (!expectedBytes.AsSpan().SequenceEqual(actualBytes))
            {
                throw new InvalidOperationException("Expected byte sequences to match.");
            }
            return;
        }
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected '{expected}', got '{actual}'.");
        }
    }

    private static void AssertProtectedEqual(ProtectedState expected, ProtectedState actual)
    {
        AssertEqual(expected.Pointer, actual.Pointer);
        AssertEqual(expected.Security, actual.Security);
        AssertEqual(expected.Witness, actual.Witness);
        AssertEqual(expected.StartupStub, actual.StartupStub);
        AssertEqual(expected.HarnessTree, actual.HarnessTree);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(
        string newFileName,
        string existingFileName,
        IntPtr securityAttributes);

    private sealed class MaintenanceFixture : IDisposable
    {
        private static readonly JsonSerializerOptions JsonOptions =
            new(JsonSerializerDefaults.Web);

        private readonly Func<PersonalManagedProgramQuarantine, bool>? _deleteQuarantine;

        public MaintenanceFixture(
            string scope,
            bool executableLauncher = false,
            Action<PersonalWindowsRegistrationRemovalStage>? removalObserver = null,
            Func<PersonalManagedProgramQuarantine, bool>? deleteQuarantine = null)
        {
            Root = Path.Combine(TempRoot, scope + "-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
            Layout = new PersonalInstallationLayout(
                Path.Combine(Root, "managed"),
                Path.Combine(Root, ".dsh"),
                Path.Combine(Root, "security-witness.dpapi"));
            ReleaseSetId = "personal-maintenance-set-v1";
            RegistrationContext = new PersonalWindowsRegistrationContext(
                @"Software\Ensou\CodexTests\PersonalMaintenance\" + Guid.NewGuid().ToString("N"),
                Path.Combine(Root, "shell", "desktop", PersonalWindowsRegistration.ShortcutFileName),
                Path.Combine(Root, "shell", "programs", "Ensou", PersonalWindowsRegistration.ShortcutFileName),
                removalObserver);
            _deleteQuarantine = deleteQuarantine;
            Layout.EnsureManagedRoots();
            File.WriteAllBytes(Layout.StartupStubPath, Encoding.UTF8.GetBytes("stable startup stub"));
            Directory.CreateDirectory(Layout.HarnessHome);
            Directory.CreateDirectory(Path.Combine(Layout.HarnessHome, "workspaces", "demo"));
            File.WriteAllText(Path.Combine(Layout.HarnessHome, "history.json"), "history");
            File.WriteAllText(
                Path.Combine(Layout.HarnessHome, "workspaces", "demo", "notes.md"),
                "workspace");

            var client = WriteComponent(
                Layout.GetClientBundleDirectory("client-maintenance-v1"),
                PersonalReleaseSetContract.ClientBundleComponent,
                "client-maintenance-v1",
                new Dictionary<string, byte[]>(StringComparer.Ordinal)
                {
                    [PersonalInstallationLayout.ClientBootstrapperExecutableName] =
                        Encoding.UTF8.GetBytes("versioned bootstrapper"),
                    [PersonalInstallationLayout.LauncherExecutableName] =
                        executableLauncher
                            ? File.ReadAllBytes(Path.Combine(
                                Environment.GetFolderPath(Environment.SpecialFolder.System),
                                "ping.exe"))
                            : Encoding.UTF8.GetBytes("launcher"),
                    [PersonalInstallationLayout.MaintenanceExecutableName] =
                        Encoding.UTF8.GetBytes("maintenance"),
                },
                PersonalInstallationLayout.ClientBootstrapperExecutableName,
                PersonalInstallationLayout.LauncherExecutableName);
            var runtime = WriteComponent(
                Layout.GetRuntimeDirectory("runtime-maintenance-v1"),
                PersonalReleaseSetContract.RuntimeComponent,
                "runtime-maintenance-v1",
                new Dictionary<string, byte[]>(StringComparer.Ordinal)
                {
                    ["node.exe"] = Encoding.UTF8.GetBytes("node"),
                    ["node_modules/@deepseek-ai/dsh/lib/bin.js"] =
                        Encoding.UTF8.GetBytes("console.log('dsh')"),
                },
                "node.exe",
                "node_modules/@deepseek-ai/dsh/lib/bin.js");
            MaintenancePath = Path.Combine(
                client.Directory,
                PersonalInstallationLayout.MaintenanceExecutableName);
            LauncherPath = Path.Combine(
                client.Directory,
                PersonalInstallationLayout.LauncherExecutableName);
            var current = new PersonalInstalledReleaseSetReference(
                ReleaseSetId,
                1,
                1,
                0,
                new string('a', 64),
                new PersonalStartupStubCompatibility
                {
                    MinimumVersion = "1.0.0",
                    MaximumVersion = "1.9.9",
                },
                client,
                runtime,
                PersonalReleaseHealthStates.Healthy,
                null,
                null,
                DateTimeOffset.UtcNow);
            Current = current;
            var pointer = new PersonalInstalledReleaseSetPointer(
                3,
                PersonalReleaseSetContract.Product,
                PersonalReleaseSetContract.ProductionEnvironment,
                "stable",
                current,
                null,
                DateTimeOffset.UtcNow);
            File.WriteAllBytes(
                Layout.ReleaseSetPointerPath,
                JsonSerializer.SerializeToUtf8Bytes(pointer, JsonOptions));
            File.WriteAllBytes(
                Layout.UpdateSecurityStatePath,
                Encoding.UTF8.GetBytes("security-state-sentinel"));
            File.WriteAllBytes(
                Layout.UpdateSecurityWitnessPath,
                Encoding.UTF8.GetBytes("security-witness-sentinel"));
        }

        public string Root { get; }

        public PersonalInstallationLayout Layout { get; }

        public string ReleaseSetId { get; }

        public PersonalInstalledReleaseSetReference Current { get; }

        public PersonalWindowsRegistrationContext RegistrationContext { get; }

        public string MaintenancePath { get; }

        public string LauncherPath { get; }

        public PersonalMaintenanceOperations CreateOperations() =>
            new(Layout, RegistrationContext, _deleteQuarantine);

        public ProtectedState CaptureProtectedState() => new(
            File.ReadAllBytes(Layout.ReleaseSetPointerPath),
            File.ReadAllBytes(Layout.UpdateSecurityStatePath),
            File.ReadAllBytes(Layout.UpdateSecurityWitnessPath),
            File.ReadAllBytes(Layout.StartupStubPath),
            SnapshotTree(Layout.HarnessHome));

        public void Dispose()
        {
            try
            {
                Registry.CurrentUser.DeleteSubKeyTree(
                    RegistrationContext.RegistrySubKey,
                    throwOnMissingSubKey: false);
            }
            finally
            {
                if (Directory.Exists(Root))
                {
                    Directory.Delete(Root, recursive: true);
                }
            }
        }

        private static PersonalInstalledComponentReference WriteComponent(
            string directory,
            string component,
            string releaseId,
            IReadOnlyDictionary<string, byte[]> files,
            string primary,
            string secondary)
        {
            Directory.CreateDirectory(directory);
            foreach (var pair in files)
            {
                var path = Path.Combine(directory, pair.Key.Replace('/', Path.DirectorySeparatorChar));
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.WriteAllBytes(path, pair.Value);
            }
            var tree = new PersonalCompleteTreeManifest
            {
                SchemaVersion = 1,
                Component = component,
                ReleaseId = releaseId,
                Files = files.OrderBy(pair => pair.Key, StringComparer.Ordinal)
                    .Select(pair => new PersonalCompleteTreeFile
                    {
                        Path = pair.Key,
                        SizeBytes = pair.Value.LongLength,
                        Sha256 = Hash(pair.Value),
                    })
                    .ToArray(),
            };
            var treeBytes = JsonSerializer.SerializeToUtf8Bytes(tree, JsonOptions);
            var completeTreeSha256 = Hash(treeBytes);
            File.WriteAllBytes(
                Path.Combine(directory, PersonalReleaseArtifactInstaller.CompleteTreeEntryName),
                treeBytes);
            var receipt = new PersonalReleaseComponentReceipt(
                1,
                component,
                releaseId,
                new string(component == PersonalReleaseSetContract.ClientBundleComponent ? 'b' : 'c', 64),
                completeTreeSha256,
                primary,
                Hash(files[primary]),
                secondary,
                Hash(files[secondary]),
                DateTimeOffset.UtcNow);
            PersonalReleaseSetPointerStore.WriteComponentReceipt(
                directory,
                receipt,
                Path.GetFullPath(Path.Combine(directory, "..", "..")));
            return new PersonalInstalledComponentReference(
                component,
                releaseId,
                directory,
                receipt.ArchiveSha256,
                completeTreeSha256);
        }

        private static string Hash(ReadOnlySpan<byte> bytes) =>
            Convert.ToHexStringLower(SHA256.HashData(bytes));
    }

    private sealed record ProtectedState(
        byte[] Pointer,
        byte[] Security,
        byte[] Witness,
        byte[] StartupStub,
        string HarnessTree);
}
