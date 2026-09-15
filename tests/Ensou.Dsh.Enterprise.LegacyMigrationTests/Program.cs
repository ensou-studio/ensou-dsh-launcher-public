using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.LegacyMigrationTests;

internal static class Program
{
    private const string ManagedProcessFixtureArgument =
        "--managed-process-fixture";
    private const string ManagedProcessFixtureReady =
        "ensou-dsh-enterprise-managed-process-fixture-ready";
    private static readonly string TempRoot = Path.Combine(
        Path.GetTempPath(),
        "edsh-legacy-migration-tests",
        Guid.NewGuid().ToString("N"));

    public static async Task<int> Main(string[] args)
    {
        if (args is [ManagedProcessFixtureArgument])
        {
            Console.WriteLine(ManagedProcessFixtureReady);
            Console.Out.Flush();
            Thread.Sleep(TimeSpan.FromSeconds(60));
            return 0;
        }
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("Enterprise legacy migration tests require Windows.");
            return 1;
        }

        Directory.CreateDirectory(TempRoot);
        var tests = new (string Name, Func<Task> Run)[]
        {
            ("clean device remains on fresh-install path", CleanDeviceRemainsFreshAsync),
            ("legacy migration rejects SQLite before journal or program mutation", LegacySqliteBlocksMigrationBeforeMutationAsync),
            ("schema2 plain feed is ignored and local data is preserved", LegacyPlainStateIgnoredAsync),
            ("all durable crash points recover idempotently", DurableCrashPointsRecoverAsync),
            ("registration failure leaves trusted program active and retryable", RegistrationFailureIsRetryableAsync),
            ("candidate tamper before isolation fails closed", CandidateTamperFailsClosedAsync),
            ("self-consistent wrong candidate receipts fail closed", WrongCandidateReceiptsFailClosedAsync),
            ("protected journal tamper fails closed", JournalTamperFailsClosedAsync),
            ("legacy reparse tree fails closed", LegacyReparseFailsClosedAsync),
            ("legacy hardlink tree fails closed", LegacyHardlinkFailsClosedAsync),
            ("running legacy executable blocks isolation", RunningLegacyProcessFailsClosedAsync),
            ("process start at isolation commit fails closed", IsolationCommitProcessRaceFailsClosedAsync),
            ("test cleanup retries a transient executable lock", TransientTestCleanupLockRetriesAsync),
            ("external Installer bytes stay locked", ExternalInstallerIdentityIsLockedAsync),
            ("external operation lease serializes migration", ExternalOperationLeaseSerializesAsync),
            ("migration recovers an active install journal first", ActiveInstallJournalRecoversBeforeMigrationAsync),
            ("migration recovers an active uninstall journal first", ActiveUninstallJournalRecoversBeforeMigrationAsync),
            ("default barrier leaves coexisting installer journals untouched", DefaultBarrierPrecedesInstallerJournalRecoveryAsync),
            ("all active migration crash phases block unrelated recovery", AllActivePhasesBlockUnrelatedRecoveryAsync),
            ("active migration blocks update and garbage collection", ActiveMigrationBlocksUpdateAndGcAsync),
            ("active migration blocks health and operator rollback", ActiveMigrationBlocksHealthAndRollbackAsync),
            ("active migration blocks maintenance repair and ordinary uninstall", ActiveMigrationBlocksMaintenanceAndUninstallAsync),
            ("external Installer resumes migration before uninstall", ExternalInstallerResumesThenUninstallsAsync),
            ("wrong external Installer cannot uninstall an active migration", WrongExternalInstallerCannotUninstallAsync),
            ("completed tombstone is independent from old Installer bytes", CompletedTombstoneIsInstallerIndependentAsync),
            ("independent witness reconciles a lost tombstone", LostTombstoneReconcilesAsync),
            ("completed migration permits uninstall then fresh reinstall", UninstallThenFreshReinstallAsync),
            ("pointer-only damaged current install fails closed", PointerOnlyDamagedCurrentFailsClosedAsync),
            ("installer-bootstrap receipt tuple drift fails closed", InstallerReceiptTupleDriftFailsClosedAsync),
            ("cross-component receipt fails closed", CrossComponentReceiptFailsClosedAsync),
            ("journal transitions use the injected UTC clock", JournalUsesInjectedClockAsync),
            ("backwards UTC crash retry remains monotonic and bounded", BackwardsUtcCrashRetryIsMonotonicAsync),
            ("production facade uses the authorized candidate pipeline", ProductionFacadeCandidatePipelineAsync),
            ("external facade fresh install uses normal installer transaction", ExternalFacadeFreshInstallAsync),
            ("current exact repair restores registration and installed Installer", CurrentExactRepairRestoresRegistrationAsync),
            ("stable-shell repair preserves a newer current tuple", StableShellRepairPreservesCurrentTupleAsync),
            ("stable-shell registration failure rolls back stable files", StableShellFailureRollsBackAsync),
            ("stable-shell SQLite rollback failure is path-free", StableShellSqliteRollbackFailureIsPathFreeAsync),
            ("production payload self-check invokes embedded migration lease", ProductionSelfCheckInvokesMigrationLeaseAsync),
            ("Installer machine self-check failures are bounded and noninteractive", InstallerMachineSelfCheckFailuresAreBoundedAsync),
            ("Installer application initialization failure uses the machine boundary", InstallerApplicationInitializationFailureUsesMachineBoundaryAsync),
        };

        if (args.Length != 0)
        {
            if (args is not ["--case", var methodName])
            {
                throw new ArgumentException("Expected --case followed by one exact test method name.");
            }
            tests = tests.Where(test => test.Run.Method.Name == methodName).ToArray();
            if (tests.Length != 1)
            {
                throw new ArgumentException("The selected legacy migration test does not exist.");
            }
        }
        var failures = 0;
        try
        {
            foreach (var test in tests)
            {
                try
                {
                    Console.WriteLine($"RUN   {test.Name}");
                    await test.Run().ConfigureAwait(false);
                    Console.WriteLine($"PASS  {test.Name}");
                }
                catch (Exception exception)
                {
                    failures++;
                    Console.Error.WriteLine($"FAIL  {test.Name}");
                    Console.Error.WriteLine(exception);
                }
            }
        }
        finally
        {
            DeleteTestDirectoryEventually(TempRoot);
        }

        Console.WriteLine($"{tests.Length - failures}/{tests.Length} legacy migration checks passed.");
        return failures == 0 ? 0 : 1;
    }

    private static void DeleteTestDirectoryEventually(string path)
    {
        const int attempts = 20;
        const int retryDelayMilliseconds = 100;
        Exception? lastFailure = null;

        for (var attempt = 0; attempt < attempts; attempt++)
        {
            if (!Directory.Exists(path))
            {
                return;
            }

            try
            {
                Directory.Delete(path, recursive: true);
                return;
            }
            catch (Exception exception) when (exception is
                IOException
                or UnauthorizedAccessException)
            {
                lastFailure = exception;
                if (attempt + 1 < attempts)
                {
                    Thread.Sleep(retryDelayMilliseconds);
                }
            }
        }

        throw new IOException(
            "Legacy migration test cleanup remained locked after bounded retries.",
            lastFailure);
    }

    private static async Task CleanDeviceRemainsFreshAsync()
    {
        using var fixture = Fixture.Create(seedLegacy: false);
        using var installer = fixture.OpenTrustedInstaller();
        var result = await fixture.Migrator()
            .MigrateIfRequiredAsync(installer, fixture.Callbacks)
            .ConfigureAwait(false);
        Equal(EnterpriseLegacyMigrationDisposition.FreshInstallRequired, result.Disposition);
        False(Directory.Exists(fixture.Layout.ManagedRoot));
        False(Directory.Exists(fixture.MigrationRoot));
        fixture.RequireUserDataUnchanged();
    }

    private static async Task LegacySqliteBlocksMigrationBeforeMutationAsync()
    {
        using var fixture = Fixture.Create();
        var sqlite = Path.Combine(fixture.Layout.HarnessHome, "sessions.sqlite-shm");
        var sqliteBytes = "legacy-sqlite-sidecar"u8.ToArray();
        File.WriteAllBytes(sqlite, sqliteBytes);
        var pointerBytes = File.ReadAllBytes(fixture.Layout.ReleaseSetPointerPath);
        var oldLauncher = Path.Combine(
            fixture.Layout.LauncherVersionsRoot,
            "legacy-launcher",
            "old.bin");
        var oldRuntime = Path.Combine(
            fixture.Layout.RuntimeVersionsRoot,
            "legacy-runtime",
            "old.bin");

        using var installer = fixture.OpenTrustedInstaller();
        await ThrowsAsync<InvalidOperationException>(() => fixture.Migrator()
            .MigrateIfRequiredAsync(installer, fixture.Callbacks));

        True(sqliteBytes.AsSpan().SequenceEqual(File.ReadAllBytes(sqlite)));
        True(pointerBytes.AsSpan().SequenceEqual(
            File.ReadAllBytes(fixture.Layout.ReleaseSetPointerPath)));
        Equal("old-launcher", File.ReadAllText(oldLauncher));
        Equal("old-runtime", File.ReadAllText(oldRuntime));
        False(Directory.Exists(fixture.MigrationRoot));
        False(Directory.Exists(fixture.Layout.UpdateOperationLockRoot));
        False(Directory.EnumerateDirectories(
            Path.GetDirectoryName(fixture.Layout.ManagedRoot)!,
            $".{Path.GetFileName(fixture.Layout.ManagedRoot)}.migration-candidate-*",
            SearchOption.TopDirectoryOnly).Any());
        fixture.RequireLegacyActive();
    }

    private static async Task LegacyPlainStateIgnoredAsync()
    {
        using var fixture = Fixture.Create();
        File.WriteAllText(
            Path.Combine(fixture.Layout.StateRoot, "release-set-current.v2.json"),
            "{\"schemaVersion\":2,\"current\":{\"launcher\":{\"directory\":\"C:/escape\"}}}");
        File.WriteAllText(
            Path.Combine(fixture.Layout.StateRoot, "release-feed-state.v2.json"),
            "{\"highestSequence\":9223372036854775807,\"manifestUri\":\"file:///C:/escape\"}");

        using var installer = fixture.OpenTrustedInstaller();
        var result = await fixture.Migrator()
            .MigrateIfRequiredAsync(installer, fixture.Callbacks)
            .ConfigureAwait(false);
        Equal("launcher-current", result.LauncherReleaseId);
        Equal("runtime-current", result.RuntimeReleaseId);
        True(Directory.Exists(result.PreservedLegacyProgramDirectory!));
        True(File.Exists(Path.Combine(
            result.PreservedLegacyProgramDirectory!,
            "state",
            "release-feed-state.v2.json")));
        fixture.RequireFinalizedAndRegistered();
        fixture.RequireUserDataUnchanged();
        False(File.Exists(fixture.OldExecutionMarker));
    }

    private static async Task DurableCrashPointsRecoverAsync()
    {
        var points = Enum.GetValues<EnterpriseLegacyMigrationFaultPoint>();
        True(points.Length >= 12);
        foreach (var point in points)
        {
            using var fixture = Fixture.Create(scope: point.ToString());
            using (var installer = fixture.OpenTrustedInstaller())
            {
                var crashed = false;
                try
                {
                    await fixture.Migrator(observed =>
                        {
                            if (observed == point)
                            {
                                throw new EnterpriseLegacyMigrationInjectedCrashException(point);
                            }
                        })
                        .MigrateIfRequiredAsync(installer, fixture.Callbacks)
                        .ConfigureAwait(false);
                }
                catch (EnterpriseLegacyMigrationInjectedCrashException exception)
                    when (exception.FaultPoint == point)
                {
                    crashed = true;
                }
                True(crashed);
            }

            using (var retryInstaller = fixture.OpenTrustedInstaller())
            {
                _ = await fixture.Migrator()
                    .MigrateIfRequiredAsync(retryInstaller, fixture.Callbacks)
                    .ConfigureAwait(false);
            }
            fixture.RequireFinalizedAndRegistered();
            fixture.RequireUserDataUnchanged();
            True(fixture.FindLegacyQuarantines().Count == 1);

            using var idempotentInstaller = fixture.OpenTrustedInstaller();
            _ = await fixture.Migrator()
                .MigrateIfRequiredAsync(idempotentInstaller, fixture.Callbacks)
                .ConfigureAwait(false);
            fixture.RequireFinalizedAndRegistered();
            True(fixture.FindLegacyQuarantines().Count == 1);
        }
    }

    private static async Task RegistrationFailureIsRetryableAsync()
    {
        using var fixture = Fixture.Create();
        fixture.FailRegistrationOnce = true;
        using (var installer = fixture.OpenTrustedInstaller())
        {
            await ThrowsAsync<IOException>(() => fixture.Migrator()
                .MigrateIfRequiredAsync(installer, fixture.Callbacks));
        }

        True(Directory.Exists(fixture.Layout.ManagedRoot));
        True(fixture.FindLegacyQuarantines().Count == 1);
        Equal("partial-registration", File.ReadAllText(fixture.RegistrationPath));
        fixture.RequireFinalized();
        fixture.RequireUserDataUnchanged();

        using var retryInstaller = fixture.OpenTrustedInstaller();
        var result = await fixture.Migrator()
            .MigrateIfRequiredAsync(retryInstaller, fixture.Callbacks)
            .ConfigureAwait(false);
        Equal(EnterpriseLegacyMigrationDisposition.RegistrationRecovered, result.Disposition);
        fixture.RequireFinalizedAndRegistered();
    }

    private static async Task CandidateTamperFailsClosedAsync()
    {
        using var fixture = Fixture.Create();
        using (var installer = fixture.OpenTrustedInstaller())
        {
            await ThrowsAsync<EnterpriseLegacyMigrationInjectedCrashException>(() =>
                fixture.Migrator(point =>
                    {
                        if (point == EnterpriseLegacyMigrationFaultPoint.AfterCandidatePreparedJournal)
                        {
                            throw new EnterpriseLegacyMigrationInjectedCrashException(point);
                        }
                    })
                    .MigrateIfRequiredAsync(installer, fixture.Callbacks));
        }

        var candidate = fixture.FindCandidate();
        File.AppendAllText(
            Path.Combine(
                candidate,
                "launcher-versions",
                "launcher-current",
                EnterpriseInstallationLayout.LauncherExecutableName),
            "tampered");
        using var retryInstaller = fixture.OpenTrustedInstaller();
        await ThrowsAsync<InvalidDataException>(() => fixture.Migrator()
            .MigrateIfRequiredAsync(retryInstaller, fixture.Callbacks));
        True(Directory.Exists(fixture.Layout.ManagedRoot));
        True(fixture.FindLegacyQuarantines().Count == 0);
        fixture.RequireLegacyActive();
        fixture.RequireUserDataUnchanged();
    }

    private static async Task WrongCandidateReceiptsFailClosedAsync()
    {
        using var fixture = Fixture.Create();
        fixture.StageWrongSelfConsistentCandidate = true;
        using var installer = fixture.OpenTrustedInstaller();
        await ThrowsAsync<InvalidDataException>(() => fixture.Migrator()
            .MigrateIfRequiredAsync(installer, fixture.Callbacks));
        fixture.RequireLegacyActive();
        True(fixture.FindLegacyQuarantines().Count == 0);
        fixture.RequireUserDataUnchanged();
    }

    private static async Task JournalTamperFailsClosedAsync()
    {
        using var fixture = Fixture.Create();
        using (var installer = fixture.OpenTrustedInstaller())
        {
            await ThrowsAsync<EnterpriseLegacyMigrationInjectedCrashException>(() =>
                fixture.Migrator(point =>
                    {
                        if (point == EnterpriseLegacyMigrationFaultPoint.AfterIntentJournal)
                        {
                            throw new EnterpriseLegacyMigrationInjectedCrashException(point);
                        }
                    })
                    .MigrateIfRequiredAsync(installer, fixture.Callbacks));
        }
        File.AppendAllText(fixture.JournalPath, "tampered");
        using var retryInstaller = fixture.OpenTrustedInstaller();
        await ThrowsAsync<InvalidDataException>(() => fixture.Migrator()
            .MigrateIfRequiredAsync(retryInstaller, fixture.Callbacks));
        fixture.RequireLegacyActive();
        fixture.RequireUserDataUnchanged();
    }

    private static async Task LegacyReparseFailsClosedAsync()
    {
        using var fixture = Fixture.Create();
        var target = Path.Combine(fixture.Root, "junction-target");
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "outside.txt"), "outside");
        var link = Path.Combine(fixture.Layout.ManagedRoot, "legacy-junction");
        if (!TryCreateDirectoryJunction(link, target))
        {
            throw new IOException("Unable to create required legacy reparse fixture.");
        }
        try
        {
            using var installer = fixture.OpenTrustedInstaller();
            await ThrowsAsync<InvalidDataException>(() => fixture.Migrator()
                .MigrateIfRequiredAsync(installer, fixture.Callbacks));
            True(File.Exists(Path.Combine(target, "outside.txt")));
            fixture.RequireLegacyActive();
        }
        finally
        {
            if (Directory.Exists(link))
            {
                Directory.Delete(link);
            }
        }
    }

    private static async Task LegacyHardlinkFailsClosedAsync()
    {
        using var fixture = Fixture.Create();
        var external = Path.Combine(fixture.Root, "hardlink-target.bin");
        File.WriteAllText(external, "hardlink");
        var linked = Path.Combine(fixture.Layout.StateRoot, "legacy-hardlink.bin");
        if (!CreateHardLink(linked, external, IntPtr.Zero))
        {
            throw new IOException("Unable to create required legacy hardlink fixture.");
        }
        using var installer = fixture.OpenTrustedInstaller();
        await ThrowsAsync<InvalidDataException>(() => fixture.Migrator()
            .MigrateIfRequiredAsync(installer, fixture.Callbacks));
        fixture.RequireLegacyActive();
        True(File.Exists(external));
    }

    private static async Task RunningLegacyProcessFailsClosedAsync()
    {
        using var fixture = Fixture.Create();
        var runningPath = Path.Combine(fixture.Layout.ManagedRoot, "legacy-running.exe");
        CopyManagedProcessFixture(runningPath);
        using var process = StartManagedProcessFixture(runningPath);
        try
        {
            using var installer = fixture.OpenTrustedInstaller();
            await ThrowsAsync<IOException>(() => fixture.Migrator()
                .MigrateIfRequiredAsync(installer, fixture.Callbacks));
            fixture.RequireLegacyActive();
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
            await process.WaitForExitAsync().ConfigureAwait(false);
        }
    }

    private static async Task IsolationCommitProcessRaceFailsClosedAsync()
    {
        using var fixture = Fixture.Create();
        var runningPath = Path.Combine(fixture.Layout.ManagedRoot, "legacy-race.exe");
        CopyManagedProcessFixture(runningPath);
        Process? process = null;
        try
        {
            using var installer = fixture.OpenTrustedInstaller();
            var migrator = new EnterpriseLegacyTestInstallationMigrator(
                fixture.Layout,
                beforeLegacyIsolationCommitForTest: _ =>
                {
                    process = StartManagedProcessFixture(runningPath);
                });
            await ThrowsAsync<IOException>(() => migrator.MigrateIfRequiredAsync(
                installer,
                fixture.Callbacks));
            fixture.RequireLegacyActive();
            True(File.Exists(fixture.JournalPath));
            True(fixture.FindLegacyQuarantines().Count == 0);
        }
        finally
        {
            if (process is not null)
            {
                try
                {
                    if (!process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                    }
                    await process.WaitForExitAsync().ConfigureAwait(false);
                }
                finally
                {
                    process.Dispose();
                }
            }
        }
    }

    private static void CopyManagedProcessFixture(string executable)
    {
        var directory = Path.GetDirectoryName(executable)
            ?? throw new InvalidOperationException(
                "Managed process fixture has no parent directory.");
        Directory.CreateDirectory(directory);
        File.Copy(GetManagedProcessFixtureAppHostPath(), executable, overwrite: true);
        foreach (var source in EnumerateManagedProcessFixtureDependencies())
        {
            File.Copy(
                source,
                Path.Combine(directory, Path.GetFileName(source)),
                overwrite: true);
        }
    }

    private static Process StartManagedProcessFixture(string executable)
    {
        var process = Process.Start(new ProcessStartInfo
        {
            FileName = EnterpriseMaintenanceIntegrity.ToExtendedWindowsPath(executable),
            WorkingDirectory = Path.GetDirectoryName(executable),
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true,
            ArgumentList = { ManagedProcessFixtureArgument },
        }) ?? throw new InvalidOperationException(
            "Unable to start managed legacy process fixture.");
        try
        {
            var readyLine = process.StandardOutput.ReadLineAsync();
            if (!readyLine.Wait(TimeSpan.FromSeconds(5)))
            {
                throw new TimeoutException(
                    "Managed legacy process fixture did not signal readiness within five seconds.");
            }
            Equal(ManagedProcessFixtureReady, readyLine.Result);
            False(process.HasExited);
            return process;
        }
        catch
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                    if (!process.WaitForExit(5_000))
                    {
                        throw new TimeoutException(
                            "Managed legacy process fixture cleanup did not finish.");
                    }
                }
            }
            finally
            {
                process.Dispose();
            }
            throw;
        }
    }

    private static string GetManagedProcessFixtureAppHostPath()
    {
        var entryAssemblyPath = Assembly.GetEntryAssembly()?.Location
            ?? throw new InvalidOperationException(
                "LegacyMigrationTests entry assembly is unavailable for the managed process fixture.");
        var appHostPath = Path.ChangeExtension(entryAssemblyPath, ".exe");
        if (!File.Exists(appHostPath))
        {
            throw new InvalidOperationException(
                "LegacyMigrationTests apphost is unavailable for the managed process fixture.");
        }
        return appHostPath;
    }

    private static IEnumerable<string> EnumerateManagedProcessFixtureDependencies()
    {
        var entryAssemblyPath = Assembly.GetEntryAssembly()?.Location
            ?? throw new InvalidOperationException(
                "LegacyMigrationTests entry assembly is unavailable for the managed process fixture.");
        var baseDirectory = Path.GetDirectoryName(entryAssemblyPath)
            ?? throw new InvalidOperationException(
                "LegacyMigrationTests output directory is unavailable for the managed process fixture.");
        var assemblyName = Path.GetFileNameWithoutExtension(entryAssemblyPath);
        return Directory.EnumerateFiles(baseDirectory, "*.dll")
            .Append(Path.Combine(baseDirectory, $"{assemblyName}.deps.json"))
            .Append(Path.Combine(baseDirectory, $"{assemblyName}.runtimeconfig.json"));
    }

    private static async Task TransientTestCleanupLockRetriesAsync()
    {
        var root = Path.Combine(TempRoot, $"cleanup-lock-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var lockedPath = Path.Combine(root, "transient-lock.exe");
        var stream = new FileStream(
            lockedPath,
            FileMode.CreateNew,
            FileAccess.ReadWrite,
            FileShare.None);
        var release = Task.Run(async () =>
        {
            await Task.Delay(250).ConfigureAwait(false);
            stream.Dispose();
        });

        try
        {
            DeleteTestDirectoryEventually(root);
            await release.ConfigureAwait(false);
            False(Directory.Exists(root));
        }
        finally
        {
            stream.Dispose();
            await release.ConfigureAwait(false);
            DeleteTestDirectoryEventually(root);
        }
    }

    private static async Task ActiveInstallJournalRecoversBeforeMigrationAsync()
    {
        using var fixture = Fixture.Create();
        await CreateActiveMigrationAtAsync(
            fixture,
            EnterpriseLegacyMigrationFaultPoint.AfterRegistrationPendingJournal)
            .ConfigureAwait(false);
        var abandoned = new EnterpriseInstallRollbackTransaction(fixture.Layout);
        abandoned.CaptureFile(fixture.Layout.BootstrapperPath);
        File.WriteAllText(fixture.Layout.BootstrapperPath, "interrupted-install-damage");

        using var installer = fixture.OpenTrustedInstaller();
        var result = await fixture.Migrator()
            .MigrateIfRequiredAsync(installer, fixture.Callbacks)
            .ConfigureAwait(false);

        Equal(
            EnterpriseLegacyMigrationDisposition.RegistrationRecovered,
            result.Disposition);
        fixture.RequireFinalizedAndRegistered();
        False(Directory.EnumerateDirectories(
                Path.GetDirectoryName(fixture.Layout.ManagedRoot)!,
                $".{Path.GetFileName(fixture.Layout.ManagedRoot)}.install-rollback-*",
                SearchOption.TopDirectoryOnly)
            .Any());
        GC.KeepAlive(abandoned);
    }

    private static async Task ActiveUninstallJournalRecoversBeforeMigrationAsync()
    {
        using var fixture = Fixture.Create();
        await CreateActiveMigrationAtAsync(
            fixture,
            EnterpriseLegacyMigrationFaultPoint.AfterRegistrationPendingJournal)
            .ConfigureAwait(false);
        var registrationContext = fixture.CreateRegistrationContext("uninstall-interleave");
        var abandoned = new EnterpriseUninstallRollbackTransaction(
            fixture.Layout,
            registrationContext);
        _ = abandoned.QuarantineManagedRoot();
        False(Directory.Exists(fixture.Layout.ManagedRoot));

        using var resumeInstaller = fixture.OpenTrustedInstaller();
        var result = await fixture.Migrator()
            .MigrateIfRequiredAsync(resumeInstaller, fixture.Callbacks)
            .ConfigureAwait(false);

        Equal(
            EnterpriseLegacyMigrationDisposition.RegistrationRecovered,
            result.Disposition);
        fixture.RequireFinalizedAndRegistered();
        False(EnterpriseUninstallRollbackTransaction.HasPendingJournal(fixture.Layout));
        GC.KeepAlive(abandoned);
    }

    private static async Task DefaultBarrierPrecedesInstallerJournalRecoveryAsync()
    {
        using (var installFixture = Fixture.Create("barrier-install-coexist"))
        {
            await CreateActiveMigrationAtAsync(
                installFixture,
                EnterpriseLegacyMigrationFaultPoint.AfterRegistrationPendingJournal)
                .ConfigureAwait(false);
            var abandonedInstall = new EnterpriseInstallRollbackTransaction(
                installFixture.Layout);
            abandonedInstall.CaptureFile(installFixture.Layout.BootstrapperPath);
            File.WriteAllText(
                installFixture.Layout.BootstrapperPath,
                "coexisting-install-journal-damage");
            var before = SnapshotMutationSurface(installFixture);
            await using (var lease = await EnterpriseManagedUpdateOperationLease
                             .AcquireRequiredAsync(installFixture.Layout)
                             .ConfigureAwait(false))
            {
                Throws<InvalidOperationException>(() =>
                    EnterpriseManagedOperationRecovery.RecoverInterruptedUnderLease(
                        installFixture.Layout));
            }
            Equal(before, SnapshotMutationSurface(installFixture));
            Equal(
                "coexisting-install-journal-damage",
                File.ReadAllText(installFixture.Layout.BootstrapperPath));
            GC.KeepAlive(abandonedInstall);
        }

        using var uninstallFixture = Fixture.Create("barrier-uninstall-coexist");
        await CreateActiveMigrationAtAsync(
            uninstallFixture,
            EnterpriseLegacyMigrationFaultPoint.AfterRegistrationPendingJournal)
            .ConfigureAwait(false);
        var abandonedUninstall = new EnterpriseUninstallRollbackTransaction(
            uninstallFixture.Layout,
            uninstallFixture.CreateRegistrationContext("coexisting-uninstall"));
        _ = abandonedUninstall.QuarantineManagedRoot();
        var uninstallBefore = SnapshotMutationSurface(uninstallFixture);
        await using (var lease = await EnterpriseManagedUpdateOperationLease
                         .AcquireRequiredAsync(uninstallFixture.Layout)
                         .ConfigureAwait(false))
        {
            Throws<InvalidOperationException>(() =>
                EnterpriseManagedOperationRecovery.RecoverInterruptedUnderLease(
                    uninstallFixture.Layout));
        }
        Equal(uninstallBefore, SnapshotMutationSurface(uninstallFixture));
        False(Directory.Exists(uninstallFixture.Layout.ManagedRoot));
        True(EnterpriseUninstallRollbackTransaction.HasPendingJournal(
            uninstallFixture.Layout));
        GC.KeepAlive(abandonedUninstall);
    }

    private static async Task AllActivePhasesBlockUnrelatedRecoveryAsync()
    {
        foreach (var point in Enum.GetValues<EnterpriseLegacyMigrationFaultPoint>())
        {
            using var fixture = Fixture.Create("barrier-" + point);
            await CreateActiveMigrationAtAsync(fixture, point).ConfigureAwait(false);
            var before = SnapshotMutationSurface(fixture);

            await using (var lease = await EnterpriseManagedUpdateOperationLease
                             .AcquireRequiredAsync(fixture.Layout)
                             .ConfigureAwait(false))
            {
                Throws<InvalidOperationException>(() =>
                    EnterpriseManagedOperationRecovery.RecoverInterruptedUnderLease(
                        fixture.Layout));
            }

            Equal(before, SnapshotMutationSurface(fixture));
            True(File.Exists(fixture.JournalPath));
        }
    }

    private static async Task ActiveMigrationBlocksUpdateAndGcAsync()
    {
        using var fixture = Fixture.Create();
        await CreateActiveMigrationAtAsync(
            fixture,
            EnterpriseLegacyMigrationFaultPoint.AfterRegistrationPendingJournal)
            .ConfigureAwait(false);
        var before = SnapshotMutationSurface(fixture);
        var (policy, compiledTrust) = CreateReleaseTrust();
        using var handler = new RejectingHttpHandler();
        using var client = new HttpClient(handler);
        var manifestUri = new Uri("https://updates.example/release-set.v2.json");

        await ThrowsAsync<InvalidOperationException>(() =>
            new EnterpriseReleaseSetUpdateService(
                    fixture.Layout,
                    policy,
                    client)
                .CheckAndStageAsync(manifestUri));
        await ThrowsAsync<InvalidOperationException>(() =>
            new EnterpriseManagedArtifactGarbageCollector(
                    fixture.Layout,
                    compiledTrust)
                .CollectAsync());

        Equal(0, handler.RequestCount);
        Equal(before, SnapshotMutationSurface(fixture));
    }

    private static async Task ActiveMigrationBlocksHealthAndRollbackAsync()
    {
        using var fixture = Fixture.Create();
        await CreateActiveMigrationAtAsync(
            fixture,
            EnterpriseLegacyMigrationFaultPoint.AfterRegistrationPendingJournal)
            .ConfigureAwait(false);
        var before = SnapshotMutationSurface(fixture);
        var probeCalled = false;

        await ThrowsAsync<InvalidOperationException>(() =>
            new EnterpriseBootstrapHealthGate(fixture.Layout, TimeSpan.FromSeconds(1))
                .EnsureHealthyAsync((_, _, _, _) =>
                {
                    probeCalled = true;
                    return Task.FromResult(0);
                }));
        await using (var lease = await EnterpriseManagedUpdateOperationLease
                         .AcquireRequiredAsync(fixture.Layout)
                         .ConfigureAwait(false))
        {
            Throws<InvalidOperationException>(() =>
            {
                EnterpriseManagedOperationRecovery.RecoverInterruptedUnderLease(
                    fixture.Layout);
                _ = new EnterpriseReleaseSetPointerStore(fixture.Layout)
                    .RollbackPending("test operator rollback");
            });
        }

        False(probeCalled);
        Equal(before, SnapshotMutationSurface(fixture));
    }

    private static async Task ActiveMigrationBlocksMaintenanceAndUninstallAsync()
    {
        using var fixture = Fixture.Create();
        await CreateActiveMigrationAtAsync(
            fixture,
            EnterpriseLegacyMigrationFaultPoint.AfterRegistrationPendingJournal)
            .ConfigureAwait(false);
        var before = SnapshotMutationSurface(fixture);
        var context = fixture.CreateRegistrationContext("barrier-maintenance");
        var operations = new EnterpriseMaintenanceOperations(
            fixture.Layout,
            context);

        Throws<InvalidOperationException>(() =>
            operations.RepairShell(Path.Combine(
                fixture.Layout.GetLauncherVersionDirectory("launcher-current"),
                EnterpriseInstallationLayout.MaintenanceExecutableName)));
        Throws<InvalidOperationException>(() =>
            new EnterpriseInstallationService(fixture.Layout)
                .UninstallManagedProgramFiles(context));

        Equal(before, SnapshotMutationSurface(fixture));
        True(Directory.Exists(fixture.Layout.ManagedRoot));
    }

    private static async Task ExternalInstallerResumesThenUninstallsAsync()
    {
        using var fixture = Fixture.Create();
        await CreateActiveMigrationAtAsync(
            fixture,
            EnterpriseLegacyMigrationFaultPoint.AfterRegistrationPendingJournal)
            .ConfigureAwait(false);
        var context = fixture.CreateRegistrationContext("trusted-external-uninstall");
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        var result = await EnterpriseLegacyMigrationInstallerFacade
            .UninstallDevelopmentPayloadAfterRecoveringLegacyMigrationForTestAsync(
                fixture.Layout,
                fixture.PayloadRoot,
                fixture.ExternalInstallerPath,
                context,
                cancellationToken: cancellation.Token)
            .ConfigureAwait(false);

        True(result.ActiveInstallationRemoved);
        False(Directory.Exists(fixture.Layout.ManagedRoot));
        False(File.Exists(fixture.JournalPath));
        fixture.RequireUserDataUnchanged();
        using var verifyInstaller = fixture.OpenTrustedInstaller();
        var classification = await fixture.Migrator()
            .MigrateIfRequiredAsync(verifyInstaller, fixture.Callbacks)
            .ConfigureAwait(false);
        Equal(
            EnterpriseLegacyMigrationDisposition.FreshInstallRequired,
            classification.Disposition);
    }

    private static async Task WrongExternalInstallerCannotUninstallAsync()
    {
        using var fixture = Fixture.Create();
        await CreateActiveMigrationAtAsync(
            fixture,
            EnterpriseLegacyMigrationFaultPoint.AfterRegistrationPendingJournal)
            .ConfigureAwait(false);
        var wrongInstaller = Path.Combine(fixture.Root, "external", "wrong-installer.exe");
        File.WriteAllText(wrongInstaller, "different-signed-installer-test-bytes");
        var before = SnapshotMutationSurface(fixture);
        var context = fixture.CreateRegistrationContext("wrong-external-uninstall");

        await ThrowsAsync<InvalidDataException>(() =>
            EnterpriseLegacyMigrationInstallerFacade
                .UninstallDevelopmentPayloadAfterRecoveringLegacyMigrationForTestAsync(
                    fixture.Layout,
                    fixture.PayloadRoot,
                    wrongInstaller,
                    context));

        Equal(before, SnapshotMutationSurface(fixture));
        True(File.Exists(fixture.JournalPath));
        True(Directory.Exists(fixture.Layout.ManagedRoot));
    }

    private static Task ExternalInstallerIdentityIsLockedAsync()
    {
        using var fixture = Fixture.Create();
        using var installer = fixture.OpenTrustedInstaller();
        Throws<IOException>(() =>
            File.Open(
                fixture.ExternalInstallerPath,
                FileMode.Open,
                FileAccess.Write,
                FileShare.Read).Dispose());
        installer.RequireIdentityUnchanged();
        return Task.CompletedTask;
    }

    private static async Task ExternalOperationLeaseSerializesAsync()
    {
        using var fixture = Fixture.Create();
        using var held = EnterpriseManagedUpdateOperationLease.TryAcquire(fixture.Layout)
            ?? throw new InvalidOperationException("Unable to acquire operation lease fixture.");
        using var installer = fixture.OpenTrustedInstaller();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
        await ThrowsAsync<OperationCanceledException>(() => fixture.Migrator()
            .MigrateIfRequiredAsync(
                installer,
                fixture.Callbacks,
                cancellation.Token));
        fixture.RequireLegacyActive();
        fixture.RequireUserDataUnchanged();
    }

    private static async Task CompletedTombstoneIsInstallerIndependentAsync()
    {
        using var fixture = Fixture.Create();
        using (var installer = fixture.OpenTrustedInstaller())
        {
            _ = await fixture.Migrator()
                .MigrateIfRequiredAsync(installer, fixture.Callbacks)
                .ConfigureAwait(false);
        }
        File.WriteAllText(
            fixture.ExternalInstallerPath,
            "newer-current-authenticode-installer-test-bytes");
        using var newerInstaller = fixture.OpenTrustedInstaller();
        var result = await fixture.Migrator()
            .MigrateIfRequiredAsync(newerInstaller, fixture.Callbacks)
            .ConfigureAwait(false);
        Equal(
            EnterpriseLegacyMigrationDisposition.CurrentInstallationAlreadyTrusted,
            result.Disposition);
        fixture.RequireFinalizedAndRegistered();
        True(File.Exists(fixture.TombstonePath));
        False(File.Exists(fixture.JournalPath));
    }

    private static async Task LostTombstoneReconcilesAsync()
    {
        using var fixture = Fixture.Create();
        using (var installer = fixture.OpenTrustedInstaller())
        {
            _ = await fixture.Migrator()
                .MigrateIfRequiredAsync(installer, fixture.Callbacks)
                .ConfigureAwait(false);
        }
        True(File.Exists(fixture.WitnessPath));
        File.Delete(fixture.TombstonePath);

        using var retryInstaller = fixture.OpenTrustedInstaller();
        var result = await fixture.Migrator()
            .MigrateIfRequiredAsync(retryInstaller, fixture.Callbacks)
            .ConfigureAwait(false);
        Equal(
            EnterpriseLegacyMigrationDisposition.CurrentInstallationAlreadyTrusted,
            result.Disposition);
        True(File.Exists(fixture.TombstonePath));
        True(File.Exists(fixture.WitnessPath));
        fixture.RequireFinalizedAndRegistered();
    }

    private static async Task UninstallThenFreshReinstallAsync()
    {
        using var fixture = Fixture.Create();
        using (var installer = fixture.OpenTrustedInstaller())
        {
            _ = await fixture.Migrator()
                .MigrateIfRequiredAsync(installer, fixture.Callbacks)
                .ConfigureAwait(false);
        }
        Directory.Delete(fixture.Layout.ManagedRoot, recursive: true);
        using (var afterUninstallInstaller = fixture.OpenTrustedInstaller())
        {
            var fresh = await fixture.Migrator()
                .MigrateIfRequiredAsync(afterUninstallInstaller, fixture.Callbacks)
                .ConfigureAwait(false);
            Equal(
                EnterpriseLegacyMigrationDisposition.FreshInstallRequired,
                fresh.Disposition);
        }

        await fixture.InstallFreshCurrentAsync().ConfigureAwait(false);
        using var afterReinstallInstaller = fixture.OpenTrustedInstaller();
        var current = await fixture.Migrator()
            .MigrateIfRequiredAsync(afterReinstallInstaller, fixture.Callbacks)
            .ConfigureAwait(false);
        Equal(
            EnterpriseLegacyMigrationDisposition.CurrentInstallationAlreadyTrusted,
            current.Disposition);
        fixture.RequireFinalized();
        fixture.RequireUserDataUnchanged();
    }

    private static async Task PointerOnlyDamagedCurrentFailsClosedAsync()
    {
        using var fixture = Fixture.Create(seedLegacy: false);
        await fixture.InstallFreshCurrentAsync().ConfigureAwait(false);
        File.Delete(fixture.Layout.InstalledInstallerPath);
        using var installer = fixture.OpenTrustedInstaller();
        await ThrowsAsync<IOException>(() => fixture.Migrator()
            .MigrateIfRequiredAsync(installer, fixture.Callbacks));
        fixture.RequireUserDataUnchanged();
    }

    private static async Task CrossComponentReceiptFailsClosedAsync()
    {
        using var fixture = Fixture.Create();
        fixture.StageCrossComponentReceipt = true;
        using var installer = fixture.OpenTrustedInstaller();
        await ThrowsAsync<InvalidDataException>(() => fixture.Migrator()
            .MigrateIfRequiredAsync(installer, fixture.Callbacks));
        fixture.RequireLegacyActive();
        True(fixture.FindLegacyQuarantines().Count == 0);
    }

    private static async Task InstallerReceiptTupleDriftFailsClosedAsync()
    {
        using var fixture = Fixture.Create(seedLegacy: false);
        await fixture.InstallFreshCurrentAsync().ConfigureAwait(false);
        EnterprisePathGuard.WriteFileAtomically(
            Path.Combine(fixture.Layout.StateRoot, "installation-receipt.json"),
            JsonSerializer.SerializeToUtf8Bytes(
                new EnterpriseInstallationReceipt(
                    1,
                    fixture.Layout.LayoutProfile,
                    "launcher-wrong",
                    "runtime-wrong",
                    DevelopmentUnsignedPayload: true,
                    DateTimeOffset.UtcNow),
                EnterpriseInstallJson.Options),
            fixture.Layout.ManagedRoot);
        using var installer = fixture.OpenTrustedInstaller();
        await ThrowsAsync<InvalidDataException>(() => fixture.Migrator()
            .MigrateIfRequiredAsync(installer, fixture.Callbacks));
        fixture.RequireUserDataUnchanged();
    }

    private static async Task JournalUsesInjectedClockAsync()
    {
        using var fixture = Fixture.Create();
        var clock = new FixedUtcTimeProvider(
            new DateTimeOffset(2200, 1, 2, 3, 4, 5, TimeSpan.Zero));
        using (var installer = fixture.OpenTrustedInstaller())
        {
            await ThrowsAsync<EnterpriseLegacyMigrationInjectedCrashException>(() =>
                fixture.Migrator(
                        observed =>
                        {
                            if (observed == EnterpriseLegacyMigrationFaultPoint
                                .AfterOldIsolatedJournal)
                            {
                                throw new EnterpriseLegacyMigrationInjectedCrashException(
                                    observed);
                            }
                        },
                        clock)
                    .MigrateIfRequiredAsync(installer, fixture.Callbacks));
        }
        using var retryInstaller = fixture.OpenTrustedInstaller();
        _ = await fixture.Migrator(timeProvider: clock)
            .MigrateIfRequiredAsync(retryInstaller, fixture.Callbacks)
            .ConfigureAwait(false);
        fixture.RequireFinalizedAndRegistered();
    }

    private static async Task BackwardsUtcCrashRetryIsMonotonicAsync()
    {
        using var fixture = Fixture.Create();
        var createdAt = new DateTimeOffset(2200, 1, 2, 3, 4, 5, TimeSpan.Zero);
        var clock = new SequenceUtcTimeProvider(
            createdAt,
            createdAt.AddDays(-1),
            createdAt.AddDays(-2),
            createdAt.AddDays(-3),
            createdAt.AddDays(-4),
            createdAt.AddDays(-5),
            createdAt.AddDays(-6));
        using (var installer = fixture.OpenTrustedInstaller())
        {
            await ThrowsAsync<EnterpriseLegacyMigrationInjectedCrashException>(() =>
                fixture.Migrator(
                        observed =>
                        {
                            if (observed == EnterpriseLegacyMigrationFaultPoint
                                .AfterCandidateStagedBeforeJournal)
                            {
                                throw new EnterpriseLegacyMigrationInjectedCrashException(
                                    observed);
                            }
                        },
                        clock)
                    .MigrateIfRequiredAsync(installer, fixture.Callbacks));
        }
        Equal(0, fixture.FindAbandonedCandidates().Count);

        using (var retryInstaller = fixture.OpenTrustedInstaller())
        {
            var result = await fixture.Migrator(timeProvider: clock)
                .MigrateIfRequiredAsync(retryInstaller, fixture.Callbacks)
                .ConfigureAwait(false);
            Equal(EnterpriseLegacyMigrationDisposition.Migrated, result.Disposition);
        }
        fixture.RequireFinalizedAndRegistered();
        Equal(1, fixture.FindAbandonedCandidates().Count);
        var tombstone = new EnterpriseLegacyMigrationJournalStore(fixture.Layout)
            .TryReadTombstone()
            ?? throw new InvalidOperationException("Expected migration tombstone.");
        Equal(createdAt, tombstone.CompletedAtUtc);

        using var completedInstaller = fixture.OpenTrustedInstaller();
        var completed = await fixture.Migrator(timeProvider: clock)
            .MigrateIfRequiredAsync(completedInstaller, fixture.Callbacks)
            .ConfigureAwait(false);
        Equal(
            EnterpriseLegacyMigrationDisposition.CurrentInstallationAlreadyTrusted,
            completed.Disposition);
        Equal(1, fixture.FindAbandonedCandidates().Count);
    }

    private static async Task ProductionFacadeCandidatePipelineAsync()
    {
        using var fixture = Fixture.Create();
        var registration = fixture.CreateRegistrationContext("migration");
        try
        {
            var result = await EnterpriseLegacyMigrationInstallerFacade
                .InstallOrRepairDevelopmentPayloadAndRegisterForTestAsync(
                    fixture.Layout,
                    fixture.PayloadRoot,
                    fixture.ExternalInstallerPath,
                    registration)
                .ConfigureAwait(false);
            Equal("launcher-current", result.LauncherReleaseId);
            Equal("runtime-current", result.RuntimeReleaseId);
            fixture.RequireFinalized();
            _ = EnterpriseWindowsRegistration.ReadAndValidate(
                fixture.Layout,
                result.LauncherReleaseId,
                developmentUnsignedPayload: true,
                registration);
            fixture.RequireUserDataUnchanged();
            True(fixture.FindLegacyQuarantines().Count == 1);
            False(File.Exists(fixture.OldExecutionMarker));
        }
        finally
        {
            EnterpriseWindowsRegistration.Remove(fixture.Layout, registration);
        }
    }

    private static async Task StableShellRepairPreservesCurrentTupleAsync()
    {
        using var fixture = Fixture.Create(seedLegacy: false);
        await fixture.InstallFreshCurrentAsync().ConfigureAwait(false);
        var releaseSetBefore = File.ReadAllBytes(fixture.Layout.ReleaseSetPointerPath);
        var launcherPointerBefore = File.ReadAllBytes(fixture.Layout.LauncherPointerPath);
        var runtimePointerBefore = File.ReadAllBytes(fixture.Layout.RuntimePointerPath);
        var installationReceiptBefore = File.ReadAllBytes(Path.Combine(
            fixture.Layout.StateRoot,
            "installation-receipt.json"));
        var alternatePayload = fixture.CreateAlternatePayload(
            "launcher-new-installer",
            "runtime-new-installer",
            "new-stable-bootstrapper");
        File.WriteAllText(
            fixture.ExternalInstallerPath,
            "new-external-installer-bytes");
        var registration = fixture.CreateRegistrationContext("stable-shell");
        try
        {
            var result = await EnterpriseLegacyMigrationInstallerFacade
                .InstallOrRepairDevelopmentPayloadAndRegisterForTestAsync(
                    fixture.Layout,
                    alternatePayload,
                    fixture.ExternalInstallerPath,
                    registration)
                .ConfigureAwait(false);
            Equal("launcher-current", result.LauncherReleaseId);
            Equal("runtime-current", result.RuntimeReleaseId);
            True(releaseSetBefore.SequenceEqual(
                File.ReadAllBytes(fixture.Layout.ReleaseSetPointerPath)));
            True(launcherPointerBefore.SequenceEqual(
                File.ReadAllBytes(fixture.Layout.LauncherPointerPath)));
            True(runtimePointerBefore.SequenceEqual(
                File.ReadAllBytes(fixture.Layout.RuntimePointerPath)));
            True(installationReceiptBefore.SequenceEqual(File.ReadAllBytes(Path.Combine(
                fixture.Layout.StateRoot,
                "installation-receipt.json"))));
            var alternateManifest = EnterpriseInstallManifest.Parse(File.ReadAllBytes(
                Path.Combine(
                    alternatePayload,
                    EnterpriseEmbeddedPayloadSource.ManifestFileName)));
            Equal(
                alternateManifest.BootstrapperSha256,
                HashFile(fixture.Layout.BootstrapperPath));
            Equal(
                HashFile(fixture.ExternalInstallerPath),
                HashFile(fixture.Layout.InstalledInstallerPath));
            _ = EnterpriseWindowsRegistration.ReadAndValidate(
                fixture.Layout,
                "launcher-current",
                developmentUnsignedPayload: true,
                registration);
            fixture.RequireUserDataUnchanged();
        }
        finally
        {
            EnterpriseWindowsRegistration.Remove(fixture.Layout, registration);
        }
    }

    private static async Task ExternalFacadeFreshInstallAsync()
    {
        using var fixture = Fixture.Create(seedLegacy: false);
        var registration = fixture.CreateRegistrationContext("fresh");
        try
        {
            var result = await EnterpriseLegacyMigrationInstallerFacade
                .InstallOrRepairDevelopmentPayloadAndRegisterForTestAsync(
                    fixture.Layout,
                    fixture.PayloadRoot,
                    fixture.ExternalInstallerPath,
                    registration)
                .ConfigureAwait(false);
            Equal("launcher-current", result.LauncherReleaseId);
            Equal("runtime-current", result.RuntimeReleaseId);
            fixture.RequireFinalized();
            _ = EnterpriseWindowsRegistration.ReadAndValidate(
                fixture.Layout,
                result.LauncherReleaseId,
                developmentUnsignedPayload: true,
                registration);
            fixture.RequireUserDataUnchanged();
            True(fixture.FindLegacyQuarantines().Count == 0);
        }
        finally
        {
            EnterpriseWindowsRegistration.Remove(fixture.Layout, registration);
        }
    }

    private static async Task CurrentExactRepairRestoresRegistrationAsync()
    {
        using var fixture = Fixture.Create(seedLegacy: false);
        await fixture.InstallFreshCurrentAsync().ConfigureAwait(false);
        var registration = fixture.CreateRegistrationContext("exact-repair");
        File.WriteAllText(
            fixture.ExternalInstallerPath,
            "refreshed-exact-installer-bytes");
        try
        {
            var result = await EnterpriseLegacyMigrationInstallerFacade
                .InstallOrRepairDevelopmentPayloadAndRegisterForTestAsync(
                    fixture.Layout,
                    fixture.PayloadRoot,
                    fixture.ExternalInstallerPath,
                    registration)
                .ConfigureAwait(false);
            Equal("launcher-current", result.LauncherReleaseId);
            Equal("runtime-current", result.RuntimeReleaseId);
            Equal(
                HashFile(fixture.ExternalInstallerPath),
                HashFile(fixture.Layout.InstalledInstallerPath));
            _ = EnterpriseWindowsRegistration.ReadAndValidate(
                fixture.Layout,
                result.LauncherReleaseId,
                developmentUnsignedPayload: true,
                registration);
            fixture.RequireFinalized();
            fixture.RequireUserDataUnchanged();
        }
        finally
        {
            EnterpriseWindowsRegistration.Remove(fixture.Layout, registration);
        }
    }

    private static async Task StableShellFailureRollsBackAsync()
    {
        using var fixture = Fixture.Create(seedLegacy: false);
        await fixture.InstallFreshCurrentAsync().ConfigureAwait(false);
        var bootstrapperBefore = File.ReadAllBytes(fixture.Layout.BootstrapperPath);
        var bootstrapperReceiptBefore = File.ReadAllBytes(
            fixture.Layout.BootstrapperReceiptPath);
        var installerBefore = File.ReadAllBytes(fixture.Layout.InstalledInstallerPath);
        var releaseSetBefore = File.ReadAllBytes(fixture.Layout.ReleaseSetPointerPath);
        var alternatePayload = fixture.CreateAlternatePayload(
            "launcher-rollback-new",
            "runtime-rollback-new",
            "rollback-new-stub");
        File.WriteAllText(
            fixture.ExternalInstallerPath,
            "rollback-new-installer");
        var baseContext = fixture.CreateRegistrationContext("stable-rollback");
        var registration = baseContext with
        {
            InstallObserver = stage =>
            {
                if (stage == EnterpriseWindowsRegistrationInstallStage
                    .DesktopShortcutInstalled)
                {
                    throw new IOException("Injected stable-shell registration crash.");
                }
            },
        };
        try
        {
            await ThrowsAsync<IOException>(() =>
                EnterpriseLegacyMigrationInstallerFacade
                    .InstallOrRepairDevelopmentPayloadAndRegisterForTestAsync(
                        fixture.Layout,
                        alternatePayload,
                        fixture.ExternalInstallerPath,
                        registration));
            True(bootstrapperBefore.SequenceEqual(
                File.ReadAllBytes(fixture.Layout.BootstrapperPath)));
            True(bootstrapperReceiptBefore.SequenceEqual(
                File.ReadAllBytes(fixture.Layout.BootstrapperReceiptPath)));
            True(installerBefore.SequenceEqual(
                File.ReadAllBytes(fixture.Layout.InstalledInstallerPath)));
            True(releaseSetBefore.SequenceEqual(
                File.ReadAllBytes(fixture.Layout.ReleaseSetPointerPath)));
            False(File.Exists(baseContext.DesktopShortcutPath));
            False(File.Exists(baseContext.StartMenuShortcutPath));
            fixture.RequireFinalized();
            fixture.RequireUserDataUnchanged();
        }
        finally
        {
            EnterpriseWindowsRegistration.Remove(fixture.Layout, baseContext);
        }
    }

    private static async Task StableShellSqliteRollbackFailureIsPathFreeAsync()
    {
        using var fixture = Fixture.Create(seedLegacy: false);
        await fixture.InstallFreshCurrentAsync().ConfigureAwait(false);
        var alternatePayload = fixture.CreateAlternatePayload(
            "launcher-sqlite-rollback",
            "runtime-sqlite-rollback",
            "sqlite-rollback-stub");
        File.WriteAllText(
            fixture.ExternalInstallerPath,
            "sqlite-rollback-installer");
        var registration = fixture.CreateRegistrationContext(
            "sqlite-rollback-redaction");
        var lateLegacy = Path.Combine(
            fixture.Layout.HarnessHome,
            "late.sqlite");
        FileStream? rollbackBlocker = null;
        try
        {
            InvalidOperationException? rollbackFailure = null;
            try
            {
                await new EnterpriseInstallationService(
                        fixture.Layout,
                        () =>
                        {
                            File.WriteAllBytes(
                                lateLegacy,
                                "late-legacy-sqlite"u8.ToArray());
                            rollbackBlocker = new FileStream(
                                fixture.Layout.InstalledInstallerPath,
                                FileMode.Open,
                                FileAccess.Read,
                                FileShare.None);
                        })
                    .RepairDevelopmentStableShellAndRegisterAsync(
                        alternatePayload,
                        fixture.ExternalInstallerPath,
                        "launcher-current",
                        registration)
                    .ConfigureAwait(false);
            }
            catch (InvalidOperationException exception)
            {
                rollbackFailure = exception;
            }

            if (rollbackFailure is null)
            {
                throw new InvalidOperationException(
                    "Expected the stable-shell SQLite rollback boundary to fail.");
            }
            Equal(
                EnterpriseLegacySqliteUpgradeGuard.RepairRollbackFailureMessage,
                rollbackFailure.Message);
            True(rollbackFailure.InnerException is null);
            False(rollbackFailure.Message.Contains(
                fixture.Root,
                StringComparison.OrdinalIgnoreCase));
            False(rollbackFailure.Message.Contains(
                fixture.Layout.InstalledInstallerPath,
                StringComparison.OrdinalIgnoreCase));
            True(File.Exists(lateLegacy));
        }
        finally
        {
            rollbackBlocker?.Dispose();
            EnterpriseWindowsRegistration.Remove(fixture.Layout, registration);
        }
    }

    private static Task ProductionSelfCheckInvokesMigrationLeaseAsync()
    {
        var repositoryRoot = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..", ".."));
        var programPath = Path.Combine(
            repositoryRoot,
            "src",
            "Ensou.Dsh.Enterprise.Installer",
            "Program.cs");
        var source = File.ReadAllText(programPath);
        True(source.Contains(
            "RequireEmbeddedProductionMigrationPayload(",
            StringComparison.Ordinal));
        True(source.Contains(
            "--production-payload-self-check",
            StringComparison.Ordinal));
        True(source.Contains(
            "UninstallAfterRecoveringLegacyMigrationAsync(",
            StringComparison.Ordinal));
        return Task.CompletedTask;
    }

    private static async Task InstallerMachineSelfCheckFailuresAreBoundedAsync()
    {
        var repositoryRoot = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..", ".."));
        var installer = Path.Combine(
            repositoryRoot,
            "src",
            "Ensou.Dsh.Enterprise.Installer",
            "bin",
            "Release",
            "net10.0-windows",
            "win-x64",
            "Ensou.Dsh.Enterprise.Installer.exe");
        True(File.Exists(installer));
        var zeroHash = new string('0', 64);
        var probes = new (string Stage, string[] Arguments)[]
        {
            ("brand", ["--brand-self-check", zeroHash]),
            ("brand-missing-argument", ["--brand-self-check"]),
            ("brand-extra-argument", ["--brand-self-check", zeroHash, "unexpected"]),
            ("binary", ["--binary-self-check"]),
            ("binary-extra-argument", ["--binary-self-check", "unexpected"]),
            (
                "production-payload",
                [
                    "--production-payload-self-check",
                    "launcher-current",
                    "runtime-current",
                    zeroHash,
                    zeroHash,
                    zeroHash,
                ]),
            (
                "production-payload-missing-argument",
                [
                    "--production-payload-self-check",
                    "launcher-current",
                    "runtime-current",
                    zeroHash,
                    zeroHash,
                ]),
            (
                "production-payload-extra-argument",
                [
                    "--production-payload-self-check",
                    "launcher-current",
                    "runtime-current",
                    zeroHash,
                    zeroHash,
                    zeroHash,
                    "unexpected",
                ]),
        };
        const string expectedFailure =
            "Ensou DSH Enterprise Installer machine command failed.";

        foreach (var probe in probes)
        {
            var start = new ProcessStartInfo
            {
                FileName = installer,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            foreach (var argument in probe.Arguments)
            {
                start.ArgumentList.Add(argument);
            }

            using var process = Process.Start(start)
                ?? throw new InvalidOperationException(
                    $"Unable to start unsigned Enterprise Installer {probe.Stage} fixture.");
            var standardOutput = process.StandardOutput.ReadToEndAsync();
            var standardError = process.StandardError.ReadToEndAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            try
            {
                await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                }
                await process.WaitForExitAsync().ConfigureAwait(false);
                throw new TimeoutException(
                    $"Enterprise Installer {probe.Stage} fixture did not exit within 30 seconds.");
            }

            var output = await standardOutput.ConfigureAwait(false);
            var error = await standardError.ConfigureAwait(false);
            if (process.ExitCode != 1
                || output.Length != 0
                || !string.Equals(
                    error.TrimEnd('\r', '\n'),
                    expectedFailure,
                    StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Enterprise Installer {probe.Stage} failure escaped its noninteractive boundary. "
                    + $"Exit={process.ExitCode}; stdout='{output}'; stderr='{error}'.");
            }
        }
    }

    private static Task InstallerApplicationInitializationFailureUsesMachineBoundaryAsync()
    {
        var repositoryRoot = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..", ".."));
        var installerAssemblyPath = Path.Combine(
            repositoryRoot,
            "src",
            "Ensou.Dsh.Enterprise.Installer",
            "bin",
            "Release",
            "net10.0-windows",
            "win-x64",
            "Ensou.Dsh.Enterprise.Installer.dll");
        True(File.Exists(installerAssemblyPath));
        var installerAssembly = Assembly.LoadFrom(installerAssemblyPath);
        var installerProgram = installerAssembly.GetType(
            "Ensou.Dsh.Enterprise.Installer.Program",
            throwOnError: true)!;
        var boundary = installerProgram.GetMethod(
            "RunWithApplicationInitializer",
            BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException(
                "Unable to locate the Enterprise Installer application initialization boundary.");
        True(boundary.IsPrivate);
        Equal("Main", installerAssembly.EntryPoint?.Name);

        const string expectedFailure =
            "Ensou DSH Enterprise Installer machine command failed.";
        var originalError = Console.Error;
        using var capturedError = new StringWriter();
        object? exitCode;
        try
        {
            Console.SetError(capturedError);
            exitCode = boundary.Invoke(
                null,
                [
                    new[] { "--binary-self-check" },
                    new Action(() => throw new InvalidOperationException(
                        "Injected application initialization failure.")),
                ]);
        }
        finally
        {
            Console.SetError(originalError);
        }

        Equal(1, (int)exitCode!);
        Equal(
            expectedFailure,
            capturedError.ToString().TrimEnd('\r', '\n'));
        return Task.CompletedTask;
    }

    private static async Task CreateActiveMigrationAtAsync(
        Fixture fixture,
        EnterpriseLegacyMigrationFaultPoint faultPoint)
    {
        using var installer = fixture.OpenTrustedInstaller();
        await ThrowsAsync<EnterpriseLegacyMigrationInjectedCrashException>(() =>
            fixture.Migrator(observed =>
                {
                    if (observed == faultPoint)
                    {
                        throw new EnterpriseLegacyMigrationInjectedCrashException(
                            faultPoint);
                    }
                })
                .MigrateIfRequiredAsync(installer, fixture.Callbacks));
        True(File.Exists(fixture.JournalPath));
    }

    private static string SnapshotMutationSurface(Fixture fixture)
    {
        var root = Path.GetFullPath(fixture.Root);
        var records = new List<string>();
        foreach (var directory in Directory.EnumerateDirectories(
                     root,
                     "*",
                     SearchOption.AllDirectories))
        {
            records.Add("d:" + Path.GetRelativePath(root, directory).Replace('\\', '/'));
        }
        foreach (var file in Directory.EnumerateFiles(
                     root,
                     "*",
                     SearchOption.AllDirectories))
        {
            records.Add(
                "f:"
                + Path.GetRelativePath(root, file).Replace('\\', '/')
                + ":"
                + new FileInfo(file).Length
                + ":"
                + HashFile(file));
        }
        records.Sort(StringComparer.Ordinal);
        return string.Join('\n', records);
    }

    private static (EnterpriseReleaseTrustPolicy Policy,
        EnterpriseCompiledReleaseTrust CompiledTrust) CreateReleaseTrust()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = signer.ExportParameters(includePrivateParameters: false);
        var policy = new EnterpriseReleaseTrustPolicy
        {
            Product = EnterpriseReleaseSetContract.Product,
            Environment = EnterpriseReleaseSetContract.DevelopmentE2EEnvironment,
            ExpectedChannel = EnterpriseReleaseSetContract.LabChannel,
            CurrentStartupStubProtocol =
                EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
            ManifestOrigin = new Uri("https://updates.example/"),
            ArtifactOrigin = new Uri("https://artifacts.example/"),
            TrustedKeys =
            [
                new EnterpriseReleasePublicKey(
                    "legacy-barrier-test-key",
                    Base64Url(parameters.Q.X!),
                    Base64Url(parameters.Q.Y!)),
            ],
        };
        var manifestUri = new Uri("https://updates.example/release-set.v2.json");
        return (policy, new EnterpriseCompiledReleaseTrust(manifestUri, policy));
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private sealed class RejectingHttpHandler : HttpMessageHandler
    {
        public int RequestCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestCount++;
            throw new InvalidOperationException(
                "Network must not be reached while a legacy migration is active.");
        }
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _userDataSnapshot;
        private bool _disposed;

        private Fixture(
            string root,
            EnterpriseInstallationLayout layout,
            string payloadRoot,
            string externalInstallerPath)
        {
            Root = root;
            Layout = layout;
            PayloadRoot = payloadRoot;
            ExternalInstallerPath = externalInstallerPath;
            MigrationRoot = EnterpriseLegacyMigrationJournalStore.GetMigrationRoot(layout);
            JournalPath = Path.Combine(
                MigrationRoot,
                "legacy-schema2-program-migration.v1.dpapi");
            TombstonePath = Path.Combine(
                MigrationRoot,
                "legacy-schema2-migrated.v1.dpapi");
            WitnessPath = Path.Combine(
                layout.ReleaseSecurityWitnessRoot,
                "legacy-schema2-migrated.v1.witness.dpapi");
            RegistrationPath = Path.Combine(root, "shell", "enterprise-registration.json");
            OldExecutionMarker = Path.Combine(root, "old-managed-binary-executed.txt");
            _userDataSnapshot = SnapshotUserData(layout);
            Callbacks = new EnterpriseLegacyMigrationCallbacks(
                StageCandidateAsync,
                FinalizeAsync,
                ValidateFinalized,
                RegisterAsync,
                ValidateRegistration);
        }

        public string Root { get; }

        public EnterpriseInstallationLayout Layout { get; }

        public string PayloadRoot { get; }

        public string ExternalInstallerPath { get; }

        public string MigrationRoot { get; }

        public string JournalPath { get; }

        public string TombstonePath { get; }

        public string WitnessPath { get; }

        public string RegistrationPath { get; }

        public string OldExecutionMarker { get; }

        public bool FailRegistrationOnce { get; set; }

        public bool StageWrongSelfConsistentCandidate { get; set; }

        public bool StageCrossComponentReceipt { get; set; }

        public EnterpriseLegacyMigrationCallbacks Callbacks { get; }

        public static Fixture Create(string? scope = null, bool seedLegacy = true)
        {
            scope ??= Guid.NewGuid().ToString("N")[..12];
            var root = Path.Combine(TempRoot, scope + "-" + Guid.NewGuid().ToString("N")[..8]);
            var local = Path.Combine(root, "local");
            var profile = Path.Combine(root, "profile");
            Directory.CreateDirectory(local);
            Directory.CreateDirectory(profile);
            var layout = EnterpriseInstallationLayout.CreateDevelopmentE2E(local, profile);
            if (seedLegacy)
            {
                SeedLegacy(layout, root);
            }
            SeedUserData(layout);
            var payload = CreatePayload(root);
            var externalInstaller = Path.Combine(root, "external", "EnterpriseInstaller.exe");
            Directory.CreateDirectory(Path.GetDirectoryName(externalInstaller)!);
            File.WriteAllText(externalInstaller, "current-authenticode-installer-test-bytes");
            return new Fixture(root, layout, payload, externalInstaller);
        }

        public EnterpriseLegacyMigrationTrustedInstallerLease OpenTrustedInstaller()
        {
            var source = EnterpriseDirectoryPayloadSource.OpenExplicitDevelopmentPayload(
                PayloadRoot);
            return EnterpriseLegacyMigrationTrustedInstallerLease.OpenForTest(
                Layout,
                ExternalInstallerPath,
                source);
        }

        public EnterpriseLegacyTestInstallationMigrator Migrator(
            Action<EnterpriseLegacyMigrationFaultPoint>? observer = null,
            TimeProvider? timeProvider = null) =>
            new(Layout, timeProvider, observer);

        public EnterpriseWindowsRegistrationContext CreateRegistrationContext(
            string scope)
        {
            var suffix = Guid.NewGuid().ToString("N");
            return new EnterpriseWindowsRegistrationContext(
                $"Software\\Ensou\\Dsh\\LegacyMigrationTests\\{suffix}",
                Path.Combine(Root, "shell", scope, "desktop.lnk"),
                Path.Combine(Root, "shell", scope, "start-menu.lnk"));
        }

        public string CreateAlternatePayload(
            string launcherReleaseId,
            string runtimeReleaseId,
            string bootstrapperContents) => CreatePayload(
            Root,
            "payload-alternate-" + Guid.NewGuid().ToString("N"),
            launcherReleaseId,
            runtimeReleaseId,
            bootstrapperContents);

        public async Task InstallFreshCurrentAsync()
        {
            var parent = Path.GetDirectoryName(Layout.ManagedRoot)!;
            var candidateRoot = Path.Combine(
                parent,
                $".{Path.GetFileName(Layout.ManagedRoot)}.migration-candidate-{Guid.NewGuid():N}");
            using var source = EnterpriseDirectoryPayloadSource
                .OpenExplicitDevelopmentPayload(PayloadRoot);
            var candidate = await StageCandidateAsync(
                    candidateRoot,
                    source,
                    CancellationToken.None)
                .ConfigureAwait(false);
            Directory.Move(candidateRoot, Layout.ManagedRoot);
            await FinalizeAsync(candidate, CancellationToken.None).ConfigureAwait(false);
        }

        public List<string> FindLegacyQuarantines()
        {
            var parent = Path.GetDirectoryName(Layout.ManagedRoot)!;
            var prefix = $".{Path.GetFileName(Layout.ManagedRoot)}.legacy-quarantine-";
            return Directory.Exists(parent)
                ? Directory.EnumerateDirectories(parent)
                    .Where(path => Path.GetFileName(path).StartsWith(prefix, StringComparison.Ordinal))
                    .ToList()
                : [];
        }

        public List<string> FindAbandonedCandidates()
        {
            var parent = Path.GetDirectoryName(Layout.ManagedRoot)!;
            var prefix = $".{Path.GetFileName(Layout.ManagedRoot)}.abandoned-candidate-";
            return Directory.Exists(parent)
                ? Directory.EnumerateDirectories(parent)
                    .Where(path => Path.GetFileName(path).StartsWith(
                        prefix,
                        StringComparison.Ordinal))
                    .ToList()
                : [];
        }

        public string FindCandidate()
        {
            var parent = Path.GetDirectoryName(Layout.ManagedRoot)!;
            var prefix = $".{Path.GetFileName(Layout.ManagedRoot)}.migration-candidate-";
            return Directory.EnumerateDirectories(parent)
                .Single(path => Path.GetFileName(path).StartsWith(prefix, StringComparison.Ordinal));
        }

        public void RequireLegacyActive()
        {
            True(File.Exists(Path.Combine(
                Layout.StateRoot,
                "release-feed-state.v2.json")));
            True(File.Exists(Layout.BootstrapperPath));
            False(File.Exists(OldExecutionMarker));
        }

        public void RequireFinalized()
        {
            var pointer = new EnterpriseReleaseSetPointerStore(Layout).ReadRequired();
            Equal("launcher-current", pointer.Current.Launcher.ReleaseId);
            Equal("runtime-current", pointer.Current.Runtime.ReleaseId);
            Equal(EnterpriseReleaseHealthStates.Healthy, pointer.Current.HealthState);
            True(pointer.Previous is null);
            EnterpriseStableBootstrapperVerifier.RequireTrusted(Layout);
            True(File.Exists(Layout.BootstrapperPath));
            False(File.Exists(OldExecutionMarker));
        }

        public void RequireFinalizedAndRegistered()
        {
            RequireFinalized();
            Equal("registered", File.ReadAllText(RegistrationPath));
        }

        public void RequireUserDataUnchanged() =>
            Equal(_userDataSnapshot, SnapshotUserData(Layout));

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            DeleteTestDirectoryEventually(Root);
        }

        private Task<EnterpriseLegacyMigrationCandidate> StageCandidateAsync(
            string candidateRoot,
            IEnterprisePayloadSource source,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var candidateLayout = EnterpriseInstallationLayout.CreateMigrationCandidate(
                Layout,
                candidateRoot);
            Directory.CreateDirectory(candidateLayout.ManagedRoot);
            Directory.CreateDirectory(candidateLayout.LauncherVersionsRoot);
            Directory.CreateDirectory(candidateLayout.RuntimeVersionsRoot);
            Directory.CreateDirectory(candidateLayout.PluginPolicyVersionsRoot);
            Directory.CreateDirectory(candidateLayout.StateRoot);
            Directory.CreateDirectory(candidateLayout.PackageRoot);
            var launcher = candidateLayout.GetLauncherVersionDirectory("launcher-current");
            var runtime = candidateLayout.GetRuntimeVersionDirectory("runtime-current");
            using (var launcherArchive = source.Open("launcher.zip"))
            {
                ExtractArchive(launcherArchive, launcher);
            }
            using (var runtimeArchive = source.Open("runtime.zip"))
            {
                ExtractArchive(runtimeArchive, runtime);
            }
            File.WriteAllBytes(
                candidateLayout.BuildProfileMarkerPath,
                EnterpriseBuildProfileMarker.CreateCanonical(
                    candidateLayout.LayoutProfile));
            File.Copy(ExternalInstallerPath, candidateLayout.InstalledInstallerPath);
            using (var input = source.Open(
                       EnterpriseInstallationLayout.BootstrapperExecutableName))
            using (var output = new FileStream(
                       candidateLayout.BootstrapperPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            {
                input.CopyTo(output);
                output.Flush(flushToDisk: true);
            }

            var manifest = EnterpriseInstallManifest.Parse(File.ReadAllBytes(Path.Combine(
                PayloadRoot,
                EnterpriseEmbeddedPayloadSource.ManifestFileName)));
            if (StageWrongSelfConsistentCandidate)
            {
                File.AppendAllText(
                    Path.Combine(
                        launcher,
                        EnterpriseInstallationLayout.LauncherExecutableName),
                    "wrong-but-self-consistent");
            }
            WriteComponentReceipts(
                launcher,
                manifest.LauncherReleaseId,
                manifest.LauncherArchiveSha256,
                EnterpriseReleaseSetContract.LauncherComponent,
                EnterpriseInstallationLayout.LauncherExecutableName,
                secondaryRelativePath: null,
                runtimeManifestSha256: null,
                candidateLayout.ManagedRoot);
            var runtimeManifestSha256 = EnterpriseRuntimeFileManifest
                .ValidateCompleteTree(runtime);
            WriteComponentReceipts(
                runtime,
                manifest.RuntimeReleaseId,
                manifest.RuntimeArchiveSha256,
                EnterpriseReleaseSetContract.RuntimeComponent,
                "node.exe",
                "node_modules/@deepseek-ai/dsh/lib/bin.js",
                runtimeManifestSha256,
                candidateLayout.ManagedRoot);
            if (StageCrossComponentReceipt)
            {
                File.Copy(
                    Path.Combine(runtime, ".ensou-enterprise-runtime.json"),
                    Path.Combine(launcher, ".ensou-enterprise-runtime.json"));
            }
            return Task.FromResult(new EnterpriseLegacyMigrationCandidate(
                "launcher-current",
                "runtime-current"));
        }

        private Task FinalizeAsync(
            EnterpriseLegacyMigrationCandidate candidate,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Directory.CreateDirectory(Layout.StateRoot);
            EnterpriseStableBootstrapperVerifier.WriteReceipt(
                Layout,
                HashFile(Layout.BootstrapperPath));
            _ = new EnterpriseRuntimePointerStore(Layout)
                .Activate(candidate.RuntimeReleaseId);
            _ = new EnterpriseLauncherPointerStore(Layout)
                .Activate(candidate.LauncherReleaseId);
            _ = new EnterpriseReleaseSetPointerStore(Layout)
                .ActivateInitialHealthy(
                    candidate.LauncherReleaseId,
                    candidate.RuntimeReleaseId);
            EnterprisePathGuard.WriteFileAtomically(
                Path.Combine(Layout.StateRoot, "installation-receipt.json"),
                JsonSerializer.SerializeToUtf8Bytes(
                    new EnterpriseInstallationReceipt(
                        1,
                        Layout.LayoutProfile,
                        candidate.LauncherReleaseId,
                        candidate.RuntimeReleaseId,
                        DevelopmentUnsignedPayload: true,
                        DateTimeOffset.UtcNow),
                    EnterpriseInstallJson.Options),
                Layout.ManagedRoot);
            return Task.CompletedTask;
        }

        private void ValidateFinalized(EnterpriseLegacyMigrationCandidate candidate)
        {
            Equal("launcher-current", candidate.LauncherReleaseId);
            Equal("runtime-current", candidate.RuntimeReleaseId);
            RequireFinalized();
        }

        private Task RegisterAsync(
            EnterpriseLegacyMigrationCandidate candidate,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Directory.CreateDirectory(Path.GetDirectoryName(RegistrationPath)!);
            if (FailRegistrationOnce)
            {
                FailRegistrationOnce = false;
                File.WriteAllText(RegistrationPath, "partial-registration");
                throw new IOException("Injected enterprise registration failure.");
            }
            File.WriteAllText(RegistrationPath, "registered");
            return Task.CompletedTask;
        }

        private void ValidateRegistration(EnterpriseLegacyMigrationCandidate candidate) =>
            Equal("registered", File.ReadAllText(RegistrationPath));

        private static void ExtractArchive(Stream archiveStream, string destination)
        {
            Directory.CreateDirectory(destination);
            using var archive = new ZipArchive(
                archiveStream,
                ZipArchiveMode.Read,
                leaveOpen: false);
            foreach (var entry in archive.Entries)
            {
                var relative = entry.FullName.Replace('/', Path.DirectorySeparatorChar);
                var output = Path.GetFullPath(Path.Combine(destination, relative));
                if (!output.StartsWith(
                        Path.TrimEndingDirectorySeparator(destination)
                            + Path.DirectorySeparatorChar,
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException("Test archive escaped candidate root.");
                }
                if (entry.FullName.EndsWith("/", StringComparison.Ordinal))
                {
                    Directory.CreateDirectory(output);
                    continue;
                }
                Directory.CreateDirectory(Path.GetDirectoryName(output)!);
                using var input = entry.Open();
                using var file = new FileStream(
                    output,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    4096,
                    FileOptions.WriteThrough);
                input.CopyTo(file);
                file.Flush(flushToDisk: true);
            }
        }

        private static void WriteComponentReceipts(
            string directory,
            string releaseId,
            string archiveSha256,
            string component,
            string primaryRelativePath,
            string? secondaryRelativePath,
            string? runtimeManifestSha256,
            string managedRoot)
        {
            var receipt = new EnterpriseInstalledReleaseReceipt(
                1,
                releaseId,
                archiveSha256,
                HashFile(Path.Combine(directory, primaryRelativePath)),
                secondaryRelativePath is null
                    ? null
                    : HashFile(Path.Combine(directory, secondaryRelativePath)),
                DateTimeOffset.UtcNow);
            if (string.Equals(
                    component,
                    EnterpriseReleaseSetContract.LauncherComponent,
                    StringComparison.Ordinal))
            {
                EnterpriseLauncherPointerStore.WriteReceipt(
                    directory,
                    receipt,
                    managedRoot);
            }
            else
            {
                EnterpriseRuntimePointerStore.WriteReceipt(
                    directory,
                    receipt,
                    managedRoot);
            }
            var artifact = new EnterpriseReleaseArtifactReceiptV2(
                2,
                component,
                releaseId,
                archiveSha256,
                EnterpriseTreeHash.Compute(directory),
                runtimeManifestSha256,
                DateTimeOffset.UtcNow);
            EnterprisePathGuard.WriteFileAtomically(
                Path.Combine(directory, EnterpriseTreeHash.ReceiptFileName),
                EnterprisePointerJson.Serialize(artifact),
                managedRoot);
        }

        private static void SeedLegacy(EnterpriseInstallationLayout layout, string root)
        {
            Directory.CreateDirectory(layout.ManagedRoot);
            Directory.CreateDirectory(layout.StateRoot);
            Directory.CreateDirectory(layout.LauncherVersionsRoot);
            Directory.CreateDirectory(layout.RuntimeVersionsRoot);
            Directory.CreateDirectory(Path.Combine(layout.LauncherVersionsRoot, "legacy-launcher"));
            Directory.CreateDirectory(Path.Combine(layout.RuntimeVersionsRoot, "legacy-runtime"));
            File.WriteAllText(
                Path.Combine(layout.LauncherVersionsRoot, "legacy-launcher", "old.bin"),
                "old-launcher");
            File.WriteAllText(
                Path.Combine(layout.RuntimeVersionsRoot, "legacy-runtime", "old.bin"),
                "old-runtime");
            File.WriteAllText(
                layout.ReleaseSetPointerPath,
                "{\"schemaVersion\":2,\"oldPlainPointer\":true}");
            File.WriteAllText(
                Path.Combine(layout.StateRoot, "release-feed-state.v2.json"),
                "{\"schemaVersion\":2,\"oldPlainFeed\":true}");
            File.WriteAllBytes(
                layout.BuildProfileMarkerPath,
                EnterpriseBuildProfileMarker.CreateCanonical(
                    layout.LayoutProfile));
            File.WriteAllText(layout.BootstrapperPath, "old-bootstrapper-never-execute");
            File.WriteAllText(layout.InstalledInstallerPath, "old-installer-never-execute");
            File.WriteAllText(
                Path.Combine(layout.ManagedRoot, "DO-NOT-EXECUTE.cmd"),
                $"@echo executed>{Path.Combine(root, "old-managed-binary-executed.txt")}");
        }

        private static void SeedUserData(EnterpriseInstallationLayout layout)
        {
            Directory.CreateDirectory(Path.Combine(layout.HarnessHome, "workspace"));
            File.WriteAllText(
                Path.Combine(layout.HarnessHome, "workspace", "customer-project.txt"),
                "keep-workspace");
            File.WriteAllText(
                Path.Combine(layout.HarnessHome, "conversation-history.jsonl"),
                "keep-history");
            Directory.CreateDirectory(layout.HarnessRecoveryRoot);
            File.WriteAllText(
                Path.Combine(layout.HarnessRecoveryRoot, "recovery-generation.json"),
                "keep-recovery");
        }

        private static string CreatePayload(
            string root,
            string payloadLeaf = "payload",
            string launcherReleaseId = "launcher-current",
            string runtimeReleaseId = "runtime-current",
            string bootstrapperContents = "signed-bootstrapper-test-bytes")
        {
            var payload = Path.Combine(root, payloadLeaf);
            Directory.CreateDirectory(payload);
            File.WriteAllText(
                Path.Combine(payload, EnterpriseDirectoryPayloadSource.DevelopmentConsentFileName),
                EnterpriseDirectoryPayloadSource.DevelopmentConsentText);
            var launcher = Path.Combine(payload, "launcher.zip");
            var runtime = Path.Combine(payload, "runtime.zip");
            var bootstrapper = Path.Combine(
                payload,
                EnterpriseInstallationLayout.BootstrapperExecutableName);
            using (var archive = ZipFile.Open(launcher, ZipArchiveMode.Create))
            {
                WriteZipEntry(
                    archive,
                    EnterpriseInstallationLayout.LauncherExecutableName,
                    "trusted-launcher-" + launcherReleaseId);
                WriteZipEntry(
                    archive,
                    EnterpriseInstallationLayout.ClientBootstrapperExecutableName,
                    "trusted-client-bootstrapper-" + launcherReleaseId);
                WriteZipEntry(
                    archive,
                    EnterpriseInstallationLayout.MaintenanceExecutableName,
                    "trusted-maintenance-" + launcherReleaseId);
                WriteZipEntry(
                    archive,
                    EnterpriseInstallationLayout.BuildProfileMarkerFileName,
                    Encoding.UTF8.GetString(EnterpriseBuildProfileMarker.CreateCanonical(
                        EnterpriseInstallationLayout.DevelopmentE2ELayoutProfile)));
            }
            var nodeContents = "trusted-node-" + runtimeReleaseId;
            var entryContents = "trusted-runtime-entry-" + runtimeReleaseId;
            using (var archive = ZipFile.Open(runtime, ZipArchiveMode.Create))
            {
                WriteZipEntry(archive, "node.exe", nodeContents);
                WriteZipEntry(
                    archive,
                    "node_modules/@deepseek-ai/dsh/lib/bin.js",
                    entryContents);
                WriteZipEntry(
                    archive,
                    EnterpriseRuntimeFileManifest.FileName,
                    HashText(nodeContents) + "  node.exe\n"
                    + HashText(entryContents)
                    + "  node_modules/@deepseek-ai/dsh/lib/bin.js\n");
            }
            File.WriteAllText(bootstrapper, bootstrapperContents);
            var manifest = new EnterpriseInstallManifest
            {
                SchemaVersion = 1,
                LayoutProfile = EnterpriseInstallationLayout.DevelopmentE2ELayoutProfile,
                LauncherReleaseId = launcherReleaseId,
                RuntimeReleaseId = runtimeReleaseId,
                LauncherArchive = Path.GetFileName(launcher),
                LauncherArchiveSizeBytes = new FileInfo(launcher).Length,
                LauncherArchiveSha256 = HashFile(launcher),
                RuntimeArchive = Path.GetFileName(runtime),
                RuntimeArchiveSizeBytes = new FileInfo(runtime).Length,
                RuntimeArchiveSha256 = HashFile(runtime),
                BootstrapperFile = Path.GetFileName(bootstrapper),
                BootstrapperSizeBytes = new FileInfo(bootstrapper).Length,
                BootstrapperSha256 = HashFile(bootstrapper),
                PublishedAtUtc = DateTimeOffset.UtcNow,
            };
            File.WriteAllText(
                Path.Combine(payload, EnterpriseEmbeddedPayloadSource.ManifestFileName),
                JsonSerializer.Serialize(
                    manifest,
                    new JsonSerializerOptions(JsonSerializerDefaults.Web)));
            return payload;
        }

        private static void WriteZipEntry(
            ZipArchive archive,
            string relativePath,
            string contents)
        {
            var entry = archive.CreateEntry(relativePath, CompressionLevel.NoCompression);
            using var writer = new StreamWriter(
                entry.Open(),
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            writer.Write(contents);
        }

        private static string HashText(string contents) =>
            Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(contents)));

        private static string SnapshotUserData(EnterpriseInstallationLayout layout) =>
            string.Join(
                "\n",
                new[] { layout.HarnessHome, layout.HarnessRecoveryRoot }
                    .SelectMany(root => Directory.EnumerateFiles(
                        root,
                        "*",
                        SearchOption.AllDirectories))
                    .Select(path =>
                        Path.GetRelativePath(layout.UserProfileRoot, path).Replace('\\', '/')
                        + ":"
                        + HashFile(path))
                    .Order(StringComparer.Ordinal));
    }

    private sealed class FixedUtcTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }

    private sealed class SequenceUtcTimeProvider(
        params DateTimeOffset[] utcSequence) : TimeProvider
    {
        private int _index;

        public override DateTimeOffset GetUtcNow()
        {
            if (utcSequence.Length == 0)
            {
                throw new InvalidOperationException("UTC test sequence is empty.");
            }
            var index = Math.Min(
                Interlocked.Increment(ref _index) - 1,
                utcSequence.Length - 1);
            return utcSequence[index];
        }
    }

    private static string HashFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    private static bool TryCreateDirectoryJunction(string junctionPath, string targetPath)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe",
            Arguments = $"/d /c mklink /J \"{junctionPath}\" \"{targetPath}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });
        if (process is null)
        {
            return false;
        }
        process.WaitForExit();
        return process.ExitCode == 0;
    }

    private static void True(bool value)
    {
        if (!value)
        {
            throw new InvalidOperationException("Expected true.");
        }
    }

    private static void False(bool value) => True(!value);

    private static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected '{expected}', actual '{actual}'.");
        }
    }

    private static void Throws<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }
        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }

    private static async Task ThrowsAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (TException)
        {
            return;
        }
        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(
        string fileName,
        string existingFileName,
        IntPtr securityAttributes);
}
