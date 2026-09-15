using System.Buffers.Binary;
using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.Personal.Installer;
using Ensou.Dsh.UpdateEngine;
using Microsoft.Win32;

namespace Ensou.Dsh.Personal.InstallerTests;

internal static class Program
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;
    private static bool _traceInstallerHealth;
    private static readonly string TempRoot = Path.Combine(
        Path.GetTempPath(),
        "edi-" + Guid.NewGuid().ToString("N")[..8]);

    public static async Task<int> Main(string[] args)
    {
        Directory.CreateDirectory(TempRoot);
        var tests = new (string Name, Func<Task> Run)[]
        {
            ("Installer command line fails closed for unsigned development", InstallerCommandAdmissionAsync),
            ("Installer health exit must be confirmed before rollback", InstallerHealthProcessExitTests.RunAsync),
            ("preflight failures leave installation state unchanged", PersonalInstallPreflightTests.RejectsBeforeInstallStateMutationAsync),
            ("preflight classifies exact v1 and rejects unknown manual roots", PersonalInstallPreflightTests.ClassifiesLegacyAndManualConflictAsync),
            ("preflight rejects every single and partial v2 marker set", PersonalInstallPreflightTests.RejectsEveryPartialV2MarkerAsync),
            ("legacy enrollment conservatively classifies Node writers", PersonalInstallPreflightTests.NodeProcessesAlwaysBlockAsync),
            ("preflight native Windows identity probe is readable", PersonalInstallPreflightTests.NativeWindowsPlatformProbeAsync),
            ("preflight write probe leaves no filesystem residue", PersonalInstallPreflightTests.WriteProbeLeavesNoResidueAsync),
            ("installation identity persists across upgrade and separates clean roots", InstallationIdentityLifecycleAsync),
            ("installation identity rejects copied or unauthenticated evidence", InstallationIdentityCopyAndTamperRejectedAsync),
            ("installation identity preserves the legacy pointer v3 wire contract", InstallationIdentityPointerV3CompatibilityAsync),
            ("clean install commits and retires active journal", CleanInstallAsync),
            ("exact local v1 tree is preserved without parsing settings", LegacyMigrationAsync),
            ("legacy hardlink is rejected before rename", LegacyHardlinkRejectedAsync),
            ("provenance primary and witness repair independently", ProvenanceCopyRepairAsync),
            ("provenance divergence fails closed", ProvenanceDivergenceRejectedAsync),
            ("clock rollback uses preserved trusted time", ClockRollbackAsync),
            ("candidate expired at preserved time is rejected", ExpiredAtTrustedTimeRejectedAsync),
            ("same manifest repairs damaged and newer Startup Stub", SameManifestStubRepairAsync),
            ("every partial registration write rolls back a clean shell", RegistrationCleanRollbackAsync),
            ("every partial registration write restores an upgrade shell exactly", RegistrationUpgradeRollbackAsync),
            ("registration subkeys fail closed before any mutation", RegistrationSubkeyRejectedAsync),
            ("registration failure restores previous Stub and retries", RegistrationFailureRetryAsync),
            ("clean registration failure removes installed Stub and retries", CleanFailureStubRemovalAsync),
            ("clean partial registration failure is shell-atomic and resumable", CleanRegistrationPartialFailureAsync),
            ("failed health journal is retired for higher Installer takeover", FailedHealthNewerTakeoverAsync),
            ("legacy health failure preserves both quarantines for takeover", LegacyHealthFailureAsync),
            ("legacy registration failure resumes without v1 execution", LegacyRegistrationFailureAsync),
            ("single provenance loss plus uninstall permits certified reinstall", ProvenanceLossUninstallReinstallAsync),
            ("installer health command requires its exact active journal", InstallerHealthAdmissionAsync),
            ("process guard fails before journal creation", ProcessGuardAsync),
            ("all install checkpoints resume after simulated crash", InstallCheckpointResumeAsync),
            ("failed-health finalization checkpoints are idempotent", FailureCheckpointResumeAsync),
            ("DPAPI journal tamper fails closed", JournalTamperRejectedAsync),
            ("legacy reparse and unexpected roots fail before rename", LegacyShapeTamperRejectedAsync),
            ("payload self-check verifies signed exact embedded closure", PayloadSelfCheckAsync),
            ("production payload self-check emits one canonical evidence line", PayloadSelfCheckEvidenceAsync),
            ("compiled Installer trust mismatch fails closed", CompiledTrustMismatchAsync),
            ("compiled client trust fingerprint rejects every trust mismatch", CompiledClientTrustFingerprintAsync),
            ("Installer executable identity lease prevents replacement", InstallerIdentityLeaseAsync),
            ("compiled trust process lease prevents path replacement", CompiledTrustProcessLeaseAsync),
        };
        if (args.Length != 0)
        {
            string[] selectedNames;
            if (args is ["--test", "installer-command-admission"])
            {
                selectedNames =
                [
                    "Installer command line fails closed for unsigned development",
                ];
            }
            else if (args is ["--test", "health-process-exit"])
            {
                selectedNames = ["Installer health exit must be confirmed before rollback"];
            }
            else if (args is ["--test", "installation-identity-lifecycle"])
            {
                selectedNames = ["installation identity persists across upgrade and separates clean roots"];
                _traceInstallerHealth = true;
            }
            else if (args is ["--test", "home-coordination-integration"])
            {
                selectedNames =
                [
                    "clean install commits and retires active journal",
                    "exact local v1 tree is preserved without parsing settings",
                    "failed health journal is retired for higher Installer takeover",
                    "legacy health failure preserves both quarantines for takeover",
                    "installer health command requires its exact active journal",
                    "all install checkpoints resume after simulated crash",
                    "failed-health finalization checkpoints are idempotent",
                ];
            }
            else
            {
                Console.Error.WriteLine("Unknown Personal Installer test selector.");
                return 2;
            }
            tests = tests.Where(test => selectedNames.Contains(
                test.Name,
                StringComparer.Ordinal)).ToArray();
            if (tests.Length != selectedNames.Length)
            {
                Console.Error.WriteLine("Personal Installer test selector is incomplete.");
                return 2;
            }
        }
        var failures = 0;
        try
        {
            foreach (var test in tests)
            {
                try
                {
                    await test.Run().ConfigureAwait(false);
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
        Console.WriteLine($"{tests.Length - failures}/{tests.Length} Personal Installer tests passed.");
        return failures == 0 ? 0 : 1;
    }

    private static Task InstallerCommandAdmissionAsync()
    {
        foreach (var arguments in new string[][]
        {
            Array.Empty<string>(),
            [PersonalInstallerCommandLine.InstallArgument],
            [PersonalInstallerCommandLine.QuietArgument],
            [
                PersonalInstallerCommandLine.InstallArgument,
                PersonalInstallerCommandLine.QuietArgument,
            ],
        })
        {
            var continuationCount = 0;
            var command = PersonalInstallerCommandLine.Parse(arguments);
            AssertEqual(PersonalInstallerCommandKind.Install, command.Kind);
            AssertThrows<PersonalInstallerInstallAdmissionException>(() =>
            {
                PersonalInstallerCommandLine.RequireInstallAllowed(
                    command,
                    productionBuild: false,
                    developmentE2ECompiled: false);
                continuationCount++;
            });
            AssertEqual(0, continuationCount);
        }

        var unsignedWithoutLayout = PersonalInstallerCommandLine.Parse(
            [
                PersonalInstallerCommandLine.InstallArgument,
                PersonalInstallerCommandLine.QuietArgument,
                PersonalInstallerCommandLine.DevelopmentOverrideArgument,
            ]);
        PersonalInstallerCommandLine.RequireInstallAllowed(
            unsignedWithoutLayout,
            productionBuild: false,
            developmentE2ECompiled: false);
        AssertThrows<PersonalInstallerInstallAdmissionException>(() =>
            PersonalInstallerCommandLine.RequireInstallAllowed(
                unsignedWithoutLayout,
                productionBuild: false,
                developmentE2ECompiled: true));

        var production = PersonalInstallerCommandLine.Parse([]);
        PersonalInstallerCommandLine.RequireInstallAllowed(
            production,
            productionBuild: true,
            developmentE2ECompiled: false);
        var productionOverride = PersonalInstallerCommandLine.Parse(
            [PersonalInstallerCommandLine.DevelopmentOverrideArgument]);
        var productionContinuationCount = 0;
        AssertThrows<PersonalInstallerInstallAdmissionException>(() =>
        {
            PersonalInstallerCommandLine.RequireInstallAllowed(
                productionOverride,
                productionBuild: true,
                developmentE2ECompiled: false);
            productionContinuationCount++;
        });
        AssertEqual(0, productionContinuationCount);

        foreach (var arguments in new[]
        {
            new[] { "--unknown" },
            new[] { "--INSTALL" },
            new[] { "--Quiet" },
            new[] { "--allow-unsigned-development-Install" },
            new[] {
                PersonalInstallerCommandLine.InstallArgument,
                PersonalInstallerCommandLine.InstallArgument,
            },
            new[] {
                PersonalInstallerCommandLine.QuietArgument,
                PersonalInstallerCommandLine.QuietArgument,
            },
            new[] {
                PersonalInstallerCommandLine.DevelopmentOverrideArgument,
                PersonalInstallerCommandLine.DevelopmentOverrideArgument,
            },
        })
        {
            AssertThrows<ArgumentException>(() =>
                PersonalInstallerCommandLine.Parse(arguments));
        }

        var binarySelfCheck = PersonalInstallerCommandLine.Parse(
            [PersonalInstallerCommandLine.BinarySelfCheckArgument]);
        AssertEqual(
            PersonalInstallerCommandKind.BinarySelfCheck,
            binarySelfCheck.Kind);
        AssertTrue(binarySelfCheck.IsMachineSelfCheck);
        AssertThrows<PersonalInstallerInstallAdmissionException>(() =>
            PersonalInstallerCommandLine.RequireInstallAllowed(
                binarySelfCheck,
                productionBuild: false,
                developmentE2ECompiled: false));

        var developmentManagedRoot = Path.Combine(TempRoot, "development-e2e", "managed");
        var developmentHarnessHome = Path.Combine(TempRoot, "development-e2e", "harness");
        var developmentWitness = Path.Combine(
            TempRoot,
            "development-e2e-witness",
            "state.dpapi");
        var developmentLayout = PersonalInstallerCommandLine.Parse(
        [
            PersonalInstallerCommandLine.InstallArgument,
            PersonalInstallerCommandLine.QuietArgument,
            PersonalInstallerCommandLine.DevelopmentOverrideArgument,
            PersonalInstallerCommandLine.DevelopmentE2ELayoutArgument,
            PersonalInstallerCommandLine.DevelopmentManagedRootArgument,
            developmentManagedRoot,
            PersonalInstallerCommandLine.DevelopmentHarnessHomeArgument,
            developmentHarnessHome,
            PersonalInstallerCommandLine.DevelopmentUpdateSecurityWitnessArgument,
            developmentWitness,
            PersonalInstallerCommandLine.DevelopmentNoShellRegistrationArgument,
        ]);
        AssertTrue(developmentLayout.DevelopmentE2ELayout is not null);
        AssertEqual(developmentManagedRoot, developmentLayout.DevelopmentE2ELayout!.ManagedRoot);
        AssertThrows<PersonalInstallerInstallAdmissionException>(() =>
            PersonalInstallerCommandLine.RequireInstallAllowed(
                developmentLayout,
                productionBuild: false,
                developmentE2ECompiled: false));
        PersonalInstallerCommandLine.RequireInstallAllowed(
            developmentLayout,
            productionBuild: false,
            developmentE2ECompiled: true);
        AssertThrows<PersonalInstallerInstallAdmissionException>(() =>
            PersonalInstallerCommandLine.RequireInstallAllowed(
                developmentLayout,
                productionBuild: true,
                developmentE2ECompiled: true));

        var forwardedEnvelope = new[]
        {
            "--installer-health",
            PersonalDevelopmentE2ELayoutArguments.LayoutArgument,
            PersonalDevelopmentE2ELayoutArguments.ManagedRootArgument,
            developmentManagedRoot,
            PersonalDevelopmentE2ELayoutArguments.HarnessHomeArgument,
            developmentHarnessHome,
            PersonalDevelopmentE2ELayoutArguments.UpdateSecurityWitnessArgument,
            developmentWitness,
        };
        AssertThrows<InvalidOperationException>(() =>
            PersonalDevelopmentE2ELayoutArguments.ParseAndStrip(
                forwardedEnvelope,
                developmentE2ECompiled: false,
                out _));
        var parsedEnvelope = PersonalDevelopmentE2ELayoutArguments.ParseAndStrip(
            forwardedEnvelope,
            developmentE2ECompiled: true,
            out var healthCommand);
        AssertTrue(parsedEnvelope is not null);
        AssertEqual("--installer-health", healthCommand.Single());
        AssertEqual(developmentManagedRoot, parsedEnvelope!.Layout.ManagedRoot);

        AssertThrows<ArgumentException>(() =>
            PersonalInstallerCommandLine.Parse(
            [
                PersonalInstallerCommandLine.QuietArgument,
                PersonalInstallerCommandLine.DevelopmentOverrideArgument,
                PersonalInstallerCommandLine.DevelopmentE2ELayoutArgument,
                PersonalInstallerCommandLine.DevelopmentManagedRootArgument,
                developmentManagedRoot,
                PersonalInstallerCommandLine.DevelopmentHarnessHomeArgument,
                developmentHarnessHome,
                PersonalInstallerCommandLine.DevelopmentUpdateSecurityWitnessArgument,
                developmentWitness,
                PersonalInstallerCommandLine.DevelopmentNoShellRegistrationArgument,
            ]));

        var developmentSelfCheckArguments = Enumerable.Repeat("value", 10).ToArray();
        developmentSelfCheckArguments[0] =
            PersonalInstallerCommandLine.DevelopmentPayloadSelfCheckArgument;
        var developmentSelfCheck = PersonalInstallerCommandLine.Parse(
            developmentSelfCheckArguments);
        AssertEqual(
            PersonalInstallerCommandKind.DevelopmentPayloadSelfCheck,
            developmentSelfCheck.Kind);

        var productionSelfCheckArguments = Enumerable.Repeat("value", 10).ToArray();
        productionSelfCheckArguments[0] =
            PersonalInstallerCommandLine.ProductionPayloadSelfCheckArgument;
        var productionSelfCheck = PersonalInstallerCommandLine.Parse(
            productionSelfCheckArguments);
        AssertEqual(
            PersonalInstallerCommandKind.ProductionPayloadSelfCheck,
            productionSelfCheck.Kind);

        AssertThrows<ArgumentException>(() =>
            PersonalInstallerCommandLine.Parse(
            [
                PersonalInstallerCommandLine.BinarySelfCheckArgument,
                PersonalInstallerCommandLine.DevelopmentOverrideArgument,
            ]));
        developmentSelfCheckArguments[9] =
            PersonalInstallerCommandLine.DevelopmentOverrideArgument;
        AssertThrows<ArgumentException>(() =>
            PersonalInstallerCommandLine.Parse(developmentSelfCheckArguments));
        AssertThrows<ArgumentException>(() =>
            PersonalInstallerCommandLine.Parse(
                productionSelfCheckArguments.Append(
                    PersonalInstallerCommandLine.DevelopmentOverrideArgument)
                .ToArray()));
        AssertThrows<ArgumentException>(() =>
            PersonalInstallerCommandLine.Parse(["--Binary-Self-Check"]));

        return Task.CompletedTask;
    }

    private static async Task CleanInstallAsync()
    {
        using var scenario = new Scenario("clean");
        var payload = scenario.CreatePayload(1, "personal-installer-v1", "stub-v1");
        var service = scenario.CreateService();
        var prepared = await service.PrepareForTestsAsync(
            payload,
            scenario.Trust,
            GetFreePort());
        AssertTrue(prepared.RequiresHealthValidation);
        AssertTrue(File.Exists(scenario.Layout.StartupStubPath));
        AssertTrue(new PersonalInstallMigrationJournalStore(
            scenario.Layout,
            scenario.Clock).TryRead() is not null);
        AssertEqual(
            PersonalLegacyInstallClassification.ManagedV2,
            PersonalInstallPreflightTests.RequireReadyForManagedScenario(
                scenario.Layout).ExistingInstall);
        await PassInstallerHealthAsync(scenario.Layout);
        _ = await service.CompleteAfterHealthAsync(
            prepared.ReleaseSetId,
            prepared.ManifestSha256);
        AssertTrue(new PersonalInstallMigrationJournalStore(
            scenario.Layout,
            scenario.Clock).TryRead() is null);
        var provenance = new PersonalInstallProvenanceStore(
            scenario.Layout,
            scenario.Clock);
        AssertTrue(File.Exists(provenance.PrimaryPath));
        AssertTrue(File.Exists(provenance.WitnessPath));
        AssertEqual(
            PersonalReleaseHealthStates.Healthy,
            new PersonalReleaseSetPointerStore(scenario.Layout)
                .ReadRequired().Current.HealthState);
        AssertEqual(
            PersonalLegacyInstallClassification.ManagedV2,
            PersonalInstallPreflightTests.RequireReadyForManagedScenario(
                scenario.Layout).ExistingInstall);
        foreach (var requiredMarker in new[]
        {
            scenario.Layout.ReleaseSetPointerPath,
            scenario.Layout.InstallationIdentityReceiptPath,
            scenario.Layout.InstallationIdentityProtectedPath,
            scenario.Layout.UpdateSecurityStatePath,
            scenario.Layout.UpdateSecurityStatePath + ".anchor",
            scenario.Layout.UpdateSecurityWitnessPath,
            scenario.Layout.V2MigrationFootprintPath,
            scenario.Layout.StartupStubPath,
            provenance.PrimaryPath,
            provenance.WitnessPath,
        })
        {
            var withheld = requiredMarker + ".preflight-withheld";
            File.Move(requiredMarker, withheld);
            try
            {
                PersonalInstallPreflightTests.AssertManagedScenarioIsManualConflict(
                    scenario.Layout);
            }
            finally
            {
                File.Move(withheld, requiredMarker);
            }
        }
    }

    private static async Task LegacyMigrationAsync()
    {
        using var scenario = new Scenario("legacy");
        CreateExactLegacyTree(scenario.Layout);
        var settings = File.ReadAllBytes(Path.Combine(
            scenario.Layout.ManagedRoot,
            "launcher.settings.json"));
        var prepared = await scenario.CreateService().PrepareForTestsAsync(
            scenario.CreatePayload(1, "personal-legacy-v2", "stub-v1"),
            scenario.Trust,
            GetFreePort());
        AssertTrue(prepared.LegacyQuarantinePath is not null);
        AssertSequenceEqual(
            settings,
            File.ReadAllBytes(Path.Combine(
                prepared.LegacyQuarantinePath!,
                "launcher.settings.json")));
        AssertTrue(File.Exists(Path.Combine(
            prepared.LegacyQuarantinePath!,
            "snapshots",
            "snapshot.bin")));
    }

    private static async Task LegacyHardlinkRejectedAsync()
    {
        using var scenario = new Scenario("legacy-hardlink");
        CreateExactLegacyTree(scenario.Layout);
        var settings = Path.Combine(scenario.Layout.ManagedRoot, "launcher.settings.json");
        var sibling = Path.Combine(Path.GetDirectoryName(settings)!, "settings-hardlink-copy");
        if (!CreateHardLink(sibling, settings, IntPtr.Zero))
        {
            throw new IOException(
                "Could not create hardlink test fixture.",
                new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
        }
        try
        {
            await AssertThrowsAsync<InvalidDataException>(() =>
                scenario.CreateService().PrepareForTestsAsync(
                    scenario.CreatePayload(1, "personal-hardlink-v2", "stub-v1"),
                    scenario.Trust,
                    GetFreePort()));
            AssertTrue(Directory.Exists(scenario.Layout.ManagedRoot));
        }
        finally
        {
            File.Delete(sibling);
        }
    }

    private static async Task ProvenanceCopyRepairAsync()
    {
        using var scenario = new Scenario("provenance-repair");
        var payload = scenario.CreatePayload(1, "personal-provenance-v1", "stub-v1");
        await CompleteAsync(scenario, payload);
        var store = new PersonalInstallProvenanceStore(scenario.Layout, scenario.Clock);
        File.Delete(store.PrimaryPath);
        AssertTrue(store.TryReadAndRepair() is not null);
        AssertTrue(File.Exists(store.PrimaryPath));
        File.Delete(store.WitnessPath);
        AssertTrue(store.TryReadAndRepair() is not null);
        AssertTrue(File.Exists(store.WitnessPath));
    }

    private static async Task ProvenanceDivergenceRejectedAsync()
    {
        using var scenario = new Scenario("provenance-divergence");
        await CompleteAsync(
            scenario,
            scenario.CreatePayload(1, "personal-divergence-v1", "stub-v1"));
        var store = new PersonalInstallProvenanceStore(scenario.Layout, scenario.Clock);
        var current = store.TryReadAndRepair()!;
        store.WriteWitnessForTests(current with
        {
            CapturedAtUtc = current.CapturedAtUtc.AddSeconds(1),
        });
        AssertThrows<InvalidDataException>(() => store.TryReadAndRepair());
    }

    private static async Task ClockRollbackAsync()
    {
        using var scenario = new Scenario("clock-rollback");
        var payload = scenario.CreatePayload(1, "personal-clock-v1", "stub-v1");
        var service = scenario.CreateService();
        var first = await service.PrepareForTestsAsync(
            payload,
            scenario.Trust,
            GetFreePort());
        scenario.Clock.SetUtcNow(Now.AddDays(-2));
        await PassInstallerHealthAsync(scenario.Layout);
        _ = await service.CompleteAfterHealthAsync(
            first.ReleaseSetId,
            first.ManifestSha256);
        var prepared = await scenario.CreateService().PrepareForTestsAsync(
            payload,
            scenario.Trust,
            GetFreePort());
        AssertTrue(prepared.AlreadyCompleted);
        var provenance = new PersonalInstallProvenanceStore(
            scenario.Layout,
            scenario.Clock).TryReadAndRepair()!;
        AssertTrue(provenance.CapturedAtUtc >= provenance.SecurityState.TrustedTimeUtc);
    }

    private static async Task ExpiredAtTrustedTimeRejectedAsync()
    {
        using var scenario = new Scenario("trusted-expiry");
        await CompleteAsync(
            scenario,
            scenario.CreatePayload(1, "personal-expiry-v1", "stub-v1"));
        scenario.Clock.SetUtcNow(Now.AddDays(-2));
        var expired = scenario.CreatePayload(
            2,
            "personal-expiry-v2",
            "stub-v2",
            issuedAtUtc: Now.AddDays(-3),
            expiresAtUtc: Now.AddHours(-1));
        await AssertThrowsAsync<InvalidDataException>(() =>
            scenario.CreateService().PrepareForTestsAsync(
                expired,
                scenario.Trust,
                GetFreePort()));
    }

    private static async Task SameManifestStubRepairAsync()
    {
        using var scenario = new Scenario("stub-repair");
        var manifestPayload = scenario.CreatePayload(
            1,
            "personal-stub-repair-v1",
            "stub-v1");
        await CompleteAsync(scenario, manifestPayload);
        File.WriteAllText(scenario.Layout.StartupStubPath, "damaged-stub");
        var repaired = await scenario.CreateService().PrepareForTestsAsync(
            manifestPayload,
            scenario.Trust,
            GetFreePort());
        AssertTrue(repaired.AlreadyCompleted);
        AssertEqual(
            Sha256(manifestPayload.StartupStub),
            FileSha256(scenario.Layout.StartupStubPath));

        var newerStub = manifestPayload with
        {
            StartupStub = Encoding.UTF8.GetBytes("same-manifest-newer-stub"),
        };
        _ = await scenario.CreateService().PrepareForTestsAsync(
            newerStub,
            scenario.Trust,
            GetFreePort());
        AssertEqual(
            Sha256(newerStub.StartupStub),
            FileSha256(scenario.Layout.StartupStubPath));
    }

    private static Task RegistrationCleanRollbackAsync()
    {
        using var scenario = new Scenario("registration-clean");
        PrepareRegistrationFixture(scenario);
        var context = CreateRegistrationContext(scenario);
        try
        {
            foreach (var stage in Enum.GetValues<PersonalWindowsRegistrationInstallStage>())
            {
                var failing = context with
                {
                    InstallObserver = observed =>
                    {
                        if (observed == stage)
                        {
                            throw new IOException("simulated registration stage " + stage);
                        }
                    },
                };
                AssertThrows<IOException>(() =>
                    PersonalWindowsRegistration.Install(
                        scenario.Layout,
                        "clean-v1",
                        failing));
                AssertRegistrationAbsent(context);
            }
        }
        finally
        {
            DeleteRegistrationFixture(context);
        }
        return Task.CompletedTask;
    }

    private static Task RegistrationUpgradeRollbackAsync()
    {
        using var scenario = new Scenario("registration-upgrade");
        PrepareRegistrationFixture(scenario);
        var context = CreateRegistrationContext(scenario);
        try
        {
            _ = PersonalWindowsRegistration.Install(
                scenario.Layout,
                "upgrade-v1",
                context);
            using (var key = Registry.CurrentUser.OpenSubKey(
                       context.RegistrySubKey,
                       writable: true)
                   ?? throw new InvalidOperationException("Expected test ARP key."))
            {
                key.SetValue("SystemComponent", 1, RegistryValueKind.DWord);
                key.SetValue("NoRemove", 1L, RegistryValueKind.QWord);
                key.SetValue(
                    "LegacyTags",
                    new[] { "alpha", "beta" },
                    RegistryValueKind.MultiString);
                key.SetValue(
                    "LegacyExpandable",
                    "%TEMP%\\legacy",
                    RegistryValueKind.ExpandString);
                key.Flush();
            }
            var previous = CaptureRegistration(context);
            foreach (var stage in Enum.GetValues<PersonalWindowsRegistrationInstallStage>())
            {
                var failing = context with
                {
                    InstallObserver = observed =>
                    {
                        if (observed == stage)
                        {
                            throw new IOException("simulated registration stage " + stage);
                        }
                    },
                };
                AssertThrows<IOException>(() =>
                    PersonalWindowsRegistration.Install(
                        scenario.Layout,
                        "upgrade-v2",
                        failing));
                AssertRegistrationEqual(previous, CaptureRegistration(context));
            }
            _ = PersonalWindowsRegistration.Install(
                scenario.Layout,
                "upgrade-v2",
                context);
            _ = PersonalWindowsRegistration.ReadAndValidate(
                scenario.Layout,
                "upgrade-v2",
                context);
            var completed = CaptureRegistration(context);
            AssertEqual(10, completed.RegistryValues?.Count ?? 0);
            AssertFalse(completed.RegistryValues!.ContainsKey("SystemComponent"));
            AssertFalse(completed.RegistryValues.ContainsKey("NoRemove"));
            AssertFalse(completed.RegistryValues.ContainsKey("LegacyTags"));
            AssertFalse(completed.RegistryValues.ContainsKey("LegacyExpandable"));
        }
        finally
        {
            DeleteRegistrationFixture(context);
        }
        return Task.CompletedTask;
    }

    private static Task RegistrationSubkeyRejectedAsync()
    {
        using var scenario = new Scenario("registration-subkey");
        PrepareRegistrationFixture(scenario);
        var context = CreateRegistrationContext(scenario);
        try
        {
            using (var key = Registry.CurrentUser.CreateSubKey(
                       context.RegistrySubKey + "\\unexpected",
                       writable: true)
                   ?? throw new InvalidOperationException("Expected test ARP subkey."))
            {
                key.SetValue("marker", "preserve", RegistryValueKind.String);
                key.Flush();
            }
            AssertThrows<InvalidDataException>(() =>
                PersonalWindowsRegistration.Install(
                    scenario.Layout,
                    "subkey-v1",
                    context));
            AssertFalse(File.Exists(context.DesktopShortcutPath));
            AssertFalse(File.Exists(context.StartMenuShortcutPath));
            using var preserved = Registry.CurrentUser.OpenSubKey(
                context.RegistrySubKey + "\\unexpected",
                writable: false);
            AssertTrue(preserved is not null);
            AssertEqual("preserve", preserved!.GetValue("marker") as string);
        }
        finally
        {
            DeleteRegistrationFixture(context);
        }
        return Task.CompletedTask;
    }

    private static async Task RegistrationFailureRetryAsync()
    {
        using var scenario = new Scenario("registration-retry");
        var original = scenario.CreatePayload(1, "personal-registration-v1", "stub-v1");
        await CompleteAsync(scenario, original);
        var originalHash = FileSha256(scenario.Layout.StartupStubPath);
        var replacement = original with
        {
            StartupStub = Encoding.UTF8.GetBytes("replacement-stub"),
        };
        var failing = scenario.CreateService(registerFailure: true);
        await AssertThrowsAsync<IOException>(() => failing.PrepareForTestsAsync(
            replacement,
            scenario.Trust,
            GetFreePort()));
        await failing.RollbackStableStubAfterFailureAsync();
        AssertEqual(originalHash, FileSha256(scenario.Layout.StartupStubPath));
        var retried = await scenario.CreateService().PrepareForTestsAsync(
            replacement,
            scenario.Trust,
            GetFreePort());
        AssertTrue(retried.AlreadyCompleted);
    }

    private static async Task CleanFailureStubRemovalAsync()
    {
        using var scenario = new Scenario("clean-stub-removal");
        var payload = scenario.CreatePayload(1, "personal-clean-failure-v1", "stub-v1");
        var failing = scenario.CreateService(registerFailure: true);
        await AssertThrowsAsync<IOException>(() => failing.PrepareForTestsAsync(
            payload,
            scenario.Trust,
            GetFreePort()));
        await failing.RollbackStableStubAfterFailureAsync();
        AssertFalse(File.Exists(scenario.Layout.StartupStubPath));
        var resumed = await scenario.CreateService().PrepareForTestsAsync(
            payload,
            scenario.Trust,
            GetFreePort());
        AssertTrue(resumed.RequiresHealthValidation);
    }

    private static async Task CleanRegistrationPartialFailureAsync()
    {
        using var scenario = new Scenario("clean-registration");
        var context = CreateRegistrationContext(scenario);
        var payload = scenario.CreatePayload(
            1,
            "personal-clean-registration-v1",
            "stub-v1");
        var failingContext = context with
        {
            InstallObserver = stage =>
            {
                if (stage == PersonalWindowsRegistrationInstallStage.RegistryNoRepairWritten)
                {
                    throw new IOException("simulated late clean registration failure");
                }
            },
        };
        try
        {
            var failing = scenario.CreateWindowsRegistrationService(failingContext);
            await AssertThrowsAsync<IOException>(() => failing.PrepareForTestsAsync(
                payload,
                scenario.Trust,
                GetFreePort()));
            AssertRegistrationAbsent(context);
            var pointer = new PersonalReleaseSetPointerStore(scenario.Layout).ReadRequired();
            AssertEqual(PersonalReleaseHealthStates.Pending, pointer.Current.HealthState);
            var journal = new PersonalInstallMigrationJournalStore(
                scenario.Layout,
                scenario.Clock).TryRead()
                ?? throw new InvalidOperationException("Expected resumable clean journal.");
            AssertEqual(
                PersonalInstallMigrationJournalState.PointerActivatedPhase,
                journal.Phase);

            await failing.RollbackStableStubAfterFailureAsync();
            AssertFalse(File.Exists(scenario.Layout.StartupStubPath));
            AssertRegistrationAbsent(context);

            var resumedService = scenario.CreateWindowsRegistrationService(context);
            var resumed = await resumedService.PrepareForTestsAsync(
                payload,
                scenario.Trust,
                GetFreePort());
            AssertTrue(resumed.RequiresHealthValidation);
            await PassInstallerHealthAsync(scenario.Layout);
            _ = await resumedService.CompleteAfterHealthAsync(
                resumed.ReleaseSetId,
                resumed.ManifestSha256);
            _ = PersonalWindowsRegistration.ReadAndValidate(
                scenario.Layout,
                "personal-clean-registration-v1",
                context);
        }
        finally
        {
            DeleteRegistrationFixture(context);
        }
    }

    private static async Task FailedHealthNewerTakeoverAsync()
    {
        using var scenario = new Scenario("failed-health-takeover");
        var first = scenario.CreatePayload(1, "personal-failed-v1", "stub-v1");
        var firstService = scenario.CreateService();
        _ = await firstService.PrepareForTestsAsync(
            first,
            scenario.Trust,
            GetFreePort());
        var failed = await new PersonalBootstrapHealthGate(
                scenario.Layout,
                TimeSpan.FromSeconds(5))
            .EnsureInstallerHealthyAsync((_, _, _, _) => Task.FromResult(17));
        AssertFalse(failed.Healthy);
        await firstService.RollbackStableStubAfterFailureAsync(
            abandonPendingCandidate: true);
        AssertTrue(new PersonalInstallMigrationJournalStore(
            scenario.Layout,
            scenario.Clock).TryRead() is null);
        AssertFalse(Directory.Exists(scenario.Layout.ManagedRoot));

        var second = scenario.CreatePayload(2, "personal-failed-v2", "stub-v2");
        var secondService = scenario.CreateService();
        var prepared = await secondService.PrepareForTestsAsync(
            second,
            scenario.Trust,
            GetFreePort());
        AssertTrue(prepared.RequiresHealthValidation);
        await PassInstallerHealthAsync(scenario.Layout);
        _ = await secondService.CompleteAfterHealthAsync(
            prepared.ReleaseSetId,
            prepared.ManifestSha256);
        AssertEqual(
            "personal-failed-v2",
            new PersonalReleaseSetPointerStore(scenario.Layout)
                .ReadRequired().Current.ReleaseSetId);
    }

    private static async Task LegacyHealthFailureAsync()
    {
        using var scenario = new Scenario("legacy-health-fail");
        CreateExactLegacyTree(scenario.Layout);
        var first = scenario.CreatePayload(1, "personal-legacy-failed-v1", "stub-v1");
        var firstService = scenario.CreateService();
        var prepared = await firstService.PrepareForTestsAsync(
            first,
            scenario.Trust,
            GetFreePort());
        var legacyQuarantine = prepared.LegacyQuarantinePath
            ?? throw new InvalidOperationException("Expected legacy quarantine path.");
        var failed = await new PersonalBootstrapHealthGate(
                scenario.Layout,
                TimeSpan.FromSeconds(5))
            .EnsureInstallerHealthyAsync((_, _, _, _) => Task.FromResult(29));
        AssertFalse(failed.Healthy);
        await firstService.RollbackStableStubAfterFailureAsync(
            abandonPendingCandidate: true);

        AssertTrue(new PersonalInstallMigrationJournalStore(
            scenario.Layout,
            scenario.Clock).TryRead() is null);
        AssertFalse(Directory.Exists(scenario.Layout.ManagedRoot));
        AssertTrue(Directory.Exists(legacyQuarantine));
        AssertTrue(File.Exists(Path.Combine(
            legacyQuarantine,
            "launcher.settings.json")));
        var failedQuarantine = Path.Combine(
            Path.GetDirectoryName(scenario.Layout.ManagedRoot)!,
            "DshLauncherFailedInstallQuarantine");
        var failedRoots = Directory.GetDirectories(failedQuarantine);
        AssertEqual(1, failedRoots.Length);

        var second = scenario.CreatePayload(2, "personal-legacy-failed-v2", "stub-v2");
        await CompleteAsync(scenario, second);
        AssertHealthyInstall(scenario, second);
        AssertTrue(Directory.Exists(legacyQuarantine));
        AssertTrue(Directory.Exists(failedRoots[0]));
    }

    private static async Task LegacyRegistrationFailureAsync()
    {
        using var scenario = new Scenario("legacy-register-fail");
        CreateExactLegacyTree(scenario.Layout);
        var payload = scenario.CreatePayload(1, "personal-legacy-register-v1", "stub-v1");
        var context = CreateRegistrationContext(scenario);
        var failingContext = context with
        {
            InstallObserver = stage =>
            {
                if (stage == PersonalWindowsRegistrationInstallStage.RegistryFlushed)
                {
                    throw new IOException("simulated late legacy registration failure");
                }
            },
        };
        try
        {
            var failing = scenario.CreateWindowsRegistrationService(failingContext);
            await AssertThrowsAsync<IOException>(() => failing.PrepareForTestsAsync(
                payload,
                scenario.Trust,
                GetFreePort()));
            AssertRegistrationAbsent(context);
            var state = new PersonalInstallMigrationJournalStore(
                scenario.Layout,
                scenario.Clock).TryRead()
                ?? throw new InvalidOperationException("Expected resumable legacy journal.");
            var legacyQuarantine = state.LegacyQuarantinePath
                ?? throw new InvalidOperationException("Expected legacy quarantine path.");
            AssertEqual(
                PersonalInstallMigrationJournalState.PointerActivatedPhase,
                state.Phase);
            await failing.RollbackStableStubAfterFailureAsync();
            AssertFalse(File.Exists(scenario.Layout.StartupStubPath));
            AssertRegistrationAbsent(context);
            AssertTrue(Directory.Exists(legacyQuarantine));
            AssertTrue(File.Exists(Path.Combine(
                legacyQuarantine,
                "snapshots",
                "snapshot.bin")));

            var resumedService = scenario.CreateWindowsRegistrationService(context);
            var resumed = await resumedService.PrepareForTestsAsync(
                payload,
                scenario.Trust,
                GetFreePort());
            AssertTrue(resumed.RequiresHealthValidation);
            await PassInstallerHealthAsync(scenario.Layout);
            _ = await resumedService.CompleteAfterHealthAsync(
                resumed.ReleaseSetId,
                resumed.ManifestSha256);
            AssertHealthyInstall(scenario, payload);
            _ = PersonalWindowsRegistration.ReadAndValidate(
                scenario.Layout,
                "personal-legacy-register-v1",
                context);
            AssertTrue(Directory.Exists(legacyQuarantine));
        }
        finally
        {
            DeleteRegistrationFixture(context);
        }
    }

    private static async Task ProvenanceLossUninstallReinstallAsync()
    {
        using var scenario = new Scenario("uninstall-reinstall");
        var first = scenario.CreatePayload(1, "personal-uninstall-v1", "stub-v1");
        await CompleteAsync(scenario, first);
        var provenance = new PersonalInstallProvenanceStore(
            scenario.Layout,
            scenario.Clock);
        File.Delete(provenance.PrimaryPath);
        Directory.Delete(scenario.Layout.ManagedRoot, recursive: true);
        var second = scenario.CreatePayload(2, "personal-uninstall-v2", "stub-v2");
        var prepared = await scenario.CreateService().PrepareForTestsAsync(
            second,
            scenario.Trust,
            GetFreePort());
        AssertTrue(File.Exists(provenance.PrimaryPath));
        AssertTrue(prepared.RequiresHealthValidation);
    }

    private static async Task InstallerHealthAdmissionAsync()
    {
        using var scenario = new Scenario("health-admission");
        await AssertThrowsAsync<InvalidDataException>(() =>
            new PersonalBootstrapHealthGate(scenario.Layout)
                .EnsureInstallerHealthyAsync((_, _, _, _) => Task.FromResult(0)));
        _ = await scenario.CreateService().PrepareForTestsAsync(
            scenario.CreatePayload(1, "personal-health-command-v1", "stub-v1"),
            scenario.Trust,
            GetFreePort());
        await PassInstallerHealthAsync(scenario.Layout);
    }

    private static async Task ProcessGuardAsync()
    {
        using var scenario = new Scenario("process-guard");
        var service = scenario.CreateService(processFailure: true);
        await AssertThrowsAsync<InvalidOperationException>(() =>
            service.PrepareForTestsAsync(
                scenario.CreatePayload(1, "personal-process-v1", "stub-v1"),
                scenario.Trust,
                GetFreePort()));
        AssertTrue(new PersonalInstallMigrationJournalStore(
            scenario.Layout,
            scenario.Clock).TryRead() is null);
    }

    private static async Task InstallCheckpointResumeAsync()
    {
        var checkpoints = new[]
        {
            PersonalInstallMigrationCheckpoint.JournalCreated,
            PersonalInstallMigrationCheckpoint.PayloadStaged,
            PersonalInstallMigrationCheckpoint.LegacyQuarantined,
            PersonalInstallMigrationCheckpoint.SecurityAdmitted,
            PersonalInstallMigrationCheckpoint.ComponentsInstalled,
            PersonalInstallMigrationCheckpoint.StartupStubInstalled,
            PersonalInstallMigrationCheckpoint.PointerActivated,
            PersonalInstallMigrationCheckpoint.RegistrationInstalled,
            PersonalInstallMigrationCheckpoint.AwaitingHealth,
        };
        foreach (var checkpoint in checkpoints)
        {
            using var scenario = new Scenario("checkpoint-" + checkpoint);
            var payload = scenario.CreatePayload(1, $"personal-{checkpoint.ToString().ToLowerInvariant()}-v1", "stub-v1");
            var crashed = false;
            var service = scenario.CreateService(checkpoint: observed =>
            {
                if (!crashed && observed == checkpoint)
                {
                    crashed = true;
                    throw new SimulatedCrashException(checkpoint.ToString());
                }
            });
            await AssertThrowsAsync<SimulatedCrashException>(() =>
                service.PrepareForTestsAsync(payload, scenario.Trust, GetFreePort()));
            AssertTrue(crashed);
            if (checkpoint >= PersonalInstallMigrationCheckpoint.SecurityAdmitted)
            {
                scenario.Clock.SetUtcNow(Now.AddDays(-2));
            }
            var resumed = await scenario.CreateService().PrepareForTestsAsync(
                payload,
                scenario.Trust,
                GetFreePort());
            if (resumed.RequiresHealthValidation)
            {
                await PassInstallerHealthAsync(scenario.Layout);
                _ = await scenario.CreateService().CompleteAfterHealthAsync(
                    resumed.ReleaseSetId,
                    resumed.ManifestSha256);
            }
            AssertHealthyInstall(scenario, payload);
        }

        foreach (var checkpoint in new[]
        {
            PersonalInstallMigrationCheckpoint.LegacyAuthorizedBeforeMove,
            PersonalInstallMigrationCheckpoint.LegacyMovedBeforeJournal,
        })
        {
            using var scenario = new Scenario("legacy-checkpoint-" + checkpoint);
            CreateExactLegacyTree(scenario.Layout);
            var payload = scenario.CreatePayload(1, $"personal-legacy-{checkpoint.ToString().ToLowerInvariant()}-v1", "stub-v1");
            var crashed = false;
            await AssertThrowsAsync<SimulatedCrashException>(() =>
                scenario.CreateService(checkpoint: observed =>
                {
                    if (!crashed && observed == checkpoint)
                    {
                        crashed = true;
                        throw new SimulatedCrashException(checkpoint.ToString());
                    }
                }).PrepareForTestsAsync(payload, scenario.Trust, GetFreePort()));
            var resumed = await scenario.CreateService().PrepareForTestsAsync(
                payload,
                scenario.Trust,
                GetFreePort());
            AssertTrue(resumed.LegacyQuarantinePath is not null);
            if (resumed.RequiresHealthValidation)
            {
                await PassInstallerHealthAsync(scenario.Layout);
                _ = await scenario.CreateService().CompleteAfterHealthAsync(
                    resumed.ReleaseSetId,
                    resumed.ManifestSha256);
            }
            AssertHealthyInstall(scenario, payload);
        }

        using (var scenario = new Scenario("completed-checkpoint"))
        {
            var payload = scenario.CreatePayload(1, "personal-completed-checkpoint-v1", "stub-v1");
            var service = scenario.CreateService(checkpoint: observed =>
            {
                if (observed == PersonalInstallMigrationCheckpoint.Completed)
                {
                    throw new SimulatedCrashException("completed");
                }
            });
            var prepared = await service.PrepareForTestsAsync(
                payload,
                scenario.Trust,
                GetFreePort());
            await PassInstallerHealthAsync(scenario.Layout);
            await AssertThrowsAsync<SimulatedCrashException>(() =>
                service.CompleteAfterHealthAsync(
                    prepared.ReleaseSetId,
                    prepared.ManifestSha256));
            var resumed = await scenario.CreateService().PrepareForTestsAsync(
                payload,
                scenario.Trust,
                GetFreePort());
            AssertTrue(resumed.AlreadyCompleted);
            AssertHealthyInstall(scenario, payload);
        }
    }

    private static async Task FailureCheckpointResumeAsync()
    {
        var checkpoints = new[]
        {
            PersonalInstallMigrationCheckpoint.HealthFailureMarked,
            PersonalInstallMigrationCheckpoint.FailedPointerRolledBack,
            PersonalInstallMigrationCheckpoint.FailureProvenanceWritten,
            PersonalInstallMigrationCheckpoint.FailedRootQuarantined,
            PersonalInstallMigrationCheckpoint.FailureRegistrationRestored,
            PersonalInstallMigrationCheckpoint.FailureJournalRetired,
        };
        foreach (var checkpoint in checkpoints)
        {
            using var scenario = new Scenario("failure-checkpoint-" + checkpoint);
            var first = scenario.CreatePayload(1, $"personal-failure-{checkpoint.ToString().ToLowerInvariant()}-v1", "stub-v1");
            var crashed = false;
            var service = scenario.CreateService(checkpoint: observed =>
            {
                if (!crashed && observed == checkpoint)
                {
                    crashed = true;
                    throw new SimulatedCrashException(checkpoint.ToString());
                }
            });
            _ = await service.PrepareForTestsAsync(first, scenario.Trust, GetFreePort());
            await AssertThrowsAsync<SimulatedCrashException>(() =>
                service.RollbackStableStubAfterFailureAsync(
                    abandonPendingCandidate: true));

            var second = scenario.CreatePayload(2, $"personal-failure-{checkpoint.ToString().ToLowerInvariant()}-v2", "stub-v2");
            var resumed = await scenario.CreateService().PrepareForTestsAsync(
                second,
                scenario.Trust,
                GetFreePort());
            AssertTrue(resumed.RequiresHealthValidation);
            var failedQuarantine = Path.Combine(
                Path.GetDirectoryName(scenario.Layout.ManagedRoot)!,
                "DshLauncherFailedInstallQuarantine");
            AssertTrue(Directory.Exists(failedQuarantine));
            var preservedFailures = Directory.GetDirectories(failedQuarantine);
            AssertEqual(1, preservedFailures.Length);
            await PassInstallerHealthAsync(scenario.Layout);
            _ = await scenario.CreateService().CompleteAfterHealthAsync(
                resumed.ReleaseSetId,
                resumed.ManifestSha256);
            AssertHealthyInstall(scenario, second);
            AssertTrue(Directory.Exists(preservedFailures[0]));
        }
    }

    private static async Task JournalTamperRejectedAsync()
    {
        using var scenario = new Scenario("journal-tamper");
        var payload = scenario.CreatePayload(1, "personal-journal-tamper-v1", "stub-v1");
        await AssertThrowsAsync<SimulatedCrashException>(() =>
            scenario.CreateService(checkpoint: observed =>
            {
                if (observed == PersonalInstallMigrationCheckpoint.JournalCreated)
                {
                    throw new SimulatedCrashException("journal");
                }
            }).PrepareForTestsAsync(payload, scenario.Trust, GetFreePort()));
        var store = new PersonalInstallMigrationJournalStore(scenario.Layout, scenario.Clock);
        var bytes = File.ReadAllBytes(store.JournalPath);
        bytes[bytes.Length / 2] ^= 0x5a;
        File.WriteAllBytes(store.JournalPath, bytes);
        AssertThrows<InvalidDataException>(() => store.TryRead());
    }

    private static async Task LegacyShapeTamperRejectedAsync()
    {
        using (var scenario = new Scenario("legacy-extra"))
        {
            CreateExactLegacyTree(scenario.Layout);
            File.WriteAllText(Path.Combine(scenario.Layout.ManagedRoot, "unexpected.bin"), "x");
            await AssertThrowsAsync<InvalidDataException>(() =>
                scenario.CreateService().PrepareForTestsAsync(
                    scenario.CreatePayload(1, "personal-legacy-extra-v1", "stub-v1"),
                    scenario.Trust,
                    GetFreePort()));
        }
        using (var scenario = new Scenario("legacy-wrong-state"))
        {
            CreateExactLegacyTree(scenario.Layout);
            File.WriteAllText(Path.Combine(scenario.Layout.ManagedRoot, "state", "extra.json"), "{}");
            await AssertThrowsAsync<InvalidDataException>(() =>
                scenario.CreateService().PrepareForTestsAsync(
                    scenario.CreatePayload(1, "personal-legacy-wrong-v1", "stub-v1"),
                    scenario.Trust,
                    GetFreePort()));
        }
        using (var scenario = new Scenario("legacy-reparse"))
        {
            CreateExactLegacyTree(scenario.Layout);
            var snapshots = Path.Combine(scenario.Layout.ManagedRoot, "snapshots");
            Directory.Delete(snapshots, recursive: true);
            var target = Path.Combine(scenario.Root, "external-snapshots");
            Directory.CreateDirectory(target);
            CreateDirectoryJunction(snapshots, target);
            try
            {
                await AssertThrowsAsync<InvalidDataException>(() =>
                    scenario.CreateService().PrepareForTestsAsync(
                        scenario.CreatePayload(1, "personal-legacy-reparse-v1", "stub-v1"),
                        scenario.Trust,
                        GetFreePort()));
            }
            finally
            {
                Directory.Delete(snapshots, recursive: false);
            }
        }
    }

    private static async Task PayloadSelfCheckAsync()
    {
        using var scenario = new Scenario("payload-self-check");
        var payload = scenario.CreatePayload(1, "personal-payload-check-v1", "stub-v1");
        var expected = Expectation(payload, scenario.Policy, Now);
        await PersonalInstallerPayloadSelfCheck.VerifyPayloadForTestsAsync(
            payload,
            scenario.Trust,
            expected);
        var installerPath = Path.Combine(scenario.Root, "development-installer.exe");
        File.WriteAllText(installerPath, "development-installer");
        using (var installerIdentity =
               PersonalAuthenticodeVerifier.AcquireExecutableIdentityLeaseForTests(
                   installerPath))
        {
            await PersonalInstallerPayloadSelfCheck.VerifyDevelopmentPayloadAsync(
                payload,
                scenario.Trust,
                installerIdentity,
                expected);
        }

        await AssertThrowsAsync<InvalidDataException>(() =>
            PersonalInstallerPayloadSelfCheck.VerifyPayloadForTestsAsync(
                payload,
                scenario.Trust,
                expected with { StartupStubSha256 = new string('f', 64) }));
        var badManifest = payload with { Manifest = payload.Manifest.ToArray() };
        badManifest.Manifest[badManifest.Manifest.Length / 2] ^= 0x01;
        await AssertThrowsAsync<InvalidDataException>(() =>
            PersonalInstallerPayloadSelfCheck.VerifyPayloadForTestsAsync(
                badManifest,
                scenario.Trust,
                expected with
                {
                    RawManifestSha256 = Sha256(badManifest.Manifest),
                }));
        var badClient = payload with { ClientBundle = payload.ClientBundle.ToArray() };
        badClient.ClientBundle[badClient.ClientBundle.Length / 2] ^= 0x01;
        await AssertThrowsAsync<InvalidDataException>(() =>
            PersonalInstallerPayloadSelfCheck.VerifyPayloadForTestsAsync(
                badClient,
                scenario.Trust,
                expected));

        var missingTree = scenario.CreatePayload(
            2,
            "personal-payload-no-tree-v2",
            "stub-v2",
            omitClientCompleteTree: true);
        await AssertThrowsAsync<InvalidDataException>(() =>
            PersonalInstallerPayloadSelfCheck.VerifyPayloadForTestsAsync(
                missingTree,
                scenario.Trust,
                Expectation(missingTree, scenario.Policy, Now)));
    }

    private static async Task PayloadSelfCheckEvidenceAsync()
    {
        using var scenario = new Scenario("payload-self-check-evidence");
        var payload = scenario.CreatePayload(
            1,
            "personal-payload-evidence-v1",
            "stub-v1");
        var expectation = Expectation(payload, scenario.Policy, Now);
        var installerPath = Path.Combine(scenario.Root, "installer-under-lease.exe");
        var installerBytes = Encoding.UTF8.GetBytes("exact-signed-installer-bytes");
        File.WriteAllBytes(installerPath, installerBytes);
        using var installerIdentity =
            PersonalAuthenticodeVerifier.AcquireExecutableIdentityLeaseForTests(
                installerPath);

        using (var unexpectedOutput = new MemoryStream())
        {
            using var machineOutput =
                PersonalInstallerProductionPayloadSelfCheckOutput.BeginForTests(
                    unexpectedOutput);
            AssertThrows<InvalidOperationException>(() =>
                Console.Out.Write("unexpected"));
            AssertThrows<InvalidOperationException>(() =>
                Console.Error.Write("unexpected"));
            AssertThrows<InvalidOperationException>(() =>
                machineOutput.WriteVerifiedResult(
                    PersonalInstallerCommandLine.ProductionPayloadSelfCheckArgument,
                    installerIdentity,
                    expectation));
            AssertEqual(0L, unexpectedOutput.Length);
        }

        byte[] actual;
        using (var output = new MemoryStream())
        {
            using (var machineOutput =
                   PersonalInstallerProductionPayloadSelfCheckOutput.BeginForTests(output))
            {
                machineOutput.WriteVerifiedResult(
                    PersonalInstallerCommandLine.ProductionPayloadSelfCheckArgument,
                    installerIdentity,
                    expectation);
                AssertThrows<InvalidOperationException>(() =>
                    machineOutput.WriteVerifiedResult(
                        PersonalInstallerCommandLine.ProductionPayloadSelfCheckArgument,
                        installerIdentity,
                        expectation));
            }
            actual = output.ToArray();
        }

        var installerSha256 = Sha256(installerBytes);
        var expectedJson = string.Concat(
            "{\"schemaVersion\":1,",
            "\"resultType\":\"ensou-dsh-personal-installer-production-payload-self-check\",",
            "\"command\":\"--production-payload-self-check\",",
            "\"status\":\"VERIFIED\",",
            "\"installerSha256\":\"", installerSha256, "\",",
            "\"releaseSetId\":\"", expectation.ReleaseSetId, "\",",
            "\"manifestSha256\":\"", expectation.RawManifestSha256, "\",",
            "\"manifestSizeBytes\":",
            expectation.ManifestSizeBytes.ToString(CultureInfo.InvariantCulture), ",",
            "\"startupStubSha256\":\"", expectation.StartupStubSha256, "\",",
            "\"startupStubSizeBytes\":",
            expectation.StartupStubSizeBytes.ToString(CultureInfo.InvariantCulture), ",",
            "\"clientBundleSha256\":\"", expectation.ClientBundleSha256, "\",",
            "\"clientBundleSizeBytes\":",
            expectation.ClientBundleSizeBytes.ToString(CultureInfo.InvariantCulture), ",",
            "\"runtimeSha256\":\"", expectation.RuntimeSha256, "\",",
            "\"runtimeSizeBytes\":",
            expectation.RuntimeSizeBytes.ToString(CultureInfo.InvariantCulture),
            "}\n");
        AssertSequenceEqual(Encoding.UTF8.GetBytes(expectedJson), actual);
        AssertEqual(1, actual.Count(value => value == (byte)'\n'));
        AssertFalse(actual.Contains((byte)'\r'));
        AssertFalse(actual.AsSpan().StartsWith(Encoding.UTF8.Preamble));
        using (var document = JsonDocument.Parse(actual.AsMemory(0, actual.Length - 1)))
        {
            AssertEqual(JsonValueKind.Object, document.RootElement.ValueKind);
            AssertEqual(
                14,
                document.RootElement.EnumerateObject().Count());
        }

        using (var invalidOutput = new MemoryStream())
        {
            using var machineOutput =
                PersonalInstallerProductionPayloadSelfCheckOutput.BeginForTests(
                    invalidOutput);
            AssertThrows<InvalidDataException>(() =>
                machineOutput.WriteVerifiedResult(
                    PersonalInstallerCommandLine.ProductionPayloadSelfCheckArgument,
                    installerIdentity,
                    expectation with
                    {
                        RawManifestSha256 = new string('F', 64),
                    }));
            AssertEqual(0L, invalidOutput.Length);
        }

        using (var concurrentOutput = new MemoryStream())
        using (var reachedCommit = new ManualResetEventSlim(initialState: false))
        using (var continueCommit = new ManualResetEventSlim(initialState: false))
        {
            using var machineOutput =
                PersonalInstallerProductionPayloadSelfCheckOutput.BeginForTests(
                    concurrentOutput,
                    () =>
                    {
                        reachedCommit.Set();
                        if (!continueCommit.Wait(TimeSpan.FromSeconds(30)))
                        {
                            throw new TimeoutException(
                                "Timed out waiting to exercise the concurrent output gate.");
                        }
                    });
            var writeTask = Task.Run(() => machineOutput.WriteVerifiedResult(
                PersonalInstallerCommandLine.ProductionPayloadSelfCheckArgument,
                installerIdentity,
                expectation));
            AssertTrue(reachedCommit.Wait(TimeSpan.FromSeconds(30)));
            try
            {
                AssertThrows<InvalidOperationException>(() =>
                    Console.Out.Write("concurrent-unexpected"));
            }
            finally
            {
                continueCommit.Set();
            }
            await AssertThrowsAsync<InvalidOperationException>(() => writeTask);
            AssertEqual(0L, concurrentOutput.Length);
        }
    }

    private static async Task InstallationIdentityLifecycleAsync()
    {
        using var first = new Scenario("identity-first");
        var firstPrepared = await CompleteAsync(
            first,
            first.CreatePayload(1, "personal-identity-v1", "stub-v1"));
        var firstPointer = new PersonalReleaseSetPointerStore(first.Layout).ReadRequired();
        AssertEqual(3, firstPointer.SchemaVersion);
        var initialIdentity = new PersonalInstallationIdentityStore(
            first.Layout,
            first.Clock).GetOrCreate();
        var equivalentCaseLayout = new PersonalInstallationLayout(
            first.Layout.ManagedRoot.ToLowerInvariant(),
            first.Layout.HarnessHome.ToLowerInvariant());
        var equivalentCaseIdentity = new PersonalInstallationIdentityStore(
            equivalentCaseLayout,
            first.Clock).ReadRequired(
                initialIdentity.InstallationId,
                initialIdentity.ReceiptSha256);
        AssertEqual(initialIdentity.InstallationId, equivalentCaseIdentity.InstallationId);
        AssertTrue(File.Exists(first.Layout.InstallationIdentityReceiptPath));
        AssertTrue(File.Exists(first.Layout.InstallationIdentityProtectedPath));
        var receiptText = File.ReadAllText(first.Layout.InstallationIdentityReceiptPath);
        AssertFalse(receiptText.Contains("token", StringComparison.OrdinalIgnoreCase));
        AssertFalse(receiptText.Contains("secret", StringComparison.OrdinalIgnoreCase));

        var secondPrepared = await CompleteAsync(
            first,
            first.CreatePayload(2, "personal-identity-v2", "stub-v2"));
        AssertFalse(string.Equals(
            firstPrepared.ReleaseSetId,
            secondPrepared.ReleaseSetId,
            StringComparison.Ordinal));
        var upgradedIdentity = new PersonalInstallationIdentityStore(
            first.Layout,
            first.Clock).GetOrCreate();
        AssertEqual(initialIdentity.InstallationId, upgradedIdentity.InstallationId);
        AssertEqual(initialIdentity.ReceiptSha256, upgradedIdentity.ReceiptSha256);

        using var second = new Scenario("identity-second");
        await CompleteAsync(
            second,
            second.CreatePayload(1, "personal-identity-other-v1", "stub-v1"));
        var independent = new PersonalInstallationIdentityStore(
            second.Layout,
            second.Clock).GetOrCreate();
        AssertFalse(string.Equals(
            initialIdentity.InstallationId,
            independent.InstallationId,
            StringComparison.Ordinal));
        AssertFalse(string.Equals(
            initialIdentity.StateBindingSha256,
            independent.StateBindingSha256,
            StringComparison.Ordinal));

        using var reinstalled = new Scenario("identity-reinstall");
        var reinstallStore = new PersonalInstallationIdentityStore(
            reinstalled.Layout,
            reinstalled.Clock);
        var beforeCleanInstall = reinstallStore.GetOrCreate();
        Directory.Delete(reinstalled.Layout.ManagedRoot, recursive: true);
        var afterCleanInstall = reinstallStore.GetOrCreate();
        AssertFalse(string.Equals(
            beforeCleanInstall.InstallationId,
            afterCleanInstall.InstallationId,
            StringComparison.Ordinal));
        AssertFalse(string.Equals(
            beforeCleanInstall.StateBindingSha256,
            afterCleanInstall.StateBindingSha256,
            StringComparison.Ordinal));
    }

    private static Task InstallationIdentityCopyAndTamperRejectedAsync()
    {
        using var source = new Scenario("identity-source");
        var sourceStore = new PersonalInstallationIdentityStore(source.Layout, source.Clock);
        var sourceIdentity = sourceStore.GetOrCreate();

        using var copied = new Scenario("identity-copied");
        copied.Layout.EnsureManagedRoots();
        File.Copy(
            source.Layout.InstallationIdentityReceiptPath,
            copied.Layout.InstallationIdentityReceiptPath);
        File.Copy(
            source.Layout.InstallationIdentityProtectedPath,
            copied.Layout.InstallationIdentityProtectedPath);
        AssertThrows<InvalidDataException>(() =>
            new PersonalInstallationIdentityStore(copied.Layout, copied.Clock)
                .GetOrCreate());

        using var publicOnly = new Scenario("identity-public");
        publicOnly.Layout.EnsureManagedRoots();
        File.Copy(
            source.Layout.InstallationIdentityReceiptPath,
            publicOnly.Layout.InstallationIdentityReceiptPath);
        AssertThrows<InvalidDataException>(() =>
            new PersonalInstallationIdentityStore(publicOnly.Layout, publicOnly.Clock)
                .GetOrCreate());

        var tampered = JsonNode.Parse(
            File.ReadAllBytes(source.Layout.InstallationIdentityReceiptPath))!.AsObject();
        tampered["installationId"] = Guid.NewGuid().ToString("D");
        File.WriteAllText(
            source.Layout.InstallationIdentityReceiptPath,
            tampered.ToJsonString(new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        AssertThrows<InvalidDataException>(() => sourceStore.ReadRequired(
            sourceIdentity.InstallationId,
            sourceIdentity.ReceiptSha256));
        return Task.CompletedTask;
    }

    private static async Task InstallationIdentityPointerV3CompatibilityAsync()
    {
        using var scenario = new Scenario(
            "identity-pointer-v3",
            startupStubVersion: "1.1.0");
        await CompleteAsync(
            scenario,
            scenario.CreatePayload(1, "personal-identity-pointer-v3", "stub-v1"));
        var bytes = File.ReadAllBytes(scenario.Layout.ReleaseSetPointerPath);
        var pointerNode = JsonNode.Parse(bytes)!.AsObject();
        AssertEqual(3, pointerNode["schemaVersion"]!.GetValue<int>());
        AssertFalse(pointerNode.ContainsKey("installationId"));
        AssertFalse(pointerNode.ContainsKey("installationIdentityReceiptSha256"));
        var legacyReader = JsonSerializer.Deserialize<LegacyPersonalPointerV3>(
            bytes,
            new JsonSerializerOptions(JsonSerializerDefaults.Web)
            {
                PropertyNameCaseInsensitive = false,
                UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            });
        AssertTrue(legacyReader is not null);
        AssertEqual(3, legacyReader!.SchemaVersion);
        AssertTrue(File.Exists(scenario.Layout.InstallationIdentityReceiptPath));
        AssertTrue(File.Exists(scenario.Layout.InstallationIdentityProtectedPath));

        File.Delete(scenario.Layout.InstallationIdentityReceiptPath);
        File.Delete(scenario.Layout.InstallationIdentityProtectedPath);
        AssertEqual(
            PersonalLegacyInstallClassification.ManagedV2,
            PersonalInstallPreflightTests.RequireReadyForManagedScenario(
                scenario.Layout).ExistingInstall);
        AssertThrows<InvalidDataException>(() =>
            new PersonalInstallationIdentityStore(
                scenario.Layout,
                scenario.Clock).GetOrCreate());
        await CompleteAsync(
            scenario,
            scenario.CreatePayload(
                2,
                "personal-identity-pointer-v3-migrated",
                "stub-v2",
                minimumStartupStubVersion: "1.1.0"));
        var adoptedIdentity = new PersonalInstallationIdentityStore(
            scenario.Layout,
            scenario.Clock).GetOrCreate();
        PersonalInstallationIdentityStore.RequireCanonicalInstallationId(
            adoptedIdentity.InstallationId);
        AssertTrue(File.Exists(scenario.Layout.InstallationIdentityReceiptPath));
        AssertTrue(File.Exists(scenario.Layout.InstallationIdentityProtectedPath));

        File.Delete(scenario.Layout.InstallationIdentityReceiptPath);
        File.Delete(scenario.Layout.InstallationIdentityProtectedPath);
        PersonalInstallPreflightTests.AssertManagedScenarioIsManualConflict(
            scenario.Layout);
        AssertThrows<InvalidDataException>(() =>
            new PersonalInstallationIdentityStore(
                scenario.Layout,
                scenario.Clock).GetOrCreate());
    }

    private static Task CompiledTrustMismatchAsync()
    {
        using var scenario = new Scenario("compiled-trust-mismatch");
        var other = scenario.Trust with
        {
            ManifestOrigin = new Uri("https://other.example.test/"),
        };
        AssertThrows<InvalidOperationException>(() =>
            PersonalAuthenticodeVerifier.RequireMatchingCompiledTrustForTests(
                scenario.Trust,
                other));
        return Task.CompletedTask;
    }

    private static Task CompiledClientTrustFingerprintAsync()
    {
        using var scenario = new Scenario("compiled-client-trust");
        var signer = new string('A', 64);
        var production = scenario.Trust with
        {
            ProductionBuild = true,
            AuthenticodeSignerSha256Thumbprint = signer,
        };
        var expected = PersonalCompiledTrustFingerprint.Create(production);
        var canonical = expected.SerializeCanonical();
        try
        {
            AssertEqual(
                expected,
                PersonalCompiledTrustFingerprint.ParseCanonical(canonical));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }

        var key = production.ReleasePolicy.TrustedKeys[0];
        var mismatches = new[]
        {
            production with
            {
                ProductionBuild = false,
                AuthenticodeSignerSha256Thumbprint = null,
            },
            production with
            {
                ManifestOrigin = new Uri("https://wrong-manifest.example.test/"),
            },
            production with
            {
                ReleasePolicy = production.ReleasePolicy with
                {
                    ArtifactOrigin = new Uri("https://wrong-artifact.example.test/"),
                },
            },
            production with
            {
                ReleasePolicy = production.ReleasePolicy with
                {
                    Channel = "pilot",
                },
            },
            production with
            {
                ReleasePolicy = production.ReleasePolicy with
                {
                    TrustedKeys =
                    [
                        key with { KeyId = "wrong-release-key" },
                    ],
                },
            },
            production with
            {
                AuthenticodeSignerSha256Thumbprint = new string('B', 64),
            },
        };
        foreach (var mismatch in mismatches)
        {
            AssertThrows<InvalidDataException>(() =>
                PersonalCompiledTrustFingerprint.RequireMatches(
                    expected,
                    PersonalCompiledTrustFingerprint.Create(mismatch),
                    "test client"));
        }
        return Task.CompletedTask;
    }

    private static Task InstallerIdentityLeaseAsync()
    {
        using var scenario = new Scenario("installer-identity");
        var executable = Path.Combine(scenario.Root, "Ensou.Dsh.Personal.Installer.exe");
        var replacement = Path.Combine(scenario.Root, "replacement.exe");
        File.WriteAllText(executable, "original-installer");
        File.WriteAllText(replacement, "replacement-installer");

        using (PersonalAuthenticodeVerifier.AcquireExecutableIdentityLeaseForTests(executable))
        {
            AssertSharingViolation(() => File.Delete(executable));
            AssertSharingViolation(() => File.Move(replacement, executable, overwrite: true));
            AssertEqual("original-installer", File.ReadAllText(executable));
            AssertTrue(File.Exists(replacement));
        }

        File.Move(replacement, executable, overwrite: true);
        AssertEqual("replacement-installer", File.ReadAllText(executable));
        return Task.CompletedTask;
    }

    private static Task CompiledTrustProcessLeaseAsync()
    {
        using var scenario = new Scenario("compiled-process-lease");
        var path = Path.Combine(
            scenario.Root,
            PersonalInstallationLayout.ClientBootstrapperExecutableName);
        File.Copy(
            Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            path,
            overwrite: false);
        var replacement = Path.Combine(scenario.Root, "replacement.exe");
        File.WriteAllText(replacement, "replacement");
        var observed = false;
        try
        {
            _ = PersonalCompiledTrustProcessVerifier.RequireExecutableForTests(
                path,
                PersonalInstallationLayout.ClientBootstrapperExecutableName,
                PersonalCompiledTrustFingerprint.Create(scenario.Trust),
                () =>
                {
                    observed = true;
                    AssertSharingViolation(() => File.Move(
                        replacement,
                        path,
                        overwrite: true));
                });
        }
        catch
        {
            // cmd.exe is deliberately not a Personal self-check binary. The
            // assertion above proves the verified lease spans path execution.
        }
        AssertTrue(observed);
        AssertTrue(File.Exists(replacement));
        return Task.CompletedTask;
    }

    private static async Task<PersonalInstallPreparationResult> CompleteAsync(
        Scenario scenario,
        TestPayload payload)
    {
        var service = scenario.CreateService();
        var prepared = await service.PrepareForTestsAsync(
            payload,
            scenario.Trust,
            GetFreePort());
        if (prepared.RequiresHealthValidation)
        {
            await PassInstallerHealthAsync(scenario.Layout);
            _ = await service.CompleteAfterHealthAsync(
                prepared.ReleaseSetId,
                prepared.ManifestSha256);
        }
        return prepared;
    }

    private static async Task PassInstallerHealthAsync(PersonalInstallationLayout layout)
    {
        using var trace = new InstallerFixtureHealthTrace(_traceInstallerHealth);
        var coordinator = new PersonalReleaseHealthCoordinator(layout);
        var result = await new PersonalBootstrapHealthGate(
                layout,
                TimeSpan.FromSeconds(5),
                trace.Mark)
            .EnsureInstallerHealthyAsync((_, token, _, cancellationToken) =>
            {
                trace.MarkCancellation("fixture_callback_begin", cancellationToken);
                CompleteFixtureHomeHealthAttemptIfRequired(layout, token, trace);
                trace.MarkCancellation("fixture_home_released", cancellationToken);
                coordinator.WriteSignal(
                    token,
                    Environment.ProcessId,
                    new string('a', 64));
                trace.MarkCancellation("fixture_signal_written", cancellationToken);
                return Task.FromResult(0);
            });
        if (!result.Healthy)
        {
            var pointer = new PersonalReleaseSetPointerStore(layout).TryRead();
            var channel = pointer?.Channel ?? "stable";
            PersonalReleaseSecurityState? security = null;
            try
            {
                security = await new PersonalReleaseSecurityStateStore(
                        layout.UpdateSecurityStatePath,
                        new PersonalReleaseStateIdentity(
                            PersonalReleaseSetContract.Product,
                            PersonalReleaseSetContract.ProductionEnvironment,
                            channel),
                        layout.UpdateSecurityWitnessPath)
                    .TryReadAsync();
            }
            catch
            {
                // Preserve the health result as the primary test diagnostic.
            }
            throw new InvalidOperationException(
                "Installer health failed: " + result.Detail
                + "; quarantine="
                + string.Join(",", security?.FailedReleaseQuarantine.Select(item => item.ReasonCode)
                    ?? Array.Empty<string>()));
        }
        trace.Succeeded = true;
    }

    private static void CompleteFixtureHomeHealthAttemptIfRequired(
        PersonalInstallationLayout layout,
        string healthToken,
        InstallerFixtureHealthTrace? trace = null)
    {
        trace?.Mark("fixture_pointer_begin");
        var pointer = new PersonalReleaseSetPointerStore(layout).ReadRequired();
        trace?.Mark("fixture_pointer_end");
        var homeMode = PersonalReleaseSetPointerStore
            .GetPendingHomeTransactionMode(pointer);
        if (homeMode == PersonalReleaseHomeTransactionMode.NoneRuntimeReused)
        {
            return;
        }
        AssertEqual(pointer.Current.HealthToken, healthToken);
        var transactionId = pointer.Current.HomeTransactionId
            ?? throw new InvalidDataException(
                "Fixture pending release has no Harness-home transaction.");
        trace?.Mark("fixture_home_lease_begin");
        using var lease = new PersonalHarnessHomeCoordinator(layout.HarnessHome)
            .AcquireLease(static () => { });
        trace?.Mark("fixture_home_lease_acquired");
        lease.AdmitHealthAttempt(transactionId, healthToken);
        trace?.Mark("fixture_attempt_admitted");
        using (var runtimeSession = lease.BeginRuntimeSession())
        {
            // Fixture-only stand-in for the DshHostService job events; no process starts.
            runtimeSession.RecordAssignedProcess(12345, 1);
            runtimeSession.RecordJobEmpty();
        }
        trace?.Mark("fixture_session_released");
        lease.CompleteHealthAttempt(transactionId, healthToken);
        lease.RequireCompletedHealthAttempt(transactionId, healthToken);
        trace?.Mark("fixture_attempt_completed");
    }

    private static void AssertHealthyInstall(Scenario scenario, TestPayload payload)
    {
        AssertTrue(new PersonalInstallMigrationJournalStore(
            scenario.Layout,
            scenario.Clock).TryRead() is null);
        var pointer = new PersonalReleaseSetPointerStore(scenario.Layout).ReadRequired();
        var verified = PersonalReleaseSetValidator.ParseAndVerify(
            payload.Manifest,
            scenario.Policy,
            MaxUtc(Now, scenario.Clock.GetUtcNow()));
        AssertEqual(verified.Manifest.ReleaseSetId, pointer.Current.ReleaseSetId);
        AssertEqual(PersonalReleaseHealthStates.Healthy, pointer.Current.HealthState);
        AssertEqual(Sha256(payload.StartupStub), FileSha256(scenario.Layout.StartupStubPath));
        var provenance = new PersonalInstallProvenanceStore(
            scenario.Layout,
            scenario.Clock);
        AssertTrue(provenance.TryReadAndRepair() is not null);
        AssertTrue(File.Exists(provenance.PrimaryPath));
        AssertTrue(File.Exists(provenance.WitnessPath));
    }

    private static PersonalWindowsRegistrationContext CreateRegistrationContext(
        Scenario scenario) => new(
            $@"Software\Ensou\Tests\PersonalInstaller\{Guid.NewGuid():N}",
            Path.Combine(
                scenario.Root,
                "shell",
                "desktop",
                PersonalWindowsRegistration.ShortcutFileName),
            Path.Combine(
                scenario.Root,
                "shell",
                "start-menu",
                PersonalWindowsRegistration.ShortcutFileName));

    private static void PrepareRegistrationFixture(Scenario scenario)
    {
        scenario.Layout.EnsureManagedRoots();
        File.WriteAllText(scenario.Layout.StartupStubPath, "registration-test-stub");
    }

    private static TestRegistrationSnapshot CaptureRegistration(
        PersonalWindowsRegistrationContext context)
    {
        var desktop = CaptureTestFile(context.DesktopShortcutPath);
        var startMenu = CaptureTestFile(context.StartMenuShortcutPath);
        using var key = Registry.CurrentUser.OpenSubKey(
            context.RegistrySubKey,
            writable: false);
        if (key is null)
        {
            return new TestRegistrationSnapshot(desktop, startMenu, null);
        }
        var values = key.GetValueNames()
            .ToDictionary(
                name => name,
                name => new TestRegistryValue(
                    key.GetValueKind(name),
                    CloneTestRegistryValue(key.GetValue(
                            name,
                            defaultValue: null,
                            RegistryValueOptions.DoNotExpandEnvironmentNames)
                        ?? throw new InvalidDataException(
                            "Test registration value could not be read."))),
                StringComparer.Ordinal);
        return new TestRegistrationSnapshot(desktop, startMenu, values);
    }

    private static TestFileSnapshot? CaptureTestFile(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }
        return new TestFileSnapshot(
            File.ReadAllBytes(path),
            File.GetAttributes(path));
    }

    private static object CloneTestRegistryValue(object value) => value switch
    {
        byte[] bytes => bytes.ToArray(),
        string[] strings => strings.ToArray(),
        _ => value,
    };

    private static void AssertRegistrationAbsent(
        PersonalWindowsRegistrationContext context)
    {
        AssertFalse(File.Exists(context.DesktopShortcutPath));
        AssertFalse(File.Exists(context.StartMenuShortcutPath));
        using var key = Registry.CurrentUser.OpenSubKey(
            context.RegistrySubKey,
            writable: false);
        AssertTrue(key is null);
    }

    private static void AssertRegistrationEqual(
        TestRegistrationSnapshot expected,
        TestRegistrationSnapshot actual)
    {
        AssertTestFileEqual(expected.DesktopShortcut, actual.DesktopShortcut);
        AssertTestFileEqual(expected.StartMenuShortcut, actual.StartMenuShortcut);
        if (expected.RegistryValues is null || actual.RegistryValues is null)
        {
            AssertTrue(expected.RegistryValues is null && actual.RegistryValues is null);
            return;
        }
        AssertEqual(expected.RegistryValues.Count, actual.RegistryValues.Count);
        foreach (var pair in expected.RegistryValues)
        {
            AssertTrue(actual.RegistryValues.TryGetValue(pair.Key, out var value));
            AssertEqual(pair.Value.Kind, value!.Kind);
            AssertTrue(TestRegistryValueEquals(pair.Value.Value, value.Value));
        }
    }

    private static void AssertTestFileEqual(
        TestFileSnapshot? expected,
        TestFileSnapshot? actual)
    {
        if (expected is null || actual is null)
        {
            AssertTrue(expected is null && actual is null);
            return;
        }
        AssertEqual(expected.Attributes, actual.Attributes);
        AssertSequenceEqual(expected.Bytes, actual.Bytes);
    }

    private static bool TestRegistryValueEquals(object expected, object actual) =>
        (expected, actual) switch
        {
            (byte[] left, byte[] right) => left.AsSpan().SequenceEqual(right),
            (string[] left, string[] right) => left.SequenceEqual(right, StringComparer.Ordinal),
            _ => Equals(expected, actual),
        };

    private static void DeleteRegistrationFixture(
        PersonalWindowsRegistrationContext context)
    {
        Registry.CurrentUser.DeleteSubKeyTree(
            context.RegistrySubKey,
            throwOnMissingSubKey: false);
        if (File.Exists(context.DesktopShortcutPath))
        {
            File.Delete(context.DesktopShortcutPath);
        }
        if (File.Exists(context.StartMenuShortcutPath))
        {
            File.Delete(context.StartMenuShortcutPath);
        }
    }

    private static void CreateExactLegacyTree(PersonalInstallationLayout layout)
    {
        Directory.CreateDirectory(Path.Combine(layout.ManagedRoot, "runtimes"));
        Directory.CreateDirectory(Path.Combine(layout.ManagedRoot, "snapshots"));
        Directory.CreateDirectory(Path.Combine(layout.ManagedRoot, "state"));
        File.WriteAllText(
            Path.Combine(layout.ManagedRoot, "runtimes", "node.exe"),
            "legacy-node");
        File.WriteAllText(
            Path.Combine(layout.ManagedRoot, "snapshots", "snapshot.bin"),
            "legacy-snapshot");
        File.WriteAllText(
            Path.Combine(layout.ManagedRoot, "state", "runtime-current.json"),
            "{this is deliberately not trusted json}");
        File.WriteAllBytes(
            Path.Combine(layout.ManagedRoot, "launcher.settings.json"),
            [0xff, 0x00, 0x7b, 0x7d]);
    }

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
        finally
        {
            listener.Stop();
        }
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(
        string fileName,
        string existingFileName,
        IntPtr securityAttributes);

    private static void CreateDirectoryJunction(string path, string target)
    {
        Directory.CreateDirectory(path);
        var substituteName = @"\??\" + Path.GetFullPath(target).TrimEnd(Path.DirectorySeparatorChar);
        var printName = Path.GetFullPath(target).TrimEnd(Path.DirectorySeparatorChar);
        var substituteBytes = Encoding.Unicode.GetBytes(substituteName);
        var printBytes = Encoding.Unicode.GetBytes(printName);
        var pathBufferLength = substituteBytes.Length + 2 + printBytes.Length + 2;
        var reparseDataLength = checked((ushort)(8 + pathBufferLength));
        var buffer = new byte[8 + reparseDataLength];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(0, 4), 0xA0000003);
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(4, 2), reparseDataLength);
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(8, 2), 0);
        BinaryPrimitives.WriteUInt16LittleEndian(
            buffer.AsSpan(10, 2),
            checked((ushort)substituteBytes.Length));
        BinaryPrimitives.WriteUInt16LittleEndian(
            buffer.AsSpan(12, 2),
            checked((ushort)(substituteBytes.Length + 2)));
        BinaryPrimitives.WriteUInt16LittleEndian(
            buffer.AsSpan(14, 2),
            checked((ushort)printBytes.Length));
        substituteBytes.CopyTo(buffer.AsSpan(16));
        printBytes.CopyTo(buffer.AsSpan(18 + substituteBytes.Length));

        using var handle = CreateFile(
            path,
            0x40000000,
            0,
            IntPtr.Zero,
            3,
            0x00200000 | 0x02000000,
            IntPtr.Zero);
        if (handle.IsInvalid
            || !DeviceIoControl(
                handle,
                0x000900A4,
                buffer,
                buffer.Length,
                IntPtr.Zero,
                0,
                out _,
                IntPtr.Zero))
        {
            throw new IOException(
                "Could not create an unprivileged directory junction test fixture.",
                new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
        }
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        Microsoft.Win32.SafeHandles.SafeFileHandle device,
        uint controlCode,
        byte[] input,
        int inputSize,
        IntPtr output,
        int outputSize,
        out int bytesReturned,
        IntPtr overlapped);

    private static DateTimeOffset MaxUtc(DateTimeOffset left, DateTimeOffset right) =>
        left >= right ? left : right;

    private static string FileSha256(string path)
    {
        using var input = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(input));
    }

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static PersonalProductionPayloadExpectation Expectation(
        TestPayload payload,
        PersonalReleaseTrustPolicy policy,
        DateTimeOffset now)
    {
        var verified = PersonalReleaseSetValidator.ParseAndVerify(
            payload.Manifest,
            policy,
            now);
        return new PersonalProductionPayloadExpectation(
            verified.Manifest.ReleaseSetId,
            Sha256(payload.Manifest),
            payload.Manifest.LongLength,
            Sha256(payload.StartupStub),
            payload.StartupStub.LongLength,
            Sha256(payload.ClientBundle),
            payload.ClientBundle.LongLength,
            Sha256(payload.Runtime),
            payload.Runtime.LongLength);
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
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected '{expected}', got '{actual}'.");
        }
    }

    private static void AssertSequenceEqual(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual)
    {
        if (!expected.SequenceEqual(actual))
        {
            throw new InvalidOperationException("Byte sequences differ.");
        }
    }

    private static void AssertThrows<TException>(Action action)
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

    private static async Task AssertThrowsAsync<TException>(Func<Task> action)
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

    private sealed record TestFileSnapshot(byte[] Bytes, FileAttributes Attributes);

    private sealed record TestRegistryValue(RegistryValueKind Kind, object Value);

    private sealed record TestRegistrationSnapshot(
        TestFileSnapshot? DesktopShortcut,
        TestFileSnapshot? StartMenuShortcut,
        IReadOnlyDictionary<string, TestRegistryValue>? RegistryValues);

    private sealed class Scenario : IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private int _registrations;
        private int _removals;

        public Scenario(
            string scope,
            string startupStubVersion = "1.0.0")
        {
            var safeScope = scope[..Math.Min(scope.Length, 16)];
            Root = Path.Combine(
                TempRoot,
                safeScope + "-" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(Root);
            Layout = new PersonalInstallationLayout(
                Path.Combine(Root, "DshLauncher"),
                Path.Combine(Root, ".dsh"),
                Path.Combine(Root, "security-primary", "state.witness.dpapi"));
            Clock = new MutableTimeProvider(Now);
            Policy = new PersonalReleaseTrustPolicy
            {
                Product = PersonalReleaseSetContract.Product,
                Environment = PersonalReleaseSetContract.ProductionEnvironment,
                Channel = "stable",
                ArtifactOrigin = new Uri("https://updates.example.test/"),
                StartupStubVersion = startupStubVersion,
                TrustedKeys =
                [
                    PersonalReleaseSetSigner.ExportPublicKey("personal-installer-test", _key),
                ],
            };
            Trust = new PersonalInstallerTrustConfiguration(
                false,
                new Uri("https://updates.example.test/"),
                Policy,
                null);
        }

        public string Root { get; }
        public PersonalInstallationLayout Layout { get; }
        public MutableTimeProvider Clock { get; }
        public PersonalReleaseTrustPolicy Policy { get; }
        public PersonalInstallerTrustConfiguration Trust { get; }

        public TestPayload CreatePayload(
            long sequence,
            string releaseSetId,
            string startupStub,
            DateTimeOffset? issuedAtUtc = null,
            DateTimeOffset? expiresAtUtc = null,
            bool omitClientCompleteTree = false,
            string minimumStartupStubVersion = "1.0.0")
        {
            var client = CreateArchive(
                PersonalReleaseSetContract.ClientBundleComponent,
                $"client-v{sequence}",
                new Dictionary<string, byte[]>(StringComparer.Ordinal)
                {
                    [PersonalInstallationLayout.ClientBootstrapperExecutableName] =
                        Encoding.UTF8.GetBytes("client-bootstrapper"),
                    [PersonalInstallationLayout.LauncherExecutableName] =
                        Encoding.UTF8.GetBytes("launcher"),
                    [PersonalInstallationLayout.MaintenanceExecutableName] =
                        Encoding.UTF8.GetBytes("maintenance"),
                },
                includeCompleteTree: !omitClientCompleteTree);
            var runtime = CreateArchive(
                PersonalReleaseSetContract.RuntimeComponent,
                $"runtime-v{sequence}",
                new Dictionary<string, byte[]>(StringComparer.Ordinal)
                {
                    ["node.exe"] = Encoding.UTF8.GetBytes("node"),
                    ["node_modules/@deepseek-ai/dsh/lib/bin.js"] =
                        Encoding.UTF8.GetBytes("console.log('dsh')"),
                    ["node_modules/@deepseek-ai/dsh/package.json"] =
                        Encoding.UTF8.GetBytes("{\"version\":\"test\"}"),
                });
            var unsigned = new PersonalReleaseSetManifest
            {
                SchemaVersion = PersonalReleaseSetContract.SchemaVersion,
                Product = PersonalReleaseSetContract.Product,
                Environment = PersonalReleaseSetContract.ProductionEnvironment,
                Channel = "stable",
                ReleaseSetId = releaseSetId,
                Provenance = new PersonalReleaseProvenance
                {
                    LauncherRepositoryCommit = new string('a', 40),
                    HarnessSourceTag = "dsh-v0.1.1-test",
                    HarnessSourceCommit = new string('b', 40),
                },
                Generation = sequence,
                Sequence = sequence,
                MinAcceptedSequence = Math.Max(0, sequence - 1),
                IssuedAtUtc = issuedAtUtc ?? Now.AddMinutes(-1),
                ExpiresAtUtc = expiresAtUtc ?? Now.AddDays(7),
                MaximumOfflineGraceSeconds = 7 * 24 * 60 * 60,
                StartupStub = new PersonalStartupStubCompatibility
                {
                    MinimumVersion = minimumStartupStubVersion,
                    MaximumVersion = "1.9.9",
                },
                RevokedReleaseSetIds = Array.Empty<string>(),
                Artifacts = [client.Artifact, runtime.Artifact],
            };
            var signed = PersonalReleaseSetSigner.Sign(
                unsigned,
                "personal-installer-test",
                _key);
            return new TestPayload(
                PersonalReleaseSetJson.SerializeSigned(signed),
                Encoding.UTF8.GetBytes(startupStub),
                client.Bytes,
                runtime.Bytes);
        }

        public PersonalInstallMigrationService CreateService(
            bool registerFailure = false,
            bool processFailure = false,
            Action<PersonalInstallMigrationCheckpoint>? checkpoint = null) => new(
                Layout,
                Clock,
                () =>
                {
                    if (processFailure)
                    {
                        throw new InvalidOperationException("simulated managed process");
                    }
                },
                _ => { },
                displayVersion =>
                {
                    Interlocked.Increment(ref _registrations);
                    if (registerFailure)
                    {
                        throw new IOException("simulated registration failure");
                    }
                    return Snapshot(Layout, displayVersion);
                },
                () => Interlocked.Increment(ref _removals),
                checkpoint);

        public PersonalInstallMigrationService CreateWindowsRegistrationService(
            PersonalWindowsRegistrationContext context,
            Action<PersonalInstallMigrationCheckpoint>? checkpoint = null) => new(
                Layout,
                Clock,
                () => { },
                _ => { },
                displayVersion => PersonalWindowsRegistration.Install(
                    Layout,
                    displayVersion,
                    context),
                () => PersonalWindowsRegistration.Remove(Layout, context),
                checkpoint);

        public void Dispose()
        {
            _key.Dispose();
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }

        private static PersonalWindowsRegistrationSnapshot Snapshot(
            PersonalInstallationLayout layout,
            string version) => new(
                "test-registry",
                "test",
                version,
                "ensou",
                layout.StartupStubPath,
                layout.ManagedRoot,
                "repair",
                "uninstall",
                "quiet-uninstall",
                Path.Combine(layout.ManagedRoot, "desktop-test.lnk"),
                Path.Combine(layout.ManagedRoot, "start-test.lnk"),
                layout.StartupStubPath);

        private static ArchivePayload CreateArchive(
            string component,
            string releaseId,
            IReadOnlyDictionary<string, byte[]> files,
            bool includeCompleteTree = true)
        {
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
                        Sha256 = Sha256(pair.Value),
                    })
                    .ToArray(),
            };
            var treeBytes = JsonSerializer.SerializeToUtf8Bytes(
                tree,
                new JsonSerializerOptions(JsonSerializerDefaults.Web));
            using var output = new MemoryStream();
            using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
            {
                foreach (var pair in files.OrderBy(pair => pair.Key, StringComparer.Ordinal))
                {
                    var entry = archive.CreateEntry(pair.Key, CompressionLevel.Optimal);
                    using var stream = entry.Open();
                    stream.Write(pair.Value);
                }
                if (includeCompleteTree)
                {
                    var treeEntry = archive.CreateEntry(
                        PersonalReleaseArtifactInstaller.CompleteTreeEntryName,
                        CompressionLevel.Optimal);
                    using var treeStream = treeEntry.Open();
                    treeStream.Write(treeBytes);
                }
            }
            var bytes = output.ToArray();
            return new ArchivePayload(
                bytes,
                new PersonalReleaseArtifact
                {
                    Component = component,
                    ReleaseId = releaseId,
                    Uri = new Uri($"https://updates.example.test/artifacts/{releaseId}.zip"),
                    SizeBytes = bytes.LongLength,
                    Sha256 = Sha256(bytes),
                    CompleteTreeSha256 = Sha256(treeBytes),
                });
        }
    }

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record LegacyPersonalComponentReferenceV3(
        string Component,
        string ReleaseId,
        string Directory,
        string ArchiveSha256,
        string CompleteTreeSha256);

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record LegacyPersonalStartupStubCompatibilityV3(
        string MinimumVersion,
        string MaximumVersion);

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record LegacyPersonalReleaseSetReferenceV3(
        string ReleaseSetId,
        long Generation,
        long Sequence,
        long MinAcceptedSequence,
        string ManifestSha256,
        LegacyPersonalStartupStubCompatibilityV3 StartupStub,
        LegacyPersonalComponentReferenceV3 ClientBundle,
        LegacyPersonalComponentReferenceV3 Runtime,
        string HealthState,
        string? HealthToken,
        string? HomeTransactionId,
        DateTimeOffset ActivatedAtUtc);

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record LegacyPersonalPointerV3(
        int SchemaVersion,
        string Product,
        string Environment,
        string Channel,
        LegacyPersonalReleaseSetReferenceV3 Current,
        LegacyPersonalReleaseSetReferenceV3? Previous,
        DateTimeOffset UpdatedAtUtc);

    private sealed record ArchivePayload(
        byte[] Bytes,
        PersonalReleaseArtifact Artifact);

    private sealed record TestPayload(
        byte[] Manifest,
        byte[] StartupStub,
        byte[] ClientBundle,
        byte[] Runtime) : IPersonalInstallerPayloadSource
    {
        public Stream OpenSignedReleaseManifest() => new MemoryStream(Manifest, writable: false);
        public Stream OpenStartupStub() => new MemoryStream(StartupStub, writable: false);
        public Stream OpenClientBundleArchive() => new MemoryStream(ClientBundle, writable: false);
        public Stream OpenRuntimeArchive() => new MemoryStream(Runtime, writable: false);
    }

    private sealed class MutableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
        public void SetUtcNow(DateTimeOffset value) => _now = value;
    }

    private sealed class SimulatedCrashException(string checkpoint)
        : Exception("Simulated crash at " + checkpoint);
}
