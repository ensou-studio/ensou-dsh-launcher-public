using System.Runtime.InteropServices;
using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.Personal.InstallerTests;

internal static class PersonalInstallPreflightTests
{
    public static Task RejectsBeforeInstallStateMutationAsync()
    {
        using var scenario = new PreflightScenario();
        var baseline = scenario.Snapshot();
        var runtimePort = 0;
        var ready = scenario.CreateReadyProbes() with
        {
            RequireNoRuntimeConflict = port => runtimePort = port,
        };

        AssertFailure(
            "PERSONAL_PREFLIGHT_WINDOWS_VERSION_UNSUPPORTED",
            scenario,
            ready with
            {
                ReadPlatform = () => SupportedPlatform() with { IsWindows = false },
            },
            baseline);
        AssertFailure(
            "PERSONAL_PREFLIGHT_WINDOWS_VERSION_UNSUPPORTED",
            scenario,
            ready with
            {
                ReadPlatform = () => SupportedPlatform() with
                {
                    IsClientOperatingSystem = false,
                },
            },
            baseline);
        AssertFailure(
            "PERSONAL_PREFLIGHT_WINDOWS_VERSION_UNSUPPORTED",
            scenario,
            ready with
            {
                ReadPlatform = () => SupportedPlatform() with
                {
                    OperatingSystemVersion = new Version(6, 3, 9600),
                },
            },
            baseline);
        AssertFailure(
            "PERSONAL_PREFLIGHT_WINDOWS_VERSION_UNSUPPORTED",
            scenario,
            ready with
            {
                ReadPlatform = () => SupportedPlatform() with
                {
                    OperatingSystemVersion = new Version(11, 0, 1000),
                },
            },
            baseline);
        AssertFailure(
            "PERSONAL_PREFLIGHT_ARCHITECTURE_UNSUPPORTED",
            scenario,
            ready with
            {
                ReadPlatform = () => SupportedPlatform() with
                {
                    OperatingSystemArchitecture = Architecture.Arm64,
                },
            },
            baseline);
        AssertFailure(
            "PERSONAL_PREFLIGHT_ARCHITECTURE_UNSUPPORTED",
            scenario,
            ready with
            {
                ReadPlatform = () => SupportedPlatform() with
                {
                    ProcessArchitecture = Architecture.Arm64,
                },
            },
            baseline);
        AssertFailure(
            "PERSONAL_PREFLIGHT_TOKEN_UNSUPPORTED",
            scenario,
            ready with
            {
                ReadPlatform = () => SupportedPlatform() with { IsElevated = true },
            },
            baseline);
        AssertFailure(
            "PERSONAL_PREFLIGHT_TOKEN_UNSUPPORTED",
            scenario,
            ready with
            {
                ReadPlatform = () => SupportedPlatform() with { IntegrityLevelRid = 0x1000 },
            },
            baseline);
        AssertFailure(
            "PERSONAL_PREFLIGHT_TOKEN_UNSUPPORTED",
            scenario,
            ready with
            {
                ReadPlatform = () => SupportedPlatform() with { IntegrityLevelRid = 0x2100 },
            },
            baseline);
        AssertFailure(
            "PERSONAL_PREFLIGHT_INSTALL_ROOT_UNSAFE",
            scenario,
            ready with
            {
                RequireOrdinaryWritableRoots = _ => throw new UnauthorizedAccessException(),
            },
            baseline);
        AssertFailure(
            "PERSONAL_PREFLIGHT_RUNTIME_CONFLICT",
            scenario,
            ready with
            {
                RequireNoRuntimeConflict = _ => throw new InvalidOperationException(),
            },
            baseline);
        AssertFailure(
            "PERSONAL_PREFLIGHT_DISK_SPACE_INSUFFICIENT",
            scenario,
            ready with
            {
                ReadAvailableDiskBytes = _ => PersonalInstallPreflight.MinimumDiskBytes - 1,
            },
            baseline);
        AssertFailure(
            "PERSONAL_PREFLIGHT_DEFAULT_BROWSER_MISSING",
            scenario,
            ready with { HasDefaultHttpBrowser = () => false },
            baseline);

        var result = PersonalInstallPreflight.RequireReady(
            scenario.Layout,
            PersonalInstallMigrationService.DefaultLoopbackPort,
            ready with
            {
                ReadAvailableDiskBytes = _ => 3L * 1024 * 1024 * 1024,
            });
        AssertEqual(PersonalLegacyInstallClassification.Clean, result.ExistingInstall);
        AssertTrue(result.IsBelowRecommendedDiskSpace);
        AssertEqual(PersonalInstallMigrationService.DefaultLoopbackPort, runtimePort);
        AssertSequenceEqual(baseline, scenario.Snapshot());
        return Task.CompletedTask;
    }

    public static Task ClassifiesLegacyAndManualConflictAsync()
    {
        using (var exact = new PreflightScenario())
        {
            Directory.CreateDirectory(Path.Combine(exact.Layout.ManagedRoot, "runtimes"));
            Directory.CreateDirectory(Path.Combine(exact.Layout.ManagedRoot, "snapshots"));
            Directory.CreateDirectory(Path.Combine(exact.Layout.ManagedRoot, "state"));
            File.WriteAllText(
                Path.Combine(exact.Layout.ManagedRoot, "state", "runtime-current.json"),
                "{}");
            File.WriteAllText(
                Path.Combine(exact.Layout.ManagedRoot, "launcher.settings.json"),
                "{}");
            var baseline = exact.Snapshot();
            var result = PersonalInstallPreflight.RequireReady(
                exact.Layout,
                PersonalInstallMigrationService.DefaultLoopbackPort,
                exact.CreateReadyProbes());
            AssertEqual(PersonalLegacyInstallClassification.ExactV1, result.ExistingInstall);
            AssertSequenceEqual(baseline, exact.Snapshot());
        }

        using (var conflict = new PreflightScenario())
        {
            Directory.CreateDirectory(conflict.Layout.ManagedRoot);
            File.WriteAllText(
                Path.Combine(conflict.Layout.ManagedRoot, "manual-dsh.cmd"),
                "manual");
            var baseline = conflict.Snapshot();
            AssertFailure(
                "PERSONAL_PREFLIGHT_UNKNOWN_MANUAL_CONFLICT",
                conflict,
                conflict.CreateReadyProbes(),
                baseline);
        }

        using (var incompleteV2 = new PreflightScenario())
        {
            Directory.CreateDirectory(incompleteV2.Layout.StateRoot);
            File.WriteAllText(incompleteV2.Layout.ReleaseSetPointerPath, "{}");
            var baseline = incompleteV2.Snapshot();
            AssertFailure(
                "PERSONAL_PREFLIGHT_UNKNOWN_MANUAL_CONFLICT",
                incompleteV2,
                incompleteV2.CreateReadyProbes(),
                baseline);
        }
        return Task.CompletedTask;
    }

    public static Task RejectsEveryPartialV2MarkerAsync()
    {
        foreach (var selectPath in new Func<PersonalInstallationLayout, string>[]
        {
            layout => layout.ReleaseSetPointerPath,
            layout => layout.UpdateSecurityStatePath,
            layout => layout.UpdateSecurityStatePath + ".anchor",
            layout => layout.UpdateSecurityWitnessPath,
            layout => layout.V2MigrationFootprintPath,
            layout => layout.StartupStubPath,
            layout => layout.UpdateOperationLockPath,
            layout => Path.Combine(
                layout.UpdateOperationLockRoot,
                "personal-install-migration.v1.dpapi"),
        })
        {
            using var scenario = new PreflightScenario();
            var path = selectPath(scenario.Layout);
            Directory.CreateDirectory(Path.GetDirectoryName(path)
                ?? throw new InvalidOperationException("Partial marker has no parent."));
            File.WriteAllText(path, "partial-v2-marker");
            var baseline = scenario.Snapshot();
            AssertFailure(
                "PERSONAL_PREFLIGHT_UNKNOWN_MANUAL_CONFLICT",
                scenario,
                scenario.CreateReadyProbes(),
                baseline);
        }

        using (var partialSet = new PreflightScenario())
        {
            foreach (var path in new[]
            {
                partialSet.Layout.ReleaseSetPointerPath,
                partialSet.Layout.UpdateSecurityStatePath,
                partialSet.Layout.StartupStubPath,
            })
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path)
                    ?? throw new InvalidOperationException("Partial marker has no parent."));
                File.WriteAllText(path, "partial-v2-set");
            }
            var baseline = partialSet.Snapshot();
            AssertFailure(
                "PERSONAL_PREFLIGHT_UNKNOWN_MANUAL_CONFLICT",
                partialSet,
                partialSet.CreateReadyProbes(),
                baseline);
        }
        return Task.CompletedTask;
    }

    public static Task NodeProcessesAlwaysBlockAsync()
    {
        AssertTrue(PersonalHarnessWriterGuard.ClassifyPossibleHarnessWriter(
            "dsh"));
        AssertTrue(PersonalHarnessWriterGuard.ClassifyPossibleHarnessWriter(
            "node"));
        AssertTrue(PersonalHarnessWriterGuard.ClassifyPossibleHarnessWriter(
            "node.exe"));
        AssertTrue(PersonalHarnessWriterGuard.ClassifyPossibleHarnessWriter(
            "deepseek-harness"));
        AssertFalse(PersonalHarnessWriterGuard.ClassifyPossibleHarnessWriter(
            "dotnet"));
        return Task.CompletedTask;
    }

    public static Task NativeWindowsPlatformProbeAsync()
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.CompletedTask;
        }
        var platform = PersonalInstallPreflightWindows.ReadPlatform();
        AssertTrue(platform.IsWindows);
        AssertTrue(platform.OperatingSystemVersion.Major > 0);
        AssertTrue(platform.OperatingSystemVersion.Build >= 0);
        AssertTrue(platform.IntegrityLevelRid > 0);
        return Task.CompletedTask;
    }

    public static PersonalInstallPreflightResult RequireReadyForManagedScenario(
        PersonalInstallationLayout layout) => PersonalInstallPreflight.RequireReady(
            layout,
            PersonalInstallMigrationService.DefaultLoopbackPort,
            new PersonalInstallPreflightProbes(
                SupportedPlatform,
                PersonalInstallPreflightFileSystem.RequireOrdinaryWritableRoots,
                _ => { },
                _ => PersonalInstallPreflight.RecommendedDiskBytes,
                () => true));

    public static void AssertManagedScenarioIsManualConflict(
        PersonalInstallationLayout layout)
    {
        try
        {
            _ = RequireReadyForManagedScenario(layout);
        }
        catch (PersonalInstallPreflightException exception)
        {
            AssertEqual(
                "PERSONAL_PREFLIGHT_UNKNOWN_MANUAL_CONFLICT",
                exception.Code);
            return;
        }
        throw new InvalidOperationException(
            "Expected incomplete managed v2 state to fail closed.");
    }

    public static Task WriteProbeLeavesNoResidueAsync()
    {
        using var scenario = new PreflightScenario();
        var roots = PersonalInstallPreflightFileSystem.GetProtectedRoots(scenario.Layout);
        var baseline = scenario.Snapshot();
        PersonalInstallPreflightFileSystem.RequireOrdinaryWritableRoots(roots);
        AssertSequenceEqual(baseline, scenario.Snapshot());

        Directory.CreateDirectory(scenario.Layout.ManagedRoot);
        var marker = Path.Combine(scenario.Layout.ManagedRoot, "marker.txt");
        File.WriteAllText(marker, "preserve");
        baseline = scenario.Snapshot();
        PersonalInstallPreflightFileSystem.RequireOrdinaryWritableRoots(roots);
        AssertSequenceEqual(baseline, scenario.Snapshot());
        AssertEqual("preserve", File.ReadAllText(marker));
        return Task.CompletedTask;
    }

    private static PersonalInstallPlatformSnapshot SupportedPlatform() => new(
        true,
        true,
        new Version(10, 0, 22631),
        Architecture.X64,
        Architecture.X64,
        false,
        PersonalInstallPlatformSnapshot.MediumIntegrityRid);

    private static void AssertFailure(
        string expectedCode,
        PreflightScenario scenario,
        PersonalInstallPreflightProbes probes,
        IReadOnlyList<string> baseline)
    {
        try
        {
            _ = PersonalInstallPreflight.RequireReady(
                scenario.Layout,
                PersonalInstallMigrationService.DefaultLoopbackPort,
                probes);
        }
        catch (PersonalInstallPreflightException exception)
        {
            AssertEqual(expectedCode, exception.Code);
            AssertSequenceEqual(baseline, scenario.Snapshot());
            return;
        }
        throw new InvalidOperationException(
            $"Expected Personal preflight failure '{expectedCode}'.");
    }

    private static void AssertSequenceEqual(
        IReadOnlyList<string> expected,
        IReadOnlyList<string> actual)
    {
        if (!expected.SequenceEqual(actual, StringComparer.Ordinal))
        {
            throw new InvalidOperationException(
                $"Expected identical filesystem snapshots. Expected [{string.Join(", ", expected)}], actual [{string.Join(", ", actual)}].");
        }
    }

    private static void AssertTrue(bool value)
    {
        if (!value)
        {
            throw new InvalidOperationException("Expected true.");
        }
    }

    private static void AssertFalse(bool value) => AssertTrue(!value);

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
        throw new InvalidOperationException(
            $"Expected exception {typeof(TException).Name}.");
    }

    private static void AssertEqual<T>(T expected, T actual)
        where T : notnull
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException(
                $"Expected '{expected}', actual '{actual}'.");
        }
    }

    private sealed class PreflightScenario : IDisposable
    {
        private readonly string _root = Path.Combine(
            Path.GetTempPath(),
            "dsh-personal-preflight-" + Guid.NewGuid().ToString("N"));

        public PreflightScenario()
        {
            Directory.CreateDirectory(_root);
            Layout = new PersonalInstallationLayout(
                Path.Combine(_root, "program", "DshLauncher"),
                Path.Combine(_root, "profile", ".dsh"),
                Path.Combine(_root, "security", "personal-update-security.v2.witness.dpapi"));
        }

        public PersonalInstallationLayout Layout { get; }

        public PersonalInstallPreflightProbes CreateReadyProbes() => new(
            SupportedPlatform,
            PersonalInstallPreflightFileSystem.RequireOrdinaryWritableRoots,
            _ => { },
            _ => PersonalInstallPreflight.RecommendedDiskBytes,
            () => true);

        public IReadOnlyList<string> Snapshot() => Directory
            .EnumerateFileSystemEntries(_root, "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(_root, path))
            .Order(StringComparer.Ordinal)
            .ToArray();

        public void Dispose()
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
    }
}
