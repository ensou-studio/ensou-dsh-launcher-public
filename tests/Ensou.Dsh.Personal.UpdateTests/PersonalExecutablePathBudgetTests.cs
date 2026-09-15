using Ensou.Dsh.Contracts;
using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.Personal.UpdateTests;

internal static class PersonalExecutablePathBudgetTests
{
    // Pure path cases do not inspect or create these synthetic filesystem locations.
    private const string TestRoot = @"C:\synthetic-personal-path-budget";
    internal static IReadOnlyList<(string Name, Func<Task> Run)> Cases { get; } =
    [
        ("executable path 259 is admitted without filesystem access", () => BoundaryAsync(259, reject: false)),
        ("executable path 260 is rejected with stable private diagnostic", () => BoundaryAsync(260, reject: true)),
        ("executable path 261 is rejected with stable private diagnostic", () => BoundaryAsync(261, reject: true)),
        ("production client staging is included in the execution budget", ProductionStagingAsync),
        ("production temporary verification executables have their own budget", TemporaryVerificationAsync),
        ("long Harness home and witness paths are not executable budgets", LongDataPathsAsync),
        ("future client release identifier cannot exceed the installed execution budget", FutureReleaseIdAsync),
        ("direct release installation rejects overlong candidate before operation or root writes", DirectInstallRejectsBeforeWritesAsync),
        ("acquired release installation rejects overlong candidate before source validation or state writes", AcquiredInstallRejectsBeforeWritesAsync),
    ];

    internal static async Task<int> RunAsync()
    {
        int failures = 0;
        foreach (var test in Cases)
        {
            try { await test.Run(); Console.WriteLine($"PASS {test.Name}"); }
            catch (Exception error) { failures++; Console.Error.WriteLine($"FAIL {test.Name}: {error}"); }
        }
        Console.WriteLine($"RESULT {Cases.Count - failures}/{Cases.Count} executable path budget tests passed");
        return failures == 0 ? 0 : 1;
    }

    private static Task BoundaryAsync(int length, bool reject)
    {
        var layout = LayoutAtMaintenanceLength(length);
        var manifest = Manifest("client-v1");
        if (reject) RequireFailure(() => PersonalExecutablePathBudget.RequireCandidate(layout, manifest, false));
        else PersonalExecutablePathBudget.RequireCandidate(layout, manifest, false);
        return Task.CompletedTask;
    }

    private static Task ProductionStagingAsync()
    {
        // The dot, '.staging-' and 32 hexadecimal characters add exactly 42 characters.
        PersonalExecutablePathBudget.RequireCandidate(LayoutAtMaintenanceLength(217), Manifest("client-v1"), true);
        var layout = LayoutAtMaintenanceLength(218);
        PersonalExecutablePathBudget.RequireCandidate(layout, Manifest("client-v1"), false);
        RequireFailure(() => PersonalExecutablePathBudget.RequireCandidate(layout, Manifest("client-v1"), true));
        RequireFailure(() => PersonalExecutablePathBudget.RequireInstallerCandidate(layout, Manifest("client-v1"), true));
        return Task.CompletedTask;
    }

    private static Task LongDataPathsAsync()
    {
        var ordinary = LayoutAtMaintenanceLength(200);
        var layout = new PersonalInstallationLayout(ordinary.ManagedRoot,
            TestRoot + "\\data\\" + new string('d', 180) + "\\" + new string('e', 180),
            TestRoot + "\\witness\\" + new string('w', 180) + "\\" + new string('x', 180) + "\\w.dpapi");
        PersonalExecutablePathBudget.RequireCandidate(layout, Manifest("client-v1"), true);
        return Task.CompletedTask;
    }

    private static Task TemporaryVerificationAsync()
    {
        const string suffix = "\\ensou-personal-candidate-verification\\00000000000000000000000000000000\\Ensou.Dsh.Personal.Maintenance.exe";
        string root259 = TestRoot + "\\" + new string('t', 259 - TestRoot.Length - 1 - suffix.Length);
        PersonalExecutablePathBudget.RequireArchiveVerification("client-bundle", true, root259);
        RequireFailure(() => PersonalExecutablePathBudget.RequireArchiveVerification("client-bundle", true, root259 + "t"));
        PersonalExecutablePathBudget.RequireArchiveVerification("client-bundle", false, root259 + "t");
        PersonalExecutablePathBudget.RequireArchiveVerification("runtime", true, root259 + "t");
        return Task.CompletedTask;
    }

    private static Task FutureReleaseIdAsync()
    {
        var layout = LayoutAtMaintenanceLength(259);
        PersonalExecutablePathBudget.RequireCandidate(layout, Manifest("client-v1"), false);
        RequireFailure(() => PersonalExecutablePathBudget.RequireCandidate(layout, Manifest("client-v10"), false));
        return Task.CompletedTask;
    }

    private static async Task DirectInstallRejectsBeforeWritesAsync()
    {
        var layout = LayoutAtMaintenanceLength(260, Path.Combine(Path.GetTempPath(), "path-budget-" + Guid.NewGuid().ToString("N")));
        RequireNoGeneratedState(layout);
        await RequireFailureAsync(() => new PersonalReleaseArtifactInstaller().InstallReleaseSetAsync(
            layout, Verified(), "never-open-client.zip", "never-open-runtime.zip", 3080));
        RequireNoGeneratedState(layout);
    }

    private static async Task AcquiredInstallRejectsBeforeWritesAsync()
    {
        var layout = LayoutAtMaintenanceLength(260, Path.Combine(Path.GetTempPath(), "path-budget-" + Guid.NewGuid().ToString("N")));
        RequireNoGeneratedState(layout);
        await RequireFailureAsync(() => new PersonalReleaseArtifactInstaller().InstallAcquiredReleaseSetAsync(
            layout, Verified(), new PersonalAcquiredReleaseSet(
                PersonalReleaseArtifactSource.Downloaded("never-open-client.zip"),
                PersonalReleaseArtifactSource.Downloaded("never-open-runtime.zip")), 3080));
        RequireNoGeneratedState(layout);
    }

    private static PersonalInstallationLayout LayoutAtMaintenanceLength(int length, string? temporaryTestRoot = null)
    {
        const string suffix = "\\client-bundle-versions\\client-v1\\Ensou.Dsh.Personal.Maintenance.exe";
        string root = temporaryTestRoot ?? TestRoot;
        if (temporaryTestRoot is not null) length = Math.Max(length, root.Length + suffix.Length + 2);
        return new PersonalInstallationLayout(
            root + "\\" + new string('m', length - root.Length - 1 - suffix.Length),
            root + "\\home", root + "\\witness.dpapi");
    }

    private static void RequireNoGeneratedState(PersonalInstallationLayout layout)
    {
        foreach (string path in new[] { layout.ManagedRoot, layout.HarnessHome, layout.HarnessRecoveryRoot,
                     layout.UpdateOperationLockRoot, layout.UpdateSecurityStatePath, layout.UpdateSecurityWitnessPath,
                     layout.ReleaseSetPointerPath })
            if (File.Exists(path) || Directory.Exists(path))
                throw new InvalidOperationException("An executable path rejection generated installation, journal, or security state.");
    }

    private static VerifiedPersonalReleaseSetManifest Verified() => new(Manifest("client-v1"), new string('a', 64), DateTimeOffset.UnixEpoch);
    private static PersonalReleaseSetManifest Manifest(string clientReleaseId) => new()
    {
        SchemaVersion = 2, Product = PersonalReleaseSetContract.Product,
        Environment = "production", Channel = "stable", ReleaseSetId = "path-budget-v1",
        Provenance = new() { LauncherRepositoryCommit = new string('a', 40), HarnessSourceTag = "v1", HarnessSourceCommit = new string('a', 40) },
        Generation = 1, Sequence = 1, MinAcceptedSequence = 1,
        IssuedAtUtc = DateTimeOffset.UnixEpoch, ExpiresAtUtc = DateTimeOffset.UnixEpoch.AddDays(1),
        MaximumOfflineGraceSeconds = 3600, StartupStub = new() { MinimumVersion = "1.2.0", MaximumVersion = "1.2.0" },
        RevokedReleaseSetIds = [], Artifacts = [Artifact("client-bundle", clientReleaseId), Artifact("runtime", "runtime-v1")]
    };
    private static PersonalReleaseArtifact Artifact(string component, string releaseId) => new()
    {
        Component = component, ReleaseId = releaseId, Uri = new("https://synthetic.invalid/a.zip"),
        SizeBytes = 1, Sha256 = new string('a', 64), CompleteTreeSha256 = new string('b', 64)
    };
    private static void RequireFailure(Action action)
    {
        try { action(); }
        catch (PersonalInstallPreflightException error) { RequireError(error); return; }
        throw new InvalidOperationException("Expected exact executable path rejection.");
    }
    private static async Task RequireFailureAsync(Func<Task> action)
    {
        try { await action(); }
        catch (PersonalInstallPreflightException error) { RequireError(error); return; }
        throw new InvalidOperationException("Expected path rejection before any installation work.");
    }
    private static void RequireError(PersonalInstallPreflightException error)
    {
        if (error.Code != PersonalExecutablePathBudget.ErrorCode || error.Message.Contains(@"C:\", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Diagnostic code is unstable or leaks an absolute path.");
    }
}
