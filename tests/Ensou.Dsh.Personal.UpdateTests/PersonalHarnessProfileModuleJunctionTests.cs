using System.Diagnostics;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.Personal.UpdateTests;

internal static class PersonalHarnessProfileModuleJunctionTests
{
    internal static IReadOnlyList<(string Name, Func<Task> Run)> Cases { get; } =
    [
        ("profile module unscoped Junction survives clone and rollback", () => CloneRollbackAsync(scoped: false)),
        ("profile module scoped Junction survives clone and rollback", () => CloneRollbackAsync(scoped: true)),
        ("profile module nested dependency Junction target survives clone and rollback", NestedDependencyTargetAsync),
        ("profile module Junction snapshot never traverses its locked target", LockedExternalTargetAsync),
        ("official profile module Junctions verify and commit", CandidateGeneratedJunctionsCommitAsync),
        ("Junction outside the profile module allowlist is rejected", OutsideAllowlistRejectedAsync),
        ("unsupported profile module reparse tag is rejected before clone", UnsupportedReparseTagRejectedAsync),
        ("profile module Junction with a mismatched package target is rejected", MismatchedTargetRejectedAsync),
        ("move-window profile module Junction mutation is rejected", MoveWindowJunctionRejectedAsync),
    ];

    internal static async Task<int> RunAsync()
    {
        var failures = 0;
        foreach (var test in Cases)
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
        Console.WriteLine($"RESULT {Cases.Count - failures}/{Cases.Count} profile module Junction tests passed");
        return failures == 0 ? 0 : 1;
    }

    private static Task CloneRollbackAsync(bool scoped) => RunWithFixtureAsync(
        scoped ? "scoped-rollback" : "unscoped-rollback",
        fixture =>
        {
            fixture.EnrollEmptyHome();
            fixture.SeedLocalData();
            var package = scoped ? Path.Combine("@deepseek-ai", "dsh") : "dsh-tool";
            var target = fixture.CreateExternalPackage(package, "external-package-data");
            var junction = fixture.CreatePackageJunction(package, target);
            var before = ReadJunction(fixture.Home, junction);

            var transaction = fixture.CreateTransaction();
            var prepared = transaction.Prepare("junction-rollback-v1", GetFreePort());
            AssertJunctionEquals(before, ReadJunction(fixture.Home, junction));
            AssertEqual("local-history", File.ReadAllText(fixture.LocalDataPath));
            AssertEqual("local-workspace", File.ReadAllText(fixture.WorkspaceDataPath));

            var restored = transaction.Rollback(prepared.TransactionId, "TEST_ROLLBACK");
            AssertEqual(PersonalHarnessHomeTransaction.RestoredStatus, restored.Status);
            AssertJunctionEquals(before, ReadJunction(fixture.Home, junction));
            AssertEqual("local-history", File.ReadAllText(fixture.LocalDataPath));
            AssertEqual("local-workspace", File.ReadAllText(fixture.WorkspaceDataPath));
            AssertEqual("external-package-data", File.ReadAllText(Path.Combine(target, "package.txt")));
        });

    private static Task LockedExternalTargetAsync() => RunWithFixtureAsync(
        "locked-target",
        fixture =>
        {
            fixture.EnrollEmptyHome();
            fixture.SeedLocalData();
            var target = fixture.CreateExternalPackage("locked-package", "locked-external-data");
            var junction = fixture.CreatePackageJunction("locked-package", target);
            var before = ReadJunction(fixture.Home, junction);
            using (var locked = new FileStream(
                       Path.Combine(target, "package.txt"),
                       FileMode.Open,
                       FileAccess.ReadWrite,
                       FileShare.None))
            {
                var transaction = fixture.CreateTransaction();
                var prepared = transaction.Prepare("junction-locked-v1", GetFreePort());
                AssertJunctionEquals(before, ReadJunction(fixture.Home, junction));
                _ = transaction.Rollback(prepared.TransactionId, "TEST_LOCKED_TARGET");
            }
            AssertEqual("locked-external-data", File.ReadAllText(Path.Combine(target, "package.txt")));
        });

    private static Task NestedDependencyTargetAsync() => RunWithFixtureAsync(
        "nested-dependency-target",
        fixture =>
        {
            fixture.EnrollEmptyHome();
            fixture.SeedLocalData();
            var target = fixture.CreateNestedExternalPackage("nested-tool", "nested-target");
            var junction = fixture.CreatePackageJunction("nested-tool", target);
            var before = ReadJunction(fixture.Home, junction);
            var transaction = fixture.CreateTransaction();
            var prepared = transaction.Prepare("junction-nested-v1", GetFreePort());
            AssertJunctionEquals(before, ReadJunction(fixture.Home, junction));
            _ = transaction.Rollback(prepared.TransactionId, "TEST_NESTED_TARGET");
            AssertJunctionEquals(before, ReadJunction(fixture.Home, junction));
            AssertEqual("nested-target", File.ReadAllText(Path.Combine(target, "package.txt")));
        });

    private static Task CandidateGeneratedJunctionsCommitAsync() => RunWithFixtureAsync(
        "candidate-generated",
        fixture =>
        {
            fixture.EnrollEmptyHome();
            fixture.SeedLocalData();
            var transaction = fixture.CreateTransaction();
            var prepared = transaction.Prepare("junction-generated-v1", GetFreePort());

            var plainTarget = fixture.CreateExternalPackage("generated-tool", "plain-target");
            var scopedTarget = fixture.CreateExternalPackage(
                Path.Combine("@deepseek-ai", "generated-dsh"),
                "scoped-target");
            var plain = fixture.CreatePackageJunction("generated-tool", plainTarget);
            var scoped = fixture.CreatePackageJunction(
                Path.Combine("@deepseek-ai", "generated-dsh"),
                scopedTarget);
            var plainIdentity = ReadJunction(fixture.Home, plain);
            var scopedIdentity = ReadJunction(fixture.Home, scoped);

            var evidence = transaction.VerifyCandidateReadable(prepared.TransactionId);
            AssertTrue(evidence.FileCount >= 1);
            transaction.MarkHealthPassed(prepared.TransactionId);
            transaction.FinalizeCommit(prepared.TransactionId);

            AssertTrue(transaction.TryReadActive() is null);
            AssertJunctionEquals(plainIdentity, ReadJunction(fixture.Home, plain));
            AssertJunctionEquals(scopedIdentity, ReadJunction(fixture.Home, scoped));
            AssertEqual("local-history", File.ReadAllText(fixture.LocalDataPath));
            AssertEqual("local-workspace", File.ReadAllText(fixture.WorkspaceDataPath));
        });

    private static Task OutsideAllowlistRejectedAsync() => RunWithFixtureAsync(
        "outside-allowlist",
        fixture =>
        {
            fixture.EnrollEmptyHome();
            fixture.SeedLocalData();
            var target = fixture.CreateExternalPackage("outside-package", "outside-target");
            var junction = Path.Combine(fixture.Home, "node_modules", "outside-package");
            fixture.CreateJunction(junction, target);
            AssertThrows<InvalidDataException>(() =>
                fixture.CreateTransaction().Prepare("junction-outside-v1", GetFreePort()));
        });

    private static Task UnsupportedReparseTagRejectedAsync() => RunWithFixtureAsync(
        "unsupported-reparse-tag",
        fixture =>
        {
            fixture.EnrollEmptyHome();
            fixture.SeedLocalData();
            var target = fixture.CreateExternalPackage("tag-package", "tag-target");
            var link = fixture.CreatePackageJunction("tag-package", target);
            byte[] raw;
            using (var junction = PersonalHarnessProfileModuleJunction.OpenRead(fixture.Home, link))
            {
                raw = junction.RawData;
            }
            DeleteReparseOnly(link);
            // This mutates captured object metadata only. It deliberately does not
            // create, or claim coverage of creating, an operating-system symlink.
            BinaryPrimitives.WriteUInt32LittleEndian(raw, 0xA000000C);
            AssertThrows<InvalidDataException>(() =>
                PersonalHarnessProfileModuleJunction.CreateClone(fixture.Home, link, raw));
            AssertThrows<FileNotFoundException>(() => _ = File.GetAttributes(link));
        });

    private static Task MismatchedTargetRejectedAsync() => RunWithFixtureAsync(
        "mismatched-target",
        fixture =>
        {
            fixture.EnrollEmptyHome();
            fixture.SeedLocalData();
            var target = fixture.CreateExternalPackage("different-package", "wrong-target");
            var junction = fixture.GetPackagePath("expected-package");
            fixture.CreateJunction(junction, target);
            AssertThrows<InvalidDataException>(() =>
                fixture.CreateTransaction().Prepare("junction-mismatch-v1", GetFreePort()));
        });

    private static Task MoveWindowJunctionRejectedAsync() => RunWithFixtureAsync(
        "move-window",
        fixture =>
        {
            fixture.EnrollEmptyHome();
            fixture.SeedLocalData();
            var target = fixture.CreateExternalPackage("window-package", "window-target");
            var injected = fixture.GetPackagePath("window-package");
            Directory.CreateDirectory(Path.GetDirectoryName(injected)!);
            var sawWindow = false;
            var transaction = fixture.CreateTransaction((phase, _, _) =>
            {
                if (phase != PersonalHarnessHomeMoveGapPhase.DescendantsReleasedBeforeMove)
                {
                    return;
                }
                sawWindow = true;
                fixture.CreateJunction(injected, target);
            });

            AssertThrows<InvalidDataException>(() =>
                transaction.Prepare("junction-window-v1", GetFreePort()));
            AssertTrue(sawWindow);
            var active = transaction.TryReadActive()
                ?? throw new InvalidOperationException("Expected fail-closed active recovery state.");
            var movedJunction = Path.Combine(
                active.OriginalDirectory,
                Path.GetRelativePath(fixture.Home, injected));
            fixture.TrackReparse(movedJunction);
            DeleteReparseOnly(movedJunction);
            var recovered = transaction.RecoverInterrupted();
            AssertEqual(PersonalHarnessHomeTransaction.RestoredStatus, recovered!.Status);
            AssertEqual("local-history", File.ReadAllText(fixture.LocalDataPath));
        });

    private static async Task RunWithFixtureAsync(string name, Action<Fixture> test)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Real profile module Junction tests require Windows.");
        }
        var fixture = new Fixture(name);
        try
        {
            test(fixture);
            fixture.DeleteSuccessEvidenceNoFollow();
        }
        catch
        {
            fixture.ReleaseLeasePreservingEvidence();
            Console.Error.WriteLine($"Junction test evidence retained at: {fixture.Root}");
            throw;
        }
        await Task.CompletedTask;
    }

    private static JunctionIdentity ReadJunction(string home, string path)
    {
        using var junction = PersonalHarnessProfileModuleJunction.OpenRead(home, path);
        return new JunctionIdentity(
            junction.RawData.ToArray(),
            new DirectoryInfo(path).LinkTarget
                ?? throw new InvalidDataException("Junction target text is unavailable."));
    }

    private static void AssertJunctionEquals(JunctionIdentity expected, JunctionIdentity actual)
    {
        AssertTrue(expected.RawData.AsSpan().SequenceEqual(actual.RawData));
        AssertEqual(expected.TargetText, actual.TargetText);
    }

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try { return ((IPEndPoint)listener.LocalEndpoint).Port; }
        finally { listener.Stop(); }
    }

    private static void CreateJunction(string junction, string target)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(junction)!);
        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "cmd.exe"),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in new[] { "/d", "/c", "mklink", "/J", junction, target })
        {
            startInfo.ArgumentList.Add(argument);
        }
        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start the Junction fixture helper.");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(30_000))
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
            throw new TimeoutException("Junction fixture helper timed out.");
        }
        if (process.ExitCode != 0
            || !Directory.Exists(junction)
            || (File.GetAttributes(junction) & (FileAttributes.Directory | FileAttributes.ReparsePoint))
                != (FileAttributes.Directory | FileAttributes.ReparsePoint))
        {
            throw new InvalidOperationException(
                $"Could not create Junction fixture: {output.GetAwaiter().GetResult()} {error.GetAwaiter().GetResult()}");
        }
    }

    private static void DeleteTreeNoFollow(string path)
    {
        FileAttributes attributes;
        try { attributes = File.GetAttributes(path); }
        catch (FileNotFoundException) { return; }
        catch (DirectoryNotFoundException) { return; }
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            DeleteReparseOnly(path);
            return;
        }
        if ((attributes & FileAttributes.Directory) == 0)
        {
            File.Delete(path);
            return;
        }
        foreach (var child in Directory.EnumerateFileSystemEntries(path, "*", SearchOption.TopDirectoryOnly))
        {
            DeleteTreeNoFollow(child);
        }
        Directory.Delete(path, recursive: false);
    }

    private static void DeleteReparseOnly(string path)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) == 0)
        {
            throw new InvalidDataException("Fixture cleanup refused a non-reparse path.");
        }
        if ((attributes & FileAttributes.Directory) != 0) Directory.Delete(path, recursive: false);
        else File.Delete(path);
    }

    private static void AssertThrows<TException>(Action action) where TException : Exception
    {
        try { action(); }
        catch (TException) { return; }
        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }

    private static void AssertTrue(bool value)
    {
        if (!value) throw new InvalidOperationException("Assertion failed.");
    }

    private static void AssertEqual<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected '{expected}', got '{actual}'.");
        }
    }

    private sealed record JunctionIdentity(byte[] RawData, string TargetText);

    private sealed class Fixture
    {
        private readonly HashSet<string> _reparsePaths = new(StringComparer.OrdinalIgnoreCase);
        private readonly string _allowedRoot;
        private PersonalHarnessHomeLease? _lease;
        internal string Root { get; }
        internal string Home => Path.Combine(Root, "home");
        internal string Recovery => Path.Combine(Root, "recovery");
        internal string External => Path.Combine(Root, "external");
        internal string LocalDataPath => Path.Combine(Home, "history", "local.txt");
        internal string WorkspaceDataPath => Path.Combine(Home, "workspace", "draft.txt");

        internal Fixture(string name)
        {
            _allowedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.Combine(
                Path.GetTempPath(),
                "ensou-personal-profile-junction-tests")));
            Root = Path.GetFullPath(Path.Combine(
                _allowedRoot,
                name + "-" + Guid.NewGuid().ToString("N")));
            ValidateRootBoundary(requireAbsent: true);
        }

        internal void EnrollEmptyHome()
        {
            ValidateRootBoundary(requireAbsent: true);
            Directory.CreateDirectory(Home);
            _lease = new PersonalHarnessHomeCoordinator(Home).AcquireLease(
                () => throw new InvalidOperationException("Fresh fixture unexpectedly required legacy admission."));
        }

        internal void SeedLocalData()
        {
            Directory.CreateDirectory(Path.GetDirectoryName(LocalDataPath)!);
            File.WriteAllText(LocalDataPath, "local-history");
            Directory.CreateDirectory(Path.GetDirectoryName(WorkspaceDataPath)!);
            File.WriteAllText(WorkspaceDataPath, "local-workspace");
        }

        internal string CreateExternalPackage(string package, string contents)
        {
            var target = Path.Combine(External, "registry", "node_modules", package);
            Directory.CreateDirectory(target);
            File.WriteAllText(Path.Combine(target, "package.txt"), contents);
            return target;
        }

        internal string CreateNestedExternalPackage(string package, string contents)
        {
            var target = Path.Combine(
                External,
                "runtime",
                "node_modules",
                "parent",
                "node_modules",
                package);
            Directory.CreateDirectory(target);
            File.WriteAllText(Path.Combine(target, "package.txt"), contents);
            return target;
        }

        internal string GetPackagePath(string package) =>
            Path.Combine(Home, "profiles", "node_modules", package);

        internal string CreatePackageJunction(string package, string target)
        {
            var junction = GetPackagePath(package);
            CreateJunction(junction, target);
            TrackReparse(junction);
            return junction;
        }

        internal void CreateJunction(string path, string target)
        {
            PersonalHarnessProfileModuleJunctionTests.CreateJunction(path, target);
            TrackReparse(path);
        }

        internal void TrackReparse(string path) => _reparsePaths.Add(Path.GetFullPath(path));

        internal PersonalHarnessHomeTransaction CreateTransaction(
            Action<PersonalHarnessHomeMoveGapPhase, string, string>? moveGapHook = null)
        {
            return new PersonalHarnessHomeTransaction(
                Home,
                Recovery,
                TimeProvider.System,
                moveGapHook,
                PersonalHarnessWriterGuard.RequireAvailableLoopbackPort,
                _lease ?? throw new InvalidOperationException("Fixture home was not enrolled."));
        }

        internal void DeleteSuccessEvidenceNoFollow()
        {
            ValidateRootBoundary(requireAbsent: false);
            ReleaseLeasePreservingEvidence();
            foreach (var path in _reparsePaths
                         .OrderByDescending(path => path.Length))
            {
                try { DeleteReparseOnly(path); }
                catch (FileNotFoundException) { }
                catch (DirectoryNotFoundException) { }
            }
            DeleteTreeNoFollow(Root);
        }

        internal void ReleaseLeasePreservingEvidence()
        {
            _lease?.Dispose();
            _lease = null;
        }

        private void ValidateRootBoundary(bool requireAbsent)
        {
            var expectedPrefix = _allowedRoot + Path.DirectorySeparatorChar;
            if (!Root.StartsWith(expectedPrefix, StringComparison.OrdinalIgnoreCase)
                || string.Equals(Root, _allowedRoot, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Junction fixture root escaped its fixed test parent.");
            }

            var rootExists = TryGetAttributes(Root, out var rootAttributes);
            if (requireAbsent && rootExists)
            {
                throw new IOException("Junction fixture root must be create-only.");
            }
            if (!requireAbsent
                && (!rootExists
                    || (rootAttributes & FileAttributes.Directory) == 0
                    || (rootAttributes & FileAttributes.ReparsePoint) != 0))
            {
                throw new InvalidDataException("Junction fixture cleanup root is missing or linked.");
            }

            for (var current = new DirectoryInfo(Root); current is not null; current = current.Parent)
            {
                if (!TryGetAttributes(current.FullName, out var attributes)) continue;
                if ((attributes & FileAttributes.Directory) == 0
                    || (attributes & FileAttributes.ReparsePoint) != 0)
                {
                    throw new InvalidDataException(
                        "Junction fixture path crosses a non-directory or reparse ancestor.");
                }
            }
        }

        private static bool TryGetAttributes(string path, out FileAttributes attributes)
        {
            try
            {
                attributes = File.GetAttributes(path);
                return true;
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
            attributes = default;
            return false;
        }
    }
}
