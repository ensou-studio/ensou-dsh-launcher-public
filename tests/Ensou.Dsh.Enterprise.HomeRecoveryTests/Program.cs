using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.HomeRecoveryTests;

internal static class Program
{
    private static int Main()
    {
        var tests = new (string Name, Action Run)[]
        {
            ("rollback restores the complete original home", RollbackRestoresOriginal),
            ("commit retains recovery generation and clears active state", CommitRetainsRecovery),
            ("startup recovery restores an interrupted prepared update", RecoverInterruptedUpdate),
            ("filesystem links fail closed", ReparsePointFailsClosed),
            ("occupied Harness port fails closed", OccupiedPortFailsClosed),
            ("Harness port takeover before rename fails closed", PortTakeoverBeforeRenameFailsClosed),
            ("open foreign writer fails closed", OpenForeignWriterFailsClosed),
            ("rename gap permits only an exactly restored tree", MoveGapExactRestore),
            ("rename gap rejects a persistent writer", MoveGapPersistentWriter),
            ("rename gap rejects a created entry", () => MoveGapMutationRejected("create")),
            ("rename gap rejects a deleted entry", () => MoveGapMutationRejected("delete")),
            ("rename gap rejects a replaced entry", () => MoveGapMutationRejected("replace")),
            ("rename gap rejects a reparse entry", MoveGapReparseRejected),
        };
        var failed = 0;
        foreach (var test in tests)
        {
            try
            {
                test.Run();
                Console.WriteLine($"PASS {test.Name}");
            }
            catch (Exception exception)
            {
                failed++;
                Console.Error.WriteLine($"FAIL {test.Name}: {exception}");
            }
        }
        return failed == 0 ? 0 : 1;
    }

    private static void RollbackRestoresOriginal()
    {
        using var fixture = new Fixture();
        fixture.Seed();
        var transaction = fixture.CreateTransaction();
        var prepared = transaction.Prepare(Fixture.ReleaseId, GetFreePort());
        File.WriteAllText(Path.Combine(fixture.Home, "settings.yaml"), "candidate");
        File.WriteAllText(Path.Combine(fixture.Home, "candidate-only.txt"), "new");

        var restored = transaction.Rollback(prepared.TransactionId, "runtime-health-failed");

        Equal(EnterpriseHarnessHomeUpdateTransaction.RestoredStatus, restored.Status);
        Equal("original", File.ReadAllText(Path.Combine(fixture.Home, "settings.yaml")));
        True(!File.Exists(Path.Combine(fixture.Home, "candidate-only.txt")));
        True(restored.FailedCandidateDirectory is not null
            && File.Exists(Path.Combine(restored.FailedCandidateDirectory, "candidate-only.txt")));
    }

    private static void CommitRetainsRecovery()
    {
        using var fixture = new Fixture();
        fixture.Seed();
        var transaction = fixture.CreateTransaction();
        var prepared = transaction.Prepare(Fixture.ReleaseId, GetFreePort());
        File.WriteAllText(Path.Combine(fixture.Home, "migration.txt"), "committed");

        transaction.Commit(prepared.TransactionId);

        True(File.Exists(Path.Combine(fixture.Home, "migration.txt")));
        True(Directory.Exists(prepared.OriginalDirectory));
        True(transaction.TryReadPrepared() is null);
    }

    private static void RecoverInterruptedUpdate()
    {
        using var fixture = new Fixture();
        fixture.Seed();
        var transaction = fixture.CreateTransaction();
        _ = transaction.Prepare(Fixture.ReleaseId, GetFreePort());
        File.WriteAllText(Path.Combine(fixture.Home, "settings.yaml"), "half-migrated");

        var recovered = fixture.CreateTransaction().RecoverInterrupted();

        True(recovered is not null);
        Equal(EnterpriseHarnessHomeUpdateTransaction.RestoredStatus, recovered!.Status);
        Equal("original", File.ReadAllText(Path.Combine(fixture.Home, "settings.yaml")));
    }

    private static void ReparsePointFailsClosed()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        using var fixture = new Fixture();
        fixture.Seed();
        var target = Path.Combine(fixture.Root, "target");
        Directory.CreateDirectory(target);
        var link = Path.Combine(fixture.Home, "linked-workspace");
        try
        {
            Directory.CreateSymbolicLink(link, target);
        }
        catch (Exception exception) when (
            exception is UnauthorizedAccessException or IOException)
        {
            return;
        }
        Throws<InvalidDataException>(() =>
            fixture.CreateTransaction().Prepare(Fixture.ReleaseId, GetFreePort()));
    }

    private static void OccupiedPortFailsClosed()
    {
        using var fixture = new Fixture();
        fixture.Seed();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        Throws<InvalidOperationException>(() =>
            fixture.CreateTransaction().Prepare(Fixture.ReleaseId, port));

        Equal("original", File.ReadAllText(Path.Combine(fixture.Home, "settings.yaml")));
        True(fixture.CreateTransaction().TryReadActiveState() is null);
    }

    private static void OpenForeignWriterFailsClosed()
    {
        using var fixture = new Fixture();
        fixture.Seed();
        var path = Path.Combine(fixture.Home, "settings.yaml");
        using var writer = new FileStream(
            path,
            FileMode.Open,
            FileAccess.ReadWrite,
            FileShare.Read | FileShare.Delete);

        Throws<InvalidOperationException>(() =>
            fixture.CreateTransaction().Prepare(Fixture.ReleaseId, GetFreePort()));

        writer.Dispose();
        Equal("original", File.ReadAllText(path));
        True(fixture.CreateTransaction().TryReadActiveState() is null);
    }

    private static void PortTakeoverBeforeRenameFailsClosed()
    {
        using var fixture = new Fixture();
        fixture.Seed();
        var port = GetFreePort();
        TcpListener? listener = null;
        var transaction = fixture.CreateTransaction((phase, _, _) =>
        {
            if (phase == EnterpriseHarnessHomeMoveGapPhase.StatePersistedBeforeSecondGuard)
            {
                listener = new TcpListener(IPAddress.Loopback, port);
                listener.Start();
            }
        });

        try
        {
            Throws<InvalidOperationException>(() =>
                transaction.Prepare(Fixture.ReleaseId, port));
        }
        finally
        {
            listener?.Stop();
        }
        Equal("original", File.ReadAllText(Path.Combine(fixture.Home, "settings.yaml")));
        True(transaction.TryReadActiveState() is null);
    }

    private static void MoveGapExactRestore()
    {
        using var fixture = new Fixture();
        fixture.Seed();
        var dataPath = Path.Combine(fixture.Home, "settings.yaml");
        var sawRelockedCloneBoundary = false;
        var transaction = fixture.CreateTransaction((phase, _, originalDirectory) =>
        {
            var originalData = Path.Combine(originalDirectory, "settings.yaml");
            if (phase == EnterpriseHarnessHomeMoveGapPhase.DescendantsReleasedBeforeMove)
            {
                File.WriteAllText(dataPath, "transient-write");
                File.WriteAllText(dataPath, "original");
            }
            else if (phase == EnterpriseHarnessHomeMoveGapPhase.DestinationRelockedBeforeClone)
            {
                sawRelockedCloneBoundary = true;
                MutationDenied(() => File.WriteAllText(originalData, "blocked-write"));
            }
        });

        var prepared = transaction.Prepare(Fixture.ReleaseId, GetFreePort());

        True(sawRelockedCloneBoundary);
        Equal("original", File.ReadAllText(dataPath));
        _ = transaction.Rollback(prepared.TransactionId, "test-complete");
        Equal("original", File.ReadAllText(dataPath));
    }

    private static void MoveGapPersistentWriter()
    {
        using var fixture = new Fixture();
        fixture.Seed();
        FileStream? writer = null;
        var transaction = fixture.CreateTransaction((phase, _, originalDirectory) =>
        {
            if (phase == EnterpriseHarnessHomeMoveGapPhase.RootMovedBeforeRelock)
            {
                writer = new FileStream(
                    Path.Combine(originalDirectory, "settings.yaml"),
                    FileMode.Open,
                    FileAccess.ReadWrite,
                    FileShare.Read | FileShare.Delete);
            }
        });

        try
        {
            Throws<InvalidOperationException>(() =>
                transaction.Prepare(Fixture.ReleaseId, GetFreePort()));
            True(transaction.TryReadActiveState() is not null);
        }
        finally
        {
            writer?.Dispose();
        }
        var recovered = transaction.RecoverInterrupted();
        True(recovered is not null);
        Equal(EnterpriseHarnessHomeUpdateTransaction.RestoredStatus, recovered!.Status);
        Equal("original", File.ReadAllText(Path.Combine(fixture.Home, "settings.yaml")));
    }

    private static void MoveGapMutationRejected(string mutation)
    {
        using var fixture = new Fixture();
        fixture.Seed();
        var dataPath = Path.Combine(fixture.Home, "settings.yaml");
        var extraPath = Path.Combine(fixture.Home, "extra.bin");
        var transaction = fixture.CreateTransaction((phase, _, _) =>
        {
            if (phase != EnterpriseHarnessHomeMoveGapPhase.DescendantsReleasedBeforeMove)
            {
                return;
            }
            switch (mutation)
            {
                case "create":
                    File.WriteAllText(extraPath, "extra");
                    break;
                case "delete":
                    File.Delete(dataPath);
                    break;
                case "replace":
                    File.Delete(dataPath);
                    File.WriteAllText(dataPath, "replacement");
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(mutation));
            }
        });

        Throws<InvalidDataException>(() =>
            transaction.Prepare(Fixture.ReleaseId, GetFreePort()));
        var active = transaction.TryReadActiveState()
            ?? throw new InvalidOperationException("Expected fail-closed active recovery state.");
        var movedData = Path.Combine(active.OriginalDirectory, "settings.yaml");
        if (mutation == "create")
        {
            File.Delete(Path.Combine(active.OriginalDirectory, "extra.bin"));
        }
        else
        {
            File.WriteAllText(movedData, "original");
        }
        var recovered = transaction.RecoverInterrupted();
        True(recovered is not null);
        Equal(EnterpriseHarnessHomeUpdateTransaction.RestoredStatus, recovered!.Status);
        Equal("original", File.ReadAllText(dataPath));
    }

    private static void MoveGapReparseRejected()
    {
        using var fixture = new Fixture();
        fixture.Seed();
        var target = Path.Combine(fixture.Root, "linked-target");
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "outside.bin"), "outside");
        var transaction = fixture.CreateTransaction((phase, _, _) =>
        {
            if (phase == EnterpriseHarnessHomeMoveGapPhase.DescendantsReleasedBeforeMove)
            {
                CreateDirectoryLinkForTest(
                    Path.Combine(fixture.Home, "linked"),
                    target);
            }
        });

        Throws<InvalidDataException>(() =>
            transaction.Prepare(Fixture.ReleaseId, GetFreePort()));
        var active = transaction.TryReadActiveState()
            ?? throw new InvalidOperationException("Expected fail-closed active recovery state.");
        Directory.Delete(Path.Combine(active.OriginalDirectory, "linked"));
        var recovered = transaction.RecoverInterrupted();
        True(recovered is not null);
        Equal(EnterpriseHarnessHomeUpdateTransaction.RestoredStatus, recovered!.Status);
        Equal("original", File.ReadAllText(Path.Combine(fixture.Home, "settings.yaml")));
    }

    private static void True(bool value)
    {
        if (!value) throw new InvalidOperationException("Assertion failed.");
    }

    private static void Equal<T>(T expected, T actual)
        where T : notnull
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected {expected}, got {actual}.");
        }
    }

    private static void Throws<T>(Action action)
        where T : Exception
    {
        try
        {
            action();
        }
        catch (T)
        {
            return;
        }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }

    private static int GetFreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static void MutationDenied(Action action)
    {
        try
        {
            action();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return;
        }
        throw new InvalidOperationException("Expected the locked filesystem mutation to be denied.");
    }

    private static void CreateDirectoryLinkForTest(string linkPath, string targetPath)
    {
        try
        {
            Directory.CreateSymbolicLink(linkPath, targetPath);
            return;
        }
        catch (IOException) when (OperatingSystem.IsWindows())
        {
            // Junctions exercise the same reparse-point boundary without the
            // symbolic-link privilege on standard Windows test workers.
        }
        var startInfo = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        };
        startInfo.ArgumentList.Add("/d");
        startInfo.ArgumentList.Add("/c");
        startInfo.ArgumentList.Add("mklink");
        startInfo.ArgumentList.Add("/J");
        startInfo.ArgumentList.Add(linkPath);
        startInfo.ArgumentList.Add(targetPath);
        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start junction test helper.");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0 || !Directory.Exists(linkPath))
        {
            throw new InvalidOperationException(
                $"Could not create test junction: {output} {error}");
        }
    }

    private sealed class Fixture : IDisposable
    {
        public const string ReleaseId = "managed-v2026.08.26.1";
        public Fixture()
        {
            Root = Path.Combine(Path.GetTempPath(), $"ensou-home-recovery-{Guid.NewGuid():N}");
            Home = Path.Combine(Root, ".dsh-enterprise");
            Recovery = Path.Combine(Root, ".dsh-enterprise-recovery");
            Directory.CreateDirectory(Home);
        }

        public string Root { get; }
        public string Home { get; }
        public string Recovery { get; }

        public void Seed()
        {
            Directory.CreateDirectory(Path.Combine(Home, "sessions", "nested"));
            Directory.CreateDirectory(Path.Combine(Home, "workspaces", "empty"));
            File.WriteAllText(Path.Combine(Home, "settings.yaml"), "original");
            File.WriteAllBytes(Path.Combine(Home, "sessions", "nested", "history.bin"), [0, 1, 2, 3, 255]);
        }

        public EnterpriseHarnessHomeUpdateTransaction CreateTransaction() => new(
            Home,
            Recovery,
            TimeProvider.System,
            moveGapHookForTesting: null,
            requireQuiescentLoopbackPort:
                EnterpriseHarnessWriterGuard.RequireQuiescentLoopbackPort,
            requireNoPossibleHarnessWriter: static () => { });

        public EnterpriseHarnessHomeUpdateTransaction CreateTransaction(
            Action<EnterpriseHarnessHomeMoveGapPhase, string, string> moveGapHook) =>
            new(
                Home,
                Recovery,
                TimeProvider.System,
                moveGapHook,
                EnterpriseHarnessWriterGuard.RequireQuiescentLoopbackPort,
                requireNoPossibleHarnessWriter: static () => { });

        public void Dispose()
        {
            if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true);
        }
    }
}
