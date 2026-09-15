using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Ensou.Dsh.UpdateEngine;

internal static class VerifiedRollbackCompatibilityTests
{
    // Optional isolated filesystem cases. No process, Job, port, default layout, or installed home is used.
    internal static IReadOnlyList<(string Name, Action Run)> StateCases(string privateRoot) =>
    [
        ("verified rollback restores data and emits a fresh v1 enrollment", () => RestoreAndReset(privateRoot)),
        ("long Unicode home rename preserves complete rollback and commit behavior", () => LongPathRename(privateRoot)),
        ("each rollback persistence interruption is safely retryable", () => InterruptedCheckpoints(privateRoot)),
        ("restored retry remeasures and rejects changed original data", () => RestoredTamper(privateRoot)),
        ("a retained clean writer session blocks legacy enrollment reset", () => RetainedWriter(privateRoot)),
        ("healthy commit retains atomic schema and never demotes", () => HealthyCommit(privateRoot)),
        ("unrelated completed health is not discarded during rollback reset", () => UnrelatedAttempt(privateRoot)),
        ("an unissued rollback proof cannot reset an atomic generation", () => UnissuedProof(privateRoot)),
    ];

    private static void RestoreAndReset(string root)
    {
        using var fixture = new Fixture(root);
        var transaction = fixture.Transaction();
        var state = fixture.PrepareAtomic(transaction);
        var restored = transaction.Rollback(state.TransactionId, "synthetic-failure");
        fixture.RequireRestored(transaction);
        Require(restored.FailedCandidateDirectory is not null);
        Require(File.ReadAllText(Path.Combine(restored.FailedCandidateDirectory!, "history.txt")) == "candidate-data");
        Require(transaction.RecoverInterrupted() is null);
    }

    private static void LongPathRename(string root)
    {
        // Keep this beyond MAX_PATH even if the runner moves to a shorter private output path.
        var longRoot = Path.Combine(root, "rename-資料-" + new string('a', 110), "segment-" + new string('b', 110));
        using var fixture = new Fixture(longRoot);
        Require(fixture.Home.Length > 260);
        var transaction = fixture.Transaction();
        var prepared = fixture.PrepareAtomic(transaction);
        Require(prepared.OriginalDirectory.Length > 260);
        Require(!prepared.OriginalDirectory.StartsWith(@"\\?\", StringComparison.Ordinal));
        Require(File.ReadAllText(Path.Combine(prepared.OriginalDirectory, "history.txt")) == "original-data");
        var restored = transaction.Rollback(prepared.TransactionId, "long-path-failure");
        fixture.RequireRestored(transaction);
        Require(File.ReadAllText(Path.Combine(restored.FailedCandidateDirectory!, "history.txt")) == "candidate-data");

        var next = fixture.PrepareAtomic(transaction);
        transaction.VerifyCandidateReadable(next.TransactionId);
        fixture.Lease.CompleteHealthAttempt(next.TransactionId, "synthetic-token");
        transaction.MarkHealthPassed(next.TransactionId);
        transaction.FinalizeCommit(next.TransactionId);
        Require(transaction.TryReadActive() is null);
        Require(File.ReadAllText(fixture.HistoryPath) == "candidate-data");
        Require(fixture.State()["schemaVersion"]!.GetValue<int>() == 2);
    }

    private static void InterruptedCheckpoints(string root)
    {
        foreach (var checkpoint in Enum.GetValues<PersonalHarnessHomeRollbackCheckpoint>())
        {
            using var fixture = new Fixture(root);
            var transaction = fixture.Transaction(actual =>
            {
                if (actual == checkpoint) throw new SyntheticInterruption();
            });
            var state = fixture.PrepareAtomic(transaction);
            Throws<SyntheticInterruption>(() => transaction.Rollback(state.TransactionId, "synthetic-failure"));
            Require(File.ReadAllText(fixture.HistoryPath) == "original-data");
            var active = transaction.TryReadActive()!;
            Require(active.TransactionId == state.TransactionId);
            var reset = checkpoint == PersonalHarnessHomeRollbackCheckpoint.LegacyCoordinationPrepared;
            Require(fixture.State()["schemaVersion"]!.GetValue<int>() == (reset ? 1 : 2));
            if (checkpoint != PersonalHarnessHomeRollbackCheckpoint.RestoredJournalWritten)
            {
                Require(active.Status == PersonalHarnessHomeTransaction.RestoredStatus);
                Throws<InvalidOperationException>(() => transaction.VerifyCandidateReadable(state.TransactionId));
                Throws<InvalidOperationException>(() => transaction.MarkHealthPassed(state.TransactionId));
            }
            // Model process restart by releasing and reacquiring the actual home admission lease.
            fixture.Reacquire();
            var retry = fixture.Transaction();
            var restored = checkpoint == PersonalHarnessHomeRollbackCheckpoint.RestoredActiveWritten
                ? retry.Rollback(state.TransactionId, "synthetic-retry")
                : retry.RecoverInterrupted();
            Require(restored?.Status == PersonalHarnessHomeTransaction.RestoredStatus);
            Require(restored!.FailedCandidateDirectory is not null);
            Require(File.ReadAllText(Path.Combine(restored.FailedCandidateDirectory!, "history.txt")) == "candidate-data");
            fixture.RequireRestored(retry);
        }
    }

    private static void RestoredTamper(string root)
    {
        using var fixture = new Fixture(root);
        var transaction = fixture.Transaction(phase =>
        {
            if (phase == PersonalHarnessHomeRollbackCheckpoint.LegacyCoordinationPrepared)
                throw new SyntheticInterruption();
        });
        var state = fixture.PrepareAtomic(transaction);
        Throws<SyntheticInterruption>(() => transaction.Rollback(state.TransactionId, "synthetic-failure"));
        File.WriteAllText(fixture.HistoryPath, "changed-after-restoration");
        fixture.Reacquire();
        var retry = fixture.Transaction();
        Throws<InvalidDataException>(() => retry.RecoverInterrupted());
        Require(retry.TryReadActive()?.Status == PersonalHarnessHomeTransaction.RestoredStatus);
        Require(File.ReadAllText(fixture.HistoryPath) == "changed-after-restoration");
        Throws<InvalidOperationException>(() => retry.VerifyCandidateReadable(state.TransactionId));
    }

    private static void RetainedWriter(string root)
    {
        using var fixture = new Fixture(root);
        var transaction = fixture.Transaction();
        var state = transaction.Prepare("synthetic-release", 3080);
        using (var session = fixture.Lease.BeginAtomicRuntimeSession())
        {
            session.RecordNeverStarted();
            Throws<InvalidOperationException>(() => transaction.Rollback(state.TransactionId, "synthetic-failure"));
            Require(transaction.TryReadActive()?.Status == PersonalHarnessHomeTransaction.RestoredStatus);
            Require(fixture.State()["schemaVersion"]!.GetValue<int>() == 2);
        }
        transaction.Rollback(state.TransactionId, "synthetic-retry");
        fixture.RequireRestored(transaction);
    }

    private static void HealthyCommit(string root)
    {
        using var fixture = new Fixture(root);
        var transaction = fixture.Transaction();
        var state = fixture.PrepareAtomic(transaction);
        transaction.VerifyCandidateReadable(state.TransactionId);
        fixture.Lease.CompleteHealthAttempt(state.TransactionId, "synthetic-token");
        transaction.MarkHealthPassed(state.TransactionId);
        transaction.FinalizeCommit(state.TransactionId);
        Require(transaction.TryReadActive() is null);
        Require(fixture.State()["schemaVersion"]!.GetValue<int>() == 2);
        Require(fixture.State()["runtime"] is not null);
        Require(File.ReadAllText(fixture.HistoryPath) == "candidate-data");
    }

    private static void UnrelatedAttempt(string root)
    {
        using var fixture = new Fixture(root);
        fixture.Lease.AdmitHealthAttempt("earlier-transaction", "synthetic-token");
        using (var session = fixture.Lease.BeginAtomicRuntimeSession())
        {
            // Synthetic persisted lifecycle evidence only; no real process or health success is claimed.
            session.RecordAssignedProcess(12345, 1);
            session.RecordJobEmpty();
        }
        fixture.Lease.CompleteHealthAttempt("earlier-transaction", "synthetic-token");
        var transaction = fixture.Transaction();
        var state = transaction.Prepare("synthetic-release", 3080);
        Throws<InvalidOperationException>(() => transaction.Rollback(state.TransactionId, "synthetic-failure"));
        Require(fixture.State()["schemaVersion"]!.GetValue<int>() == 2);
        Require(fixture.State()["healthAttempt"]!["transactionId"]!.GetValue<string>() == "earlier-transaction");
        Require(transaction.TryReadActive()?.Status == PersonalHarnessHomeTransaction.RestoredStatus);
    }

    private static void UnissuedProof(string root)
    {
        using var fixture = new Fixture(root);
        var transaction = fixture.Transaction();
        var state = fixture.PrepareAtomic(transaction);
        fixture.Lease.AbortHealthAttempt(state.TransactionId);
        var proof = new PersonalHarnessHomeTransaction.VerifiedRollbackProof(transaction, fixture.Lease,
            state with { Status = PersonalHarnessHomeTransaction.RestoredStatus }, fixture.Lease.RollbackGenerationId);
        var before = File.ReadAllBytes(fixture.StatePath);
        Throws<InvalidOperationException>(() => fixture.Lease.PrepareLegacyCoordinationAfterVerifiedRollback(proof));
        Require(before.SequenceEqual(File.ReadAllBytes(fixture.StatePath)));
        Require(transaction.TryReadActive()?.Status == PersonalHarnessHomeTransaction.PreparedStatus);
    }

    private sealed class Fixture : IDisposable
    {
        internal string Home { get; }
        internal string Recovery { get; }
        internal string HistoryPath => Path.Combine(Home, "history.txt");
        internal PersonalHarnessHomeLease Lease { get; private set; }
        internal string StatePath => Directory.GetFiles(Path.Combine(Path.GetDirectoryName(Home)!,
            ".ensou-dsh-home-coordination"), "state.v1.json", SearchOption.AllDirectories).Single();
        internal JsonObject State() => JsonNode.Parse(File.ReadAllText(StatePath))!.AsObject();

        internal Fixture(string root)
        {
            const string allowed = "C:\\Users\\ensou\\Documents\\Codex\\2026-08-22\\q\\.tmp\\";
            if (!Path.IsPathFullyQualified(root) || !Path.GetFullPath(root).StartsWith(allowed, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Rollback compatibility tests require the explicit task-private .tmp root.");
            for (var directory = new DirectoryInfo(root); directory is not null; directory = directory.Parent)
                if (directory.Exists && (directory.Attributes & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException("Rollback compatibility test root crosses a link.");
            var isolated = Path.Combine(root, "rollback-state-" + Guid.NewGuid().ToString("N"));
            Home = Path.Combine(isolated, "home");
            Recovery = Path.Combine(isolated, "recovery");
            Lease = new PersonalHarnessHomeCoordinator(Home).AcquireLease();
            Directory.CreateDirectory(Home);
            File.WriteAllText(HistoryPath, "original-data");
        }

        internal PersonalHarnessHomeTransaction Transaction(Action<PersonalHarnessHomeRollbackCheckpoint>? checkpoint = null) =>
            new(Home, Recovery, timeProvider: null, moveGapHookForTesting: null,
                writerGuardForTesting: _ => { }, homeLease: Lease, rollbackCheckpointForTesting: checkpoint);

        internal PersonalHarnessHomeRecoveryState PrepareAtomic(PersonalHarnessHomeTransaction transaction)
        {
            var state = transaction.Prepare("synthetic-release", 3080);
            Lease.AdmitHealthAttempt(state.TransactionId, "synthetic-token");
            using (var session = Lease.BeginAtomicRuntimeSession())
            {
                // Test-only metadata substitute; this does not start a process or assert real Job health.
                session.RecordAssignedProcess(12345, 1);
                session.RecordJobEmpty();
            }
            File.WriteAllText(HistoryPath, "candidate-data");
            return state;
        }

        internal void Reacquire()
        {
            Lease.Dispose();
            Lease = new PersonalHarnessHomeCoordinator(Home).AcquireLease();
        }

        internal void RequireRestored(PersonalHarnessHomeTransaction transaction)
        {
            Require(File.ReadAllText(HistoryPath) == "original-data");
            Require(transaction.TryReadActive() is null);
            var state = State();
            Require(state["schemaVersion"]!.GetValue<int>() == 1 && state["runtime"] is null && state["healthAttempt"] is null);
            // Exact legacy enrollment wire-shape check only, not an executed old Stub/Previous binary test.
            var legacy = JsonSerializer.Deserialize<LegacyEnrollment>(File.ReadAllText(StatePath), new JsonSerializerOptions(JsonSerializerDefaults.Web)
            { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, PropertyNameCaseInsensitive = false })!;
            Require(legacy.SchemaVersion == 1 && legacy.Runtime is null && legacy.HealthAttempt is null);
            Require(string.Equals(legacy.CanonicalHarnessHome, Lease.CanonicalHarnessHome, StringComparison.Ordinal));
            Require(legacy.HomeKey.Length == 64);
        }

        public void Dispose() => Lease.Dispose();
    }

    private sealed record LegacyEnrollment(int SchemaVersion, string CanonicalHarnessHome, string HomeKey,
        JsonElement? Runtime, JsonElement? HealthAttempt);
    private sealed class SyntheticInterruption : Exception { }
    private static void Require(bool condition)
    { if (!condition) throw new InvalidOperationException("Verified rollback compatibility assertion failed."); }
    private static void Throws<T>(Action action) where T : Exception
    {
        try { action(); } catch (T) { return; }
        throw new InvalidOperationException("Expected verified rollback compatibility rejection was absent.");
    }
}
