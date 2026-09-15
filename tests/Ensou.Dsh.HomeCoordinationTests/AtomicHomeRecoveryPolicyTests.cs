using System.Text.Json.Nodes;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.UpdateEngine;

internal static class AtomicHomeRecoveryPolicyTests
{
    internal static IReadOnlyList<(string Name, Action Run)> Cases { get; } =
    [
        ("atomic recovery matrix admits only dead-owner exact-session empty or absent jobs", Matrix),
        ("legacy and malformed protocol claims cannot obtain atomic absence recovery", VersionFence),
        ("unknown session cannot establish local Job absence", SessionFence),
    ];

    private static void Matrix()
    {
        foreach (var owner in Enum.GetValues<PersonalOwnerObservationKind>())
        foreach (var job in Enum.GetValues<PersonalJobObservationKind>())
        {
            var actual = PersonalAtomicHomeRecoveryPolicy.RecoveryEvidence(2,
                PersonalAtomicHomeRecoveryPolicy.AtomicProtocol, 3, 3, owner, job);
            var expected = owner == PersonalOwnerObservationKind.Gone
                ? job switch
                {
                    PersonalJobObservationKind.Empty => "recovered-atomic-job-empty",
                    PersonalJobObservationKind.NotFound => "recovered-atomic-job-absent",
                    _ => null,
                } : null;
            Require(actual == expected);
        }
    }

    private static void VersionFence()
    {
        foreach (var schema in new[] { 0, 1, 3 })
            Require(PersonalAtomicHomeRecoveryPolicy.RecoveryEvidence(schema,
                PersonalAtomicHomeRecoveryPolicy.AtomicProtocol, 3, 3,
                PersonalOwnerObservationKind.Gone, PersonalJobObservationKind.NotFound) is null);
        foreach (var protocol in new[] { null, "", PersonalAtomicHomeRecoveryPolicy.LegacyProtocol, "unknown" })
            Require(PersonalAtomicHomeRecoveryPolicy.RecoveryEvidence(2, protocol, 3, 3,
                PersonalOwnerObservationKind.Gone, PersonalJobObservationKind.NotFound) is null);
    }

    private static void SessionFence()
    {
        foreach (var sessions in new (uint? Owner, uint? Observer)[] { (null, 3), (3, null), (3, 4), (null, null) })
            Require(PersonalAtomicHomeRecoveryPolicy.RecoveryEvidence(2,
                PersonalAtomicHomeRecoveryPolicy.AtomicProtocol, sessions.Owner, sessions.Observer,
                PersonalOwnerObservationKind.Gone, PersonalJobObservationKind.NotFound) is null);
    }

    // These optional state tests never start a process or perform recovery on an installed home.
    // The caller must supply a fresh private test root; no default home/layout is consulted.
    internal static IReadOnlyList<(string Name, Action Run)> StateCases(string privateRoot) =>
    [
        ("atomic factory writes v2 while legacy factory never downgrades it", () => FactoryVersioning(privateRoot)),
        ("unclean v1 cannot be promoted by the atomic factory", () => UncleanLegacyFence(privateRoot)),
        ("v2 requires its protocol fields and remains incompatible with a v1-only reader", () => MalformedAndOldReaderFence(privateRoot)),
        ("synthetic atomic recovery evidence cannot complete health", () => RecoveryCannotCompleteHealth(privateRoot)),
    ];

    private static void FactoryVersioning(string root)
    {
        var home = NewHome(root);
        using var lease = new PersonalHarnessHomeCoordinator(home).AcquireLease();
        using (var session = lease.BeginAtomicRuntimeSession())
        {
            Require(session is IDshAtomicHomeWriterSession);
            var state = ReadState(home);
            Require(state["schemaVersion"]!.GetValue<int>() == 2);
            Require(state["runtime"]!["containmentProtocol"]!.GetValue<string>() == PersonalAtomicHomeRecoveryPolicy.AtomicProtocol);
            Require(state["runtime"]!["ownerSessionId"] is not null);
            Require(session.JobName.StartsWith("Local\\Ensou.Dsh.Home.v2.", StringComparison.Ordinal));
            session.RecordNeverStarted();
        }
        using var legacy = lease.BeginRuntimeSession();
        Require(legacy is not IDshAtomicHomeWriterSession);
        var after = ReadState(home);
        Require(after["schemaVersion"]!.GetValue<int>() == 2);
        Require(after["runtime"]!["containmentProtocol"]!.GetValue<string>() == PersonalAtomicHomeRecoveryPolicy.LegacyProtocol);
        Require(after["runtime"]!["ownerSessionId"] is null);
        legacy.RecordNeverStarted();
    }

    private static void UncleanLegacyFence(string root)
    {
        var home = NewHome(root);
        using (var lease = new PersonalHarnessHomeCoordinator(home).AcquireLease())
        using (var session = lease.BeginRuntimeSession()) { }
        using var retry = new PersonalHarnessHomeCoordinator(home).AcquireLease();
        Throws<InvalidOperationException>(() => retry.BeginAtomicRuntimeSession());
        Require(ReadState(home)["schemaVersion"]!.GetValue<int>() == 1);
    }

    private static void MalformedAndOldReaderFence(string root)
    {
        var home = NewHome(root);
        using (var lease = new PersonalHarnessHomeCoordinator(home).AcquireLease())
        using (var session = lease.BeginAtomicRuntimeSession()) { session.RecordNeverStarted(); }
        var state = ReadState(home);
        // This is the existing reader's explicit schema fence, not a successful old-client rollback.
        Throws<InvalidDataException>(() =>
        {
            if (state["schemaVersion"]!.GetValue<int>() != 1) throw new InvalidDataException("v1 reader rejects v2");
        });
        state["runtime"]!.AsObject().Remove("containmentProtocol");
        File.WriteAllText(StatePath(home), state.ToJsonString());
        Throws<InvalidDataException>(() => new PersonalHarnessHomeCoordinator(home).AcquireLease());
    }

    private static string NewHome(string privateRoot)
    {
        const string allowed = "C:\\Users\\ensou\\Documents\\Codex\\2026-08-22\\q\\.tmp\\";
        if (!Path.IsPathFullyQualified(privateRoot) || !Path.GetFullPath(privateRoot).StartsWith(allowed, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Atomic state tests require the explicit task-private .tmp root.");
        for (var directory = new DirectoryInfo(privateRoot); directory is not null; directory = directory.Parent)
            if (directory.Exists && (directory.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Atomic state test root crosses a link.");
        var home = Path.Combine(privateRoot, "atomic-state-" + Guid.NewGuid().ToString("N"), "home");
        return home;
    }

    private static void RecoveryCannotCompleteHealth(string root)
    {
        foreach (var evidence in new[] { "recovered-atomic-job-empty", "recovered-atomic-job-absent" })
        {
            var home = NewHome(root);
            using (var lease = new PersonalHarnessHomeCoordinator(home).AcquireLease())
            {
                lease.AdmitHealthAttempt("synthetic-transaction", "synthetic-token");
                using var session = lease.BeginAtomicRuntimeSession();
                // A test-only metadata substitute; no actual process/Job/health is claimed.
                session.RecordAssignedProcess(12345, 1);
                session.RecordJobEmpty();
            }
            var state = ReadState(home);
            state["runtime"]!["cleanEvidence"] = evidence;
            File.WriteAllText(StatePath(home), state.ToJsonString());
            using var retry = new PersonalHarnessHomeCoordinator(home).AcquireLease();
            retry.RequireMutationAdmission(home);
            Throws<InvalidOperationException>(() => retry.CompleteHealthAttempt("synthetic-transaction", "synthetic-token"));
            Require(ReadState(home)["healthAttempt"]!["phase"]!.GetValue<string>() == "admitted");
        }
    }

    private static string StatePath(string home) => Directory.GetFiles(
        Path.Combine(Path.GetDirectoryName(home)!, ".ensou-dsh-home-coordination"), "state.v1.json", SearchOption.AllDirectories).Single();
    private static JsonObject ReadState(string home) => JsonNode.Parse(File.ReadAllText(StatePath(home)))!.AsObject();
    private static void Require(bool condition) { if (!condition) throw new InvalidOperationException("Atomic recovery policy assertion failed."); }
    private static void Throws<T>(Action action) where T : Exception
    {
        try { action(); } catch (T) { return; }
        throw new InvalidOperationException("Expected atomic recovery rejection was absent.");
    }
}
