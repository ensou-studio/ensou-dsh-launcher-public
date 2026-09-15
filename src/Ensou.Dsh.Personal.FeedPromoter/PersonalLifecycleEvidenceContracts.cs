using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.Personal.FeedPromoter;

public static class PersonalLifecycleEvidenceContract
{
    public const int SchemaVersion = 1;
    public const int MaximumReceiptBytes = 512 * 1024;
    public const string ReceiptType = "ensou-dsh-personal-certified-lifecycle-evidence";
    public const string CleanDeviceLifecycle = "clean-device-lifecycle";
    public const string TwoUpdateUpgradeLifecycle = "two-update-upgrade-lifecycle";
    public const string FailureRecoveryLifecycle = "failure-recovery-lifecycle";

    private static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> Gates =
        new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
        {
            [CleanDeviceLifecycle] =
            [
                "clean-install",
                "launcher-self-update",
                "actual-runtime-start",
                "webui-open",
                "client-restart",
                "repair-offline",
                "history-preservation",
                "workspace-preservation",
                "pilot-soak",
            ],
            [TwoUpdateUpgradeLifecycle] =
            [
                "old-install-upgrade",
                "launcher-self-update",
                "second-consecutive-update",
                "actual-runtime-start",
                "client-restart",
                "history-preservation",
                "workspace-preservation",
            ],
            [FailureRecoveryLifecycle] =
            [
                "whole-home-restore",
                "previous-runtime-restart",
                "interruption-matrix",
                "weak-network-resume",
                "offline-replay-matrix",
                "repair-offline",
                "history-preservation",
                "workspace-preservation",
            ],
        };

    public static IReadOnlyList<string> RequiredGates(string kind) =>
        Gates.TryGetValue(kind, out var gates)
            ? gates
            : throw new InvalidDataException("Personal lifecycle evidence kind is invalid.");

    public static void RequireCanonicalTestRunId(string? testRunId)
    {
        if (!Guid.TryParseExact(testRunId, "D", out var value)
            || !string.Equals(value.ToString("D"), testRunId, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal lifecycle evidence testRunId must be one lowercase canonical UUID.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalLifecycleEvidenceReceipt
{
    public required int SchemaVersion { get; init; }
    public required string ReceiptType { get; init; }
    public required string Product { get; init; }
    public required string Environment { get; init; }
    public required string Channel { get; init; }
    public required string Kind { get; init; }
    public required string TestRunId { get; init; }
    public required string ReleaseSetId { get; init; }
    public required long Generation { get; init; }
    public required long Sequence { get; init; }
    public required string PilotManifestSha256 { get; init; }
    public required IReadOnlyList<PersonalFeedArtifactReceipt> Artifacts { get; init; }
    public required DateTimeOffset CompletedAtUtc { get; init; }
    public required IReadOnlyList<PersonalLifecycleUpdateHop> UpdateChain { get; init; }
    public required PersonalLifecycleLocalDataWitness LocalDataWitness { get; init; }
    public required IReadOnlyList<PersonalLifecycleGateEvidence> RequiredGates { get; init; }

    public static PersonalLifecycleEvidenceReceipt Parse(ReadOnlySpan<byte> json)
    {
        if (json.Length is <= 0 or > PersonalLifecycleEvidenceContract.MaximumReceiptBytes)
        {
            throw new InvalidDataException("Personal lifecycle evidence receipt size is invalid.");
        }
        try
        {
            PersonalFeedJson.RequireNoDuplicateMembers(json);
            var value = JsonSerializer.Deserialize<PersonalLifecycleEvidenceReceipt>(
                    json,
                    PersonalFeedJson.Options)
                ?? throw new InvalidDataException(
                    "Personal lifecycle evidence receipt is empty.");
            value.RequireValidShape();
            var canonical = PersonalFeedJson.Serialize(value);
            if (!json.SequenceEqual(canonical))
            {
                throw new InvalidDataException(
                    "Personal lifecycle evidence receipt must use canonical JSON encoding.");
            }
            return value;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Personal lifecycle evidence receipt JSON is invalid.",
                exception);
        }
    }

    public byte[] SerializeCanonical()
    {
        RequireValidShape();
        return PersonalFeedJson.Serialize(this);
    }

    public void VerifyTarget(
        PersonalReleaseSetManifest target,
        string pilotManifestSha256)
    {
        ArgumentNullException.ThrowIfNull(target);
        RequireValidShape();
        var expectedArtifacts = PersonalFeedArtifactReceipt.FromManifest(target);
        if (!string.Equals(ReleaseSetId, target.ReleaseSetId, StringComparison.Ordinal)
            || Generation != target.Generation
            || Sequence != target.Sequence
            || !string.Equals(PilotManifestSha256, pilotManifestSha256, StringComparison.Ordinal)
            || Artifacts is null
            || !Artifacts.SequenceEqual(expectedArtifacts))
        {
            throw new InvalidDataException(
                "Personal lifecycle evidence does not bind the exact certified release target.");
        }
    }

    private void RequireValidShape()
    {
        PersonalLifecycleEvidenceContract.RequireCanonicalTestRunId(TestRunId);
        PersonalReleaseSetValidator.ValidateToken(ReleaseSetId, "evidence releaseSetId", 128);
        var expectedGates = PersonalLifecycleEvidenceContract.RequiredGates(Kind);
        if (SchemaVersion != PersonalLifecycleEvidenceContract.SchemaVersion
            || !string.Equals(
                ReceiptType,
                PersonalLifecycleEvidenceContract.ReceiptType,
                StringComparison.Ordinal)
            || !string.Equals(Product, PersonalReleaseSetContract.Product, StringComparison.Ordinal)
            || !string.Equals(
                Environment,
                PersonalReleaseSetContract.ProductionEnvironment,
                StringComparison.Ordinal)
            || !string.Equals(Channel, "pilot", StringComparison.Ordinal)
            || Generation is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || Sequence is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || !PersonalReleaseSetValidator.IsSha256(PilotManifestSha256)
            || Artifacts is null
            || Artifacts.Count != 2
            || Artifacts.Any(artifact => artifact is null || !artifact.IsValid())
            || Artifacts.Select(artifact => artifact.Component).Distinct(StringComparer.Ordinal).Count() != 2
            || CompletedAtUtc.Offset != TimeSpan.Zero
            || UpdateChain is null
            || LocalDataWitness is null
            || RequiredGates is null
            || !RequiredGates.Select(gate => gate.Gate).SequenceEqual(
                expectedGates,
                StringComparer.Ordinal))
        {
            throw new InvalidDataException("Personal lifecycle evidence receipt is invalid.");
        }

        LocalDataWitness.RequirePreserved();
        var witnessSha256 = PersonalFeedJson.Sha256(
            PersonalFeedJson.Serialize(LocalDataWitness));
        foreach (var gate in RequiredGates)
        {
            gate.RequireExact(Kind, witnessSha256);
        }
        RequireUpdateChain();
    }

    private void RequireUpdateChain()
    {
        if (!string.Equals(
                Kind,
                PersonalLifecycleEvidenceContract.TwoUpdateUpgradeLifecycle,
                StringComparison.Ordinal))
        {
            if (UpdateChain.Count != 0)
            {
                throw new InvalidDataException(
                    "Only the two-update lifecycle may contain an update chain.");
            }
            return;
        }
        if (UpdateChain.Count != 2)
        {
            throw new InvalidDataException(
                "The two-update lifecycle must contain exactly two consecutive updates.");
        }
        foreach (var hop in UpdateChain)
        {
            hop.RequireStrictlyForward();
        }
        if (!UpdateChain[0].To.Equals(UpdateChain[1].From)
            || !UpdateChain[1].To.Matches(
                ReleaseSetId,
                Generation,
                Sequence,
                PilotManifestSha256))
        {
            throw new InvalidDataException(
                "The two-update lifecycle is discontinuous or does not end at the certified target.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalLifecycleUpdateHop(
    PersonalLifecycleReleaseIdentity From,
    PersonalLifecycleReleaseIdentity To)
{
    public void RequireStrictlyForward()
    {
        if (From is null || To is null)
        {
            throw new InvalidDataException("Personal lifecycle update hop is incomplete.");
        }
        From.RequireValid();
        To.RequireValid();
        if (To.Generation < From.Generation
            || To.Sequence <= From.Sequence
            || string.Equals(To.ReleaseSetId, From.ReleaseSetId, StringComparison.Ordinal)
            || string.Equals(To.ManifestSha256, From.ManifestSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal lifecycle update hop does not move strictly forward.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalLifecycleReleaseIdentity(
    string ReleaseSetId,
    long Generation,
    long Sequence,
    string ManifestSha256)
{
    public void RequireValid()
    {
        PersonalReleaseSetValidator.ValidateToken(ReleaseSetId, "evidence update releaseSetId", 128);
        if (Generation is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || Sequence is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || !PersonalReleaseSetValidator.IsSha256(ManifestSha256))
        {
            throw new InvalidDataException("Personal lifecycle update identity is invalid.");
        }
    }

    public bool Matches(
        string releaseSetId,
        long generation,
        long sequence,
        string manifestSha256) =>
        string.Equals(ReleaseSetId, releaseSetId, StringComparison.Ordinal)
        && Generation == generation
        && Sequence == sequence
        && string.Equals(ManifestSha256, manifestSha256, StringComparison.Ordinal);
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalLifecycleLocalDataWitness
{
    public required string HistoryBeforeSha256 { get; init; }
    public required string HistoryAfterSha256 { get; init; }
    public required string WorkspaceBeforeSha256 { get; init; }
    public required string WorkspaceAfterSha256 { get; init; }

    public void RequirePreserved()
    {
        if (!PersonalReleaseSetValidator.IsSha256(HistoryBeforeSha256)
            || !PersonalReleaseSetValidator.IsSha256(HistoryAfterSha256)
            || !PersonalReleaseSetValidator.IsSha256(WorkspaceBeforeSha256)
            || !PersonalReleaseSetValidator.IsSha256(WorkspaceAfterSha256)
            || !string.Equals(
                HistoryBeforeSha256,
                HistoryAfterSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                WorkspaceBeforeSha256,
                WorkspaceAfterSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal lifecycle history or workspace witness was not preserved.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalLifecycleGateEvidence
{
    public required string Gate { get; init; }
    public required string Status { get; init; }
    public required string EvidenceSha256 { get; init; }
    public required string ObservedProcessRole { get; init; }
    public required string ObservedProcessState { get; init; }
    public required string ObservedProcessExecutableSha256 { get; init; }
    public required string NetworkMode { get; init; }
    public required string LocalDataWitnessSha256 { get; init; }

    public void RequireExact(string kind, string witnessSha256)
    {
        var expected = ExpectedSemantics(kind, Gate);
        if (!string.Equals(Status, "PASS", StringComparison.Ordinal)
            || !PersonalReleaseSetValidator.IsSha256(EvidenceSha256)
            || !PersonalReleaseSetValidator.IsSha256(ObservedProcessExecutableSha256)
            || !string.Equals(ObservedProcessRole, expected.Role, StringComparison.Ordinal)
            || !string.Equals(ObservedProcessState, expected.State, StringComparison.Ordinal)
            || !string.Equals(NetworkMode, expected.NetworkMode, StringComparison.Ordinal)
            || !string.Equals(LocalDataWitnessSha256, witnessSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Personal lifecycle gate '{Gate}' does not bind the required execution evidence.");
        }
    }

    public static (string Role, string State, string NetworkMode) ExpectedSemantics(
        string kind,
        string gate)
    {
        _ = PersonalLifecycleEvidenceContract.RequiredGates(kind);
        return gate switch
        {
            "actual-runtime-start" or "webui-open" or "history-preservation"
                or "workspace-preservation" or "pilot-soak" or "weak-network-resume" =>
                ("runtime", "started-and-healthy", "controlled"),
            "client-restart" => ("launcher", "started-and-healthy", "controlled"),
            "previous-runtime-restart" =>
                ("previous-runtime", "started-and-healthy", "controlled"),
            "repair-offline" or "whole-home-restore" =>
                ("maintenance", "completed", "offline"),
            "offline-replay-matrix" => ("test-runner", "completed", "offline"),
            "interruption-matrix" => ("test-runner", "completed", "controlled"),
            "clean-install" or "launcher-self-update" or "old-install-upgrade"
                or "second-consecutive-update" =>
                ("launcher", "completed", "controlled"),
            _ => throw new InvalidDataException(
                $"Personal lifecycle gate '{gate}' is not defined for '{kind}'."),
        };
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalLifecycleEvidenceReference
{
    public required string Kind { get; init; }
    public required string TestRunId { get; init; }
    public required long ReceiptSizeBytes { get; init; }
    public required string ReceiptSha256 { get; init; }
    public required DateTimeOffset CompletedAtUtc { get; init; }

    internal void RequireExact(
        PersonalLifecycleEvidenceSnapshot snapshot,
        string expectedKind,
        DateTimeOffset approvedAtUtc)
    {
        PersonalLifecycleEvidenceContract.RequireCanonicalTestRunId(TestRunId);
        if (!string.Equals(Kind, expectedKind, StringComparison.Ordinal)
            || !string.Equals(snapshot.Receipt.Kind, expectedKind, StringComparison.Ordinal)
            || !string.Equals(TestRunId, snapshot.Receipt.TestRunId, StringComparison.Ordinal)
            || ReceiptSizeBytes != snapshot.RawBytes.LongLength
            || ReceiptSizeBytes is <= 0 or > PersonalLifecycleEvidenceContract.MaximumReceiptBytes
            || !PersonalReleaseSetValidator.IsSha256(ReceiptSha256)
            || !string.Equals(ReceiptSha256, snapshot.RawSha256, StringComparison.Ordinal)
            || CompletedAtUtc.Offset != TimeSpan.Zero
            || CompletedAtUtc != snapshot.Receipt.CompletedAtUtc
            || CompletedAtUtc > approvedAtUtc)
        {
            throw new InvalidDataException(
                $"Personal lifecycle reference for '{expectedKind}' does not bind the exact sidecar bytes.");
        }
    }
}

internal sealed record PersonalLifecycleEvidenceSnapshot(
    byte[] RawBytes,
    string RawSha256,
    PersonalLifecycleEvidenceReceipt Receipt)
{
    public static PersonalLifecycleEvidenceSnapshot Read(string path, string label)
    {
        var bytes = PersonalFeedPathGuard.ReadBoundedRegularFile(
            path,
            PersonalLifecycleEvidenceContract.MaximumReceiptBytes,
            label);
        return new PersonalLifecycleEvidenceSnapshot(
            bytes,
            PersonalFeedJson.Sha256(bytes),
            PersonalLifecycleEvidenceReceipt.Parse(bytes));
    }
}

internal sealed record PersonalLifecycleEvidenceSet(
    PersonalLifecycleEvidenceSnapshot CleanDevice,
    PersonalLifecycleEvidenceSnapshot TwoUpdateUpgrade,
    PersonalLifecycleEvidenceSnapshot FailureRecovery);
