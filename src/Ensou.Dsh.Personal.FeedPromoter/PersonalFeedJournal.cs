using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.Personal.FeedPromoter;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalFeedPromotionJournalEntry(
    int SchemaVersion,
    string Product,
    string Environment,
    string Channel,
    string ReleaseSetId,
    long Generation,
    long Sequence,
    long MinAcceptedSequence,
    string ManifestSha256,
    IReadOnlyList<string> RevokedReleaseSetIds,
    string PreviousEntryFileName,
    string PreviousEntrySha256,
    IReadOnlyList<PersonalFeedArtifactReceipt> Artifacts,
    DateTimeOffset PublishedAtUtc)
{
    public static PersonalFeedPromotionJournalEntry Parse(ReadOnlySpan<byte> json)
    {
        if (json.Length is <= 0 or > 512 * 1024)
        {
            throw new InvalidDataException("Personal promotion journal entry size is invalid.");
        }
        try
        {
            PersonalFeedJson.RequireNoDuplicateMembers(json);
            return JsonSerializer.Deserialize<PersonalFeedPromotionJournalEntry>(
                       json,
                       PersonalFeedJson.Options)
                   ?? throw new InvalidDataException("Personal promotion journal entry is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Personal promotion journal entry JSON is invalid.",
                exception);
        }
    }

    public void RequireIdentity(
        PersonalReleaseSetManifest manifest,
        string manifestSha256,
        IReadOnlyList<PersonalFeedArtifactReceipt> artifacts)
    {
        if (SchemaVersion != 1
            || !string.Equals(Product, PersonalReleaseSetContract.Product, StringComparison.Ordinal)
            || !string.Equals(
                Environment,
                PersonalReleaseSetContract.ProductionEnvironment,
                StringComparison.Ordinal)
            || !string.Equals(Channel, manifest.Channel, StringComparison.Ordinal)
            || !string.Equals(ReleaseSetId, manifest.ReleaseSetId, StringComparison.Ordinal)
            || Generation != manifest.Generation
            || Sequence != manifest.Sequence
            || MinAcceptedSequence != manifest.MinAcceptedSequence
            || !string.Equals(ManifestSha256, manifestSha256, StringComparison.Ordinal)
            || RevokedReleaseSetIds is null
            || !RevokedReleaseSetIds.SequenceEqual(
                manifest.RevokedReleaseSetIds,
                StringComparer.Ordinal)
            || Artifacts is null
            || !Artifacts.SequenceEqual(artifacts)
            || Artifacts.Count != 2
            || Artifacts.Any(artifact => !artifact.IsValid())
            || !PersonalReleaseSetValidator.IsSha256(PreviousEntrySha256)
            || PublishedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException("Personal promotion journal entry identity is invalid.");
        }
        RequirePreviousPointer();
    }

    public void RequireValidStoredEntry(string expectedChannel)
    {
        PersonalFeedChannels.Require(expectedChannel);
        if (SchemaVersion != 1
            || !string.Equals(Product, PersonalReleaseSetContract.Product, StringComparison.Ordinal)
            || !string.Equals(
                Environment,
                PersonalReleaseSetContract.ProductionEnvironment,
                StringComparison.Ordinal)
            || !string.Equals(Channel, expectedChannel, StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(ReleaseSetId)
            || Generation is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || Sequence is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || MinAcceptedSequence < 0
            || MinAcceptedSequence > Sequence
            || !PersonalReleaseSetValidator.IsSha256(ManifestSha256)
            || RevokedReleaseSetIds is null
            || RevokedReleaseSetIds.Count > 1_000
            || RevokedReleaseSetIds.Distinct(StringComparer.Ordinal).Count()
                != RevokedReleaseSetIds.Count
            || !RevokedReleaseSetIds.SequenceEqual(
                RevokedReleaseSetIds.Order(StringComparer.Ordinal),
                StringComparer.Ordinal)
            || Artifacts is null
            || Artifacts.Count != 2
            || Artifacts.Any(artifact => !artifact.IsValid())
            || PublishedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException("Stored personal promotion journal entry is invalid.");
        }
        PersonalReleaseSetValidator.ValidateReleaseId(ReleaseSetId, "journal releaseSetId");
        foreach (var revoked in RevokedReleaseSetIds)
        {
            PersonalReleaseSetValidator.ValidateReleaseId(revoked, "journal revoked releaseSetId");
        }
        RequirePreviousPointer();
    }

    private void RequirePreviousPointer()
    {
        var zero = new string('0', 64);
        if (string.IsNullOrEmpty(PreviousEntryFileName))
        {
            if (!string.Equals(PreviousEntrySha256, zero, StringComparison.Ordinal))
            {
                throw new InvalidDataException("Personal journal genesis pointer is invalid.");
            }
            return;
        }
        PersonalFeedPathGuard.RequireSafeFileName(
            PreviousEntryFileName,
            "previous journal entry filename");
        if (!PersonalReleaseSetValidator.IsSha256(PreviousEntrySha256))
        {
            throw new InvalidDataException("Personal previous journal digest is invalid.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PersonalFeedJournalHead(
    int SchemaVersion,
    string Product,
    string Environment,
    string Channel,
    string ReleaseSetId,
    long Generation,
    long Sequence,
    string ManifestSha256,
    string EntryFileName,
    string EntrySha256)
{
    public static PersonalFeedJournalHead Parse(ReadOnlySpan<byte> json)
    {
        if (json.Length is <= 0 or > 128 * 1024)
        {
            throw new InvalidDataException("Personal promotion journal head size is invalid.");
        }
        try
        {
            PersonalFeedJson.RequireNoDuplicateMembers(json);
            return JsonSerializer.Deserialize<PersonalFeedJournalHead>(
                       json,
                       PersonalFeedJson.Options)
                   ?? throw new InvalidDataException("Personal promotion journal head is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Personal promotion journal head JSON is invalid.",
                exception);
        }
    }
}

internal sealed record PersonalFeedJournalSnapshot(
    PersonalFeedJournalHead Head,
    PersonalFeedPromotionJournalEntry LatestEntry,
    int EntryCount);

internal sealed record PersonalFeedJournalCompletion(
    string EntryPath,
    string EntrySha256,
    PersonalFeedPromotionJournalEntry Entry);

internal static class PersonalFeedJournalStore
{
    private const int MaximumChainEntries = 100_000;

    public static PersonalFeedJournalSnapshot? ReadValidated(
        string channelJournalRoot,
        string channel)
    {
        PersonalFeedChannels.Require(channel);
        var headPath = Path.Combine(channelJournalRoot, "head.json");
        if (!File.Exists(headPath))
        {
            return null;
        }
        var headBytes = PersonalFeedPathGuard.ReadBoundedRegularFile(
            headPath,
            128 * 1024,
            "personal promotion journal head");
        var head = PersonalFeedJournalHead.Parse(headBytes);
        PersonalFeedPathGuard.RequireSafeFileName(head.EntryFileName, "journal entry filename");
        if (head.SchemaVersion != 1
            || !string.Equals(head.Product, PersonalReleaseSetContract.Product, StringComparison.Ordinal)
            || !string.Equals(
                head.Environment,
                PersonalReleaseSetContract.ProductionEnvironment,
                StringComparison.Ordinal)
            || !string.Equals(head.Channel, channel, StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(head.ReleaseSetId)
            || head.Generation is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || head.Sequence is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || !PersonalReleaseSetValidator.IsSha256(head.ManifestSha256)
            || !PersonalReleaseSetValidator.IsSha256(head.EntrySha256))
        {
            throw new InvalidDataException("Personal promotion journal head is invalid.");
        }

        var currentFileName = head.EntryFileName;
        var expectedDigest = head.EntrySha256;
        var visited = new HashSet<string>(StringComparer.Ordinal);
        PersonalFeedPromotionJournalEntry? latest = null;
        long previousSequence = long.MaxValue;
        var count = 0;
        while (!string.IsNullOrEmpty(currentFileName))
        {
            if (++count > MaximumChainEntries || !visited.Add(currentFileName))
            {
                throw new InvalidDataException("Personal promotion journal chain is cyclic or too large.");
            }
            PersonalFeedPathGuard.RequireSafeFileName(currentFileName, "journal entry filename");
            var entryBytes = PersonalFeedPathGuard.ReadBoundedRegularFile(
                Path.Combine(channelJournalRoot, currentFileName),
                512 * 1024,
                "personal promotion journal entry");
            var measuredDigest = PersonalFeedJson.Sha256(entryBytes);
            if (!string.Equals(measuredDigest, expectedDigest, StringComparison.Ordinal))
            {
                throw new InvalidDataException("Personal promotion journal chain digest is invalid.");
            }
            var entry = PersonalFeedPromotionJournalEntry.Parse(entryBytes);
            entry.RequireValidStoredEntry(channel);
            if (entry.Sequence >= previousSequence)
            {
                throw new InvalidDataException(
                    "Personal promotion journal chain does not move strictly backward.");
            }
            if (latest is null)
            {
                latest = entry;
                if (!string.Equals(head.ReleaseSetId, entry.ReleaseSetId, StringComparison.Ordinal)
                    || head.Generation != entry.Generation
                    || head.Sequence != entry.Sequence
                    || !string.Equals(
                        head.ManifestSha256,
                        entry.ManifestSha256,
                        StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "Personal promotion journal head does not bind its latest entry.");
                }
            }
            previousSequence = entry.Sequence;
            currentFileName = entry.PreviousEntryFileName;
            expectedDigest = entry.PreviousEntrySha256;
        }
        if (!string.Equals(expectedDigest, new string('0', 64), StringComparison.Ordinal)
            || latest is null)
        {
            throw new InvalidDataException("Personal promotion journal genesis is invalid.");
        }
        return new PersonalFeedJournalSnapshot(head, latest, count);
    }

    public static PersonalFeedJournalCompletion Complete(
        string channelJournalRoot,
        PersonalReleaseSetManifest manifest,
        string manifestSha256,
        IReadOnlyList<PersonalFeedArtifactReceipt> artifacts,
        DateTimeOffset nowUtc,
        Action<PersonalFeedPromotionStage>? fault)
    {
        var previous = ReadValidated(channelJournalRoot, manifest.Channel);
        var entryName = $"{manifest.Sequence:D20}-{manifest.ReleaseSetId}-{manifestSha256}.json";
        PersonalFeedPathGuard.RequireSafeFileName(entryName, "journal entry filename");
        var entryPath = Path.Combine(channelJournalRoot, entryName);
        byte[] entryBytes;
        PersonalFeedPromotionJournalEntry entry;
        if (File.Exists(entryPath))
        {
            entryBytes = PersonalFeedPathGuard.ReadBoundedRegularFile(
                entryPath,
                512 * 1024,
                "personal promotion journal entry");
            entry = PersonalFeedPromotionJournalEntry.Parse(entryBytes);
            entry.RequireIdentity(manifest, manifestSha256, artifacts);
            if (previous is not null
                && string.Equals(previous.Head.EntryFileName, entryName, StringComparison.Ordinal))
            {
                if (!string.Equals(
                        previous.Head.EntrySha256,
                        PersonalFeedJson.Sha256(entryBytes),
                        StringComparison.Ordinal))
                {
                    throw new InvalidDataException("Personal promotion journal head digest is invalid.");
                }
                return new PersonalFeedJournalCompletion(
                    entryPath,
                    previous.Head.EntrySha256,
                    entry);
            }
            RequireNext(previous, manifest.Sequence);
            RequirePreviousLink(entry, previous);
        }
        else
        {
            RequireNext(previous, manifest.Sequence);
            entry = new PersonalFeedPromotionJournalEntry(
                1,
                PersonalReleaseSetContract.Product,
                PersonalReleaseSetContract.ProductionEnvironment,
                manifest.Channel,
                manifest.ReleaseSetId,
                manifest.Generation,
                manifest.Sequence,
                manifest.MinAcceptedSequence,
                manifestSha256,
                manifest.RevokedReleaseSetIds,
                previous?.Head.EntryFileName ?? string.Empty,
                previous?.Head.EntrySha256 ?? new string('0', 64),
                artifacts,
                nowUtc);
            entryBytes = PersonalFeedJson.Serialize(entry);
            PersonalFeedPathGuard.WriteNewDurable(entryPath, entryBytes, readOnly: true);
            fault?.Invoke(PersonalFeedPromotionStage.JournalEntryCreated);
        }

        var entrySha256 = PersonalFeedJson.Sha256(entryBytes);
        var nextHead = new PersonalFeedJournalHead(
            1,
            PersonalReleaseSetContract.Product,
            PersonalReleaseSetContract.ProductionEnvironment,
            manifest.Channel,
            manifest.ReleaseSetId,
            manifest.Generation,
            manifest.Sequence,
            manifestSha256,
            entryName,
            entrySha256);
        PersonalFeedPathGuard.ReplaceDurableFileAtomically(
            Path.Combine(channelJournalRoot, "head.json"),
            PersonalFeedJson.Serialize(nextHead),
            channelJournalRoot);
        fault?.Invoke(PersonalFeedPromotionStage.JournalHeadReplaced);
        return new PersonalFeedJournalCompletion(entryPath, entrySha256, entry);
    }

    private static void RequireNext(PersonalFeedJournalSnapshot? previous, long sequence)
    {
        if (previous is not null && sequence <= previous.Head.Sequence)
        {
            throw new InvalidDataException(
                "Personal promotion journal sequence must move strictly forward.");
        }
    }

    private static void RequirePreviousLink(
        PersonalFeedPromotionJournalEntry existing,
        PersonalFeedJournalSnapshot? previous)
    {
        if (!string.Equals(
                existing.PreviousEntryFileName,
                previous?.Head.EntryFileName ?? string.Empty,
                StringComparison.Ordinal)
            || !string.Equals(
                existing.PreviousEntrySha256,
                previous?.Head.EntrySha256 ?? new string('0', 64),
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Orphan personal promotion journal entry does not continue the current chain.");
        }
    }
}
