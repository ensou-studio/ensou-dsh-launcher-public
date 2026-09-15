using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.FeedPromoter;

public sealed record EnterpriseFeedPromotionOptions(
    string CandidateDirectory,
    string FeedRoot,
    string TrustConfigurationPath,
    string Channel,
    string? CertifiedDistributionReceiptPath = null,
    string? StablePromotionAuthorizationPath = null,
    string? ResultReceiptPath = null,
    EnterpriseFeedProductionFoundation? ProductionFoundation = null);

public sealed record EnterpriseFeedPromotionResult(
    string Product,
    string Environment,
    string Channel,
    string ReleaseSetId,
    long Generation,
    long Sequence,
    long MinAcceptedSequence,
    string ManifestSha256,
    string ChannelManifestPath,
    string JournalEntryPath,
    string JournalEntrySha256,
    DateTimeOffset PublishedAtUtc,
    bool ChannelHeadChanged,
    bool ImmutableReleaseCreated,
    EnterpriseFeedPromotionOperationReceipt? ProductionReceipt = null);

internal enum EnterpriseFeedPromotionStage
{
    ImmutableReleaseReady,
    ChannelHeadReplaced,
    JournalEntryCreated,
    JournalHeadReplaced,
    OperationReceiptCommitted,
}

public sealed class EnterpriseFeedPromoter
{
    private readonly TimeProvider _timeProvider;
    private readonly Action<EnterpriseFeedPromotionStage>? _testFault;

    public EnterpriseFeedPromoter()
        : this(TimeProvider.System, null)
    {
    }

    internal EnterpriseFeedPromoter(
        TimeProvider timeProvider,
        Action<EnterpriseFeedPromotionStage>? testFault)
    {
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _testFault = testFault;
    }

    public EnterpriseFeedPromotionResult Promote(EnterpriseFeedPromotionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        RequireChannel(options.Channel);
        options.ProductionFoundation?.Validate();
        var candidate = FeedPathGuard.RequireExistingDirectory(
            options.CandidateDirectory,
            "candidate directory");
        var root = FeedPathGuard.RequireExistingDirectory(options.FeedRoot, "feed root");
        var stagingRoot = FeedPathGuard.RequireExactDirectory(root, "staging");
        var journalRoot = FeedPathGuard.RequireExactDirectory(root, "journal");
        var publicRoot = FeedPathGuard.RequireExactDirectory(root, "public");
        var releasesRoot = FeedPathGuard.RequireExactDirectory(publicRoot, "releases");
        var channelsRoot = FeedPathGuard.RequireExactDirectory(publicRoot, "channels");
        var channelRoot = FeedPathGuard.RequireExactDirectory(channelsRoot, options.Channel);
        var channelJournalRoot = FeedPathGuard.RequireExactDirectory(journalRoot, options.Channel);
        if (options.ProductionFoundation is not null)
        {
            _ = FeedPathGuard.RequireExternalResultReceiptPath(
                options.ResultReceiptPath
                    ?? throw new InvalidDataException(
                        "Enterprise production promotion requires a result receipt path."),
                root,
                candidate,
                options.TrustConfigurationPath);
        }
        FeedPathGuard.RequireSafeTree(candidate);
        FeedPathGuard.RequireSafeTree(root);
        FeedPathGuard.RequireRootOwnedManagedTree(root);
        RequireManagedRootInventory(root, publicRoot, channelsRoot, journalRoot);

        var trustBytes = EnterpriseFeedLinuxSecurity.ReadRootOwnedStableFile(
            options.TrustConfigurationPath,
            256 * 1024,
            "trust configuration");
        var trust = EnterpriseFeedTrustConfiguration.Parse(trustBytes, options.Channel);
        var trustSha256 = FeedJson.Sha256(trustBytes);
        var releasePolicy = trust.ToReleasePolicy(options.Channel);
        using var publicationLock = OpenGlobalPublicationLock(journalRoot);
        using var promotionLock = OpenChannelPromotionLock(channelJournalRoot);

        var stage = Path.Combine(
            stagingRoot,
            $"{options.Channel}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(stage);
        FeedPathGuard.RequireSafeTree(stage);
        try
        {
            var stagedManifestPath = Path.Combine(stage, "release-set.v2.json");
            var manifestBytes = FeedPathGuard.ReadBoundedRegularFile(
                Path.Combine(candidate, "release-set.v2.json"),
                512 * 1024,
                "candidate manifest");
            FeedPathGuard.WriteNewDurable(stagedManifestPath, manifestBytes);
            var manifestSha256 = FeedJson.Sha256(manifestBytes);
            var manifest = EnterpriseReleaseSetManifest.Parse(manifestBytes);
            EnterpriseReleaseSetValidator.Verify(
                manifest,
                releasePolicy,
                _timeProvider.GetUtcNow());
            if (!string.Equals(manifest.Channel, options.Channel, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Signed release-set channel does not match the promotion channel.");
            }

            var payloadStage = Path.Combine(stage, "release");
            Directory.CreateDirectory(payloadStage);
            var artifacts = StageAndVerifyArtifacts(
                candidate,
                payloadStage,
                manifest,
                releasePolicy);
            RequireExactCandidateTree(candidate, artifacts);

            var channelHeadPath = Path.Combine(channelRoot, "release-set.v2.json");
            var journalHeadPath = Path.Combine(channelJournalRoot, "head.json");
            var observedChannelHead = EnterpriseFeedOperationStore.Observe(
                channelHeadPath,
                512 * 1024,
                "enterprise channel head CAS input");
            var observedJournalHead = EnterpriseFeedOperationStore.Observe(
                journalHeadPath,
                128 * 1024,
                "enterprise journal head CAS input");
            EnterpriseFeedOperationRequest? operationRequest = null;
            if (options.ProductionFoundation is not null)
            {
                var feedIdentitySha256 = EnterpriseFeedIdentityStore.ReadRequiredSha256(
                    root,
                    trust.Product,
                    trust.Environment);
                if (!string.Equals(
                        feedIdentitySha256,
                        options.ProductionFoundation.ExpectedFeedIdentitySha256,
                        StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "Enterprise expected feed identity does not match the locked production feed.");
                }
                operationRequest = EnterpriseFeedOperationStore.CreateRequest(
                    options.ProductionFoundation,
                    trust.Product,
                    trust.Environment,
                    options.Channel,
                    manifestBytes.LongLength,
                    manifestSha256,
                    trustSha256);
            }
            var current = ReadCurrentHead(
                channelHeadPath,
                releasesRoot,
                releasePolicy);
            var journalBefore = ReadCurrentJournal(
                journalHeadPath,
                channelJournalRoot);
            RequireRecoverableHeadAndJournal(
                current,
                journalBefore,
                manifest,
                manifestSha256);
            var sameManifest = current is not null
                && string.Equals(current.ManifestSha256, manifestSha256, StringComparison.Ordinal);
            if (current is not null && !sameManifest)
            {
                RequireForwardOnly(current.Manifest, manifest);
            }

            if (string.Equals(options.Channel, "stable", StringComparison.Ordinal))
            {
                VerifyStableAuthorization(
                    options,
                    trust,
                    releasePolicy,
                    manifest,
                    manifestSha256);
            }
            else if (options.CertifiedDistributionReceiptPath is not null
                || options.StablePromotionAuthorizationPath is not null)
            {
                throw new InvalidDataException(
                    "Stable certification inputs are accepted only by the stable channel.");
            }

            EnterpriseFeedOperationSession? operation = operationRequest is null
                ? null
                : EnterpriseFeedOperationStore.Begin(
                    journalRoot,
                    operationRequest,
                    observedChannelHead,
                    observedJournalHead,
                    allowCreate: !sameManifest);
            if (operation?.CommittedReceipt is not null)
            {
                EnterpriseFeedOperationStore.RequireCas(
                    operation.CommittedReceipt.ChannelHead,
                    observedChannelHead,
                    "committed channel head");
                EnterpriseFeedOperationStore.RequireCas(
                    operation.CommittedReceipt.JournalHead,
                    observedJournalHead,
                    "committed journal head");
                if (!sameManifest || current is null)
                {
                    throw new InvalidDataException(
                        "Enterprise committed operation response no longer matches the channel head.");
                }
                RequireCommittedHead(current, journalBefore);
                return ResultFromReceipt(operation.CommittedReceipt);
            }

            var releaseDirectory = Path.Combine(releasesRoot, manifest.ReleaseSetId);
            var releaseCreated = PublishOrVerifyImmutableRelease(
                payloadStage,
                releaseDirectory,
                artifacts);
            _testFault?.Invoke(EnterpriseFeedPromotionStage.ImmutableReleaseReady);

            var headChanged = false;
            if (!sameManifest)
            {
                FeedPathGuard.ReplaceDurableFileAtomically(
                    channelHeadPath,
                    manifestBytes,
                    channelRoot);
                headChanged = true;
                _testFault?.Invoke(EnterpriseFeedPromotionStage.ChannelHeadReplaced);
            }

            var journal = CompleteJournal(
                channelJournalRoot,
                manifest,
                manifestSha256,
                artifacts,
                _testFault);
            if (operation is not null)
            {
                var finalChannelHead = EnterpriseFeedOperationStore.Observe(
                    channelHeadPath,
                    512 * 1024,
                    "enterprise committed channel head");
                var finalJournalHead = EnterpriseFeedOperationStore.Observe(
                    journalHeadPath,
                    128 * 1024,
                    "enterprise committed journal head");
                var channelUri = new Uri(
                    trust.ManifestOrigin,
                    $"v2/channels/{Uri.EscapeDataString(options.Channel)}/release-set.v2.json");
                if (!string.Equals(
                        channelUri.Scheme,
                        Uri.UriSchemeHttps,
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException(
                        "Enterprise production result channel manifest URI must use HTTPS.");
                }
                var receipt = EnterpriseFeedOperationStore.Commit(
                    operation,
                    new EnterpriseFeedPromotionOperationReceipt(
                        1,
                        operation.Request.OperationId,
                        operation.Request.RequestSha256,
                        manifest.Product,
                        manifest.Environment,
                        options.Channel,
                        manifest.ReleaseSetId,
                        manifest.Generation,
                        manifest.Sequence,
                        manifest.MinAcceptedSequence,
                        manifestSha256,
                        $"public/channels/{options.Channel}/release-set.v2.json",
                        channelUri.AbsoluteUri,
                        $"journal/{options.Channel}/{Path.GetFileName(journal.EntryPath)}",
                        journal.EntrySha256,
                        finalChannelHead,
                        finalJournalHead,
                        journal.Entry.PublishedAtUtc,
                        ChannelHeadChanged: true,
                        ImmutableReleaseCreated: true));
                _testFault?.Invoke(EnterpriseFeedPromotionStage.OperationReceiptCommitted);
                return ResultFromReceipt(receipt);
            }
            return new EnterpriseFeedPromotionResult(
                manifest.Product,
                manifest.Environment,
                options.Channel,
                manifest.ReleaseSetId,
                manifest.Generation,
                manifest.Sequence,
                manifest.MinAcceptedSequence,
                manifestSha256,
                channelHeadPath,
                journal.EntryPath,
                journal.EntrySha256,
                journal.Entry.PublishedAtUtc,
                headChanged,
                releaseCreated);
        }
        finally
        {
            FeedPathGuard.DeletePrivateStage(stage, stagingRoot);
        }
    }

    private static EnterpriseFeedPromotionResult ResultFromReceipt(
        EnterpriseFeedPromotionOperationReceipt receipt) => new(
            receipt.Product,
            receipt.Environment,
            receipt.Channel,
            receipt.ReleaseSetId,
            receipt.Generation,
            receipt.Sequence,
            receipt.MinAcceptedSequence,
            receipt.ManifestSha256,
            receipt.ChannelManifestRelativePath,
            receipt.PromotionJournalEntryRelativePath,
            receipt.PromotionJournalSha256,
            receipt.PublishedAtUtc,
            receipt.ChannelHeadChanged,
            receipt.ImmutableReleaseCreated,
            receipt);

    private static FileStream OpenGlobalPublicationLock(string journalRoot)
    {
        var path = Path.Combine(journalRoot, "publication.lock");
        if (!File.Exists(path))
        {
            try
            {
                FeedPathGuard.WriteNewDurable(path, []);
            }
            catch (IOException) when (File.Exists(path))
            {
                // Another process created the one global lock first.
            }
        }
        var safe = FeedPathGuard.RequireRegularFile(
            path,
            "enterprise feed global publication lock");
        return new FileStream(
            safe,
            FileMode.Open,
            FileAccess.ReadWrite,
            FileShare.None,
            1,
            FileOptions.WriteThrough);
    }

    private static FileStream OpenChannelPromotionLock(string channelJournalRoot)
    {
        var path = Path.Combine(channelJournalRoot, "promotion.lock");
        if (!File.Exists(path))
        {
            FeedPathGuard.WriteNewDurable(path, []);
        }
        var safe = FeedPathGuard.RequireRegularFile(
            path,
            "enterprise feed channel promotion lock");
        return new FileStream(
            safe,
            FileMode.Open,
            FileAccess.ReadWrite,
            FileShare.None,
            1,
            FileOptions.WriteThrough);
    }

    private static void RequireManagedRootInventory(
        string root,
        string publicRoot,
        string channelsRoot,
        string journalRoot)
    {
        FeedPathGuard.RequireExactInventory(
            root,
            ["journal", "public", "staging"],
            [],
            [],
            [EnterpriseFeedIdentityStore.FileName],
            "enterprise feed root");
        FeedPathGuard.RequireExactInventory(
            publicRoot,
            ["channels", "releases"],
            [],
            [],
            [],
            "enterprise public root");
        FeedPathGuard.RequireExactInventory(
            channelsRoot,
            ["lab", "pilot", "stable"],
            [],
            [],
            [],
            "enterprise channel root");
        FeedPathGuard.RequireExactInventory(
            journalRoot,
            ["lab", "pilot", "stable"],
            [],
            ["operations"],
            ["publication.lock"],
            "enterprise journal root");
    }

    private static void RequireRecoverableHeadAndJournal(
        EnterpriseCurrentFeedHead? current,
        EnterpriseCurrentJournal? journal,
        EnterpriseReleaseSetManifest candidate,
        string candidateManifestSha256)
    {
        if (current is null)
        {
            if (journal is not null)
            {
                throw new InvalidDataException(
                    "Enterprise channel head is missing behind its promotion journal.");
            }
            return;
        }
        if (journal is null)
        {
            if (!string.Equals(
                    current.ManifestSha256,
                    candidateManifestSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Enterprise promotion journal is missing for the current channel head.");
            }
            return;
        }
        var committed = journal.Head.Sequence == current.Manifest.Sequence
            && journal.Entry.Generation == current.Manifest.Generation
            && string.Equals(
                journal.Head.ReleaseSetId,
                current.Manifest.ReleaseSetId,
                StringComparison.Ordinal)
            && string.Equals(
                current.ManifestSha256,
                journal.Entry.ManifestSha256,
                StringComparison.Ordinal);
        if (committed)
        {
            return;
        }
        var interrupted = string.Equals(
                current.ManifestSha256,
                candidateManifestSha256,
                StringComparison.Ordinal)
            && current.Manifest.Sequence == candidate.Sequence
            && current.Manifest.Generation == candidate.Generation
            && current.Manifest.Sequence > journal.Head.Sequence;
        if (!interrupted)
        {
            throw new InvalidDataException(
                "Enterprise channel head and promotion journal are inconsistent.");
        }
    }

    private static void RequireCommittedHead(
        EnterpriseCurrentFeedHead current,
        EnterpriseCurrentJournal? journal)
    {
        if (journal is null
            || journal.Head.Sequence != current.Manifest.Sequence
            || journal.Entry.Generation != current.Manifest.Generation
            || !string.Equals(
                journal.Head.ReleaseSetId,
                current.Manifest.ReleaseSetId,
                StringComparison.Ordinal)
            || !string.Equals(
                journal.Entry.ManifestSha256,
                current.ManifestSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise operation receipt requires a committed channel/journal pair.");
        }
    }

    private static EnterpriseCurrentJournal? ReadCurrentJournal(
        string journalHeadPath,
        string channelJournalRoot)
    {
        var head = EnterpriseFeedJournalHead.ReadOptional(
            journalHeadPath,
            channelJournalRoot);
        if (head is null)
        {
            return null;
        }
        var entryBytes = FeedPathGuard.ReadBoundedRegularFile(
            Path.Combine(channelJournalRoot, head.EntryFileName),
            512 * 1024,
            "enterprise current journal entry");
        var entry = EnterpriseFeedPromotionJournalEntry.Parse(entryBytes);
        if (!string.Equals(
                FeedJson.Sha256(entryBytes),
                head.EntrySha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise current journal entry digest differs from its head.");
        }
        return new EnterpriseCurrentJournal(head, entry);
    }

    private static IReadOnlyList<EnterpriseFeedArtifactReceipt> StageAndVerifyArtifacts(
        string candidate,
        string payloadStage,
        EnterpriseReleaseSetManifest manifest,
        EnterpriseReleaseTrustPolicy policy)
    {
        var receipts = new List<EnterpriseFeedArtifactReceipt>(manifest.Artifacts.Count);
        var fileNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var artifact in manifest.Artifacts)
        {
            var fileName = RequireExactArtifactUri(manifest, artifact, policy);
            if (!fileNames.Add(fileName))
            {
                throw new InvalidDataException(
                    "Enterprise release artifacts must use distinct filenames.");
            }
            var sourcePath = Path.Combine(candidate, fileName);
            var destinationPath = Path.Combine(payloadStage, fileName);
            var copied = FeedPathGuard.CopyNewAndHash(sourcePath, destinationPath);
            if (copied.SizeBytes != artifact.SizeBytes
                || !string.Equals(copied.Sha256, artifact.Sha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Candidate artifact does not match signed bytes: {artifact.Component}.");
            }
            receipts.Add(new EnterpriseFeedArtifactReceipt(
                artifact.Component,
                artifact.ReleaseId,
                fileName,
                copied.SizeBytes,
                copied.Sha256));
        }
        return receipts;
    }

    private static void RequireExactCandidateTree(
        string candidate,
        IReadOnlyList<EnterpriseFeedArtifactReceipt> artifacts)
    {
        var expected = artifacts.Select(artifact => artifact.FileName)
            .Append("release-set.v2.json")
            .Order(StringComparer.Ordinal)
            .ToArray();
        var actual = Directory.EnumerateFiles(candidate)
            .Select(Path.GetFileName)
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (!actual.SequenceEqual(expected, StringComparer.Ordinal)
            || Directory.EnumerateDirectories(candidate).Any())
        {
            throw new InvalidDataException(
                "Enterprise candidate must contain only its canonical manifest and signed artifacts.");
        }
    }

    internal static string RequireExactArtifactUri(
        EnterpriseReleaseSetManifest manifest,
        EnterpriseReleaseArtifact artifact,
        EnterpriseReleaseTrustPolicy policy)
    {
        policy.RequireArtifactUri(artifact.Uri);
        var escapedSegments = artifact.Uri.AbsolutePath.Split(
            '/',
            StringSplitOptions.RemoveEmptyEntries);
        if (escapedSegments.Length != 4
            || !string.Equals(escapedSegments[0], "v2", StringComparison.Ordinal)
            || !string.Equals(escapedSegments[1], "releases", StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise artifact URI does not use the immutable v2 release layout.");
        }
        var uriReleaseId = Uri.UnescapeDataString(escapedSegments[2]);
        var fileName = Uri.UnescapeDataString(escapedSegments[3]);
        FeedPathGuard.RequireSafeFileName(fileName, "artifact filename");
        if (!string.Equals(uriReleaseId, manifest.ReleaseSetId, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise artifact URI release directory does not match releaseSetId.");
        }
        var expected = new Uri(
            policy.ArtifactOrigin,
            $"v2/releases/{Uri.EscapeDataString(manifest.ReleaseSetId)}/{Uri.EscapeDataString(fileName)}");
        if (!string.Equals(
                artifact.Uri.AbsoluteUri,
                expected.AbsoluteUri,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("Enterprise artifact URI is not canonical.");
        }
        return fileName;
    }

    private static EnterpriseCurrentFeedHead? ReadCurrentHead(
        string headPath,
        string releasesRoot,
        EnterpriseReleaseTrustPolicy policy)
    {
        if (!File.Exists(headPath))
        {
            return null;
        }
        var bytes = FeedPathGuard.ReadBoundedRegularFile(
            headPath,
            512 * 1024,
            "current channel head");
        var manifest = EnterpriseReleaseSetManifest.Parse(bytes);
        // An old head may legitimately be expired when a replacement is promoted.
        // Its own issuance instant still exercises the complete signed contract.
        EnterpriseReleaseSetValidator.Verify(manifest, policy, manifest.IssuedAtUtc);
        var receipts = manifest.Artifacts.Select(artifact =>
        {
            var fileName = RequireExactArtifactUri(manifest, artifact, policy);
            var measured = FeedPathGuard.HashRegularFile(
                Path.Combine(releasesRoot, manifest.ReleaseSetId, fileName));
            if (measured.SizeBytes != artifact.SizeBytes
                || !string.Equals(measured.Sha256, artifact.Sha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Current feed head references missing or changed immutable bytes.");
            }
            return new EnterpriseFeedArtifactReceipt(
                artifact.Component,
                artifact.ReleaseId,
                fileName,
                measured.SizeBytes,
                measured.Sha256);
        }).ToArray();
        return new EnterpriseCurrentFeedHead(
            manifest,
            FeedJson.Sha256(bytes),
            receipts);
    }

    private static void RequireForwardOnly(
        EnterpriseReleaseSetManifest current,
        EnterpriseReleaseSetManifest candidate)
    {
        if (candidate.Sequence <= current.Sequence
            || candidate.Generation < current.Generation
            || candidate.MinAcceptedSequence < current.MinAcceptedSequence
            || !current.RevokedReleaseSetIds.All(value =>
                candidate.RevokedReleaseSetIds.Contains(value, StringComparer.Ordinal)))
        {
            throw new InvalidDataException(
                "Feed promoter rejected sequence, generation, minimum floor, or revocation rollback.");
        }
    }

    private void VerifyStableAuthorization(
        EnterpriseFeedPromotionOptions options,
        EnterpriseFeedTrustConfiguration trust,
        EnterpriseReleaseTrustPolicy releasePolicy,
        EnterpriseReleaseSetManifest manifest,
        string manifestSha256)
    {
        if (string.IsNullOrWhiteSpace(options.CertifiedDistributionReceiptPath)
            || string.IsNullOrWhiteSpace(options.StablePromotionAuthorizationPath))
        {
            throw new InvalidDataException(
                "Stable promotion requires a certified receipt and its signed authorization.");
        }
        var receiptBytes = FeedPathGuard.ReadBoundedRegularFile(
            options.CertifiedDistributionReceiptPath,
            512 * 1024,
            "certified distribution receipt");
        var receipt = EnterpriseCertifiedDistributionReceipt.Parse(receiptBytes);
        receipt.Verify(manifest, manifestSha256, releasePolicy);
        var authorizationBytes = FeedPathGuard.ReadBoundedRegularFile(
            options.StablePromotionAuthorizationPath,
            128 * 1024,
            "stable promotion authorization");
        var authorization = EnterpriseStablePromotionAuthorization.Parse(authorizationBytes);
        authorization.Verify(
            trust,
            manifest,
            manifestSha256,
            receipt,
            FeedJson.Sha256(receiptBytes),
            _timeProvider.GetUtcNow());
    }

    private static bool PublishOrVerifyImmutableRelease(
        string stagedRelease,
        string destination,
        IReadOnlyList<EnterpriseFeedArtifactReceipt> artifacts)
    {
        if (Directory.Exists(destination))
        {
            FeedPathGuard.RequireSafeTree(destination);
            var names = Directory.EnumerateFiles(destination)
                .Select(Path.GetFileName)
                .Order(StringComparer.Ordinal)
                .ToArray();
            var expectedNames = artifacts.Select(value => value.FileName)
                .Order(StringComparer.Ordinal)
                .ToArray();
            if (!names.SequenceEqual(expectedNames, StringComparer.Ordinal)
                || Directory.EnumerateDirectories(destination).Any())
            {
                throw new InvalidDataException(
                    "Existing immutable release directory has an unexpected tree.");
            }
            foreach (var artifact in artifacts)
            {
                var measured = FeedPathGuard.HashRegularFile(
                    Path.Combine(destination, artifact.FileName));
                if (measured.SizeBytes != artifact.SizeBytes
                    || !string.Equals(measured.Sha256, artifact.Sha256, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "Existing immutable release bytes conflict with the candidate.");
                }
            }
            return false;
        }

        FeedPathGuard.MoveDirectoryDurably(stagedRelease, destination);
        FeedPathGuard.MakeReleaseReadOnly(destination);
        return true;
    }

    private EnterpriseJournalCompletion CompleteJournal(
        string channelJournalRoot,
        EnterpriseReleaseSetManifest manifest,
        string manifestSha256,
        IReadOnlyList<EnterpriseFeedArtifactReceipt> artifacts,
        Action<EnterpriseFeedPromotionStage>? fault)
    {
        var journalHeadPath = Path.Combine(channelJournalRoot, "head.json");
        var previous = EnterpriseFeedJournalHead.ReadOptional(journalHeadPath, channelJournalRoot);
        var entryName = $"{manifest.Sequence:D20}-{manifest.ReleaseSetId}-{manifestSha256}.json";
        var entryPath = Path.Combine(channelJournalRoot, entryName);
        byte[] entryBytes;
        EnterpriseFeedPromotionJournalEntry entry;
        if (File.Exists(entryPath))
        {
            entryBytes = FeedPathGuard.ReadBoundedRegularFile(
                entryPath,
                512 * 1024,
                "promotion journal entry");
            entry = EnterpriseFeedPromotionJournalEntry.Parse(entryBytes);
            entry.RequireIdentity(manifest, manifestSha256, artifacts);
            if (previous is not null
                && string.Equals(previous.EntryFileName, entryName, StringComparison.Ordinal))
            {
                if (!string.Equals(
                        previous.EntrySha256,
                        FeedJson.Sha256(entryBytes),
                        StringComparison.Ordinal))
                {
                    throw new InvalidDataException("Promotion journal head digest is invalid.");
                }
                return new EnterpriseJournalCompletion(
                    entryPath,
                    previous.EntrySha256,
                    entry);
            }
            if (previous is not null && manifest.Sequence <= previous.Sequence)
            {
                throw new InvalidDataException(
                    "Promotion journal rejected an idempotent recovery behind its committed head.");
            }
            if (!string.Equals(
                    entry.PreviousEntrySha256,
                    previous?.EntrySha256 ?? new string('0', 64),
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Orphan promotion journal entry does not continue the current chain.");
            }
        }
        else
        {
            if (previous is not null && manifest.Sequence <= previous.Sequence)
            {
                throw new InvalidDataException(
                    "Promotion journal sequence must move strictly forward.");
            }
            entry = new EnterpriseFeedPromotionJournalEntry(
                1,
                manifest.Channel,
                manifest.ReleaseSetId,
                manifest.Generation,
                manifest.Sequence,
                manifest.MinAcceptedSequence,
                manifestSha256,
                previous?.EntrySha256 ?? new string('0', 64),
                artifacts,
                WholeSecondUtc(_timeProvider.GetUtcNow()));
            entryBytes = FeedJson.Serialize(entry);
            FeedPathGuard.WriteNewDurable(entryPath, entryBytes);
            fault?.Invoke(EnterpriseFeedPromotionStage.JournalEntryCreated);
        }
        var entrySha256 = FeedJson.Sha256(entryBytes);
        var nextHead = new EnterpriseFeedJournalHead(
            1,
            manifest.Channel,
            manifest.ReleaseSetId,
            manifest.Sequence,
            entryName,
            entrySha256);
        FeedPathGuard.ReplaceDurableFileAtomically(
            journalHeadPath,
            FeedJson.Serialize(nextHead),
            channelJournalRoot);
        fault?.Invoke(EnterpriseFeedPromotionStage.JournalHeadReplaced);
        return new EnterpriseJournalCompletion(entryPath, entrySha256, entry);
    }

    private static void RequireChannel(string channel)
    {
        if (channel is not "lab" and not "pilot" and not "stable")
        {
            throw new ArgumentException("Channel must be lab, pilot, or stable.", nameof(channel));
        }
    }

    private static DateTimeOffset WholeSecondUtc(DateTimeOffset value) =>
        DateTimeOffset.FromUnixTimeSeconds(value.ToUnixTimeSeconds());
}

internal sealed record EnterpriseCurrentFeedHead(
    EnterpriseReleaseSetManifest Manifest,
    string ManifestSha256,
    IReadOnlyList<EnterpriseFeedArtifactReceipt> Artifacts);

internal sealed record EnterpriseCurrentJournal(
    EnterpriseFeedJournalHead Head,
    EnterpriseFeedPromotionJournalEntry Entry);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseFeedArtifactReceipt(
    string Component,
    string ReleaseId,
    string FileName,
    long SizeBytes,
    string Sha256);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseFeedPromotionJournalEntry(
    int SchemaVersion,
    string Channel,
    string ReleaseSetId,
    long Generation,
    long Sequence,
    long MinAcceptedSequence,
    string ManifestSha256,
    string PreviousEntrySha256,
    IReadOnlyList<EnterpriseFeedArtifactReceipt> Artifacts,
    [property: JsonConverter(typeof(EnterpriseWholeSecondUtcJsonConverter))]
    DateTimeOffset PublishedAtUtc)
{
    public static EnterpriseFeedPromotionJournalEntry Parse(ReadOnlySpan<byte> json)
    {
        try
        {
            EnterpriseReleaseJson.RequireNoDuplicateMembers(json);
            return System.Text.Json.JsonSerializer.Deserialize<EnterpriseFeedPromotionJournalEntry>(
                       json,
                       FeedJson.Options)
                   ?? throw new InvalidDataException("Promotion journal entry is empty.");
        }
        catch (System.Text.Json.JsonException exception)
        {
            throw new InvalidDataException("Promotion journal entry JSON is invalid.", exception);
        }
    }

    public void RequireIdentity(
        EnterpriseReleaseSetManifest manifest,
        string manifestSha256,
        IReadOnlyList<EnterpriseFeedArtifactReceipt> artifacts)
    {
        if (SchemaVersion != 1
            || !string.Equals(Channel, manifest.Channel, StringComparison.Ordinal)
            || !string.Equals(ReleaseSetId, manifest.ReleaseSetId, StringComparison.Ordinal)
            || Generation != manifest.Generation
            || Sequence != manifest.Sequence
            || MinAcceptedSequence != manifest.MinAcceptedSequence
            || !string.Equals(ManifestSha256, manifestSha256, StringComparison.Ordinal)
            || !Artifacts.SequenceEqual(artifacts)
            || !EnterpriseReleaseValueValidator.IsSha256(PreviousEntrySha256)
            || PublishedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException("Promotion journal entry identity is invalid.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record EnterpriseFeedJournalHead(
    int SchemaVersion,
    string Channel,
    string ReleaseSetId,
    long Sequence,
    string EntryFileName,
    string EntrySha256)
{
    public static EnterpriseFeedJournalHead? ReadOptional(string path, string journalRoot)
    {
        if (!File.Exists(path))
        {
            return null;
        }
        try
        {
            var bytes = FeedPathGuard.ReadBoundedRegularFile(path, 128 * 1024, "journal head");
            EnterpriseReleaseJson.RequireNoDuplicateMembers(bytes);
            var value = System.Text.Json.JsonSerializer.Deserialize<EnterpriseFeedJournalHead>(
                bytes,
                FeedJson.Options)
                ?? throw new InvalidDataException("Promotion journal head is empty.");
            FeedPathGuard.RequireSafeFileName(value.EntryFileName, "journal entry filename");
            var entryPath = Path.Combine(journalRoot, value.EntryFileName);
            var entryBytes = FeedPathGuard.ReadBoundedRegularFile(
                entryPath,
                512 * 1024,
                "journal head entry");
            var entry = EnterpriseFeedPromotionJournalEntry.Parse(entryBytes);
            if (value.SchemaVersion != 1
                || value.Channel is not "lab" and not "pilot" and not "stable"
                || !string.Equals(value.Channel, entry.Channel, StringComparison.Ordinal)
                || !string.Equals(value.ReleaseSetId, entry.ReleaseSetId, StringComparison.Ordinal)
                || value.Sequence != entry.Sequence
                || value.Sequence <= 0
                || !EnterpriseReleaseValueValidator.IsSha256(value.EntrySha256)
                || !string.Equals(
                    value.EntrySha256,
                    FeedJson.Sha256(entryBytes),
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException("Promotion journal head is invalid.");
            }
            return value;
        }
        catch (System.Text.Json.JsonException exception)
        {
            throw new InvalidDataException("Promotion journal head JSON is invalid.", exception);
        }
    }
}

internal sealed record EnterpriseJournalCompletion(
    string EntryPath,
    string EntrySha256,
    EnterpriseFeedPromotionJournalEntry Entry);

internal static class FeedPathGuard
{
    public static string RequireExistingDirectory(string path, string label)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException($"{label} must be absolute.");
        }
        var full = Path.GetFullPath(path);
        if (!Directory.Exists(full))
        {
            throw new DirectoryNotFoundException($"{label} is missing: {full}");
        }
        RequireNoLinkAncestors(full);
        return full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    public static string RequireExactDirectory(string parent, string name)
    {
        RequireSafeFileName(name, "managed directory name");
        var full = Path.GetFullPath(Path.Combine(parent, name));
        var expectedParent = Path.GetFullPath(parent).TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar);
        if (!string.Equals(
                Path.GetDirectoryName(full)?.TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar),
                expectedParent,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("Feed managed directory escaped its parent.");
        }
        return RequireExistingDirectory(full, $"feed {name} directory");
    }

    public static void RequireSafeTree(string root)
    {
        var full = RequireExistingDirectory(root, "tree");
        foreach (var path in Directory.EnumerateFileSystemEntries(
                     full,
                     "*",
                     SearchOption.AllDirectories))
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("Feed paths may not contain filesystem links.");
            }
            if (File.Exists(path))
            {
                _ = RequireRegularFile(path, "enterprise feed managed file");
            }
        }
    }

    public static byte[] ReadBoundedRegularFile(string path, int maximumBytes, string label)
    {
        var full = RequireRegularFile(path, label);
        var info = new FileInfo(full);
        if (info.Length is <= 0 || info.Length > maximumBytes)
        {
            throw new InvalidDataException($"{label} size is invalid.");
        }
        using var stream = new FileStream(
            full,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.SequentialScan);
        var bytes = new byte[info.Length];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1 || new FileInfo(full).Length != info.Length)
        {
            throw new IOException($"{label} changed while it was read.");
        }
        return bytes;
    }

    public static (long SizeBytes, string Sha256) CopyNewAndHash(
        string source,
        string destination)
    {
        var fullSource = RequireRegularFile(source, "candidate artifact");
        using var input = new FileStream(
            fullSource,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.SequentialScan);
        var initialLength = input.Length;
        using var output = new FileStream(
            destination,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            128 * 1024,
            FileOptions.SequentialScan | FileOptions.WriteThrough);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[128 * 1024];
        long total = 0;
        int read;
        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            output.Write(buffer, 0, read);
            hash.AppendData(buffer, 0, read);
            total += read;
        }
        output.Flush(flushToDisk: true);
        LinuxDurability.SyncDirectory(
            Path.GetDirectoryName(Path.GetFullPath(destination))
            ?? throw new InvalidDataException("Artifact destination has no parent."));
        if (total != initialLength || input.Length != initialLength)
        {
            throw new IOException("Candidate artifact changed while it was copied.");
        }
        return (total, Convert.ToHexStringLower(hash.GetHashAndReset()));
    }

    public static (long SizeBytes, string Sha256) HashRegularFile(string path)
    {
        var full = RequireRegularFile(path, "immutable artifact");
        using var stream = new FileStream(
            full,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.SequentialScan);
        var length = stream.Length;
        var hash = Convert.ToHexStringLower(SHA256.HashData(stream));
        if (stream.Length != length)
        {
            throw new IOException("Immutable artifact changed while it was hashed.");
        }
        return (length, hash);
    }

    public static void WriteNewDurable(string path, ReadOnlySpan<byte> bytes)
    {
        using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            128 * 1024,
            FileOptions.WriteThrough);
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);
        LinuxDurability.SyncDirectory(
            Path.GetDirectoryName(Path.GetFullPath(path))
            ?? throw new InvalidDataException("Durable file has no parent."));
    }

    public static void ReplaceDurableFileAtomically(
        string destination,
        ReadOnlySpan<byte> bytes,
        string exactParent)
    {
        var parent = Path.GetDirectoryName(Path.GetFullPath(destination))
            ?? throw new InvalidDataException("Atomic destination has no parent.");
        if (!string.Equals(
                parent.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                Path.GetFullPath(exactParent).TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar),
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("Atomic destination escaped its exact parent.");
        }
        var temporary = Path.Combine(parent, $".{Path.GetFileName(destination)}.{Guid.NewGuid():N}.tmp");
        try
        {
            WriteNewDurable(temporary, bytes);
            File.Move(temporary, destination, overwrite: true);
            LinuxDurability.SyncDirectory(parent);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    public static void MoveDirectoryDurably(string source, string destination)
    {
        var sourceParent = Path.GetDirectoryName(Path.GetFullPath(source))
            ?? throw new InvalidDataException("Source directory has no parent.");
        var destinationParent = Path.GetDirectoryName(Path.GetFullPath(destination))
            ?? throw new InvalidDataException("Destination directory has no parent.");
        LinuxDurability.SyncDirectory(source);
        Directory.Move(source, destination);
        LinuxDurability.SyncDirectory(destination);
        LinuxDurability.SyncDirectory(destinationParent);
        if (!string.Equals(sourceParent, destinationParent, StringComparison.Ordinal))
        {
            LinuxDurability.SyncDirectory(sourceParent);
        }
    }

    public static void MakeReleaseReadOnly(string directory)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        foreach (var file in Directory.EnumerateFiles(directory))
        {
            File.SetUnixFileMode(
                file,
                UnixFileMode.UserRead | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        }
        File.SetUnixFileMode(
            directory,
            UnixFileMode.UserRead | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        LinuxDurability.SyncDirectory(directory);
    }

    public static void DeletePrivateStage(string stage, string stagingRoot)
    {
        var fullStage = Path.GetFullPath(stage);
        var fullRoot = Path.GetFullPath(stagingRoot).TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar);
        if (!string.Equals(Path.GetDirectoryName(fullStage), fullRoot, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Refusing to clean a stage outside the staging root.");
        }
        if (Directory.Exists(fullStage))
        {
            RequireSafeTree(fullStage);
            Directory.Delete(fullStage, recursive: true);
            LinuxDurability.SyncDirectory(fullRoot);
        }
    }

    public static void RequireSafeFileName(string? fileName, string label)
    {
        if (string.IsNullOrWhiteSpace(fileName)
            || fileName is "." or ".."
            || fileName != Path.GetFileName(fileName)
            || fileName.Length > 255
            || fileName.Any(char.IsControl)
            || fileName.IndexOfAny(['\\', '/', ':', '*', '?', '"', '<', '>', '|']) >= 0
            || fileName.EndsWith(' ')
            || fileName.EndsWith('.'))
        {
            throw new InvalidDataException($"{label} is unsafe.");
        }
    }

    public static string RequireRegularFile(string path, string label)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException($"{label} must be absolute.");
        }
        var full = Path.GetFullPath(path);
        if (!File.Exists(full)
            || (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
        {
            throw new FileNotFoundException($"{label} is missing or linked.", full);
        }
        RequireNoLinkAncestors(Path.GetDirectoryName(full)!);
        RequireSingleLink(full, label);
        return full;
    }

    public static void WriteNewDurableAtomicallyCreateOnly(
        string destination,
        ReadOnlySpan<byte> bytes)
    {
        var full = Path.GetFullPath(destination);
        var parent = Path.GetDirectoryName(full)
            ?? throw new InvalidDataException("Atomic create-only destination has no parent.");
        var expected = bytes.ToArray();
        var temporary = Path.Combine(
            parent,
            $".{Path.GetFileName(full)}.{Guid.NewGuid():N}.tmp");
        try
        {
            WriteNewDurable(temporary, expected);
            try
            {
                File.Move(temporary, full);
                LinuxDurability.SyncDirectory(parent);
            }
            catch (IOException) when (File.Exists(full))
            {
                // Exact readback below decides a create-only race.
            }
            var committed = ReadBoundedRegularFile(
                full,
                expected.Length,
                "create-only durable output");
            if (!committed.AsSpan().SequenceEqual(expected))
            {
                throw new InvalidDataException(
                    "Create-only durable output conflicts with existing bytes.");
            }
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
                LinuxDurability.SyncDirectory(parent);
            }
        }
    }

    public static string RequireExternalResultReceiptPath(
        string path,
        string feedRoot,
        string candidateRoot,
        string trustPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException(
                "Enterprise promotion result receipt must use an absolute path.");
        }
        var full = Path.GetFullPath(path);
        RequireSafeFileName(Path.GetFileName(full), "promotion result receipt filename");
        var parent = RequireExistingDirectory(
            Path.GetDirectoryName(full)
                ?? throw new InvalidDataException(
                    "Enterprise promotion result receipt has no parent."),
            "promotion result receipt parent");
        if (IsSameOrDescendant(full, feedRoot)
            || IsSameOrDescendant(full, candidateRoot)
            || PathsEqual(full, Path.GetFullPath(trustPath)))
        {
            throw new InvalidDataException(
                "Enterprise promotion result receipt must be outside feed, candidate, and trust inputs.");
        }
        if (Directory.Exists(full))
        {
            throw new InvalidDataException(
                "Enterprise promotion result receipt path is unexpectedly a directory.");
        }
        if (File.Exists(full))
        {
            _ = RequireRegularFile(full, "existing promotion result receipt");
        }
        if (OperatingSystem.IsLinux())
        {
            for (var current = new DirectoryInfo(parent);
                 current is not null;
                 current = current.Parent)
            {
                RequireRootOwnedAndNotWritableByOthers(
                    current.FullName,
                    "promotion result receipt ancestor");
            }
        }
        return full;
    }

    private static bool IsSameOrDescendant(string path, string root)
    {
        var fullPath = Path.GetFullPath(path);
        var fullRoot = Path.GetFullPath(root).TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar);
        return PathsEqual(fullPath, fullRoot)
            || fullPath.StartsWith(
                fullRoot + Path.DirectorySeparatorChar,
                OperatingSystem.IsWindows()
                    ? StringComparison.OrdinalIgnoreCase
                    : StringComparison.Ordinal);
    }

    private static bool PathsEqual(string left, string right) => string.Equals(
        left,
        right,
        OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal);

    private static void RequireSingleLink(string path, string label)
    {
        if (OperatingSystem.IsLinux())
        {
            if (LStat(path, out var status) != 0)
            {
                throw new IOException(
                    $"Could not inspect {label} link count.",
                    new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
            }
            if ((status.Mode & FileTypeMask) != RegularFileType || status.HardLinks != 1)
            {
                throw new InvalidDataException(
                    $"{label} must be one ordinary single-link file.");
            }
            return;
        }
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Enterprise feed single-link validation supports Linux and Windows.");
        }
        using var handle = File.OpenHandle(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw new IOException(
                $"Could not inspect {label} link count.",
                new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
        }
        if (information.NumberOfLinks != 1
            || (information.FileAttributes & (uint)(
                FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new InvalidDataException(
                $"{label} must be one ordinary single-link file.");
        }
    }

    public static void RequireRootOwnedManagedTree(string root)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        RequireRootOwnedAndNotWritableByOthers(root, "enterprise feed root");
        foreach (var path in Directory.EnumerateFileSystemEntries(
                     root,
                     "*",
                     SearchOption.AllDirectories))
        {
            RequireRootOwnedAndNotWritableByOthers(path, "enterprise managed feed path");
        }
    }

    public static void RequireExactInventory(
        string directory,
        IReadOnlyCollection<string> requiredDirectories,
        IReadOnlyCollection<string> requiredFiles,
        IReadOnlyCollection<string> optionalDirectories,
        IReadOnlyCollection<string> optionalFiles,
        string label,
        IReadOnlyCollection<string>? alreadyValidatedOpenFiles = null)
    {
        var entries = Directory.EnumerateFileSystemEntries(directory).ToArray();
        var actualNames = entries.Select(Path.GetFileName)
            .Where(name => name is not null)
            .Cast<string>()
            .ToHashSet(StringComparer.Ordinal);
        var allowed = requiredDirectories
            .Concat(requiredFiles)
            .Concat(optionalDirectories)
            .Concat(optionalFiles)
            .ToHashSet(StringComparer.Ordinal);
        if (requiredDirectories.Any(name => !actualNames.Contains(name))
            || requiredFiles.Any(name => !actualNames.Contains(name))
            || actualNames.Any(name => !allowed.Contains(name)))
        {
            throw new InvalidDataException($"{label} contains unexpected inventory.");
        }
        foreach (var name in requiredDirectories.Concat(optionalDirectories)
                     .Where(actualNames.Contains))
        {
            _ = RequireExactDirectory(directory, name);
        }
        foreach (var name in requiredFiles.Concat(optionalFiles).Where(actualNames.Contains))
        {
            var path = Path.Combine(directory, name);
            if (alreadyValidatedOpenFiles is null
                || !alreadyValidatedOpenFiles.Any(value => PathsEqual(
                    Path.GetFullPath(value),
                    Path.GetFullPath(path))))
            {
                _ = RequireRegularFile(path, $"{label} managed file");
            }
        }
    }

    public static void RequireRootOwnedAndNotWritableByOthers(
        string path,
        string label)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        if (LStat(path, out var status) != 0)
        {
            throw new IOException(
                $"Could not inspect {label} ownership and mode.",
                new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
        }
        if ((status.Mode & FileTypeMask) == SymbolicLinkType
            || status.UserId != 0
            || (status.Mode & GroupOrOtherWrite) != 0)
        {
            throw new UnauthorizedAccessException(
                $"{label} must be root-owned, link-free, and not writable by group or others.");
        }
    }

    private const uint FileTypeMask = 0xF000;
    private const uint RegularFileType = 0x8000;
    private const uint SymbolicLinkType = 0xA000;
    private const uint GroupOrOtherWrite = 0x12;

    [DllImport("libc", EntryPoint = "lstat", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int LStat(string path, out LinuxStat status);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

    [StructLayout(LayoutKind.Sequential)]
    private struct LinuxTimespec
    {
        public long Seconds;
        public long Nanoseconds;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LinuxStat
    {
        public ulong Device;
        public ulong Inode;
        public ulong HardLinks;
        public uint Mode;
        public uint UserId;
        public uint GroupId;
        public int Padding;
        public ulong RawDevice;
        public long Size;
        public long BlockSize;
        public long Blocks;
        public LinuxTimespec AccessTime;
        public LinuxTimespec ModificationTime;
        public LinuxTimespec ChangeTime;
        public long Reserved0;
        public long Reserved1;
        public long Reserved2;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    private static void RequireNoLinkAncestors(string path)
    {
        var current = new DirectoryInfo(Path.GetFullPath(path));
        while (current is not null)
        {
            if (current.Exists
                && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("Feed paths may not cross filesystem links.");
            }
            current = current.Parent;
        }
    }
}

internal static partial class EnterpriseFeedLinuxSecurity
{
    private const uint FileTypeMask = 0xF000;
    private const uint RegularFileType = 0x8000;
    private const uint GroupOrOtherWrite = 0x12;
    private const int OpenReadOnly = 0;
    private const int OpenNoFollow = 0x20000;
    private const int OpenCloseOnExec = 0x80000;

    public static byte[] ReadRootOwnedStableFile(
        string path,
        int maximumBytes,
        string label,
        Action? afterOpen = null)
    {
        if (!OperatingSystem.IsLinux())
        {
            return FeedPathGuard.ReadBoundedRegularFile(path, maximumBytes, label);
        }
        var full = FeedPathGuard.RequireRegularFile(path, label);
        for (var current = new DirectoryInfo(Path.GetDirectoryName(full)!);
             current is not null;
             current = current.Parent)
        {
            FeedPathGuard.RequireRootOwnedAndNotWritableByOthers(
                current.FullName,
                $"{label} ancestor");
        }
        using var handle = OpenHandle(full, label);
        var initial = RequireSecure(handle, label, maximumBytes);
        afterOpen?.Invoke();
        var bytes = new byte[(int)initial.Size];
        var offset = 0;
        while (offset < bytes.Length)
        {
            var read = RandomAccess.Read(handle, bytes.AsSpan(offset), offset);
            if (read == 0)
            {
                throw new IOException($"{label} changed while it was read.");
            }
            offset += read;
        }
        Span<byte> extra = stackalloc byte[1];
        if (RandomAccess.Read(handle, extra, offset) != 0)
        {
            throw new IOException($"{label} changed while it was read.");
        }
        var final = RequireSecure(handle, label, maximumBytes);
        RequireSameIdentity(initial, final, label);
        using var probe = OpenHandle(full, label);
        RequireSameIdentity(final, RequireSecure(probe, label, maximumBytes), label);
        return bytes;
    }

    /// <summary>Reads a PKCS8 key only when it is root-private (0400 or 0600).</summary>
    public static byte[] ReadRootPrivateStableFile(string path, int maximumBytes, string label)
    {
        if (!OperatingSystem.IsLinux())
        {
            return FeedPathGuard.ReadBoundedRegularFile(path, maximumBytes, label);
        }
        var full = FeedPathGuard.RequireRegularFile(path, label);
        RequirePrivateKeyMode(full, label);
        var bytes = ReadRootOwnedStableFile(full, maximumBytes, label);
        RequirePrivateKeyMode(full, label);
        return bytes;
    }

    public static string HashRootOwnedStableFile(string path, long expectedSize, string label)
    {
        if (expectedSize <= 0) throw new InvalidDataException($"{label} size is invalid.");
        if (!OperatingSystem.IsLinux())
        {
            var measured = FeedPathGuard.HashRegularFile(path);
            if (measured.SizeBytes != expectedSize) throw new InvalidDataException($"{label} size changed.");
            return measured.Sha256;
        }
        var full = FeedPathGuard.RequireRegularFile(path, label);
        using var handle = OpenHandle(full, label);
        var initial = RequireSecure(handle, label, expectedSize);
        if (initial.Size != expectedSize) throw new InvalidDataException($"{label} size changed.");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[128 * 1024]; long offset = 0;
        while (offset < expectedSize)
        {
            var wanted = (int)Math.Min(buffer.Length, expectedSize - offset);
            var read = RandomAccess.Read(handle, buffer.AsSpan(0, wanted), offset);
            if (read <= 0) throw new IOException($"{label} changed while it was hashed.");
            hash.AppendData(buffer, 0, read); offset += read;
        }
        Span<byte> extra = stackalloc byte[1];
        if (RandomAccess.Read(handle, extra, offset) != 0) throw new IOException($"{label} changed while it was hashed.");
        RequireSameIdentity(initial, RequireSecure(handle, label, expectedSize), label);
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    public static void CreateOwnedPrivateDirectory(string path, string marker)
    {
        if (OperatingSystem.IsLinux())
        {
            if (Mkdir(path, Convert.ToUInt32("700", 8)) != 0)
                throw new IOException("Publication staging directory already exists or cannot be created.", new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));
        }
        else { Directory.CreateDirectory(path); }
        FeedPathGuard.RequireRootOwnedAndNotWritableByOthers(path, "publication staging directory");
        FeedPathGuard.WriteNewDurable(Path.Combine(path, ".owner"), System.Text.Encoding.ASCII.GetBytes(marker));
    }

    public static void DeleteOwnedPrivateDirectory(string path, string marker)
    {
        if (!Directory.Exists(path)) return;
        try
        {
            FeedPathGuard.RequireRootOwnedAndNotWritableByOthers(path, "publication staging directory");
            var owner = FeedPathGuard.ReadBoundedRegularFile(Path.Combine(path, ".owner"), 64, "publication staging owner");
            if (!System.Text.Encoding.ASCII.GetString(owner).Equals(marker, StringComparison.Ordinal)) return;
            FeedPathGuard.RequireSafeTree(path); Directory.Delete(path, true);
        }
        catch { }
    }

    [SupportedOSPlatform("linux")]
    private static void RequirePrivateKeyMode(string path, string label)
    {
        var mode = File.GetUnixFileMode(path);
        if (mode is not UnixFileMode.UserRead and not (UnixFileMode.UserRead | UnixFileMode.UserWrite))
        {
            throw new UnauthorizedAccessException(
                $"{label} must be root-private mode 0400 or 0600.");
        }
    }

    private static SafeFileHandle OpenHandle(string path, string label)
    {
        var descriptor = Open(
            path,
            OpenReadOnly | OpenNoFollow | OpenCloseOnExec);
        if (descriptor < 0)
        {
            throw new IOException(
                $"Could not open {label} without following links.",
                new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));
        }
        return new SafeFileHandle((nint)descriptor, ownsHandle: true);
    }

    [DllImport("libc", EntryPoint = "mkdir", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int Mkdir(string path, uint mode);

    private static LinuxStableStat RequireSecure(
        SafeFileHandle handle,
        string label,
        long maximumBytes)
    {
        var addedReference = false;
        LinuxStableStat status;
        int result;
        try
        {
            handle.DangerousAddRef(ref addedReference);
            result = FStat(handle.DangerousGetHandle().ToInt32(), out status);
        }
        finally
        {
            if (addedReference)
            {
                handle.DangerousRelease();
            }
        }
        if (result != 0)
        {
            throw new IOException(
                $"Could not inspect {label} stable handle.",
                new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));
        }
        if ((status.Mode & FileTypeMask) != RegularFileType
            || status.HardLinks != 1
            || status.UserId != 0
            || (status.Mode & GroupOrOtherWrite) != 0)
        {
            throw new UnauthorizedAccessException(
                $"{label} must be a root-owned single-link regular file not writable by group or others.");
        }
        if (status.Size is <= 0 || status.Size > maximumBytes || status.Size > int.MaxValue)
        {
            throw new InvalidDataException($"{label} size is invalid.");
        }
        return status;
    }

    private static void RequireSameIdentity(
        LinuxStableStat expected,
        LinuxStableStat actual,
        string label)
    {
        if (expected.Device != actual.Device
            || expected.Inode != actual.Inode
            || expected.Size != actual.Size
            || expected.ModificationTime.Seconds != actual.ModificationTime.Seconds
            || expected.ModificationTime.Nanoseconds != actual.ModificationTime.Nanoseconds
            || expected.ChangeTime.Seconds != actual.ChangeTime.Seconds
            || expected.ChangeTime.Nanoseconds != actual.ChangeTime.Nanoseconds)
        {
            throw new IOException($"{label} changed while it was read.");
        }
    }

    [LibraryImport(
        "libc",
        EntryPoint = "open",
        SetLastError = true,
        StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Open(string path, int flags);

    [LibraryImport("libc", EntryPoint = "fstat", SetLastError = true)]
    private static partial int FStat(int descriptor, out LinuxStableStat status);

    [StructLayout(LayoutKind.Sequential)]
    private struct LinuxStableTimespec
    {
        public long Seconds;
        public long Nanoseconds;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LinuxStableStat
    {
        public ulong Device;
        public ulong Inode;
        public ulong HardLinks;
        public uint Mode;
        public uint UserId;
        public uint GroupId;
        public int Padding;
        public ulong RawDevice;
        public long Size;
        public long BlockSize;
        public long Blocks;
        public LinuxStableTimespec AccessTime;
        public LinuxStableTimespec ModificationTime;
        public LinuxStableTimespec ChangeTime;
        public long Reserved0;
        public long Reserved1;
        public long Reserved2;
    }
}

internal static partial class LinuxIdentity
{
    [LibraryImport("libc")]
    private static partial uint geteuid();

    public static void RequireRoot()
    {
        if (OperatingSystem.IsLinux() && geteuid() != 0)
        {
            throw new UnauthorizedAccessException(
                "Enterprise feed promotion must run as root through the reviewed sudo command.");
        }
    }
}

internal static partial class LinuxDurability
{
    private const int OReadOnly = 0;
    private const int ODirectory = 0x10000;
    private const int OCloseOnExec = 0x80000;

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int open(string path, int flags);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int fsync(int descriptor);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int close(int descriptor);

    public static void SyncDirectory(string path)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        var descriptor = open(
            Path.GetFullPath(path),
            OReadOnly | ODirectory | OCloseOnExec);
        if (descriptor < 0)
        {
            throw new IOException(
                "Could not open a feed directory for durable metadata sync.",
                new System.ComponentModel.Win32Exception(
                    System.Runtime.InteropServices.Marshal.GetLastPInvokeError()));
        }
        try
        {
            if (fsync(descriptor) != 0)
            {
                throw new IOException(
                    "Could not fsync a feed directory after metadata mutation.",
                    new System.ComponentModel.Win32Exception(
                        System.Runtime.InteropServices.Marshal.GetLastPInvokeError()));
            }
        }
        finally
        {
            _ = close(descriptor);
        }
    }
}
