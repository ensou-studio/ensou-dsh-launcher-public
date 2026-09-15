using System.Security.Cryptography;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.Personal.FeedPromoter;

public sealed record PersonalFeedPromotionOptions(
    string CandidateDirectory,
    string FeedRoot,
    string TrustConfigurationPath,
    string Channel,
    string? CertifiedDistributionReceiptPath = null,
    string? StablePromotionAuthorizationPath = null,
    string? CleanDeviceLifecyclePath = null,
    string? TwoUpdateUpgradeLifecyclePath = null,
    string? FailureRecoveryLifecyclePath = null,
    string? ProductionGateEvidencePath = null,
    PersonalFeedProductionFoundation? ProductionFoundation = null,
    string? ResultReceiptPath = null);

public sealed record PersonalFeedPromotionResult(
    string Channel,
    string ReleaseSetId,
    long Generation,
    long Sequence,
    string ManifestSha256,
    string JournalEntryPath,
    string JournalEntrySha256,
    bool ChannelHeadChanged,
    bool ImmutableReleaseCreated,
    PersonalFeedPromotionResultReceipt? ProductionReceipt = null);

internal enum PersonalFeedPromotionStage
{
    ImmutableReleaseReady,
    ChannelHeadReplaced,
    JournalEntryCreated,
    JournalHeadReplaced,
    OperationReceiptCommitted,
}

public sealed class PersonalFeedPromoter
{
    private readonly TimeProvider _timeProvider;
    private readonly Action<PersonalFeedPromotionStage>? _testFault;

    public PersonalFeedPromoter()
        : this(TimeProvider.System, null)
    {
    }

    internal PersonalFeedPromoter(
        TimeProvider timeProvider,
        Action<PersonalFeedPromotionStage>? testFault)
    {
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _testFault = testFault;
    }

    public PersonalFeedPromotionResult Promote(PersonalFeedPromotionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        PersonalFeedChannels.Require(options.Channel);
        options.ProductionFoundation?.Validate();
        var candidate = PersonalFeedPathGuard.RequireExistingDirectory(
            options.CandidateDirectory,
            "candidate directory");
        if (options.ProductionFoundation is not null)
        {
            _ = PersonalFeedPathGuard.RequireExternalResultReceiptPath(
                options.ResultReceiptPath
                    ?? throw new InvalidDataException(
                        "Personal production promotion requires a result receipt path."),
                options.FeedRoot,
                candidate,
                options.TrustConfigurationPath);
        }
        PersonalFeedPathGuard.RequireSafeTree(candidate);
        var layout = PersonalFeedLayout.Open(options.FeedRoot);
        var trustBytes = LinuxNative.ReadRootOwnedRegularFile(
            options.TrustConfigurationPath,
            256 * 1024,
            "personal feed trust configuration");
        var trust = PersonalFeedTrustConfiguration.Parse(trustBytes);
        var trustSha256 = PersonalFeedJson.Sha256(trustBytes);
        var releasePolicy = trust.ToReleasePolicy(options.Channel);

        RequireCertificationArgumentSet(options);
        var candidateManifestBytes = PersonalFeedPathGuard.ReadBoundedRegularFile(
            Path.Combine(candidate, "release-set.v2.json"),
            PersonalReleaseSetContract.MaximumManifestBytes,
            "personal candidate manifest");
        var verified = PersonalReleaseSetValidator.ParseAndVerify(
            candidateManifestBytes,
            releasePolicy,
            _timeProvider.GetUtcNow());
        var manifest = verified.Manifest;
        var canonicalManifest = PersonalReleaseSetJson.SerializeSigned(manifest);
        if (!candidateManifestBytes.AsSpan().SequenceEqual(canonicalManifest))
        {
            throw new InvalidDataException(
                "Personal feed candidate manifest must use the canonical signed JSON encoding.");
        }
        var manifestSha256 = PersonalFeedJson.Sha256(candidateManifestBytes);
        if (!string.Equals(
                manifestSha256,
                verified.CanonicalSignedManifestSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal feed candidate manifest digest is not canonical.");
        }

        var publicationLockPath = Path.Combine(layout.JournalRoot, "publication.lock");
        var channelLockPath = Path.Combine(
            layout.ChannelJournalRoot(options.Channel),
            "promotion.lock");
        using var publicationLock = OpenPromotionLock(publicationLockPath);
        using var channelLock = OpenPromotionLock(channelLockPath);
        layout = PersonalFeedLayout.Open(
            options.FeedRoot,
            [publicationLockPath, channelLockPath]);

        if (string.Equals(options.Channel, "stable", StringComparison.Ordinal))
        {
            VerifyStableAuthorization(
                options,
                layout,
                trust,
                manifest,
                manifestSha256);
        }

        var stage = Path.Combine(
            layout.StagingRoot,
            $"{options.Channel}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(stage);
        PersonalFeedPathGuard.SetDirectoryMode(stage, publicRead: false);
        LinuxNative.FlushDirectory(layout.StagingRoot);
        try
        {
            var stagedManifestPath = Path.Combine(stage, "release-set.v2.json");
            PersonalFeedPathGuard.WriteNewDurable(stagedManifestPath, candidateManifestBytes);

            var payloadStage = Path.Combine(stage, "release");
            Directory.CreateDirectory(payloadStage);
            PersonalFeedPathGuard.SetDirectoryMode(payloadStage, publicRead: false);
            var artifacts = StageAndVerifyArtifacts(
                candidate,
                payloadStage,
                manifest,
                releasePolicy);
            RequireExactCandidateTree(candidate, artifacts);

            var channelRoot = layout.ChannelRoot(options.Channel);
            var channelHeadPath = Path.Combine(channelRoot, "release-set.v2.json");
            var channelJournalRoot = layout.ChannelJournalRoot(options.Channel);
            var journalHeadPath = Path.Combine(channelJournalRoot, "head.json");
            PersonalFeedOperationRequest? operationRequest = null;
            var observedChannelHead = PersonalFeedOperationStore.Observe(
                channelHeadPath,
                PersonalReleaseSetContract.MaximumManifestBytes,
                "personal channel head CAS input");
            var observedJournalHead = PersonalFeedOperationStore.Observe(
                journalHeadPath,
                128 * 1024,
                "personal journal head CAS input");
            if (options.ProductionFoundation is not null)
            {
                var identityBytes = PersonalFeedPathGuard.ReadBoundedRegularFile(
                    Path.Combine(layout.Root, PersonalFeedLayout.IdentityFileName),
                    16 * 1024,
                    "personal feed identity CAS input");
                var identitySha256 = PersonalFeedJson.Sha256(identityBytes);
                if (!string.Equals(
                        identitySha256,
                        options.ProductionFoundation.ExpectedFeedIdentitySha256,
                        StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "Personal expected feed identity does not match the locked production feed.");
                }
                operationRequest = PersonalFeedOperationStore.CreateRequest(
                    options.ProductionFoundation,
                    options.Channel,
                    candidateManifestBytes.LongLength,
                    manifestSha256,
                    trustSha256);
            }
            var current = ReadCurrentHead(
                channelHeadPath,
                layout.ReleasesRoot,
                releasePolicy);
            var journal = PersonalFeedJournalStore.ReadValidated(
                channelJournalRoot,
                options.Channel);
            RequireRecoverableHeadAndJournal(current, journal, manifest, manifestSha256);
            var sameManifest = current is not null
                && string.Equals(current.ManifestSha256, manifestSha256, StringComparison.Ordinal);
            if (current is not null && !sameManifest)
            {
                RequireForwardOnly(current.Manifest, manifest);
            }
            RequireForwardFromJournal(journal, manifest, sameManifest);

            PersonalFeedOperationSession? operation = operationRequest is null
                ? null
                : PersonalFeedOperationStore.Begin(
                    layout.OperationsRoot,
                    operationRequest,
                    observedChannelHead,
                    observedJournalHead,
                    allowCreate: !sameManifest);
            if (operation?.CommittedReceipt is not null)
            {
                PersonalFeedOperationStore.RequireCas(
                    operation.CommittedReceipt.ChannelHead,
                    observedChannelHead,
                    "committed channel head");
                PersonalFeedOperationStore.RequireCas(
                    operation.CommittedReceipt.JournalHead,
                    observedJournalHead,
                    "committed journal head");
                if (!sameManifest || current is null)
                {
                    throw new InvalidDataException(
                        "Personal committed operation response no longer matches the channel head.");
                }
                RequireCommittedHead(current, journal);
                return ResultFromReceipt(operation.CommittedReceipt);
            }

            var releaseDirectory = Path.Combine(layout.ReleasesRoot, manifest.ReleaseSetId);
            var releaseCreated = PublishOrVerifyImmutableRelease(
                payloadStage,
                releaseDirectory,
                artifacts);
            _testFault?.Invoke(PersonalFeedPromotionStage.ImmutableReleaseReady);

            var headChanged = false;
            if (!sameManifest)
            {
                PersonalFeedPathGuard.ReplaceDurableFileAtomically(
                    channelHeadPath,
                    candidateManifestBytes,
                    channelRoot);
                headChanged = true;
                _testFault?.Invoke(PersonalFeedPromotionStage.ChannelHeadReplaced);
            }

            var journalCompletion = PersonalFeedJournalStore.Complete(
                channelJournalRoot,
                manifest,
                manifestSha256,
                artifacts,
                _timeProvider.GetUtcNow(),
                _testFault);
            if (operation is not null)
            {
                var finalChannelHead = PersonalFeedOperationStore.Observe(
                    channelHeadPath,
                    PersonalReleaseSetContract.MaximumManifestBytes,
                    "personal committed channel head");
                var finalJournalHead = PersonalFeedOperationStore.Observe(
                    journalHeadPath,
                    128 * 1024,
                    "personal committed journal head");
                var channelUri = new Uri(
                    trust.ManifestOrigin,
                    $"v2/channels/{Uri.EscapeDataString(options.Channel)}/release-set.v2.json");
                if (!string.Equals(
                        channelUri.Scheme,
                        Uri.UriSchemeHttps,
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException(
                        "Personal production result channel manifest URI must use HTTPS.");
                }
                var receipt = PersonalFeedOperationStore.Commit(
                    operation,
                    new PersonalFeedPromotionResultReceipt(
                        1,
                        operation.Request.OperationId,
                        operation.Request.RequestSha256,
                        PersonalReleaseSetContract.Product,
                        PersonalReleaseSetContract.ProductionEnvironment,
                        options.Channel,
                        manifest.ReleaseSetId,
                        manifest.Generation,
                        manifest.Sequence,
                        manifest.MinAcceptedSequence,
                        manifestSha256,
                        $"public/channels/{options.Channel}/release-set.v2.json",
                        channelUri.AbsoluteUri,
                        $"journal/{options.Channel}/{Path.GetFileName(journalCompletion.EntryPath)}",
                        journalCompletion.EntrySha256,
                        finalChannelHead,
                        finalJournalHead,
                        journalCompletion.Entry.PublishedAtUtc,
                        ChannelHeadChanged: true,
                        ImmutableReleaseCreated: true));
                _testFault?.Invoke(PersonalFeedPromotionStage.OperationReceiptCommitted);
                return ResultFromReceipt(receipt);
            }
            return new PersonalFeedPromotionResult(
                options.Channel,
                manifest.ReleaseSetId,
                manifest.Generation,
                manifest.Sequence,
                manifestSha256,
                journalCompletion.EntryPath,
                journalCompletion.EntrySha256,
                headChanged,
                releaseCreated);
        }
        finally
        {
            PersonalFeedPathGuard.DeletePrivateStage(stage, layout.StagingRoot);
        }
    }

    private static PersonalFeedPromotionResult ResultFromReceipt(
        PersonalFeedPromotionResultReceipt receipt) => new(
            receipt.Channel,
            receipt.ReleaseSetId,
            receipt.Generation,
            receipt.Sequence,
            receipt.ManifestSha256,
            receipt.PromotionJournalEntryRelativePath,
            receipt.PromotionJournalSha256,
            receipt.ChannelHeadChanged,
            receipt.ImmutableReleaseCreated,
            receipt);

    private static FileStream OpenPromotionLock(string path)
    {
        var full = PersonalFeedPathGuard.RequireRegularFile(path, "personal feed lock");
        LinuxNative.RequireRootOwnedAndNotWritableByOthers(full, "personal feed lock");
        var stream = new FileStream(
            full,
            FileMode.Open,
            FileAccess.Read,
            FileShare.None,
            1,
            FileOptions.None);
        return stream;
    }

    private static void RequireCertificationArgumentSet(PersonalFeedPromotionOptions options)
    {
        var values = new[]
        {
            options.CertifiedDistributionReceiptPath,
            options.StablePromotionAuthorizationPath,
            options.CleanDeviceLifecyclePath,
            options.TwoUpdateUpgradeLifecyclePath,
            options.FailureRecoveryLifecyclePath,
            options.ProductionGateEvidencePath,
        };
        if (string.Equals(options.Channel, "stable", StringComparison.Ordinal))
        {
            if (values.Any(string.IsNullOrWhiteSpace))
            {
                throw new InvalidDataException(
                    "Personal Stable promotion requires the distribution receipt, independent authorization, and all three lifecycle sidecars.");
            }
        }
        else if (values.Any(value => value is not null))
        {
            throw new InvalidDataException(
                "Personal Stable certification inputs are accepted only by the stable channel.");
        }
    }

    private static IReadOnlyList<PersonalFeedArtifactReceipt> StageAndVerifyArtifacts(
        string candidate,
        string payloadStage,
        PersonalReleaseSetManifest manifest,
        PersonalReleaseTrustPolicy policy)
    {
        var receipts = new List<PersonalFeedArtifactReceipt>(2);
        var fileNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var artifact in manifest.Artifacts)
        {
            var fileName = RequireExactArtifactUri(manifest, artifact, policy);
            if (!fileNames.Add(fileName))
            {
                throw new InvalidDataException(
                    "Personal release artifacts must use distinct filenames.");
            }
            var destination = Path.Combine(payloadStage, fileName);
            var copied = PersonalFeedPathGuard.CopyNewAndHash(
                Path.Combine(candidate, fileName),
                destination);
            if (copied.SizeBytes != artifact.SizeBytes
                || !string.Equals(copied.Sha256, artifact.Sha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Personal candidate artifact does not match signed bytes: {artifact.Component}.");
            }
            receipts.Add(new PersonalFeedArtifactReceipt(
                artifact.Component,
                artifact.ReleaseId,
                fileName,
                copied.SizeBytes,
                copied.Sha256,
                artifact.CompleteTreeSha256));
        }
        return receipts;
    }

    private static string RequireExactArtifactUri(
        PersonalReleaseSetManifest manifest,
        PersonalReleaseArtifact artifact,
        PersonalReleaseTrustPolicy policy)
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
                "Personal artifact URI does not use the immutable v2 release layout.");
        }
        var uriReleaseId = Uri.UnescapeDataString(escapedSegments[2]);
        var fileName = Uri.UnescapeDataString(escapedSegments[3]);
        PersonalFeedPathGuard.RequireSafeFileName(fileName, "artifact filename");
        if (!string.Equals(uriReleaseId, manifest.ReleaseSetId, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal artifact URI release directory does not match releaseSetId.");
        }
        var expected = new Uri(
            policy.ArtifactOrigin,
            $"v2/releases/{Uri.EscapeDataString(manifest.ReleaseSetId)}/{Uri.EscapeDataString(fileName)}");
        if (!string.Equals(
                artifact.Uri.AbsoluteUri,
                expected.AbsoluteUri,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("Personal artifact URI is not canonical.");
        }
        return fileName;
    }

    private static void RequireExactCandidateTree(
        string candidate,
        IReadOnlyList<PersonalFeedArtifactReceipt> artifacts)
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
                "Personal candidate must contain only its canonical manifest and two signed artifacts.");
        }
    }

    private static PersonalCurrentFeedHead? ReadCurrentHead(
        string headPath,
        string releasesRoot,
        PersonalReleaseTrustPolicy policy)
    {
        if (!File.Exists(headPath))
        {
            return null;
        }
        var bytes = PersonalFeedPathGuard.ReadBoundedRegularFile(
            headPath,
            PersonalReleaseSetContract.MaximumManifestBytes,
            "personal current channel head");
        var manifest = PersonalReleaseSetJson.Parse(bytes);
        var historicalPolicy = policy with
        {
            StartupStubVersion = manifest.StartupStub.MinimumVersion,
        };
        PersonalReleaseSetValidator.Verify(manifest, historicalPolicy, manifest.IssuedAtUtc);
        if (!bytes.AsSpan().SequenceEqual(PersonalReleaseSetJson.SerializeSigned(manifest)))
        {
            throw new InvalidDataException("Personal current channel head is not canonical JSON.");
        }
        var receipts = manifest.Artifacts.Select(artifact =>
        {
            var fileName = RequireExactArtifactUri(manifest, artifact, historicalPolicy);
            var measured = PersonalFeedPathGuard.HashRegularFile(
                Path.Combine(releasesRoot, manifest.ReleaseSetId, fileName));
            if (measured.SizeBytes != artifact.SizeBytes
                || !string.Equals(measured.Sha256, artifact.Sha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Personal current feed head references missing or changed immutable bytes.");
            }
            return new PersonalFeedArtifactReceipt(
                artifact.Component,
                artifact.ReleaseId,
                fileName,
                measured.SizeBytes,
                measured.Sha256,
                artifact.CompleteTreeSha256);
        }).ToArray();
        return new PersonalCurrentFeedHead(manifest, PersonalFeedJson.Sha256(bytes), receipts);
    }

    private static void RequireRecoverableHeadAndJournal(
        PersonalCurrentFeedHead? current,
        PersonalFeedJournalSnapshot? journal,
        PersonalReleaseSetManifest candidate,
        string candidateManifestSha256)
    {
        if (current is null)
        {
            if (journal is not null)
            {
                throw new InvalidDataException(
                    "Personal channel head is missing behind its promotion journal.");
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
                    "Personal promotion journal is missing for the current channel head.");
            }
            return;
        }
        var committed = journal.Head.Sequence == current.Manifest.Sequence
            && journal.Head.Generation == current.Manifest.Generation
            && string.Equals(
                journal.Head.ReleaseSetId,
                current.Manifest.ReleaseSetId,
                StringComparison.Ordinal)
            && string.Equals(
                journal.Head.ManifestSha256,
                current.ManifestSha256,
                StringComparison.Ordinal);
        if (committed)
        {
            return;
        }
        var interruptedCandidate = string.Equals(
                current.ManifestSha256,
                candidateManifestSha256,
                StringComparison.Ordinal)
            && current.Manifest.Sequence == candidate.Sequence
            && current.Manifest.Generation == candidate.Generation
            && current.Manifest.Sequence > journal.Head.Sequence;
        if (!interruptedCandidate)
        {
            throw new InvalidDataException(
                "Personal channel head and promotion journal are inconsistent.");
        }
    }

    private static void RequireForwardOnly(
        PersonalReleaseSetManifest current,
        PersonalReleaseSetManifest candidate)
    {
        if (candidate.Sequence <= current.Sequence
            || candidate.Generation < current.Generation
            || candidate.MinAcceptedSequence < current.MinAcceptedSequence
            || !current.RevokedReleaseSetIds.All(value =>
                candidate.RevokedReleaseSetIds.Contains(value, StringComparer.Ordinal)))
        {
            throw new InvalidDataException(
                "Personal feed rejected sequence, generation, minimum floor, or revocation rollback.");
        }
    }

    private static void RequireForwardFromJournal(
        PersonalFeedJournalSnapshot? journal,
        PersonalReleaseSetManifest candidate,
        bool sameManifest)
    {
        if (journal is null)
        {
            return;
        }
        if (sameManifest
            && journal.Head.Sequence == candidate.Sequence
            && string.Equals(
                journal.Head.ManifestSha256,
                PersonalFeedJson.Sha256(PersonalReleaseSetJson.SerializeSigned(candidate)),
                StringComparison.Ordinal))
        {
            return;
        }
        var latest = journal.LatestEntry;
        if (candidate.Sequence <= latest.Sequence
            || candidate.Generation < latest.Generation
            || candidate.MinAcceptedSequence < latest.MinAcceptedSequence
            || !latest.RevokedReleaseSetIds.All(value =>
                candidate.RevokedReleaseSetIds.Contains(value, StringComparer.Ordinal)))
        {
            throw new InvalidDataException(
                "Personal feed candidate rolls back the authenticated promotion journal.");
        }
    }

    private void VerifyStableAuthorization(
        PersonalFeedPromotionOptions options,
        PersonalFeedLayout layout,
        PersonalFeedTrustConfiguration trust,
        PersonalReleaseSetManifest stable,
        string stableManifestSha256)
    {
        if (string.IsNullOrWhiteSpace(options.CertifiedDistributionReceiptPath)
            || string.IsNullOrWhiteSpace(options.StablePromotionAuthorizationPath)
            || string.IsNullOrWhiteSpace(options.CleanDeviceLifecyclePath)
            || string.IsNullOrWhiteSpace(options.TwoUpdateUpgradeLifecyclePath)
            || string.IsNullOrWhiteSpace(options.FailureRecoveryLifecyclePath)
            || string.IsNullOrWhiteSpace(options.ProductionGateEvidencePath))
        {
            throw new InvalidDataException(
                "Personal Stable promotion requires all certified Pilot evidence inputs.");
        }
        var pilotPolicy = trust.ToReleasePolicy("pilot");
        var pilot = ReadCurrentHead(
            Path.Combine(layout.ChannelRoot("pilot"), "release-set.v2.json"),
            layout.ReleasesRoot,
            pilotPolicy)
            ?? throw new InvalidDataException(
                "Personal Stable promotion requires a current certified Pilot head.");
        var pilotJournal = PersonalFeedJournalStore.ReadValidated(
            layout.ChannelJournalRoot("pilot"),
            "pilot");
        RequireCommittedHead(pilot, pilotJournal);
        RequireStableMatchesPilot(pilot.Manifest, stable);

        var lifecycleEvidence = new PersonalLifecycleEvidenceSet(
            PersonalLifecycleEvidenceSnapshot.Read(
                options.CleanDeviceLifecyclePath,
                "clean-device lifecycle evidence receipt"),
            PersonalLifecycleEvidenceSnapshot.Read(
                options.TwoUpdateUpgradeLifecyclePath,
                "two-update upgrade lifecycle evidence receipt"),
            PersonalLifecycleEvidenceSnapshot.Read(
                options.FailureRecoveryLifecyclePath,
                "failure-recovery lifecycle evidence receipt"));

        var receiptBytes = PersonalFeedPathGuard.ReadBoundedRegularFile(
            options.CertifiedDistributionReceiptPath,
            512 * 1024,
            "personal certified distribution receipt");
        var receipt = PersonalCertifiedDistributionReceipt.Parse(receiptBytes);
        var gateEvidence = PersonalProductionGateEvidenceSnapshot.Read(
            options.ProductionGateEvidencePath);
        gateEvidence.Evidence.Verify(
            trust,
            stable,
            stableManifestSha256,
            PersonalReleaseSetJson.SerializeSigned(stable).LongLength);
        receipt.Verify(
            pilot.Manifest,
            pilot.ManifestSha256,
            stable,
            stableManifestSha256,
            trust,
            lifecycleEvidence,
            gateEvidence);
        var authorizationBytes = PersonalFeedPathGuard.ReadBoundedRegularFile(
            options.StablePromotionAuthorizationPath,
            128 * 1024,
            "personal Stable promotion authorization");
        var authorization = PersonalStablePromotionAuthorization.Parse(authorizationBytes);
        authorization.Verify(
            trust,
            stable,
            pilot.ManifestSha256,
            stableManifestSha256,
            receipt,
            PersonalFeedJson.Sha256(receiptBytes),
            _timeProvider.GetUtcNow());
    }

    private static void RequireCommittedHead(
        PersonalCurrentFeedHead head,
        PersonalFeedJournalSnapshot? journal)
    {
        if (journal is null
            || journal.Head.Sequence != head.Manifest.Sequence
            || journal.Head.Generation != head.Manifest.Generation
            || !string.Equals(
                journal.Head.ReleaseSetId,
                head.Manifest.ReleaseSetId,
                StringComparison.Ordinal)
            || !string.Equals(
                journal.Head.ManifestSha256,
                head.ManifestSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal Pilot channel head is not committed by its promotion journal.");
        }
    }

    internal static void RequireStableMatchesPilot(
        PersonalReleaseSetManifest pilot,
        PersonalReleaseSetManifest stable)
    {
        var pilotWithoutChannelAndSignatures = StableEquivalenceProjection.Create(pilot);
        var stableWithoutChannelAndSignatures = StableEquivalenceProjection.Create(stable);
        if (!pilotWithoutChannelAndSignatures.Equals(stableWithoutChannelAndSignatures))
        {
            throw new InvalidDataException(
                "Personal Stable must promote the exact certified Pilot release and artifact bytes.");
        }
    }

    private static bool PublishOrVerifyImmutableRelease(
        string stagedRelease,
        string destination,
        IReadOnlyList<PersonalFeedArtifactReceipt> artifacts)
    {
        if (Directory.Exists(destination))
        {
            PersonalFeedPathGuard.RequireSafeTree(destination);
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
                    "Existing personal immutable release directory has an unexpected tree.");
            }
            foreach (var artifact in artifacts)
            {
                var measured = PersonalFeedPathGuard.HashRegularFile(
                    Path.Combine(destination, artifact.FileName));
                if (measured.SizeBytes != artifact.SizeBytes
                    || !string.Equals(measured.Sha256, artifact.Sha256, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "Existing personal immutable release bytes conflict with the candidate.");
                }
            }
            return false;
        }
        Directory.Move(stagedRelease, destination);
        PersonalFeedPathGuard.MakeReleaseReadOnly(destination);
        return true;
    }

    private sealed record PersonalCurrentFeedHead(
        PersonalReleaseSetManifest Manifest,
        string ManifestSha256,
        IReadOnlyList<PersonalFeedArtifactReceipt> Artifacts);

    private sealed record StableEquivalenceProjection(
        string ReleaseSetId,
        string LauncherRepositoryCommit,
        string HarnessSourceTag,
        string HarnessSourceCommit,
        long Generation,
        long Sequence,
        long MinAcceptedSequence,
        DateTimeOffset IssuedAtUtc,
        DateTimeOffset ExpiresAtUtc,
        long MaximumOfflineGraceSeconds,
        string MinimumStubVersion,
        string MaximumStubVersion,
        string Revocations,
        string Artifacts)
    {
        public static StableEquivalenceProjection Create(PersonalReleaseSetManifest manifest) => new(
            manifest.ReleaseSetId,
            manifest.Provenance.LauncherRepositoryCommit,
            manifest.Provenance.HarnessSourceTag,
            manifest.Provenance.HarnessSourceCommit,
            manifest.Generation,
            manifest.Sequence,
            manifest.MinAcceptedSequence,
            manifest.IssuedAtUtc,
            manifest.ExpiresAtUtc,
            manifest.MaximumOfflineGraceSeconds,
            manifest.StartupStub.MinimumVersion,
            manifest.StartupStub.MaximumVersion,
            string.Join('\n', manifest.RevokedReleaseSetIds),
            string.Join('\n', manifest.Artifacts.Select(artifact => string.Join(
                '|',
                artifact.Component,
                artifact.ReleaseId,
                artifact.Uri.AbsolutePath,
                artifact.SizeBytes,
                artifact.Sha256,
                artifact.CompleteTreeSha256))));
    }
}
