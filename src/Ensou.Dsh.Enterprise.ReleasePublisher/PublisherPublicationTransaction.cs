using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Installation;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.Enterprise.ReleasePublisher;

internal enum PublisherPublicationCommitStage
{
    PendingCommitted,
    LedgerCommitted,
    AnchorCommitted,
    OutputFileCommitted,
    ManifestCommitted,
    ReceiptCommitted,
    PendingCleanupCompleted,
}

internal sealed record PublisherPublicationSource(
    string FileName,
    string SourcePath,
    long SizeBytes,
    string Sha256);

internal sealed record PublisherPublicationRequest(
    string LedgerPath,
    string OutputDirectory,
    PublisherLedger LedgerAfter,
    string ConfigSha256,
    string InputSetSha256,
    byte[] ManifestBytes,
    byte[] PublicKeyBytes,
    IReadOnlyList<PublisherPublicationSource> Artifacts);

internal sealed record PublisherPublicationProbe(
    string LedgerPath,
    string OutputDirectory,
    string Environment,
    string Channel,
    string ReleaseSetId,
    long Generation,
    long Sequence,
    long MinAcceptedSequence,
    string ConfigSha256,
    string InputSetSha256,
    byte[] PublicKeyBytes,
    IReadOnlyList<PublisherPublicationSource> Artifacts);

internal sealed record PublisherPublicationResult(
    string OutputDirectory,
    string ManifestPath,
    long ManifestSizeBytes,
    string ManifestSha256,
    bool IsExactCommittedRetry);

/// <summary>
/// Publishes the Enterprise release candidate and advances its sequence ledger
/// as one recoverable transaction. The authority files are DPAPI authenticated
/// and live outside the ledger/output tree, so replaying that whole tree cannot
/// roll the independently protected high-water mark back.
/// </summary>
internal sealed class PublisherPublicationTransaction
{
    internal const string ManifestFileName = "release-set.v2.json";
    internal const string PublicKeyFileName = "release-public-key.v2.json";
    private const int CurrentSchemaVersion = 2;
    private const int MaximumManifestBytes = 512 * 1024;
    private const int MaximumPublicKeyBytes = 256 * 1024;
    private const int MaximumLedgerBytes = 512 * 1024;
    private const int MaximumProtectedBytes = 8 * 1024 * 1024;
    private static readonly string ZeroSha256 = new('0', 64);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 64,
        NumberHandling = JsonNumberHandling.Strict,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = true,
    };

    private readonly Action<PublisherPublicationCommitStage>? _checkpoint;
    private readonly string? _authorityRoot;

    public PublisherPublicationTransaction(
        Action<PublisherPublicationCommitStage>? checkpoint = null,
        string? authorityRoot = null)
    {
        _checkpoint = checkpoint;
        _authorityRoot = authorityRoot;
    }

    public PublisherPublicationResult Publish(PublisherPublicationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        RequireWindows();
        var validated = ValidatedRequest.Create(request);
        var authority = new AuthorityStore(validated, _authorityRoot);

        using var authorityLock = authority.AcquireLock();
        using var ledgerLock = AcquireLedgerLock(validated.LedgerPath);
        authority.InitializeGenesisIfSafe();
        var anchor = authority.ReadAnchor();

        if (authority.PendingExists)
        {
            var recovered = RecoverPending(authority, anchor, validated);
            return CompleteCleanupWithoutChangingCommittedOutcome(authority, recovered);
        }

        var ledgerBefore = ReadLedgerState(validated.LedgerPath, validated);
        RequireLedgerMatchesAnchor(anchor, ledgerBefore);
        var committed = authority.TryReadReceipt(anchor, ledgerBefore.Ledger);
        if (committed is not null)
        {
            var exact = IsExactCandidate(committed, validated);
            if (exact)
            {
                return CreateResult(committed, isExactRetry: true);
            }
        }

        if (Directory.Exists(validated.OutputDirectory)
            || File.Exists(validated.OutputDirectory))
        {
            throw new IOException(
                "Enterprise publication output exists without the exact authenticated committed receipt for this candidate.");
        }

        RequireForward(ledgerBefore.Ledger, validated.LedgerAfter);
        var intent = authority.CreateIntent(anchor, ledgerBefore, validated);
        authority.WritePending(intent);
        _checkpoint?.Invoke(PublisherPublicationCommitStage.PendingCommitted);
        var committedReceipt = ApplyIntent(authority, anchor, ledgerBefore, intent, validated);
        return CompleteCleanupWithoutChangingCommittedOutcome(
            authority,
            CreateResult(committedReceipt, isExactRetry: false));
    }

    public PublisherPublicationResult? TryRecoverOrReadExact(
        PublisherPublicationProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        RequireWindows();
        var validated = ValidatedRequest.CreateProbe(probe);
        var authority = new AuthorityStore(validated, _authorityRoot);
        using var authorityLock = authority.AcquireLock();
        using var ledgerLock = AcquireLedgerLock(validated.LedgerPath);
        authority.InitializeGenesisIfSafe();
        var anchor = authority.ReadAnchor();
        if (authority.PendingExists)
        {
            var recovered = RecoverPending(authority, anchor, validated);
            return CompleteCleanupWithoutChangingCommittedOutcome(authority, recovered);
        }
        var ledger = ReadLedgerState(validated.LedgerPath, validated);
        RequireLedgerMatchesAnchor(anchor, ledger);
        var receipt = authority.TryReadReceipt(anchor, ledger.Ledger);
        return receipt is not null && IsExactCandidate(receipt, validated)
            ? CreateResult(receipt, isExactRetry: true)
            : null;
    }

    internal static string GetAnchorPath(
        PublisherPublicationRequest request,
        string? authorityRoot = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        RequireWindows();
        return new AuthorityStore(ValidatedRequest.Create(request), authorityRoot).AnchorPath;
    }

    private PublisherPublicationResult RecoverPending(
        AuthorityStore authority,
        PublicationAnchor anchor,
        ValidatedRequest request)
    {
        var intent = authority.ReadPending();
        try
        {
            authority.ValidateIntent(intent);
            if (!string.Equals(
                    intent.CandidateIdentitySha256,
                    request.CandidateIdentitySha256,
                    StringComparison.Ordinal)
                || !string.Equals(
                    intent.OutputDirectory,
                    request.OutputDirectory,
                    StringComparison.OrdinalIgnoreCase)
                || !SourceDescriptorsMatch(intent.OutputFiles, request))
            {
                throw new InvalidOperationException(
                    "Enterprise publication has an authenticated pending candidate. Only that exact candidate may recover it; a later sequence is rejected before recovery.");
            }

            var ledger = ReadLedgerState(request.LedgerPath, request);
            var atPrevious = AnchorEquals(anchor, intent.PreviousAnchor)
                && string.Equals(
                    ledger.Sha256,
                    intent.LedgerBeforeSha256,
                    StringComparison.Ordinal);
            var atNext = AnchorEquals(anchor, intent.NextAnchor)
                && string.Equals(
                    ledger.Sha256,
                    intent.LedgerAfterSha256,
                    StringComparison.Ordinal);
            var ledgerAheadOfAnchor = AnchorEquals(anchor, intent.PreviousAnchor)
                && string.Equals(
                    ledger.Sha256,
                    intent.LedgerAfterSha256,
                    StringComparison.Ordinal);
            if (!atPrevious && !atNext && !ledgerAheadOfAnchor)
            {
                throw new InvalidDataException(
                    "Enterprise publication recovery found an unrelated, replayed, or substituted ledger/anchor pair.");
            }

            if (atPrevious)
            {
                ReplaceDurable(request.LedgerPath, intent.LedgerAfterBytes, "publisher ledger");
                RequireFileDigest(
                    request.LedgerPath,
                    intent.LedgerAfterBytes.LongLength,
                    intent.LedgerAfterSha256,
                    MaximumLedgerBytes,
                    "publisher ledger after recovery write");
                _checkpoint?.Invoke(PublisherPublicationCommitStage.LedgerCommitted);
            }
            if (!atNext)
            {
                authority.CommitAnchor(intent.NextAnchor);
                anchor = authority.ReadAnchor();
                if (!AnchorEquals(anchor, intent.NextAnchor))
                {
                    throw new IOException(
                        "Enterprise publication anchor did not persist exactly during recovery.");
                }
                _checkpoint?.Invoke(PublisherPublicationCommitStage.AnchorCommitted);
            }

            var currentLedger = ReadLedgerState(request.LedgerPath, request);
            RequireLedgerMatchesAnchor(anchor, currentLedger);
            var receipt = authority.TryReadReceiptForPending(
                intent,
                currentLedger.Ledger
                    ?? throw new InvalidDataException(
                        "Enterprise publication pending transaction committed no ledger."));
            if (receipt is null)
            {
                receipt = PublishOutputAndReceipt(authority, intent, request);
            }
            else
            {
                authority.RequireReceiptMatchesIntent(receipt, intent);
            }
            return CreateResult(receipt, isExactRetry: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(intent.ManifestBytes);
            CryptographicOperations.ZeroMemory(intent.PublicKeyBytes);
            CryptographicOperations.ZeroMemory(intent.LedgerAfterBytes);
        }
    }

    private PublicationReceipt ApplyIntent(
        AuthorityStore authority,
        PublicationAnchor anchor,
        LedgerState ledgerBefore,
        PublicationIntent intent,
        ValidatedRequest request)
    {
        ReplaceDurable(request.LedgerPath, intent.LedgerAfterBytes, "publisher ledger");
        RequireFileDigest(
            request.LedgerPath,
            intent.LedgerAfterBytes.LongLength,
            intent.LedgerAfterSha256,
            MaximumLedgerBytes,
            "publisher ledger after commit write");
        _checkpoint?.Invoke(PublisherPublicationCommitStage.LedgerCommitted);

        authority.CommitAnchor(intent.NextAnchor);
        var committedAnchor = authority.ReadAnchor();
        if (!AnchorEquals(committedAnchor, intent.NextAnchor))
        {
            throw new IOException("Enterprise publication anchor did not persist exactly.");
        }
        _checkpoint?.Invoke(PublisherPublicationCommitStage.AnchorCommitted);

        var ledgerAfter = ReadLedgerState(request.LedgerPath, request);
        RequireLedgerMatchesAnchor(committedAnchor, ledgerAfter);
        return PublishOutputAndReceipt(authority, intent, request);
    }

    private PublicationReceipt PublishOutputAndReceipt(
        AuthorityStore authority,
        PublicationIntent intent,
        ValidatedRequest request)
    {
        PublishOutput(intent, request);
        var receipt = authority.CommitReceipt(intent);
        _checkpoint?.Invoke(PublisherPublicationCommitStage.ReceiptCommitted);
        return receipt;
    }

    private PublisherPublicationResult CompleteCleanupWithoutChangingCommittedOutcome(
        AuthorityStore authority,
        PublisherPublicationResult committed)
    {
        // The immutable manifest readback and authenticated receipt already
        // define a committed publication. Pending-marker cleanup is hygiene;
        // a late access/AV failure must not report the committed release as failed.
        if (authority.TryDeleteCommittedPending())
        {
            try
            {
                _checkpoint?.Invoke(PublisherPublicationCommitStage.PendingCleanupCompleted);
            }
            catch
            {
                // Deliberately ignored after the commit result is fixed.
            }
        }
        return committed;
    }

    private static PublisherPublicationResult CreateResult(
        PublicationReceipt receipt,
        bool isExactRetry)
    {
        var manifest = receipt.OutputFiles.Single(value => value.Role == OutputRole.Manifest);
        var manifestPath = Path.Combine(receipt.OutputDirectory, manifest.FileName);
        RequireFileDigest(
            manifestPath,
            manifest.SizeBytes,
            manifest.Sha256,
            MaximumManifestBytes,
            "committed Enterprise release-set manifest");
        return new PublisherPublicationResult(
            receipt.OutputDirectory,
            manifestPath,
            manifest.SizeBytes,
            manifest.Sha256,
            isExactRetry);
    }

    private void PublishOutput(PublicationIntent intent, ValidatedRequest request)
    {
        RequireSafeOutputDirectory(intent.OutputDirectory);
        if (File.Exists(intent.OutputDirectory))
        {
            throw new InvalidDataException(
                "Enterprise publication output directory is unexpectedly a file.");
        }
        Directory.CreateDirectory(intent.OutputDirectory);
        RequireSafeOutputDirectory(intent.OutputDirectory);

        var allowed = intent.OutputFiles
            .Select(value => value.FileName)
            .Concat(intent.OutputFiles.Select(value => TemporaryName(value, intent)))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var path in Directory.EnumerateFileSystemEntries(intent.OutputDirectory))
        {
            if (!allowed.Contains(Path.GetFileName(path)))
            {
                throw new InvalidDataException(
                    "Enterprise publication output contains an unexpected file or directory.");
            }
        }

        foreach (var descriptor in intent.OutputFiles
                     .Where(value => value.Role != OutputRole.Manifest)
                     .OrderBy(value => value.FileName, StringComparer.Ordinal))
        {
            var bytes = descriptor.Role == OutputRole.PublicKey
                ? intent.PublicKeyBytes
                : null;
            var source = descriptor.Role == OutputRole.Artifact
                ? request.Artifacts.Single(value => string.Equals(
                    value.FileName,
                    descriptor.FileName,
                    StringComparison.Ordinal))
                : null;
            PublishOneFile(intent, descriptor, source, bytes);
            _checkpoint?.Invoke(PublisherPublicationCommitStage.OutputFileCommitted);
        }

        var manifest = intent.OutputFiles.Single(value => value.Role == OutputRole.Manifest);
        PublishOneFile(intent, manifest, source: null, intent.ManifestBytes);
        RequireExactOutputSet(intent.OutputDirectory, intent.OutputFiles);
        _checkpoint?.Invoke(PublisherPublicationCommitStage.ManifestCommitted);
    }

    private static void PublishOneFile(
        PublicationIntent intent,
        PublicationOutputFile descriptor,
        PublisherPublicationSource? source,
        byte[]? bytes)
    {
        var destination = Path.Combine(intent.OutputDirectory, descriptor.FileName);
        RequirePathDirectChild(intent.OutputDirectory, destination, "publication output file");
        if (File.Exists(destination))
        {
            RequireFileDigest(
                destination,
                descriptor.SizeBytes,
                descriptor.Sha256,
                MaximumFor(descriptor),
                "existing publication output file");
            return;
        }
        if (Directory.Exists(destination))
        {
            throw new InvalidDataException(
                "Enterprise publication output filename is occupied by a directory.");
        }

        var temporary = Path.Combine(
            intent.OutputDirectory,
            TemporaryName(descriptor, intent));
        RequirePathDirectChild(intent.OutputDirectory, temporary, "publication temporary file");
        if (File.Exists(temporary))
        {
            RequireOrdinarySingleLinkFile(temporary, "publication temporary file");
            File.Delete(temporary);
        }
        else if (Directory.Exists(temporary))
        {
            throw new InvalidDataException(
                "Enterprise publication temporary path is unexpectedly a directory.");
        }

        try
        {
            if (descriptor.Role == OutputRole.Artifact)
            {
                if (source is null)
                {
                    throw new InvalidDataException(
                        "Enterprise publication artifact source is missing during recovery.");
                }
                CopySourceDurable(source, temporary);
            }
            else
            {
                if (bytes is null
                    || bytes.LongLength != descriptor.SizeBytes
                    || !string.Equals(Sha256(bytes), descriptor.Sha256, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "Enterprise publication protected output bytes do not match their descriptor.");
                }
                WriteCreateOnlyDurable(temporary, bytes);
            }
            RequireFileDigest(
                temporary,
                descriptor.SizeBytes,
                descriptor.Sha256,
                MaximumFor(descriptor),
                "staged publication output file");
            if (File.Exists(destination) || Directory.Exists(destination))
            {
                throw new IOException(
                    "Enterprise publication destination appeared during atomic commit.");
            }
            File.Move(temporary, destination);
            RequireFileDigest(
                destination,
                descriptor.SizeBytes,
                descriptor.Sha256,
                MaximumFor(descriptor),
                "committed publication output file");
        }
        finally
        {
            if (File.Exists(temporary))
            {
                RequireOrdinarySingleLinkFile(temporary, "publication temporary file");
                File.Delete(temporary);
            }
        }
    }

    private static void CopySourceDurable(
        PublisherPublicationSource source,
        string destination)
    {
        RequireSource(source);
        using var input = PublisherSafeFile.OpenLockedRead(source.SourcePath);
        if (input.Length != source.SizeBytes
            || !string.Equals(
                PublisherSafeFile.HashAndRewind(input),
                source.Sha256,
                StringComparison.Ordinal))
        {
            throw new IOException(
                "Enterprise publication source changed after its immutable input snapshot.");
        }
        using var output = new FileStream(
            destination,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            1024 * 1024,
            FileOptions.WriteThrough);
        input.CopyTo(output, 1024 * 1024);
        output.Flush(flushToDisk: true);
    }

    private static void RequireExactOutputSet(
        string outputDirectory,
        IReadOnlyList<PublicationOutputFile> expected)
    {
        RequireSafeOutputDirectory(outputDirectory);
        var expectedNames = expected.Select(value => value.FileName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var actual = Directory.EnumerateFileSystemEntries(outputDirectory).ToArray();
        if (actual.Length != expected.Count
            || actual.Any(path => !expectedNames.Contains(Path.GetFileName(path))))
        {
            throw new InvalidDataException(
                "Enterprise publication output is not the exact committed file set.");
        }
        foreach (var descriptor in expected)
        {
            RequireFileDigest(
                Path.Combine(outputDirectory, descriptor.FileName),
                descriptor.SizeBytes,
                descriptor.Sha256,
                MaximumFor(descriptor),
                "committed Enterprise publication output");
        }
    }

    private static long MaximumFor(PublicationOutputFile descriptor) => descriptor.Role switch
    {
        OutputRole.Manifest => MaximumManifestBytes,
        OutputRole.PublicKey => MaximumPublicKeyBytes,
        _ => descriptor.SizeBytes,
    };

    private static string TemporaryName(
        PublicationOutputFile descriptor,
        PublicationIntent intent) =>
        $".{descriptor.FileName}.{intent.NextAnchor.StateCommitId}.publication.tmp";

    private static bool SourceDescriptorsMatch(
        IReadOnlyList<PublicationOutputFile> pending,
        ValidatedRequest request)
    {
        var pendingArtifacts = pending.Where(value => value.Role == OutputRole.Artifact)
            .OrderBy(value => value.FileName, StringComparer.Ordinal)
            .ToArray();
        var currentArtifacts = request.Artifacts
            .OrderBy(value => value.FileName, StringComparer.Ordinal)
            .ToArray();
        if (pendingArtifacts.Length != currentArtifacts.Length)
        {
            return false;
        }
        for (var index = 0; index < pendingArtifacts.Length; index++)
        {
            if (!string.Equals(
                    pendingArtifacts[index].FileName,
                    currentArtifacts[index].FileName,
                    StringComparison.Ordinal)
                || pendingArtifacts[index].SizeBytes != currentArtifacts[index].SizeBytes
                || !string.Equals(
                    pendingArtifacts[index].Sha256,
                    currentArtifacts[index].Sha256,
                    StringComparison.Ordinal))
            {
                return false;
            }
        }
        var publicKey = pending.Single(value => value.Role == OutputRole.PublicKey);
        return publicKey.SizeBytes == request.PublicKeyBytes.LongLength
            && string.Equals(publicKey.Sha256, Sha256(request.PublicKeyBytes), StringComparison.Ordinal);
    }

    private static bool IsExactCandidate(
        PublicationReceipt receipt,
        ValidatedRequest request) =>
        string.Equals(
            receipt.CandidateIdentitySha256,
            request.CandidateIdentitySha256,
            StringComparison.Ordinal)
        && string.Equals(
            receipt.OutputDirectory,
            request.OutputDirectory,
            StringComparison.OrdinalIgnoreCase);

    private static void RequireForward(PublisherLedger? previous, PublisherLedger candidate)
    {
        if (previous is null)
        {
            return;
        }
        if (candidate.HighestGeneration < previous.HighestGeneration
            || candidate.HighestSequence <= previous.HighestSequence
            || candidate.MinAcceptedSequence < previous.MinAcceptedSequence)
        {
            throw new InvalidDataException(
                "Publisher ledger rejected generation/sequence reuse or rollback.");
        }
    }

    private sealed record ValidatedRequest(
        string LedgerPath,
        string OutputDirectory,
        PublisherLedger LedgerAfter,
        byte[] LedgerAfterBytes,
        string LedgerAfterSha256,
        string ConfigSha256,
        string InputSetSha256,
        string CandidateIdentitySha256,
        byte[] ManifestBytes,
        byte[] PublicKeyBytes,
        IReadOnlyList<PublisherPublicationSource> Artifacts,
        IReadOnlyList<PublicationOutputFile> OutputFiles)
    {
        public static ValidatedRequest CreateProbe(PublisherPublicationProbe probe)
        {
            var ledgerPath = NormalizeFilePath(probe.LedgerPath, "publisher ledger");
            var outputDirectory = NormalizeDirectoryPath(
                probe.OutputDirectory,
                "publication output directory");
            if (IsSameOrDescendant(ledgerPath, outputDirectory)
                || !EnterpriseReleaseValueValidator.IsSha256(probe.ConfigSha256)
                || !EnterpriseReleaseValueValidator.IsSha256(probe.InputSetSha256)
                || probe.PublicKeyBytes.Length is <= 0 or > MaximumPublicKeyBytes)
            {
                throw new InvalidDataException(
                    "Enterprise publication retry probe identity is invalid.");
            }
            _ = ParseStrict<EnterpriseReleasePublicKey>(
                probe.PublicKeyBytes,
                "release public key");
            var artifacts = probe.Artifacts.Select(source =>
            {
                RequireSource(source);
                return source with { SourcePath = Path.GetFullPath(source.SourcePath) };
            }).ToArray();
            if (artifacts.Length != 3
                || artifacts.Select(value => value.FileName)
                    .Distinct(StringComparer.OrdinalIgnoreCase).Count() != artifacts.Length
                || artifacts.Any(value => value.FileName is ManifestFileName or PublicKeyFileName))
            {
                throw new InvalidDataException(
                    "Enterprise publication retry probe artifact set is invalid.");
            }
            var ledger = new PublisherLedger(
                2,
                probe.Environment,
                probe.Channel,
                probe.Generation,
                probe.Sequence,
                probe.MinAcceptedSequence,
                probe.ReleaseSetId,
                ZeroSha256,
                DateTimeOffset.UnixEpoch);
            ValidateLedger(ledger, probe.Environment, probe.Channel);
            var outputFiles = artifacts.Select(value => new PublicationOutputFile(
                    OutputRole.Artifact,
                    value.FileName,
                    value.SizeBytes,
                    value.Sha256))
                .Append(new PublicationOutputFile(
                    OutputRole.PublicKey,
                    PublicKeyFileName,
                    probe.PublicKeyBytes.LongLength,
                    Sha256(probe.PublicKeyBytes)))
                .OrderBy(value => value.FileName, StringComparer.Ordinal)
                .ToArray();
            var candidateIdentity = ComputeCandidateIdentity(
                ledgerPath,
                outputDirectory,
                ledger,
                probe.ConfigSha256,
                probe.InputSetSha256,
                outputFiles);
            return new ValidatedRequest(
                ledgerPath,
                outputDirectory,
                ledger,
                [],
                ZeroSha256,
                probe.ConfigSha256,
                probe.InputSetSha256,
                candidateIdentity,
                [],
                probe.PublicKeyBytes,
                artifacts,
                outputFiles);
        }

        public static ValidatedRequest Create(PublisherPublicationRequest request)
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException(
                    "Enterprise publication transactions require Windows DPAPI.");
            }
            var ledgerPath = NormalizeFilePath(request.LedgerPath, "publisher ledger");
            var outputDirectory = NormalizeDirectoryPath(
                request.OutputDirectory,
                "publication output directory");
            if (IsSameOrDescendant(ledgerPath, outputDirectory))
            {
                throw new InvalidDataException(
                    "Enterprise publication ledger must be independent from the output directory.");
            }
            if (!EnterpriseReleaseValueValidator.IsSha256(request.ConfigSha256)
                || !EnterpriseReleaseValueValidator.IsSha256(request.InputSetSha256))
            {
                throw new InvalidDataException(
                    "Enterprise publication candidate identity digests are invalid.");
            }
            ValidateLedger(request.LedgerAfter, expectedEnvironment: null, expectedChannel: null);
            if (request.ManifestBytes.Length is <= 0 or > MaximumManifestBytes
                || request.PublicKeyBytes.Length is <= 0 or > MaximumPublicKeyBytes)
            {
                throw new InvalidDataException(
                    "Enterprise publication manifest or public-key size is invalid.");
            }
            var manifest = EnterpriseReleaseSetManifest.Parse(request.ManifestBytes);
            var publicKey = ParseStrict<EnterpriseReleasePublicKey>(
                request.PublicKeyBytes,
                "release public key");
            if (manifest.Signature is null
                || !string.Equals(manifest.Product, EnterpriseReleaseSetContract.Product, StringComparison.Ordinal)
                || !string.Equals(manifest.Environment, request.LedgerAfter.Environment, StringComparison.Ordinal)
                || !string.Equals(manifest.Channel, request.LedgerAfter.Channel, StringComparison.Ordinal)
                || !string.Equals(manifest.ReleaseSetId, request.LedgerAfter.ReleaseSetId, StringComparison.Ordinal)
                || manifest.Generation != request.LedgerAfter.HighestGeneration
                || manifest.Sequence != request.LedgerAfter.HighestSequence
                || manifest.MinAcceptedSequence != request.LedgerAfter.MinAcceptedSequence
                || !string.Equals(manifest.Signature.KeyId, publicKey.KeyId, StringComparison.Ordinal)
                || !string.Equals(
                    request.LedgerAfter.ManifestPayloadSha256,
                    Sha256(EnterpriseReleaseCanonicalJson.ManifestPayload(manifest)),
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Enterprise publication manifest, public key, and ledger are not one exact candidate.");
            }

            if (request.Artifacts is null || request.Artifacts.Count != manifest.Artifacts.Count)
            {
                throw new InvalidDataException(
                    "Enterprise publication artifact source set is incomplete.");
            }
            var artifacts = request.Artifacts.Select(source =>
            {
                RequireSource(source);
                return source with
                {
                    SourcePath = Path.GetFullPath(source.SourcePath),
                };
            }).ToArray();
            if (artifacts.Select(value => value.FileName)
                    .Distinct(StringComparer.OrdinalIgnoreCase).Count() != artifacts.Length
                || artifacts.Any(value => value.FileName is ManifestFileName or PublicKeyFileName))
            {
                throw new InvalidDataException(
                    "Enterprise publication output filenames are duplicated or reserved.");
            }
            foreach (var artifact in manifest.Artifacts)
            {
                var name = Path.GetFileName(artifact.Uri.AbsolutePath);
                var source = artifacts.SingleOrDefault(value => string.Equals(
                    value.FileName,
                    name,
                    StringComparison.Ordinal))
                    ?? throw new InvalidDataException(
                        "Enterprise publication manifest artifact has no exact source.");
                if (source.SizeBytes != artifact.SizeBytes
                    || !string.Equals(source.Sha256, artifact.Sha256, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "Enterprise publication artifact source differs from its signed manifest descriptor.");
                }
            }

            var ledgerAfterBytes = Serialize(request.LedgerAfter);
            var outputFiles = artifacts.Select(value => new PublicationOutputFile(
                    OutputRole.Artifact,
                    value.FileName,
                    value.SizeBytes,
                    value.Sha256))
                .Concat([
                    new PublicationOutputFile(
                        OutputRole.PublicKey,
                        PublicKeyFileName,
                        request.PublicKeyBytes.LongLength,
                        Sha256(request.PublicKeyBytes)),
                    new PublicationOutputFile(
                        OutputRole.Manifest,
                        ManifestFileName,
                        request.ManifestBytes.LongLength,
                        Sha256(request.ManifestBytes)),
                ])
                .OrderBy(value => value.FileName, StringComparer.Ordinal)
                .ToArray();
            var candidateIdentity = ComputeCandidateIdentity(
                ledgerPath,
                outputDirectory,
                request.LedgerAfter,
                request.ConfigSha256,
                request.InputSetSha256,
                outputFiles.Where(value => value.Role != OutputRole.Manifest).ToArray());
            return new ValidatedRequest(
                ledgerPath,
                outputDirectory,
                request.LedgerAfter,
                ledgerAfterBytes,
                Sha256(ledgerAfterBytes),
                request.ConfigSha256,
                request.InputSetSha256,
                candidateIdentity,
                request.ManifestBytes,
                request.PublicKeyBytes,
                artifacts,
                outputFiles);
        }
    }

    private sealed class AuthorityStore
    {
        private readonly ValidatedRequest _request;
        private readonly string _ledgerPathSha256;
        private readonly string _pendingPath;
        private readonly string _receiptPath;
        private readonly string _lockPath;
        private readonly byte[] _entropy;

        public AuthorityStore(ValidatedRequest request, string? authorityRoot)
        {
            _request = request;
            _ledgerPathSha256 = Sha256Utf8(request.LedgerPath.ToUpperInvariant());
            var root = ResolveAuthorityRoot(authorityRoot);
            var ledgerRoot = Path.GetDirectoryName(request.LedgerPath)!;
            if (IsSameOrDescendant(root, ledgerRoot)
                || IsSameOrDescendant(ledgerRoot, root)
                || IsSameOrDescendant(root, request.OutputDirectory)
                || IsSameOrDescendant(request.OutputDirectory, root))
            {
                throw new InvalidDataException(
                    "Enterprise publication anchor authority must be outside the ledger and output trees.");
            }
            var identity = Sha256Utf8(string.Join(
                '|',
                EnterpriseReleaseSetContract.Product,
                request.LedgerAfter.Environment,
                request.LedgerAfter.Channel,
                _ledgerPathSha256,
                "enterprise-release-publication-authority-v2"));
            AnchorPath = Path.Combine(root, $"{identity}.dpapi");
            _pendingPath = AnchorPath + ".pending.v2";
            _receiptPath = AnchorPath + ".publication.v2";
            _lockPath = AnchorPath + ".lock";
            _entropy = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join(
                '|',
                EnterpriseReleaseSetContract.Product,
                request.LedgerAfter.Environment,
                request.LedgerAfter.Channel,
                request.LedgerPath.ToUpperInvariant(),
                "enterprise-release-publication-dpapi-v2")));
        }

        public string AnchorPath { get; }

        public bool PendingExists => RequireOrdinarySingleLinkFileOrMissing(
            _pendingPath,
            "publication pending state");

        public FileStream AcquireLock()
        {
            var parent = EnsureDirectory(
                Path.GetDirectoryName(_lockPath)!,
                "publication authority directory");
            RequirePathDirectChild(parent, _lockPath, "publication authority lock");
            RejectLinkedFileIfPresent(_lockPath, "publication authority lock");
            return new FileStream(
                _lockPath,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None,
                1,
                FileOptions.WriteThrough);
        }

        public void InitializeGenesisIfSafe()
        {
            RejectLinkedFileIfPresent(AnchorPath, "publication anchor");
            RejectLinkedFileIfPresent(_pendingPath, "publication pending state");
            RejectLinkedFileIfPresent(_receiptPath, "publication receipt");
            if (File.Exists(AnchorPath))
            {
                return;
            }
            if (File.Exists(_request.LedgerPath)
                || File.Exists(_pendingPath)
                || File.Exists(_receiptPath)
                || Directory.Exists(_request.OutputDirectory))
            {
                throw new InvalidDataException(
                    "Enterprise publication anchor is missing for existing ledger, pending, receipt, or output state; controlled state review is required.");
            }
            var genesis = new PublicationAnchor(
                CurrentSchemaVersion,
                EnterpriseReleaseSetContract.Product,
                _request.LedgerAfter.Environment,
                _request.LedgerAfter.Channel,
                _ledgerPathSha256,
                0,
                Guid.NewGuid().ToString("N"),
                ZeroSha256,
                null);
            ValidateAnchor(genesis);
            WriteProtected(AnchorPath, genesis, overwrite: false);
        }

        public PublicationAnchor ReadAnchor()
        {
            if (!File.Exists(AnchorPath))
            {
                throw new InvalidDataException(
                    "Enterprise publication independent anchor is missing.");
            }
            var value = ReadProtected<PublicationAnchor>(AnchorPath, "publication anchor");
            ValidateAnchor(value);
            return value;
        }

        public PublicationIntent CreateIntent(
            PublicationAnchor previous,
            LedgerState ledgerBefore,
            ValidatedRequest request)
        {
            ValidateAnchor(previous);
            var next = new PublicationAnchor(
                CurrentSchemaVersion,
                EnterpriseReleaseSetContract.Product,
                request.LedgerAfter.Environment,
                request.LedgerAfter.Channel,
                _ledgerPathSha256,
                checked(previous.StateRevision + 1),
                Guid.NewGuid().ToString("N"),
                request.LedgerAfterSha256,
                new PublicationHead(
                    CurrentSchemaVersion,
                    request.LedgerAfter.HighestGeneration,
                    request.LedgerAfter.HighestSequence,
                    request.LedgerAfter.MinAcceptedSequence,
                    request.LedgerAfter.ReleaseSetId,
                    request.LedgerAfter.ManifestPayloadSha256,
                    request.CandidateIdentitySha256));
            ValidateTransition(previous, next);
            var intent = new PublicationIntent(
                CurrentSchemaVersion,
                EnterpriseReleaseSetContract.Product,
                request.LedgerAfter.Environment,
                request.LedgerAfter.Channel,
                _ledgerPathSha256,
                request.CandidateIdentitySha256,
                request.ConfigSha256,
                request.InputSetSha256,
                request.OutputDirectory,
                ledgerBefore.Sha256,
                request.LedgerAfterSha256,
                request.LedgerAfterBytes.ToArray(),
                previous,
                next,
                request.OutputFiles,
                request.ManifestBytes.ToArray(),
                request.PublicKeyBytes.ToArray());
            ValidateIntent(intent);
            return intent;
        }

        public void WritePending(PublicationIntent intent)
        {
            ValidateIntent(intent);
            WriteProtected(_pendingPath, intent, overwrite: false);
            var persisted = ReadPending();
            try
            {
                if (!Serialize(persisted).AsSpan().SequenceEqual(Serialize(intent)))
                {
                    throw new IOException(
                        "Enterprise publication pending intent did not persist exactly.");
                }
            }
            finally
            {
                ZeroIntent(persisted);
            }
        }

        public PublicationIntent ReadPending()
        {
            if (!File.Exists(_pendingPath))
            {
                throw new InvalidDataException(
                    "Enterprise publication pending state disappeared during recovery.");
            }
            var intent = ReadProtected<PublicationIntent>(
                _pendingPath,
                "publication pending state");
            ValidateIntent(intent);
            return intent;
        }

        public void CommitAnchor(PublicationAnchor anchor)
        {
            ValidateAnchor(anchor);
            WriteProtected(AnchorPath, anchor, overwrite: true);
        }

        public PublicationReceipt CommitReceipt(PublicationIntent intent)
        {
            ValidateIntent(intent);
            RequireExactOutputSet(intent.OutputDirectory, intent.OutputFiles);
            var committedLedger = ParseStrict<PublisherLedger>(
                intent.LedgerAfterBytes,
                "pending publisher ledger");
            var receipt = new PublicationReceipt(
                CurrentSchemaVersion,
                EnterpriseReleaseSetContract.Product,
                _request.LedgerAfter.Environment,
                _request.LedgerAfter.Channel,
                _ledgerPathSha256,
                intent.CandidateIdentitySha256,
                intent.ConfigSha256,
                intent.InputSetSha256,
                intent.OutputDirectory,
                intent.LedgerBeforeSha256,
                intent.LedgerAfterSha256,
                intent.NextAnchor.StateRevision,
                intent.NextAnchor.StateCommitId,
                intent.OutputFiles);
            ValidateReceipt(receipt, intent.NextAnchor, committedLedger);

            if (File.Exists(_receiptPath))
            {
                var observed = ReadProtected<PublicationReceipt>(
                    _receiptPath,
                    "publication receipt");
                if (observed.StateRevision == receipt.StateRevision
                    && string.Equals(
                        observed.StateCommitId,
                        receipt.StateCommitId,
                        StringComparison.Ordinal))
                {
                    RequireReceiptMatchesIntent(observed, intent);
                    return observed;
                }
                if (observed.StateRevision == intent.PreviousAnchor.StateRevision
                    && string.Equals(
                        observed.StateCommitId,
                        intent.PreviousAnchor.StateCommitId,
                        StringComparison.Ordinal))
                {
                    ValidateReceipt(observed, intent.PreviousAnchor, ledger: null);
                    RequireCommittedOutputMatchesHead(
                        observed,
                        intent.PreviousAnchor.Head
                            ?? throw new InvalidDataException(
                                "Enterprise publication previous receipt cannot accompany genesis."));
                }
                else
                {
                    throw new InvalidDataException(
                        "Enterprise publication receipt is unrelated to the pending transaction.");
                }
            }

            WriteProtected(_receiptPath, receipt, overwrite: true);
            var persisted = ReadProtected<PublicationReceipt>(
                _receiptPath,
                "publication receipt");
            ValidateReceipt(persisted, intent.NextAnchor, committedLedger);
            RequireExactOutputSet(persisted.OutputDirectory, persisted.OutputFiles);
            if (!Serialize(persisted).AsSpan().SequenceEqual(Serialize(receipt)))
            {
                throw new IOException(
                    "Enterprise publication receipt did not persist exactly.");
            }
            return persisted;
        }

        public PublicationReceipt? TryReadReceipt(
            PublicationAnchor anchor,
            PublisherLedger? ledger)
        {
            ValidateAnchor(anchor);
            RejectLinkedFileIfPresent(_receiptPath, "publication receipt");
            if (!File.Exists(_receiptPath))
            {
                return null;
            }
            if (ledger is null || anchor.Head is null)
            {
                throw new InvalidDataException(
                    "Enterprise publication receipt cannot accompany genesis state.");
            }
            var receipt = ReadProtected<PublicationReceipt>(
                _receiptPath,
                "publication receipt");
            ValidateReceipt(receipt, anchor, ledger);
            RequireCommittedOutputMatchesHead(receipt, anchor.Head);
            return receipt;
        }

        public PublicationReceipt? TryReadReceiptForPending(
            PublicationIntent intent,
            PublisherLedger ledgerAfter)
        {
            ValidateIntent(intent);
            RejectLinkedFileIfPresent(_receiptPath, "publication receipt");
            if (!File.Exists(_receiptPath))
            {
                return null;
            }

            var receipt = ReadProtected<PublicationReceipt>(
                _receiptPath,
                "publication receipt");
            if (receipt.StateRevision == intent.NextAnchor.StateRevision
                && string.Equals(
                    receipt.StateCommitId,
                    intent.NextAnchor.StateCommitId,
                    StringComparison.Ordinal))
            {
                ValidateReceipt(receipt, intent.NextAnchor, ledgerAfter);
                RequireCommittedOutputMatchesHead(
                    receipt,
                    intent.NextAnchor.Head
                        ?? throw new InvalidDataException(
                            "Enterprise publication next anchor has no head."));
                return receipt;
            }

            if (intent.PreviousAnchor.Head is not null
                && receipt.StateRevision == intent.PreviousAnchor.StateRevision
                && string.Equals(
                    receipt.StateCommitId,
                    intent.PreviousAnchor.StateCommitId,
                    StringComparison.Ordinal))
            {
                ValidateReceipt(receipt, intent.PreviousAnchor, ledger: null);
                RequireCommittedOutputMatchesHead(receipt, intent.PreviousAnchor.Head);
                return null;
            }

            throw new InvalidDataException(
                "Enterprise publication receipt is unrelated to the authenticated pending transaction.");
        }

        public void RequireReceiptMatchesIntent(
            PublicationReceipt receipt,
            PublicationIntent intent)
        {
            var committedLedger = ParseStrict<PublisherLedger>(
                intent.LedgerAfterBytes,
                "pending publisher ledger");
            ValidateReceipt(receipt, intent.NextAnchor, committedLedger);
            var expected = new PublicationReceipt(
                CurrentSchemaVersion,
                EnterpriseReleaseSetContract.Product,
                _request.LedgerAfter.Environment,
                _request.LedgerAfter.Channel,
                _ledgerPathSha256,
                intent.CandidateIdentitySha256,
                intent.ConfigSha256,
                intent.InputSetSha256,
                intent.OutputDirectory,
                intent.LedgerBeforeSha256,
                intent.LedgerAfterSha256,
                intent.NextAnchor.StateRevision,
                intent.NextAnchor.StateCommitId,
                intent.OutputFiles);
            if (!Serialize(receipt).AsSpan().SequenceEqual(Serialize(expected)))
            {
                throw new InvalidDataException(
                    "Enterprise publication receipt conflicts with the authenticated pending transaction.");
            }
            RequireExactOutputSet(receipt.OutputDirectory, receipt.OutputFiles);
        }

        public bool TryDeleteCommittedPending()
        {
            try
            {
                if (!File.Exists(_pendingPath))
                {
                    return true;
                }
                RequireOrdinarySingleLinkFile(_pendingPath, "publication pending state");
                File.Delete(_pendingPath);
                return !File.Exists(_pendingPath) && !Directory.Exists(_pendingPath);
            }
            catch
            {
                return false;
            }
        }

        public void ValidateIntent(PublicationIntent intent)
        {
            if (intent.SchemaVersion != CurrentSchemaVersion
                || !string.Equals(intent.Product, EnterpriseReleaseSetContract.Product, StringComparison.Ordinal)
                || !string.Equals(intent.Environment, _request.LedgerAfter.Environment, StringComparison.Ordinal)
                || !string.Equals(intent.Channel, _request.LedgerAfter.Channel, StringComparison.Ordinal)
                || !string.Equals(intent.LedgerPathSha256, _ledgerPathSha256, StringComparison.Ordinal)
                || !EnterpriseReleaseValueValidator.IsSha256(intent.CandidateIdentitySha256)
                || !EnterpriseReleaseValueValidator.IsSha256(intent.ConfigSha256)
                || !EnterpriseReleaseValueValidator.IsSha256(intent.InputSetSha256)
                || !EnterpriseReleaseValueValidator.IsSha256(intent.LedgerBeforeSha256)
                || !EnterpriseReleaseValueValidator.IsSha256(intent.LedgerAfterSha256)
                || intent.LedgerAfterBytes.Length is <= 0 or > MaximumLedgerBytes
                || intent.ManifestBytes.Length is <= 0 or > MaximumManifestBytes
                || intent.PublicKeyBytes.Length is <= 0 or > MaximumPublicKeyBytes)
            {
                throw new InvalidDataException(
                    "Enterprise publication pending transaction identity is invalid.");
            }
            var normalizedOutput = NormalizeDirectoryPath(
                intent.OutputDirectory,
                "publication output directory");
            if (!string.Equals(normalizedOutput, intent.OutputDirectory, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(Sha256(intent.LedgerAfterBytes), intent.LedgerAfterSha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Enterprise publication pending transaction paths or ledger digest are invalid.");
            }
            ValidateTransition(intent.PreviousAnchor, intent.NextAnchor);
            if (!string.Equals(
                    intent.PreviousAnchor.LedgerSha256,
                    intent.LedgerBeforeSha256,
                    StringComparison.Ordinal)
                || !string.Equals(
                    intent.NextAnchor.LedgerSha256,
                    intent.LedgerAfterSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Enterprise publication pending ledger before/after digests do not bind its anchors.");
            }
            var ledgerAfter = ParseStrict<PublisherLedger>(
                intent.LedgerAfterBytes,
                "pending publisher ledger");
            ValidateLedger(
                ledgerAfter,
                _request.LedgerAfter.Environment,
                _request.LedgerAfter.Channel);
            if (!Serialize(ledgerAfter).AsSpan().SequenceEqual(intent.LedgerAfterBytes)
                || intent.NextAnchor.Head is null
                || !HeadMatchesLedger(intent.NextAnchor.Head, ledgerAfter)
                || !string.Equals(
                    intent.NextAnchor.Head.CandidateIdentitySha256,
                    intent.CandidateIdentitySha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Enterprise publication pending ledger is non-canonical or does not match its next anchor.");
            }
            ValidateOutputFiles(intent.OutputFiles, intent.ManifestBytes, intent.PublicKeyBytes);
            var manifest = EnterpriseReleaseSetManifest.Parse(intent.ManifestBytes);
            if (manifest.Generation != ledgerAfter.HighestGeneration
                || manifest.Sequence != ledgerAfter.HighestSequence
                || manifest.MinAcceptedSequence != ledgerAfter.MinAcceptedSequence
                || !string.Equals(manifest.ReleaseSetId, ledgerAfter.ReleaseSetId, StringComparison.Ordinal)
                || !string.Equals(
                    Sha256(EnterpriseReleaseCanonicalJson.ManifestPayload(manifest)),
                    ledgerAfter.ManifestPayloadSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Enterprise publication protected manifest does not match the pending ledger.");
            }
        }

        private void ValidateReceipt(
            PublicationReceipt receipt,
            PublicationAnchor anchor,
            PublisherLedger? ledger)
        {
            ValidateAnchor(anchor);
            if (receipt.SchemaVersion != CurrentSchemaVersion
                || !string.Equals(receipt.Product, EnterpriseReleaseSetContract.Product, StringComparison.Ordinal)
                || !string.Equals(receipt.Environment, _request.LedgerAfter.Environment, StringComparison.Ordinal)
                || !string.Equals(receipt.Channel, _request.LedgerAfter.Channel, StringComparison.Ordinal)
                || !string.Equals(receipt.LedgerPathSha256, _ledgerPathSha256, StringComparison.Ordinal)
                || !EnterpriseReleaseValueValidator.IsSha256(receipt.CandidateIdentitySha256)
                || !EnterpriseReleaseValueValidator.IsSha256(receipt.ConfigSha256)
                || !EnterpriseReleaseValueValidator.IsSha256(receipt.InputSetSha256)
                || !EnterpriseReleaseValueValidator.IsSha256(receipt.LedgerBeforeSha256)
                || !EnterpriseReleaseValueValidator.IsSha256(receipt.LedgerAfterSha256)
                || receipt.StateRevision != anchor.StateRevision
                || !string.Equals(receipt.StateCommitId, anchor.StateCommitId, StringComparison.Ordinal)
                || !string.Equals(receipt.LedgerAfterSha256, anchor.LedgerSha256, StringComparison.Ordinal)
                || anchor.Head is null
                || !string.Equals(
                    receipt.CandidateIdentitySha256,
                    anchor.Head.CandidateIdentitySha256,
                    StringComparison.Ordinal)
                || !string.Equals(
                    NormalizeDirectoryPath(receipt.OutputDirectory, "publication receipt output"),
                    receipt.OutputDirectory,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "Enterprise publication receipt is invalid or does not match its independent anchor.");
            }
            if (ledger is not null && !HeadMatchesLedger(anchor.Head, ledger))
            {
                throw new InvalidDataException(
                    "Enterprise publication receipt anchor does not match the current ledger.");
            }
            ValidateOutputFiles(receipt.OutputFiles, manifestBytes: null, publicKeyBytes: null);
        }

        private void ValidateAnchor(PublicationAnchor anchor)
        {
            if (anchor.SchemaVersion != CurrentSchemaVersion
                || !string.Equals(anchor.Product, EnterpriseReleaseSetContract.Product, StringComparison.Ordinal)
                || !string.Equals(anchor.Environment, _request.LedgerAfter.Environment, StringComparison.Ordinal)
                || !string.Equals(anchor.Channel, _request.LedgerAfter.Channel, StringComparison.Ordinal)
                || !string.Equals(anchor.LedgerPathSha256, _ledgerPathSha256, StringComparison.Ordinal)
                || anchor.StateRevision < 0
                || anchor.StateRevision > 9_007_199_254_740_991L
                || anchor.StateCommitId.Length != 32
                || anchor.StateCommitId.Any(character =>
                    character is not (>= '0' and <= '9')
                        and not (>= 'a' and <= 'f'))
                || !EnterpriseReleaseValueValidator.IsSha256(anchor.LedgerSha256)
                || (anchor.StateRevision == 0) != (anchor.Head is null)
                || anchor.StateRevision == 0
                    && !string.Equals(anchor.LedgerSha256, ZeroSha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Enterprise publication independent anchor is invalid or downgraded.");
            }
            anchor.Head?.Validate();
        }

        private void ValidateTransition(PublicationAnchor previous, PublicationAnchor next)
        {
            ValidateAnchor(previous);
            ValidateAnchor(next);
            if (next.StateRevision != checked(previous.StateRevision + 1)
                || next.Head is null
                || previous.Head is not null
                    && (next.Head.Sequence <= previous.Head.Sequence
                        || next.Head.Generation < previous.Head.Generation
                        || next.Head.MinAcceptedSequence < previous.Head.MinAcceptedSequence))
            {
                throw new InvalidDataException(
                    "Enterprise publication pending transaction does not advance its authenticated high-water anchor.");
            }
        }

        private T ReadProtected<T>(string path, string label)
        {
            var protectedBytes = ReadBounded(path, MaximumProtectedBytes, label);
            byte[]? plaintext = null;
            try
            {
                try
                {
                    plaintext = ProtectedData.Unprotect(
                        protectedBytes,
                        _entropy,
                        DataProtectionScope.CurrentUser);
                }
                catch (CryptographicException exception)
                {
                    throw new InvalidDataException(
                        $"Enterprise {label} is not authenticated for this publisher identity.",
                        exception);
                }
                if (plaintext.Length is <= 0 or > MaximumProtectedBytes)
                {
                    throw new InvalidDataException(
                        $"Enterprise {label} plaintext size is invalid.");
                }
                return ParseStrict<T>(plaintext, label);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
                if (plaintext is not null)
                {
                    CryptographicOperations.ZeroMemory(plaintext);
                }
            }
        }

        private void WriteProtected<T>(string path, T value, bool overwrite)
        {
            var plaintext = Serialize(value);
            byte[]? protectedBytes = null;
            var parent = EnsureDirectory(
                Path.GetDirectoryName(path)!,
                "publication authority directory");
            RequirePathDirectChild(parent, path, "publication authority state");
            RejectLinkedFileIfPresent(path, "publication authority state");
            var temporary = Path.Combine(
                parent,
                $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
            try
            {
                protectedBytes = ProtectedData.Protect(
                    plaintext,
                    _entropy,
                    DataProtectionScope.CurrentUser);
                if (protectedBytes.Length is <= 0 or > MaximumProtectedBytes)
                {
                    throw new InvalidDataException(
                        "Protected Enterprise publication authority state size is invalid.");
                }
                WriteCreateOnlyDurable(temporary, protectedBytes);
                File.Move(temporary, path, overwrite);
                RequireOrdinarySingleLinkFile(path, "publication authority state");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
                if (protectedBytes is not null)
                {
                    CryptographicOperations.ZeroMemory(protectedBytes);
                }
                if (File.Exists(temporary))
                {
                    RequireOrdinarySingleLinkFile(temporary, "publication authority temporary file");
                    File.Delete(temporary);
                }
            }
        }

        private static void RequireCommittedOutputMatchesHead(
            PublicationReceipt receipt,
            PublicationHead head)
        {
            RequireExactOutputSet(receipt.OutputDirectory, receipt.OutputFiles);
            var manifest = receipt.OutputFiles.Single(value => value.Role == OutputRole.Manifest);
            var manifestBytes = ReadBounded(
                Path.Combine(receipt.OutputDirectory, manifest.FileName),
                MaximumManifestBytes,
                "committed release-set manifest");
            var parsed = EnterpriseReleaseSetManifest.Parse(manifestBytes);
            if (parsed.Generation != head.Generation
                || parsed.Sequence != head.Sequence
                || parsed.MinAcceptedSequence != head.MinAcceptedSequence
                || !string.Equals(parsed.ReleaseSetId, head.ReleaseSetId, StringComparison.Ordinal)
                || !string.Equals(
                    Sha256(EnterpriseReleaseCanonicalJson.ManifestPayload(parsed)),
                    head.ManifestPayloadSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Enterprise committed manifest does not match its authenticated ledger receipt.");
            }
        }
    }

    private enum OutputRole
    {
        Artifact,
        PublicKey,
        Manifest,
    }

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record PublicationOutputFile(
        OutputRole Role,
        string FileName,
        long SizeBytes,
        string Sha256);

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record PublicationHead(
        int SchemaVersion,
        long Generation,
        long Sequence,
        long MinAcceptedSequence,
        string ReleaseSetId,
        string ManifestPayloadSha256,
        string CandidateIdentitySha256)
    {
        public void Validate()
        {
            if (SchemaVersion != CurrentSchemaVersion
                || Generation <= 0
                || Sequence <= 0
                || MinAcceptedSequence < 0
                || MinAcceptedSequence > Sequence
                || !EnterpriseReleaseValueValidator.IsSha256(ManifestPayloadSha256)
                || !EnterpriseReleaseValueValidator.IsSha256(CandidateIdentitySha256))
            {
                throw new InvalidDataException(
                    "Enterprise publication anchor head is invalid.");
            }
            EnterpriseReleaseValueValidator.ValidateReleaseId(ReleaseSetId);
        }
    }

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record PublicationAnchor(
        int SchemaVersion,
        string Product,
        string Environment,
        string Channel,
        string LedgerPathSha256,
        long StateRevision,
        string StateCommitId,
        string LedgerSha256,
        PublicationHead? Head);

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record PublicationIntent(
        int SchemaVersion,
        string Product,
        string Environment,
        string Channel,
        string LedgerPathSha256,
        string CandidateIdentitySha256,
        string ConfigSha256,
        string InputSetSha256,
        string OutputDirectory,
        string LedgerBeforeSha256,
        string LedgerAfterSha256,
        byte[] LedgerAfterBytes,
        PublicationAnchor PreviousAnchor,
        PublicationAnchor NextAnchor,
        IReadOnlyList<PublicationOutputFile> OutputFiles,
        byte[] ManifestBytes,
        byte[] PublicKeyBytes);

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record PublicationReceipt(
        int SchemaVersion,
        string Product,
        string Environment,
        string Channel,
        string LedgerPathSha256,
        string CandidateIdentitySha256,
        string ConfigSha256,
        string InputSetSha256,
        string OutputDirectory,
        string LedgerBeforeSha256,
        string LedgerAfterSha256,
        long StateRevision,
        string StateCommitId,
        IReadOnlyList<PublicationOutputFile> OutputFiles);

    private sealed record LedgerState(
        PublisherLedger? Ledger,
        byte[] Bytes,
        string Sha256);

    private static LedgerState ReadLedgerState(
        string ledgerPath,
        ValidatedRequest request)
    {
        RejectLinkedFileIfPresent(ledgerPath, "publisher ledger");
        if (!File.Exists(ledgerPath))
        {
            return new LedgerState(null, [], ZeroSha256);
        }
        var bytes = ReadBounded(ledgerPath, MaximumLedgerBytes, "publisher ledger");
        var ledger = ParseStrict<PublisherLedger>(bytes, "publisher ledger");
        ValidateLedger(
            ledger,
            request.LedgerAfter.Environment,
            request.LedgerAfter.Channel);
        if (!Serialize(ledger).AsSpan().SequenceEqual(bytes))
        {
            throw new InvalidDataException(
                "Enterprise publisher ledger is not canonical.");
        }
        return new LedgerState(ledger, bytes, Sha256(bytes));
    }

    private static void RequireLedgerMatchesAnchor(
        PublicationAnchor anchor,
        LedgerState ledger)
    {
        if (!string.Equals(anchor.LedgerSha256, ledger.Sha256, StringComparison.Ordinal)
            || (anchor.Head is null) != (ledger.Ledger is null)
            || anchor.Head is not null
                && !HeadMatchesLedger(anchor.Head, ledger.Ledger!))
        {
            throw new InvalidDataException(
                "Enterprise publisher ledger is missing, replayed, or differs from its independent high-water anchor.");
        }
    }

    private static bool HeadMatchesLedger(
        PublicationHead head,
        PublisherLedger ledger) =>
        head.Generation == ledger.HighestGeneration
        && head.Sequence == ledger.HighestSequence
        && head.MinAcceptedSequence == ledger.MinAcceptedSequence
        && string.Equals(head.ReleaseSetId, ledger.ReleaseSetId, StringComparison.Ordinal)
        && string.Equals(
            head.ManifestPayloadSha256,
            ledger.ManifestPayloadSha256,
            StringComparison.Ordinal);

    private static void ValidateLedger(
        PublisherLedger ledger,
        string? expectedEnvironment,
        string? expectedChannel)
    {
        if (ledger.SchemaVersion != 2
            || expectedEnvironment is not null
                && !string.Equals(ledger.Environment, expectedEnvironment, StringComparison.Ordinal)
            || expectedChannel is not null
                && !string.Equals(ledger.Channel, expectedChannel, StringComparison.Ordinal)
            || ledger.Environment is not EnterpriseReleaseSetContract.ProductionEnvironment
                and not EnterpriseReleaseSetContract.DevelopmentE2EEnvironment
            || !EnterpriseReleaseSetContract.IsSupportedChannel(ledger.Channel)
            || ledger.HighestGeneration <= 0
            || ledger.HighestSequence <= 0
            || ledger.MinAcceptedSequence < 0
            || ledger.MinAcceptedSequence > ledger.HighestSequence
            || !EnterpriseReleaseValueValidator.IsSha256(ledger.ManifestPayloadSha256)
            || ledger.PublishedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException(
                "Enterprise publisher ledger is invalid, downgraded, or belongs to another feed.");
        }
        EnterpriseReleaseValueValidator.ValidateReleaseId(ledger.ReleaseSetId);
    }

    private static void ValidateOutputFiles(
        IReadOnlyList<PublicationOutputFile>? files,
        byte[]? manifestBytes,
        byte[]? publicKeyBytes)
    {
        if (files is null
            || files.Count != 5
            || files.Count(value => value.Role == OutputRole.Artifact) != 3
            || files.Count(value => value.Role == OutputRole.PublicKey) != 1
            || files.Count(value => value.Role == OutputRole.Manifest) != 1
            || files.Select(value => value.FileName)
                .Distinct(StringComparer.OrdinalIgnoreCase).Count() != files.Count
            || !files.SequenceEqual(
                files.OrderBy(value => value.FileName, StringComparer.Ordinal)))
        {
            throw new InvalidDataException(
                "Enterprise publication output descriptor set is invalid.");
        }
        foreach (var file in files)
        {
            PublisherPathGuard.RequireSafeArtifactFileName(
                file.FileName,
                "Publication output filename");
            if (file.SizeBytes <= 0
                || !EnterpriseReleaseValueValidator.IsSha256(file.Sha256))
            {
                throw new InvalidDataException(
                    "Enterprise publication output descriptor is invalid.");
            }
        }
        var manifest = files.Single(value => value.Role == OutputRole.Manifest);
        var publicKey = files.Single(value => value.Role == OutputRole.PublicKey);
        if (!string.Equals(manifest.FileName, ManifestFileName, StringComparison.Ordinal)
            || manifest.SizeBytes > MaximumManifestBytes
            || !string.Equals(publicKey.FileName, PublicKeyFileName, StringComparison.Ordinal)
            || publicKey.SizeBytes > MaximumPublicKeyBytes
            || manifestBytes is not null
                && (manifestBytes.LongLength != manifest.SizeBytes
                    || !string.Equals(Sha256(manifestBytes), manifest.Sha256, StringComparison.Ordinal))
            || publicKeyBytes is not null
                && (publicKeyBytes.LongLength != publicKey.SizeBytes
                    || !string.Equals(Sha256(publicKeyBytes), publicKey.Sha256, StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "Enterprise publication protected manifest/public-key descriptors are invalid.");
        }
    }

    private static string ComputeCandidateIdentity(
        string ledgerPath,
        string outputDirectory,
        PublisherLedger ledger,
        string configSha256,
        string inputSetSha256,
        IReadOnlyList<PublicationOutputFile> nonManifestFiles)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        AppendIdentity(hash, "ensou-enterprise-publication-candidate-v2");
        AppendIdentity(hash, ledgerPath.ToUpperInvariant());
        AppendIdentity(hash, outputDirectory.ToUpperInvariant());
        AppendIdentity(hash, ledger.Environment);
        AppendIdentity(hash, ledger.Channel);
        AppendIdentity(hash, ledger.ReleaseSetId);
        AppendInt64(hash, ledger.HighestGeneration);
        AppendInt64(hash, ledger.HighestSequence);
        AppendInt64(hash, ledger.MinAcceptedSequence);
        AppendIdentity(hash, configSha256);
        AppendIdentity(hash, inputSetSha256);
        foreach (var file in nonManifestFiles.OrderBy(value => value.FileName, StringComparer.Ordinal))
        {
            AppendIdentity(hash, file.Role.ToString());
            AppendIdentity(hash, file.FileName);
            AppendInt64(hash, file.SizeBytes);
            AppendIdentity(hash, file.Sha256);
        }
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static void AppendIdentity(IncrementalHash hash, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[sizeof(int)];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(length, bytes.Length);
        hash.AppendData(length);
        hash.AppendData(bytes);
    }

    private static void AppendInt64(IncrementalHash hash, long value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(long)];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(bytes, value);
        hash.AppendData(bytes);
    }

    private static FileStream AcquireLedgerLock(string ledgerPath)
    {
        var parent = EnsureDirectory(
            Path.GetDirectoryName(ledgerPath)!,
            "publisher ledger directory");
        var lockPath = ledgerPath + ".lock";
        RequirePathDirectChild(parent, lockPath, "publisher ledger lock");
        RejectLinkedFileIfPresent(lockPath, "publisher ledger lock");
        return new FileStream(
            lockPath,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None,
            1,
            FileOptions.WriteThrough);
    }

    private static void ReplaceDurable(
        string destination,
        ReadOnlySpan<byte> bytes,
        string label)
    {
        var parent = EnsureDirectory(
            Path.GetDirectoryName(destination)!,
            $"{label} directory");
        RequirePathDirectChild(parent, destination, label);
        RejectLinkedFileIfPresent(destination, label);
        var temporary = Path.Combine(
            parent,
            $".{Path.GetFileName(destination)}.{Guid.NewGuid():N}.tmp");
        try
        {
            WriteCreateOnlyDurable(temporary, bytes);
            File.Move(temporary, destination, overwrite: true);
            RequireOrdinarySingleLinkFile(destination, label);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                RequireOrdinarySingleLinkFile(temporary, $"{label} temporary file");
                File.Delete(temporary);
            }
        }
    }

    private static void WriteCreateOnlyDurable(string path, ReadOnlySpan<byte> bytes)
    {
        using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            64 * 1024,
            FileOptions.WriteThrough);
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);
    }

    private static byte[] ReadBounded(string path, int maximumBytes, string label)
    {
        RequireOrdinarySingleLinkFile(path, label);
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.SequentialScan);
        if (stream.Length is <= 0 || stream.Length > maximumBytes || stream.Length > int.MaxValue)
        {
            throw new InvalidDataException($"Enterprise {label} size is invalid.");
        }
        var bytes = new byte[(int)stream.Length];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1 || stream.Length != bytes.LongLength)
        {
            throw new IOException($"Enterprise {label} changed while it was read.");
        }
        return bytes;
    }

    private static void RequireFileDigest(
        string path,
        long expectedSize,
        string expectedSha256,
        long maximumBytes,
        string label)
    {
        RequireOrdinarySingleLinkFile(path, label);
        using var stream = PublisherSafeFile.OpenLockedRead(path);
        if (stream.Length <= 0
            || stream.Length > maximumBytes
            || stream.Length != expectedSize
            || !string.Equals(
                PublisherSafeFile.HashAndRewind(stream),
                expectedSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Enterprise {label} size or digest is invalid.");
        }
    }

    private static void RequireSource(PublisherPublicationSource source)
    {
        ArgumentNullException.ThrowIfNull(source);
        PublisherPathGuard.RequireSafeArtifactFileName(
            source.FileName,
            "Publication artifact filename");
        if (!Path.IsPathFullyQualified(source.SourcePath)
            || source.SizeBytes <= 0
            || !EnterpriseReleaseValueValidator.IsSha256(source.Sha256))
        {
            throw new InvalidDataException(
                "Enterprise publication artifact source descriptor is invalid.");
        }
        PublisherPathGuard.RequireSafeExistingFile(source.SourcePath);
        RequireOrdinarySingleLinkFile(source.SourcePath, "publication artifact source");
        RequireFileDigest(
            source.SourcePath,
            source.SizeBytes,
            source.Sha256,
            source.SizeBytes,
            "publication artifact source");
    }

    private static string NormalizeFilePath(string path, string label)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException($"Enterprise {label} path must be absolute.");
        }
        var full = Path.GetFullPath(path);
        PublisherPathGuard.RequireSafeArtifactFileName(Path.GetFileName(full), label);
        RejectExistingLinkAncestors(Path.GetDirectoryName(full)!, label);
        RejectLinkedFileIfPresent(full, label);
        return full;
    }

    private static string NormalizeDirectoryPath(string path, string label)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException($"Enterprise {label} must be absolute.");
        }
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        RejectExistingLinkAncestors(full, label);
        return full;
    }

    private static string EnsureDirectory(string path, string label)
    {
        var full = NormalizeDirectoryPath(path, label);
        Directory.CreateDirectory(full);
        RejectExistingLinkAncestors(full, label);
        return full;
    }

    private static void RequireSafeOutputDirectory(string path)
    {
        _ = NormalizeDirectoryPath(path, "publication output directory");
        if (Directory.Exists(path)
            && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Enterprise publication output directory must not be linked.");
        }
    }

    private static void RequirePathDirectChild(string parent, string path, string label)
    {
        var normalizedParent = Path.TrimEndingDirectorySeparator(Path.GetFullPath(parent));
        var normalizedPath = Path.GetFullPath(path);
        if (!string.Equals(
                Path.GetDirectoryName(normalizedPath),
                normalizedParent,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"Enterprise {label} escaped its parent directory.");
        }
    }

    private static void RejectExistingLinkAncestors(string path, string label)
    {
        for (var current = new DirectoryInfo(path); current is not null; current = current.Parent)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    $"Enterprise {label} may not cross a filesystem link.");
            }
        }
    }

    private static void RejectLinkedFileIfPresent(string path, string label) =>
        _ = RequireOrdinarySingleLinkFileOrMissing(path, label);

    private static void RequireOrdinarySingleLinkFile(string path, string label)
    {
        if (!RequireOrdinarySingleLinkFileOrMissing(path, label))
        {
            throw new FileNotFoundException($"Enterprise {label} is missing.", path);
        }
    }

    private static bool RequireOrdinarySingleLinkFileOrMissing(string path, string label)
    {
        FileAttributes attributes;
        try
        {
            attributes = File.GetAttributes(path);
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            return false;
        }
        if ((attributes & FileAttributes.Directory) != 0)
        {
            throw new InvalidDataException($"Enterprise {label} is unexpectedly a directory.");
        }
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException($"Enterprise {label} must not be a filesystem link.");
        }
        using var handle = File.OpenHandle(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read);
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw new IOException(
                $"Unable to inspect Enterprise {label} link count.",
                Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error()));
        }
        if (information.NumberOfLinks != 1)
        {
            throw new InvalidDataException(
                $"Enterprise {label} must not be shared through a hard link.");
        }
        return true;
    }

    private static string ResolveAuthorityRoot(string? overrideRoot)
    {
        var root = overrideRoot;
        if (root is null)
        {
            var localApplicationData = Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData,
                Environment.SpecialFolderOption.DoNotVerify);
            if (string.IsNullOrWhiteSpace(localApplicationData))
            {
                throw new InvalidDataException(
                    "Enterprise publication could not resolve its CurrentUser authority root.");
            }
            root = Path.Combine(
                localApplicationData,
                "Ensou",
                "Dsh",
                "EnterpriseReleasePublisher",
                "PublicationAnchors");
        }
        return NormalizeDirectoryPath(root, "publication authority root");
    }

    private static bool IsSameOrDescendant(string candidate, string root)
    {
        var normalizedCandidate = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate));
        var normalizedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        return string.Equals(normalizedCandidate, normalizedRoot, StringComparison.OrdinalIgnoreCase)
            || normalizedCandidate.StartsWith(
                normalizedRoot + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase);
    }

    private static bool AnchorEquals(PublicationAnchor left, PublicationAnchor right) =>
        Serialize(left).AsSpan().SequenceEqual(Serialize(right));

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static string Sha256Utf8(string value) =>
        Sha256(Encoding.UTF8.GetBytes(value));

    private static byte[] Serialize<T>(T value) =>
        JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);

    private static T ParseStrict<T>(ReadOnlySpan<byte> bytes, string label)
    {
        try
        {
            using var document = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 64,
            });
            RejectDuplicateMembers(document.RootElement, "$", label);
            return JsonSerializer.Deserialize<T>(bytes, JsonOptions)
                ?? throw new InvalidDataException($"Enterprise {label} is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"Enterprise {label} JSON is invalid.", exception);
        }
    }

    private static void RejectDuplicateMembers(JsonElement element, string path, string label)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidDataException(
                        $"Enterprise {label} contains duplicate member '{property.Name}' at {path}.");
                }
                RejectDuplicateMembers(property.Value, $"{path}.{property.Name}", label);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in element.EnumerateArray())
            {
                RejectDuplicateMembers(item, $"{path}[{index++}]", label);
            }
        }
    }

    private static void ZeroIntent(PublicationIntent intent)
    {
        CryptographicOperations.ZeroMemory(intent.LedgerAfterBytes);
        CryptographicOperations.ZeroMemory(intent.ManifestBytes);
        CryptographicOperations.ZeroMemory(intent.PublicKeyBytes);
    }

    private static void RequireWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Enterprise publication transaction authentication requires Windows DPAPI.");
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

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
}
