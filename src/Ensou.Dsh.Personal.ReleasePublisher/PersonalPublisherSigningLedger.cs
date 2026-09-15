using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.Personal.ReleasePublisher;

internal enum PersonalPublisherSigningLedgerCommitStage
{
    PendingAnchorWritten,
    EntryWritten,
    HeadReplaced,
    AnchorCommitted,
    ManifestPublished,
    PublicationReceiptCommitted,
    PendingDeleted,
}

internal sealed class PersonalPublisherSigningLedger : IDisposable
{
    private readonly string _channelRoot;
    private readonly SigningLedgerAnchorStore _anchorStore;
    private readonly FileStream _anchorLock;
    private readonly FileStream _lock;
    private readonly SigningLedgerSnapshot? _snapshot;
    private readonly SigningLedgerAnchor _anchor;
    private readonly bool _cleanupBlocked;
    private readonly Action<PersonalPublisherSigningLedgerCommitStage>? _checkpoint;

    private PersonalPublisherSigningLedger(
        string channelRoot,
        SigningLedgerAnchorStore anchorStore,
        FileStream anchorLock,
        FileStream ledgerLock,
        SigningLedgerSnapshot? snapshot,
        SigningLedgerAnchor anchor,
        bool cleanupBlocked,
        Action<PersonalPublisherSigningLedgerCommitStage>? checkpoint)
    {
        _channelRoot = channelRoot;
        _anchorStore = anchorStore;
        _anchorLock = anchorLock;
        _lock = ledgerLock;
        _snapshot = snapshot;
        _anchor = anchor;
        _cleanupBlocked = cleanupBlocked;
        _checkpoint = checkpoint;
    }

    public static string InitializeAnchor(
        PersonalReleasePublisherConfig config,
        string? anchorAuthorityRoot = null)
    {
        ArgumentNullException.ThrowIfNull(config);
        RequireWindows();
        var anchorStore = new SigningLedgerAnchorStore(config, anchorAuthorityRoot);
        anchorStore.RequireUpgradeReadyForMutation();
        using var anchorLock = anchorStore.AcquireLock();
        anchorStore.RequireUpgradeReadyForMutation();
        anchorStore.RequireAbsentForInitialization();
        var root = EnsureDirectory(config.SigningLedgerRoot, "signing ledger root");
        var channelRoot = EnsureDirectory(
            Path.Combine(root, config.Channel),
            "signing ledger channel");
        var lockPath = Path.Combine(channelRoot, "signing.lock");
        using var ledgerLock = new FileStream(
            lockPath,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None,
            1,
            FileOptions.WriteThrough);
        var snapshot = ReadSnapshot(channelRoot, config.Channel);
        var unexpected = Directory.EnumerateFileSystemEntries(channelRoot)
            .Where(path => !string.Equals(
                Path.GetFileName(path),
                "signing.lock",
                StringComparison.Ordinal)
                && !string.Equals(
                    Path.GetFileName(path),
                    "head.json",
                    StringComparison.Ordinal)
                && !string.Equals(
                    Path.GetExtension(path),
                    ".json",
                    StringComparison.Ordinal))
            .ToArray();
        if (unexpected.Length != 0)
        {
            throw new InvalidDataException(
                "Personal signing ledger initialization found unexpected channel files.");
        }
        anchorStore.RequireUpgradeReadyForMutation();
        anchorStore.WriteInitial(snapshot?.Head);
        return anchorStore.AnchorPath;
    }

    public static string GetAnchorPath(
        PersonalReleasePublisherConfig config,
        string? anchorAuthorityRoot = null)
    {
        ArgumentNullException.ThrowIfNull(config);
        RequireWindows();
        return new SigningLedgerAnchorStore(config, anchorAuthorityRoot).AnchorPath;
    }

    public static string CheckSigningLedgerUpgradeReady(
        PersonalReleasePublisherConfig config,
        string? anchorAuthorityRoot = null)
    {
        ArgumentNullException.ThrowIfNull(config);
        RequireWindows();
        return new SigningLedgerAnchorStore(config, anchorAuthorityRoot)
            .CheckUpgradeReadyReadOnly();
    }

    public static PersonalPublisherSigningLedger Acquire(
        PersonalReleasePublisherConfig config,
        Action<PersonalPublisherSigningLedgerCommitStage>? checkpoint = null,
        string? anchorAuthorityRoot = null)
    {
        ArgumentNullException.ThrowIfNull(config);
        RequireWindows();
        var anchorStore = new SigningLedgerAnchorStore(config, anchorAuthorityRoot);
        anchorStore.RequireUpgradeReadyForMutation();
        var anchorLock = anchorStore.AcquireLock();
        FileStream? ledgerLock = null;
        try
        {
            anchorStore.RequireUpgradeReadyForMutation();
            var anchor = anchorStore.ReadRequired(allowLegacySchema: true);
            var channelRoot = RequireExistingDirectory(
                Path.Combine(
                    RequireExistingDirectory(
                        config.SigningLedgerRoot,
                        "signing ledger root"),
                    config.Channel),
                "signing ledger channel");
            ledgerLock = new FileStream(
                Path.Combine(channelRoot, "signing.lock"),
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None,
                1,
                FileOptions.WriteThrough);
            var cleanupBlocked = false;
            if (anchorStore.PendingExists)
            {
                cleanupBlocked = !anchorStore.RecoverPending(channelRoot, anchor);
                anchor = anchorStore.ReadRequired();
            }
            var snapshot = ReadSnapshot(channelRoot, config.Channel);
            RequireAnchorMatches(anchor, snapshot);
            anchor = anchorStore.EnsureCurrentSchemaFence(anchor);
            anchorStore.RequirePublicationReceiptConsistentIfPresent(
                anchor,
                snapshot?.Head);
            return new PersonalPublisherSigningLedger(
                channelRoot,
                anchorStore,
                anchorLock,
                ledgerLock,
                snapshot,
                anchor,
                cleanupBlocked,
                checkpoint);
        }
        catch
        {
            ledgerLock?.Dispose();
            anchorLock.Dispose();
            throw;
        }
    }

    public void RequireForward(PersonalReleasePublisherConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        if (_cleanupBlocked)
        {
            throw new InvalidOperationException(
                "Personal signing ledger has an authenticated committed publication whose pending marker cleanup is blocked. Exact retry is allowed, but a new sequence cannot be signed until controlled cleanup succeeds.");
        }
        RequireForward(_snapshot?.Latest, config);
    }

    public byte[]? TryReadExactCommittedManifest(
        string outputManifestPath,
        string configSha256,
        string inputSetSha256) =>
        _anchorStore.TryReadExactCommittedManifest(
            _anchor,
            _snapshot?.Head,
            outputManifestPath,
            configSha256,
            inputSetSha256);

    public void Commit(
        PersonalReleasePublisherConfig config,
        PersonalReleaseSetManifest manifest,
        ReadOnlySpan<byte> manifestBytes,
        string outputManifestPath,
        string configSha256,
        string inputSetSha256,
        DateTimeOffset nowUtc)
    {
        if (nowUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException("Personal signing ledger time must use UTC.");
        }
        RequireForward(config);
        _anchorStore.RequireUpgradeReadyForMutation();
        var manifestSha256 = Convert.ToHexStringLower(SHA256.HashData(manifestBytes));
        var entryName = $"{manifest.Sequence:D20}-{manifest.ReleaseSetId}-{manifestSha256}.json";
        RequireSafeFileName(entryName, "signing ledger entry");
        var entry = new SigningLedgerEntry(
            1,
            PersonalReleaseSetContract.Product,
            manifest.Environment,
            manifest.Channel,
            manifest.ReleaseSetId,
            manifest.Generation,
            manifest.Sequence,
            manifest.MinAcceptedSequence,
            manifestSha256,
            manifest.RevokedReleaseSetIds,
            _snapshot?.Head.EntryFileName ?? string.Empty,
            _snapshot?.Head.EntrySha256 ?? new string('0', 64),
            nowUtc);
        var entryBytes = SigningLedgerJson.Serialize(entry);
        var entrySha256 = Convert.ToHexStringLower(SHA256.HashData(entryBytes));
        var head = new SigningLedgerHead(
            1,
            PersonalReleaseSetContract.Product,
            manifest.Environment,
            manifest.Channel,
            manifest.ReleaseSetId,
            manifest.Generation,
            manifest.Sequence,
            manifest.MinAcceptedSequence,
            manifestSha256,
            manifest.RevokedReleaseSetIds,
            entryName,
            entrySha256);
        var headBytes = SigningLedgerJson.Serialize(head);
        var nextAnchor = _anchorStore.CreateNext(_anchor, head);
        _anchorStore.WritePending(
            _anchor,
            nextAnchor,
            entryName,
            entryBytes,
            headBytes,
            outputManifestPath,
            manifestSha256,
            configSha256,
            inputSetSha256,
            manifestBytes);
        _checkpoint?.Invoke(PersonalPublisherSigningLedgerCommitStage.PendingAnchorWritten);
        WriteCreateOnlyDurable(Path.Combine(_channelRoot, entryName), entryBytes);
        _checkpoint?.Invoke(PersonalPublisherSigningLedgerCommitStage.EntryWritten);
        ReplaceDurable(Path.Combine(_channelRoot, "head.json"), headBytes);
        _checkpoint?.Invoke(PersonalPublisherSigningLedgerCommitStage.HeadReplaced);
        _anchorStore.Commit(nextAnchor);
        _checkpoint?.Invoke(PersonalPublisherSigningLedgerCommitStage.AnchorCommitted);
        _anchorStore.PublishPending(nextAnchor);
        _checkpoint?.Invoke(PersonalPublisherSigningLedgerCommitStage.ManifestPublished);
        _anchorStore.CommitPendingPublicationReceipt(nextAnchor);
        _checkpoint?.Invoke(
            PersonalPublisherSigningLedgerCommitStage.PublicationReceiptCommitted);
        if (_anchorStore.TryDeleteCommittedPending())
        {
            _checkpoint?.Invoke(PersonalPublisherSigningLedgerCommitStage.PendingDeleted);
        }
    }

    public void Dispose()
    {
        _lock.Dispose();
        _anchorLock.Dispose();
    }

    private static void RequireForward(
        SigningLedgerEntry? previous,
        PersonalReleasePublisherConfig candidate)
    {
        if (previous is null)
        {
            return;
        }
        if (candidate.Sequence <= previous.Sequence
            || candidate.Generation < previous.Generation
            || candidate.MinAcceptedSequence < previous.MinAcceptedSequence
            || !previous.RevokedReleaseSetIds.All(value =>
                candidate.RevokedReleaseSetIds.Contains(value, StringComparer.Ordinal)))
        {
            throw new InvalidDataException(
                "Personal signer ledger rejected sequence, generation, floor, or revocation rollback.");
        }
    }

    private static void RequireAnchorMatches(
        SigningLedgerAnchor anchor,
        SigningLedgerSnapshot? snapshot)
    {
        if (anchor.Head is null)
        {
            if (snapshot is not null)
            {
                throw new InvalidDataException(
                    "Personal signing ledger appeared after its independent genesis anchor was established.");
            }
            return;
        }
        if (snapshot is null
            || !SigningLedgerJson.Serialize(anchor.Head).AsSpan().SequenceEqual(
                SigningLedgerJson.Serialize(snapshot.Head)))
        {
            throw new InvalidDataException(
                "Personal signing ledger is missing, replayed, or differs from its independent high-water anchor.");
        }
    }

    private static SigningLedgerSnapshot? ReadSnapshot(
        string channelRoot,
        string channel,
        string? allowedUncommittedEntry = null)
    {
        var headPath = Path.Combine(channelRoot, "head.json");
        var entryFiles = Directory.EnumerateFiles(channelRoot, "*.json")
            .Where(path => !string.Equals(
                Path.GetFileName(path),
                "head.json",
                StringComparison.Ordinal))
            .ToArray();
        if (!File.Exists(headPath))
        {
            if (entryFiles.Any(path => !string.Equals(
                Path.GetFileName(path),
                allowedUncommittedEntry,
                StringComparison.Ordinal)))
            {
                throw new InvalidDataException(
                    "Personal signing ledger contains an uncommitted entry.");
            }
            return null;
        }
        var headBytes = ReadBounded(headPath, 128 * 1024, "signing ledger head");
        var head = SigningLedgerJson.Parse<SigningLedgerHead>(headBytes, "signing ledger head");
        head.Validate(channel);

        var expectedName = head.EntryFileName;
        var expectedSha256 = head.EntrySha256;
        var visited = new HashSet<string>(StringComparer.Ordinal);
        SigningLedgerEntry? latest = null;
        long previousSequence = long.MaxValue;
        while (!string.IsNullOrEmpty(expectedName))
        {
            RequireSafeFileName(expectedName, "signing ledger entry");
            if (!visited.Add(expectedName) || visited.Count > 100_000)
            {
                throw new InvalidDataException("Personal signing ledger is cyclic or too large.");
            }
            var bytes = ReadBounded(
                Path.Combine(channelRoot, expectedName),
                512 * 1024,
                "signing ledger entry");
            if (!string.Equals(
                    Convert.ToHexStringLower(SHA256.HashData(bytes)),
                    expectedSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException("Personal signing ledger chain digest is invalid.");
            }
            var entry = SigningLedgerJson.Parse<SigningLedgerEntry>(bytes, "signing ledger entry");
            entry.Validate(channel);
            if (entry.Sequence >= previousSequence)
            {
                throw new InvalidDataException("Personal signing ledger order is invalid.");
            }
            latest ??= entry;
            previousSequence = entry.Sequence;
            expectedName = entry.PreviousEntryFileName;
            expectedSha256 = entry.PreviousEntrySha256;
        }
        if (latest is null
            || !string.Equals(expectedSha256, new string('0', 64), StringComparison.Ordinal)
            || head.Sequence != latest.Sequence
            || head.Generation != latest.Generation
            || !string.Equals(head.ReleaseSetId, latest.ReleaseSetId, StringComparison.Ordinal)
            || !string.Equals(head.ManifestSha256, latest.ManifestSha256, StringComparison.Ordinal)
            || !head.RevokedReleaseSetIds.SequenceEqual(
                latest.RevokedReleaseSetIds,
                StringComparer.Ordinal))
        {
            throw new InvalidDataException("Personal signing ledger head is invalid.");
        }
        if (entryFiles.Select(Path.GetFileName).Any(name => name is null
                || !visited.Contains(name)
                    && !string.Equals(name, allowedUncommittedEntry, StringComparison.Ordinal))
            || entryFiles.Count(path => string.Equals(
                Path.GetFileName(path),
                allowedUncommittedEntry,
                StringComparison.Ordinal)) > 1)
        {
            throw new InvalidDataException(
                "Personal signing ledger contains an uncommitted or unexpected entry.");
        }
        return new SigningLedgerSnapshot(head, latest);
    }

    private static string EnsureDirectory(string path, string label)
    {
        if (!Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException($"Personal {label} must be absolute.");
        }
        var full = Path.GetFullPath(path);
        RejectExistingLinkAncestors(full, label);
        Directory.CreateDirectory(full);
        RejectExistingLinkAncestors(full, label);
        return full;
    }

    private static string RequireExistingDirectory(string path, string label)
    {
        if (!Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException($"Personal {label} must be absolute.");
        }
        var full = Path.GetFullPath(path);
        RejectExistingLinkAncestors(full, label);
        if (!Directory.Exists(full))
        {
            throw new InvalidDataException(
                $"Personal {label} is missing; explicit anchor initialization or authorized recovery is required.");
        }
        RejectExistingLinkAncestors(full, label);
        return full;
    }

    private static void RequireWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Personal publisher signing-ledger protection requires Windows DPAPI.");
        }
    }

    private static void RejectExistingLinkAncestors(string path, string label)
    {
        for (var current = new DirectoryInfo(path); current is not null; current = current.Parent)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException($"Personal {label} may not cross a filesystem link.");
            }
        }
    }

    private static byte[] ReadBounded(string path, int maximumBytes, string label)
    {
        if (!File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new FileNotFoundException($"Personal {label} is missing or linked.", path);
        }
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.SequentialScan);
        if (stream.Length is <= 0 || stream.Length > maximumBytes || stream.Length > int.MaxValue)
        {
            throw new InvalidDataException($"Personal {label} size is invalid.");
        }
        var bytes = new byte[(int)stream.Length];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1 || stream.Length != bytes.LongLength)
        {
            throw new IOException($"Personal {label} changed while it was read.");
        }
        return bytes;
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

    private static void ReplaceDurable(string destination, ReadOnlySpan<byte> bytes)
    {
        var parent = Path.GetDirectoryName(destination)
            ?? throw new InvalidDataException("Personal signing ledger path has no parent.");
        var temporary = Path.Combine(parent, $".head.{Guid.NewGuid():N}.tmp");
        try
        {
            WriteCreateOnlyDurable(temporary, bytes);
            File.Move(temporary, destination, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private static void RequireSafeFileName(string? value, string label)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value is "." or ".."
            || value != Path.GetFileName(value)
            || value.Length > 255
            || value.Any(char.IsControl)
            || value.IndexOfAny(['\\', '/', ':', '*', '?', '"', '<', '>', '|']) >= 0)
        {
            throw new InvalidDataException($"Personal {label} filename is unsafe.");
        }
    }

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record SigningLedgerAnchor(
        int SchemaVersion,
        string Product,
        string Environment,
        string Channel,
        string LedgerRootSha256,
        long StateRevision,
        string StateCommitId,
        SigningLedgerHead? Head);

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record SigningLedgerCommitIntent(
        int SchemaVersion,
        string Product,
        string Environment,
        string Channel,
        string LedgerRootSha256,
        SigningLedgerAnchor PreviousAnchor,
        SigningLedgerAnchor NextAnchor,
        string EntryFileName,
        byte[] EntryBytes,
        byte[] HeadBytes,
        string OutputManifestPath,
        string ManifestSha256,
        string ConfigSha256,
        string InputSetSha256,
        byte[] ManifestBytes);

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record SigningLedgerPublicationReceipt(
        int SchemaVersion,
        string Product,
        string Environment,
        string Channel,
        string LedgerRootSha256,
        long StateRevision,
        string StateCommitId,
        string HeadSha256,
        string OutputManifestPath,
        string ManifestSha256,
        long ManifestSizeBytes,
        string ConfigSha256,
        string InputSetSha256);

    private sealed class SigningLedgerAnchorStore
    {
        private const int LegacyAnchorSchemaVersion = 1;
        private const int CurrentAnchorSchemaVersion = 2;
        private const int MaximumProtectedBytes = 2 * 1024 * 1024;
        private readonly string _environment;
        private readonly string _channel;
        private readonly string _ledgerRoot;
        private readonly string _ledgerRootSha256;
        private readonly string _anchorPath;
        private readonly string _pendingPath;
        private readonly string _legacyPendingPath;
        private readonly string _publicationReceiptPath;
        private readonly string _lockPath;
        private readonly byte[] _entropy;

        public SigningLedgerAnchorStore(
            PersonalReleasePublisherConfig config,
            string? anchorAuthorityRoot)
        {
            if (!string.Equals(
                    config.Environment,
                    PersonalReleaseSetContract.ProductionEnvironment,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Personal signing ledger anchor requires the production environment.");
            }
            PersonalReleaseSetValidator.ValidateChannel(config.Channel);
            ArgumentException.ThrowIfNullOrWhiteSpace(config.SigningLedgerRoot);
            if (!Path.IsPathFullyQualified(config.SigningLedgerRoot))
            {
                throw new InvalidDataException(
                    "Personal signing ledger path must be absolute.");
            }

            _environment = config.Environment;
            _channel = config.Channel;
            _ledgerRoot = NormalizeDirectory(config.SigningLedgerRoot);
            var authorityRoot = ResolveAnchorAuthorityRoot(anchorAuthorityRoot);
            var anchorIdentity = Sha256Utf8(string.Join(
                '|',
                PersonalReleaseSetContract.Product,
                _environment,
                _channel,
                "personal-publisher-signing-ledger-anchor-authority-v1"));
            _anchorPath = Path.Combine(authorityRoot, $"{anchorIdentity}.dpapi");
            if (IsSameOrDescendant(_anchorPath, _ledgerRoot))
            {
                throw new InvalidDataException(
                    "Personal signing ledger anchor must be outside the signing-ledger root.");
            }
            var anchorParent = Path.GetDirectoryName(_anchorPath)
                ?? throw new InvalidDataException(
                    "Personal signing ledger anchor has no parent directory.");
            RejectExistingLinkAncestors(anchorParent, "signing ledger anchor");
            if (Directory.Exists(_anchorPath))
            {
                throw new InvalidDataException(
                    "Personal signing ledger anchor path is unexpectedly a directory.");
            }
            _pendingPath = _anchorPath + ".pending.v2";
            _legacyPendingPath = _anchorPath + ".pending";
            _publicationReceiptPath = _anchorPath + ".publication.v2";
            _lockPath = _anchorPath + ".lock";
            _ledgerRootSha256 = Sha256Utf8(_ledgerRoot.ToUpperInvariant());
            _entropy = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(string.Join(
                '|',
                PersonalReleaseSetContract.Product,
                _environment,
                _channel,
                _ledgerRoot.ToUpperInvariant(),
                "personal-publisher-signing-ledger-anchor-v1")));
        }

        public string AnchorPath => _anchorPath;

        public bool PendingExists
        {
            get
            {
                RejectLinkedFileIfPresent(_pendingPath, "pending signing ledger anchor");
                return File.Exists(_pendingPath);
            }
        }

        public string CheckUpgradeReadyReadOnly()
        {
            var legacyPendingExists = RequireOrdinarySingleLinkFileOrMissing(
                _legacyPendingPath,
                "legacy signing ledger pending marker");
            var v2PendingExists = RequireOrdinarySingleLinkFileOrMissing(
                _pendingPath,
                "v2 signing ledger pending marker");
            _ = RequireOrdinarySingleLinkFileOrMissing(
                _anchorPath,
                "signing ledger anchor");
            _ = RequireOrdinarySingleLinkFileOrMissing(
                _publicationReceiptPath,
                "signing ledger publication receipt");

            if (legacyPendingExists && v2PendingExists)
            {
                throw new InvalidDataException(
                    $"Personal signing ledger has conflicting legacy and v2 pending markers. Leave both untouched and complete controlled recovery before publishing. Legacy: '{_legacyPendingPath}'. V2: '{_pendingPath}'.");
            }
            if (legacyPendingExists)
            {
                throw new InvalidDataException(
                    $"Personal signing ledger upgrade is blocked by legacy '.pending' state. The current publisher will not parse, rename, or delete it. Complete controlled recovery with the matching legacy publisher before retrying. Legacy: '{_legacyPendingPath}'.");
            }

            return v2PendingExists
                ? $"READY: no legacy '.pending' marker; a regular '.pending.v2' marker is present at '{_pendingPath}'. This read-only check does not authenticate its contents; publication recovery will do so before mutation."
                : $"READY: no legacy '.pending' marker or v2 recovery conflict for anchor '{_anchorPath}'.";
        }

        public void RequireUpgradeReadyForMutation() =>
            _ = CheckUpgradeReadyReadOnly();

        public FileStream AcquireLock()
        {
            var parent = Path.GetDirectoryName(_lockPath)!;
            _ = EnsureDirectory(parent, "signing ledger anchor directory");
            RejectLinkedFileIfPresent(_lockPath, "signing ledger anchor lock");
            return new FileStream(
                _lockPath,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None,
                1,
                FileOptions.WriteThrough);
        }

        public void RequireAbsentForInitialization()
        {
            RejectLinkedFileIfPresent(_anchorPath, "signing ledger anchor");
            RejectLinkedFileIfPresent(_pendingPath, "pending signing ledger anchor");
            RejectLinkedFileIfPresent(
                _publicationReceiptPath,
                "signing ledger publication receipt");
            if (File.Exists(_anchorPath)
                || File.Exists(_pendingPath)
                || File.Exists(_publicationReceiptPath))
            {
                throw new InvalidOperationException(
                    "Personal signing ledger anchor is already initialized or has v2 recovery/publication state.");
            }
        }

        public void WriteInitial(SigningLedgerHead? head)
        {
            if (head is not null)
            {
                head.Validate(_channel);
            }
            var initial = new SigningLedgerAnchor(
                CurrentAnchorSchemaVersion,
                PersonalReleaseSetContract.Product,
                _environment,
                _channel,
                _ledgerRootSha256,
                head is null ? 0 : 1,
                Guid.NewGuid().ToString("N"),
                head);
            ValidateAnchor(initial);
            WriteProtectedAtomically(_anchorPath, initial, overwrite: false);
        }

        public SigningLedgerAnchor ReadRequired(bool allowLegacySchema = false)
        {
            if (!File.Exists(_anchorPath))
            {
                throw new InvalidDataException(
                    "Personal signing ledger independent anchor is missing; run the explicit anchor initialization command after authorized state review.");
            }
            var anchor = ReadProtected<SigningLedgerAnchor>(
                _anchorPath,
                "signing ledger anchor");
            ValidateAnchor(anchor, allowLegacySchema);
            return anchor;
        }

        public SigningLedgerAnchor EnsureCurrentSchemaFence(
            SigningLedgerAnchor anchor)
        {
            ValidateAnchor(anchor, allowLegacySchema: true);
            if (anchor.SchemaVersion == CurrentAnchorSchemaVersion)
            {
                return anchor;
            }

            var upgraded = ToCurrentSchema(anchor);
            Commit(upgraded);
            var persisted = ReadRequired();
            if (!AnchorEquals(persisted, upgraded))
            {
                throw new IOException(
                    "Personal signing ledger schema-v2 downgrade fence did not persist exactly.");
            }
            return persisted;
        }

        public SigningLedgerAnchor CreateNext(
            SigningLedgerAnchor previous,
            SigningLedgerHead head)
        {
            ValidateAnchor(previous);
            head.Validate(_channel);
            var next = new SigningLedgerAnchor(
                CurrentAnchorSchemaVersion,
                PersonalReleaseSetContract.Product,
                _environment,
                _channel,
                _ledgerRootSha256,
                checked(previous.StateRevision + 1),
                Guid.NewGuid().ToString("N"),
                head);
            ValidateAnchor(next);
            return next;
        }

        public void WritePending(
            SigningLedgerAnchor previous,
            SigningLedgerAnchor next,
            string entryFileName,
            ReadOnlySpan<byte> entryBytes,
            ReadOnlySpan<byte> headBytes,
            string outputManifestPath,
            string manifestSha256,
            string configSha256,
            string inputSetSha256,
            ReadOnlySpan<byte> manifestBytes)
        {
            ValidateTransition(previous, next);
            RequireSafeFileName(entryFileName, "pending signing ledger entry");
            var normalizedOutputPath = NormalizePublicationPath(outputManifestPath);
            var intent = new SigningLedgerCommitIntent(
                2,
                PersonalReleaseSetContract.Product,
                _environment,
                _channel,
                _ledgerRootSha256,
                previous,
                next,
                entryFileName,
                entryBytes.ToArray(),
                headBytes.ToArray(),
                normalizedOutputPath,
                manifestSha256,
                configSha256,
                inputSetSha256,
                manifestBytes.ToArray());
            try
            {
                ValidateIntent(intent);
                WriteProtectedAtomically(_pendingPath, intent, overwrite: false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(intent.EntryBytes);
                CryptographicOperations.ZeroMemory(intent.HeadBytes);
                CryptographicOperations.ZeroMemory(intent.ManifestBytes);
            }
        }

        public bool RecoverPending(string channelRoot, SigningLedgerAnchor currentAnchor)
        {
            ValidateAnchor(currentAnchor, allowLegacySchema: true);
            var intent = ReadProtected<SigningLedgerCommitIntent>(
                _pendingPath,
                "pending signing ledger anchor");
            try
            {
                ValidateIntent(intent, allowLegacyAnchorSchema: true);
                var previousAnchor = ToCurrentSchema(intent.PreviousAnchor);
                var nextAnchor = ToCurrentSchema(intent.NextAnchor);
                var currentIsPrevious = AnchorEqualsAcrossSchema(
                    currentAnchor,
                    previousAnchor);
                var currentIsNext = AnchorEqualsAcrossSchema(
                    currentAnchor,
                    nextAnchor);
                if (!currentIsPrevious && !currentIsNext)
                {
                    throw new InvalidDataException(
                        "Personal signing ledger pending transaction does not extend its independent anchor.");
                }

                var headPath = Path.Combine(channelRoot, "head.json");
                var existingHead = File.Exists(headPath)
                    ? ReadBounded(headPath, 128 * 1024, "signing ledger head during recovery")
                    : null;
                var previousHead = previousAnchor.Head is null
                    ? null
                    : SigningLedgerJson.Serialize(previousAnchor.Head);
                var atPreviousHead = existingHead is null && previousHead is null
                    || existingHead is not null
                        && previousHead is not null
                        && existingHead.AsSpan().SequenceEqual(previousHead);
                var atNextHead = existingHead is not null
                    && existingHead.AsSpan().SequenceEqual(intent.HeadBytes);
                if (!atPreviousHead && !atNextHead)
                {
                    throw new InvalidDataException(
                        "Personal signing ledger crash recovery found an unrelated or replayed head.");
                }

                var entryPath = Path.Combine(channelRoot, intent.EntryFileName);
                if (File.Exists(entryPath))
                {
                    var existingEntry = ReadBounded(
                        entryPath,
                        512 * 1024,
                        "pending signing ledger entry");
                    if (!existingEntry.AsSpan().SequenceEqual(intent.EntryBytes))
                    {
                        throw new InvalidDataException(
                            "Personal signing ledger crash recovery found substituted entry bytes.");
                    }
                }

                // The authenticated v2 intent may have been written by the
                // pre-fence publisher with schema-v1 anchors. Persist the
                // schema-v2 anchor while both the authority and ledger locks
                // are held, before repairing any ledger or publication state.
                currentAnchor = EnsureCurrentSchemaFence(currentAnchor);
                currentIsPrevious = AnchorEquals(currentAnchor, previousAnchor);
                currentIsNext = AnchorEquals(currentAnchor, nextAnchor);
                if (!currentIsPrevious && !currentIsNext)
                {
                    throw new InvalidDataException(
                        "Personal signing ledger schema-v2 fence changed pending transaction identity.");
                }

                var currentIntent = intent with
                {
                    PreviousAnchor = previousAnchor,
                    NextAnchor = nextAnchor,
                };

                if (atPreviousHead)
                {
                    var previousSnapshot = ReadSnapshot(
                        channelRoot,
                        _channel,
                        intent.EntryFileName);
                    RequireAnchorMatches(previousAnchor, previousSnapshot);
                    if (!File.Exists(entryPath))
                    {
                        WriteCreateOnlyDurable(entryPath, intent.EntryBytes);
                    }
                    ReplaceDurable(headPath, intent.HeadBytes);
                }
                else if (!File.Exists(entryPath))
                {
                    WriteCreateOnlyDurable(entryPath, intent.EntryBytes);
                }

                var nextSnapshot = ReadSnapshot(channelRoot, _channel);
                RequireAnchorMatches(nextAnchor, nextSnapshot);
                if (currentIsPrevious)
                {
                    Commit(nextAnchor);
                }
                PublishManifest(currentIntent);
                CommitPublicationReceipt(currentIntent);
                return TryDeleteCommittedPending();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(intent.EntryBytes);
                CryptographicOperations.ZeroMemory(intent.HeadBytes);
                CryptographicOperations.ZeroMemory(intent.ManifestBytes);
            }
        }

        public void PublishPending(SigningLedgerAnchor currentAnchor)
        {
            ValidateAnchor(currentAnchor);
            var intent = ReadProtected<SigningLedgerCommitIntent>(
                _pendingPath,
                "pending signing ledger anchor");
            try
            {
                ValidateIntent(intent);
                if (!AnchorEquals(currentAnchor, intent.NextAnchor))
                {
                    throw new InvalidDataException(
                        "Personal signing ledger publication intent does not match its committed anchor.");
                }
                PublishManifest(intent);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(intent.EntryBytes);
                CryptographicOperations.ZeroMemory(intent.HeadBytes);
                CryptographicOperations.ZeroMemory(intent.ManifestBytes);
            }
        }

        public void CommitPendingPublicationReceipt(
            SigningLedgerAnchor currentAnchor)
        {
            ValidateAnchor(currentAnchor);
            var intent = ReadProtected<SigningLedgerCommitIntent>(
                _pendingPath,
                "pending signing ledger anchor");
            try
            {
                ValidateIntent(intent);
                if (!AnchorEquals(currentAnchor, intent.NextAnchor))
                {
                    throw new InvalidDataException(
                        "Personal signing ledger publication receipt intent does not match its committed anchor.");
                }
                RequirePublishedManifest(intent);
                CommitPublicationReceipt(intent);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(intent.EntryBytes);
                CryptographicOperations.ZeroMemory(intent.HeadBytes);
                CryptographicOperations.ZeroMemory(intent.ManifestBytes);
            }
        }

        public void Commit(SigningLedgerAnchor next)
        {
            ValidateAnchor(next);
            WriteProtectedAtomically(_anchorPath, next, overwrite: true);
        }

        public bool TryDeleteCommittedPending()
        {
            try
            {
                if (!File.Exists(_pendingPath))
                {
                    return true;
                }
                RejectLinkedFileIfPresent(_pendingPath, "pending signing ledger anchor");
                File.Delete(_pendingPath);
                return !File.Exists(_pendingPath) && !Directory.Exists(_pendingPath);
            }
            catch (Exception)
            {
                return false;
            }
        }

        public void RequirePublicationReceiptConsistentIfPresent(
            SigningLedgerAnchor currentAnchor,
            SigningLedgerHead? currentHead) =>
            _ = ReadValidatedPublicationReceiptIfPresent(
                currentAnchor,
                currentHead);

        public byte[]? TryReadExactCommittedManifest(
            SigningLedgerAnchor currentAnchor,
            SigningLedgerHead? currentHead,
            string outputManifestPath,
            string configSha256,
            string inputSetSha256)
        {
            if (!PersonalReleaseSetValidator.IsSha256(configSha256)
                || !PersonalReleaseSetValidator.IsSha256(inputSetSha256))
            {
                throw new InvalidDataException(
                    "Personal publication retry identity digest is invalid.");
            }
            var publication = ReadValidatedPublicationReceiptIfPresent(
                currentAnchor,
                currentHead);
            if (publication is null)
            {
                return null;
            }

            var normalizedOutputPath = NormalizePublicationPath(outputManifestPath);
            return string.Equals(
                    publication.Value.Receipt.OutputManifestPath,
                    normalizedOutputPath,
                    StringComparison.OrdinalIgnoreCase)
                && string.Equals(
                    publication.Value.Receipt.ConfigSha256,
                    configSha256,
                    StringComparison.Ordinal)
                && string.Equals(
                    publication.Value.Receipt.InputSetSha256,
                    inputSetSha256,
                    StringComparison.Ordinal)
                    ? publication.Value.ManifestBytes
                    : null;
        }

        private void CommitPublicationReceipt(
            SigningLedgerCommitIntent intent)
        {
            var receipt = new SigningLedgerPublicationReceipt(
                2,
                PersonalReleaseSetContract.Product,
                _environment,
                _channel,
                _ledgerRootSha256,
                intent.NextAnchor.StateRevision,
                intent.NextAnchor.StateCommitId,
                Convert.ToHexStringLower(SHA256.HashData(intent.HeadBytes)),
                NormalizePublicationPath(intent.OutputManifestPath),
                intent.ManifestSha256,
                intent.ManifestBytes.LongLength,
                intent.ConfigSha256,
                intent.InputSetSha256);
            ValidatePublicationReceipt(
                receipt,
                intent.NextAnchor,
                intent.NextAnchor.Head!);
            if (HasExactPublicationReceiptForCommit(intent, receipt))
            {
                return;
            }
            WriteProtectedAtomically(
                _publicationReceiptPath,
                receipt,
                overwrite: true);
            _ = ReadValidatedPublicationReceiptIfPresent(
                intent.NextAnchor,
                intent.NextAnchor.Head!);
        }

        private bool HasExactPublicationReceiptForCommit(
            SigningLedgerCommitIntent intent,
            SigningLedgerPublicationReceipt expected)
        {
            RejectLinkedFileIfPresent(
                _publicationReceiptPath,
                "signing ledger publication receipt");
            if (!File.Exists(_publicationReceiptPath))
            {
                return false;
            }

            var observed = ReadProtected<SigningLedgerPublicationReceipt>(
                _publicationReceiptPath,
                "signing ledger publication receipt");
            if (observed.StateRevision == intent.NextAnchor.StateRevision
                && string.Equals(
                    observed.StateCommitId,
                    intent.NextAnchor.StateCommitId,
                    StringComparison.Ordinal))
            {
                var validated = ReadValidatedPublicationReceiptIfPresent(
                    intent.NextAnchor,
                    intent.NextAnchor.Head!)
                    ?? throw new InvalidDataException(
                        "Personal signing ledger committed publication receipt disappeared during readback.");
                if (!SigningLedgerJson.Serialize(validated.Receipt).AsSpan()
                        .SequenceEqual(SigningLedgerJson.Serialize(expected)))
                {
                    throw new InvalidDataException(
                        "Personal signing ledger publication receipt conflicts with the authenticated pending transaction.");
                }
                return true;
            }

            if (intent.PreviousAnchor.Head is not null
                && observed.StateRevision == intent.PreviousAnchor.StateRevision
                && string.Equals(
                    observed.StateCommitId,
                    intent.PreviousAnchor.StateCommitId,
                    StringComparison.Ordinal))
            {
                _ = ReadValidatedPublicationReceiptIfPresent(
                    intent.PreviousAnchor,
                    intent.PreviousAnchor.Head);
                return false;
            }

            throw new InvalidDataException(
                "Personal signing ledger publication receipt is unrelated to the authenticated pending transaction.");
        }

        private (
            SigningLedgerPublicationReceipt Receipt,
            byte[] ManifestBytes)? ReadValidatedPublicationReceiptIfPresent(
                SigningLedgerAnchor currentAnchor,
                SigningLedgerHead? currentHead)
        {
            ValidateAnchor(currentAnchor);
            RejectLinkedFileIfPresent(
                _publicationReceiptPath,
                "signing ledger publication receipt");
            if (!File.Exists(_publicationReceiptPath))
            {
                return null;
            }
            if (currentHead is null)
            {
                throw new InvalidDataException(
                    "Personal signing ledger publication receipt cannot accompany a genesis anchor.");
            }

            var receipt = ReadProtected<SigningLedgerPublicationReceipt>(
                _publicationReceiptPath,
                "signing ledger publication receipt");
            ValidatePublicationReceipt(receipt, currentAnchor, currentHead);
            var manifestBytes = ReadBounded(
                receipt.OutputManifestPath,
                PersonalReleaseSetContract.MaximumManifestBytes,
                "published release-set manifest bound by the signing ledger receipt");
            if (manifestBytes.LongLength != receipt.ManifestSizeBytes
                || !string.Equals(
                    Convert.ToHexStringLower(SHA256.HashData(manifestBytes)),
                    receipt.ManifestSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Personal signing ledger publication receipt does not match the immutable output manifest.");
            }
            var manifest = PersonalReleaseSetJson.Parse(manifestBytes);
            if (!PersonalReleaseSetJson.SerializeSigned(manifest).AsSpan()
                    .SequenceEqual(manifestBytes)
                || manifest.Generation != currentHead.Generation
                || manifest.Sequence != currentHead.Sequence
                || manifest.MinAcceptedSequence != currentHead.MinAcceptedSequence
                || !string.Equals(
                    manifest.ReleaseSetId,
                    currentHead.ReleaseSetId,
                    StringComparison.Ordinal)
                || !manifest.RevokedReleaseSetIds.SequenceEqual(
                    currentHead.RevokedReleaseSetIds,
                    StringComparer.Ordinal))
            {
                throw new InvalidDataException(
                    "Personal signing ledger publication receipt manifest is not canonical or does not match the ledger head.");
            }
            return (receipt, manifestBytes);
        }

        private void ValidatePublicationReceipt(
            SigningLedgerPublicationReceipt receipt,
            SigningLedgerAnchor currentAnchor,
            SigningLedgerHead currentHead)
        {
            currentHead.Validate(_channel);
            var normalizedOutputPath = NormalizePublicationPath(
                receipt.OutputManifestPath);
            if (receipt.SchemaVersion != 2
                || !string.Equals(
                    receipt.Product,
                    PersonalReleaseSetContract.Product,
                    StringComparison.Ordinal)
                || !string.Equals(receipt.Environment, _environment, StringComparison.Ordinal)
                || !string.Equals(receipt.Channel, _channel, StringComparison.Ordinal)
                || !string.Equals(
                    receipt.LedgerRootSha256,
                    _ledgerRootSha256,
                    StringComparison.Ordinal)
                || receipt.StateRevision != currentAnchor.StateRevision
                || !string.Equals(
                    receipt.StateCommitId,
                    currentAnchor.StateCommitId,
                    StringComparison.Ordinal)
                || !string.Equals(
                    receipt.HeadSha256,
                    Convert.ToHexStringLower(SHA256.HashData(
                        SigningLedgerJson.Serialize(currentHead))),
                    StringComparison.Ordinal)
                || !string.Equals(
                    normalizedOutputPath,
                    receipt.OutputManifestPath,
                    StringComparison.OrdinalIgnoreCase)
                || !string.Equals(
                    receipt.ManifestSha256,
                    currentHead.ManifestSha256,
                    StringComparison.Ordinal)
                || receipt.ManifestSizeBytes is <= 0
                    or > PersonalReleaseSetContract.MaximumManifestBytes
                || !PersonalReleaseSetValidator.IsSha256(receipt.ConfigSha256)
                || !PersonalReleaseSetValidator.IsSha256(receipt.InputSetSha256))
            {
                throw new InvalidDataException(
                    "Personal signing ledger publication receipt is invalid or does not match the current independent anchor.");
            }
        }

        private void ValidateIntent(
            SigningLedgerCommitIntent intent,
            bool allowLegacyAnchorSchema = false)
        {
            if (intent.SchemaVersion != 2
                || !string.Equals(
                    intent.Product,
                    PersonalReleaseSetContract.Product,
                    StringComparison.Ordinal)
                || !string.Equals(intent.Environment, _environment, StringComparison.Ordinal)
                || !string.Equals(intent.Channel, _channel, StringComparison.Ordinal)
                || !string.Equals(
                    intent.LedgerRootSha256,
                    _ledgerRootSha256,
                    StringComparison.Ordinal)
                || intent.EntryBytes.Length is <= 0 or > 512 * 1024
                || intent.HeadBytes.Length is <= 0 or > 128 * 1024
                || intent.ManifestBytes.Length is <= 0
                    or > PersonalReleaseSetContract.MaximumManifestBytes
                || !PersonalReleaseSetValidator.IsSha256(intent.ManifestSha256)
                || !PersonalReleaseSetValidator.IsSha256(intent.ConfigSha256)
                || !PersonalReleaseSetValidator.IsSha256(intent.InputSetSha256))
            {
                throw new InvalidDataException(
                    "Personal signing ledger pending transaction identity is invalid.");
            }
            ValidateTransition(
                intent.PreviousAnchor,
                intent.NextAnchor,
                allowLegacyAnchorSchema);
            RequireSafeFileName(intent.EntryFileName, "pending signing ledger entry");
            var entry = SigningLedgerJson.Parse<SigningLedgerEntry>(
                intent.EntryBytes,
                "pending signing ledger entry");
            var head = SigningLedgerJson.Parse<SigningLedgerHead>(
                intent.HeadBytes,
                "pending signing ledger head");
            var manifest = PersonalReleaseSetJson.Parse(intent.ManifestBytes);
            entry.Validate(_channel);
            head.Validate(_channel);
            var normalizedOutputPath = NormalizePublicationPath(intent.OutputManifestPath);
            if (!SigningLedgerJson.Serialize(entry).AsSpan().SequenceEqual(intent.EntryBytes)
                || !SigningLedgerJson.Serialize(head).AsSpan().SequenceEqual(intent.HeadBytes)
                || !SigningLedgerJson.Serialize(intent.NextAnchor.Head!).AsSpan()
                    .SequenceEqual(intent.HeadBytes)
                || !string.Equals(
                    intent.EntryFileName,
                    head.EntryFileName,
                    StringComparison.Ordinal)
                || !string.Equals(
                    Convert.ToHexStringLower(SHA256.HashData(intent.EntryBytes)),
                    head.EntrySha256,
                    StringComparison.Ordinal)
                || !string.Equals(
                    normalizedOutputPath,
                    intent.OutputManifestPath,
                    StringComparison.OrdinalIgnoreCase)
                || !PersonalReleaseSetJson.SerializeSigned(manifest).AsSpan()
                    .SequenceEqual(intent.ManifestBytes)
                || !string.Equals(
                    Convert.ToHexStringLower(SHA256.HashData(intent.ManifestBytes)),
                    intent.ManifestSha256,
                    StringComparison.Ordinal)
                || !string.Equals(
                    intent.ManifestSha256,
                    head.ManifestSha256,
                    StringComparison.Ordinal)
                || manifest.Generation != head.Generation
                || manifest.Sequence != head.Sequence
                || manifest.MinAcceptedSequence != head.MinAcceptedSequence
                || !string.Equals(
                    manifest.Product,
                    PersonalReleaseSetContract.Product,
                    StringComparison.Ordinal)
                || !string.Equals(manifest.Environment, _environment, StringComparison.Ordinal)
                || !string.Equals(manifest.Channel, _channel, StringComparison.Ordinal)
                || !string.Equals(
                    manifest.ReleaseSetId,
                    head.ReleaseSetId,
                    StringComparison.Ordinal)
                || !manifest.RevokedReleaseSetIds.SequenceEqual(
                    head.RevokedReleaseSetIds,
                    StringComparer.Ordinal))
            {
                throw new InvalidDataException(
                    "Personal signing ledger pending transaction bytes are not canonical or bound to its anchor.");
            }
        }

        private void RequirePublishedManifest(
            SigningLedgerCommitIntent intent)
        {
            var destination = NormalizePublicationPath(intent.OutputManifestPath);
            var persisted = ReadBounded(
                destination,
                PersonalReleaseSetContract.MaximumManifestBytes,
                "published release-set manifest");
            if (!persisted.AsSpan().SequenceEqual(intent.ManifestBytes))
            {
                throw new IOException(
                    "Personal release publication destination conflicts with the authenticated pending manifest.");
            }
        }

        private void PublishManifest(SigningLedgerCommitIntent intent)
        {
            var destination = NormalizePublicationPath(intent.OutputManifestPath);
            if (File.Exists(destination))
            {
                var existing = ReadBounded(
                    destination,
                    PersonalReleaseSetContract.MaximumManifestBytes,
                    "published release-set manifest");
                if (!existing.AsSpan().SequenceEqual(intent.ManifestBytes))
                {
                    throw new IOException(
                        "Personal release publication destination conflicts with the authenticated pending manifest.");
                }
                return;
            }

            var parent = Path.GetDirectoryName(destination)
                ?? throw new InvalidDataException(
                    "Personal release publication destination has no parent directory.");
            _ = EnsureDirectory(parent, "release publication output directory");
            destination = NormalizePublicationPath(destination);
            var temporary = Path.Combine(
                parent,
                $".{Path.GetFileName(destination)}.{intent.NextAnchor.StateCommitId}.publication.tmp");
            try
            {
                RejectLinkedFileIfPresent(temporary, "pending release publication temporary file");
                if (File.Exists(temporary))
                {
                    // The protected transaction id makes this an operation-owned
                    // crash residue. Recreate it from the authenticated bytes so
                    // a torn write cannot make recovery permanently unavailable.
                    File.Delete(temporary);
                }
                WriteCreateOnlyDurable(temporary, intent.ManifestBytes);
                var staged = ReadBounded(
                    temporary,
                    PersonalReleaseSetContract.MaximumManifestBytes,
                    "pending release publication temporary file");
                if (!staged.AsSpan().SequenceEqual(intent.ManifestBytes))
                {
                    throw new IOException(
                        "Personal release publication staging bytes changed before commit.");
                }

                if (File.Exists(destination) || Directory.Exists(destination))
                {
                    throw new IOException(
                        "Personal release publication destination appeared during commit.");
                }
                File.Move(temporary, destination);
                destination = NormalizePublicationPath(destination);
                var persisted = ReadBounded(
                    destination,
                    PersonalReleaseSetContract.MaximumManifestBytes,
                    "published release-set manifest");
                if (!persisted.AsSpan().SequenceEqual(intent.ManifestBytes))
                {
                    throw new IOException(
                        "Personal release publication bytes changed after commit.");
                }
            }
            finally
            {
                if (File.Exists(temporary))
                {
                    RejectExistingLinkAncestors(
                        parent,
                        "pending release publication temporary file");
                    RejectLinkedFileIfPresent(
                        temporary,
                        "pending release publication temporary file");
                    File.Delete(temporary);
                }
            }
        }

        private string NormalizePublicationPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            {
                throw new InvalidDataException(
                    "Personal release publication destination must be absolute.");
            }
            var normalized = Path.GetFullPath(path);
            RequireSafeFileName(
                Path.GetFileName(normalized),
                "release publication destination");
            var parent = Path.GetDirectoryName(normalized)
                ?? throw new InvalidDataException(
                    "Personal release publication destination has no parent directory.");
            RejectExistingLinkAncestors(parent, "release publication destination");
            RejectLinkedFileIfPresent(normalized, "release publication destination");
            if (IsSameOrDescendant(normalized, _ledgerRoot)
                || IsSameOrDescendant(normalized, Path.GetDirectoryName(_anchorPath)!))
            {
                throw new InvalidDataException(
                    "Personal release publication destination must be independent from signing-ledger authority state.");
            }
            return normalized;
        }

        private void ValidateTransition(
            SigningLedgerAnchor previous,
            SigningLedgerAnchor next,
            bool allowLegacyAnchorSchema = false)
        {
            ValidateAnchor(previous, allowLegacyAnchorSchema);
            ValidateAnchor(next, allowLegacyAnchorSchema);
            if (previous.SchemaVersion != next.SchemaVersion
                || next.StateRevision != previous.StateRevision + 1
                || next.Head is null
                || previous.Head is not null
                    && (next.Head.Sequence <= previous.Head.Sequence
                        || next.Head.Generation < previous.Head.Generation
                        || next.Head.MinAcceptedSequence < previous.Head.MinAcceptedSequence
                        || !previous.Head.RevokedReleaseSetIds.All(value =>
                            next.Head.RevokedReleaseSetIds.Contains(
                                value,
                                StringComparer.Ordinal))))
            {
                throw new InvalidDataException(
                    "Personal signing ledger pending transaction does not advance its independent high-water anchor.");
            }
        }

        private void ValidateAnchor(
            SigningLedgerAnchor anchor,
            bool allowLegacySchema = false)
        {
            if (anchor.SchemaVersion != CurrentAnchorSchemaVersion
                    && (!allowLegacySchema
                        || anchor.SchemaVersion != LegacyAnchorSchemaVersion)
                || !string.Equals(
                    anchor.Product,
                    PersonalReleaseSetContract.Product,
                    StringComparison.Ordinal)
                || !string.Equals(anchor.Environment, _environment, StringComparison.Ordinal)
                || !string.Equals(anchor.Channel, _channel, StringComparison.Ordinal)
                || !string.Equals(
                    anchor.LedgerRootSha256,
                    _ledgerRootSha256,
                    StringComparison.Ordinal)
                || anchor.StateRevision < 0
                || anchor.StateRevision > PersonalReleaseSetContract.MaximumSafeInteger
                || anchor.StateCommitId.Length != 32
                || anchor.StateCommitId.Any(character =>
                    (character < '0' || character > '9')
                    && (character < 'a' || character > 'f'))
                || (anchor.Head is null) != (anchor.StateRevision == 0))
            {
                throw new InvalidDataException(
                    "Personal signing ledger independent anchor is invalid.");
            }
            anchor.Head?.Validate(_channel);
        }

        private SigningLedgerAnchor ToCurrentSchema(SigningLedgerAnchor anchor)
        {
            ValidateAnchor(anchor, allowLegacySchema: true);
            var current = anchor.SchemaVersion == CurrentAnchorSchemaVersion
                ? anchor
                : anchor with { SchemaVersion = CurrentAnchorSchemaVersion };
            ValidateAnchor(current);
            return current;
        }

        private T ReadProtected<T>(string path, string label)
        {
            RejectLinkedFileIfPresent(path, label);
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
                        $"Personal {label} is not authenticated for this publisher identity.",
                        exception);
                }
                if (plaintext.Length is <= 0 or > MaximumProtectedBytes)
                {
                    throw new InvalidDataException($"Personal {label} plaintext size is invalid.");
                }
                return SigningLedgerJson.Parse<T>(plaintext, label);
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

        private void WriteProtectedAtomically<T>(string path, T value, bool overwrite)
        {
            var plaintext = SigningLedgerJson.Serialize(value);
            byte[]? protectedBytes = null;
            var parent = Path.GetDirectoryName(path)!;
            _ = EnsureDirectory(parent, "signing ledger anchor directory");
            RejectLinkedFileIfPresent(path, "signing ledger anchor state");
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
                        "Protected personal signing ledger anchor size is invalid.");
                }
                WriteCreateOnlyDurable(temporary, protectedBytes);
                File.Move(temporary, path, overwrite);
                RejectLinkedFileIfPresent(path, "signing ledger anchor state");
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
                    File.Delete(temporary);
                }
            }
        }

        private static bool AnchorEquals(
            SigningLedgerAnchor left,
            SigningLedgerAnchor right) => SigningLedgerJson.Serialize(left).AsSpan()
            .SequenceEqual(SigningLedgerJson.Serialize(right));

        private bool AnchorEqualsAcrossSchema(
            SigningLedgerAnchor left,
            SigningLedgerAnchor right) => AnchorEquals(
            ToCurrentSchema(left),
            ToCurrentSchema(right));

        private static void RejectLinkedFileIfPresent(string path, string label)
        {
            _ = RequireOrdinarySingleLinkFileOrMissing(path, label);
        }

        private static bool RequireOrdinarySingleLinkFileOrMissing(
            string path,
            string label)
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
                throw new InvalidDataException(
                    $"Personal {label} is unexpectedly a directory.");
            }
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    $"Personal {label} must not be a filesystem link.");
            }
            if (OperatingSystem.IsWindows())
            {
                using var handle = File.OpenHandle(
                    path,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read);
                if (!GetFileInformationByHandle(handle, out var information))
                {
                    throw new IOException(
                        $"Unable to inspect Personal {label} link count.",
                        Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error()));
                }
                if (information.NumberOfLinks != 1)
                {
                    throw new InvalidDataException(
                        $"Personal {label} must not be shared through a hard link.");
                }
            }
            return true;
        }

        private static string NormalizeDirectory(string path) => Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(path));

        private static string ResolveAnchorAuthorityRoot(string? overrideRoot)
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
                        "Personal signing ledger could not resolve the CurrentUser anchor authority root.");
                }
                root = Path.Combine(
                    localApplicationData,
                    "Ensou",
                    "Dsh",
                    "PersonalReleasePublisher",
                    "SigningLedgerAnchors");
            }
            if (!Path.IsPathFullyQualified(root))
            {
                throw new InvalidDataException(
                    "Personal signing ledger anchor authority root must be absolute.");
            }
            return NormalizeDirectory(root);
        }

        private static bool IsSameOrDescendant(string candidate, string root)
        {
            var normalizedCandidate = Path.GetFullPath(candidate);
            var normalizedRoot = NormalizeDirectory(root);
            return string.Equals(
                    Path.TrimEndingDirectorySeparator(normalizedCandidate),
                    normalizedRoot,
                    StringComparison.OrdinalIgnoreCase)
                || normalizedCandidate.StartsWith(
                    normalizedRoot + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase);
        }

        private static string Sha256Utf8(string value) => Convert.ToHexStringLower(
            SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value)));

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

    private sealed record SigningLedgerSnapshot(SigningLedgerHead Head, SigningLedgerEntry Latest);

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record SigningLedgerHead(
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
        string EntryFileName,
        string EntrySha256)
    {
        public void Validate(string channel)
        {
            RequireCommon(
                SchemaVersion,
                Product,
                Environment,
                Channel,
                ReleaseSetId,
                Generation,
                Sequence,
                MinAcceptedSequence,
                ManifestSha256,
                RevokedReleaseSetIds,
                channel);
            RequireSafeFileName(EntryFileName, "signing ledger head entry");
            if (!PersonalReleaseSetValidator.IsSha256(EntrySha256))
            {
                throw new InvalidDataException("Personal signing ledger entry digest is invalid.");
            }
        }
    }

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record SigningLedgerEntry(
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
        DateTimeOffset CommittedAtUtc)
    {
        public void Validate(string channel)
        {
            RequireCommon(
                SchemaVersion,
                Product,
                Environment,
                Channel,
                ReleaseSetId,
                Generation,
                Sequence,
                MinAcceptedSequence,
                ManifestSha256,
                RevokedReleaseSetIds,
                channel);
            if (CommittedAtUtc.Offset != TimeSpan.Zero
                || !PersonalReleaseSetValidator.IsSha256(PreviousEntrySha256))
            {
                throw new InvalidDataException("Personal signing ledger entry metadata is invalid.");
            }
            if (string.IsNullOrEmpty(PreviousEntryFileName))
            {
                if (!string.Equals(
                        PreviousEntrySha256,
                        new string('0', 64),
                        StringComparison.Ordinal))
                {
                    throw new InvalidDataException("Personal signing ledger genesis is invalid.");
                }
            }
            else
            {
                RequireSafeFileName(PreviousEntryFileName, "previous signing ledger entry");
            }
        }
    }

    private static void RequireCommon(
        int schemaVersion,
        string product,
        string environment,
        string storedChannel,
        string releaseSetId,
        long generation,
        long sequence,
        long minimum,
        string manifestSha256,
        IReadOnlyList<string>? revocations,
        string expectedChannel)
    {
        if (schemaVersion != 1
            || !string.Equals(product, PersonalReleaseSetContract.Product, StringComparison.Ordinal)
            || !string.Equals(
                environment,
                PersonalReleaseSetContract.ProductionEnvironment,
                StringComparison.Ordinal)
            || !string.Equals(storedChannel, expectedChannel, StringComparison.Ordinal)
            || generation is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || sequence is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || minimum < 0
            || minimum > sequence
            || !PersonalReleaseSetValidator.IsSha256(manifestSha256)
            || revocations is null
            || revocations.Count > 1_000
            || !revocations.SequenceEqual(revocations.Order(StringComparer.Ordinal), StringComparer.Ordinal)
            || revocations.Distinct(StringComparer.Ordinal).Count() != revocations.Count)
        {
            throw new InvalidDataException("Personal signing ledger record is invalid.");
        }
        PersonalReleaseSetValidator.ValidateReleaseId(releaseSetId, "signing ledger releaseSetId");
        foreach (var revoked in revocations)
        {
            PersonalReleaseSetValidator.ValidateReleaseId(revoked, "signing ledger revocation");
        }
    }

    private static class SigningLedgerJson
    {
        private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
        {
            AllowTrailingCommas = false,
            MaxDepth = 32,
            NumberHandling = JsonNumberHandling.Strict,
            PropertyNameCaseInsensitive = false,
            ReadCommentHandling = JsonCommentHandling.Disallow,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            WriteIndented = true,
        };

        public static byte[] Serialize<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, Options);

        public static T Parse<T>(ReadOnlySpan<byte> json, string label)
        {
            try
            {
                using var document = JsonDocument.Parse(json.ToArray(), new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 32,
                });
                RejectDuplicates(document.RootElement, "$");
                return JsonSerializer.Deserialize<T>(json, Options)
                    ?? throw new InvalidDataException($"Personal {label} is empty.");
            }
            catch (JsonException exception)
            {
                throw new InvalidDataException($"Personal {label} JSON is invalid.", exception);
            }
        }

        private static void RejectDuplicates(JsonElement element, string path)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in element.EnumerateObject())
                {
                    if (!names.Add(property.Name))
                    {
                        throw new InvalidDataException(
                            $"Personal signing ledger contains duplicate member '{property.Name}' at {path}.");
                    }
                    RejectDuplicates(property.Value, $"{path}.{property.Name}");
                }
            }
            else if (element.ValueKind == JsonValueKind.Array)
            {
                var index = 0;
                foreach (var item in element.EnumerateArray())
                {
                    RejectDuplicates(item, $"{path}[{index++}]");
                }
            }
        }
    }
}
