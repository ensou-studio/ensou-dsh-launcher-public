using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.UpdateEngine;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PersonalInstallProvenance
{
    public required int SchemaVersion { get; init; }

    public required string Product { get; init; }

    public required string StateBindingSha256 { get; init; }

    public required PersonalReleaseSecurityState SecurityState { get; init; }

    public required DateTimeOffset CapturedAtUtc { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PersonalInstallProvenanceCommitMarker
{
    public required int SchemaVersion { get; init; }

    public required string Product { get; init; }

    public required string StateBindingSha256 { get; init; }

    public required string ProvenanceSha256 { get; init; }

    public required DateTimeOffset PreparedAtUtc { get; init; }
}

/// <summary>
/// Installer-agnostic, dual-root high-water witness. The two CurrentUser-DPAPI
/// copies carry the complete authenticated v2 state needed after an authorized
/// uninstall. Missing one copy is repairable from the other; an unexplained
/// disagreement is never resolved by choosing a winner.
/// </summary>
internal sealed class PersonalInstallProvenanceStore
{
    private const int SchemaVersion = 1;
    private const int MaximumProtectedBytes = 4 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 64,
        NumberHandling = JsonNumberHandling.Strict,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = false,
    };

    private readonly PersonalInstallationLayout _layout;
    private readonly TimeProvider _timeProvider;
    private readonly string _binding;
    private readonly string _primaryRoot;
    private readonly string _witnessRoot;
    private readonly string _primaryPath;
    private readonly string _witnessPath;
    private readonly string _primaryPendingPath;
    private readonly string _witnessPendingPath;
    private readonly string _markerPath;
    private readonly byte[] _primaryEntropy;
    private readonly byte[] _witnessEntropy;
    private readonly byte[] _markerEntropy;

    public PersonalInstallProvenanceStore(
        PersonalInstallationLayout layout,
        TimeProvider timeProvider)
    {
        _layout = layout ?? throw new ArgumentNullException(nameof(layout));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _binding = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{PersonalReleaseSetContract.Product}|{layout.UpdateSecurityStatePath}|personal-install-provenance-binding-v1")));
        var roamingSecurityParent = Path.GetDirectoryName(layout.UpdateSecurityWitnessPath)
            ?? throw new InvalidDataException(
                "Personal update witness has no parent for install provenance.");
        var localManagedParent = Path.GetDirectoryName(layout.ManagedRoot)
            ?? throw new InvalidDataException(
                "Personal managed root has no parent for install provenance.");
        _primaryRoot = Path.Combine(
            roamingSecurityParent,
            "personal-install-provenance-primary");
        _witnessRoot = Path.Combine(
            localManagedParent,
            ".DshLauncherInstallProvenanceWitness");
        var fileName = $"personal-install-provenance-{_binding[..24]}.v1.dpapi";
        _primaryPath = Path.Combine(_primaryRoot, fileName);
        _witnessPath = Path.Combine(_witnessRoot, fileName);
        _primaryPendingPath = _primaryPath + ".pending";
        _witnessPendingPath = _witnessPath + ".pending";
        _markerPath = Path.Combine(
            layout.UpdateOperationLockRoot,
            $"personal-install-provenance-{_binding[..24]}.commit.dpapi");
        _primaryEntropy = Entropy("primary");
        _witnessEntropy = Entropy("witness");
        _markerEntropy = Entropy("commit");
        RequireIndependentRoots();
    }

    internal string PrimaryPath => _primaryPath;

    internal string WitnessPath => _witnessPath;

    internal IReadOnlyList<string> EvidencePaths =>
    [
        _primaryPath,
        _witnessPath,
        _primaryPendingPath,
        _witnessPendingPath,
        _markerPath,
    ];

    /// <summary>
    /// Reads enough authenticated provenance to classify an existing v2
    /// installation without creating roots, lock files, repairing copies, or
    /// deleting interrupted-write residue. The ordinary transaction path
    /// repeats validation and performs any authorized repair under its lease.
    /// </summary>
    internal PersonalInstallProvenance? TryReadAuthenticatedForPreflight()
    {
        var marker = ReadMarkerIfPresent();
        if (marker is not null)
        {
            var candidates = new[]
            {
                ReadCopyIfPresent(_primaryPendingPath, _primaryEntropy, "pending primary"),
                ReadCopyIfPresent(_witnessPendingPath, _witnessEntropy, "pending witness"),
                ReadCopyIfPresent(_primaryPath, _primaryEntropy, "primary during preflight"),
                ReadCopyIfPresent(_witnessPath, _witnessEntropy, "witness during preflight"),
            }.Where(value => value is not null)
                .Cast<PersonalInstallProvenance>()
                .Where(value => string.Equals(
                    Sha256(Serialize(value)),
                    marker.ProvenanceSha256,
                    StringComparison.Ordinal))
                .ToArray();
            if (candidates.Length == 0)
            {
                throw new InvalidDataException(
                    "Personal install provenance commit marker has no authenticated preflight witness.");
            }
            foreach (var candidate in candidates.Skip(1))
            {
                RequireEqual(candidates[0], candidate);
            }
            return candidates[0];
        }

        var primary = ReadCopyIfPresent(
            _primaryPath,
            _primaryEntropy,
            "preflight primary");
        var witness = ReadCopyIfPresent(
            _witnessPath,
            _witnessEntropy,
            "preflight witness");
        if (primary is null && witness is null)
        {
            if (EvidencePaths.Skip(2).Any(path => File.Exists(path) || Directory.Exists(path)))
            {
                throw new InvalidDataException(
                    "Personal install provenance has only unauthenticated partial-write evidence.");
            }
            return null;
        }
        if (primary is not null && witness is not null)
        {
            RequireEqual(primary, witness);
        }
        return primary ?? witness;
    }

    internal void WriteWitnessForTests(PersonalInstallProvenance value)
    {
        Validate(value);
        EnsureRoots();
        WriteCopy(_witnessPath, value, _witnessEntropy);
    }

    public PersonalInstallProvenance? TryReadAndRepair()
    {
        EnsureRoots();
        RecoverPreparedCommit();
        var primary = ReadCopyIfPresent(_primaryPath, _primaryEntropy, "primary");
        var witness = ReadCopyIfPresent(_witnessPath, _witnessEntropy, "witness");
        if (primary is null && witness is null)
        {
            DeleteUncommittedPendingIfPresent(_primaryPendingPath);
            DeleteUncommittedPendingIfPresent(_witnessPendingPath);
            return null;
        }
        if (primary is null)
        {
            WriteCopy(_primaryPath, witness!, _primaryEntropy);
            primary = ReadCopy(_primaryPath, _primaryEntropy, "repaired primary");
        }
        if (witness is null)
        {
            WriteCopy(_witnessPath, primary, _witnessEntropy);
            witness = ReadCopy(_witnessPath, _witnessEntropy, "repaired witness");
        }
        RequireEqual(primary, witness);
        DeleteUncommittedPendingIfPresent(_primaryPendingPath);
        DeleteUncommittedPendingIfPresent(_witnessPendingPath);
        return primary;
    }

    public PersonalInstallProvenance WriteFromSecurityState(
        PersonalReleaseSecurityState securityState)
    {
        ArgumentNullException.ThrowIfNull(securityState);
        CreateSecurityStore(securityState.Channel).RequireValidProvenanceState(securityState);
        var proposed = new PersonalInstallProvenance
        {
            SchemaVersion = SchemaVersion,
            Product = "Ensou.Dsh.Personal.InstallProvenance",
            StateBindingSha256 = _binding,
            SecurityState = securityState,
            CapturedAtUtc = MaxUtc(
                RequireUtc(_timeProvider.GetUtcNow()),
                securityState.TrustedTimeUtc),
        };
        Validate(proposed);
        var previous = TryReadAndRepair();
        if (previous is not null)
        {
            RequireNonRollback(previous.SecurityState, proposed.SecurityState);
        }
        var canonical = Serialize(proposed);
        var marker = new PersonalInstallProvenanceCommitMarker
        {
            SchemaVersion = SchemaVersion,
            Product = "Ensou.Dsh.Personal.InstallProvenanceCommit",
            StateBindingSha256 = _binding,
            ProvenanceSha256 = Sha256(canonical),
            PreparedAtUtc = RequireUtc(_timeProvider.GetUtcNow()),
        };
        WriteCopy(_primaryPendingPath, proposed, _primaryEntropy);
        WriteCopy(_witnessPendingPath, proposed, _witnessEntropy);
        WriteMarker(marker);
        WriteCopy(_primaryPath, proposed, _primaryEntropy);
        WriteCopy(_witnessPath, proposed, _witnessEntropy);
        RequireEqual(
            ReadCopy(_primaryPath, _primaryEntropy, "committed primary"),
            ReadCopy(_witnessPath, _witnessEntropy, "committed witness"));
        DeleteOwnedFile(_primaryPendingPath);
        DeleteOwnedFile(_witnessPendingPath);
        DeleteOwnedFile(_markerPath);
        return proposed;
    }

    public DateTimeOffset RequireCandidateAdvance(
        PersonalInstallProvenance provenance,
        VerifiedPersonalReleaseSetManifest candidate,
        DateTimeOffset observedNowUtc)
    {
        ArgumentNullException.ThrowIfNull(provenance);
        ArgumentNullException.ThrowIfNull(candidate);
        Validate(provenance);
        observedNowUtc = RequireUtc(observedNowUtc);
        var previous = provenance.SecurityState;
        var manifest = candidate.Manifest;
        var sameManifest = string.Equals(
            candidate.CanonicalSignedManifestSha256,
            previous.LastVerifiedManifestSha256,
            StringComparison.Ordinal);
        if (sameManifest)
        {
            if (manifest.Generation != previous.HighestGeneration
                || manifest.Sequence != previous.HighestSequence)
            {
                throw new InvalidDataException(
                    "Personal reinstall manifest digest reused a different high-water tuple.");
            }
        }
        else if (manifest.Generation <= previous.HighestGeneration
            || manifest.Sequence <= previous.HighestSequence)
        {
            throw new InvalidDataException(
                "Personal Installer manifest does not strictly advance the preserved release high-water mark.");
        }
        if (manifest.MinAcceptedSequence < previous.MinAcceptedSequence
            || previous.RevokedReleaseSetIds.Except(
                manifest.RevokedReleaseSetIds,
                StringComparer.Ordinal).Any()
            || previous.RevokedReleaseSetIds.Contains(
                manifest.ReleaseSetId,
                StringComparer.Ordinal)
            || previous.FailedReleaseQuarantine.Any(failure => string.Equals(
                failure.ReleaseSetId,
                manifest.ReleaseSetId,
                StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "Personal Installer manifest reduces a preserved floor, revocation, or failed-release quarantine.");
        }
        return observedNowUtc > previous.TrustedTimeUtc
            ? observedNowUtc
            : previous.TrustedTimeUtc;
    }

    internal static void RequireNotBehind(
        PersonalReleaseSecurityState previous,
        PersonalReleaseSecurityState proposed) =>
        RequireNonRollback(previous, proposed);

    internal static void RequireMatchingFootprint(
        PersonalInstallProvenance provenance,
        PersonalV2MigrationFootprint footprint)
    {
        ArgumentNullException.ThrowIfNull(provenance);
        ArgumentNullException.ThrowIfNull(footprint);
        var first = provenance.SecurityState.AcceptedReleases
            .OrderBy(release => release.Sequence)
            .ThenBy(release => release.ReleaseSetId, StringComparer.Ordinal)
            .FirstOrDefault()
            ?? throw new InvalidDataException(
                "Personal install provenance has no first accepted release.");
        if (!string.Equals(
                footprint.FirstChannel,
                provenance.SecurityState.Channel,
                StringComparison.Ordinal)
            || !string.Equals(
                footprint.FirstReleaseSetId,
                first.ReleaseSetId,
                StringComparison.Ordinal)
            || footprint.FirstGeneration != first.Generation
            || footprint.FirstSequence != first.Sequence
            || !string.Equals(
                footprint.FirstManifestSha256,
                first.ManifestSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal install provenance and one-way v2 migration footprint disagree.");
        }
    }

    internal static void RequireMatchingSecurityState(
        PersonalInstallProvenance provenance,
        PersonalReleaseSecurityState securityState)
    {
        ArgumentNullException.ThrowIfNull(provenance);
        ArgumentNullException.ThrowIfNull(securityState);
        var expected = JsonSerializer.SerializeToUtf8Bytes(
            provenance.SecurityState,
            JsonOptions);
        var actual = JsonSerializer.SerializeToUtf8Bytes(
            securityState,
            JsonOptions);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(expected, actual))
            {
                throw new InvalidDataException(
                    "Personal install provenance and release security state disagree.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    private void RecoverPreparedCommit()
    {
        var marker = ReadMarkerIfPresent();
        if (marker is null)
        {
            return;
        }
        var candidates = new[]
        {
            ReadCopyIfPresent(_primaryPendingPath, _primaryEntropy, "pending primary"),
            ReadCopyIfPresent(_witnessPendingPath, _witnessEntropy, "pending witness"),
            ReadCopyIfPresent(_primaryPath, _primaryEntropy, "primary during recovery"),
            ReadCopyIfPresent(_witnessPath, _witnessEntropy, "witness during recovery"),
        }.Where(value => value is not null)
            .Cast<PersonalInstallProvenance>()
            .Where(value => string.Equals(
                Sha256(Serialize(value)),
                marker.ProvenanceSha256,
                StringComparison.Ordinal))
            .ToArray();
        if (candidates.Length == 0)
        {
            throw new InvalidDataException(
                "Personal install provenance commit marker has no matching complete witness.");
        }
        foreach (var candidate in candidates.Skip(1))
        {
            RequireEqual(candidates[0], candidate);
        }
        WriteCopy(_primaryPath, candidates[0], _primaryEntropy);
        WriteCopy(_witnessPath, candidates[0], _witnessEntropy);
        DeleteOwnedFile(_primaryPendingPath);
        DeleteOwnedFile(_witnessPendingPath);
        DeleteOwnedFile(_markerPath);
    }

    private PersonalInstallProvenance? ReadCopyIfPresent(
        string path,
        byte[] entropy,
        string label)
    {
        if (!File.Exists(path))
        {
            if (Directory.Exists(path))
            {
                throw new InvalidDataException(
                    $"Personal install provenance {label} is unexpectedly a directory.");
            }
            return null;
        }
        return ReadCopy(path, entropy, label);
    }

    private PersonalInstallProvenance ReadCopy(
        string path,
        byte[] entropy,
        string label)
    {
        var plaintext = ReadProtected(path, entropy, label);
        try
        {
            RejectDuplicateProperties(plaintext, label);
            var value = JsonSerializer.Deserialize<PersonalInstallProvenance>(plaintext, JsonOptions)
                ?? throw new InvalidDataException(
                    $"Personal install provenance {label} is empty.");
            Validate(value);
            return value;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                $"Personal install provenance {label} JSON is invalid.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private PersonalInstallProvenanceCommitMarker? ReadMarkerIfPresent()
    {
        if (!File.Exists(_markerPath))
        {
            if (Directory.Exists(_markerPath))
            {
                throw new InvalidDataException(
                    "Personal install provenance commit marker is unexpectedly a directory.");
            }
            return null;
        }
        var plaintext = ReadProtected(_markerPath, _markerEntropy, "commit marker");
        try
        {
            RejectDuplicateProperties(plaintext, "commit marker");
            var marker = JsonSerializer.Deserialize<PersonalInstallProvenanceCommitMarker>(
                    plaintext,
                    JsonOptions)
                ?? throw new InvalidDataException(
                    "Personal install provenance commit marker is empty.");
            if (marker.SchemaVersion != SchemaVersion
                || !string.Equals(
                    marker.Product,
                    "Ensou.Dsh.Personal.InstallProvenanceCommit",
                    StringComparison.Ordinal)
                || !string.Equals(marker.StateBindingSha256, _binding, StringComparison.Ordinal)
                || !PersonalReleaseSetValidator.IsSha256(marker.ProvenanceSha256)
                || marker.PreparedAtUtc.Offset != TimeSpan.Zero)
            {
                throw new InvalidDataException(
                    "Personal install provenance commit marker is invalid.");
            }
            return marker;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private void WriteCopy(
        string path,
        PersonalInstallProvenance value,
        byte[] entropy) => WriteProtected(path, Serialize(value), entropy);

    private void WriteMarker(PersonalInstallProvenanceCommitMarker marker) =>
        WriteProtected(
            _markerPath,
            JsonSerializer.SerializeToUtf8Bytes(marker, JsonOptions),
            _markerEntropy);

    private void WriteProtected(string path, byte[] plaintext, byte[] entropy)
    {
        var parent = Path.GetDirectoryName(path)
            ?? throw new InvalidDataException(
                "Personal install provenance file has no parent directory.");
        PersonalPathGuard.EnsureIndependentDirectory(parent);
        if (File.Exists(path))
        {
            PersonalPathGuard.RequireSingleLinkFile(path);
        }
        var protectedBytes = ProtectedData.Protect(
            plaintext,
            entropy,
            DataProtectionScope.CurrentUser);
        var temporary = Path.Combine(
            parent,
            $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       16 * 1024,
                       FileOptions.WriteThrough))
            {
                stream.Write(protectedBytes);
                stream.Flush(flushToDisk: true);
            }
            PersonalPathGuard.RequireSingleLinkFile(temporary);
            File.Move(temporary, path, overwrite: true);
            PersonalPathGuard.RequireSingleLinkFile(path);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private byte[] ReadProtected(string path, byte[] entropy, string label)
    {
        PersonalPathGuard.RequireSingleLinkFile(path);
        var protectedBytes = File.ReadAllBytes(path);
        if (protectedBytes.Length is <= 0 or > MaximumProtectedBytes)
        {
            throw new InvalidDataException(
                $"Personal install provenance {label} is empty or unbounded.");
        }
        try
        {
            var plaintext = ProtectedData.Unprotect(
                protectedBytes,
                entropy,
                DataProtectionScope.CurrentUser);
            if (plaintext.Length is <= 0 or > MaximumProtectedBytes)
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw new InvalidDataException(
                    $"Personal install provenance {label} plaintext is unbounded.");
            }
            return plaintext;
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                $"Personal install provenance {label} is not valid for this Windows user.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    private void Validate(PersonalInstallProvenance value)
    {
        if (value.SchemaVersion != SchemaVersion
            || !string.Equals(
                value.Product,
                "Ensou.Dsh.Personal.InstallProvenance",
                StringComparison.Ordinal)
            || !string.Equals(value.StateBindingSha256, _binding, StringComparison.Ordinal)
            || value.SecurityState is null
            || value.CapturedAtUtc.Offset != TimeSpan.Zero
            || value.CapturedAtUtc < value.SecurityState.TrustedTimeUtc)
        {
            throw new InvalidDataException("Personal install provenance identity is invalid.");
        }
        CreateSecurityStore(value.SecurityState.Channel)
            .RequireValidProvenanceState(value.SecurityState);
    }

    private static void RequireNonRollback(
        PersonalReleaseSecurityState previous,
        PersonalReleaseSecurityState proposed)
    {
        if (!string.Equals(previous.Product, proposed.Product, StringComparison.Ordinal)
            || !string.Equals(previous.Environment, proposed.Environment, StringComparison.Ordinal)
            || !string.Equals(previous.Channel, proposed.Channel, StringComparison.Ordinal)
            || proposed.StateRevision < previous.StateRevision
            || proposed.StateRevision == previous.StateRevision
                && !string.Equals(
                    proposed.StateCommitId,
                    previous.StateCommitId,
                    StringComparison.Ordinal)
            || proposed.HighestGeneration < previous.HighestGeneration
            || proposed.HighestSequence < previous.HighestSequence
            || proposed.MinAcceptedSequence < previous.MinAcceptedSequence
            || proposed.TrustedTimeUtc < previous.TrustedTimeUtc
            || previous.RevokedReleaseSetIds.Except(
                proposed.RevokedReleaseSetIds,
                StringComparer.Ordinal).Any()
            || previous.LastCommittedReleaseSetId is not null
                && (proposed.LastCommittedReleaseSetId is null
                    || proposed.LastCommittedSequence is null
                    || proposed.LastCommittedManifestSha256 is null))
        {
            throw new InvalidDataException(
                "Personal install provenance update attempts to reduce a release high-water mark.");
        }
    }

    private static void RequireEqual(
        PersonalInstallProvenance left,
        PersonalInstallProvenance right)
    {
        if (!Serialize(left).AsSpan().SequenceEqual(Serialize(right)))
        {
            throw new InvalidDataException(
                "Personal install provenance primary and witness disagree.");
        }
    }

    private void EnsureRoots()
    {
        PersonalPathGuard.EnsureIndependentDirectory(_primaryRoot);
        PersonalPathGuard.EnsureIndependentDirectory(_witnessRoot);
        _layout.EnsureUpdateOperationLockRoot();
    }

    private void RequireIndependentRoots()
    {
        foreach (var root in new[] { _primaryRoot, _witnessRoot })
        {
            if (PersonalPathGuard.IsSameOrDescendant(root, _layout.ManagedRoot)
                || PersonalPathGuard.IsSameOrDescendant(_layout.ManagedRoot, root)
                || PersonalPathGuard.IsSameOrDescendant(root, _layout.HarnessHome)
                || PersonalPathGuard.IsSameOrDescendant(_layout.HarnessHome, root))
            {
                throw new InvalidDataException(
                    "Personal install provenance roots must be independent from program and user data.");
            }
        }
        if (PersonalPathGuard.IsSameOrDescendant(_primaryRoot, _witnessRoot)
            || PersonalPathGuard.IsSameOrDescendant(_witnessRoot, _primaryRoot))
        {
            throw new InvalidDataException(
                "Personal install provenance primary and witness roots must be independent.");
        }
        var markerRoot = Path.GetDirectoryName(_markerPath)
            ?? throw new InvalidDataException(
                "Personal install provenance commit marker has no parent root.");
        foreach (var root in new[] { _primaryRoot, _witnessRoot })
        {
            if (PersonalPathGuard.IsSameOrDescendant(root, markerRoot)
                || PersonalPathGuard.IsSameOrDescendant(markerRoot, root))
            {
                throw new InvalidDataException(
                    "Personal install provenance copies and commit marker must use independent roots.");
            }
        }
    }

    private PersonalReleaseSecurityStateStore CreateSecurityStore(string channel) => new(
        _layout.UpdateSecurityStatePath,
        new PersonalReleaseStateIdentity(
            PersonalReleaseSetContract.Product,
            PersonalReleaseSetContract.ProductionEnvironment,
            channel),
        _layout.UpdateSecurityWitnessPath);

    private void DeleteUncommittedPendingIfPresent(string path)
    {
        if (File.Exists(path))
        {
            DeleteOwnedFile(path);
        }
        else if (Directory.Exists(path))
        {
            throw new InvalidDataException(
                "Personal install provenance pending path is unexpectedly a directory.");
        }
    }

    private static void DeleteOwnedFile(string path)
    {
        if (!File.Exists(path))
        {
            return;
        }
        PersonalPathGuard.RequireSingleLinkFile(path);
        File.Delete(path);
    }

    private byte[] Entropy(string role) => SHA256.HashData(Encoding.UTF8.GetBytes(
        $"{PersonalReleaseSetContract.Product}|{_binding}|personal-install-provenance-{role}-v1"));

    private static byte[] Serialize(PersonalInstallProvenance value) =>
        JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static DateTimeOffset RequireUtc(DateTimeOffset value) =>
        value.Offset == TimeSpan.Zero && value > DateTimeOffset.UnixEpoch
            ? value
            : throw new InvalidDataException(
                "Personal install provenance time must be valid UTC.");

    private static DateTimeOffset MaxUtc(DateTimeOffset left, DateTimeOffset right) =>
        left >= right ? left : right;

    private static void RejectDuplicateProperties(ReadOnlySpan<byte> bytes, string label)
    {
        using var document = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 64,
        });
        RejectDuplicateProperties(document.RootElement, label);
    }

    private static void RejectDuplicateProperties(JsonElement element, string path)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidDataException(
                        $"Personal install provenance contains duplicate property at {path}.");
                }
                RejectDuplicateProperties(property.Value, $"{path}.{property.Name}");
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in element.EnumerateArray())
            {
                RejectDuplicateProperties(item, $"{path}[{index++}]");
            }
        }
    }
}
