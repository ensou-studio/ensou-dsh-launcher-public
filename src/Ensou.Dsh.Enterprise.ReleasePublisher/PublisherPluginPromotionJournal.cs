using System.Security.Cryptography;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.ReleasePublisher;

// This is deliberately separate from the policy-generation ledger.  The latter
// is a reviewer input; this journal records the signer-host consumption of an
// independently authorized production promotion.
internal sealed record PublisherPluginPromotionJournalTrust(string KeyId, string X, string Y)
{
    public void Validate()
    {
        PublisherRuntimeAdmissionEncoding.ValidateToken(KeyId, "plugin promotion journal keyId", 64);
        var x = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(X, "plugin promotion journal key x", 32);
        var y = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(Y, "plugin promotion journal key y", 32);
        try
        {
            using var verifier = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y },
            });
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException("Plugin promotion journal trust is not a valid P-256 point.", exception);
        }
    }

    public void RequireIndependentFrom(
        params (string KeyId, string X, string Y, string Label)[] otherTrustRoots)
    {
        Validate();
        var journalX = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
            X,
            "plugin promotion journal key x",
            32);
        var journalY = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
            Y,
            "plugin promotion journal key y",
            32);
        foreach (var other in otherTrustRoots)
        {
            PublisherRuntimeAdmissionEncoding.ValidateToken(
                other.KeyId,
                $"{other.Label} keyId",
                64);
            var otherX = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
                other.X,
                $"{other.Label} key x",
                32);
            var otherY = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
                other.Y,
                $"{other.Label} key y",
                32);
            if (string.Equals(KeyId, other.KeyId, StringComparison.Ordinal)
                || (CryptographicOperations.FixedTimeEquals(journalX, otherX)
                    && CryptographicOperations.FixedTimeEquals(journalY, otherY)))
            {
                throw new InvalidDataException(
                    "Plugin promotion journal authorization trust must be independent from every release and admission trust root.");
            }
        }
    }
}

internal static class PublisherPluginPromotionJournalTrustResolver
{
    private const string KeyIdName = "EnterprisePluginPromotionJournalKeyId";
    private const string KeyXName = "EnterprisePluginPromotionJournalKeyX";
    private const string KeyYName = "EnterprisePluginPromotionJournalKeyY";

    public static PublisherPluginPromotionJournalTrust ResolveProduction()
    {
        var metadata = typeof(Program).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .ToArray();
        var trust = new PublisherPluginPromotionJournalTrust(
            RequireSingle(metadata, KeyIdName),
            RequireSingle(metadata, KeyXName),
            RequireSingle(metadata, KeyYName));
        trust.Validate();
        return trust;
    }

    private static string RequireSingle(
        IReadOnlyList<AssemblyMetadataAttribute> metadata,
        string name)
    {
        var values = metadata
            .Where(value => string.Equals(value.Key, name, StringComparison.Ordinal))
            .Select(value => value.Value)
            .ToArray();
        if (values.Length != 1 || string.IsNullOrWhiteSpace(values[0]))
        {
            throw new InvalidDataException(
                $"Production publisher assembly is missing exact {name} trust metadata.");
        }
        return values[0]!;
    }
}

internal sealed record PublisherPluginPromotionArtifactIdentity(
    string Component,
    string ReleaseId,
    string Uri,
    long SizeBytes,
    string Sha256,
    string CompleteTreeSha256)
{
    internal void Validate(string expectedComponent)
    {
        if (!string.Equals(Component, expectedComponent, StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(ReleaseId)
            || !System.Uri.TryCreate(Uri, System.UriKind.Absolute, out var parsedUri)
            || parsedUri.Scheme != System.Uri.UriSchemeHttps
            || SizeBytes <= 0
            || !IsSha256(Sha256)
            || !IsSha256(CompleteTreeSha256))
        {
            throw new InvalidDataException($"Plugin promotion {expectedComponent} artifact identity is invalid.");
        }
    }

    internal static bool IsSha256(string? value) => value is { Length: 64 }
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

internal sealed record PublisherPluginPromotionJournalIntent(
    string Environment,
    string Channel,
    string ReleaseSetId,
    string ReleaseSigningKeyId,
    long Generation,
    long Sequence,
    long MinAcceptedSequence,
    PublisherPluginPromotionArtifactIdentity Launcher,
    PublisherPluginPromotionArtifactIdentity Runtime,
    PublisherPluginPromotionArtifactIdentity PluginPolicy,
    string PolicyId,
    long PolicyGeneration,
    string PluginMetadataSha256,
    string RawPolicySha256,
    string PromotionHandoffSha256,
    string CompatibilityReceiptSha256,
    string ReservationSha256,
    string RuntimeSourceMetadataSha256,
    string GenerationLedgerNamespace,
    string GenerationLedgerPathSha256,
    string GenerationLedgerSha256,
    string OrganizationAdmissionReceiptSha256)
{
    internal void Validate()
    {
        if (!string.Equals(Environment, EnterpriseReleaseSetContract.ProductionEnvironment, StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(Channel)
            || string.IsNullOrWhiteSpace(ReleaseSetId)
            || string.IsNullOrWhiteSpace(ReleaseSigningKeyId)
            || Generation <= 0
            || Sequence <= 0
            || MinAcceptedSequence < 0
            || MinAcceptedSequence > Sequence
            || PolicyGeneration <= 0
            || !Guid.TryParse(PolicyId, out _)
            || !PublisherPluginPromotionArtifactIdentity.IsSha256(PluginMetadataSha256)
            || !PublisherPluginPromotionArtifactIdentity.IsSha256(RawPolicySha256)
            || !PublisherPluginPromotionArtifactIdentity.IsSha256(PromotionHandoffSha256)
            || !PublisherPluginPromotionArtifactIdentity.IsSha256(CompatibilityReceiptSha256)
            || !PublisherPluginPromotionArtifactIdentity.IsSha256(ReservationSha256)
            || !PublisherPluginPromotionArtifactIdentity.IsSha256(RuntimeSourceMetadataSha256)
            || string.IsNullOrWhiteSpace(GenerationLedgerNamespace)
            || GenerationLedgerNamespace.Length > 128
            || !char.IsAsciiLetterOrDigit(GenerationLedgerNamespace[0])
            || GenerationLedgerNamespace.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '.' and not '_' and not '+' and not '-')
            || !PublisherPluginPromotionArtifactIdentity.IsSha256(GenerationLedgerPathSha256)
            || !PublisherPluginPromotionArtifactIdentity.IsSha256(GenerationLedgerSha256)
            || !PublisherPluginPromotionArtifactIdentity.IsSha256(OrganizationAdmissionReceiptSha256))
        {
            throw new InvalidDataException("Plugin promotion authorization intent is invalid.");
        }
        Launcher.Validate(EnterpriseReleaseSetContract.LauncherComponent);
        Runtime.Validate(EnterpriseReleaseSetContract.RuntimeComponent);
        PluginPolicy.Validate(EnterpriseReleaseSetContract.PluginPolicyComponent);
    }

    internal byte[] CanonicalPayload()
    {
        Validate();
        return Encoding.UTF8.GetBytes(string.Join('\n',
            "ensou-dsh-enterprise-plugin-promotion-intent-v1",
            Environment,
            Channel,
            ReleaseSetId,
            ReleaseSigningKeyId,
            Generation.ToString(System.Globalization.CultureInfo.InvariantCulture),
            Sequence.ToString(System.Globalization.CultureInfo.InvariantCulture),
            MinAcceptedSequence.ToString(System.Globalization.CultureInfo.InvariantCulture),
            CanonicalArtifact(Launcher),
            CanonicalArtifact(Runtime),
            CanonicalArtifact(PluginPolicy),
            PolicyId,
            PolicyGeneration.ToString(System.Globalization.CultureInfo.InvariantCulture),
            PluginMetadataSha256,
            RawPolicySha256,
            PromotionHandoffSha256,
            CompatibilityReceiptSha256,
            ReservationSha256,
            RuntimeSourceMetadataSha256,
            GenerationLedgerNamespace,
            GenerationLedgerPathSha256,
            GenerationLedgerSha256,
            OrganizationAdmissionReceiptSha256));
    }

    private static string CanonicalArtifact(PublisherPluginPromotionArtifactIdentity value) => string.Join('|',
        value.Component, value.ReleaseId, value.Uri,
        value.SizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
        value.Sha256, value.CompleteTreeSha256);
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginPromotionJournalAuthorization
{
    public const string CurrentAuthorizationType = "managed-plugin-promotion-journal-authorization";

    public required int SchemaVersion { get; init; }
    public required string AuthorizationType { get; init; }
    public required string AuthorizationId { get; init; }
    public required string JournalInstanceId { get; init; }
    public required long ExpectedStateRevision { get; init; }
    public required string ExpectedHeadSha256 { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset ExpiresAtUtc { get; init; }
    public required PublisherPluginPromotionJournalIntent Intent { get; init; }
    public required EnterpriseReleaseSignature Signature { get; init; }

    public static PublisherPluginPromotionJournalAuthorization Parse(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is <= 0 or > 256 * 1024)
        {
            throw new InvalidDataException("Plugin promotion journal authorization size is invalid.");
        }
        try
        {
            using var document = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 32,
            });
            RequireNoDuplicateMembers(document.RootElement);
            RequireExactProperties(document.RootElement,
                "schemaVersion", "authorizationType", "authorizationId", "journalInstanceId",
                "expectedStateRevision", "expectedHeadSha256", "issuedAtUtc", "expiresAtUtc",
                "intent", "signature");
            RequireExactProperties(document.RootElement.GetProperty("intent"),
                "environment", "channel", "releaseSetId", "releaseSigningKeyId", "generation", "sequence",
                "minAcceptedSequence",
                "launcher", "runtime", "pluginPolicy", "policyId", "policyGeneration", "pluginMetadataSha256",
                "rawPolicySha256", "promotionHandoffSha256", "compatibilityReceiptSha256", "reservationSha256",
                "runtimeSourceMetadataSha256", "generationLedgerNamespace", "generationLedgerPathSha256",
                "generationLedgerSha256", "organizationAdmissionReceiptSha256");
            foreach (var artifact in new[] { "launcher", "runtime", "pluginPolicy" })
            {
                RequireExactProperties(document.RootElement.GetProperty("intent").GetProperty(artifact),
                    "component", "releaseId", "uri", "sizeBytes", "sha256", "completeTreeSha256");
            }
            RequireExactProperties(document.RootElement.GetProperty("signature"), "algorithm", "keyId", "value");
            return JsonSerializer.Deserialize<PublisherPluginPromotionJournalAuthorization>(bytes.ToArray(), JsonOptions)
                ?? throw new InvalidDataException("Plugin promotion journal authorization is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Plugin promotion journal authorization JSON is invalid.", exception);
        }
    }

    public void Verify(PublisherPluginPromotionJournalTrust trust, DateTimeOffset nowUtc, bool requireCurrentValidity)
    {
        ArgumentNullException.ThrowIfNull(trust);
        trust.Validate();
        if (SchemaVersion != 1
            || !string.Equals(AuthorizationType, CurrentAuthorizationType, StringComparison.Ordinal)
            || !Guid.TryParseExact(AuthorizationId, "D", out _)
            || !Guid.TryParseExact(JournalInstanceId, "D", out _)
            || ExpectedStateRevision < 0
            || !PublisherPluginPromotionArtifactIdentity.IsSha256(ExpectedHeadSha256)
            || IssuedAtUtc.Offset != TimeSpan.Zero
            || ExpiresAtUtc.Offset != TimeSpan.Zero
            || ExpiresAtUtc <= IssuedAtUtc
            || ExpiresAtUtc - IssuedAtUtc > TimeSpan.FromHours(24)
            || Intent is null
            || Signature is null
            || !string.Equals(Signature.Algorithm, EnterpriseReleaseSetContract.SignatureAlgorithm, StringComparison.Ordinal)
            || !string.Equals(Signature.KeyId, trust.KeyId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Plugin promotion journal authorization identity is invalid.");
        }
        if (requireCurrentValidity && (nowUtc < IssuedAtUtc - TimeSpan.FromMinutes(5) || nowUtc > ExpiresAtUtc))
        {
            throw new InvalidDataException("Plugin promotion journal authorization is not currently valid.");
        }
        Intent.Validate();
        var signature = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
            Signature.Value, "plugin promotion journal authorization signature", 64);
        var x = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(trust.X, "plugin promotion journal key x", 32);
        var y = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(trust.Y, "plugin promotion journal key y", 32);
        using var verifier = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = x, Y = y },
        });
        if (!verifier.VerifyData(CanonicalPayload(), signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            throw new InvalidDataException("Plugin promotion journal authorization signature verification failed.");
        }
    }

    public byte[] CanonicalPayload() => Encoding.UTF8.GetBytes(string.Join('\n',
        "ensou-dsh-enterprise-plugin-promotion-journal-authorization-v1",
        SchemaVersion.ToString(System.Globalization.CultureInfo.InvariantCulture),
        AuthorizationType,
        AuthorizationId,
        JournalInstanceId,
        ExpectedStateRevision.ToString(System.Globalization.CultureInfo.InvariantCulture),
        ExpectedHeadSha256,
        IssuedAtUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
        ExpiresAtUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
        Convert.ToHexStringLower(SHA256.HashData(Intent.CanonicalPayload()))));

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private static void RequireExactProperties(JsonElement value, params string[] names)
    {
        if (value.ValueKind != JsonValueKind.Object
            || !value.EnumerateObject().Select(property => property.Name).SequenceEqual(names, StringComparer.Ordinal))
        {
            throw new InvalidDataException("Plugin promotion journal authorization has unknown, missing, or reordered properties.");
        }
    }

    private static void RequireNoDuplicateMembers(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidDataException("Plugin promotion journal authorization has duplicate properties.");
                }
                RequireNoDuplicateMembers(property.Value);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in value.EnumerateArray())
            {
                RequireNoDuplicateMembers(item);
            }
        }
    }
}

internal enum PublisherPluginPromotionJournalCommitStage
{
    PendingAnchorWritten,
    EntryWritten,
    HeadReplaced,
    AnchorCommitted,
    PendingDeleted,
}

internal sealed record PublisherPluginPromotionJournalInitialization(
    string JournalInstanceId,
    long StateRevision,
    string HeadSha256,
    string JournalRoot);

internal sealed record PublisherPluginPromotionJournalConsumption(
    string EntryPath,
    string EntrySha256,
    bool RecoveredExactAuthorization);

internal static class PublisherPluginPromotionJournal
{
    private const string Product = "ensou-dsh-enterprise";
    private const string ZeroSha256 = "0000000000000000000000000000000000000000000000000000000000000000";
    private const int MaximumEntries = 100_000;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static PublisherPluginPromotionJournalInitialization Initialize(
        PublisherPluginPromotionJournalTrust trust,
        string? stateRootOverride = null)
    {
        RequireWindows();
        var paths = Paths.Create(trust, stateRootOverride);
        using var anchorLock = paths.AcquireAnchorLock();
        if (File.Exists(paths.AnchorPath) || File.Exists(paths.PendingPath) || Directory.Exists(paths.JournalRoot)
            || File.Exists(paths.HeadPath))
        {
            throw new InvalidDataException("Plugin promotion journal is already initialized or contains residual state.");
        }
        EnsureDirectory(paths.JournalRoot);
        EnsureDirectory(paths.EntriesRoot);
        var anchor = new Anchor(1, Product, paths.JournalRootSha256, Guid.NewGuid().ToString("D"), 0, null);
        paths.WriteProtected(paths.AnchorPath, anchor, overwrite: false);
        return new PublisherPluginPromotionJournalInitialization(anchor.JournalInstanceId, 0, ZeroSha256, paths.JournalRoot);
    }

    public static PublisherPluginPromotionJournalInitialization ReadChallenge(
        PublisherPluginPromotionJournalTrust trust,
        string? stateRootOverride = null)
    {
        RequireWindows();
        var paths = Paths.Create(trust, stateRootOverride);
        using var anchorLock = paths.AcquireAnchorLock();
        using var journalLock = paths.AcquireJournalLock();
        if (File.Exists(paths.PendingPath))
        {
            throw new InvalidDataException(
                "Plugin promotion journal has an in-progress protected transaction; recover it with the exact prior authorization before requesting a new challenge.");
        }
        var anchor = paths.ReadAnchorRequired();
        var snapshot = paths.ReadSnapshot();
        paths.RequireAnchorMatches(anchor, snapshot);
        return new PublisherPluginPromotionJournalInitialization(
            anchor.JournalInstanceId,
            anchor.StateRevision,
            snapshot?.Head.EntrySha256 ?? ZeroSha256,
            paths.JournalRoot);
    }

    public static PublisherPluginPromotionJournalConsumption Consume(
        ReadOnlySpan<byte> authorizationBytes,
        PublisherPluginPromotionJournalTrust trust,
        PublisherPluginPromotionJournalIntent intent,
        DateTimeOffset nowUtc,
        string? stateRootOverride = null,
        Action<PublisherPluginPromotionJournalCommitStage>? checkpoint = null)
    {
        RequireWindows();
        if (nowUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException(
                "Plugin promotion journal consumption clock must be UTC.");
        }
        var raw = authorizationBytes.ToArray();
        try
        {
            var authorization = PublisherPluginPromotionJournalAuthorization.Parse(raw);
            var paths = Paths.Create(trust, stateRootOverride);
            using var anchorLock = paths.AcquireAnchorLock();
            using var journalLock = paths.AcquireJournalLock();
            var anchor = paths.ReadAnchorRequired();
            var authorizationSha256 = Hash(raw);
            var intentSha256 = Hash(intent.CanonicalPayload());
            if (File.Exists(paths.PendingPath))
            {
                authorization.Verify(trust, nowUtc, requireCurrentValidity: false);
                paths.RecoverPending(
                    anchor,
                    authorization,
                    intent,
                    authorizationSha256,
                    intentSha256,
                    trust,
                    nowUtc);
                anchor = paths.ReadAnchorRequired();
            }
            var snapshot = paths.ReadSnapshot();
            paths.RequireAnchorMatches(anchor, snapshot);

            if (snapshot?.Latest.AuthorizationId == authorization.AuthorizationId)
            {
                // A journal commit can become durable immediately before the
                // publication transaction writes its own protected pending state.
                // Replaying the exact latest authorization must therefore be a
                // read-only recovery operation: it returns the already committed
                // journal receipt and never advances the head a second time.
                // RecoverPending independently requires current validity whenever
                // the protected transaction has not advanced the DPAPI anchor. Once
                // that anchor is already at the protected next state, the recorded
                // in-window ConsumedAtUtc is the recovery authority, so an otherwise
                // exact latest retry may finish after the authorization expires.
                authorization.Verify(
                    trust,
                    nowUtc,
                    requireCurrentValidity: false);
                if (!string.Equals(snapshot.Latest.AuthorizationSha256, authorizationSha256, StringComparison.Ordinal)
                    || !string.Equals(snapshot.Latest.IntentSha256, intentSha256, StringComparison.Ordinal)
                    || !IntentEquals(snapshot.Latest.Intent, intent)
                    || snapshot.Latest.ConsumedAtUtc < authorization.IssuedAtUtc
                    || snapshot.Latest.ConsumedAtUtc > authorization.ExpiresAtUtc)
                {
                    throw new InvalidDataException("Plugin promotion authorization replay differs from the exact pending recovery transaction.");
                }
                return new PublisherPluginPromotionJournalConsumption(
                    Path.Combine(paths.EntriesRoot, snapshot.Head.EntryFileName), snapshot.Head.EntrySha256, true);
            }
            if (snapshot is not null && snapshot.AuthorizationIds.Contains(authorization.AuthorizationId, StringComparer.Ordinal))
            {
                throw new InvalidDataException("Plugin promotion journal authorization was already consumed by an older head.");
            }

            authorization.Verify(trust, nowUtc, requireCurrentValidity: true);
            if (!IntentEquals(authorization.Intent, intent)
                || !string.Equals(authorization.JournalInstanceId, anchor.JournalInstanceId, StringComparison.Ordinal)
                || authorization.ExpectedStateRevision != anchor.StateRevision
                || !string.Equals(authorization.ExpectedHeadSha256, snapshot?.Head.EntrySha256 ?? ZeroSha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException("Plugin promotion journal authorization does not bind the current journal state and exact publication intent.");
            }

            var revision = checked(anchor.StateRevision + 1);
            var entry = new Entry(
                1, Product, anchor.JournalInstanceId, revision, authorization.AuthorizationId, authorizationSha256,
                intentSha256, intent, snapshot?.Head.EntryFileName ?? string.Empty,
                snapshot?.Head.EntrySha256 ?? ZeroSha256, nowUtc);
            var entryBytes = Serialize(entry);
            var entrySha256 = Hash(entryBytes);
            var entryName = $"{revision:D20}-{authorization.AuthorizationId}-{intentSha256}.json";
            var head = new Head(1, Product, anchor.JournalInstanceId, revision, entryName, entrySha256);
            var headBytes = Serialize(head);
            var nextAnchor = anchor with { StateRevision = revision, Head = head };
            var pending = new Pending(1, Product, paths.JournalRootSha256, anchor, nextAnchor, entryName, entryBytes, headBytes);
            paths.WriteProtected(paths.PendingPath, pending, overwrite: false);
            checkpoint?.Invoke(PublisherPluginPromotionJournalCommitStage.PendingAnchorWritten);
            WriteCreateNew(Path.Combine(paths.EntriesRoot, entryName), entryBytes);
            checkpoint?.Invoke(PublisherPluginPromotionJournalCommitStage.EntryWritten);
            ReplaceDurable(paths.HeadPath, headBytes);
            checkpoint?.Invoke(PublisherPluginPromotionJournalCommitStage.HeadReplaced);
            paths.WriteProtected(paths.AnchorPath, nextAnchor, overwrite: true);
            checkpoint?.Invoke(PublisherPluginPromotionJournalCommitStage.AnchorCommitted);
            DeleteFile(paths.PendingPath);
            checkpoint?.Invoke(PublisherPluginPromotionJournalCommitStage.PendingDeleted);
            return new PublisherPluginPromotionJournalConsumption(Path.Combine(paths.EntriesRoot, entryName), entrySha256, false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    private static bool IntentEquals(PublisherPluginPromotionJournalIntent left, PublisherPluginPromotionJournalIntent right) =>
        left.CanonicalPayload().AsSpan().SequenceEqual(right.CanonicalPayload());

    private static byte[] Serialize<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
    private static string Hash(ReadOnlySpan<byte> value) => Convert.ToHexStringLower(SHA256.HashData(value));

    private static void RequireWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Plugin promotion journal requires Windows CurrentUser DPAPI.");
        }
    }

    private static void EnsureDirectory(string path)
    {
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        RejectReparseAncestors(full);
        Directory.CreateDirectory(full);
        RejectReparseAncestors(full);
    }

    private static void RejectReparseAncestors(string path)
    {
        for (var current = new DirectoryInfo(Path.GetFullPath(path)); current is not null; current = current.Parent)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("Plugin promotion journal path has a reparse-point ancestor.");
            }
        }
    }

    private static void RequireRegularFile(string path)
    {
        if (!File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Plugin promotion journal file is absent or linked.");
        }
    }

    private static byte[] ReadBounded(string path, int maximum, string label)
    {
        RejectReparseAncestors(path);
        using var stream = PublisherSafeFile.OpenLockedRead(path);
        if (stream.Length <= 0 || stream.Length > maximum || stream.Length > int.MaxValue)
        {
            throw new InvalidDataException($"Plugin promotion journal {label} size is invalid.");
        }
        var bytes = new byte[(int)stream.Length];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1)
        {
            throw new InvalidDataException($"Plugin promotion journal {label} changed while it was read.");
        }
        PublisherSafeFile.RequireExpectedPathAndRegularFile(stream, Path.GetFullPath(path));
        return bytes;
    }

    private static void WriteCreateNew(string path, ReadOnlySpan<byte> bytes)
    {
        var parent = Path.GetDirectoryName(path) ?? throw new InvalidDataException("Plugin promotion journal path has no parent.");
        EnsureDirectory(parent);
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);
        File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.ReadOnly);
    }

    private static void ReplaceDurable(string path, ReadOnlySpan<byte> bytes)
    {
        var parent = Path.GetDirectoryName(path) ?? throw new InvalidDataException("Plugin promotion journal head has no parent.");
        var temporary = Path.Combine(parent, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            WriteCreateNew(temporary, bytes);
            File.SetAttributes(temporary, File.GetAttributes(temporary) & ~FileAttributes.ReadOnly);
            if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReadOnly) != 0)
            {
                File.SetAttributes(path, File.GetAttributes(path) & ~FileAttributes.ReadOnly);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.SetAttributes(temporary, File.GetAttributes(temporary) & ~FileAttributes.ReadOnly);
                File.Delete(temporary);
            }
        }
    }

    private static void DeleteFile(string path)
    {
        if (File.Exists(path))
        {
            RequireRegularFile(path);
            if ((File.GetAttributes(path) & FileAttributes.ReadOnly) != 0)
            {
                File.SetAttributes(path, File.GetAttributes(path) & ~FileAttributes.ReadOnly);
            }
            File.Delete(path);
        }
    }

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record Head(int SchemaVersion, string Product, string JournalInstanceId, long StateRevision, string EntryFileName, string EntrySha256);

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record Anchor(int SchemaVersion, string Product, string JournalRootSha256, string JournalInstanceId, long StateRevision, Head? Head);

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record Entry(
        int SchemaVersion, string Product, string JournalInstanceId, long StateRevision,
        string AuthorizationId, string AuthorizationSha256, string IntentSha256,
        PublisherPluginPromotionJournalIntent Intent, string PreviousEntryFileName,
        string PreviousEntrySha256, DateTimeOffset ConsumedAtUtc);

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record Pending(
        int SchemaVersion, string Product, string JournalRootSha256, Anchor PreviousAnchor,
        Anchor NextAnchor, string EntryFileName, byte[] EntryBytes, byte[] HeadBytes);

    private sealed record Snapshot(Head Head, Entry Latest, IReadOnlySet<string> AuthorizationIds);

    private sealed class Paths
    {
        private const int MaximumProtectedBytes = 2 * 1024 * 1024;
        private readonly byte[] _entropy;

        private Paths(string journalRoot, string authorityRoot, PublisherPluginPromotionJournalTrust trust)
        {
            JournalRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(journalRoot));
            AuthorityRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(authorityRoot));
            EntriesRoot = Path.Combine(JournalRoot, "entries");
            HeadPath = Path.Combine(JournalRoot, "head.json");
            JournalRootSha256 = Hash(Encoding.UTF8.GetBytes(JournalRoot.ToUpperInvariant()));
            var identity = Hash(Encoding.UTF8.GetBytes(string.Join('|', Product, JournalRootSha256, trust.KeyId, trust.X, trust.Y)));
            AnchorPath = Path.Combine(AuthorityRoot, identity + ".dpapi");
            PendingPath = Path.Combine(AuthorityRoot, identity + ".pending.dpapi");
            AnchorLockPath = Path.Combine(AuthorityRoot, identity + ".lock");
            JournalLockPath = Path.Combine(JournalRoot, "journal.lock");
            _entropy = SHA256.HashData(Encoding.UTF8.GetBytes("ensou-dsh-enterprise-plugin-promotion-journal-anchor-v1|" + JournalRootSha256 + "|" + trust.KeyId));
        }

        public string JournalRoot { get; }
        public string AuthorityRoot { get; }
        public string EntriesRoot { get; }
        public string HeadPath { get; }
        public string JournalRootSha256 { get; }
        public string AnchorPath { get; }
        public string PendingPath { get; }
        private string AnchorLockPath { get; }
        private string JournalLockPath { get; }

        public static Paths Create(PublisherPluginPromotionJournalTrust trust, string? overrideRoot)
        {
            trust.Validate();
            string baseRoot;
            if (overrideRoot is null)
            {
                var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData,
                    Environment.SpecialFolderOption.DoNotVerify);
                if (string.IsNullOrWhiteSpace(local))
                {
                    throw new InvalidDataException("Plugin promotion journal cannot resolve the CurrentUser LocalApplicationData root.");
                }
                baseRoot = Path.Combine(local, "Ensou", "Dsh", "EnterpriseReleasePublisher");
            }
            else
            {
                if (!Path.IsPathFullyQualified(overrideRoot))
                {
                    throw new InvalidDataException("Plugin promotion journal test override must be absolute.");
                }
                baseRoot = Path.GetFullPath(overrideRoot);
            }
            return new Paths(Path.Combine(baseRoot, "PluginPromotionJournal", "v1"),
                Path.Combine(baseRoot, "PluginPromotionJournalAnchors"), trust);
        }

        public FileStream AcquireAnchorLock()
        {
            EnsureDirectory(AuthorityRoot);
            return new FileStream(AnchorLockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.WriteThrough);
        }

        public FileStream AcquireJournalLock()
        {
            EnsureDirectory(JournalRoot);
            return new FileStream(JournalLockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.WriteThrough);
        }

        public Anchor ReadAnchorRequired()
        {
            if (!File.Exists(AnchorPath))
            {
                throw new InvalidDataException("Plugin promotion journal independent CurrentUser anchor is missing; explicit reinitialization and a new external authorization are required.");
            }
            var anchor = ReadProtected<Anchor>(AnchorPath, "anchor");
            ValidateAnchor(anchor);
            return anchor;
        }

        public void WriteProtected<T>(string path, T value, bool overwrite)
        {
            var plaintext = Serialize(value);
            byte[]? protectedBytes = null;
            try
            {
                protectedBytes = ProtectedData.Protect(plaintext, _entropy, DataProtectionScope.CurrentUser);
                var parent = Path.GetDirectoryName(path) ?? throw new InvalidDataException("Plugin promotion journal protected state has no parent.");
                EnsureDirectory(parent);
                var temporary = Path.Combine(parent, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
                try
                {
                    WriteCreateNew(temporary, protectedBytes);
                    File.SetAttributes(temporary, File.GetAttributes(temporary) & ~FileAttributes.ReadOnly);
                    if (!overwrite && File.Exists(path))
                    {
                        throw new InvalidDataException("Plugin promotion journal protected state already exists.");
                    }
                    if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReadOnly) != 0)
                    {
                        File.SetAttributes(path, File.GetAttributes(path) & ~FileAttributes.ReadOnly);
                    }
                    File.Move(temporary, path, overwrite);
                }
                finally
                {
                    if (File.Exists(temporary))
                    {
                        DeleteFile(temporary);
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
                if (protectedBytes is not null)
                {
                    CryptographicOperations.ZeroMemory(protectedBytes);
                }
            }
        }

        public void RecoverPending(
            Anchor anchor,
            PublisherPluginPromotionJournalAuthorization authorization,
            PublisherPluginPromotionJournalIntent expectedIntent,
            string authorizationSha256,
            string intentSha256,
            PublisherPluginPromotionJournalTrust trust,
            DateTimeOffset nowUtc)
        {
            var pending = ReadProtected<Pending>(PendingPath, "pending transaction");
            try
            {
                if (pending.SchemaVersion != 1 || !string.Equals(pending.Product, Product, StringComparison.Ordinal)
                    || !string.Equals(pending.JournalRootSha256, JournalRootSha256, StringComparison.Ordinal))
                {
                    throw new InvalidDataException("Plugin promotion journal pending transaction identity is invalid.");
                }
                ValidateAnchor(pending.PreviousAnchor);
                ValidateAnchor(pending.NextAnchor);
                var entry = Parse<Entry>(pending.EntryBytes, "pending entry");
                var head = Parse<Head>(pending.HeadBytes, "pending head");
                ValidateEntry(entry);
                ValidateHead(head);
                var previousHeadSha256 = pending.PreviousAnchor.Head?.EntrySha256 ?? ZeroSha256;
                var previousEntryFileName = pending.PreviousAnchor.Head?.EntryFileName ?? string.Empty;
                if (!string.Equals(authorization.JournalInstanceId, pending.PreviousAnchor.JournalInstanceId, StringComparison.Ordinal)
                    || authorization.ExpectedStateRevision != pending.PreviousAnchor.StateRevision
                    || !string.Equals(authorization.ExpectedHeadSha256, previousHeadSha256, StringComparison.Ordinal)
                    || !string.Equals(entry.JournalInstanceId, pending.PreviousAnchor.JournalInstanceId, StringComparison.Ordinal)
                    || entry.StateRevision != checked(pending.PreviousAnchor.StateRevision + 1)
                    || pending.NextAnchor.StateRevision != entry.StateRevision
                    || !string.Equals(entry.AuthorizationId, authorization.AuthorizationId, StringComparison.Ordinal)
                    || !string.Equals(entry.AuthorizationSha256, authorizationSha256, StringComparison.Ordinal)
                    || !string.Equals(entry.IntentSha256, intentSha256, StringComparison.Ordinal)
                    || !IntentEquals(authorization.Intent, expectedIntent)
                    || !IntentEquals(entry.Intent, expectedIntent)
                    || entry.ConsumedAtUtc < authorization.IssuedAtUtc
                    || entry.ConsumedAtUtc > authorization.ExpiresAtUtc
                    || !string.Equals(entry.PreviousEntryFileName, previousEntryFileName, StringComparison.Ordinal)
                    || !string.Equals(entry.PreviousEntrySha256, previousHeadSha256, StringComparison.Ordinal)
                    || !string.Equals(head.EntryFileName, pending.EntryFileName, StringComparison.Ordinal)
                    || !string.Equals(head.EntrySha256, Hash(pending.EntryBytes), StringComparison.Ordinal)
                    || !AnchorEquals(pending.NextAnchor, pending.NextAnchor with { Head = head }))
                {
                    throw new InvalidDataException(
                        "Plugin promotion journal pending transaction is not bound to the exact external authorization and previous journal state.");
                }
                var isPrevious = AnchorEquals(anchor, pending.PreviousAnchor);
                var isNext = AnchorEquals(anchor, pending.NextAnchor);
                if (!isPrevious && !isNext)
                {
                    throw new InvalidDataException("Plugin promotion journal pending transaction does not extend the independent anchor.");
                }
                if (isPrevious)
                {
                    // The independent anchor is the commit point. Before it moves,
                    // recovery would still consume the authorization and therefore
                    // must occur within the external authorization window.
                    authorization.Verify(trust, nowUtc, requireCurrentValidity: true);
                }
                var entryPath = Path.Combine(EntriesRoot, pending.EntryFileName);
                if (File.Exists(entryPath))
                {
                    if (!ReadBounded(entryPath, 512 * 1024, "pending entry").AsSpan().SequenceEqual(pending.EntryBytes))
                    {
                        throw new InvalidDataException("Plugin promotion journal pending entry differs from the protected transaction.");
                    }
                }
                else
                {
                    WriteCreateNew(entryPath, pending.EntryBytes);
                }
                if (!File.Exists(HeadPath) || !ReadBounded(HeadPath, 128 * 1024, "head").AsSpan().SequenceEqual(pending.HeadBytes))
                {
                    ReplaceDurable(HeadPath, pending.HeadBytes);
                }
                var snapshot = ReadSnapshot();
                RequireAnchorMatches(pending.NextAnchor, snapshot);
                if (isPrevious)
                {
                    WriteProtected(AnchorPath, pending.NextAnchor, overwrite: true);
                }
                DeleteFile(PendingPath);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pending.EntryBytes);
                CryptographicOperations.ZeroMemory(pending.HeadBytes);
            }
        }

        public Snapshot? ReadSnapshot()
        {
            if (!Directory.Exists(EntriesRoot))
            {
                if (File.Exists(HeadPath))
                {
                    throw new InvalidDataException("Plugin promotion journal head exists without an entry directory.");
                }
                return null;
            }
            RejectReparseAncestors(EntriesRoot);
            var entryPaths = Directory.EnumerateFileSystemEntries(
                EntriesRoot,
                "*",
                SearchOption.TopDirectoryOnly).ToArray();
            if (entryPaths.Any(path => Directory.Exists(path)
                || !string.Equals(Path.GetExtension(path), ".json", StringComparison.Ordinal)))
            {
                throw new InvalidDataException(
                    "Plugin promotion journal contains an unexpected entry object.");
            }
            var entryFiles = entryPaths;
            if (!File.Exists(HeadPath))
            {
                if (entryFiles.Length != 0)
                {
                    throw new InvalidDataException("Plugin promotion journal entries exist without a head.");
                }
                return null;
            }
            var head = Parse<Head>(ReadBounded(HeadPath, 128 * 1024, "head"), "head");
            ValidateHead(head);
            var expectedName = head.EntryFileName;
            var expectedSha = head.EntrySha256;
            var previousRevision = long.MaxValue;
            var expectedRevision = head.StateRevision;
            var ids = new HashSet<string>(StringComparer.Ordinal);
            Entry? latest = null;
            var count = 0;
            while (!string.IsNullOrEmpty(expectedName))
            {
                if (++count > MaximumEntries || !SafeEntryFileName(expectedName))
                {
                    throw new InvalidDataException("Plugin promotion journal chain is cyclic or has an unsafe entry name.");
                }
                var path = Path.Combine(EntriesRoot, expectedName);
                var bytes = ReadBounded(path, 512 * 1024, "entry");
                if (!string.Equals(Hash(bytes), expectedSha, StringComparison.Ordinal))
                {
                    throw new InvalidDataException("Plugin promotion journal chain digest is invalid.");
                }
                var entry = Parse<Entry>(bytes, "entry");
                ValidateEntry(entry);
                if (entry.StateRevision != expectedRevision
                    || entry.StateRevision >= previousRevision
                    || !string.Equals(
                        entry.JournalInstanceId,
                        head.JournalInstanceId,
                        StringComparison.Ordinal)
                    || !ids.Add(entry.AuthorizationId))
                {
                    throw new InvalidDataException("Plugin promotion journal chain ordering or authorization uniqueness is invalid.");
                }
                latest ??= entry;
                previousRevision = entry.StateRevision;
                expectedRevision--;
                expectedName = entry.PreviousEntryFileName;
                expectedSha = entry.PreviousEntrySha256;
            }
            if (expectedRevision != 0 || !string.Equals(expectedSha, ZeroSha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException("Plugin promotion journal genesis is invalid.");
            }
            if (entryFiles.Length != count)
            {
                throw new InvalidDataException("Plugin promotion journal contains uncommitted or unexpected entries.");
            }
            return new Snapshot(head, latest!, ids);
        }

        public void RequireAnchorMatches(Anchor anchor, Snapshot? snapshot)
        {
            ValidateAnchor(anchor);
            if (anchor.Head is null)
            {
                if (snapshot is not null || anchor.StateRevision != 0)
                {
                    throw new InvalidDataException("Plugin promotion journal appeared after its independent genesis anchor.");
                }
                return;
            }
            if (snapshot is null || !AnchorEquals(anchor, anchor with { Head = snapshot.Head }))
            {
                throw new InvalidDataException("Plugin promotion journal is missing, replayed, or differs from its independent high-water anchor.");
            }
        }

        private T ReadProtected<T>(string path, string label) where T : class
        {
            var protectedBytes = ReadBounded(path, MaximumProtectedBytes, label);
            byte[]? plaintext = null;
            try
            {
                try
                {
                    plaintext = ProtectedData.Unprotect(protectedBytes, _entropy, DataProtectionScope.CurrentUser);
                }
                catch (CryptographicException exception)
                {
                    throw new InvalidDataException($"Plugin promotion journal {label} is not authenticated for this CurrentUser publisher identity.", exception);
                }
                if (plaintext.Length is <= 0 or > MaximumProtectedBytes)
                {
                    throw new InvalidDataException($"Plugin promotion journal {label} plaintext size is invalid.");
                }
                return Parse<T>(plaintext, label);
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

        private void ValidateAnchor(Anchor value)
        {
            if (value.SchemaVersion != 1 || !string.Equals(value.Product, Product, StringComparison.Ordinal)
                || !string.Equals(value.JournalRootSha256, JournalRootSha256, StringComparison.Ordinal)
                || !Guid.TryParseExact(value.JournalInstanceId, "D", out _)
                || value.StateRevision < 0 || (value.Head is null && value.StateRevision != 0))
            {
                throw new InvalidDataException("Plugin promotion journal anchor is invalid.");
            }
            if (value.Head is not null)
            {
                ValidateHead(value.Head);
                if (value.Head.StateRevision != value.StateRevision
                    || !string.Equals(value.Head.JournalInstanceId, value.JournalInstanceId, StringComparison.Ordinal))
                {
                    throw new InvalidDataException("Plugin promotion journal anchor head is invalid.");
                }
            }
        }

        private static void ValidateHead(Head value)
        {
            if (value.SchemaVersion != 1 || !string.Equals(value.Product, Product, StringComparison.Ordinal)
                || !Guid.TryParseExact(value.JournalInstanceId, "D", out _)
                || value.StateRevision <= 0 || !SafeEntryFileName(value.EntryFileName)
                || !PublisherPluginPromotionArtifactIdentity.IsSha256(value.EntrySha256))
            {
                throw new InvalidDataException("Plugin promotion journal head is invalid.");
            }
        }

        private static void ValidateEntry(Entry value)
        {
            if (value.SchemaVersion != 1 || !string.Equals(value.Product, Product, StringComparison.Ordinal)
                || !Guid.TryParseExact(value.JournalInstanceId, "D", out _)
                || value.StateRevision <= 0 || !Guid.TryParseExact(value.AuthorizationId, "D", out _)
                || !PublisherPluginPromotionArtifactIdentity.IsSha256(value.AuthorizationSha256)
                || !PublisherPluginPromotionArtifactIdentity.IsSha256(value.IntentSha256)
                || !PublisherPluginPromotionArtifactIdentity.IsSha256(value.PreviousEntrySha256)
                || value.ConsumedAtUtc.Offset != TimeSpan.Zero || value.Intent is null)
            {
                throw new InvalidDataException("Plugin promotion journal entry is invalid.");
            }
            value.Intent.Validate();
            if (!string.Equals(value.IntentSha256, Hash(value.Intent.CanonicalPayload()), StringComparison.Ordinal))
            {
                throw new InvalidDataException("Plugin promotion journal entry intent digest is invalid.");
            }
            if (value.StateRevision == 1 && (!string.IsNullOrEmpty(value.PreviousEntryFileName)
                || !string.Equals(value.PreviousEntrySha256, ZeroSha256, StringComparison.Ordinal)))
            {
                throw new InvalidDataException("Plugin promotion journal genesis entry is invalid.");
            }
        }

        private static T Parse<T>(ReadOnlySpan<byte> bytes, string label) where T : class
        {
            try
            {
                using var document = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 32 });
                RequireNoDuplicateMembers(document.RootElement);
                return JsonSerializer.Deserialize<T>(bytes.ToArray(), JsonOptions) ?? throw new InvalidDataException($"Plugin promotion journal {label} is empty.");
            }
            catch (JsonException exception)
            {
                throw new InvalidDataException($"Plugin promotion journal {label} JSON is invalid.", exception);
            }
        }

        private static void RequireNoDuplicateMembers(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.Object)
            {
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in value.EnumerateObject())
                {
                    if (!names.Add(property.Name))
                    {
                        throw new InvalidDataException("Plugin promotion journal JSON contains duplicate properties.");
                    }
                    RequireNoDuplicateMembers(property.Value);
                }
            }
            else if (value.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in value.EnumerateArray())
                {
                    RequireNoDuplicateMembers(item);
                }
            }
        }

        private static bool AnchorEquals(Anchor left, Anchor right) => Serialize(left).AsSpan().SequenceEqual(Serialize(right));
        private static bool SafeEntryFileName(string value) => !string.IsNullOrWhiteSpace(value)
            && value.EndsWith(".json", StringComparison.Ordinal)
            && string.Equals(value, Path.GetFileName(value), StringComparison.Ordinal)
            && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-');
    }
}
