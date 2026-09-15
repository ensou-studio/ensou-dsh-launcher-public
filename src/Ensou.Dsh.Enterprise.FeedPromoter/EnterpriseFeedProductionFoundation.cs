using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.FeedPromoter;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseFeedRawStateExpectation(
    string State,
    long? SizeBytes,
    string? Sha256)
{
    public static EnterpriseFeedRawStateExpectation Missing() =>
        new("missing", null, null);

    public static EnterpriseFeedRawStateExpectation Present(long sizeBytes, string sha256) =>
        new("present", sizeBytes, sha256);

    internal void Validate(string label)
    {
        if (State == "missing")
        {
            if (SizeBytes is not null || Sha256 is not null)
            {
                throw new InvalidDataException(
                    $"Enterprise {label} missing expectation must not contain a size or digest.");
            }
            return;
        }
        if (State != "present"
            || SizeBytes is null or <= 0
            || Sha256 is null
            || !EnterpriseReleaseValueValidator.IsSha256(Sha256))
        {
            throw new InvalidDataException(
                $"Enterprise {label} present expectation requires raw size and sha256.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseFeedProductionFoundation(
    string OperationId,
    string ExpectedFeedIdentitySha256,
    EnterpriseFeedRawStateExpectation ExpectedChannelHead,
    EnterpriseFeedRawStateExpectation ExpectedJournalHead)
{
    internal void Validate()
    {
        if (!Guid.TryParse(OperationId, out var operation)
            || !string.Equals(OperationId, operation.ToString("N"), StringComparison.Ordinal)
            || !EnterpriseReleaseValueValidator.IsSha256(ExpectedFeedIdentitySha256))
        {
            throw new InvalidDataException(
                "Enterprise production feed operation identity is invalid.");
        }
        ExpectedChannelHead?.Validate("expected channel head");
        ExpectedJournalHead?.Validate("expected journal head");
        if (ExpectedChannelHead is null || ExpectedJournalHead is null)
        {
            throw new InvalidDataException(
                "Enterprise production feed operation requires both explicit CAS unions.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseFeedPromotionOperationReceipt(
    int SchemaVersion,
    string OperationId,
    string RequestSha256,
    string Product,
    string Environment,
    string Channel,
    string ReleaseSetId,
    long Generation,
    long Sequence,
    long MinAcceptedSequence,
    string ManifestSha256,
    string ChannelManifestRelativePath,
    string ChannelManifestUri,
    string PromotionJournalEntryRelativePath,
    string PromotionJournalSha256,
    EnterpriseFeedRawStateExpectation ChannelHead,
    EnterpriseFeedRawStateExpectation JournalHead,
    [property: JsonConverter(typeof(EnterpriseWholeSecondUtcJsonConverter))]
    DateTimeOffset PublishedAtUtc,
    bool ChannelHeadChanged,
    bool ImmutableReleaseCreated)
{
    internal void Validate(EnterpriseFeedOperationRequest request)
    {
        ChannelHead?.Validate("committed channel head");
        JournalHead?.Validate("committed journal head");
        if (SchemaVersion != 1
            || ChannelHead is null
            || JournalHead is null
            || ChannelHead.State != "present"
            || JournalHead.State != "present"
            || !string.Equals(OperationId, request.OperationId, StringComparison.Ordinal)
            || !string.Equals(RequestSha256, request.RequestSha256, StringComparison.Ordinal)
            || !string.Equals(Product, request.Product, StringComparison.Ordinal)
            || !string.Equals(Environment, request.Environment, StringComparison.Ordinal)
            || !string.Equals(Channel, request.Channel, StringComparison.Ordinal)
            || !string.Equals(ManifestSha256, request.CandidateManifestSha256, StringComparison.Ordinal)
            || !string.Equals(
                ChannelManifestRelativePath,
                $"public/channels/{Channel}/release-set.v2.json",
                StringComparison.Ordinal)
            || !IsLogicalRelativePath(PromotionJournalEntryRelativePath)
            || !PromotionJournalEntryRelativePath.StartsWith(
                $"journal/{Channel}/",
                StringComparison.Ordinal)
            || !Uri.TryCreate(ChannelManifestUri, UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !EnterpriseReleaseValueValidator.IsSha256(PromotionJournalSha256)
            || PublishedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException(
                "Enterprise production feed operation receipt is invalid or conflicts with its request.");
        }
    }

    private static bool IsLogicalRelativePath(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && !Path.IsPathFullyQualified(value)
        && !value.Contains('\\')
        && !value.Split('/').Any(segment => segment is "" or "." or "..");
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record EnterpriseFeedServiceIdentity(
    int SchemaVersion,
    string Product,
    string Environment,
    string FeedInstanceId)
{
    public void Validate(string product, string environment)
    {
        if (SchemaVersion != 2
            || !string.Equals(Product, product, StringComparison.Ordinal)
            || !string.Equals(Environment, environment, StringComparison.Ordinal)
            || !Guid.TryParse(FeedInstanceId, out var instanceId)
            || !string.Equals(
                FeedInstanceId,
                instanceId.ToString("N"),
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise feed does not have a unique current-schema production identity.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record EnterpriseFeedInitializationResult(
    int SchemaVersion,
    string Product,
    string Environment,
    string FeedInstanceId,
    string FeedIdentitySha256);

internal static class EnterpriseFeedIdentityStore
{
    public const string FileName = "feed.identity.json";
    internal const string TemporaryFileName = ".feed.identity.json.tmp";

    public static EnterpriseFeedInitializationResult Initialize(
        string feedRoot,
        EnterpriseFeedTrustConfiguration trust)
    {
        var root = FeedPathGuard.RequireExistingDirectory(feedRoot, "feed root");
        var publicRoot = FeedPathGuard.RequireExactDirectory(root, "public");
        var releasesRoot = FeedPathGuard.RequireExactDirectory(publicRoot, "releases");
        var channelsRoot = FeedPathGuard.RequireExactDirectory(publicRoot, "channels");
        var journalRoot = FeedPathGuard.RequireExactDirectory(root, "journal");
        var stagingRoot = FeedPathGuard.RequireExactDirectory(root, "staging");
        FeedPathGuard.RequireSafeTree(root);
        FeedPathGuard.RequireRootOwnedManagedTree(root);
        RequireInitializationTopInventory(
            root,
            publicRoot,
            channelsRoot,
            journalRoot,
            publicationLockRequired: false);
        var preflightIdentityPath = Path.Combine(root, FileName);
        var preflightTemporaryPath = Path.Combine(root, TemporaryFileName);
        if (File.Exists(preflightIdentityPath))
        {
            if (File.Exists(preflightTemporaryPath))
            {
                throw new InvalidDataException(
                    "Enterprise feed identity has unexpected staged residue beside its committed file.");
            }
            return ReadInitializationResult(root, trust.Product, trust.Environment);
        }
        if (!File.Exists(preflightIdentityPath))
        {
            RequireUnusedFeedState(
                stagingRoot,
                releasesRoot,
                channelsRoot,
                journalRoot);
        }
        var publicationLockPath = Path.Combine(journalRoot, "publication.lock");
        if (!File.Exists(publicationLockPath))
        {
            try
            {
                FeedPathGuard.WriteNewDurable(publicationLockPath, []);
            }
            catch (IOException) when (File.Exists(publicationLockPath))
            {
                // A concurrent initializer created the one global lock.
            }
        }
        var safeLockPath = FeedPathGuard.RequireRegularFile(
            publicationLockPath,
            "enterprise feed global publication lock");
        using var publicationLock = new FileStream(
            safeLockPath,
            FileMode.Open,
            FileAccess.ReadWrite,
            FileShare.None,
            1,
            FileOptions.WriteThrough);
        RequireInitializationTopInventory(
            root,
            publicRoot,
            channelsRoot,
            journalRoot,
            publicationLockRequired: true,
            alreadyValidatedOpenLock: publicationLockPath);
        var identityPath = Path.Combine(root, FileName);
        var temporaryPath = Path.Combine(root, TemporaryFileName);
        if (File.Exists(identityPath))
        {
            if (File.Exists(temporaryPath))
            {
                throw new InvalidDataException(
                    "Enterprise feed identity has unexpected staged residue beside its committed file.");
            }
            return ReadInitializationResult(root, trust.Product, trust.Environment);
        }
        if (Directory.Exists(identityPath))
        {
            throw new InvalidDataException(
                "Enterprise feed identity path is unexpectedly a directory.");
        }
        RequireUnusedFeedState(stagingRoot, releasesRoot, channelsRoot, journalRoot);
        var identityBytes = PrepareIdentityTemporary(
            root,
            temporaryPath,
            trust.Product,
            trust.Environment);
        try
        {
            File.Move(temporaryPath, identityPath);
            LinuxDurability.SyncDirectory(root);
        }
        catch (IOException) when (File.Exists(identityPath))
        {
            // A create-only competitor won. Exact committed readback below
            // decides whether it is the same initialized identity.
        }
        var committed = FeedPathGuard.ReadBoundedRegularFile(
            identityPath,
            16 * 1024,
            "enterprise committed feed identity");
        if (!committed.AsSpan().SequenceEqual(identityBytes))
        {
            throw new InvalidDataException(
                "Enterprise feed identity conflicts with its staged create-only bytes.");
        }
        if (File.Exists(temporaryPath))
        {
            var staged = FeedPathGuard.ReadBoundedRegularFile(
                temporaryPath,
                16 * 1024,
                "enterprise staged feed identity");
            if (!staged.AsSpan().SequenceEqual(committed))
            {
                throw new InvalidDataException(
                    "Enterprise staged feed identity conflicts with the committed identity.");
            }
            File.Delete(temporaryPath);
            LinuxDurability.SyncDirectory(root);
        }
        FeedPathGuard.RequireRootOwnedManagedTree(root);
        return ReadInitializationResult(root, trust.Product, trust.Environment);
    }

    public static EnterpriseFeedInitializationResult ReadInitializationResult(
        string feedRoot,
        string product,
        string environment)
    {
        var bytes = FeedPathGuard.ReadBoundedRegularFile(
            Path.Combine(feedRoot, FileName),
            16 * 1024,
            "enterprise feed identity");
        var identity = ParseIdentity(bytes, product, environment);
        return new EnterpriseFeedInitializationResult(
            1,
            identity.Product,
            identity.Environment,
            identity.FeedInstanceId,
            FeedJson.Sha256(bytes));
    }

    public static string ReadRequiredSha256(
        string feedRoot,
        string product,
        string environment) => ReadInitializationResult(
            feedRoot,
            product,
            environment).FeedIdentitySha256;

    private static void RequireInitializationTopInventory(
        string root,
        string publicRoot,
        string channelsRoot,
        string journalRoot,
        bool publicationLockRequired,
        string? alreadyValidatedOpenLock = null)
    {
        FeedPathGuard.RequireExactInventory(
            root,
            ["journal", "public", "staging"],
            [],
            [],
            [FileName, TemporaryFileName],
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
            publicationLockRequired ? ["publication.lock"] : [],
            ["operations"],
            publicationLockRequired ? [] : ["publication.lock"],
            "enterprise journal root",
            alreadyValidatedOpenLock is null ? null : [alreadyValidatedOpenLock]);
    }

    private static byte[] PrepareIdentityTemporary(
        string root,
        string temporaryPath,
        string product,
        string environment)
    {
        if (File.Exists(temporaryPath))
        {
            var safeTemporary = FeedPathGuard.RequireRegularFile(
                temporaryPath,
                "enterprise staged feed identity");
            var length = new FileInfo(safeTemporary).Length;
            if (length > 0 && length <= 16 * 1024)
            {
                var staged = FeedPathGuard.ReadBoundedRegularFile(
                    safeTemporary,
                    16 * 1024,
                    "enterprise staged feed identity");
                try
                {
                    EnterpriseReleaseJson.RequireNoDuplicateMembers(staged);
                    var stagedIdentity = JsonSerializer.Deserialize<EnterpriseFeedServiceIdentity>(
                                             staged,
                                             FeedJson.Options)
                                         ?? throw new InvalidDataException(
                                             "Enterprise staged feed identity is empty.");
                    stagedIdentity.Validate(product, environment);
                    return staged;
                }
                catch (JsonException)
                {
                    // A crash during the create-new write can leave a
                    // syntactically truncated temporary.
                }
            }
            // The temporary has never named the feed identity, so incomplete
            // bytes are safe to discard under the root-owned global lock.
            File.Delete(safeTemporary);
            LinuxDurability.SyncDirectory(root);
        }
        var identity = new EnterpriseFeedServiceIdentity(
            2,
            product,
            environment,
            Guid.NewGuid().ToString("N"));
        identity.Validate(product, environment);
        var bytes = FeedJson.Serialize(identity);
        FeedPathGuard.WriteNewDurable(temporaryPath, bytes);
        return bytes;
    }

    private static EnterpriseFeedServiceIdentity ParseIdentity(
        ReadOnlySpan<byte> bytes,
        string product,
        string environment)
    {
        try
        {
            EnterpriseReleaseJson.RequireNoDuplicateMembers(bytes);
            var identity = JsonSerializer.Deserialize<EnterpriseFeedServiceIdentity>(
                               bytes,
                               FeedJson.Options)
                           ?? throw new InvalidDataException(
                               "Enterprise feed identity is empty.");
            identity.Validate(product, environment);
            return identity;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Enterprise feed identity JSON is invalid.",
                exception);
        }
    }

    private static void RequireUnusedFeedState(
        string stagingRoot,
        string releasesRoot,
        string channelsRoot,
        string journalRoot)
    {
        if (Directory.EnumerateFileSystemEntries(stagingRoot).Any())
        {
            throw new InvalidDataException(
                "Enterprise feed identity initialization requires empty staging state.");
        }
        var operationsRoot = Path.Combine(journalRoot, "operations");
        if (Directory.Exists(operationsRoot)
            && Directory.EnumerateFileSystemEntries(operationsRoot).Any())
        {
            throw new InvalidDataException(
                "Enterprise feed identity initialization requires no operation residue.");
        }
        if (Directory.EnumerateFileSystemEntries(releasesRoot).Any())
        {
            throw new InvalidDataException(
                "Enterprise feed identity initialization requires no immutable releases.");
        }
        foreach (var channel in new[] { "lab", "pilot", "stable" })
        {
            var channelRoot = FeedPathGuard.RequireExactDirectory(channelsRoot, channel);
            var channelJournal = FeedPathGuard.RequireExactDirectory(journalRoot, channel);
            if (Directory.EnumerateFileSystemEntries(channelRoot).Any()
                || Directory.EnumerateFileSystemEntries(channelJournal)
                    .Any(path => !string.Equals(
                        Path.GetFileName(path),
                        "promotion.lock",
                        StringComparison.Ordinal)))
            {
                throw new InvalidDataException(
                    "Enterprise feed identity initialization requires empty channel state.");
            }
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record EnterpriseFeedOperationRequest(
    int SchemaVersion,
    string OperationId,
    string RequestSha256,
    string Product,
    string Environment,
    string Channel,
    string FeedIdentitySha256,
    long CandidateManifestSizeBytes,
    string CandidateManifestSha256,
    string TrustConfigurationSha256,
    EnterpriseFeedRawStateExpectation ExpectedChannelHead,
    EnterpriseFeedRawStateExpectation ExpectedJournalHead);

internal sealed record EnterpriseFeedOperationSession(
    string Directory,
    EnterpriseFeedOperationRequest Request,
    EnterpriseFeedPromotionOperationReceipt? CommittedReceipt,
    bool IsExistingRequest);

internal static class EnterpriseFeedOperationStore
{
    private const int MaximumOperationFileBytes = 256 * 1024;

    public static EnterpriseFeedOperationRequest CreateRequest(
        EnterpriseFeedProductionFoundation foundation,
        string product,
        string environment,
        string channel,
        long manifestSizeBytes,
        string manifestSha256,
        string trustSha256)
    {
        foundation.Validate();
        var withoutDigest = new EnterpriseFeedOperationRequest(
            1,
            foundation.OperationId,
            new string('0', 64),
            product,
            environment,
            channel,
            foundation.ExpectedFeedIdentitySha256,
            manifestSizeBytes,
            manifestSha256,
            trustSha256,
            foundation.ExpectedChannelHead,
            foundation.ExpectedJournalHead);
        var requestSha256 = FeedJson.Sha256(FeedJson.Serialize(withoutDigest));
        var request = withoutDigest with { RequestSha256 = requestSha256 };
        ValidateRequest(request);
        return request;
    }

    public static EnterpriseFeedOperationSession Begin(
        string journalRoot,
        EnterpriseFeedOperationRequest request,
        EnterpriseFeedRawStateExpectation observedChannelHead,
        EnterpriseFeedRawStateExpectation observedJournalHead,
        bool allowCreate)
    {
        ValidateRequest(request);
        var root = EnsureOperationsRoot(journalRoot);
        var operationDirectory = Path.Combine(root, request.OperationId);
        var temporaryDirectory = Path.Combine(
            root,
            $".{request.OperationId}.request.tmp");
        RequireOperationInventory(root, temporaryDirectory);
        var requestPath = Path.Combine(operationDirectory, "request.v1.json");
        var responsePath = Path.Combine(operationDirectory, "response.v1.json");
        var requestBytes = FeedJson.Serialize(request);
        var existing = Directory.Exists(operationDirectory);
        var wasExisting = existing;
        if (!existing)
        {
            if (!allowCreate)
            {
                throw new InvalidOperationException(
                    "Enterprise committed feed output can only be retried with its original exact operationId and request.");
            }
            RequireNoOtherPendingOperation(root, request.OperationId);
            RequireCas(request.ExpectedChannelHead, observedChannelHead, "channel head");
            RequireCas(request.ExpectedJournalHead, observedJournalHead, "journal head");
            PrepareCreateOnlyOperationDirectory(
                root,
                temporaryDirectory,
                operationDirectory,
                requestBytes);
            existing = Directory.Exists(operationDirectory);
        }
        if (existing)
        {
            _ = FeedPathGuard.RequireExistingDirectory(
                operationDirectory,
                "feed operation directory");
            RequireExactOperationInventory(operationDirectory);
            var persisted = FeedPathGuard.ReadBoundedRegularFile(
                requestPath,
                MaximumOperationFileBytes,
                "feed operation request");
            if (!persisted.AsSpan().SequenceEqual(requestBytes))
            {
                throw new InvalidOperationException(
                    "Enterprise feed operationId is already bound to a conflicting canonical request.");
            }
            DeleteOwnedTemporaryDirectoryIfPresent(
                root,
                temporaryDirectory,
                requestBytes,
                allowEmpty: true);
        }
        else
        {
            throw new IOException(
                "Enterprise feed operation request was not durably created.");
        }
        RequireOperationInventory(root, allowedTemporaryDirectory: null);

        EnterpriseFeedPromotionOperationReceipt? receipt = null;
        if (File.Exists(responsePath))
        {
            var responseBytes = FeedPathGuard.ReadBoundedRegularFile(
                responsePath,
                MaximumOperationFileBytes,
                "feed operation response");
            receipt = ParseReceipt(responseBytes);
            receipt.Validate(request);
        }
        return new EnterpriseFeedOperationSession(
            operationDirectory,
            request,
            receipt,
            wasExisting);
    }

    public static EnterpriseFeedPromotionOperationReceipt Commit(
        EnterpriseFeedOperationSession session,
        EnterpriseFeedPromotionOperationReceipt receipt)
    {
        receipt.Validate(session.Request);
        var path = Path.Combine(session.Directory, "response.v1.json");
        var temporary = Path.Combine(session.Directory, "response.v1.json.tmp");
        var bytes = FeedJson.Serialize(receipt);
        if (File.Exists(path))
        {
            var existing = FeedPathGuard.ReadBoundedRegularFile(
                path,
                MaximumOperationFileBytes,
                "feed operation response");
            if (!existing.AsSpan().SequenceEqual(bytes))
            {
                throw new InvalidDataException(
                    "Enterprise feed operation response conflicts with its durable exact result.");
            }
            DeleteRecoverableResponseTemporary(temporary, bytes);
            return ParseReceipt(existing);
        }
        PrepareResponseTemporary(temporary, bytes);
        try
        {
            File.Move(temporary, path);
            LinuxDurability.SyncDirectory(session.Directory);
        }
        catch (IOException) when (File.Exists(path))
        {
            // A create-only competitor committed. Exact readback below decides it.
        }
        var committed = FeedPathGuard.ReadBoundedRegularFile(
            path,
            MaximumOperationFileBytes,
            "feed operation response");
        if (!committed.AsSpan().SequenceEqual(bytes))
        {
            throw new InvalidDataException(
                "Enterprise feed operation response conflicts with its durable exact result.");
        }
        DeleteRecoverableResponseTemporary(temporary, bytes);
        return ParseReceipt(committed);
    }

    private static void PrepareResponseTemporary(string path, byte[] expected)
    {
        if (File.Exists(path))
        {
            var full = FeedPathGuard.RequireRegularFile(
                path,
                "feed operation response temporary");
            var existing = File.ReadAllBytes(full);
            if (existing.Length > expected.Length
                || !expected.AsSpan(0, existing.Length).SequenceEqual(existing))
            {
                throw new InvalidDataException(
                    "Enterprise feed operation response temporary conflicts with the exact result.");
            }
            if (existing.Length == expected.Length)
            {
                return;
            }
            File.Delete(full);
            LinuxDurability.SyncDirectory(Path.GetDirectoryName(full)!);
        }
        else if (Directory.Exists(path))
        {
            throw new InvalidDataException(
                "Enterprise feed operation response temporary is unexpectedly a directory.");
        }
        FeedPathGuard.WriteNewDurable(path, expected);
    }

    private static void DeleteRecoverableResponseTemporary(string path, byte[] expected)
    {
        if (!File.Exists(path))
        {
            return;
        }
        var full = FeedPathGuard.RequireRegularFile(
            path,
            "feed operation response temporary");
        var existing = File.ReadAllBytes(full);
        if (existing.Length > expected.Length
            || !expected.AsSpan(0, existing.Length).SequenceEqual(existing))
        {
            throw new InvalidDataException(
                "Enterprise feed operation response temporary conflicts with the committed result.");
        }
        File.Delete(full);
        LinuxDurability.SyncDirectory(Path.GetDirectoryName(full)!);
    }

    public static EnterpriseFeedRawStateExpectation Observe(
        string path,
        int maximumBytes,
        string label)
    {
        if (!File.Exists(path))
        {
            return EnterpriseFeedRawStateExpectation.Missing();
        }
        var bytes = FeedPathGuard.ReadBoundedRegularFile(path, maximumBytes, label);
        return EnterpriseFeedRawStateExpectation.Present(
            bytes.LongLength,
            FeedJson.Sha256(bytes));
    }

    public static void RequireCas(
        EnterpriseFeedRawStateExpectation expected,
        EnterpriseFeedRawStateExpectation observed,
        string label)
    {
        expected.Validate($"expected {label}");
        observed.Validate($"observed {label}");
        if (!FeedJson.Serialize(expected).AsSpan()
                .SequenceEqual(FeedJson.Serialize(observed)))
        {
            throw new InvalidOperationException(
                $"Enterprise feed {label} CAS precondition failed inside the global publication lock.");
        }
    }

    public static byte[] SerializeReceipt(EnterpriseFeedPromotionOperationReceipt receipt) =>
        FeedJson.Serialize(receipt);

    public static EnterpriseFeedPromotionOperationReceipt ParseReceipt(ReadOnlySpan<byte> bytes)
    {
        try
        {
            EnterpriseReleaseJson.RequireNoDuplicateMembers(bytes);
            return JsonSerializer.Deserialize<EnterpriseFeedPromotionOperationReceipt>(
                       bytes,
                       FeedJson.Options)
                   ?? throw new InvalidDataException(
                       "Enterprise feed operation response is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Enterprise feed operation response JSON is invalid.",
                exception);
        }
    }

    private static string EnsureOperationsRoot(string journalRoot)
    {
        var root = Path.Combine(journalRoot, "operations");
        if (!Directory.Exists(root))
        {
            Directory.CreateDirectory(root);
            LinuxDurability.SyncDirectory(journalRoot);
        }
        return FeedPathGuard.RequireExistingDirectory(root, "feed operation store");
    }

    private static void PrepareCreateOnlyOperationDirectory(
        string root,
        string temporaryDirectory,
        string operationDirectory,
        byte[] requestBytes)
    {
        var stagedRequestPath = Path.Combine(temporaryDirectory, "request.v1.json");
        if (Directory.Exists(temporaryDirectory))
        {
            var entries = RequireOwnedTemporaryInventory(temporaryDirectory);
            if (entries.Length == 0)
            {
                Directory.Delete(temporaryDirectory);
                LinuxDurability.SyncDirectory(root);
            }
            else
            {
                var staged = FeedPathGuard.ReadBoundedRegularFile(
                    stagedRequestPath,
                    MaximumOperationFileBytes,
                    "feed operation staged request");
                if (!staged.AsSpan().SequenceEqual(requestBytes))
                {
                    throw new InvalidOperationException(
                        "Enterprise feed operationId has a conflicting durable staged request.");
                }
            }
        }
        else if (File.Exists(temporaryDirectory))
        {
            throw new InvalidDataException(
                "Enterprise feed operation request staging path is unexpectedly a file.");
        }
        if (!Directory.Exists(temporaryDirectory))
        {
            Directory.CreateDirectory(temporaryDirectory);
            LinuxDurability.SyncDirectory(root);
            FeedPathGuard.WriteNewDurable(stagedRequestPath, requestBytes);
        }
        try
        {
            Directory.Move(temporaryDirectory, operationDirectory);
            LinuxDurability.SyncDirectory(root);
        }
        catch (IOException) when (Directory.Exists(operationDirectory))
        {
            // Begin compares the winning target before removing the exact stage.
        }
    }

    private static void DeleteOwnedTemporaryDirectoryIfPresent(
        string root,
        string temporaryDirectory,
        byte[] expectedRequestBytes,
        bool allowEmpty)
    {
        if (File.Exists(temporaryDirectory))
        {
            throw new InvalidDataException(
                "Enterprise feed operation request staging path is unexpectedly a file.");
        }
        if (!Directory.Exists(temporaryDirectory))
        {
            return;
        }
        var entries = RequireOwnedTemporaryInventory(temporaryDirectory);
        if (entries.Length == 0 && !allowEmpty)
        {
            throw new InvalidDataException(
                "Enterprise feed operation request staging directory lost its durable request.");
        }
        if (entries.Length == 1)
        {
            var staged = FeedPathGuard.ReadBoundedRegularFile(
                entries[0],
                MaximumOperationFileBytes,
                "feed operation staged request");
            if (!staged.AsSpan().SequenceEqual(expectedRequestBytes))
            {
                throw new InvalidOperationException(
                    "Enterprise feed operationId has a conflicting durable staged request.");
            }
            File.Delete(entries[0]);
        }
        Directory.Delete(temporaryDirectory);
        LinuxDurability.SyncDirectory(root);
    }

    private static string[] RequireOwnedTemporaryInventory(string temporaryDirectory)
    {
        _ = FeedPathGuard.RequireExistingDirectory(
            temporaryDirectory,
            "feed operation request staging directory");
        var entries = Directory.EnumerateFileSystemEntries(temporaryDirectory).ToArray();
        if (entries.Length > 1
            || entries.Length == 1
                && !string.Equals(
                    Path.GetFileName(entries[0]),
                    "request.v1.json",
                    StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise feed operation request staging directory contains unexpected inventory.");
        }
        return entries;
    }

    private static void ValidateRequest(EnterpriseFeedOperationRequest request)
    {
        request.ExpectedChannelHead?.Validate("request channel head");
        request.ExpectedJournalHead?.Validate("request journal head");
        var normalized = request with { RequestSha256 = new string('0', 64) };
        if (request.SchemaVersion != 1
            || !Guid.TryParse(request.OperationId, out var operation)
            || !string.Equals(request.OperationId, operation.ToString("N"), StringComparison.Ordinal)
            || !EnterpriseReleaseValueValidator.IsSha256(request.RequestSha256)
            || !string.Equals(
                request.RequestSha256,
                FeedJson.Sha256(FeedJson.Serialize(normalized)),
                StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(request.Product)
            || string.IsNullOrWhiteSpace(request.Environment)
            || request.Channel is not "lab" and not "pilot" and not "stable"
            || !EnterpriseReleaseValueValidator.IsSha256(request.FeedIdentitySha256)
            || request.CandidateManifestSizeBytes is <= 0 or > 512 * 1024
            || !EnterpriseReleaseValueValidator.IsSha256(request.CandidateManifestSha256)
            || !EnterpriseReleaseValueValidator.IsSha256(request.TrustConfigurationSha256)
            || request.ExpectedChannelHead is null
            || request.ExpectedJournalHead is null)
        {
            throw new InvalidDataException(
                "Enterprise canonical feed operation request is invalid.");
        }
    }

    private static void RequireOperationInventory(
        string root,
        string? allowedTemporaryDirectory)
    {
        foreach (var entry in Directory.EnumerateFileSystemEntries(root))
        {
            var name = Path.GetFileName(entry);
            if (allowedTemporaryDirectory is not null
                && string.Equals(
                    Path.GetFullPath(entry),
                    Path.GetFullPath(allowedTemporaryDirectory),
                    StringComparison.Ordinal))
            {
                if (!Directory.Exists(entry))
                {
                    throw new InvalidDataException(
                        "Enterprise feed operation request staging inventory is invalid.");
                }
                _ = FeedPathGuard.RequireExistingDirectory(
                    entry,
                    "feed operation request staging directory");
                continue;
            }
            if (!Directory.Exists(entry)
                || !Guid.TryParseExact(name, "N", out _)
                || !string.Equals(name, name.ToLowerInvariant(), StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Enterprise feed operation store contains unexpected inventory.");
            }
            _ = FeedPathGuard.RequireExistingDirectory(
                entry,
                "feed operation directory");
            RequireExactOperationInventory(entry);
        }
    }

    private static void RequireExactOperationInventory(string directory)
    {
        var names = Directory.EnumerateFileSystemEntries(directory)
            .Select(Path.GetFileName)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var requestOnly = new[] { "request.v1.json" };
        var responsePending = new[] { "request.v1.json", "response.v1.json.tmp" };
        var completed = new[] { "request.v1.json", "response.v1.json" };
        if (!names.SequenceEqual(requestOnly, StringComparer.Ordinal)
            && !names.SequenceEqual(responsePending, StringComparer.Ordinal)
            && !names.SequenceEqual(completed, StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise feed operation directory contains unexpected inventory.");
        }
    }

    private static void RequireNoOtherPendingOperation(
        string root,
        string requestedOperationId)
    {
        foreach (var directory in Directory.EnumerateDirectories(root))
        {
            var name = Path.GetFileName(directory);
            if (string.Equals(name, requestedOperationId, StringComparison.Ordinal)
                || !Guid.TryParseExact(name, "N", out _))
            {
                continue;
            }
            if (!File.Exists(Path.Combine(directory, "response.v1.json")))
            {
                throw new InvalidOperationException(
                    "Enterprise feed has a pending operation that must be recovered before a new operation can start.");
            }
        }
    }
}
