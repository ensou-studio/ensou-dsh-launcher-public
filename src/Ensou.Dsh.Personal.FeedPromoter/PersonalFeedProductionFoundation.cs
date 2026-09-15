using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.Personal.FeedPromoter;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalFeedRawStateExpectation(
    string State,
    long? SizeBytes,
    string? Sha256)
{
    public static PersonalFeedRawStateExpectation Missing() =>
        new("missing", null, null);

    public static PersonalFeedRawStateExpectation Present(long sizeBytes, string sha256) =>
        new("present", sizeBytes, sha256);

    internal void Validate(string label)
    {
        if (State == "missing")
        {
            if (SizeBytes is not null || Sha256 is not null)
            {
                throw new InvalidDataException(
                    $"Personal {label} missing expectation must not contain a size or digest.");
            }
            return;
        }
        if (State != "present"
            || SizeBytes is null or <= 0
            || !PersonalReleaseSetValidator.IsSha256(Sha256))
        {
            throw new InvalidDataException(
                $"Personal {label} present expectation requires raw size and sha256.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalFeedProductionFoundation(
    string OperationId,
    string ExpectedFeedIdentitySha256,
    PersonalFeedRawStateExpectation ExpectedChannelHead,
    PersonalFeedRawStateExpectation ExpectedJournalHead)
{
    internal void Validate()
    {
        if (!Guid.TryParse(OperationId, out var operation)
            || !string.Equals(OperationId, operation.ToString("N"), StringComparison.Ordinal)
            || !PersonalReleaseSetValidator.IsSha256(ExpectedFeedIdentitySha256))
        {
            throw new InvalidDataException(
                "Personal production feed operation identity is invalid.");
        }
        ExpectedChannelHead?.Validate("expected channel head");
        ExpectedJournalHead?.Validate("expected journal head");
        if (ExpectedChannelHead is null || ExpectedJournalHead is null)
        {
            throw new InvalidDataException(
                "Personal production feed operation requires both explicit CAS unions.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalFeedPromotionResultReceipt(
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
    PersonalFeedRawStateExpectation ChannelHead,
    PersonalFeedRawStateExpectation JournalHead,
    DateTimeOffset PublishedAtUtc,
    bool ChannelHeadChanged,
    bool ImmutableReleaseCreated)
{
    internal void Validate(PersonalFeedOperationRequest request)
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
            || !PersonalReleaseSetValidator.IsSha256(PromotionJournalSha256)
            || PublishedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException(
                "Personal production feed operation receipt is invalid or conflicts with its request.");
        }
    }

    private static bool IsLogicalRelativePath(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && !Path.IsPathFullyQualified(value)
        && !value.Contains('\\')
        && !value.Split('/').Any(segment => segment is "" or "." or "..");
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PersonalFeedOperationRequest(
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
    PersonalFeedRawStateExpectation ExpectedChannelHead,
    PersonalFeedRawStateExpectation ExpectedJournalHead);

internal sealed record PersonalFeedOperationSession(
    string Directory,
    PersonalFeedOperationRequest Request,
    PersonalFeedPromotionResultReceipt? CommittedReceipt,
    bool IsExistingRequest);

internal static class PersonalFeedOperationStore
{
    private const int MaximumOperationFileBytes = 256 * 1024;

    // Read-only export must not call Begin: that method can create/recover requests.
    internal static (PersonalFeedOperationRequest Request, PersonalFeedPromotionResultReceipt Receipt,
        byte[] RequestBytes, byte[] ReceiptBytes) ReadCommitted(string operationsRoot, string operationId)
    {
        if (!Guid.TryParseExact(operationId, "N", out var id) || id.ToString("N") != operationId)
            throw new InvalidDataException("Export operation ID is invalid.");
        RequireOperationInventory(operationsRoot, allowedTemporaryDirectory: null);
        var directory = PersonalFeedPathGuard.RequireExistingDirectory(
            Path.Combine(operationsRoot, operationId), "completed operation");
        var requestBytes = PersonalFeedPathGuard.ReadBoundedRegularFile(
            Path.Combine(directory, "request.v1.json"), MaximumOperationFileBytes, "completed operation request");
        PersonalFeedJson.RequireNoDuplicateMembers(requestBytes);
        var request = JsonSerializer.Deserialize<PersonalFeedOperationRequest>(requestBytes, PersonalFeedJson.Options)
            ?? throw new InvalidDataException("Completed operation request is empty.");
        ValidateRequest(request);
        if (request.OperationId != operationId || !requestBytes.AsSpan().SequenceEqual(PersonalFeedJson.Serialize(request)))
            throw new InvalidDataException("Completed operation request identity/encoding conflicts.");
        var receiptBytes = PersonalFeedPathGuard.ReadBoundedRegularFile(
            Path.Combine(directory, "response.v1.json"), MaximumOperationFileBytes, "completed operation response");
        var receipt = ParseReceipt(receiptBytes);
        receipt.Validate(request);
        if (!receiptBytes.AsSpan().SequenceEqual(SerializeReceipt(receipt)))
            throw new InvalidDataException("Completed operation response encoding conflicts.");
        return (request, receipt, requestBytes, receiptBytes);
    }

    public static PersonalFeedOperationRequest CreateRequest(
        PersonalFeedProductionFoundation foundation,
        string channel,
        long manifestSizeBytes,
        string manifestSha256,
        string trustSha256)
    {
        foundation.Validate();
        var withoutDigest = new PersonalFeedOperationRequest(
            1,
            foundation.OperationId,
            new string('0', 64),
            PersonalReleaseSetContract.Product,
            PersonalReleaseSetContract.ProductionEnvironment,
            channel,
            foundation.ExpectedFeedIdentitySha256,
            manifestSizeBytes,
            manifestSha256,
            trustSha256,
            foundation.ExpectedChannelHead,
            foundation.ExpectedJournalHead);
        var requestSha256 = PersonalFeedJson.Sha256(PersonalFeedJson.Serialize(withoutDigest));
        var request = withoutDigest with { RequestSha256 = requestSha256 };
        ValidateRequest(request);
        return request;
    }

    public static PersonalFeedOperationSession Begin(
        string operationsRoot,
        PersonalFeedOperationRequest request,
        PersonalFeedRawStateExpectation observedChannelHead,
        PersonalFeedRawStateExpectation observedJournalHead,
        bool allowCreate)
    {
        ValidateRequest(request);
        var root = PersonalFeedPathGuard.RequireExistingDirectory(
            operationsRoot,
            "feed operation store");
        var operationDirectory = Path.Combine(root, request.OperationId);
        var temporaryDirectory = Path.Combine(
            root,
            $".{request.OperationId}.request.tmp");
        RequireOperationInventory(root, temporaryDirectory);
        var requestPath = Path.Combine(operationDirectory, "request.v1.json");
        var responsePath = Path.Combine(operationDirectory, "response.v1.json");
        var requestBytes = PersonalFeedJson.Serialize(request);
        var existing = Directory.Exists(operationDirectory);
        var wasExisting = existing;
        if (!existing)
        {
            if (!allowCreate)
            {
                throw new InvalidOperationException(
                    "Personal committed feed output can only be retried with its original exact operationId and request.");
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
            PersonalFeedPathGuard.RequireExistingDirectory(
                operationDirectory,
                "feed operation directory");
            RequireExactOperationInventory(operationDirectory);
            var persisted = PersonalFeedPathGuard.ReadBoundedRegularFile(
                requestPath,
                MaximumOperationFileBytes,
                "feed operation request");
            if (!persisted.AsSpan().SequenceEqual(requestBytes))
            {
                throw new InvalidOperationException(
                    "Personal feed operationId is already bound to a conflicting canonical request.");
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
                "Personal feed operation request was not durably created.");
        }
        RequireOperationInventory(root, allowedTemporaryDirectory: null);

        PersonalFeedPromotionResultReceipt? receipt = null;
        if (File.Exists(responsePath))
        {
            var responseBytes = PersonalFeedPathGuard.ReadBoundedRegularFile(
                responsePath,
                MaximumOperationFileBytes,
                "feed operation response");
            receipt = ParseReceipt(responseBytes);
            receipt.Validate(request);
        }
        return new PersonalFeedOperationSession(
            operationDirectory,
            request,
            receipt,
            wasExisting);
    }

    public static PersonalFeedPromotionResultReceipt Commit(
        PersonalFeedOperationSession session,
        PersonalFeedPromotionResultReceipt receipt)
    {
        receipt.Validate(session.Request);
        var path = Path.Combine(session.Directory, "response.v1.json");
        var temporary = Path.Combine(session.Directory, "response.v1.json.tmp");
        var bytes = PersonalFeedJson.Serialize(receipt);
        if (File.Exists(path))
        {
            var existing = PersonalFeedPathGuard.ReadBoundedRegularFile(
                path,
                MaximumOperationFileBytes,
                "feed operation response");
            if (!existing.AsSpan().SequenceEqual(bytes))
            {
                throw new InvalidDataException(
                    "Personal feed operation response conflicts with its durable exact result.");
            }
            DeleteRecoverableResponseTemporary(temporary, bytes);
            return ParseReceipt(existing);
        }
        PrepareResponseTemporary(temporary, bytes);
        try
        {
            File.Move(temporary, path);
            LinuxNative.FlushDirectory(session.Directory);
        }
        catch (IOException) when (File.Exists(path))
        {
            // A create-only competitor committed. Exact readback below decides it.
        }
        var committed = PersonalFeedPathGuard.ReadBoundedRegularFile(
            path,
            MaximumOperationFileBytes,
            "feed operation response");
        if (!committed.AsSpan().SequenceEqual(bytes))
        {
            throw new InvalidDataException(
                "Personal feed operation response conflicts with its durable exact result.");
        }
        DeleteRecoverableResponseTemporary(temporary, bytes);
        return ParseReceipt(committed);
    }

    private static void PrepareResponseTemporary(string path, byte[] expected)
    {
        if (File.Exists(path))
        {
            var full = PersonalFeedPathGuard.RequireRegularFile(
                path,
                "feed operation response temporary");
            var existing = File.ReadAllBytes(full);
            if (existing.Length > expected.Length
                || !expected.AsSpan(0, existing.Length).SequenceEqual(existing))
            {
                throw new InvalidDataException(
                    "Personal feed operation response temporary conflicts with the exact result.");
            }
            if (existing.Length == expected.Length)
            {
                return;
            }
            File.Delete(full);
            LinuxNative.FlushDirectory(Path.GetDirectoryName(full)!);
        }
        else if (Directory.Exists(path))
        {
            throw new InvalidDataException(
                "Personal feed operation response temporary is unexpectedly a directory.");
        }
        PersonalFeedPathGuard.WriteNewDurable(path, expected);
    }

    private static void DeleteRecoverableResponseTemporary(string path, byte[] expected)
    {
        if (!File.Exists(path))
        {
            return;
        }
        var full = PersonalFeedPathGuard.RequireRegularFile(
            path,
            "feed operation response temporary");
        var existing = File.ReadAllBytes(full);
        if (existing.Length > expected.Length
            || !expected.AsSpan(0, existing.Length).SequenceEqual(existing))
        {
            throw new InvalidDataException(
                "Personal feed operation response temporary conflicts with the committed result.");
        }
        File.Delete(full);
        LinuxNative.FlushDirectory(Path.GetDirectoryName(full)!);
    }

    public static PersonalFeedRawStateExpectation Observe(
        string path,
        int maximumBytes,
        string label)
    {
        if (!File.Exists(path))
        {
            return PersonalFeedRawStateExpectation.Missing();
        }
        var bytes = PersonalFeedPathGuard.ReadBoundedRegularFile(path, maximumBytes, label);
        return PersonalFeedRawStateExpectation.Present(
            bytes.LongLength,
            PersonalFeedJson.Sha256(bytes));
    }

    public static void RequireCas(
        PersonalFeedRawStateExpectation expected,
        PersonalFeedRawStateExpectation observed,
        string label)
    {
        expected.Validate($"expected {label}");
        observed.Validate($"observed {label}");
        if (!PersonalFeedJson.Serialize(expected).AsSpan()
                .SequenceEqual(PersonalFeedJson.Serialize(observed)))
        {
            throw new InvalidOperationException(
                $"Personal feed {label} CAS precondition failed inside the global publication lock.");
        }
    }

    public static byte[] SerializeReceipt(PersonalFeedPromotionResultReceipt receipt) =>
        PersonalFeedJson.Serialize(receipt);

    public static PersonalFeedPromotionResultReceipt ParseReceipt(ReadOnlySpan<byte> bytes)
    {
        try
        {
            PersonalFeedJson.RequireNoDuplicateMembers(bytes);
            return JsonSerializer.Deserialize<PersonalFeedPromotionResultReceipt>(
                       bytes,
                       PersonalFeedJson.Options)
                   ?? throw new InvalidDataException(
                       "Personal feed operation response is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Personal feed operation response JSON is invalid.",
                exception);
        }
    }

    private static void ValidateRequest(PersonalFeedOperationRequest request)
    {
        request.ExpectedChannelHead?.Validate("request channel head");
        request.ExpectedJournalHead?.Validate("request journal head");
        var normalized = request with { RequestSha256 = new string('0', 64) };
        if (request.SchemaVersion != 1
            || !Guid.TryParse(request.OperationId, out var operation)
            || !string.Equals(request.OperationId, operation.ToString("N"), StringComparison.Ordinal)
            || !PersonalReleaseSetValidator.IsSha256(request.RequestSha256)
            || !string.Equals(
                request.RequestSha256,
                PersonalFeedJson.Sha256(PersonalFeedJson.Serialize(normalized)),
                StringComparison.Ordinal)
            || !string.Equals(request.Product, PersonalReleaseSetContract.Product, StringComparison.Ordinal)
            || !string.Equals(
                request.Environment,
                PersonalReleaseSetContract.ProductionEnvironment,
                StringComparison.Ordinal)
            || request.Channel is not "lab" and not "pilot" and not "stable"
            || !PersonalReleaseSetValidator.IsSha256(request.FeedIdentitySha256)
            || request.CandidateManifestSizeBytes is <= 0
                or > PersonalReleaseSetContract.MaximumManifestBytes
            || !PersonalReleaseSetValidator.IsSha256(request.CandidateManifestSha256)
            || !PersonalReleaseSetValidator.IsSha256(request.TrustConfigurationSha256)
            || request.ExpectedChannelHead is null
            || request.ExpectedJournalHead is null)
        {
            throw new InvalidDataException(
                "Personal canonical feed operation request is invalid.");
        }
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
                LinuxNative.FlushDirectory(root);
            }
            else
            {
                var staged = PersonalFeedPathGuard.ReadBoundedRegularFile(
                    stagedRequestPath,
                    MaximumOperationFileBytes,
                    "feed operation staged request");
                if (!staged.AsSpan().SequenceEqual(requestBytes))
                {
                    throw new InvalidOperationException(
                        "Personal feed operationId has a conflicting durable staged request.");
                }
            }
        }
        else if (File.Exists(temporaryDirectory))
        {
            throw new InvalidDataException(
                "Personal feed operation request staging path is unexpectedly a file.");
        }
        if (!Directory.Exists(temporaryDirectory))
        {
            Directory.CreateDirectory(temporaryDirectory);
            PersonalFeedPathGuard.SetDirectoryMode(temporaryDirectory, publicRead: false);
            LinuxNative.FlushDirectory(root);
            PersonalFeedPathGuard.WriteNewDurable(stagedRequestPath, requestBytes);
        }
        try
        {
            Directory.Move(temporaryDirectory, operationDirectory);
            LinuxNative.FlushDirectory(root);
        }
        catch (IOException) when (Directory.Exists(operationDirectory))
        {
            // A create-only rename competitor won. Begin reads and compares its
            // canonical request before the exact staged request can be removed.
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
                "Personal feed operation request staging path is unexpectedly a file.");
        }
        if (!Directory.Exists(temporaryDirectory))
        {
            return;
        }
        var entries = RequireOwnedTemporaryInventory(temporaryDirectory);
        if (entries.Length == 0 && !allowEmpty)
        {
            throw new InvalidDataException(
                "Personal feed operation request staging directory lost its durable request.");
        }
        if (entries.Length == 1)
        {
            var staged = PersonalFeedPathGuard.ReadBoundedRegularFile(
                entries[0],
                MaximumOperationFileBytes,
                "feed operation staged request");
            if (!staged.AsSpan().SequenceEqual(expectedRequestBytes))
            {
                throw new InvalidOperationException(
                    "Personal feed operationId has a conflicting durable staged request.");
            }
            File.Delete(entries[0]);
        }
        Directory.Delete(temporaryDirectory);
        LinuxNative.FlushDirectory(root);
    }

    private static string[] RequireOwnedTemporaryInventory(string temporaryDirectory)
    {
        _ = PersonalFeedPathGuard.RequireExistingDirectory(
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
                "Personal feed operation request staging directory contains unexpected inventory.");
        }
        return entries;
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
                        "Personal feed operation request staging inventory is invalid.");
                }
                _ = PersonalFeedPathGuard.RequireExistingDirectory(
                    entry,
                    "feed operation request staging directory");
                continue;
            }
            if (!Directory.Exists(entry)
                || !Guid.TryParseExact(name, "N", out _)
                || !string.Equals(name, name.ToLowerInvariant(), StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Personal feed operation store contains unexpected inventory.");
            }
            _ = PersonalFeedPathGuard.RequireExistingDirectory(
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
                "Personal feed operation directory contains unexpected inventory.");
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
                    "Personal feed has a pending operation that must be recovered before a new operation can start.");
            }
        }
    }
}
