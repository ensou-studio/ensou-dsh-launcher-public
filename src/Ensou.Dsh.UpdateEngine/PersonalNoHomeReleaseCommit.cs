using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.UpdateEngine;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PersonalNoHomeCommitReceipt(
    int SchemaVersion,
    string ReceiptType,
    string Status,
    string ReleaseSetId,
    long Generation,
    long Sequence,
    string ManifestSha256,
    string ClientBundleReleaseId,
    string ClientBundleDirectory,
    string ClientBundleArchiveSha256,
    string ClientBundleCompleteTreeSha256,
    string RuntimeReleaseId,
    string RuntimeDirectory,
    string RuntimeArchiveSha256,
    string RuntimeCompleteTreeSha256,
    string PreviousReleaseSetId,
    string HealthTokenSha256,
    DateTimeOffset PreparedAtUtc,
    DateTimeOffset? CommittedAtUtc);

/// <summary>
/// Closes the only multi-file crash window in a Runtime-reused activation.
/// Both files live under the managed program root; neither path overlaps or
/// probes Harness user data or its recovery generations.
/// </summary>
internal sealed class PersonalNoHomeCommitStore
{
    internal const string PreparedStatus = "prepared";
    internal const string CommittedStatus = "committed";
    private const string ReceiptType = "ensou-dsh-personal-no-home-commit";
    private const string PendingFileName = "personal-no-home-commit.pending.v1.json";
    private const string CurrentFileName = "personal-no-home-commit.current.v1.json";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 16,
        NumberHandling = JsonNumberHandling.Strict,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = false,
    };

    private readonly PersonalInstallationLayout _layout;

    internal PersonalNoHomeCommitStore(PersonalInstallationLayout layout)
    {
        _layout = layout ?? throw new ArgumentNullException(nameof(layout));
    }

    internal PersonalNoHomeCommitReceipt Prepare(
        PersonalInstalledReleaseSetPointer pointer,
        string healthToken)
    {
        ArgumentNullException.ThrowIfNull(pointer);
        ArgumentException.ThrowIfNullOrWhiteSpace(healthToken);
        RequireNoHomePointer(pointer, requirePending: true);
        var tokenHash = HashHealthToken(healthToken);
        var existing = TryRead(PendingPath);
        if (existing is not null)
        {
            RequireMatches(existing, pointer, tokenHash, PreparedStatus);
            return existing;
        }

        var current = pointer.Current;
        var receipt = new PersonalNoHomeCommitReceipt(
            1,
            ReceiptType,
            PreparedStatus,
            current.ReleaseSetId,
            current.Generation,
            current.Sequence,
            current.ManifestSha256,
            current.ClientBundle.ReleaseId,
            current.ClientBundle.Directory,
            current.ClientBundle.ArchiveSha256,
            current.ClientBundle.CompleteTreeSha256,
            current.Runtime.ReleaseId,
            current.Runtime.Directory,
            current.Runtime.ArchiveSha256,
            current.Runtime.CompleteTreeSha256,
            pointer.Previous!.ReleaseSetId,
            tokenHash,
            DateTimeOffset.UtcNow,
            null);
        Validate(receipt);
        PersonalReleaseSetPointerStore.WriteFileAtomically(
            PendingPath,
            JsonSerializer.SerializeToUtf8Bytes(receipt, JsonOptions),
            _layout.ManagedRoot);
        return receipt;
    }

    internal PersonalNoHomeCommitReceipt? TryReadPending() => TryRead(PendingPath);

    internal PersonalNoHomeCommitReceipt ReadCommittedRequired(
        PersonalInstalledReleaseSetPointer pointer)
    {
        ArgumentNullException.ThrowIfNull(pointer);
        RequireNoHomePointer(pointer, requirePending: false);
        var receipt = TryRead(CurrentPath)
            ?? throw new InvalidDataException(
                "Personal no-home committed receipt is missing.");
        RequireMatches(receipt, pointer, expectedTokenHash: null, CommittedStatus);
        return receipt;
    }

    internal void RequirePreparedMatchesHealthy(
        PersonalNoHomeCommitReceipt receipt,
        PersonalInstalledReleaseSetPointer pointer)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ArgumentNullException.ThrowIfNull(pointer);
        RequireNoHomePointer(pointer, requirePending: false);
        RequireMatches(receipt, pointer, expectedTokenHash: null, PreparedStatus);
    }

    internal PersonalNoHomeCommitReceipt Commit(
        PersonalNoHomeCommitReceipt prepared,
        PersonalInstalledReleaseSetPointer healthy)
    {
        RequirePreparedMatchesHealthy(prepared, healthy);
        var committed = prepared with
        {
            Status = CommittedStatus,
            CommittedAtUtc = DateTimeOffset.UtcNow,
        };
        Validate(committed);
        PersonalReleaseSetPointerStore.WriteFileAtomically(
            CurrentPath,
            JsonSerializer.SerializeToUtf8Bytes(committed, JsonOptions),
            _layout.ManagedRoot);
        File.Delete(PendingPath);
        return committed;
    }

    internal void AbortPending(
        PersonalInstalledReleaseSetPointer pointer,
        string healthToken)
    {
        var receipt = TryRead(PendingPath);
        if (receipt is null)
        {
            return;
        }
        RequireMatches(
            receipt,
            pointer,
            HashHealthToken(healthToken),
            PreparedStatus);
        File.Delete(PendingPath);
    }

    internal string GetHealthSignalPath(PersonalNoHomeCommitReceipt receipt)
    {
        Validate(receipt);
        return Path.Combine(_layout.HealthSignalRoot, $"{receipt.HealthTokenSha256}.json");
    }

    private void RequireMatches(
        PersonalNoHomeCommitReceipt receipt,
        PersonalInstalledReleaseSetPointer pointer,
        string? expectedTokenHash,
        string expectedStatus)
    {
        Validate(receipt);
        var current = pointer.Current;
        if (!string.Equals(receipt.Status, expectedStatus, StringComparison.Ordinal)
            || !string.Equals(receipt.ReleaseSetId, current.ReleaseSetId, StringComparison.Ordinal)
            || receipt.Generation != current.Generation
            || receipt.Sequence != current.Sequence
            || !string.Equals(receipt.ManifestSha256, current.ManifestSha256, StringComparison.Ordinal)
            || !ComponentMatches(
                receipt.ClientBundleReleaseId,
                receipt.ClientBundleDirectory,
                receipt.ClientBundleArchiveSha256,
                receipt.ClientBundleCompleteTreeSha256,
                current.ClientBundle)
            || !ComponentMatches(
                receipt.RuntimeReleaseId,
                receipt.RuntimeDirectory,
                receipt.RuntimeArchiveSha256,
                receipt.RuntimeCompleteTreeSha256,
                current.Runtime)
            || pointer.Previous is null
            || !string.Equals(
                receipt.PreviousReleaseSetId,
                pointer.Previous.ReleaseSetId,
                StringComparison.Ordinal)
            || expectedTokenHash is not null
                && !string.Equals(
                    receipt.HealthTokenSha256,
                    expectedTokenHash,
                    StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal no-home commit receipt does not match its release pointer.");
        }
    }

    private static bool ComponentMatches(
        string releaseId,
        string directory,
        string archiveSha256,
        string treeSha256,
        PersonalInstalledComponentReference component) =>
        string.Equals(releaseId, component.ReleaseId, StringComparison.Ordinal)
        && string.Equals(directory, component.Directory, StringComparison.OrdinalIgnoreCase)
        && string.Equals(archiveSha256, component.ArchiveSha256, StringComparison.Ordinal)
        && string.Equals(treeSha256, component.CompleteTreeSha256, StringComparison.Ordinal);

    private static void RequireNoHomePointer(
        PersonalInstalledReleaseSetPointer pointer,
        bool requirePending)
    {
        if (pointer.Previous is null
            || !PersonalReleaseSetPointerStore.InstalledComponentsMatch(
                pointer.Current.Runtime,
                pointer.Previous.Runtime)
            || PersonalReleaseVersion.Compare(
                pointer.Current.StartupStub.MinimumVersion,
                PersonalReleaseArtifactInstaller.NoHomeMinimumStartupStubVersion) < 0
            || requirePending
                && (pointer.Current.HealthState != PersonalReleaseHealthStates.Pending
                    || !string.Equals(
                        pointer.Current.HomeTransactionId,
                        PersonalReleaseSetPointerStore.NoHomeTransactionSentinel,
                        StringComparison.Ordinal))
            || !requirePending
                && (pointer.Current.HealthState != PersonalReleaseHealthStates.Healthy
                    || !string.Equals(
                        pointer.Current.HomeTransactionId,
                        PersonalReleaseSetPointerStore.NoHomeTransactionSentinel,
                        StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "Personal no-home commit state is not bound to a Runtime-reused activation.");
        }
    }

    private PersonalNoHomeCommitReceipt? TryRead(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }
        if (!PersonalPathGuard.IsStrictDescendant(path, _layout.ManagedRoot)
            || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Personal no-home commit receipt path is unsafe.");
        }
        PersonalPathGuard.RequireSingleLinkFile(path);
        var bytes = File.ReadAllBytes(path);
        RejectDuplicateProperties(bytes);
        var receipt = JsonSerializer.Deserialize<PersonalNoHomeCommitReceipt>(
            bytes,
            JsonOptions) ?? throw new InvalidDataException(
                "Personal no-home commit receipt is empty.");
        Validate(receipt);
        var canonical = JsonSerializer.SerializeToUtf8Bytes(receipt, JsonOptions);
        if (!bytes.AsSpan().SequenceEqual(canonical))
        {
            throw new InvalidDataException(
                "Personal no-home commit receipt is not canonical JSON.");
        }
        return receipt;
    }

    private static void RejectDuplicateProperties(ReadOnlySpan<byte> bytes)
    {
        using var document = JsonDocument.Parse(
            bytes.ToArray(),
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16,
            });
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                "Personal no-home commit receipt must be a JSON object.");
        }
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (!names.Add(property.Name))
            {
                throw new InvalidDataException(
                    "Personal no-home commit receipt contains duplicate properties.");
            }
        }
    }

    private static void Validate(PersonalNoHomeCommitReceipt receipt)
    {
        if (receipt.SchemaVersion != 1
            || !string.Equals(receipt.ReceiptType, ReceiptType, StringComparison.Ordinal)
            || receipt.Status is not (PreparedStatus or CommittedStatus)
            || receipt.Status == PreparedStatus && receipt.CommittedAtUtc is not null
            || receipt.Status == CommittedStatus && receipt.CommittedAtUtc is null
            || receipt.Generation is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || receipt.Sequence is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || !PersonalReleaseSetValidator.IsSha256(receipt.ManifestSha256)
            || !PersonalReleaseSetValidator.IsSha256(receipt.ClientBundleArchiveSha256)
            || !PersonalReleaseSetValidator.IsSha256(receipt.ClientBundleCompleteTreeSha256)
            || !PersonalReleaseSetValidator.IsSha256(receipt.RuntimeArchiveSha256)
            || !PersonalReleaseSetValidator.IsSha256(receipt.RuntimeCompleteTreeSha256)
            || !PersonalReleaseSetValidator.IsSha256(receipt.HealthTokenSha256)
            || receipt.PreparedAtUtc.Offset != TimeSpan.Zero
            || receipt.CommittedAtUtc is { Offset: var offset }
                && offset != TimeSpan.Zero)
        {
            throw new InvalidDataException(
                "Personal no-home commit receipt is invalid.");
        }
        PersonalPathGuard.ValidateReleaseId(receipt.ReleaseSetId);
        PersonalPathGuard.ValidateReleaseId(receipt.ClientBundleReleaseId);
        PersonalPathGuard.ValidateReleaseId(receipt.RuntimeReleaseId);
        PersonalPathGuard.ValidateReleaseId(receipt.PreviousReleaseSetId);
        _ = PersonalPathGuard.NormalizeDirectory(receipt.ClientBundleDirectory);
        _ = PersonalPathGuard.NormalizeDirectory(receipt.RuntimeDirectory);
    }

    private static string HashHealthToken(string healthToken)
    {
        var token = PersonalReleaseBase64Url.Decode(healthToken, "health token");
        try
        {
            if (token.Length != 32)
            {
                throw new InvalidDataException(
                    "Personal no-home commit health token length is invalid.");
            }
            return Convert.ToHexStringLower(SHA256.HashData(token));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(token);
        }
    }

    private string PendingPath => Path.Combine(_layout.StateRoot, PendingFileName);

    private string CurrentPath => Path.Combine(_layout.StateRoot, CurrentFileName);
}
