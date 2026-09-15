using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.FeedPromoter;

public sealed record EnterpriseStablePublicationAttestationOptions(
    string FeedRoot, string ContextPath, string TrustConfigurationPath,
    string SigningKeyPath, string OutputBundlePath);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseStablePublicationContext(
    int SchemaVersion, string ContextType, string OperationId, string OrchestrationId,
    string ReleaseSetId, string PlanSha256, string SourceIdentitySha256,
    string SourceR9HeadSha256, string OfflinePromotionRequestSha256,
    string OfflineAuthorizationSha256, string BundleSetSha256,
    string ExpectedFeedIdentitySha256, EnterpriseFeedRawStateExpectation ExpectedChannelHead,
    EnterpriseFeedRawStateExpectation ExpectedJournalHead, string CandidateManifestSha256,
    string ChannelManifestUri, EnterpriseStablePublicationAttestationTrust Trust);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseStablePublicationAttestationTrust(
    string Algorithm, string KeyId, string Purpose, string X, string Y);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseStablePublicationFile(string Role, long SizeBytes, string Sha256);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseStablePublicationStatement(
    int SchemaVersion, string ResultType, string ContextSha256, string OperationId,
    string FeedOperationRequestSha256,
    [property: JsonConverter(typeof(EnterpriseWholeSecondUtcJsonConverter))] DateTimeOffset ObservedAtUtc,
    [property: JsonConverter(typeof(EnterpriseWholeSecondUtcJsonConverter))] DateTimeOffset ExpiresAtUtc,
    IReadOnlyList<EnterpriseStablePublicationFile> Files,
    IReadOnlyList<EnterpriseFeedArtifactReceipt> PublishedArtifacts);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseStablePublicationEnvelope(
    int SchemaVersion, string Algorithm, string KeyId, string Purpose,
    string Payload, string Signature);

public sealed class EnterpriseStablePublicationAttestor
{
    private static readonly string[] EvidenceNames = [
        "context.json", "feed-identity.json", "operation-request.json", "operation-result.json",
        "trust-configuration.json", "channel-head.json", "journal-head.json", "journal-entry.json"];

    public EnterpriseStablePublicationEnvelope Attest(EnterpriseStablePublicationAttestationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var root = FeedPathGuard.RequireExistingDirectory(options.FeedRoot, "feed root");
        RequireDisjointOutput(options.OutputBundlePath, options.FeedRoot, options.ContextPath,
            options.TrustConfigurationPath, options.SigningKeyPath);
        FeedPathGuard.RequireRootOwnedManagedTree(root);
        var contextBytes = EnterpriseFeedLinuxSecurity.ReadRootOwnedStableFile(options.ContextPath, 256 * 1024, "publication context");
        var context = ParseContext(contextBytes);
        ValidateContext(context);
        var journalRoot = FeedPathGuard.RequireExactDirectory(root, "journal");
        var channelRoot = FeedPathGuard.RequireExactDirectory(FeedPathGuard.RequireExactDirectory(root, "public"), "channels");
        var stableRoot = FeedPathGuard.RequireExactDirectory(channelRoot, "stable");
        var stableJournalRoot = FeedPathGuard.RequireExactDirectory(journalRoot, "stable");
        using var globalLock = OpenExistingLock(Path.Combine(journalRoot, "publication.lock"), "global publication lock");
        using var channelLock = OpenExistingLock(Path.Combine(stableJournalRoot, "promotion.lock"), "stable publication lock");
        var requestPath = Path.Combine(journalRoot, "operations", context.OperationId, "request.v1.json");
        var resultPath = Path.Combine(journalRoot, "operations", context.OperationId, "response.v1.json");
        RequireCompletedOperationInventory(Path.GetDirectoryName(requestPath)!);
        var requestBytes = EnterpriseFeedLinuxSecurity.ReadRootOwnedStableFile(requestPath, 256 * 1024, "operation request");
        var request = ParseRequest(requestBytes);
        var resultBytes = EnterpriseFeedLinuxSecurity.ReadRootOwnedStableFile(resultPath, 256 * 1024, "operation result");
        var receipt = EnterpriseFeedOperationStore.ParseReceipt(resultBytes);
        receipt.Validate(request);
        if (request.Channel != "stable" || request.OperationId != context.OperationId || request.CandidateManifestSha256 != context.CandidateManifestSha256 || receipt.ReleaseSetId != context.ReleaseSetId)
            throw new InvalidDataException("Publication context does not match committed Stable operation.");
        EnterpriseFeedOperationStore.RequireCas(context.ExpectedChannelHead, request.ExpectedChannelHead, "context/request channel precondition");
        EnterpriseFeedOperationStore.RequireCas(context.ExpectedJournalHead, request.ExpectedJournalHead, "context/request journal precondition");
        if (context.ExpectedFeedIdentitySha256 != request.FeedIdentitySha256)
            throw new InvalidDataException("Publication context feed identity does not match the committed operation precondition.");
        var trustBytes = EnterpriseFeedLinuxSecurity.ReadRootOwnedStableFile(options.TrustConfigurationPath, 256 * 1024, "trust configuration");
        if (FeedJson.Sha256(trustBytes) != request.TrustConfigurationSha256)
            throw new InvalidDataException("Current trust configuration does not match the committed operation request.");
        var trust = EnterpriseFeedTrustConfiguration.Parse(trustBytes, "stable");
        var identityPath = Path.Combine(root, EnterpriseFeedIdentityStore.FileName);
        var headPath = Path.Combine(stableRoot, "release-set.v2.json");
        var journalHeadPath = Path.Combine(stableJournalRoot, "head.json");
        var identityBytes = EnterpriseFeedLinuxSecurity.ReadRootOwnedStableFile(identityPath, 256 * 1024, "feed identity");
        var headBytes = EnterpriseFeedLinuxSecurity.ReadRootOwnedStableFile(headPath, 512 * 1024, "channel head");
        var journalHeadBytes = EnterpriseFeedLinuxSecurity.ReadRootOwnedStableFile(journalHeadPath, 256 * 1024, "journal head");
        if (FeedJson.Sha256(identityBytes) != context.ExpectedFeedIdentitySha256)
            throw new InvalidDataException("Current feed identity does not match the committed operation precondition.");
        EnterpriseFeedOperationStore.RequireCas(receipt.ChannelHead, EnterpriseFeedRawStateExpectation.Present(headBytes.LongLength, FeedJson.Sha256(headBytes)), "channel head");
        EnterpriseFeedOperationStore.RequireCas(receipt.JournalHead, EnterpriseFeedRawStateExpectation.Present(journalHeadBytes.LongLength, FeedJson.Sha256(journalHeadBytes)), "journal head");
        var journalHead = EnterpriseFeedJournalHead.ReadOptional(journalHeadPath, stableJournalRoot)
            ?? throw new InvalidDataException("Journal head is empty.");
        if (!FeedJson.Serialize(journalHead).AsSpan().SequenceEqual(journalHeadBytes))
            throw new InvalidDataException("Journal head is not canonical stable bytes.");
        var entryPath = Path.Combine(stableJournalRoot, journalHead.EntryFileName);
        var entryBytes = EnterpriseFeedLinuxSecurity.ReadRootOwnedStableFile(entryPath, 512 * 1024, "journal entry");
        var entry = EnterpriseFeedPromotionJournalEntry.Parse(entryBytes);
        if (!FeedJson.Serialize(entry).AsSpan().SequenceEqual(entryBytes))
            throw new InvalidDataException("Journal entry is not canonical stable bytes.");
        var manifest = EnterpriseReleaseSetManifest.Parse(headBytes);
        EnterpriseReleaseSetValidator.Verify(manifest, trust.ToReleasePolicy("stable"), manifest.IssuedAtUtc);
        var manifestSha = FeedJson.Sha256(headBytes);
        entry.RequireIdentity(manifest, manifestSha, entry.Artifacts);
        if (manifestSha != context.CandidateManifestSha256 || manifest.ReleaseSetId != context.ReleaseSetId || receipt.ManifestSha256 != manifestSha)
            throw new InvalidDataException("Committed Stable manifest does not match publication context.");
        var expectedChannelUri = new Uri(trust.ManifestOrigin, "v2/channels/stable/release-set.v2.json");
        if (context.ChannelManifestUri != expectedChannelUri.AbsoluteUri
            || receipt.ChannelManifestUri != expectedChannelUri.AbsoluteUri
            || journalHead.Channel != "stable" || journalHead.ReleaseSetId != manifest.ReleaseSetId
            || journalHead.Sequence != manifest.Sequence || journalHead.EntrySha256 != FeedJson.Sha256(entryBytes)
            || receipt.PromotionJournalEntryRelativePath != $"journal/stable/{journalHead.EntryFileName}"
            || receipt.PromotionJournalSha256 != journalHead.EntrySha256)
            throw new InvalidDataException("Journal head, entry, and committed receipt are not one exact Stable chain.");
        var expectedArtifacts = manifest.Artifacts.Select(artifact => new EnterpriseFeedArtifactReceipt(
            artifact.Component, artifact.ReleaseId,
            EnterpriseFeedPromoter.RequireExactArtifactUri(manifest, artifact, trust.ToReleasePolicy("stable")),
            artifact.SizeBytes, artifact.Sha256)).ToArray();
        if (!entry.Artifacts.SequenceEqual(expectedArtifacts))
            throw new InvalidDataException("Journal artifacts do not exactly match the signed manifest.");
        VerifyArtifacts(root, manifest.ReleaseSetId, entry.Artifacts);
        if (!EnterpriseFeedLinuxSecurity.ReadRootOwnedStableFile(headPath, 512 * 1024, "channel head recheck").AsSpan().SequenceEqual(headBytes)
            || !EnterpriseFeedLinuxSecurity.ReadRootOwnedStableFile(journalHeadPath, 256 * 1024, "journal head recheck").AsSpan().SequenceEqual(journalHeadBytes)
            || !EnterpriseFeedLinuxSecurity.ReadRootOwnedStableFile(entryPath, 512 * 1024, "journal entry recheck").AsSpan().SequenceEqual(entryBytes))
            throw new InvalidDataException("Committed Stable observation changed during attestation.");
        var copies = new Dictionary<string, byte[]>(StringComparer.Ordinal) {
            ["context.json"] = contextBytes, ["feed-identity.json"] = identityBytes,
            ["operation-request.json"] = requestBytes, ["operation-result.json"] = resultBytes,
            ["trust-configuration.json"] = trustBytes, ["channel-head.json"] = headBytes,
            ["journal-head.json"] = journalHeadBytes, ["journal-entry.json"] = entryBytes };
        var files = EvidenceNames.Select(n => new EnterpriseStablePublicationFile(n, copies[n].LongLength, FeedJson.Sha256(copies[n]))).ToArray();
        var now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var statement = new EnterpriseStablePublicationStatement(1, "ensou-dsh-enterprise-stable-publication-result", FeedJson.Sha256(contextBytes), context.OperationId, request.RequestSha256, now, now.AddMinutes(10), files, entry.Artifacts);
        var payload = FeedJson.Serialize(statement);
        var key = EnterpriseFeedLinuxSecurity.ReadRootPrivateStableFile(options.SigningKeyPath, 64 * 1024, "publication signing key");
        try { return WriteBundle(options.OutputBundlePath, copies, statement, payload, key, context.Trust); }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private static EnterpriseStablePublicationEnvelope WriteBundle(string output, Dictionary<string, byte[]> copies, EnterpriseStablePublicationStatement statement, byte[] payload, byte[] key, EnterpriseStablePublicationAttestationTrust trust)
    {
        using var signer = ECDsa.Create(); signer.ImportPkcs8PrivateKey(key, out var used);
        if (used != key.Length || signer.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value) throw new InvalidDataException("Publication signing key is not an exact P-256 PKCS8 key.");
        var p = signer.ExportParameters(false);
        if (p.Q.X is null || p.Q.Y is null || B64(p.Q.X) != trust.X || B64(p.Q.Y) != trust.Y) throw new InvalidDataException("Publication signing key does not match context trust.");
        var signed = Encoding.UTF8.GetBytes("ensou-dsh-enterprise-stable-publication-result-v1\n" + trust.KeyId + "\n").Concat(payload).ToArray();
        var sig = signer.SignData(signed, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        NormalizeLowS(sig);
        if (sig.Length != 64 || !signer.VerifyData(signed, sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) throw new InvalidDataException("Publication signature self-check failed.");
        var envelope = new EnterpriseStablePublicationEnvelope(1, "ES256", trust.KeyId, trust.Purpose, B64(payload), B64(sig));
        if (Directory.Exists(output) || File.Exists(output)) throw new IOException("Publication output bundle already exists.");
        var parent = FeedPathGuard.RequireExistingDirectory(Path.GetDirectoryName(Path.GetFullPath(output)) ?? throw new InvalidDataException("Publication output has no parent."), "publication output parent");
        FeedPathGuard.RequireRootOwnedAndNotWritableByOthers(parent, "publication output parent");
        var stage = Path.Combine(parent, ".publication-attestation-" + Guid.NewGuid().ToString("N"));
        var marker = Guid.NewGuid().ToString("N");
        try { EnterpriseFeedLinuxSecurity.CreateOwnedPrivateDirectory(stage, marker); var ev = Path.Combine(stage, "evidence"); Directory.CreateDirectory(ev); foreach (var pair in copies) FeedPathGuard.WriteNewDurable(Path.Combine(ev, pair.Key), pair.Value); FeedPathGuard.WriteNewDurable(Path.Combine(stage, "publication-result.v1.json"), FeedJson.Serialize(envelope)); Directory.Move(stage, output); File.Delete(Path.Combine(output, ".owner")); return envelope; }
        catch { EnterpriseFeedLinuxSecurity.DeleteOwnedPrivateDirectory(stage, marker); throw; }
    }
    private static FileStream OpenExistingLock(string path, string label) => new(FeedPathGuard.RequireRegularFile(path, label), FileMode.Open, FileAccess.Read, FileShare.None, 1, FileOptions.None);
    private static void VerifyArtifacts(string root, string releaseSetId, IReadOnlyList<EnterpriseFeedArtifactReceipt> artifacts)
    {
        foreach (var artifact in artifacts)
        {
            FeedPathGuard.RequireSafeFileName(artifact.ReleaseId, "artifact release id");
            FeedPathGuard.RequireSafeFileName(artifact.FileName, "artifact file name");
            var path = Path.Combine(root, "public", "releases", releaseSetId, artifact.FileName);
            var first = EnterpriseFeedLinuxSecurity.HashRootOwnedStableFile(path, artifact.SizeBytes, "published artifact");
            var second = EnterpriseFeedLinuxSecurity.HashRootOwnedStableFile(path, artifact.SizeBytes, "published artifact");
            if (first != artifact.Sha256 || second != first)
                throw new InvalidDataException("Published artifact bytes changed or do not match the committed journal.");
        }
    }
    private static void RequireDisjointOutput(string output, params string[] inputs)
    {
        if (!Path.IsPathFullyQualified(output)) throw new InvalidDataException("Publication output bundle path must be absolute.");
        var target = Path.GetFullPath(output).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        foreach (var input in inputs)
        {
            var value = Path.GetFullPath(input).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (target.StartsWith(value, StringComparison.Ordinal) || value.StartsWith(target, StringComparison.Ordinal))
                throw new InvalidDataException("Publication output bundle overlaps a protected input path.");
        }
    }
    private static readonly byte[] P256Order = Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    private static readonly byte[] P256HalfOrder = Convert.FromHexString("7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8");
    private static void NormalizeLowS(byte[] signature)
    {
        if (signature.Length != 64 || signature.AsSpan(32).SequenceCompareTo(P256Order) >= 0 || signature.AsSpan(32).IndexOfAnyExcept((byte)0) < 0) throw new InvalidDataException("Publication signer returned invalid ES256 signature.");
        if (signature.AsSpan(32).SequenceCompareTo(P256HalfOrder) <= 0) return;
        var borrow = 0; for (var i = 31; i >= 0; --i) { var v = P256Order[i] - signature[32 + i] - borrow; signature[32 + i] = (byte)v; borrow = v < 0 ? 1 : 0; }
        if (borrow != 0 || signature.AsSpan(32).SequenceCompareTo(P256HalfOrder) > 0) throw new InvalidDataException("Publication signature low-S normalization failed.");
    }
    private static void RequireCompletedOperationInventory(string directory)
    {
        var names = Directory.EnumerateFileSystemEntries(directory).Select(Path.GetFileName).Order(StringComparer.Ordinal).ToArray();
        if (!names.SequenceEqual(["request.v1.json", "response.v1.json"], StringComparer.Ordinal))
            throw new InvalidDataException("Publication attestation requires one completed operation with no temporary files.");
    }
    private static EnterpriseFeedOperationRequest ParseRequest(byte[] bytes) { EnterpriseReleaseJson.RequireNoDuplicateMembers(bytes); var x = JsonSerializer.Deserialize<EnterpriseFeedOperationRequest>(bytes, FeedJson.Options) ?? throw new InvalidDataException("Operation request is empty."); var expected = EnterpriseFeedOperationStore.CreateRequest(new EnterpriseFeedProductionFoundation(x.OperationId,x.FeedIdentitySha256,x.ExpectedChannelHead,x.ExpectedJournalHead),x.Product,x.Environment,x.Channel,x.CandidateManifestSizeBytes,x.CandidateManifestSha256,x.TrustConfigurationSha256); if (!FeedJson.Serialize(expected).AsSpan().SequenceEqual(bytes)) throw new InvalidDataException("Operation request is not canonical or its self-digest is invalid."); return x; }
    private static EnterpriseStablePublicationContext ParseContext(byte[] bytes) { EnterpriseReleaseJson.RequireNoDuplicateMembers(bytes); return JsonSerializer.Deserialize<EnterpriseStablePublicationContext>(bytes, FeedJson.Options) ?? throw new InvalidDataException("Publication context is empty."); }
    private static void ValidateContext(EnterpriseStablePublicationContext x)
    {
        var hashes = new[] { x.PlanSha256, x.SourceIdentitySha256, x.SourceR9HeadSha256,
            x.OfflinePromotionRequestSha256, x.OfflineAuthorizationSha256, x.BundleSetSha256,
            x.ExpectedFeedIdentitySha256, x.CandidateManifestSha256 };
        if (x.SchemaVersion != 1 || x.ContextType != "ensou-dsh-enterprise-stable-publication-context"
            || !Guid.TryParseExact(x.OperationId, "N", out var operation) || operation.Version != 4
            || !Guid.TryParseExact(x.OrchestrationId, "D", out var orchestration) || orchestration.Version != 4
            || string.IsNullOrWhiteSpace(x.ReleaseSetId) || hashes.Any(value => !EnterpriseReleaseValueValidator.IsSha256(value))
            || x.Trust is null || x.Trust.Algorithm != "ES256" || x.Trust.Purpose != "stable-public-promotion-attestation"
            || !System.Text.RegularExpressions.Regex.IsMatch(x.Trust.KeyId ?? "", "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$") || !IsCoordinate(x.Trust.X) || !IsCoordinate(x.Trust.Y)
            || !Uri.TryCreate(x.ChannelManifestUri, UriKind.Absolute, out var uri)
            || uri.Scheme != Uri.UriSchemeHttps || uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0
            || uri.AbsolutePath != "/v2/channels/stable/release-set.v2.json")
            throw new InvalidDataException("Publication context is invalid.");
        x.ExpectedChannelHead?.Validate("context channel head"); x.ExpectedJournalHead?.Validate("context journal head");
        if (x.ExpectedChannelHead is null || x.ExpectedJournalHead is null) throw new InvalidDataException("Publication context CAS data is missing.");
    }
    private static bool IsCoordinate(string value)
    {
        if (value is null || value.Length != 43 || value.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))) return false;
        try { var decoded = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + "="); return decoded.Length == 32 && B64(decoded) == value; } catch (FormatException) { return false; }
    }
    private static string B64(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+','-').Replace('/','_');
}
