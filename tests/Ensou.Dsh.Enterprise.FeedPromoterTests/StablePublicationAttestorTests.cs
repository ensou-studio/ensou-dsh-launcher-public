using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Enterprise.FeedPromoter;
using Ensou.Dsh.Enterprise.Installation;

internal static class StablePublicationAttestorTests
{
    private static readonly string[] EvidenceRoles = [
        "context.json", "feed-identity.json", "operation-request.json", "operation-result.json",
        "trust-configuration.json", "channel-head.json", "journal-head.json", "journal-entry.json"];

    // This uses an owned Linux fixture key only. It is neither a production-signature
    // assertion nor a deployment or publication acceptance test.
    public static void ExercisesRealFixturePromotionAndReadOnlyAttestation() => Run(null);

    public static string? Run(string? exportBundle)
    {
        if (!OperatingSystem.IsLinux())
        {
            if (exportBundle is not null) throw new PlatformNotSupportedException("Stable publication fixture export requires Linux.");
            return null;
        }

        if (exportBundle is not null) ValidateExportDestination(exportBundle);

        using var harness = new AttestationHarness();
        var beforeAttestation = SnapshotTree(harness.FeedRoot);
        var output = harness.OutputPath("positive");
        var envelope = harness.Attest(output);

        AssertSameSnapshot(beforeAttestation, SnapshotTree(harness.FeedRoot), "attestation must not change feed inventory or bytes");
        AssertBundle(harness, output, envelope);

        var existingBundle = SnapshotTree(output);
        AssertThrows(() => harness.Attest(output), "an existing output bundle must be rejected create-only");
        AssertSameSnapshot(existingBundle, SnapshotTree(output), "create-only rejection must preserve the existing bundle");
        AssertSameSnapshot(beforeAttestation, SnapshotTree(harness.FeedRoot), "create-only rejection must not change feed inventory");

        AssertRejected("changed current channel head", h => File.AppendAllText(h.ChannelHeadPath, "\n"));
        AssertRejected("changed operation request", h => File.AppendAllText(h.OperationRequestPath, "\n"));
        AssertRejected("changed trust configuration", h => File.AppendAllText(h.TrustConfigurationPath, "\n"));
        AssertRejected("different signing key", h => h.ReplaceSigningKey());
        AssertRejected("world-readable signing key", h => h.MakeSigningKeyWorldReadable());
        AssertRejected("group-readable signing key", h => h.MakeSigningKeyGroupReadable());
        AssertRejected("executable signing key", h => h.MakeSigningKeyExecutable());
        AssertRejected("extra operation file", h => File.WriteAllText(Path.Combine(h.OperationDirectory, "unexpected"), "unexpected"));
        AssertRejected("linked trust configuration", h => h.AddTrustHardLink());
        AssertRejected("stale context channel head", h => h.RewriteContext(context => context with { ExpectedChannelHead = EnterpriseFeedRawStateExpectation.Present(1, MissingCas) }));
        AssertRejected("overlong attestation key id", h => h.RewriteContext(context => context with { Trust = context.Trust with { KeyId = new string('a', 65) } }));
        AssertRejected("invalid attestation key id character", h => h.RewriteContext(context => context with { Trust = context.Trust with { KeyId = "fixture/key" } }));
        AssertRejected("noncanonical attestation coordinate tail bits", h => h.RewriteContext(context => context with { Trust = context.Trust with { X = NonCanonicalBase64Url32(context.Trust.X) } }));
        AssertRejected("journal artifact release differs from signed manifest", h => h.RewriteJournalArtifactRelease());
        AssertRejected("invalid signed channel manifest with rebased chain", h => h.InvalidateManifestAndRebaseChain());
        AssertRejected("receipt journal reference differs from committed head", h => h.RewriteReceiptJournalReference());
        AssertOutputParentLinkRejected();
        AssertOtherWritableOutputParentRejected();
        if (exportBundle is not null)
        {
            CopyBundle(output, exportBundle);
        }
        return exportBundle;
    }

    private static void ValidateExportDestination(string destination)
    {
        if (!Path.IsPathFullyQualified(destination)) throw new InvalidOperationException("--export-bundle must be an absolute child path.");
        if (Directory.Exists(destination) || File.Exists(destination)) throw new IOException("--export-bundle destination must not already exist.");
        var parent = Path.GetDirectoryName(Path.GetFullPath(destination));
        if (string.IsNullOrWhiteSpace(parent) || !Directory.Exists(parent) || Directory.EnumerateFileSystemEntries(parent).Any())
            throw new IOException("--export-bundle parent must be an existing empty directory.");
    }

    private static void CopyBundle(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        var createdFiles = new List<string>();
        var createdDirectories = new List<string>();
        try
        {
            foreach (var directory in Directory.EnumerateDirectories(source, "*", SearchOption.AllDirectories))
            {
                var created = Path.Combine(destination, Path.GetRelativePath(source, directory));
                Directory.CreateDirectory(created);
                createdDirectories.Add(created);
            }
            foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
            {
                var created = Path.Combine(destination, Path.GetRelativePath(source, file));
                File.Copy(file, created, overwrite: false);
                createdFiles.Add(created);
            }
        }
        catch
        {
            foreach (var file in createdFiles) { try { File.Delete(file); } catch { } }
            foreach (var directory in createdDirectories.OrderByDescending(path => path.Length)) { try { Directory.Delete(directory, recursive: false); } catch { } }
            try { Directory.Delete(destination, recursive: false); } catch { }
            throw;
        }
        AssertSameSnapshot(SnapshotTree(source), SnapshotTree(destination), "test export must contain exactly the verified bundle and no fixture private key");
    }

    private static void AssertRejected(string label, Action<AttestationHarness> tamper)
    {
        using var harness = new AttestationHarness();
        tamper(harness);
        var before = SnapshotTree(harness.FeedRoot);
        var output = harness.OutputPath("rejected");
        AssertThrows(() => harness.Attest(output), label + " must be rejected");
        Assert(!Directory.Exists(output) && !File.Exists(output), label + " failure must not leave an output bundle");
        AssertSameSnapshot(before, SnapshotTree(harness.FeedRoot), label + " rejection must not mutate the feed");
    }

    private static void AssertOutputParentLinkRejected()
    {
        using var harness = new AttestationHarness();
        var realParent = Path.Combine(harness.Root, "attestation-output-real-parent");
        var linkedParent = Path.Combine(harness.Root, "attestation-output-linked-parent");
        Directory.CreateDirectory(realParent);
        Directory.CreateSymbolicLink(linkedParent, realParent);
        var output = Path.Combine(linkedParent, "bundle");
        var before = SnapshotTree(harness.FeedRoot);
        AssertThrows(() => harness.Attest(output), "output parent symlink must be rejected");
        Assert(!Directory.Exists(Path.Combine(realParent, "bundle")), "output parent symlink rejection must not create a target through the link");
        AssertSameSnapshot(before, SnapshotTree(harness.FeedRoot), "output parent symlink rejection must not mutate the feed");
    }

    private static void AssertOtherWritableOutputParentRejected()
    {
        using var harness = new AttestationHarness();
        var parent = Path.Combine(harness.Root, "attestation-other-writable-parent");
        var output = Path.Combine(parent, "bundle");
        Directory.CreateDirectory(parent);
        var originalMode = GetUnixMode(parent);
        try
        {
            SetUnixMode(parent, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute);
            var before = SnapshotTree(harness.FeedRoot);
            AssertThrows(() => harness.Attest(output), "other-writable output parent must be rejected");
            Assert(!Directory.Exists(output), "other-writable output parent rejection must not create output");
            AssertSameSnapshot(before, SnapshotTree(harness.FeedRoot), "other-writable output parent rejection must not mutate the feed");
        }
        finally
        {
            SetUnixMode(parent, originalMode);
        }
    }

    private static void AssertBundle(AttestationHarness harness, string output, EnterpriseStablePublicationEnvelope envelope)
    {
        Assert(envelope.SchemaVersion == 1 && envelope.Algorithm == "ES256", "envelope must be schema-one ES256");
        Assert(envelope.KeyId == harness.KeyId && envelope.Purpose == "stable-public-promotion-attestation", "envelope must bind fixture trust");
        var outputEnvelope = JsonSerializer.Deserialize<EnterpriseStablePublicationEnvelope>(File.ReadAllBytes(Path.Combine(output, "publication-result.v1.json")), new JsonSerializerOptions(JsonSerializerDefaults.Web))
            ?? throw new InvalidOperationException("output envelope was not readable");
        Assert(outputEnvelope == envelope, "output envelope must equal the returned envelope");

        var payload = DecodeBase64Url(envelope.Payload);
        var signature = DecodeBase64Url(envelope.Signature);
        Assert(signature.Length == 64, "ES256 signature must be 64-byte P1363");
        AssertLowS(signature);
        var signedBytes = Encoding.UTF8.GetBytes("ensou-dsh-enterprise-stable-publication-result-v1\n" + harness.KeyId + "\n").Concat(payload).ToArray();
        using var verifier = ECDsa.Create(harness.PublicKey);
        Assert(verifier.VerifyData(signedBytes, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation), "signature must verify exact original payload bytes");

        var statement = JsonSerializer.Deserialize<EnterpriseStablePublicationStatement>(payload, new JsonSerializerOptions(JsonSerializerDefaults.Web))
            ?? throw new InvalidOperationException("statement payload was not readable");
        Assert(statement.SchemaVersion == 1 && statement.ResultType == "ensou-dsh-enterprise-stable-publication-result", "statement identity must be exact");
        Assert(statement.ContextSha256 == FeedJson.Sha256(File.ReadAllBytes(harness.ContextPath)), "statement must bind raw context bytes");
        Assert(statement.OperationId == harness.OperationId, "statement must bind operation id");
        Assert(statement.FeedOperationRequestSha256 == harness.Receipt.RequestSha256, "statement must bind the canonical operation request digest");
        Assert(statement.ExpiresAtUtc == statement.ObservedAtUtc.AddMinutes(10), "statement expiry must be exactly ten minutes");
        Assert(statement.Files.Select(file => file.Role).SequenceEqual(EvidenceRoles), "statement evidence roles must be fixed and ordered");

        foreach (var role in EvidenceRoles)
        {
            var expected = File.ReadAllBytes(harness.EvidenceSource(role));
            var actual = File.ReadAllBytes(Path.Combine(output, "evidence", role));
            Assert(expected.SequenceEqual(actual), "evidence " + role + " must preserve original source bytes");
            var item = statement.Files.Single(file => file.Role == role);
            Assert(item.SizeBytes == actual.LongLength && item.Sha256 == FeedJson.Sha256(actual), "statement metadata must match " + role);
        }
        Assert(statement.PublishedArtifacts.SequenceEqual(harness.PublishedArtifacts), "statement receipts must be from the real promotion journal");
    }

    private static Dictionary<string, string> SnapshotTree(string root)
    {
        var snapshot = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var directory in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories)) snapshot["D:" + Path.GetRelativePath(root, directory)] = string.Empty;
        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            var bytes = File.ReadAllBytes(file);
            snapshot["F:" + Path.GetRelativePath(root, file)] = bytes.LongLength + ":" + FeedJson.Sha256(bytes);
        }
        return snapshot;
    }

    private static void AssertSameSnapshot(Dictionary<string, string> expected, Dictionary<string, string> actual, string message) =>
        Assert(expected.Count == actual.Count && expected.All(item => actual.TryGetValue(item.Key, out var value) && value == item.Value), message);

    private static void AssertLowS(byte[] signature)
    {
        var s = new BigInteger(signature.AsSpan(32, 32), isUnsigned: true, isBigEndian: true);
        var halfOrder = BigInteger.Parse("7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8", System.Globalization.NumberStyles.AllowHexSpecifier);
        Assert(s <= halfOrder, "ES256 signature must use low-S form");
    }

    private static byte[] DecodeBase64Url(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(padded.PadRight(padded.Length + ((4 - padded.Length % 4) % 4), '='));
    }

    private static string NonCanonicalBase64Url32(string value)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        var last = alphabet.IndexOf(value[^1]);
        if (value.Length != 43 || last < 0) throw new InvalidOperationException("fixture coordinate must be a 32-byte base64url value");
        var replacement = (last & 0b111100) | ((last + 1) & 0b11);
        return value[..^1] + alphabet[replacement];
    }

    private static void AssertThrows(Action action, string message)
    {
        try { action(); }
        catch (Exception) { return; }
        throw new InvalidOperationException(message);
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private const string MissingCas = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    private sealed class AttestationHarness : IDisposable
    {
        private readonly Tests.Fixture fixture = new("stable");
        private readonly ECDsa signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public AttestationHarness()
        {
            var identity = fixture.InitializeProduction();
            var candidate = fixture.CreateCandidate(
                "managed-v2026.09.10.attested",
                1,
                1,
                0,
                artifactReleaseIds: new Dictionary<string, string>
                {
                    [EnterpriseReleaseSetContract.LauncherComponent] = "launcher-v2026.09.10.1",
                    [EnterpriseReleaseSetContract.RuntimeComponent] = "runtime-v2026.09.10.1",
                    [EnterpriseReleaseSetContract.PluginPolicyComponent] = "plugin-policy-v2026.09.10.1"
                });
            Assert(candidate.Manifest.Artifacts.All(artifact => artifact.ReleaseId != candidate.Manifest.ReleaseSetId), "fixture must use component release IDs distinct from its release set ID");
            var certification = fixture.CreateStableCertification(candidate);
            OperationId = Guid.NewGuid().ToString("N");
            var options = fixture.ProductionOptions(candidate, OperationId) with { CertifiedDistributionReceiptPath = certification.ReceiptPath, StablePromotionAuthorizationPath = certification.AuthorizationPath };
            var promotion = fixture.Promoter.Promote(options);
            Receipt = promotion.ProductionReceipt ?? throw new InvalidOperationException("fixture promotion did not produce a receipt");
            JournalEntryPath = ResolveFeedRelativePath(promotion.JournalEntryPath, "promotion journal entry");

            Root = Directory.GetParent(fixture.FeedRoot)?.FullName ?? throw new InvalidOperationException("fixture feed root has no parent");
            ContextPath = Path.Combine(Root, "attestation-context.json");
            SigningKeyPath = Path.Combine(Root, "attestation-signing-key.pkcs8");
            File.WriteAllBytes(SigningKeyPath, signer.ExportPkcs8PrivateKey());
            SetUnixKeyMode(SigningKeyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            PublicKey = signer.ExportParameters(false);
            KeyId = "fixture-stable-attestor-p256";
            var trust = EnterpriseFeedTrustConfiguration.Parse(File.ReadAllBytes(fixture.TrustPath), "stable");
            var receiptManifestUri = new Uri(Receipt.ChannelManifestUri, UriKind.Absolute);
            Assert(receiptManifestUri.GetLeftPart(UriPartial.Authority) == trust.ManifestOrigin.GetLeftPart(UriPartial.Authority), "fixture receipt manifest origin must match fixture trust");
            Context = new EnterpriseStablePublicationContext(1, "ensou-dsh-enterprise-stable-publication-context", OperationId, Guid.NewGuid().ToString("D"), candidate.Manifest.ReleaseSetId,
                HashText("plan"), HashText("source-identity-domain"), HashText("source-r9-head"), HashText("offline-promotion-request"), HashText("offline-authorization"), HashText("bundle-set"),
                identity.FeedIdentitySha256, options.ProductionFoundation!.ExpectedChannelHead, options.ProductionFoundation.ExpectedJournalHead, candidate.ManifestSha256, Receipt.ChannelManifestUri,
                new EnterpriseStablePublicationAttestationTrust("ES256", KeyId, "stable-public-promotion-attestation", EnterpriseBase64Url.Encode(PublicKey.Q.X!), EnterpriseBase64Url.Encode(PublicKey.Q.Y!)));
            Assert(Context.SourceIdentitySha256 != Context.ExpectedFeedIdentitySha256, "fixture must keep source and feed identity domains distinct");
            WriteContext();
            OperationDirectory = Path.Combine(fixture.OperationsRoot, OperationId);
        }

        public string FeedRoot => fixture.FeedRoot;
        public string Root { get; }
        public string OperationId { get; }
        public EnterpriseFeedPromotionOperationReceipt Receipt { get; }
        public string JournalEntryPath { get; }
        public IReadOnlyList<EnterpriseFeedArtifactReceipt> PublishedArtifacts => EnterpriseFeedPromotionJournalEntry.Parse(File.ReadAllBytes(JournalEntryPath)).Artifacts;
        public EnterpriseStablePublicationContext Context { get; private set; }
        public string ContextPath { get; }
        public string SigningKeyPath { get; }
        public ECParameters PublicKey { get; }
        public string KeyId { get; }
        public string OperationDirectory { get; }
        public string OperationRequestPath => Path.Combine(OperationDirectory, "request.v1.json");
        public string TrustConfigurationPath => fixture.TrustPath;
        public string ChannelHeadPath => fixture.ChannelHeadPath;
        public string OutputPath(string name) => Path.Combine(Root, "attestation-" + name);
        public EnterpriseStablePublicationEnvelope Attest(string output) => new EnterpriseStablePublicationAttestor().Attest(new EnterpriseStablePublicationAttestationOptions(FeedRoot, ContextPath, TrustConfigurationPath, SigningKeyPath, output));

        public string EvidenceSource(string role) => role switch
        {
            "context.json" => ContextPath, "feed-identity.json" => fixture.IdentityPath, "operation-request.json" => OperationRequestPath,
            "operation-result.json" => ResultPath, "trust-configuration.json" => TrustConfigurationPath,
            "channel-head.json" => ChannelHeadPath, "journal-head.json" => fixture.JournalHeadPath,
            "journal-entry.json" => JournalEntryPath,
            _ => throw new ArgumentOutOfRangeException(nameof(role))
        };

        public void RewriteContext(Func<EnterpriseStablePublicationContext, EnterpriseStablePublicationContext> rewrite) { Context = rewrite(Context); WriteContext(); }
        public void ReplaceSigningKey() { using var replacement = ECDsa.Create(ECCurve.NamedCurves.nistP256); File.WriteAllBytes(SigningKeyPath, replacement.ExportPkcs8PrivateKey()); }
        public void RewriteJournalArtifactRelease()
        {
            var entry = EnterpriseFeedPromotionJournalEntry.Parse(File.ReadAllBytes(JournalEntryPath));
            var changed = entry with
            {
                Artifacts = entry.Artifacts.Select((artifact, index) => index == 0
                    ? artifact with { ReleaseId = "other-release" }
                    : artifact).ToArray()
            };
            RewriteJournalChain(changed, receipt => receipt);
        }

        public void InvalidateManifestAndRebaseChain()
        {
            var manifest = EnterpriseReleaseSetManifest.Parse(File.ReadAllBytes(ChannelHeadPath));
            var replacementValue = manifest.Signature.Value[^1] == 'A'
                ? manifest.Signature.Value[..^1] + "B"
                : manifest.Signature.Value[..^1] + "A";
            var invalidManifest = manifest with { Signature = manifest.Signature with { Value = replacementValue } };
            var manifestBytes = FeedJson.Serialize(invalidManifest);
            File.WriteAllBytes(ChannelHeadPath, manifestBytes);
            var manifestSha = FeedJson.Sha256(manifestBytes);
            var request = JsonSerializer.Deserialize<EnterpriseFeedOperationRequest>(File.ReadAllBytes(OperationRequestPath), FeedJson.Options)
                ?? throw new InvalidOperationException("fixture operation request was not readable");
            var rebasedRequest = EnterpriseFeedOperationStore.CreateRequest(
                new EnterpriseFeedProductionFoundation(request.OperationId, request.FeedIdentitySha256, request.ExpectedChannelHead, request.ExpectedJournalHead),
                request.Product, request.Environment, request.Channel, manifestBytes.LongLength, manifestSha, request.TrustConfigurationSha256);
            File.WriteAllBytes(OperationRequestPath, FeedJson.Serialize(rebasedRequest));
            RewriteContext(context => context with { CandidateManifestSha256 = manifestSha });
            var entry = EnterpriseFeedPromotionJournalEntry.Parse(File.ReadAllBytes(JournalEntryPath)) with { ManifestSha256 = manifestSha };
            RewriteJournalChain(entry, receipt => receipt with
            {
                RequestSha256 = rebasedRequest.RequestSha256,
                ManifestSha256 = manifestSha,
                ChannelHead = EnterpriseFeedOperationStore.Observe(ChannelHeadPath, 512 * 1024, "rebased channel head")
            });
        }

        public void RewriteReceiptJournalReference()
        {
            var receipt = EnterpriseFeedOperationStore.ParseReceipt(File.ReadAllBytes(ResultPath));
            File.WriteAllBytes(ResultPath, EnterpriseFeedOperationStore.SerializeReceipt(receipt with
            {
                PromotionJournalEntryRelativePath = "journal/stable/not-the-committed-entry.json"
            }));
        }

        public void MakeSigningKeyWorldReadable() => SetUnixKeyMode(SigningKeyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        public void MakeSigningKeyGroupReadable() => SetUnixKeyMode(SigningKeyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
        public void MakeSigningKeyExecutable() => SetUnixKeyMode(SigningKeyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        public void AddTrustHardLink()
        {
            if (CreateHardLinkLinux(TrustConfigurationPath, TrustConfigurationPath + ".link") != 0) throw new InvalidOperationException("test hard link creation failed");
        }
        public void Dispose() { signer.Dispose(); fixture.Dispose(); }
        private void WriteContext() => File.WriteAllBytes(ContextPath, FeedJson.Serialize(Context));
        private static string HashText(string value) => FeedJson.Sha256(Encoding.UTF8.GetBytes(value));

        private string ResolveFeedRelativePath(string relativePath, string label)
        {
            if (string.IsNullOrWhiteSpace(relativePath) || Path.IsPathFullyQualified(relativePath) || relativePath.Contains('\\'))
                throw new InvalidOperationException("Fixture " + label + " must be a forward-slash relative feed path.");
            var segments = relativePath.Split('/');
            if (segments.Any(segment => segment is "" or "." or ".."))
                throw new InvalidOperationException("Fixture " + label + " contains an unsafe feed path segment.");
            return Path.Combine([fixture.FeedRoot, .. segments]);
        }

        private string ResultPath => Path.Combine(OperationDirectory, "response.v1.json");

        private void RewriteJournalChain(
            EnterpriseFeedPromotionJournalEntry entry,
            Func<EnterpriseFeedPromotionOperationReceipt, EnterpriseFeedPromotionOperationReceipt> rewriteReceipt)
        {
            var entryBytes = FeedJson.Serialize(entry);
            File.WriteAllBytes(JournalEntryPath, entryBytes);
            var journalHead = JsonSerializer.Deserialize<EnterpriseFeedJournalHead>(File.ReadAllBytes(fixture.JournalHeadPath), FeedJson.Options)
                ?? throw new InvalidOperationException("fixture journal head was not readable");
            var rebasedHead = journalHead with { EntrySha256 = FeedJson.Sha256(entryBytes) };
            File.WriteAllBytes(fixture.JournalHeadPath, FeedJson.Serialize(rebasedHead));
            var receipt = EnterpriseFeedOperationStore.ParseReceipt(File.ReadAllBytes(ResultPath));
            var rebasedReceipt = rewriteReceipt(receipt) with
            {
                PromotionJournalSha256 = rebasedHead.EntrySha256,
                JournalHead = EnterpriseFeedOperationStore.Observe(fixture.JournalHeadPath, 256 * 1024, "rebased journal head")
            };
            File.WriteAllBytes(ResultPath, EnterpriseFeedOperationStore.SerializeReceipt(rebasedReceipt));
        }
    }

    private static void SetUnixKeyMode(string path, UnixFileMode mode)
    {
        SetUnixMode(path, mode);
    }

    private static void SetUnixMode(string path, UnixFileMode mode)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Fixture key modes require Linux.");
        File.SetUnixFileMode(path, mode);
    }

    private static UnixFileMode GetUnixMode(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Fixture modes require Linux.");
        return File.GetUnixFileMode(path);
    }

    [DllImport("libc", EntryPoint = "link", SetLastError = true)]
    private static extern int CreateHardLinkLinux(string existingPath, string newPath);
}
