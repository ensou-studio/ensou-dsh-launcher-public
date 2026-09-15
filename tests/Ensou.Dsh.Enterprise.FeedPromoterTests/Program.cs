using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Enterprise.FeedPromoter;
using Ensou.Dsh.Enterprise.Installation;

if (args is ["--stable-publication-only"])
{
    StablePublicationAttestorTests.Run(null);
    Console.WriteLine("PASS  stable publication attestation fixture only");
    return 0;
}

if (args is ["--stable-publication-only", "--export-bundle", var exportBundle])
{
    var exported = StablePublicationAttestorTests.Run(exportBundle)
        ?? throw new PlatformNotSupportedException("Stable publication fixture export requires Linux.");
    Console.WriteLine("PASS  stable publication attestation fixture only");
    Console.WriteLine("STABLE_PUBLICATION_TEST_BUNDLE=" + exported);
    Console.WriteLine("STABLE_PUBLICATION_TEST_CONTEXT=" + Path.Combine(exported, "evidence", "context.json"));
    return 0;
}

if (args.Length > 0 && args[0] == "--stable-publication-only")
    throw new ArgumentException("Use --stable-publication-only or --stable-publication-only --export-bundle <absolute-child-path>.");

if (args is ["--emit-linux-stable-fixture", var stableFixtureRoot])
{
    if (!OperatingSystem.IsLinux() || Environment.GetEnvironmentVariable("ENSOU_DEVELOPMENT_LINUX_FIXTURE") != "1")
        throw new InvalidOperationException("Explicit isolated Linux development fixture opt-in required.");
    var fixtureNow = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    using var fixture = new Tests.Fixture("stable", stableFixtureRoot, preserve: true, now: fixtureNow);
    var candidate = fixture.CreateCandidate("managed-v2026.09.07.development-fixture", 1, 1, 0);
    var certification = fixture.CreateStableCertification(candidate);
    Console.WriteLine(JsonSerializer.Serialize(new {
        scope = "isolated-development-fixture-only", productionAdmission = "NO_GO",
        feedRoot = fixture.FeedRoot, trustPath = fixture.TrustPath, candidate = candidate.Directory,
        receiptPath = certification.ReceiptPath, authorizationPath = certification.AuthorizationPath,
    }));
    return 0;
}

if (args is ["--emit-linux-fixture", var fixtureRoot])
{
    var fixtureNow = DateTimeOffset.FromUnixTimeSeconds(
        DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    using var fixture = new Tests.Fixture(
        "lab",
        fixtureRoot,
        preserve: true,
        now: fixtureNow);
    var candidate = fixture.CreateCandidate("managed-v2026.08.26.1", 1, 1, 0);
    Console.WriteLine($"FEED_ROOT={fixture.FeedRoot}");
    Console.WriteLine($"TRUST_PATH={fixture.TrustPath}");
    Console.WriteLine($"CANDIDATE={candidate.Directory}");
    return 0;
}

var tests = new (string Name, Action Run)[]
{
    ("initialize CLI emits one compact JSON line for the Linux wrapper", Tests.InitializeCliEmitsCompactJson),
    ("signed lab candidate publishes immutable bytes and atomic head", Tests.PublishesLabCandidate),
    ("tampered candidate preserves current channel head", Tests.RejectsTamperedCandidate),
    ("sequence rollback preserves current channel head", Tests.RejectsSequenceRollback),
    ("immutable release URL can never be overwritten", Tests.RejectsImmutableConflict),
    ("interruption after immutable release resumes safely", Tests.RecoversAfterReleaseMove),
    ("interruption after channel switch repairs journal idempotently", Tests.RecoversAfterHeadSwitch),
    ("duplicate JSON member is rejected before signature handling", Tests.RejectsDuplicateManifestMember),
    ("incompatible signed Startup Stub protocol is rejected before feed mutation", Tests.RejectsIncompatibleStartupStubProtocol),
    ("revocation floor is cumulative", Tests.RejectsRevocationRollback),
    ("journal high-water rejects an externally rolled-back channel head", Tests.RejectsJournalRollback),
    ("promotion result receipt exposes exact manifest and journal paths", Tests.WritesMachineResultReceipt),
    ("promotion journal normalizes system time to whole-second UTC", Tests.NormalizesJournalTimestamp),
    ("Linux directory fsync primitive is callable", Tests.DirectoryFsyncPrimitive),
    ("stable channel fails closed without certification", Tests.StableRequiresCertification),
    ("stable channel accepts exact signed certification authorization", Tests.AcceptsCertifiedStable),
    ("tampered stable receipt is rejected", Tests.RejectsTamperedStableReceipt),
    ("production initialize emits unique machine identity and rejects residue", Tests.ProductionInitializeIsUniqueAndClean),
    ("production identity commit recovers staging and rejects damaged final", Tests.ProductionIdentityCommitIsAtomic),
    ("production crash windows replay exact durable response", Tests.ProductionCrashWindowsReplayExactly),
    ("production CAS conflict and pending N plus one fail closed", Tests.ProductionCasConflictAndPendingGate),
    ("operation request temp recovery preserves exact binding", Tests.OperationRequestTempRecoveryIsExact),
    ("managed tree trust and hardlink attacks fail closed", Tests.ProductionSecurityBoundariesFailClosed),
    ("invalid forward request leaves no operation residue", Tests.InvalidForwardRequestLeavesNoOperationResidue),
    ("production result path cannot enter managed inputs", Tests.ProductionResultPathIsExternal),
    ("global publication lock serializes competing CAS", Tests.GlobalPublicationLockSerializesCompetingCas),
    ("one signed Stable candidate crosses independent private and public foundations exactly", Tests.StableSplitViewUsesIndependentFoundations),
    ("stable publication attestation reads a real Linux fixture promotion without mutating its feed", StablePublicationAttestorTests.ExercisesRealFixturePromotionAndReadOnlyAttestation),
};

var failures = 0;
foreach (var test in tests)
{
    try
    {
        test.Run();
        Console.WriteLine($"PASS  {test.Name}");
    }
    catch (Exception exception)
    {
        failures++;
        Console.Error.WriteLine($"FAIL  {test.Name}: {exception}");
    }
}
Console.WriteLine($"{tests.Length - failures}/{tests.Length} feed promoter checks passed.");
return failures == 0 ? 0 : 1;

internal static class Tests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 26, 1, 0, 0, TimeSpan.Zero);

    public static void InitializeCliEmitsCompactJson()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var fixture = new Fixture("stable");
        var previous = Console.Out;
        using var output = new StringWriter();
        try
        {
            Console.SetOut(output);
            AssertEqual(0, Ensou.Dsh.Enterprise.FeedPromoter.Program.Main([
                "initialize", "--feed-root", fixture.FeedRoot, "--trust-policy", fixture.TrustPath]));
        }
        finally { Console.SetOut(previous); }
        var text = output.ToString();
        AssertEqual(1, text.Count(value => value == '\n'));
        AssertTrue(text.Contains("\"feedInstanceId\":\"", StringComparison.Ordinal), "Initializer output is not compact JSON.");
        using var parsed = JsonDocument.Parse(text);
        AssertEqual(HashFile(fixture.IdentityPath), parsed.RootElement.GetProperty("feedIdentitySha256").GetString());
    }

    public static void PublishesLabCandidate()
    {
        using var fixture = new Fixture("lab");
        var candidate = fixture.CreateCandidate("managed-v2026.08.26.1", 1, 1, 0);
        var result = fixture.Promoter.Promote(fixture.Options(candidate.Directory));
        AssertTrue(result.ChannelHeadChanged, "First promotion did not replace the channel head.");
        AssertTrue(result.ImmutableReleaseCreated, "First promotion did not create release bytes.");
        AssertEqual(candidate.ManifestSha256, result.ManifestSha256);
        AssertBytesEqual(
            candidate.ManifestBytes,
            File.ReadAllBytes(fixture.ChannelHeadPath));
        foreach (var artifact in candidate.Manifest.Artifacts)
        {
            var fileName = Path.GetFileName(artifact.Uri.AbsolutePath);
            AssertEqual(
                artifact.Sha256,
                HashFile(Path.Combine(fixture.ReleasesRoot, candidate.Manifest.ReleaseSetId, fileName)));
        }
        AssertTrue(File.Exists(result.JournalEntryPath), "Promotion journal entry is missing.");
        AssertTrue(File.Exists(fixture.JournalHeadPath), "Promotion journal head is missing.");
        AssertEqual("production", result.Environment);
        AssertEqual(0L, result.MinAcceptedSequence);
        AssertEqual(fixture.ChannelHeadPath, result.ChannelManifestPath);
    }

    public static void RejectsIncompatibleStartupStubProtocol()
    {
        using var fixture = new Fixture("lab");
        var candidate = fixture.CreateCandidate(
            "managed-v2026.08.26.incompatible",
            1,
            1,
            0,
            minimumStartupStubProtocol: 2,
            maximumStartupStubProtocol: 2);

        AssertThrows<InvalidDataException>(() =>
            fixture.Promoter.Promote(fixture.Options(candidate.Directory)));
        AssertTrue(
            !File.Exists(fixture.ChannelHeadPath),
            "Incompatible protocol advanced the channel head.");
        AssertTrue(
            !Directory.Exists(Path.Combine(
                fixture.ReleasesRoot,
                candidate.Manifest.ReleaseSetId)),
            "Incompatible protocol published immutable release bytes.");
    }

    public static void WritesMachineResultReceipt()
    {
        using var fixture = new Fixture("pilot");
        var candidate = fixture.CreateCandidate("managed-v2026.08.26.1", 1, 1, 0);
        var result = fixture.Promoter.Promote(fixture.Options(candidate.Directory));
        var resultPath = fixture.FeedRoot + ".promotion-result.v1.json";
        Ensou.Dsh.Enterprise.FeedPromoter.Program.WriteResultReceipt(resultPath, result);
        using var document = JsonDocument.Parse(File.ReadAllBytes(resultPath));
        var root = document.RootElement;
        AssertEqual(1, root.GetProperty("schemaVersion").GetInt32());
        AssertEqual(result.ChannelManifestPath, root.GetProperty("channelManifestPath").GetString());
        AssertEqual(
            result.JournalEntryPath,
            root.GetProperty("promotionJournalEntryPath").GetString());
        AssertEqual(
            result.JournalEntrySha256,
            root.GetProperty("promotionJournalSha256").GetString());
        AssertEqual(
            "2026-08-26T01:00:00Z",
            root.GetProperty("publishedAtUtc").GetString());
    }

    public static void DirectoryFsyncPrimitive()
    {
        var root = Path.Combine(Path.GetTempPath(), $"ensou-fsync-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            LinuxDurability.SyncDirectory(root);
        }
        finally
        {
            Directory.Delete(root);
        }
    }

    public static void NormalizesJournalTimestamp()
    {
        using var fixture = new Fixture("lab", now: Now.AddTicks(123_456));
        var candidate = fixture.CreateCandidate("managed-v2026.08.26.1", 1, 1, 0);
        var result = fixture.Promoter.Promote(fixture.Options(candidate.Directory));
        AssertEqual(TimeSpan.Zero, result.PublishedAtUtc.Offset);
        AssertEqual(0L, result.PublishedAtUtc.Ticks % TimeSpan.TicksPerSecond);
    }

    public static void RejectsTamperedCandidate()
    {
        using var fixture = new Fixture("lab");
        var first = fixture.CreateCandidate("managed-v2026.08.26.1", 1, 1, 0);
        _ = fixture.Promoter.Promote(fixture.Options(first.Directory));
        var before = File.ReadAllBytes(fixture.ChannelHeadPath);
        var second = fixture.CreateCandidate("managed-v2026.08.26.2", 1, 2, 0);
        File.AppendAllText(second.ArtifactPaths[0], "tamper", Encoding.UTF8);
        AssertThrows<InvalidDataException>(() =>
            fixture.Promoter.Promote(fixture.Options(second.Directory)));
        AssertBytesEqual(before, File.ReadAllBytes(fixture.ChannelHeadPath));
    }

    public static void RejectsSequenceRollback()
    {
        using var fixture = new Fixture("lab");
        var first = fixture.CreateCandidate("managed-v2026.08.26.2", 2, 2, 0);
        _ = fixture.Promoter.Promote(fixture.Options(first.Directory));
        var before = File.ReadAllBytes(fixture.ChannelHeadPath);
        var rollback = fixture.CreateCandidate("managed-v2026.08.26.1", 2, 1, 0);
        AssertThrows<InvalidDataException>(() =>
            fixture.Promoter.Promote(fixture.Options(rollback.Directory)));
        AssertBytesEqual(before, File.ReadAllBytes(fixture.ChannelHeadPath));
    }

    public static void RejectsImmutableConflict()
    {
        using var fixture = new Fixture("lab");
        var first = fixture.CreateCandidate("managed-v2026.08.26.1", 1, 1, 0);
        _ = fixture.Promoter.Promote(fixture.Options(first.Directory));
        var before = File.ReadAllBytes(fixture.ChannelHeadPath);
        var conflict = fixture.CreateCandidate(
            "managed-v2026.08.26.1",
            2,
            2,
            0,
            contentSalt: "different");
        AssertThrows<InvalidDataException>(() =>
            fixture.Promoter.Promote(fixture.Options(conflict.Directory)));
        AssertBytesEqual(before, File.ReadAllBytes(fixture.ChannelHeadPath));
    }

    public static void RecoversAfterReleaseMove()
    {
        using var fixture = new Fixture("pilot");
        var candidate = fixture.CreateCandidate("managed-v2026.08.26.1", 1, 1, 0);
        var interrupted = new EnterpriseFeedPromoter(
            fixture.TimeProvider,
            stage =>
            {
                if (stage == EnterpriseFeedPromotionStage.ImmutableReleaseReady)
                {
                    throw new SimulatedCrashException();
                }
            });
        AssertThrows<SimulatedCrashException>(() =>
            interrupted.Promote(fixture.Options(candidate.Directory)));
        AssertFalse(File.Exists(fixture.ChannelHeadPath), "Channel head changed before its fault point.");
        var recovered = fixture.Promoter.Promote(fixture.Options(candidate.Directory));
        AssertFalse(recovered.ImmutableReleaseCreated, "Recovery overwrote immutable release bytes.");
        AssertTrue(recovered.ChannelHeadChanged, "Recovery did not publish the channel head.");
    }

    public static void RecoversAfterHeadSwitch()
    {
        using var fixture = new Fixture("pilot");
        var candidate = fixture.CreateCandidate("managed-v2026.08.26.1", 1, 1, 0);
        var interrupted = new EnterpriseFeedPromoter(
            fixture.TimeProvider,
            stage =>
            {
                if (stage == EnterpriseFeedPromotionStage.ChannelHeadReplaced)
                {
                    throw new SimulatedCrashException();
                }
            });
        AssertThrows<SimulatedCrashException>(() =>
            interrupted.Promote(fixture.Options(candidate.Directory)));
        AssertTrue(File.Exists(fixture.ChannelHeadPath), "Fault did not happen after channel replacement.");
        AssertFalse(File.Exists(fixture.JournalHeadPath), "Journal unexpectedly completed before the fault.");
        var recovered = fixture.Promoter.Promote(fixture.Options(candidate.Directory));
        AssertFalse(recovered.ChannelHeadChanged, "Idempotent recovery replaced the same channel head.");
        AssertTrue(File.Exists(fixture.JournalHeadPath), "Idempotent recovery did not repair the journal.");
    }

    public static void RejectsDuplicateManifestMember()
    {
        using var fixture = new Fixture("lab");
        var candidate = fixture.CreateCandidate("managed-v2026.08.26.1", 1, 1, 0);
        var json = Encoding.UTF8.GetString(candidate.ManifestBytes);
        json = json.Replace(
            "\"channel\": \"lab\",",
            "\"channel\": \"lab\",\n  \"channel\": \"lab\",",
            StringComparison.Ordinal);
        File.WriteAllText(
            Path.Combine(candidate.Directory, "release-set.v2.json"),
            json,
            new UTF8Encoding(false));
        AssertThrows<InvalidDataException>(() =>
            fixture.Promoter.Promote(fixture.Options(candidate.Directory)));
        AssertFalse(File.Exists(fixture.ChannelHeadPath), "Duplicate JSON manifest was published.");
    }

    public static void RejectsRevocationRollback()
    {
        using var fixture = new Fixture("lab");
        var first = fixture.CreateCandidate(
            "managed-v2026.08.26.2",
            1,
            2,
            0,
            revoked: ["managed-v2026.08.25.1"]);
        _ = fixture.Promoter.Promote(fixture.Options(first.Directory));
        var second = fixture.CreateCandidate("managed-v2026.08.26.3", 1, 3, 0);
        AssertThrows<InvalidDataException>(() =>
            fixture.Promoter.Promote(fixture.Options(second.Directory)));
    }

    public static void RejectsJournalRollback()
    {
        using var fixture = new Fixture("lab");
        var first = fixture.CreateCandidate("managed-v2026.08.26.1", 1, 1, 0);
        _ = fixture.Promoter.Promote(fixture.Options(first.Directory));
        var second = fixture.CreateCandidate("managed-v2026.08.26.2", 1, 2, 0);
        _ = fixture.Promoter.Promote(fixture.Options(second.Directory));
        File.WriteAllBytes(fixture.ChannelHeadPath, first.ManifestBytes);
        AssertThrows<InvalidDataException>(() =>
            fixture.Promoter.Promote(fixture.Options(first.Directory)));
    }

    public static void StableRequiresCertification()
    {
        using var fixture = new Fixture("stable");
        var candidate = fixture.CreateCandidate("managed-v2026.08.26.1", 1, 1, 0);
        AssertThrows<InvalidDataException>(() =>
            fixture.Promoter.Promote(fixture.Options(candidate.Directory)));
        AssertFalse(File.Exists(fixture.ChannelHeadPath), "Uncertified stable head was published.");
    }

    public static void AcceptsCertifiedStable()
    {
        using var fixture = new Fixture("stable");
        var candidate = fixture.CreateCandidate("managed-v2026.08.26.1", 1, 1, 0);
        var certification = fixture.CreateStableCertification(candidate);
        var result = fixture.Promoter.Promote(fixture.Options(
            candidate.Directory,
            certification.ReceiptPath,
            certification.AuthorizationPath));
        AssertTrue(result.ChannelHeadChanged, "Certified stable head was not published.");
    }

    public static void RejectsTamperedStableReceipt()
    {
        using var fixture = new Fixture("stable");
        var candidate = fixture.CreateCandidate("managed-v2026.08.26.1", 1, 1, 0);
        var certification = fixture.CreateStableCertification(candidate);
        File.AppendAllText(certification.ReceiptPath, " ", Encoding.UTF8);
        AssertThrows<InvalidDataException>(() =>
            fixture.Promoter.Promote(fixture.Options(
                candidate.Directory,
                certification.ReceiptPath,
                certification.AuthorizationPath)));
        AssertFalse(File.Exists(fixture.ChannelHeadPath), "Tampered stable receipt was accepted.");
    }

    public static void ProductionInitializeIsUniqueAndClean()
    {
        using (var fixture = new Fixture("lab"))
        {
            var first = CaptureStandardOutput(() =>
                Ensou.Dsh.Enterprise.FeedPromoter.Program.Main(
                [
                    "initialize",
                    "--feed-root",
                    fixture.FeedRoot,
                    "--trust-policy",
                    fixture.TrustPath,
                ]));
            var second = CaptureStandardOutput(() =>
                Ensou.Dsh.Enterprise.FeedPromoter.Program.Main(
                [
                    "initialize",
                    "--feed-root",
                    fixture.FeedRoot,
                    "--trust-policy",
                    fixture.TrustPath,
                ]));
            using var firstJson = JsonDocument.Parse(first);
            using var secondJson = JsonDocument.Parse(second);
            var instanceId = firstJson.RootElement.GetProperty("feedInstanceId").GetString();
            var digest = firstJson.RootElement.GetProperty("feedIdentitySha256").GetString();
            AssertTrue(Guid.TryParseExact(instanceId, "N", out _),
                "Enterprise initialize did not emit a canonical feedInstanceId.");
            AssertTrue(digest is not null && EnterpriseReleaseValueValidator.IsSha256(digest),
                "Enterprise initialize did not emit the identity raw digest.");
            AssertEqual(instanceId,
                secondJson.RootElement.GetProperty("feedInstanceId").GetString());
            AssertEqual(digest,
                secondJson.RootElement.GetProperty("feedIdentitySha256").GetString());
            AssertFalse(first.Contains(fixture.FeedRoot, StringComparison.Ordinal),
                "Enterprise initialize leaked its absolute feed root.");

            var initialized = fixture.InitializeProduction();
            File.WriteAllBytes(fixture.IdentityPath, FeedJson.Serialize(new
            {
                SchemaVersion = 1,
                Product = EnterpriseReleaseSetContract.Product,
                Environment = EnterpriseReleaseSetContract.ProductionEnvironment,
            }));
            var candidate = fixture.CreateCandidate("managed-v2026.08.31.1", 1, 1, 0);
            var options = fixture.Options(candidate.Directory) with
            {
                ResultReceiptPath = fixture.ResultPath(Guid.NewGuid().ToString("N")),
                ProductionFoundation = new EnterpriseFeedProductionFoundation(
                    Guid.NewGuid().ToString("N"),
                    initialized.FeedIdentitySha256,
                    EnterpriseFeedRawStateExpectation.Missing(),
                    EnterpriseFeedRawStateExpectation.Missing()),
            };
            AssertThrows<InvalidDataException>(() => fixture.Promoter.Promote(options));
        }
        foreach (var residue in new[] { "staging", "operations", "unknown" })
        {
            using var fixture = new Fixture("lab");
            if (residue == "staging")
            {
                File.WriteAllText(Path.Combine(fixture.FeedRoot, "staging", "residue"), "x");
            }
            else if (residue == "operations")
            {
                var operations = Path.Combine(fixture.FeedRoot, "journal", "operations");
                Directory.CreateDirectory(operations);
                File.WriteAllText(Path.Combine(operations, "residue"), "x");
            }
            else
            {
                File.WriteAllText(Path.Combine(fixture.FeedRoot, "unexpected"), "x");
            }
            var before = SnapshotTree(fixture.FeedRoot);
            AssertThrows<InvalidDataException>(() => fixture.InitializeProduction());
            AssertTrue(before.SequenceEqual(SnapshotTree(fixture.FeedRoot), StringComparer.Ordinal),
                "Rejected Enterprise initialize mutated invalid feed state.");
            AssertFalse(File.Exists(Path.Combine(fixture.FeedRoot, "journal", "publication.lock")),
                "Rejected Enterprise initialize created its lock before inventory admission.");
        }
    }

    public static void StableSplitViewUsesIndependentFoundations()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        using var fixture = new Fixture("stable", now: now);
        var candidate = fixture.CreateCandidate(
            "managed-v2026.08.31.split-view",
            1,
            1,
            0,
            contentSalt: "identical-private-public");
        var certification = fixture.CreateStableCertification(candidate);
        var publicIdentity = fixture.InitializeProduction();
        var privateRoot = Path.Combine(
            Path.GetDirectoryName(fixture.FeedRoot)!,
            "private-feed");
        CreateEmptyFeedLayout(privateRoot);
        var trust = EnterpriseFeedTrustConfiguration.Parse(
            File.ReadAllBytes(fixture.TrustPath),
            "stable");
        var privateIdentity = EnterpriseFeedIdentityStore.Initialize(privateRoot, trust);
        AssertFalse(
            string.Equals(
                publicIdentity.FeedIdentitySha256,
                privateIdentity.FeedIdentitySha256,
                StringComparison.Ordinal),
            "Independent public/private roots reused one feed-instance identity.");

        var privateOperation = Guid.NewGuid().ToString("N");
        var privateResultPath = fixture.ResultPath(privateOperation);
        var privateOptions = fixture.Options(
            candidate.Directory,
            certification.ReceiptPath,
            certification.AuthorizationPath) with
        {
            FeedRoot = privateRoot,
            ResultReceiptPath = privateResultPath,
            ProductionFoundation = new EnterpriseFeedProductionFoundation(
                privateOperation,
                privateIdentity.FeedIdentitySha256,
                EnterpriseFeedRawStateExpectation.Missing(),
                EnterpriseFeedRawStateExpectation.Missing()),
        };
        var interruptedPrivate = new EnterpriseFeedPromoter(
            fixture.TimeProvider,
            stage =>
            {
                if (stage == EnterpriseFeedPromotionStage.ImmutableReleaseReady)
                {
                    throw new SimulatedCrashException();
                }
            });
        AssertThrows<SimulatedCrashException>(() =>
            interruptedPrivate.Promote(privateOptions));
        AssertFalse(File.Exists(fixture.ChannelHeadPath),
            "Private publication crash exposed the candidate through the public head.");
        var privateCliOutput = CaptureStandardOutput(() =>
            Ensou.Dsh.Enterprise.FeedPromoter.Program.Main(
            [
                "promote",
                "--candidate", candidate.Directory,
                "--feed-root", privateRoot,
                "--trust-policy", fixture.TrustPath,
                "--channel", "stable",
                "--operation-id", privateOperation,
                "--expected-feed-identity-sha256", privateIdentity.FeedIdentitySha256,
                "--expected-channel-head", "missing",
                "--expected-journal-head", "missing",
                "--result-receipt", privateResultPath,
                "--certified-distribution-receipt", certification.ReceiptPath,
                "--stable-authorization", certification.AuthorizationPath,
            ]));
        AssertTrue(privateCliOutput.StartsWith(
            "ENTERPRISE-FEED-PROMOTION-PASS stable ",
            StringComparison.Ordinal),
            "Private split-view Program.Main did not return its machine success marker.");
        var privateResult = fixture.Promoter.Promote(privateOptions);
        var privateReceiptBytes = File.ReadAllBytes(privateResultPath);
        AssertBytesEqual(
            EnterpriseFeedOperationStore.SerializeReceipt(privateResult.ProductionReceipt!),
            privateReceiptBytes);
        var privateReplayOutput = CaptureStandardOutput(() =>
            Ensou.Dsh.Enterprise.FeedPromoter.Program.Main(
            [
                "promote",
                "--candidate", candidate.Directory,
                "--feed-root", privateRoot,
                "--trust-policy", fixture.TrustPath,
                "--channel", "stable",
                "--operation-id", privateOperation,
                "--expected-feed-identity-sha256", privateIdentity.FeedIdentitySha256,
                "--expected-channel-head", "missing",
                "--expected-journal-head", "missing",
                "--result-receipt", privateResultPath,
                "--certified-distribution-receipt", certification.ReceiptPath,
                "--stable-authorization", certification.AuthorizationPath,
            ]));
        AssertEqual(privateCliOutput, privateReplayOutput);
        AssertBytesEqual(privateReceiptBytes, File.ReadAllBytes(privateResultPath));
        var privateReplay = fixture.Promoter.Promote(privateOptions);
        AssertBytesEqual(
            EnterpriseFeedOperationStore.SerializeReceipt(privateResult.ProductionReceipt!),
            EnterpriseFeedOperationStore.SerializeReceipt(privateReplay.ProductionReceipt!));
        AssertFalse(File.Exists(fixture.ChannelHeadPath),
            "Committed private publication changed the anonymous public head.");

        var publicOperation = Guid.NewGuid().ToString("N");
        var publicOptions = fixture.Options(
            candidate.Directory,
            certification.ReceiptPath,
            certification.AuthorizationPath) with
        {
            ResultReceiptPath = fixture.ResultPath(publicOperation),
            ProductionFoundation = new EnterpriseFeedProductionFoundation(
                publicOperation,
                publicIdentity.FeedIdentitySha256,
                EnterpriseFeedRawStateExpectation.Missing(),
                EnterpriseFeedRawStateExpectation.Missing()),
        };
        var interruptedPublic = new EnterpriseFeedPromoter(
            fixture.TimeProvider,
            stage =>
            {
                if (stage == EnterpriseFeedPromotionStage.ImmutableReleaseReady)
                {
                    throw new SimulatedCrashException();
                }
            });
        AssertThrows<SimulatedCrashException>(() =>
            interruptedPublic.Promote(publicOptions));
        AssertFalse(File.Exists(fixture.ChannelHeadPath),
            "Interrupted public immutable staging switched the public head early.");
        var publicCliOutput = CaptureStandardOutput(() =>
            Ensou.Dsh.Enterprise.FeedPromoter.Program.Main(
            [
                "promote",
                "--candidate", candidate.Directory,
                "--feed-root", fixture.FeedRoot,
                "--trust-policy", fixture.TrustPath,
                "--channel", "stable",
                "--operation-id", publicOperation,
                "--expected-feed-identity-sha256", publicIdentity.FeedIdentitySha256,
                "--expected-channel-head", "missing",
                "--expected-journal-head", "missing",
                "--result-receipt", publicOptions.ResultReceiptPath!,
                "--certified-distribution-receipt", certification.ReceiptPath,
                "--stable-authorization", certification.AuthorizationPath,
            ]));
        AssertTrue(publicCliOutput.StartsWith(
            "ENTERPRISE-FEED-PROMOTION-PASS stable ",
            StringComparison.Ordinal),
            "Public split-view Program.Main did not return its machine success marker.");
        var publicResult = fixture.Promoter.Promote(publicOptions);
        var publicReceiptBytes = File.ReadAllBytes(publicOptions.ResultReceiptPath!);
        AssertBytesEqual(
            EnterpriseFeedOperationStore.SerializeReceipt(publicResult.ProductionReceipt!),
            publicReceiptBytes);
        var publicReplayOutput = CaptureStandardOutput(() =>
            Ensou.Dsh.Enterprise.FeedPromoter.Program.Main(
            [
                "promote",
                "--candidate", candidate.Directory,
                "--feed-root", fixture.FeedRoot,
                "--trust-policy", fixture.TrustPath,
                "--channel", "stable",
                "--operation-id", publicOperation,
                "--expected-feed-identity-sha256", publicIdentity.FeedIdentitySha256,
                "--expected-channel-head", "missing",
                "--expected-journal-head", "missing",
                "--result-receipt", publicOptions.ResultReceiptPath!,
                "--certified-distribution-receipt", certification.ReceiptPath,
                "--stable-authorization", certification.AuthorizationPath,
            ]));
        AssertEqual(publicCliOutput, publicReplayOutput);
        AssertBytesEqual(publicReceiptBytes, File.ReadAllBytes(publicOptions.ResultReceiptPath!));
        var publicReplay = fixture.Promoter.Promote(publicOptions);
        AssertBytesEqual(
            EnterpriseFeedOperationStore.SerializeReceipt(publicResult.ProductionReceipt!),
            EnterpriseFeedOperationStore.SerializeReceipt(publicReplay.ProductionReceipt!));

        var privateHead = Path.Combine(
            privateRoot,
            "public",
            "channels",
            "stable",
            "release-set.v2.json");
        AssertBytesEqual(File.ReadAllBytes(privateHead), File.ReadAllBytes(fixture.ChannelHeadPath));
        foreach (var artifact in candidate.Manifest.Artifacts)
        {
            var artifactFileName = Path.GetFileName(artifact.Uri.LocalPath);
            var privateArtifact = Path.Combine(
                privateRoot,
                "public",
                "releases",
                candidate.Manifest.ReleaseSetId,
                artifactFileName);
            var publicArtifact = Path.Combine(
                fixture.ReleasesRoot,
                candidate.Manifest.ReleaseSetId,
                artifactFileName);
            AssertBytesEqual(File.ReadAllBytes(privateArtifact), File.ReadAllBytes(publicArtifact));
        }
        AssertThrows<InvalidOperationException>(() => fixture.Promoter.Promote(
            publicOptions with
            {
                ProductionFoundation = publicOptions.ProductionFoundation! with
                {
                    ExpectedFeedIdentitySha256 = privateIdentity.FeedIdentitySha256,
                },
            }));
    }

    private static void CreateEmptyFeedLayout(string feedRoot)
    {
        Directory.CreateDirectory(Path.Combine(feedRoot, "staging"));
        Directory.CreateDirectory(Path.Combine(feedRoot, "public", "releases"));
        foreach (var channel in new[] { "lab", "pilot", "stable" })
        {
            Directory.CreateDirectory(Path.Combine(feedRoot, "public", "channels", channel));
            Directory.CreateDirectory(Path.Combine(feedRoot, "journal", channel));
        }
    }

    public static void ProductionIdentityCommitIsAtomic()
    {
        using (var fixture = new Fixture("lab"))
        {
            var instanceId = Guid.NewGuid().ToString("N");
            var stagedBytes = FeedJson.Serialize(new EnterpriseFeedServiceIdentity(
                2,
                EnterpriseReleaseSetContract.Product,
                EnterpriseReleaseSetContract.ProductionEnvironment,
                instanceId));
            var temporaryPath = Path.Combine(
                fixture.FeedRoot,
                EnterpriseFeedIdentityStore.TemporaryFileName);
            FeedPathGuard.WriteNewDurable(temporaryPath, stagedBytes);

            var initialized = fixture.InitializeProduction();

            AssertEqual(instanceId, initialized.FeedInstanceId);
            AssertBytesEqual(stagedBytes, File.ReadAllBytes(fixture.IdentityPath));
            AssertFalse(File.Exists(temporaryPath),
                "Enterprise initialization left its committed identity temporary behind.");
        }
        using (var fixture = new Fixture("lab"))
        {
            var temporaryPath = Path.Combine(
                fixture.FeedRoot,
                EnterpriseFeedIdentityStore.TemporaryFileName);
            File.WriteAllBytes(temporaryPath, Encoding.UTF8.GetBytes("{\"schemaVersion\":2,"));

            var initialized = fixture.InitializeProduction();

            AssertTrue(Guid.TryParseExact(initialized.FeedInstanceId, "N", out _),
                "Enterprise initialization did not recover a truncated identity temporary.");
            AssertFalse(File.Exists(temporaryPath),
                "Enterprise initialization retained a truncated identity temporary.");
        }
        using (var fixture = new Fixture("lab"))
        {
            var damaged = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,");
            File.WriteAllBytes(fixture.IdentityPath, damaged);

            AssertThrows<InvalidDataException>(() => fixture.InitializeProduction());

            AssertBytesEqual(damaged, File.ReadAllBytes(fixture.IdentityPath));
            AssertFalse(
                File.Exists(Path.Combine(fixture.FeedRoot, "journal", "publication.lock")),
                "Rejected damaged Enterprise identity caused initialization side effects.");
        }
    }

    public static void ProductionCrashWindowsReplayExactly()
    {
        foreach (var stage in new[]
                 {
                     EnterpriseFeedPromotionStage.ImmutableReleaseReady,
                     EnterpriseFeedPromotionStage.ChannelHeadReplaced,
                     EnterpriseFeedPromotionStage.JournalEntryCreated,
                     EnterpriseFeedPromotionStage.JournalHeadReplaced,
                     EnterpriseFeedPromotionStage.OperationReceiptCommitted,
                 })
        {
            using var fixture = new Fixture("lab");
            var candidate = fixture.CreateCandidate(
                $"managed-v2026.08.31.{(int)stage + 10}",
                1,
                1,
                0,
                contentSalt: stage.ToString());
            var operationId = Guid.NewGuid().ToString("N");
            var options = fixture.ProductionOptions(candidate, operationId);
            var interrupted = new EnterpriseFeedPromoter(
                fixture.TimeProvider,
                value =>
                {
                    if (value == stage)
                    {
                        throw new SimulatedCrashException();
                    }
                });
            AssertThrows<SimulatedCrashException>(() => interrupted.Promote(options));
            var responsePath = Path.Combine(
                fixture.OperationsRoot,
                operationId,
                "response.v1.json");
            var before = File.Exists(responsePath) ? File.ReadAllBytes(responsePath) : null;
            var result = fixture.Promoter.Promote(options);
            var committed = File.ReadAllBytes(responsePath);
            if (before is not null)
            {
                AssertBytesEqual(before, committed);
            }
            var replay = fixture.Promoter.Promote(options);
            AssertBytesEqual(committed, File.ReadAllBytes(responsePath));
            AssertBytesEqual(
                EnterpriseFeedOperationStore.SerializeReceipt(result.ProductionReceipt!),
                EnterpriseFeedOperationStore.SerializeReceipt(replay.ProductionReceipt!));
            Ensou.Dsh.Enterprise.FeedPromoter.Program.WriteResultReceipt(
                options.ResultReceiptPath!,
                result,
                fixture.FeedRoot,
                candidate.Directory,
                fixture.TrustPath);
            var external = File.ReadAllText(options.ResultReceiptPath!);
            AssertFalse(external.Contains(fixture.FeedRoot, StringComparison.Ordinal),
                "Enterprise production result leaked an absolute path.");
            AssertTrue(result.JournalEntryPath.StartsWith("journal/lab/", StringComparison.Ordinal),
                "Enterprise production result did not use a logical journal path.");
            AssertTrue(result.ProductionReceipt!.ChannelManifestUri.StartsWith(
                "https://", StringComparison.Ordinal),
                "Enterprise production result URI was not HTTPS.");
        }
    }

    public static void ProductionCasConflictAndPendingGate()
    {
        using var fixture = new Fixture("lab");
        using var other = new Fixture("lab");
        var first = fixture.CreateCandidate("managed-v2026.08.31.20", 1, 1, 0);
        var wrongIdentity = other.InitializeProduction().FeedIdentitySha256;
        AssertThrows<InvalidOperationException>(() => fixture.Promoter.Promote(
            fixture.ProductionOptions(
                first,
                Guid.NewGuid().ToString("N"),
                identitySha256: wrongIdentity)));

        var operationId = Guid.NewGuid().ToString("N");
        var options = fixture.ProductionOptions(first, operationId);
        var interrupted = new EnterpriseFeedPromoter(
            fixture.TimeProvider,
            stage =>
            {
                if (stage == EnterpriseFeedPromotionStage.ImmutableReleaseReady)
                {
                    throw new SimulatedCrashException();
                }
            });
        AssertThrows<SimulatedCrashException>(() => interrupted.Promote(options));
        var second = fixture.CreateCandidate("managed-v2026.08.31.21", 1, 2, 0);
        var nextOperation = Guid.NewGuid().ToString("N");
        AssertThrows<InvalidOperationException>(() => fixture.Promoter.Promote(
            fixture.ProductionOptions(second, nextOperation)));
        AssertFalse(Directory.Exists(Path.Combine(fixture.OperationsRoot, nextOperation)),
            "Enterprise N plus one request persisted before recovery.");
        _ = fixture.Promoter.Promote(options);

        var staleOperation = Guid.NewGuid().ToString("N");
        AssertThrows<InvalidOperationException>(() => fixture.Promoter.Promote(
            fixture.ProductionOptions(
                second,
                staleOperation,
                EnterpriseFeedRawStateExpectation.Missing(),
                EnterpriseFeedRawStateExpectation.Missing())));
        AssertFalse(Directory.Exists(Path.Combine(fixture.OperationsRoot, staleOperation)),
            "Enterprise failed CAS left operation residue.");
        AssertThrows<InvalidOperationException>(() => fixture.Promoter.Promote(
            fixture.ProductionOptions(second, operationId)));
    }

    public static void OperationRequestTempRecoveryIsExact()
    {
        using (var fixture = new Fixture("lab"))
        {
            var candidate = fixture.CreateCandidate("managed-v2026.08.31.30", 1, 1, 0);
            var operationId = Guid.NewGuid().ToString("N");
            var request = CreateOperationRequest(fixture, candidate, operationId);
            Directory.CreateDirectory(Path.Combine(
                fixture.FeedRoot,
                "journal",
                "operations",
                $".{operationId}.request.tmp"));
            var session = EnterpriseFeedOperationStore.Begin(
                Path.Combine(fixture.FeedRoot, "journal"),
                request,
                EnterpriseFeedRawStateExpectation.Missing(),
                EnterpriseFeedRawStateExpectation.Missing(),
                allowCreate: true);
            AssertFalse(session.IsExistingRequest,
                "Enterprise empty pre-request temp was not rebuilt.");
        }
        using (var fixture = new Fixture("lab"))
        {
            var candidate = fixture.CreateCandidate("managed-v2026.08.31.31", 1, 1, 0);
            var operationId = Guid.NewGuid().ToString("N");
            var request = CreateOperationRequest(fixture, candidate, operationId);
            var operations = Path.Combine(fixture.FeedRoot, "journal", "operations");
            var temp = Path.Combine(operations, $".{operationId}.request.tmp");
            Directory.CreateDirectory(temp);
            var staged = FeedJson.Serialize(request);
            FeedPathGuard.WriteNewDurable(Path.Combine(temp, "request.v1.json"), staged);
            _ = EnterpriseFeedOperationStore.Begin(
                Path.Combine(fixture.FeedRoot, "journal"),
                request,
                EnterpriseFeedRawStateExpectation.Missing(),
                EnterpriseFeedRawStateExpectation.Missing(),
                allowCreate: true);
            AssertFalse(Directory.Exists(temp), "Enterprise exact staged request was not adopted.");
        }
        using (var fixture = new Fixture("lab"))
        {
            var candidate = fixture.CreateCandidate("managed-v2026.08.31.32", 1, 1, 0);
            var operationId = Guid.NewGuid().ToString("N");
            var request = CreateOperationRequest(fixture, candidate, operationId);
            var operations = Path.Combine(fixture.FeedRoot, "journal", "operations");
            var temp = Path.Combine(operations, $".{operationId}.request.tmp");
            Directory.CreateDirectory(temp);
            var staged = FeedJson.Serialize(request);
            FeedPathGuard.WriteNewDurable(Path.Combine(temp, "request.v1.json"), staged);
            var conflicting = EnterpriseFeedOperationStore.CreateRequest(
                fixture.Foundation(operationId),
                EnterpriseReleaseSetContract.Product,
                EnterpriseReleaseSetContract.ProductionEnvironment,
                "lab",
                candidate.ManifestBytes.LongLength,
                new string('b', 64),
                FeedJson.Sha256(File.ReadAllBytes(fixture.TrustPath)));
            AssertThrows<InvalidOperationException>(() => EnterpriseFeedOperationStore.Begin(
                Path.Combine(fixture.FeedRoot, "journal"),
                conflicting,
                EnterpriseFeedRawStateExpectation.Missing(),
                EnterpriseFeedRawStateExpectation.Missing(),
                allowCreate: true));
            AssertBytesEqual(staged, File.ReadAllBytes(Path.Combine(temp, "request.v1.json")));
        }
    }

    public static void ProductionSecurityBoundariesFailClosed()
    {
        using (var fixture = new Fixture("lab"))
        {
            var candidate = fixture.CreateCandidate("managed-v2026.08.31.40", 1, 1, 0);
            var options = fixture.ProductionOptions(candidate, Guid.NewGuid().ToString("N"));
            CreateHardLink(fixture.IdentityPath, fixture.IdentityPath + ".alias");
            AssertThrows<InvalidDataException>(() => fixture.Promoter.Promote(options));
        }
        using (var fixture = new Fixture("lab"))
        {
            var candidate = fixture.CreateCandidate("managed-v2026.08.31.41", 1, 1, 0);
            var options = fixture.ProductionOptions(candidate, Guid.NewGuid().ToString("N"));
            CreateHardLink(fixture.TrustPath, fixture.TrustPath + ".alias");
            AssertThrows<InvalidDataException>(() => fixture.Promoter.Promote(options));
        }
        using (var fixture = new Fixture("lab"))
        {
            var candidate = fixture.CreateCandidate("managed-v2026.08.31.42", 1, 1, 0);
            File.WriteAllText(Path.Combine(candidate.Directory, "unexpected"), "x");
            AssertThrows<InvalidDataException>(() => fixture.Promoter.Promote(
                fixture.ProductionOptions(candidate, Guid.NewGuid().ToString("N"))));
        }
        using (var fixture = new Fixture("lab"))
        {
            _ = fixture.InitializeProduction();
            Directory.CreateDirectory(fixture.OperationsRoot);
            File.WriteAllText(Path.Combine(fixture.OperationsRoot, "unexpected"), "x");
            var candidate = fixture.CreateCandidate("managed-v2026.08.31.43", 1, 1, 0);
            AssertThrows<InvalidDataException>(() => fixture.Promoter.Promote(
                fixture.ProductionOptions(candidate, Guid.NewGuid().ToString("N"))));
        }
        if (OperatingSystem.IsLinux())
        {
            using var fixture = new Fixture("lab");
            var candidate = fixture.CreateCandidate("managed-v2026.08.31.44", 1, 1, 0);
            var options = fixture.ProductionOptions(candidate, Guid.NewGuid().ToString("N"));
            File.SetUnixFileMode(
                fixture.FeedRoot,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                | UnixFileMode.GroupWrite);
            AssertThrows<UnauthorizedAccessException>(() => fixture.Promoter.Promote(options));
            File.SetUnixFileMode(
                fixture.FeedRoot,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            var original = File.ReadAllBytes(fixture.TrustPath);
            AssertThrows<IOException>(() => EnterpriseFeedLinuxSecurity.ReadRootOwnedStableFile(
                fixture.TrustPath,
                256 * 1024,
                "mutating trust",
                () =>
                {
                    var changed = original.ToArray();
                    changed[^1] ^= 1;
                    File.WriteAllBytes(fixture.TrustPath, changed);
                }));
        }
    }

    public static void InvalidForwardRequestLeavesNoOperationResidue()
    {
        using var fixture = new Fixture("lab");
        var first = fixture.CreateCandidate("managed-v2026.08.31.50", 2, 2, 0);
        _ = fixture.Promoter.Promote(
            fixture.ProductionOptions(first, Guid.NewGuid().ToString("N")));
        var rollback = fixture.CreateCandidate("managed-v2026.08.31.49", 2, 1, 0);
        var rejectedOperation = Guid.NewGuid().ToString("N");
        AssertThrows<InvalidDataException>(() => fixture.Promoter.Promote(
            fixture.ProductionOptions(rollback, rejectedOperation)));
        AssertFalse(Directory.Exists(Path.Combine(fixture.OperationsRoot, rejectedOperation)),
            "Enterprise invalid forward request left operation residue.");
        var valid = fixture.CreateCandidate("managed-v2026.08.31.51", 2, 3, 0);
        _ = fixture.Promoter.Promote(
            fixture.ProductionOptions(valid, Guid.NewGuid().ToString("N")));
    }

    public static void ProductionResultPathIsExternal()
    {
        using var fixture = new Fixture("lab");
        var candidate = fixture.CreateCandidate("managed-v2026.08.31.60", 1, 1, 0);
        var inside = Path.Combine(fixture.FeedRoot, "public", "result.json");
        var options = fixture.ProductionOptions(
            candidate,
            Guid.NewGuid().ToString("N"),
            resultPath: inside);
        var before = SnapshotTree(fixture.FeedRoot);
        AssertThrows<InvalidDataException>(() => fixture.Promoter.Promote(options));
        AssertTrue(before.SequenceEqual(SnapshotTree(fixture.FeedRoot), StringComparer.Ordinal),
            "Rejected Enterprise internal result path changed the feed tree.");
    }

    public static void GlobalPublicationLockSerializesCompetingCas()
    {
        using var fixture = new Fixture("lab");
        var first = fixture.CreateCandidate("managed-v2026.08.31.70", 1, 1, 0, "first");
        var second = fixture.CreateCandidate("managed-v2026.08.31.71", 1, 1, 0, "second");
        var firstOptions = fixture.ProductionOptions(first, Guid.NewGuid().ToString("N"));
        var secondOptions = fixture.ProductionOptions(second, Guid.NewGuid().ToString("N"));
        using var start = new ManualResetEventSlim();
        var attempts = new[] { firstOptions, secondOptions }.Select(options => Task.Run(() =>
        {
            start.Wait();
            try
            {
                _ = new EnterpriseFeedPromoter(fixture.TimeProvider, null).Promote(options);
                return true;
            }
            catch (IOException)
            {
                return false;
            }
            catch (InvalidOperationException)
            {
                return false;
            }
        })).ToArray();
        start.Set();
        Task.WaitAll(attempts);
        AssertEqual(1, attempts.Count(task => task.Result));
        AssertTrue(File.Exists(fixture.ChannelHeadPath),
            "Serialized Enterprise CAS did not commit one channel head.");
    }

    private static EnterpriseFeedOperationRequest CreateOperationRequest(
        Fixture fixture,
        Candidate candidate,
        string operationId) => EnterpriseFeedOperationStore.CreateRequest(
            fixture.Foundation(operationId),
            EnterpriseReleaseSetContract.Product,
            EnterpriseReleaseSetContract.ProductionEnvironment,
            "lab",
            candidate.ManifestBytes.LongLength,
            candidate.ManifestSha256,
            FeedJson.Sha256(File.ReadAllBytes(fixture.TrustPath)));

    private static string CaptureStandardOutput(Func<int> action)
    {
        var originalOut = Console.Out;
        var originalError = Console.Error;
        using var output = new StringWriter();
        using var error = new StringWriter();
        try
        {
            Console.SetOut(output);
            Console.SetError(error);
            AssertEqual(0, action());
            return output.ToString().Trim();
        }
        finally
        {
            Console.SetOut(originalOut);
            Console.SetError(originalError);
        }
    }

    private static string[] SnapshotTree(string root) =>
        Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(root, path))
            .Order(StringComparer.Ordinal)
            .ToArray();

    private static string HashFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    private static void AssertTrue(bool value, string message)
    {
        if (!value)
        {
            throw new InvalidOperationException(message);
        }
    }

    private static void AssertFalse(bool value, string message) => AssertTrue(!value, message);

    private static void AssertEqual<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected {expected}, got {actual}.");
        }
    }

    private static void AssertBytesEqual(byte[] expected, byte[] actual)
    {
        if (!expected.AsSpan().SequenceEqual(actual))
        {
            throw new InvalidOperationException("Byte sequences differ.");
        }
    }

    [DllImport("libc", EntryPoint = "link", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int CreateHardLinkLinux(string existingPath, string newPath);

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkWindows(
        string newPath,
        string existingPath,
        nint securityAttributes);

    private static void CreateHardLink(string existingPath, string newPath)
    {
        var succeeded = OperatingSystem.IsWindows()
            ? CreateHardLinkWindows(newPath, existingPath, 0)
            : CreateHardLinkLinux(existingPath, newPath) == 0;
        if (!succeeded)
        {
            throw new IOException(
                "Could not create Enterprise hard-link security fixture.",
                new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));
        }
    }

    private static void AssertThrows<T>(Action action) where T : Exception
    {
        try
        {
            action();
        }
        catch (T)
        {
            return;
        }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }

    internal sealed class Fixture : IDisposable
    {
        private readonly string _root;
        private readonly ECDsa _releaseSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _certificationSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly string _channel;
        private readonly bool _preserve;
        private readonly DateTimeOffset _now;
        private readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web)
        {
            WriteIndented = true,
        };

        public Fixture(
            string channel,
            string? root = null,
            bool preserve = false,
            DateTimeOffset? now = null)
        {
            _channel = channel;
            _root = root is null
                ? Path.Combine(
                    OperatingSystem.IsLinux() ? "/root" : Path.GetTempPath(),
                    $"ensou-feed-tests-{Guid.NewGuid():N}")
                : Path.GetFullPath(root);
            _preserve = preserve;
            _now = now ?? Now;
            if (Directory.Exists(_root) || File.Exists(_root))
            {
                throw new IOException("Feed test fixture root must be new.");
            }
            Directory.CreateDirectory(_root);
            FeedRoot = Path.Combine(_root, "feed");
            Directory.CreateDirectory(Path.Combine(FeedRoot, "staging"));
            Directory.CreateDirectory(Path.Combine(FeedRoot, "public", "releases"));
            foreach (var value in new[] { "lab", "pilot", "stable" })
            {
                Directory.CreateDirectory(Path.Combine(FeedRoot, "public", "channels", value));
                Directory.CreateDirectory(Path.Combine(FeedRoot, "journal", value));
            }
            TrustPath = Path.Combine(_root, "trust.json");
            File.WriteAllBytes(TrustPath, JsonSerializer.SerializeToUtf8Bytes(
                new EnterpriseFeedTrustConfiguration
                {
                    SchemaVersion = 1,
                    Product = EnterpriseReleaseSetContract.Product,
                    Environment = EnterpriseReleaseSetContract.ProductionEnvironment,
                    ManifestOrigin = new Uri("https://updates.example.test/"),
                    ArtifactOrigin = new Uri("https://updates.example.test/"),
                    ReleaseKeys = [PublicKey("release-test", _releaseSigner)],
                    CertificationKeys = [PublicKey("certification-test", _certificationSigner)],
                    AllowedClockSkewSeconds = 120,
                    MaximumOfflineGraceHours = 168,
                },
                _json));
            TimeProvider = new FixedTimeProvider(_now);
            Promoter = new EnterpriseFeedPromoter(TimeProvider, null);
        }

        public string FeedRoot { get; }
        public string TrustPath { get; }
        public FixedTimeProvider TimeProvider { get; }
        public EnterpriseFeedPromoter Promoter { get; }
        public string ReleasesRoot => Path.Combine(FeedRoot, "public", "releases");
        public string ChannelHeadPath => Path.Combine(
            FeedRoot,
            "public",
            "channels",
            _channel,
            "release-set.v2.json");
        public string JournalHeadPath => Path.Combine(FeedRoot, "journal", _channel, "head.json");
        public string OperationsRoot => Path.Combine(FeedRoot, "journal", "operations");
        public string IdentityPath => Path.Combine(
            FeedRoot,
            EnterpriseFeedIdentityStore.FileName);

        public string ResultPath(string operationId) =>
            Path.Combine(_root, $"promotion-result-{operationId}.json");

        public EnterpriseFeedInitializationResult InitializeProduction() =>
            EnterpriseFeedIdentityStore.Initialize(
                FeedRoot,
                EnterpriseFeedTrustConfiguration.Parse(
                    File.ReadAllBytes(TrustPath),
                    _channel));

        public EnterpriseFeedProductionFoundation Foundation(
            string operationId,
            EnterpriseFeedRawStateExpectation? expectedChannelHead = null,
            EnterpriseFeedRawStateExpectation? expectedJournalHead = null,
            string? identitySha256 = null)
        {
            var identity = File.Exists(IdentityPath)
                ? EnterpriseFeedIdentityStore.ReadInitializationResult(
                    FeedRoot,
                    EnterpriseReleaseSetContract.Product,
                    EnterpriseReleaseSetContract.ProductionEnvironment)
                : InitializeProduction();
            return new EnterpriseFeedProductionFoundation(
                operationId,
                identitySha256 ?? identity.FeedIdentitySha256,
                expectedChannelHead
                    ?? EnterpriseFeedOperationStore.Observe(
                        ChannelHeadPath,
                        512 * 1024,
                        "test channel head"),
                expectedJournalHead
                    ?? EnterpriseFeedOperationStore.Observe(
                        JournalHeadPath,
                        128 * 1024,
                        "test journal head"));
        }

        public EnterpriseFeedPromotionOptions ProductionOptions(
            Candidate candidate,
            string operationId,
            EnterpriseFeedRawStateExpectation? expectedChannelHead = null,
            EnterpriseFeedRawStateExpectation? expectedJournalHead = null,
            string? identitySha256 = null,
            string? resultPath = null) => Options(candidate.Directory) with
            {
                ResultReceiptPath = resultPath ?? ResultPath(operationId),
                ProductionFoundation = Foundation(
                    operationId,
                    expectedChannelHead,
                    expectedJournalHead,
                    identitySha256),
            };

        public EnterpriseFeedPromotionOptions Options(
            string candidate,
            string? receipt = null,
            string? authorization = null) => new(
                candidate,
                FeedRoot,
                TrustPath,
                _channel,
                receipt,
                authorization);

        public Candidate CreateCandidate(
            string releaseSetId,
            long generation,
            long sequence,
            long minimum,
        string contentSalt = "default",
        IReadOnlyList<string>? revoked = null,
        int minimumStartupStubProtocol =
            EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
        int maximumStartupStubProtocol =
            EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
        IReadOnlyDictionary<string, string>? artifactReleaseIds = null)
        {
            var directory = Path.Combine(_root, $"candidate-{Guid.NewGuid():N}");
            Directory.CreateDirectory(directory);
            var artifactDefinitions = new[]
            {
                (EnterpriseReleaseSetContract.LauncherComponent, "launcher.zip"),
                (EnterpriseReleaseSetContract.RuntimeComponent, "runtime.zip"),
                (EnterpriseReleaseSetContract.PluginPolicyComponent, "plugin-policy.zip"),
            };
            var unsigned = new EnterpriseReleaseSignature
            {
                Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
                KeyId = "release-test",
                Value = EnterpriseBase64Url.Encode(new byte[64]),
            };
            var paths = new List<string>();
            var artifacts = new List<EnterpriseReleaseArtifact>();
            foreach (var (component, fileName) in artifactDefinitions)
            {
                var artifactReleaseId = artifactReleaseIds is not null
                    && artifactReleaseIds.TryGetValue(component, out var configuredReleaseId)
                    ? configuredReleaseId
                    : releaseSetId;
                var bytes = Encoding.UTF8.GetBytes($"{artifactReleaseId}:{component}:{contentSalt}");
                var path = Path.Combine(directory, fileName);
                File.WriteAllBytes(path, bytes);
                paths.Add(path);
                artifacts.Add(new EnterpriseReleaseArtifact
                {
                    Component = component,
                    ReleaseId = artifactReleaseId,
                    Uri = new Uri(
                        $"https://updates.example.test/v2/releases/{releaseSetId}/{fileName}"),
                    SizeBytes = bytes.Length,
                    Sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)),
                    CompleteTreeSha256 = Convert.ToHexStringLower(
                        SHA256.HashData(Encoding.UTF8.GetBytes($"tree:{component}:{contentSalt}"))),
                    Signature = unsigned,
                });
            }
            var placeholder = new EnterpriseReleaseSetManifest
            {
                SchemaVersion = EnterpriseReleaseSetContract.SchemaVersion,
                Product = EnterpriseReleaseSetContract.Product,
                Environment = EnterpriseReleaseSetContract.ProductionEnvironment,
                Channel = _channel,
                ReleaseSetId = releaseSetId,
                Generation = generation,
                Sequence = sequence,
                MinAcceptedSequence = minimum,
                IssuedAtUtc = _now.AddMinutes(-1),
                ExpiresAtUtc = _now.AddDays(7),
                StartupStub = new EnterpriseStartupStubCompatibility
                {
                    MinimumProtocol = minimumStartupStubProtocol,
                    MaximumProtocol = maximumStartupStubProtocol,
                },
                RevokedReleaseSetIds = revoked ?? [],
                Artifacts = artifacts,
                Signature = unsigned,
            };
            artifacts = artifacts.Select(artifact => artifact with
            {
                Signature = Sign(
                    _releaseSigner,
                    "release-test",
                    EnterpriseReleaseCanonicalJson.ArtifactPayload(placeholder, artifact)),
            }).ToList();
            var signedArtifacts = placeholder with { Artifacts = artifacts };
            var manifest = signedArtifacts with
            {
                Signature = Sign(
                    _releaseSigner,
                    "release-test",
                    EnterpriseReleaseCanonicalJson.ManifestPayload(signedArtifacts)),
            };
            var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, _json);
            File.WriteAllBytes(Path.Combine(directory, "release-set.v2.json"), manifestBytes);
            return new Candidate(
                directory,
                manifest,
                manifestBytes,
                Convert.ToHexStringLower(SHA256.HashData(manifestBytes)),
                paths);
        }

        public StableCertification CreateStableCertification(Candidate candidate)
        {
            var receiptPath = Path.Combine(_root, $"receipt-{Guid.NewGuid():N}.json");
            var evidence = new string('a', 64);
            var receipt = new EnterpriseCertifiedDistributionReceipt
            {
                SchemaVersion = 1,
                Product = EnterpriseReleaseSetContract.Product,
                Channel = "stable",
                ReleaseSetId = candidate.Manifest.ReleaseSetId,
                ManifestSha256 = candidate.ManifestSha256,
                Installer = new CertifiedInstaller
                {
                    FileName = "EnsouDshEnterpriseSetup.exe",
                    SizeBytes = 123456,
                    Sha256 = new string('b', 64),
                    AuthenticodeStatus = "Valid",
                    SignerSha256Thumbprint = new string('c', 64),
                    Timestamped = true,
                },
                Feed = new CertifiedFeed
                {
                    ManifestUri = new Uri(
                        "https://updates.example.test/v2/channels/pilot/release-set.v2.json"),
                    ExternalManifestSha256 = candidate.ManifestSha256,
                    VerifiedArtifactCount = 3,
                    AllArtifactSignaturesValid = true,
                    AllArtifactHashesValid = true,
                    ImmutablePublication = true,
                    AtomicChannelHead = true,
                    VerifiedAtUtc = _now.AddHours(-2),
                },
                Certification = new CertifiedTestMatrix
                {
                    CleanInstallPassed = true,
                    OldInstallUpgradePassed = true,
                    ActualRuntimeStarted = true,
                    WebUiOpened = true,
                    EnterprisePluginLoaded = true,
                    WholeHomeRestorePassed = true,
                    InterruptionMatrixPassed = true,
                    WeakNetworkResumePassed = true,
                    OfflineAndReplayMatrixPassed = true,
                    SameBytesAsPilot = true,
                    PilotSoakPassed = true,
                    CleanDeviceEvidenceSha256 = evidence,
                    UpgradeDeviceEvidenceSha256 = evidence,
                    FailureMatrixEvidenceSha256 = evidence,
                },
                ApprovedAtUtc = _now.AddHours(-1),
                DistributionAuthorized = true,
            };
            var receiptBytes = JsonSerializer.SerializeToUtf8Bytes(receipt, _json);
            File.WriteAllBytes(receiptPath, receiptBytes);
            var placeholder = new EnterpriseStablePromotionAuthorization
            {
                SchemaVersion = 1,
                Product = EnterpriseReleaseSetContract.Product,
                Channel = "stable",
                ReleaseSetId = candidate.Manifest.ReleaseSetId,
                ManifestSha256 = candidate.ManifestSha256,
                CertificationReceiptSha256 = Convert.ToHexStringLower(SHA256.HashData(receiptBytes)),
                InstallerFileName = receipt.Installer.FileName,
                InstallerSizeBytes = receipt.Installer.SizeBytes,
                InstallerSha256 = receipt.Installer.Sha256,
                IssuedAtUtc = _now.AddMinutes(-5),
                ExpiresAtUtc = _now.AddDays(1),
                Signature = new EnterpriseReleaseSignature
                {
                    Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
                    KeyId = "certification-test",
                    Value = EnterpriseBase64Url.Encode(new byte[64]),
                },
            };
            var authorization = placeholder with
            {
                Signature = Sign(
                    _certificationSigner,
                    "certification-test",
                    EnterpriseStablePromotionAuthorization.CanonicalPayload(placeholder)),
            };
            var authorizationPath = Path.Combine(
                _root,
                $"authorization-{Guid.NewGuid():N}.json");
            File.WriteAllBytes(
                authorizationPath,
                JsonSerializer.SerializeToUtf8Bytes(authorization, _json));
            return new StableCertification(receiptPath, authorizationPath);
        }

        public void Dispose()
        {
            _releaseSigner.Dispose();
            _certificationSigner.Dispose();
            if (!_preserve && Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }

        private static EnterpriseReleasePublicKey PublicKey(string keyId, ECDsa signer)
        {
            var parameters = signer.ExportParameters(includePrivateParameters: false);
            return new EnterpriseReleasePublicKey(
                keyId,
                EnterpriseBase64Url.Encode(parameters.Q.X!),
                EnterpriseBase64Url.Encode(parameters.Q.Y!));
        }

        private static EnterpriseReleaseSignature Sign(
            ECDsa signer,
            string keyId,
            ReadOnlySpan<byte> payload) => new()
            {
                Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
                KeyId = keyId,
                Value = EnterpriseBase64Url.Encode(signer.SignData(
                    payload,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
            };
    }

    internal sealed record Candidate(
        string Directory,
        EnterpriseReleaseSetManifest Manifest,
        byte[] ManifestBytes,
        string ManifestSha256,
        IReadOnlyList<string> ArtifactPaths);

    internal sealed record StableCertification(string ReceiptPath, string AuthorizationPath);

    internal sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class SimulatedCrashException : Exception;
}
