using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.Personal.FeedPromoter;

if (args is ["--docker-e2e", var promoterPath, var workRoot])
{
    return Tests.RunDockerE2E(promoterPath, workRoot);
}

if (args is ["--export-completed-fixture", var exportRoot])
{
    try { Tests.ExportCompletedFixture(exportRoot); return 0; }
    catch (Exception exception) { Console.Error.WriteLine(exception); return 1; }
}

if (args is ["--distribution-receipt-schema-contract"])
{
    try
    {
        Tests.CanonicalDistributionReceiptMatchesV2Schema();
        Console.WriteLine("PERSONAL-DISTRIBUTION-RECEIPT-SCHEMA-CONTRACT-PASS");
        return 0;
    }
    catch (Exception exception)
    {
        Console.Error.WriteLine(
            $"PERSONAL-DISTRIBUTION-RECEIPT-SCHEMA-CONTRACT-FAIL: {exception.Message}");
        return 1;
    }
}

var tests = new (string Name, Action Run)[]
{
    ("personal Lab publishes canonical two-artifact release", Tests.PublishesLab),
    ("tampered personal artifact cannot advance the head", Tests.RejectsTamperedArtifact),
    ("sequence and floor rollback cannot advance the head", Tests.RejectsOrderingRollback),
    ("revocation rollback cannot advance the head", Tests.RejectsRevocationRollback),
    ("duplicate manifest JSON is rejected", Tests.RejectsDuplicateManifestJson),
    ("immutable release ID cannot be overwritten", Tests.RejectsImmutableConflict),
    ("crash after immutable release is recoverable", Tests.RecoversAfterReleaseMove),
    ("crash after channel switch repairs journal", Tests.RecoversAfterHeadSwitch),
    ("crash after journal entry repairs journal head", Tests.RecoversAfterJournalEntry),
    ("full hash-chain detects historical journal tamper", Tests.RejectsHistoricalJournalTamper),
    ("journal high-water rejects channel-head rollback", Tests.RejectsChannelHeadRollback),
    ("Stable fails closed without Pilot certification", Tests.StableRequiresCertification),
    ("non-Stable rejects production gate evidence", Tests.NonStableRejectsProductionGateEvidence),
    ("Stable accepts exact certified Pilot bytes", Tests.AcceptsCertifiedStable),
    ("canonical distribution receipt matches published v2 schema", Tests.CanonicalDistributionReceiptMatchesV2Schema),
    ("distribution preflight is read-only and matches certification", Tests.DistributionPreflightIsReadOnlyAndMatchesCertification),
    ("distribution preflight CLI accepts only its exact read-only inputs", Tests.DistributionPreflightCliAcceptsOnlyReadOnlyInputs),
    ("distribution preflight rejects non-HTTPS Pilot evidence", Tests.DistributionPreflightRejectsNonHttpsPilotEvidence),
    ("distribution preflight binds Stable to the compiled release key", Tests.DistributionPreflightBindsStableToCompiledReleaseKey),
    ("distribution preflight binds the compiled low-S cutover", Tests.DistributionPreflightBindsCompiledLowSCutover),
    ("distribution preflight rejects an untimestamped Installer", Tests.DistributionPreflightRejectsUntimestampedInstaller),
    ("distribution preflight rejects Pilot and Stable provenance drift", Tests.DistributionPreflightRejectsProvenanceDrift),
    ("distribution preflight rejects changed lifecycle evidence", Tests.DistributionPreflightRejectsChangedLifecycleEvidence),
    ("Stable rejects rebuilt bytes", Tests.RejectsStableRebuild),
    ("Stable rejects a tampered receipt", Tests.RejectsTamperedStableReceipt),
    ("Stable rejects expired independent authorization", Tests.RejectsExpiredAuthorization),
    ("duplicate certification JSON is rejected", Tests.RejectsDuplicateCertificationJson),
    ("Stable rejects a missing lifecycle sidecar", Tests.RejectsMissingLifecycleSidecar),
    ("Stable rejects a random lifecycle reference digest", Tests.RejectsRandomLifecycleDigest),
    ("Stable rejects lifecycle bytes changed after certification", Tests.RejectsChangedLifecycleSidecar),
    ("Stable rejects a noncanonical lifecycle sidecar even when referenced", Tests.RejectsNoncanonicalLifecycleSidecar),
    ("Stable rejects wrong lifecycle kind and run identity", Tests.RejectsWrongLifecycleIdentity),
    ("Stable rejects a lifecycle targeting other release bytes", Tests.RejectsWrongLifecycleTarget),
    ("Stable rejects an incomplete required gate list", Tests.RejectsMissingLifecycleGate),
    ("Stable rejects a discontinuous second update", Tests.RejectsBrokenSecondUpdateChain),
    ("Stable rejects repair that was not offline", Tests.RejectsOnlineRepairEvidence),
    ("Stable rejects previous Runtime not started", Tests.RejectsPreviousRuntimeNotStarted),
    ("Stable rejects changed history or workspace witnesses", Tests.RejectsChangedLocalDataWitness),
    ("release and certification keys must be independent", Tests.RejectsSharedTrustKey),
    ("feed trust requires an explicit low-S cutover and unique key points", Tests.RejectsImplicitCutoverAndKeyAliases),
    ("Linux trust policy reads reject unsafe paths and bind one file identity", Tests.LinuxTrustPolicyReadIsIdentityBound),
    ("production initialize emits a stable unique machine identity", Tests.ProductionInitializeEmitsMachineIdentity),
    ("production initialize recovers an exact partial layout", Tests.ProductionInitializeRecoversPartialLayout),
    ("production operation crash windows replay exact durable response", Tests.ProductionCrashWindowsReplayExactly),
    ("production CAS identity and operation conflicts fail closed", Tests.ProductionCasAndOperationConflictsFailClosed),
    ("pending operation blocks N plus one until exact recovery", Tests.PendingOperationBlocksNextPromotion),
    ("operation request temp recovery preserves exact binding", Tests.OperationRequestTempRecoveryIsExact),
    ("hardlinks and extra operation inventory fail closed", Tests.ProductionTreeAttacksFailClosed),
    ("invalid forward request leaves no operation residue", Tests.InvalidForwardRequestLeavesNoOperationResidue),
    ("production result path cannot enter managed inputs", Tests.ProductionResultPathIsExternal),
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
Console.WriteLine($"{tests.Length - failures}/{tests.Length} personal feed promoter checks passed.");
return failures == 0 ? 0 : 1;

internal static class Tests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 26, 2, 0, 0, TimeSpan.Zero);

    public static void PublishesLab()
    {
        using var fixture = new Fixture();
        var candidate = fixture.CreateCandidate("lab", "personal-v2026.08.26.1", 1, 1, 0);
        var result = fixture.Promoter.Promote(fixture.Options(candidate));
        AssertTrue(result.ChannelHeadChanged, "First Lab promotion did not replace the head.");
        AssertTrue(result.ImmutableReleaseCreated, "First Lab promotion did not create release bytes.");
        AssertEqual(candidate.ManifestSha256, result.ManifestSha256);
        AssertBytesEqual(candidate.ManifestBytes, File.ReadAllBytes(fixture.ChannelHead("lab")));
        AssertEqual(2, Directory.EnumerateFiles(
            Path.Combine(fixture.ReleasesRoot, candidate.Manifest.ReleaseSetId)).Count());
        AssertTrue(File.Exists(result.JournalEntryPath), "Promotion journal entry is missing.");
        AssertTrue(File.Exists(fixture.JournalHead("lab")), "Promotion journal head is missing.");
    }

    public static void RejectsImplicitCutoverAndKeyAliases()
    {
        using var fixture = new Fixture();
        var missingCutover = JsonNode.Parse(fixture.CreateTrustBytes())!.AsObject();
        AssertTrue(
            missingCutover.Remove("canonicalLowSFromSequence"),
            "Trust fixture did not contain the explicit low-S cutover.");
        AssertThrows<InvalidDataException>(() =>
            PersonalFeedTrustConfiguration.Parse(
                Encoding.UTF8.GetBytes(missingCutover.ToJsonString())));
        AssertThrows<InvalidDataException>(() =>
            PersonalFeedTrustConfiguration.Parse(
                fixture.CreateTrustWithCertificationAlias()));
    }

    public static void RejectsTamperedArtifact()
    {
        using var fixture = new Fixture();
        var first = fixture.CreateCandidate("lab", "personal-v2026.08.26.1", 1, 1, 0);
        _ = fixture.Promoter.Promote(fixture.Options(first));
        var before = File.ReadAllBytes(fixture.ChannelHead("lab"));
        var second = fixture.CreateCandidate("lab", "personal-v2026.08.26.2", 1, 2, 0);
        File.AppendAllText(second.ArtifactPaths[0], "tamper", Encoding.UTF8);
        AssertThrows<InvalidDataException>(() => fixture.Promoter.Promote(fixture.Options(second)));
        AssertBytesEqual(before, File.ReadAllBytes(fixture.ChannelHead("lab")));
    }

    public static void RejectsOrderingRollback()
    {
        using var fixture = new Fixture();
        var first = fixture.CreateCandidate("lab", "personal-v2026.08.26.2", 2, 2, 2);
        _ = fixture.Promoter.Promote(fixture.Options(first));
        var rollback = fixture.CreateCandidate("lab", "personal-v2026.08.26.3", 2, 3, 1);
        AssertThrows<InvalidDataException>(() => fixture.Promoter.Promote(fixture.Options(rollback)));
    }

    public static void RejectsRevocationRollback()
    {
        using var fixture = new Fixture();
        var first = fixture.CreateCandidate(
            "lab",
            "personal-v2026.08.26.2",
            1,
            2,
            0,
            revoked: ["personal-v2026.08.25.1"]);
        _ = fixture.Promoter.Promote(fixture.Options(first));
        var second = fixture.CreateCandidate("lab", "personal-v2026.08.26.3", 1, 3, 0);
        AssertThrows<InvalidDataException>(() => fixture.Promoter.Promote(fixture.Options(second)));
    }

    public static void NonStableRejectsProductionGateEvidence()
    {
        using var fixture = new Fixture();
        var candidate = fixture.CreateCandidate(
            "pilot",
            "personal-v2026.08.26.4",
            1,
            4,
            0);
        var ignoredGatePath = Path.Combine(fixture.FeedRoot, "ignored-production-gate.json");
        AssertThrows<InvalidDataException>(() => fixture.Promoter.Promote(
            fixture.Options(candidate, productionGateEvidence: ignoredGatePath)));
        AssertFalse(
            File.Exists(fixture.ChannelHead("pilot")),
            "Pilot head moved despite a Stable-only production gate argument.");
    }

    public static void RejectsDuplicateManifestJson()
    {
        using var fixture = new Fixture();
        var candidate = fixture.CreateCandidate("lab", "personal-v2026.08.26.1", 1, 1, 0);
        var json = Encoding.UTF8.GetString(candidate.ManifestBytes);
        json = json.Replace(
            "\"channel\":\"lab\",",
            "\"channel\":\"lab\",\"channel\":\"lab\",",
            StringComparison.Ordinal);
        File.WriteAllText(
            Path.Combine(candidate.Directory, "release-set.v2.json"),
            json,
            new UTF8Encoding(false));
        AssertThrows<InvalidDataException>(() => fixture.Promoter.Promote(fixture.Options(candidate)));
        AssertFalse(File.Exists(fixture.ChannelHead("lab")), "Duplicate manifest was published.");
    }

    public static void RejectsImmutableConflict()
    {
        using var fixture = new Fixture();
        var first = fixture.CreateCandidate("lab", "personal-v2026.08.26.1", 1, 1, 0);
        _ = fixture.Promoter.Promote(fixture.Options(first));
        var conflict = fixture.CreateCandidate(
            "pilot",
            "personal-v2026.08.26.1",
            2,
            2,
            0,
            contentSalt: "different");
        AssertThrows<InvalidDataException>(() => fixture.Promoter.Promote(fixture.Options(conflict)));
    }

    public static void RecoversAfterReleaseMove()
    {
        using var fixture = new Fixture();
        var candidate = fixture.CreateCandidate("pilot", "personal-v2026.08.26.1", 1, 1, 0);
        var interrupted = new PersonalFeedPromoter(
            fixture.TimeProvider,
            stage =>
            {
                if (stage == PersonalFeedPromotionStage.ImmutableReleaseReady)
                {
                    throw new SimulatedCrashException();
                }
            });
        AssertThrows<SimulatedCrashException>(() =>
            interrupted.Promote(fixture.Options(candidate)));
        AssertFalse(File.Exists(fixture.ChannelHead("pilot")), "Head moved before fault point.");
        var recovered = fixture.Promoter.Promote(fixture.Options(candidate));
        AssertFalse(recovered.ImmutableReleaseCreated, "Recovery overwrote immutable bytes.");
        AssertTrue(recovered.ChannelHeadChanged, "Recovery did not advance the head.");
    }

    public static void RecoversAfterHeadSwitch()
    {
        using var fixture = new Fixture();
        var candidate = fixture.CreateCandidate("pilot", "personal-v2026.08.26.1", 1, 1, 0);
        var interrupted = new PersonalFeedPromoter(
            fixture.TimeProvider,
            stage =>
            {
                if (stage == PersonalFeedPromotionStage.ChannelHeadReplaced)
                {
                    throw new SimulatedCrashException();
                }
            });
        AssertThrows<SimulatedCrashException>(() =>
            interrupted.Promote(fixture.Options(candidate)));
        AssertTrue(File.Exists(fixture.ChannelHead("pilot")), "Fault did not follow head replace.");
        AssertFalse(File.Exists(fixture.JournalHead("pilot")), "Journal unexpectedly committed.");
        var recovered = fixture.Promoter.Promote(fixture.Options(candidate));
        AssertFalse(recovered.ChannelHeadChanged, "Recovery replaced an identical head.");
        AssertTrue(File.Exists(fixture.JournalHead("pilot")), "Recovery did not repair journal.");
    }

    public static void RecoversAfterJournalEntry()
    {
        using var fixture = new Fixture();
        var candidate = fixture.CreateCandidate("pilot", "personal-v2026.08.26.1", 1, 1, 0);
        var interrupted = new PersonalFeedPromoter(
            fixture.TimeProvider,
            stage =>
            {
                if (stage == PersonalFeedPromotionStage.JournalEntryCreated)
                {
                    throw new SimulatedCrashException();
                }
            });
        AssertThrows<SimulatedCrashException>(() =>
            interrupted.Promote(fixture.Options(candidate)));
        AssertFalse(File.Exists(fixture.JournalHead("pilot")), "Journal head unexpectedly committed.");
        _ = fixture.Promoter.Promote(fixture.Options(candidate));
        AssertTrue(File.Exists(fixture.JournalHead("pilot")), "Orphan entry was not recovered.");
    }

    public static void RejectsHistoricalJournalTamper()
    {
        using var fixture = new Fixture();
        var first = fixture.CreateCandidate("lab", "personal-v2026.08.26.1", 1, 1, 0);
        var firstResult = fixture.Promoter.Promote(fixture.Options(first));
        var second = fixture.CreateCandidate("lab", "personal-v2026.08.26.2", 1, 2, 0);
        _ = fixture.Promoter.Promote(fixture.Options(second));
        File.AppendAllText(firstResult.JournalEntryPath, " ", Encoding.UTF8);
        var third = fixture.CreateCandidate("lab", "personal-v2026.08.26.3", 1, 3, 0);
        AssertThrows<InvalidDataException>(() => fixture.Promoter.Promote(fixture.Options(third)));
    }

    public static void RejectsChannelHeadRollback()
    {
        using var fixture = new Fixture();
        var first = fixture.CreateCandidate("lab", "personal-v2026.08.26.1", 1, 1, 0);
        _ = fixture.Promoter.Promote(fixture.Options(first));
        var second = fixture.CreateCandidate("lab", "personal-v2026.08.26.2", 1, 2, 0);
        _ = fixture.Promoter.Promote(fixture.Options(second));
        File.WriteAllBytes(fixture.ChannelHead("lab"), first.ManifestBytes);
        var third = fixture.CreateCandidate("lab", "personal-v2026.08.26.3", 1, 3, 0);
        AssertThrows<InvalidDataException>(() => fixture.Promoter.Promote(fixture.Options(third)));
    }

    public static void StableRequiresCertification()
    {
        using var fixture = new Fixture();
        var pilot = fixture.CreateCandidate("pilot", "personal-v2026.08.26.1", 1, 1, 0);
        _ = fixture.Promoter.Promote(fixture.Options(pilot));
        var stable = fixture.CreateCandidate("stable", "personal-v2026.08.26.1", 1, 1, 0);
        AssertThrows<InvalidDataException>(() => fixture.Promoter.Promote(fixture.Options(stable)));
        AssertFalse(File.Exists(fixture.ChannelHead("stable")), "Uncertified Stable was published.");
    }

    public static void AcceptsCertifiedStable()
    {
        using var fixture = new Fixture();
        var pilot = fixture.CreateCandidate("pilot", "personal-v2026.08.26.3", 1, 3, 0);
        _ = fixture.Promoter.Promote(fixture.Options(pilot));
        var stable = fixture.CreateCandidate("stable", "personal-v2026.08.26.3", 1, 3, 0);
        var certification = fixture.CreateStableCertification(pilot, stable);
        var result = fixture.Promoter.Promote(fixture.Options(stable, certification));
        AssertTrue(result.ChannelHeadChanged, "Certified Stable did not advance.");
        AssertFalse(result.ImmutableReleaseCreated, "Stable rebuilt Pilot artifact bytes.");
    }

    public static void CanonicalDistributionReceiptMatchesV2Schema()
    {
        using var fixture = new Fixture();
        var pilot = fixture.CreateCandidate("pilot", "personal-v2026.08.26.3", 1, 3, 0);
        _ = fixture.Promoter.Promote(fixture.Options(pilot));
        var stable = fixture.CreateCandidate("stable", "personal-v2026.08.26.3", 1, 3, 0);
        var certification = fixture.CreateStableCertification(pilot, stable);
        var receiptPath = Path.Combine(
            Path.GetDirectoryName(certification.ReceiptPath)!,
            $"producer-receipt-{Guid.NewGuid():N}.json");
        var producer = new PersonalDistributionReceiptProducer(fixture.TimeProvider);
        _ = producer.Produce(new PersonalDistributionCertificationOptions(
            fixture.TrustPath,
            Path.Combine(pilot.Directory, "release-set.v2.json"),
            Path.Combine(stable.Directory, "release-set.v2.json"),
            certification.ProductionGateEvidencePath,
            certification.ExternalPilotFeedEvidencePath,
            certification.CleanDeviceLifecyclePath,
            certification.TwoUpdateUpgradeLifecyclePath,
            certification.FailureRecoveryLifecyclePath,
            receiptPath));

        var schemaPath = FindRepositoryFile(
            "release",
            "schemas",
            "personal-certified-distribution-receipt-v2.schema.json");
        AssertTrue(
            ValidateJsonSchema(receiptPath, schemaPath, reportFailure: true),
            "Canonical producer receipt did not validate against the published v2 schema.");
        var receiptBytes = File.ReadAllBytes(receiptPath);
        var receipt = PersonalCertifiedDistributionReceipt.Parse(receiptBytes);
        AssertEqual(2, receipt.SchemaVersion);
        AssertEqual(PersonalCertifiedInstaller.OfficialFileName, receipt.Installer.FileName);
        AssertTrue(
            receipt.Installer.IsValid(new string('d', 64)),
            "Canonical producer receipt did not retain the pinned signer.");
        AssertFalse(
            receipt.Installer.IsValid(new string('e', 64)),
            "Canonical producer receipt accepted a signer outside the trust policy.");

        AssertSchemaRejects(document => document["schemaVersion"] = 1, "schemaVersion");
        AssertSchemaRejects(
            document => document.Remove("productionGateEvidence"),
            "productionGateEvidence");
        AssertSchemaRejects(
            document => document["installer"]!.AsObject()["fileName"] = "PersonalSetup.exe",
            "official Installer fileName");
        AssertSchemaRejects(
            document => document["installer"]!.AsObject()["signatureType"] = "Catalog",
            "Installer signatureType");

        var mismatchedGate = JsonNode.Parse(
            File.ReadAllBytes(certification.ProductionGateEvidencePath))!.AsObject();
        mismatchedGate["installer"]!.AsObject()["signerSha256Thumbprint"] = new string('e', 64);
        var mismatchedGatePath = Path.Combine(
            Path.GetDirectoryName(certification.ProductionGateEvidencePath)!,
            $"wrong-signer-gate-{Guid.NewGuid():N}.json");
        File.WriteAllText(
            mismatchedGatePath,
            mismatchedGate.ToJsonString(),
            new UTF8Encoding(false));
        _ = PersonalProductionGateEvidence.ParseCanonical(
            File.ReadAllBytes(mismatchedGatePath));
        AssertThrows<InvalidDataException>(() => producer.Produce(
            new PersonalDistributionCertificationOptions(
                fixture.TrustPath,
                Path.Combine(pilot.Directory, "release-set.v2.json"),
                Path.Combine(stable.Directory, "release-set.v2.json"),
                mismatchedGatePath,
                certification.ExternalPilotFeedEvidencePath,
                certification.CleanDeviceLifecyclePath,
                certification.TwoUpdateUpgradeLifecyclePath,
                certification.FailureRecoveryLifecyclePath,
                Path.Combine(
                    Path.GetDirectoryName(receiptPath)!,
                    $"wrong-signer-receipt-{Guid.NewGuid():N}.json"))));
        return;

        void AssertSchemaRejects(Action<JsonObject> mutate, string subject)
        {
            var document = JsonNode.Parse(receiptBytes)!.AsObject();
            mutate(document);
            var invalidPath = Path.Combine(
                Path.GetDirectoryName(receiptPath)!,
                $"schema-negative-{Guid.NewGuid():N}.json");
            File.WriteAllText(invalidPath, document.ToJsonString(), new UTF8Encoding(false));
            AssertFalse(
                ValidateJsonSchema(invalidPath, schemaPath),
                $"Published v2 schema accepted an invalid {subject}.");
        }
    }

    public static void DistributionPreflightIsReadOnlyAndMatchesCertification()
    {
        using var fixture = new Fixture();
        var pilot = fixture.CreateCandidate("pilot", "personal-v2026.08.26.3", 1, 3, 0);
        var stable = fixture.CreateCandidate("stable", "personal-v2026.08.26.3", 1, 3, 0);
        var certification = fixture.CreateStableCertification(pilot, stable);
        var producer = new PersonalDistributionReceiptProducer(fixture.TimeProvider);
        var root = Path.GetDirectoryName(certification.ReceiptPath)!;
        var before = SnapshotTree(root);

        var preflight = producer.Preflight(
            PreflightOptions(fixture, pilot, stable, certification));

        var after = SnapshotTree(root);
        AssertTrue(
            before.SequenceEqual(after, StringComparer.Ordinal),
            "Distribution preflight changed the input tree.");
        AssertFalse(
            preflight.DistributionReceiptCreated,
            "Distribution preflight claimed that it created an authorization receipt.");
        AssertEqual(stable.Manifest.ReleaseSetId, preflight.ReleaseSetId);
        AssertEqual(pilot.ManifestSha256, preflight.PilotManifestSha256);
        AssertEqual(stable.ManifestSha256, preflight.StableManifestSha256);
        AssertEqual(stable.Manifest.Provenance.LauncherRepositoryCommit, preflight.LauncherRepositoryCommit);
        AssertEqual(stable.Manifest.Provenance.HarnessSourceTag, preflight.HarnessSourceTag);
        AssertEqual(stable.Manifest.Provenance.HarnessSourceCommit, preflight.HarnessSourceCommit);
        AssertEqual("https://updates.example.test/", preflight.ManifestOrigin);
        AssertEqual("https://updates.example.test/", preflight.ArtifactOrigin);
        AssertEqual(stable.Manifest.Signature!.KeyId, preflight.ReleaseKeyId);
        AssertEqual(new string('d', 64), preflight.AuthenticodeSignerSha256Thumbprint);

        var outputPath = Path.Combine(root, $"preflight-parity-{Guid.NewGuid():N}.json");
        var produced = producer.Produce(
            CertificationOptions(fixture, pilot, stable, certification, outputPath));
        AssertEqual(preflight.ReceiptPreviewSizeBytes, produced.ReceiptSizeBytes);
        AssertEqual(preflight.ReceiptPreviewSha256, produced.ReceiptSha256);
        AssertEqual(preflight.InstallerSha256, produced.InstallerSha256);
        AssertEqual(
            preflight.ProductionGateEvidenceSha256,
            produced.ProductionGateEvidenceSha256);
    }

    public static void DistributionPreflightCliAcceptsOnlyReadOnlyInputs()
    {
        using var fixture = new Fixture();
        var pilot = fixture.CreateCandidate("pilot", "personal-v2026.08.26.3", 1, 3, 0);
        var stable = fixture.CreateCandidate("stable", "personal-v2026.08.26.3", 1, 3, 0);
        var certification = fixture.CreateStableCertification(pilot, stable);
        var arguments = new[]
        {
            "preflight-distribution",
            "--trust-policy",
            fixture.TrustPath,
            "--pilot-manifest",
            Path.Combine(pilot.Directory, "release-set.v2.json"),
            "--stable-manifest",
            Path.Combine(stable.Directory, "release-set.v2.json"),
            "--production-gate-evidence",
            certification.ProductionGateEvidencePath,
            "--external-pilot-feed-evidence",
            certification.ExternalPilotFeedEvidencePath,
            "--clean-device-lifecycle",
            certification.CleanDeviceLifecyclePath,
            "--two-update-upgrade-lifecycle",
            certification.TwoUpdateUpgradeLifecyclePath,
            "--failure-recovery-lifecycle",
            certification.FailureRecoveryLifecyclePath,
        };

        var parsed = Ensou.Dsh.Personal.FeedPromoter.Program.ParsePreflight(arguments);
        AssertEqual(fixture.TrustPath, parsed.TrustPolicyPath);
        AssertEqual(certification.FailureRecoveryLifecyclePath, parsed.FailureRecoveryLifecyclePath);
        AssertThrows<ArgumentException>(() =>
            Ensou.Dsh.Personal.FeedPromoter.Program.ParsePreflight(
                [.. arguments, "--output", Path.Combine(fixture.FeedRoot, "receipt.json")]));
        var repeated = arguments.ToArray();
        repeated[^2] = "--trust-policy";
        AssertThrows<ArgumentException>(() =>
            Ensou.Dsh.Personal.FeedPromoter.Program.ParsePreflight(repeated));
        var unknown = arguments.ToArray();
        unknown[^2] = "--unexpected";
        AssertThrows<ArgumentException>(() =>
            Ensou.Dsh.Personal.FeedPromoter.Program.ParsePreflight(unknown));
    }

    public static void DistributionPreflightRejectsNonHttpsPilotEvidence()
    {
        using var fixture = new Fixture();
        var pilot = fixture.CreateCandidate("pilot", "personal-v2026.08.26.3", 1, 3, 0);
        var stable = fixture.CreateCandidate("stable", "personal-v2026.08.26.3", 1, 3, 0);
        var certification = fixture.CreateStableCertification(pilot, stable);
        var feed = PersonalCertifiedFeedEvidence.ParseCanonical(
            File.ReadAllBytes(certification.ExternalPilotFeedEvidencePath));
        File.WriteAllBytes(
            certification.ExternalPilotFeedEvidencePath,
            (feed with
            {
                PilotManifestUri = new Uri(
                    "http://updates.example.test/v2/channels/pilot/release-set.v2.json"),
            }).SerializeCanonical());

        AssertThrows<InvalidDataException>(() =>
            new PersonalDistributionReceiptProducer(fixture.TimeProvider).Preflight(
                PreflightOptions(fixture, pilot, stable, certification)));
    }

    public static void DistributionPreflightBindsStableToCompiledReleaseKey()
    {
        using var fixture = new Fixture();
        var pilot = fixture.CreateCandidate("pilot", "personal-v2026.08.26.3", 1, 3, 0);
        var stable = fixture.CreateCandidate("stable", "personal-v2026.08.26.3", 1, 3, 0);
        var certification = fixture.CreateStableCertification(pilot, stable);
        using var alternateSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var alternateKey = PersonalReleaseSetSigner.ExportPublicKey(
            "personal-release-alternate-test",
            alternateSigner);
        var trust = PersonalFeedTrustConfiguration.Parse(
            File.ReadAllBytes(fixture.TrustPath));
        File.WriteAllBytes(
            fixture.TrustPath,
            PersonalFeedJson.Serialize(trust with
            {
                ReleaseKeys = trust.ReleaseKeys.Append(alternateKey).ToArray(),
            }));

        var gate = PersonalProductionGateEvidence.ParseCanonical(
            File.ReadAllBytes(certification.ProductionGateEvidencePath));
        var alternateCompiledTrust = gate.CompiledTrust with
        {
            ReleaseKeyId = alternateKey.KeyId,
            ReleaseKeyX = alternateKey.X,
            ReleaseKeyY = alternateKey.Y,
        };
        var alternateCompiledTrustSha256 =
            PersonalProductionGateEvidence.ComputeCompiledTrustSha256(
                alternateCompiledTrust);
        File.WriteAllBytes(
            certification.ProductionGateEvidencePath,
            (gate with
            {
                CompiledTrust = alternateCompiledTrust,
                CompiledTrustSha256 = alternateCompiledTrustSha256,
                Installer = gate.Installer with
                {
                    CompiledTrustSha256 = alternateCompiledTrustSha256,
                },
                ClientExecutables = gate.ClientExecutables.Select(executable =>
                    executable with
                    {
                        CompiledTrustSha256 = alternateCompiledTrustSha256,
                    }).ToArray(),
            }).SerializeCanonical());

        AssertThrows<InvalidDataException>(() =>
            new PersonalDistributionReceiptProducer(fixture.TimeProvider).Preflight(
                PreflightOptions(fixture, pilot, stable, certification)));
    }

    public static void DistributionPreflightBindsCompiledLowSCutover()
    {
        using var fixture = new Fixture();
        var pilot = fixture.CreateCandidate("pilot", "personal-v2026.08.26.3", 1, 3, 0);
        var stable = fixture.CreateCandidate("stable", "personal-v2026.08.26.3", 1, 3, 0);
        var certification = fixture.CreateStableCertification(pilot, stable);
        var gate = PersonalProductionGateEvidence.ParseCanonical(
            File.ReadAllBytes(certification.ProductionGateEvidencePath));
        var mismatchedCompiledTrust = gate.CompiledTrust with
        {
            CanonicalLowSFromSequence =
                checked(gate.CompiledTrust.CanonicalLowSFromSequence + 1),
        };
        var mismatchedCompiledTrustSha256 =
            PersonalProductionGateEvidence.ComputeCompiledTrustSha256(
                mismatchedCompiledTrust);
        File.WriteAllBytes(
            certification.ProductionGateEvidencePath,
            (gate with
            {
                CompiledTrust = mismatchedCompiledTrust,
                CompiledTrustSha256 = mismatchedCompiledTrustSha256,
                Installer = gate.Installer with
                {
                    CompiledTrustSha256 = mismatchedCompiledTrustSha256,
                },
                ClientExecutables = gate.ClientExecutables.Select(executable =>
                    executable with
                    {
                        CompiledTrustSha256 = mismatchedCompiledTrustSha256,
                    }).ToArray(),
            }).SerializeCanonical());

        AssertThrows<InvalidDataException>(() =>
            new PersonalDistributionReceiptProducer(fixture.TimeProvider).Preflight(
                PreflightOptions(fixture, pilot, stable, certification)));
    }

    public static void DistributionPreflightRejectsUntimestampedInstaller()
    {
        using var fixture = new Fixture();
        var pilot = fixture.CreateCandidate("pilot", "personal-v2026.08.26.3", 1, 3, 0);
        var stable = fixture.CreateCandidate("stable", "personal-v2026.08.26.3", 1, 3, 0);
        var certification = fixture.CreateStableCertification(pilot, stable);
        var gate = PersonalProductionGateEvidence.ParseCanonical(
            File.ReadAllBytes(certification.ProductionGateEvidencePath));
        File.WriteAllBytes(
            certification.ProductionGateEvidencePath,
            (gate with
            {
                Installer = gate.Installer with { Timestamped = false },
            }).SerializeCanonical());

        AssertThrows<InvalidDataException>(() =>
            new PersonalDistributionReceiptProducer(fixture.TimeProvider).Preflight(
                PreflightOptions(fixture, pilot, stable, certification)));
    }

    public static void DistributionPreflightRejectsProvenanceDrift()
    {
        using var fixture = new Fixture();
        var pilot = fixture.CreateCandidate("pilot", "personal-v2026.08.26.3", 1, 3, 0);
        var stable = fixture.CreateCandidate(
            "stable",
            "personal-v2026.08.26.3",
            1,
            3,
            0,
            launcherRepositoryCommit: new string('e', 40));
        var certification = fixture.CreateStableCertification(pilot, stable);

        AssertThrows<InvalidDataException>(() =>
            new PersonalDistributionReceiptProducer(fixture.TimeProvider).Preflight(
                PreflightOptions(fixture, pilot, stable, certification)));
    }

    public static void DistributionPreflightRejectsChangedLifecycleEvidence()
    {
        using var fixture = new Fixture();
        var pilot = fixture.CreateCandidate("pilot", "personal-v2026.08.26.3", 1, 3, 0);
        var stable = fixture.CreateCandidate("stable", "personal-v2026.08.26.3", 1, 3, 0);
        var certification = fixture.CreateStableCertification(pilot, stable);
        File.AppendAllText(certification.CleanDeviceLifecyclePath, " ", Encoding.UTF8);

        AssertThrows<InvalidDataException>(() =>
            new PersonalDistributionReceiptProducer(fixture.TimeProvider).Preflight(
                PreflightOptions(fixture, pilot, stable, certification)));
    }

    public static void RejectsStableRebuild()
    {
        using var fixture = new Fixture();
        var pilot = fixture.CreateCandidate("pilot", "personal-v2026.08.26.3", 1, 3, 0);
        _ = fixture.Promoter.Promote(fixture.Options(pilot));
        var stable = fixture.CreateCandidate(
            "stable",
            "personal-v2026.08.26.3",
            1,
            3,
            0,
            contentSalt: "rebuilt");
        var certification = fixture.CreateStableCertification(pilot, stable);
        AssertThrows<InvalidDataException>(() =>
            fixture.Promoter.Promote(fixture.Options(stable, certification)));
    }

    public static void RejectsTamperedStableReceipt()
    {
        using var fixture = new Fixture();
        var pilot = fixture.CreateCandidate("pilot", "personal-v2026.08.26.3", 1, 3, 0);
        _ = fixture.Promoter.Promote(fixture.Options(pilot));
        var stable = fixture.CreateCandidate("stable", "personal-v2026.08.26.3", 1, 3, 0);
        var certification = fixture.CreateStableCertification(pilot, stable);
        File.AppendAllText(certification.ReceiptPath, " ", Encoding.UTF8);
        AssertThrows<InvalidDataException>(() =>
            fixture.Promoter.Promote(fixture.Options(stable, certification)));
    }

    public static void RejectsExpiredAuthorization()
    {
        using var fixture = new Fixture();
        var pilot = fixture.CreateCandidate("pilot", "personal-v2026.08.26.3", 1, 3, 0);
        _ = fixture.Promoter.Promote(fixture.Options(pilot));
        var stable = fixture.CreateCandidate("stable", "personal-v2026.08.26.3", 1, 3, 0);
        var certification = fixture.CreateStableCertification(
            pilot,
            stable,
            authorizationIssuedAt: Now.AddDays(-3),
            authorizationExpiresAt: Now.AddDays(-2));
        AssertThrows<InvalidDataException>(() =>
            fixture.Promoter.Promote(fixture.Options(stable, certification)));
    }

    public static void RejectsDuplicateCertificationJson()
    {
        using var fixture = new Fixture();
        var pilot = fixture.CreateCandidate("pilot", "personal-v2026.08.26.3", 1, 3, 0);
        _ = fixture.Promoter.Promote(fixture.Options(pilot));
        var stable = fixture.CreateCandidate("stable", "personal-v2026.08.26.3", 1, 3, 0);
        var certification = fixture.CreateStableCertification(pilot, stable);
        var receipt = File.ReadAllText(certification.ReceiptPath);
        receipt = receipt.Replace(
            "\"schemaVersion\": 2,",
            "\"schemaVersion\": 2,\n  \"schemaVersion\": 2,",
            StringComparison.Ordinal);
        File.WriteAllText(certification.ReceiptPath, receipt, new UTF8Encoding(false));
        AssertThrows<InvalidDataException>(() =>
            fixture.Promoter.Promote(fixture.Options(stable, certification)));
    }

    public static void RejectsMissingLifecycleSidecar()
    {
        using var fixture = new Fixture();
        var (pilot, stable) = CreateCertifiedTarget(fixture);
        var certification = fixture.CreateStableCertification(pilot, stable);
        File.Delete(certification.CleanDeviceLifecyclePath);
        AssertStableRejectedBeforeFeedWrite(fixture, stable, certification);
    }

    public static void RejectsRandomLifecycleDigest()
    {
        using var fixture = new Fixture();
        var (pilot, stable) = CreateCertifiedTarget(fixture);
        var certification = fixture.CreateStableCertification(
            pilot,
            stable,
            matrixMutator: matrix => matrix with
            {
                CleanDeviceLifecycle = matrix.CleanDeviceLifecycle with
                {
                    ReceiptSha256 = new string('a', 64),
                },
            });
        AssertStableRejectedBeforeFeedWrite(fixture, stable, certification);
    }

    public static void RejectsChangedLifecycleSidecar()
    {
        using var fixture = new Fixture();
        var (pilot, stable) = CreateCertifiedTarget(fixture);
        var certification = fixture.CreateStableCertification(pilot, stable);
        File.AppendAllText(certification.FailureRecoveryLifecyclePath, "\n", Encoding.UTF8);
        AssertStableRejectedBeforeFeedWrite(fixture, stable, certification);
    }

    public static void RejectsNoncanonicalLifecycleSidecar()
    {
        using var fixture = new Fixture();
        var (pilot, stable) = CreateCertifiedTarget(fixture);
        var certification = fixture.CreateStableCertification(
            pilot,
            stable,
            evidenceBytesMutator: (receipt, bytes) => string.Equals(
                    receipt.Kind,
                    PersonalLifecycleEvidenceContract.CleanDeviceLifecycle,
                    StringComparison.Ordinal)
                ? bytes.Concat([(byte)'\n']).ToArray()
                : bytes);
        AssertStableRejectedBeforeFeedWrite(fixture, stable, certification);
    }

    public static void RejectsWrongLifecycleIdentity()
    {
        using (var fixture = new Fixture())
        {
            var (pilot, stable) = CreateCertifiedTarget(fixture);
            var certification = fixture.CreateStableCertification(
                pilot,
                stable,
                evidenceMutator: receipt => string.Equals(
                        receipt.Kind,
                        PersonalLifecycleEvidenceContract.CleanDeviceLifecycle,
                        StringComparison.Ordinal)
                    ? receipt with
                    {
                        Kind = PersonalLifecycleEvidenceContract.FailureRecoveryLifecycle,
                    }
                    : receipt);
            AssertStableRejectedBeforeFeedWrite(fixture, stable, certification);
        }
        using (var fixture = new Fixture())
        {
            var (pilot, stable) = CreateCertifiedTarget(fixture);
            var certification = fixture.CreateStableCertification(
                pilot,
                stable,
                matrixMutator: matrix => matrix with
                {
                    CleanDeviceLifecycle = matrix.CleanDeviceLifecycle with
                    {
                        TestRunId = Guid.NewGuid().ToString("D"),
                    },
                });
            AssertStableRejectedBeforeFeedWrite(fixture, stable, certification);
        }
    }

    public static void RejectsWrongLifecycleTarget()
    {
        using var fixture = new Fixture();
        var (pilot, stable) = CreateCertifiedTarget(fixture);
        var certification = fixture.CreateStableCertification(
            pilot,
            stable,
            evidenceMutator: receipt => string.Equals(
                    receipt.Kind,
                    PersonalLifecycleEvidenceContract.FailureRecoveryLifecycle,
                    StringComparison.Ordinal)
                ? receipt with { ReleaseSetId = "personal-v2026.08.26.other" }
                : receipt);
        AssertStableRejectedBeforeFeedWrite(fixture, stable, certification);
    }

    public static void RejectsMissingLifecycleGate()
    {
        using var fixture = new Fixture();
        var (pilot, stable) = CreateCertifiedTarget(fixture);
        var certification = fixture.CreateStableCertification(
            pilot,
            stable,
            evidenceMutator: receipt => string.Equals(
                    receipt.Kind,
                    PersonalLifecycleEvidenceContract.CleanDeviceLifecycle,
                    StringComparison.Ordinal)
                ? receipt with { RequiredGates = receipt.RequiredGates.SkipLast(1).ToArray() }
                : receipt);
        AssertStableRejectedBeforeFeedWrite(fixture, stable, certification);
    }

    public static void RejectsBrokenSecondUpdateChain()
    {
        using var fixture = new Fixture();
        var (pilot, stable) = CreateCertifiedTarget(fixture);
        var certification = fixture.CreateStableCertification(
            pilot,
            stable,
            evidenceMutator: receipt =>
            {
                if (!string.Equals(
                        receipt.Kind,
                        PersonalLifecycleEvidenceContract.TwoUpdateUpgradeLifecycle,
                        StringComparison.Ordinal))
                {
                    return receipt;
                }
                var hops = receipt.UpdateChain.ToArray();
                hops[1] = hops[1] with { From = hops[0].From };
                return receipt with { UpdateChain = hops };
            });
        AssertStableRejectedBeforeFeedWrite(fixture, stable, certification);
    }

    public static void RejectsOnlineRepairEvidence()
    {
        using var fixture = new Fixture();
        var (pilot, stable) = CreateCertifiedTarget(fixture);
        var certification = fixture.CreateStableCertification(
            pilot,
            stable,
            evidenceMutator: receipt => string.Equals(
                    receipt.Kind,
                    PersonalLifecycleEvidenceContract.CleanDeviceLifecycle,
                    StringComparison.Ordinal)
                ? MutateGate(
                    receipt,
                    "repair-offline",
                    gate => gate with { NetworkMode = "controlled" })
                : receipt);
        AssertStableRejectedBeforeFeedWrite(fixture, stable, certification);
    }

    public static void RejectsPreviousRuntimeNotStarted()
    {
        using var fixture = new Fixture();
        var (pilot, stable) = CreateCertifiedTarget(fixture);
        var certification = fixture.CreateStableCertification(
            pilot,
            stable,
            evidenceMutator: receipt => string.Equals(
                    receipt.Kind,
                    PersonalLifecycleEvidenceContract.FailureRecoveryLifecycle,
                    StringComparison.Ordinal)
                ? MutateGate(
                    receipt,
                    "previous-runtime-restart",
                    gate => gate with { ObservedProcessState = "completed" })
                : receipt);
        AssertStableRejectedBeforeFeedWrite(fixture, stable, certification);
    }

    public static void RejectsChangedLocalDataWitness()
    {
        using var fixture = new Fixture();
        var (pilot, stable) = CreateCertifiedTarget(fixture);
        var certification = fixture.CreateStableCertification(
            pilot,
            stable,
            evidenceMutator: receipt => string.Equals(
                    receipt.Kind,
                    PersonalLifecycleEvidenceContract.FailureRecoveryLifecycle,
                    StringComparison.Ordinal)
                ? receipt with
                {
                    LocalDataWitness = receipt.LocalDataWitness with
                    {
                        HistoryAfterSha256 = new string('a', 64),
                        WorkspaceAfterSha256 = new string('b', 64),
                    },
                }
                : receipt);
        AssertStableRejectedBeforeFeedWrite(fixture, stable, certification);
    }

    private static (Candidate Pilot, Candidate Stable) CreateCertifiedTarget(Fixture fixture)
    {
        var pilot = fixture.CreateCandidate(
            "pilot",
            "personal-v2026.08.26.3",
            1,
            3,
            0);
        _ = fixture.Promoter.Promote(fixture.Options(pilot));
        var stable = fixture.CreateCandidate(
            "stable",
            "personal-v2026.08.26.3",
            1,
            3,
            0);
        return (pilot, stable);
    }

    private static PersonalLifecycleEvidenceReceipt MutateGate(
        PersonalLifecycleEvidenceReceipt receipt,
        string gateName,
        Func<PersonalLifecycleGateEvidence, PersonalLifecycleGateEvidence> mutation) =>
        receipt with
        {
            RequiredGates = receipt.RequiredGates
                .Select(gate => string.Equals(gate.Gate, gateName, StringComparison.Ordinal)
                    ? mutation(gate)
                    : gate)
                .ToArray(),
        };

    private static void AssertStableRejectedBeforeFeedWrite(
        Fixture fixture,
        Candidate stable,
        StableCertification certification)
    {
        AssertThrows<Exception>(() =>
            fixture.Promoter.Promote(fixture.Options(stable, certification)));
        AssertFalse(
            File.Exists(fixture.ChannelHead("stable")),
            "Rejected lifecycle evidence advanced the Stable head.");
        AssertFalse(
            Directory.EnumerateFileSystemEntries(Path.Combine(fixture.FeedRoot, "staging")).Any(),
            "Rejected lifecycle evidence created a feed staging directory.");
    }

    public static void RejectsSharedTrustKey()
    {
        using var fixture = new Fixture();
        var trust = fixture.CreateTrustWithSharedKey();
        AssertThrows<InvalidDataException>(() => PersonalFeedTrustConfiguration.Parse(trust));
    }

    public static void LinuxTrustPolicyReadIsIdentityBound()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        LinuxNative.RequireRoot();

        var root = Path.Combine(
            "/root",
            $"ensou-personal-trust-policy-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        File.SetUnixFileMode(
            root,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var secure = Path.Combine(root, "secure");
            CreateSecureDirectory(secure);
            var policy = Path.Combine(secure, "trust.json");
            var trustedBytes = Encoding.UTF8.GetBytes("trusted-policy-bytes");
            WriteSecureFile(policy, trustedBytes);
            AssertBytesEqual(
                trustedBytes,
                LinuxNative.ReadRootOwnedRegularFile(
                    policy,
                    1024,
                    "test trust policy"));

            var writableAncestor = Path.Combine(root, "group-writable");
            CreateSecureDirectory(writableAncestor);
            File.SetUnixFileMode(
                writableAncestor,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute);
            var writableAncestorPolicy = Path.Combine(writableAncestor, "trust.json");
            WriteSecureFile(writableAncestorPolicy, trustedBytes);
            AssertThrows<UnauthorizedAccessException>(() =>
                LinuxNative.ReadRootOwnedRegularFile(
                    writableAncestorPolicy,
                    1024,
                    "group-writable ancestor trust policy"));
            using (var fixture = new Fixture())
            {
                var candidate = fixture.CreateCandidate(
                    "lab",
                    "personal-v2026.08.27.1",
                    1,
                    1,
                    0);
                AssertThrows<UnauthorizedAccessException>(() =>
                    fixture.Promoter.Promote(fixture.Options(candidate) with
                    {
                        TrustConfigurationPath = writableAncestorPolicy,
                    }));
            }
            AssertThrows<UnauthorizedAccessException>(() =>
                new PersonalDistributionReceiptProducer(new FixedTimeProvider(Now)).Produce(
                    new PersonalDistributionCertificationOptions(
                        writableAncestorPolicy,
                        Path.Combine(root, "missing-pilot.json"),
                        Path.Combine(root, "missing-stable.json"),
                        Path.Combine(root, "missing-gate.json"),
                        Path.Combine(root, "missing-feed.json"),
                        Path.Combine(root, "missing-clean.json"),
                        Path.Combine(root, "missing-upgrade.json"),
                        Path.Combine(root, "missing-recovery.json"),
                        Path.Combine(root, "should-not-be-created.json"))));

            var writablePolicy = Path.Combine(secure, "group-writable-trust.json");
            WriteSecureFile(writablePolicy, trustedBytes);
            File.SetUnixFileMode(
                writablePolicy,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupWrite);
            AssertThrows<UnauthorizedAccessException>(() =>
                LinuxNative.ReadRootOwnedRegularFile(
                    writablePolicy,
                    1024,
                    "group-writable trust policy"));

            var hardLinkedPolicy = Path.Combine(secure, "hard-linked-trust.json");
            var secondHardLink = Path.Combine(secure, "hard-linked-trust-alias.json");
            WriteSecureFile(hardLinkedPolicy, trustedBytes);
            CreateHardLink(hardLinkedPolicy, secondHardLink);
            AssertThrows<UnauthorizedAccessException>(() =>
                LinuxNative.ReadRootOwnedRegularFile(
                    hardLinkedPolicy,
                    1024,
                    "hard-linked trust policy"));

            var policyLink = Path.Combine(secure, "trust-link.json");
            File.CreateSymbolicLink(policyLink, policy);
            AssertThrows<IOException>(() =>
                LinuxNative.ReadRootOwnedRegularFile(
                    policyLink,
                    1024,
                    "linked trust policy"));

            var directoryLink = Path.Combine(root, "secure-link");
            Directory.CreateSymbolicLink(directoryLink, secure);
            AssertThrows<IOException>(() =>
                LinuxNative.ReadRootOwnedRegularFile(
                    Path.Combine(directoryLink, "trust.json"),
                    1024,
                    "linked trust policy ancestor"));

            var replaceablePolicy = Path.Combine(secure, "replaceable-trust.json");
            var replacement = Path.Combine(secure, "replacement.json");
            var originalBytes = Encoding.UTF8.GetBytes("opened-policy-identity");
            var replacementBytes = Encoding.UTF8.GetBytes("replacement-policy-data");
            WriteSecureFile(replaceablePolicy, originalBytes);
            WriteSecureFile(replacement, replacementBytes);
            AssertThrows<UnauthorizedAccessException>(() =>
                LinuxNative.ReadRootOwnedRegularFile(
                    replaceablePolicy,
                    1024,
                    "replaced trust policy",
                    () => File.Move(replacement, replaceablePolicy, overwrite: true)));
            AssertBytesEqual(replacementBytes, File.ReadAllBytes(replaceablePolicy));
            AssertBytesEqual(
                replacementBytes,
                LinuxNative.ReadRootOwnedRegularFile(
                    replaceablePolicy,
                    1024,
                    "replacement trust policy"));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    public static int RunDockerE2E(string promoterPath, string workRoot)
    {
        try
        {
            if (!OperatingSystem.IsLinux())
            {
                throw new PlatformNotSupportedException("Docker E2E must run inside Linux.");
            }
            LinuxTrustPolicyReadIsIdentityBound();
            using var fixture = new Fixture(
                workRoot,
                preserve: true,
                initializeFeed: false,
                nowUtc: DateTimeOffset.UtcNow);
            RunCli(promoterPath, "initialize", "--feed-root", fixture.FeedRoot);
            var pilot = fixture.CreateCandidate("pilot", "personal-v2026.08.26.3", 1, 3, 0);
            RunCli(promoterPath, fixture.PromotionArguments(pilot));
            var stable = fixture.CreateCandidate("stable", "personal-v2026.08.26.3", 1, 3, 0);
            var certification = fixture.CreateStableCertification(pilot, stable);
            var preflightRoot = Path.GetDirectoryName(certification.ReceiptPath)!;
            var beforePreflight = SnapshotTree(preflightRoot);
            RunCli(promoterPath, fixture.PreflightArguments(pilot, stable, certification));
            AssertTrue(
                beforePreflight.SequenceEqual(
                    SnapshotTree(preflightRoot),
                    StringComparer.Ordinal),
                "Docker distribution preflight changed the fixture tree.");
            RunCli(promoterPath, fixture.PromotionArguments(
                stable,
                certification));
            RunCli(promoterPath, fixture.PromotionArguments(
                stable,
                certification));
            AssertTrue(File.Exists(fixture.ChannelHead("pilot")), "Docker Pilot head is missing.");
            AssertTrue(File.Exists(fixture.ChannelHead("stable")), "Docker Stable head is missing.");
            AssertTrue(File.Exists(fixture.JournalHead("stable")), "Docker Stable journal is missing.");
            var release = Path.Combine(fixture.ReleasesRoot, stable.Manifest.ReleaseSetId);
            AssertEqual(2, Directory.EnumerateFiles(release).Count());
            Console.WriteLine("PERSONAL-FEED-DOCKER-E2E-PASS network=none pilot=committed stable=committed");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"PERSONAL-FEED-DOCKER-E2E-FAIL {exception}");
            return 1;
        }
    }

    private static void RunCli(string executable, params string[] arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start Personal FeedPromoter CLI.");
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"Personal FeedPromoter CLI failed ({process.ExitCode}): {stdout} {stderr}");
        }
    }

    private static string FindRepositoryFile(params string[] segments)
    {
        for (var current = new DirectoryInfo(AppContext.BaseDirectory);
             current is not null;
             current = current.Parent)
        {
            var candidate = segments.Aggregate(
                current.FullName,
                Path.Combine);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        throw new FileNotFoundException(
            $"Could not locate repository contract file: {Path.Combine(segments)}");
    }

    private static bool ValidateJsonSchema(
        string documentPath,
        string schemaPath,
        bool reportFailure = false)
    {
        try
        {
            using var document = JsonDocument.Parse(
                File.ReadAllBytes(documentPath),
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 64,
                });
            using var schema = JsonDocument.Parse(
                File.ReadAllBytes(schemaPath),
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 64,
                });
            var valid = ValidateSchema(
                document.RootElement,
                schema.RootElement,
                schema.RootElement,
                "$",
                out var failure);
            if (!valid && reportFailure)
            {
                Console.Error.WriteLine(
                    $"JSON Schema validation rejected the canonical receipt: {failure}");
            }
            return valid;
        }
        catch (Exception exception) when (exception is IOException or JsonException)
        {
            if (reportFailure)
            {
                Console.Error.WriteLine(
                    $"JSON Schema validation could not read its inputs: {exception.Message}");
            }
            return false;
        }
    }

    private static bool ValidateSchema(
        JsonElement value,
        JsonElement schema,
        JsonElement rootSchema,
        string path,
        out string failure)
    {
        if (schema.ValueKind == JsonValueKind.False)
        {
            failure = $"{path} is forbidden by the schema.";
            return false;
        }
        if (schema.ValueKind == JsonValueKind.True)
        {
            failure = string.Empty;
            return true;
        }
        if (schema.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("JSON Schema node must be an object or boolean.");
        }

        if (schema.TryGetProperty("$ref", out var reference))
        {
            var referenceText = reference.GetString()
                ?? throw new InvalidDataException("JSON Schema reference is empty.");
            const string definitionPrefix = "#/$defs/";
            if (!referenceText.StartsWith(definitionPrefix, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Unsupported JSON Schema reference: {referenceText}");
            }
            var definitionName = referenceText[definitionPrefix.Length..]
                .Replace("~1", "/", StringComparison.Ordinal)
                .Replace("~0", "~", StringComparison.Ordinal);
            if (!rootSchema.GetProperty("$defs").TryGetProperty(
                    definitionName,
                    out var definition))
            {
                throw new InvalidDataException(
                    $"JSON Schema definition is missing: {definitionName}");
            }
            if (!ValidateSchema(value, definition, rootSchema, path, out failure))
            {
                return false;
            }
        }

        if (schema.TryGetProperty("allOf", out var allOf))
        {
            foreach (var branch in allOf.EnumerateArray())
            {
                if (!ValidateSchema(value, branch, rootSchema, path, out failure))
                {
                    return false;
                }
            }
        }

        if (schema.TryGetProperty("type", out var type)
            && !MatchesSchemaType(value, type.GetString()))
        {
            failure = $"{path} does not have schema type {type.GetString()}.";
            return false;
        }
        if (schema.TryGetProperty("const", out var constant)
            && !JsonValuesEqual(value, constant))
        {
            failure = $"{path} does not match its const value.";
            return false;
        }
        if (schema.TryGetProperty("enum", out var choices)
            && !choices.EnumerateArray().Any(choice => JsonValuesEqual(value, choice)))
        {
            failure = $"{path} is outside its enum.";
            return false;
        }
        if (schema.TryGetProperty("pattern", out var pattern))
        {
            if (value.ValueKind != JsonValueKind.String
                || !Regex.IsMatch(
                    value.GetString()!,
                    pattern.GetString()!,
                    RegexOptions.CultureInvariant,
                    TimeSpan.FromSeconds(1)))
            {
                failure = $"{path} does not match its pattern.";
                return false;
            }
        }

        if (schema.TryGetProperty("minimum", out var minimum)
            && (!value.TryGetInt64(out var minimumValue)
                || minimumValue < minimum.GetInt64()))
        {
            failure = $"{path} is below its minimum.";
            return false;
        }
        if (schema.TryGetProperty("maximum", out var maximum)
            && (!value.TryGetInt64(out var maximumValue)
                || maximumValue > maximum.GetInt64()))
        {
            failure = $"{path} is above its maximum.";
            return false;
        }

        if (schema.TryGetProperty("required", out var required))
        {
            if (value.ValueKind != JsonValueKind.Object)
            {
                failure = $"{path} must be an object for required properties.";
                return false;
            }
            foreach (var requiredName in required.EnumerateArray())
            {
                if (!value.TryGetProperty(requiredName.GetString()!, out _))
                {
                    failure = $"{path} is missing {requiredName.GetString()}.";
                    return false;
                }
            }
        }

        var hasProperties = schema.TryGetProperty("properties", out var properties);
        if (hasProperties)
        {
            if (value.ValueKind != JsonValueKind.Object)
            {
                failure = $"{path} must be an object for properties.";
                return false;
            }
            foreach (var propertySchema in properties.EnumerateObject())
            {
                if (value.TryGetProperty(propertySchema.Name, out var propertyValue)
                    && !ValidateSchema(
                        propertyValue,
                        propertySchema.Value,
                        rootSchema,
                        $"{path}.{propertySchema.Name}",
                        out failure))
                {
                    return false;
                }
            }
        }
        if (schema.TryGetProperty("additionalProperties", out var additionalProperties)
            && additionalProperties.ValueKind == JsonValueKind.False)
        {
            if (value.ValueKind != JsonValueKind.Object)
            {
                failure = $"{path} must be an object for additionalProperties.";
                return false;
            }
            foreach (var property in value.EnumerateObject())
            {
                if (!hasProperties || !properties.TryGetProperty(property.Name, out _))
                {
                    failure = $"{path} contains unexpected property {property.Name}.";
                    return false;
                }
            }
        }

        if (schema.TryGetProperty("minItems", out var minItems)
            && (value.ValueKind != JsonValueKind.Array
                || value.GetArrayLength() < minItems.GetInt32()))
        {
            failure = $"{path} has too few items.";
            return false;
        }
        if (schema.TryGetProperty("maxItems", out var maxItems)
            && (value.ValueKind != JsonValueKind.Array
                || value.GetArrayLength() > maxItems.GetInt32()))
        {
            failure = $"{path} has too many items.";
            return false;
        }
        if (schema.TryGetProperty("prefixItems", out var prefixItems))
        {
            if (value.ValueKind != JsonValueKind.Array)
            {
                failure = $"{path} must be an array for prefixItems.";
                return false;
            }
            var values = value.EnumerateArray().ToArray();
            var prefixSchemas = prefixItems.EnumerateArray().ToArray();
            for (var index = 0; index < Math.Min(values.Length, prefixSchemas.Length); index++)
            {
                if (!ValidateSchema(
                    values[index],
                    prefixSchemas[index],
                    rootSchema,
                    $"{path}[{index}]",
                    out failure))
                {
                    return false;
                }
            }
            if (schema.TryGetProperty("items", out var items))
            {
                if (items.ValueKind == JsonValueKind.False
                    && values.Length > prefixSchemas.Length)
                {
                    failure = $"{path} has items forbidden by the schema.";
                    return false;
                }
                if (items.ValueKind is JsonValueKind.Object or JsonValueKind.True)
                {
                    for (var index = prefixSchemas.Length; index < values.Length; index++)
                    {
                        if (!ValidateSchema(
                            values[index],
                            items,
                            rootSchema,
                            $"{path}[{index}]",
                            out failure))
                        {
                            return false;
                        }
                    }
                }
            }
        }

        failure = string.Empty;
        return true;
    }

    private static bool MatchesSchemaType(JsonElement value, string? type) => type switch
    {
        "array" => value.ValueKind == JsonValueKind.Array,
        "boolean" => value.ValueKind is JsonValueKind.True or JsonValueKind.False,
        "integer" => value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out _),
        "null" => value.ValueKind == JsonValueKind.Null,
        "number" => value.ValueKind == JsonValueKind.Number,
        "object" => value.ValueKind == JsonValueKind.Object,
        "string" => value.ValueKind == JsonValueKind.String,
        _ => throw new InvalidDataException($"Unsupported JSON Schema type: {type}"),
    };

    private static bool JsonValuesEqual(JsonElement left, JsonElement right)
    {
        if (left.ValueKind != right.ValueKind)
        {
            return false;
        }
        return left.ValueKind switch
        {
            JsonValueKind.String => string.Equals(
                left.GetString(),
                right.GetString(),
                StringComparison.Ordinal),
            JsonValueKind.Number => left.TryGetDecimal(out var leftNumber)
                && right.TryGetDecimal(out var rightNumber)
                && leftNumber == rightNumber,
            JsonValueKind.True or JsonValueKind.False or JsonValueKind.Null => true,
            _ => string.Equals(
                left.GetRawText(),
                right.GetRawText(),
                StringComparison.Ordinal),
        };
    }

    private static PersonalDistributionPreflightOptions PreflightOptions(
        Fixture fixture,
        Candidate pilot,
        Candidate stable,
        StableCertification certification) => new(
            fixture.TrustPath,
            Path.Combine(pilot.Directory, "release-set.v2.json"),
            Path.Combine(stable.Directory, "release-set.v2.json"),
            certification.ProductionGateEvidencePath,
            certification.ExternalPilotFeedEvidencePath,
            certification.CleanDeviceLifecyclePath,
            certification.TwoUpdateUpgradeLifecyclePath,
            certification.FailureRecoveryLifecyclePath);

    private static PersonalDistributionCertificationOptions CertificationOptions(
        Fixture fixture,
        Candidate pilot,
        Candidate stable,
        StableCertification certification,
        string outputPath) => new(
            fixture.TrustPath,
            Path.Combine(pilot.Directory, "release-set.v2.json"),
            Path.Combine(stable.Directory, "release-set.v2.json"),
            certification.ProductionGateEvidencePath,
            certification.ExternalPilotFeedEvidencePath,
            certification.CleanDeviceLifecyclePath,
            certification.TwoUpdateUpgradeLifecyclePath,
            certification.FailureRecoveryLifecyclePath,
            outputPath);

    public static void ProductionInitializeEmitsMachineIdentity()
    {
        var root = Path.Combine(
            OperatingSystem.IsLinux() ? "/root" : Path.GetTempPath(),
            $"personal-feed-initialize-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var first = CaptureStandardOutput(() =>
                Ensou.Dsh.Personal.FeedPromoter.Program.Main(
                    ["initialize", "--feed-root", root]));
            var second = CaptureStandardOutput(() =>
                Ensou.Dsh.Personal.FeedPromoter.Program.Main(
                    ["initialize", "--feed-root", root]));
            using var firstJson = JsonDocument.Parse(first);
            using var secondJson = JsonDocument.Parse(second);
            var firstRoot = firstJson.RootElement;
            var secondRoot = secondJson.RootElement;
            var instanceId = firstRoot.GetProperty("feedInstanceId").GetString();
            var identitySha = firstRoot.GetProperty("feedIdentitySha256").GetString();
            AssertTrue(
                Guid.TryParseExact(instanceId, "N", out _),
                "Initialize did not emit a canonical feedInstanceId.");
            AssertTrue(
                PersonalReleaseSetValidator.IsSha256(identitySha),
                "Initialize did not emit a raw feed identity digest.");
            AssertEqual(instanceId, secondRoot.GetProperty("feedInstanceId").GetString());
            AssertEqual(identitySha, secondRoot.GetProperty("feedIdentitySha256").GetString());
            AssertFalse(first.Contains(root, StringComparison.Ordinal),
                "Initialize leaked its absolute feed root.");

            var identityPath = Path.Combine(root, PersonalFeedLayout.IdentityFileName);
            if (OperatingSystem.IsLinux())
            {
                File.SetUnixFileMode(identityPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            File.WriteAllBytes(identityPath, PersonalFeedJson.Serialize(new
            {
                SchemaVersion = 1,
                Product = PersonalReleaseSetContract.Product,
                Environment = PersonalReleaseSetContract.ProductionEnvironment,
            }));
            AssertThrows<InvalidDataException>(() => PersonalFeedLayout.Open(root));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    public static void ProductionInitializeRecoversPartialLayout()
    {
        var root = Path.Combine(
            OperatingSystem.IsLinux() ? "/root" : Path.GetTempPath(),
            $"personal-feed-partial-initialize-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var journal = Path.Combine(root, "journal");
            Directory.CreateDirectory(Path.Combine(journal, "lab"));
            Directory.CreateDirectory(Path.Combine(journal, "operations"));
            File.WriteAllBytes(Path.Combine(journal, "publication.lock"), []);
            File.WriteAllBytes(Path.Combine(journal, "lab", "promotion.lock"), []);
            Directory.CreateDirectory(Path.Combine(root, "staging"));
            Directory.CreateDirectory(Path.Combine(root, "public", "channels", "pilot"));
            Directory.CreateDirectory(Path.Combine(root, "public", "releases"));
            File.WriteAllBytes(
                Path.Combine(root, $".feed.identity.{Guid.NewGuid():N}.tmp"),
                PersonalFeedJson.Serialize(new { Interrupted = true }));

            var first = PersonalFeedLayout.Initialize(root);
            var firstIdentity = PersonalFeedLayout.ReadInitializationResult(root);
            var second = PersonalFeedLayout.Initialize(root);
            var secondIdentity = PersonalFeedLayout.ReadInitializationResult(root);

            AssertEqual(first.Root, second.Root);
            AssertEqual(firstIdentity.FeedInstanceId, secondIdentity.FeedInstanceId);
            AssertEqual(firstIdentity.FeedIdentitySha256, secondIdentity.FeedIdentitySha256);
            AssertFalse(
                Directory.EnumerateFiles(root, ".feed.identity.*.tmp").Any(),
                "Recovered initialization left an identity temporary behind.");
            _ = PersonalFeedLayout.Open(root);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    public static void ProductionCrashWindowsReplayExactly()
    {
        foreach (var stage in new[]
                 {
                     PersonalFeedPromotionStage.ImmutableReleaseReady,
                     PersonalFeedPromotionStage.ChannelHeadReplaced,
                     PersonalFeedPromotionStage.JournalEntryCreated,
                     PersonalFeedPromotionStage.JournalHeadReplaced,
                     PersonalFeedPromotionStage.OperationReceiptCommitted,
                 })
        {
            using var fixture = new Fixture();
            var candidate = fixture.CreateCandidate(
                "lab",
                $"personal-v2026.08.31.{(int)stage + 1}",
                1,
                1,
                0,
                contentSalt: stage.ToString());
            var operationId = Guid.NewGuid().ToString("N");
            var options = fixture.ProductionOptions(candidate, operationId);
            var interrupted = new PersonalFeedPromoter(
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
            var committedBeforeRetry = File.Exists(responsePath)
                ? File.ReadAllBytes(responsePath)
                : null;
            var result = fixture.Promoter.Promote(options);
            var committed = File.ReadAllBytes(responsePath);
            if (committedBeforeRetry is not null)
            {
                AssertBytesEqual(committedBeforeRetry, committed);
            }
            var replay = fixture.Promoter.Promote(options);
            AssertBytesEqual(committed, File.ReadAllBytes(responsePath));
            AssertBytesEqual(
                PersonalFeedOperationStore.SerializeReceipt(result.ProductionReceipt!),
                PersonalFeedOperationStore.SerializeReceipt(replay.ProductionReceipt!));
            Ensou.Dsh.Personal.FeedPromoter.Program.WriteResultReceipt(
                options.ResultReceiptPath!,
                result,
                fixture.FeedRoot,
                candidate.Directory,
                fixture.TrustPath);
            var external = File.ReadAllText(options.ResultReceiptPath!);
            AssertFalse(external.Contains(fixture.FeedRoot, StringComparison.Ordinal),
                "Production result leaked an absolute feed path.");
            AssertTrue(
                result.JournalEntryPath.StartsWith("journal/lab/", StringComparison.Ordinal),
                "Production result did not use a logical journal path.");
            AssertEqual("https", result.ProductionReceipt!.ChannelManifestUri[..5]);
        }
    }

    public static void ProductionCasAndOperationConflictsFailClosed()
    {
        using var fixture = new Fixture();
        using var other = new Fixture();
        var first = fixture.CreateCandidate("lab", "personal-v2026.08.31.10", 1, 1, 0);
        var wrongIdentity = other.Foundation("lab", Guid.NewGuid().ToString("N"))
            .ExpectedFeedIdentitySha256;
        AssertThrows<InvalidOperationException>(() => fixture.Promoter.Promote(
            fixture.ProductionOptions(
                first,
                Guid.NewGuid().ToString("N"),
                identitySha256: wrongIdentity)));
        AssertFalse(File.Exists(fixture.ChannelHead("lab")),
            "Wrong feed instance advanced the channel.");

        var operationId = Guid.NewGuid().ToString("N");
        _ = fixture.Promoter.Promote(fixture.ProductionOptions(first, operationId));
        var second = fixture.CreateCandidate("lab", "personal-v2026.08.31.11", 1, 2, 0);
        var staleOperation = Guid.NewGuid().ToString("N");
        AssertThrows<InvalidOperationException>(() => fixture.Promoter.Promote(
            fixture.ProductionOptions(
                second,
                staleOperation,
                PersonalFeedRawStateExpectation.Missing(),
                PersonalFeedRawStateExpectation.Missing())));
        AssertFalse(Directory.Exists(Path.Combine(fixture.OperationsRoot, staleOperation)),
            "Failed CAS left an operation request.");
        AssertThrows<InvalidOperationException>(() => fixture.Promoter.Promote(
            fixture.ProductionOptions(second, operationId)));
    }

    public static void PendingOperationBlocksNextPromotion()
    {
        using var fixture = new Fixture();
        var first = fixture.CreateCandidate("lab", "personal-v2026.08.31.20", 1, 1, 0);
        var firstOperation = Guid.NewGuid().ToString("N");
        var firstOptions = fixture.ProductionOptions(first, firstOperation);
        var interrupted = new PersonalFeedPromoter(
            fixture.TimeProvider,
            stage =>
            {
                if (stage == PersonalFeedPromotionStage.ImmutableReleaseReady)
                {
                    throw new SimulatedCrashException();
                }
            });
        AssertThrows<SimulatedCrashException>(() => interrupted.Promote(firstOptions));
        var second = fixture.CreateCandidate("lab", "personal-v2026.08.31.21", 1, 2, 0);
        var secondOperation = Guid.NewGuid().ToString("N");
        AssertThrows<InvalidOperationException>(() => fixture.Promoter.Promote(
            fixture.ProductionOptions(second, secondOperation)));
        AssertFalse(Directory.Exists(Path.Combine(fixture.OperationsRoot, secondOperation)),
            "N plus one request was persisted before exact recovery.");
        _ = fixture.Promoter.Promote(firstOptions);
        _ = fixture.Promoter.Promote(fixture.ProductionOptions(second, secondOperation));
    }

    public static void OperationRequestTempRecoveryIsExact()
    {
        using (var fixture = new Fixture())
        {
            var candidate = fixture.CreateCandidate("lab", "personal-v2026.08.31.30", 1, 1, 0);
            var operationId = Guid.NewGuid().ToString("N");
            var request = CreateOperationRequest(fixture, candidate, operationId);
            Directory.CreateDirectory(Path.Combine(
                fixture.OperationsRoot,
                $".{operationId}.request.tmp"));
            var session = PersonalFeedOperationStore.Begin(
                fixture.OperationsRoot,
                request,
                PersonalFeedRawStateExpectation.Missing(),
                PersonalFeedRawStateExpectation.Missing(),
                allowCreate: true);
            AssertFalse(session.IsExistingRequest,
                "Empty pre-request temp was not recovered as a new request.");
        }
        using (var fixture = new Fixture())
        {
            var candidate = fixture.CreateCandidate("lab", "personal-v2026.08.31.31", 1, 1, 0);
            var operationId = Guid.NewGuid().ToString("N");
            var request = CreateOperationRequest(fixture, candidate, operationId);
            var temp = Path.Combine(fixture.OperationsRoot, $".{operationId}.request.tmp");
            Directory.CreateDirectory(temp);
            PersonalFeedPathGuard.WriteNewDurable(
                Path.Combine(temp, "request.v1.json"),
                PersonalFeedJson.Serialize(request));
            _ = PersonalFeedOperationStore.Begin(
                fixture.OperationsRoot,
                request,
                PersonalFeedRawStateExpectation.Missing(),
                PersonalFeedRawStateExpectation.Missing(),
                allowCreate: true);
            AssertFalse(Directory.Exists(temp), "Exact staged request was not adopted.");
        }
        using (var fixture = new Fixture())
        {
            var candidate = fixture.CreateCandidate("lab", "personal-v2026.08.31.32", 1, 1, 0);
            var operationId = Guid.NewGuid().ToString("N");
            var request = CreateOperationRequest(fixture, candidate, operationId);
            var temp = Path.Combine(fixture.OperationsRoot, $".{operationId}.request.tmp");
            Directory.CreateDirectory(temp);
            var stagedBytes = PersonalFeedJson.Serialize(request);
            PersonalFeedPathGuard.WriteNewDurable(
                Path.Combine(temp, "request.v1.json"),
                stagedBytes);
            var conflicting = PersonalFeedOperationStore.CreateRequest(
                fixture.Foundation("lab", operationId),
                "lab",
                candidate.ManifestBytes.LongLength,
                new string('b', 64),
                PersonalFeedJson.Sha256(File.ReadAllBytes(fixture.TrustPath)));
            AssertThrows<InvalidOperationException>(() => PersonalFeedOperationStore.Begin(
                fixture.OperationsRoot,
                conflicting,
                PersonalFeedRawStateExpectation.Missing(),
                PersonalFeedRawStateExpectation.Missing(),
                allowCreate: true));
            AssertBytesEqual(
                stagedBytes,
                File.ReadAllBytes(Path.Combine(temp, "request.v1.json")));
        }
    }

    public static void ProductionTreeAttacksFailClosed()
    {
        using (var fixture = new Fixture())
        {
            var alias = fixture.IdentityPath + ".hardlink";
            CreateHardLink(fixture.IdentityPath, alias);
            var candidate = fixture.CreateCandidate("lab", "personal-v2026.08.31.40", 1, 1, 0);
            AssertThrows<InvalidDataException>(() => fixture.Promoter.Promote(
                fixture.ProductionOptions(candidate, Guid.NewGuid().ToString("N"))));
        }
        using (var fixture = new Fixture())
        {
            File.WriteAllText(Path.Combine(fixture.OperationsRoot, "unexpected.txt"), "poison");
            var candidate = fixture.CreateCandidate("lab", "personal-v2026.08.31.41", 1, 1, 0);
            AssertThrows<InvalidDataException>(() => fixture.Promoter.Promote(
                fixture.ProductionOptions(candidate, Guid.NewGuid().ToString("N"))));
        }
    }

    public static void InvalidForwardRequestLeavesNoOperationResidue()
    {
        using var fixture = new Fixture();
        var first = fixture.CreateCandidate("lab", "personal-v2026.08.31.50", 2, 2, 0);
        _ = fixture.Promoter.Promote(
            fixture.ProductionOptions(first, Guid.NewGuid().ToString("N")));
        var rollback = fixture.CreateCandidate("lab", "personal-v2026.08.31.49", 2, 1, 0);
        var rejectedOperation = Guid.NewGuid().ToString("N");
        AssertThrows<InvalidDataException>(() => fixture.Promoter.Promote(
            fixture.ProductionOptions(rollback, rejectedOperation)));
        AssertFalse(Directory.Exists(Path.Combine(fixture.OperationsRoot, rejectedOperation)),
            "Invalid forward request left a durable operation residue.");
        var valid = fixture.CreateCandidate("lab", "personal-v2026.08.31.51", 2, 3, 0);
        _ = fixture.Promoter.Promote(
            fixture.ProductionOptions(valid, Guid.NewGuid().ToString("N")));
    }

    public static void ProductionResultPathIsExternal()
    {
        using var fixture = new Fixture();
        var candidate = fixture.CreateCandidate("lab", "personal-v2026.08.31.60", 1, 1, 0);
        var before = SnapshotTree(fixture.FeedRoot);
        var inside = Path.Combine(fixture.FeedRoot, "public", "result.json");
        AssertThrows<InvalidDataException>(() => fixture.Promoter.Promote(
            fixture.ProductionOptions(
                candidate,
                Guid.NewGuid().ToString("N"),
                resultPath: inside)));
        AssertTrue(before.SequenceEqual(SnapshotTree(fixture.FeedRoot), StringComparer.Ordinal),
            "Rejected internal result path changed the feed tree.");
    }

    private static PersonalFeedOperationRequest CreateOperationRequest(
        Fixture fixture,
        Candidate candidate,
        string operationId) => PersonalFeedOperationStore.CreateRequest(
            fixture.Foundation(candidate.Manifest.Channel, operationId),
            candidate.Manifest.Channel,
            candidate.ManifestBytes.LongLength,
            candidate.ManifestSha256,
            PersonalFeedJson.Sha256(File.ReadAllBytes(fixture.TrustPath)));

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

    [SupportedOSPlatform("linux")]
    private static void CreateSecureDirectory(string path)
    {
        Directory.CreateDirectory(path);
        File.SetUnixFileMode(
            path,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    [SupportedOSPlatform("linux")]
    private static void WriteSecureFile(string path, byte[] bytes)
    {
        File.WriteAllBytes(path, bytes);
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    [DllImport("libc", EntryPoint = "link", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int CreateHardLinkNative(string existingPath, string newPath);

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
            : CreateHardLinkNative(existingPath, newPath) == 0;
        if (!succeeded)
        {
            throw new IOException(
                "Could not create hard-link security fixture.",
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

    internal static void ExportCompletedFixture(string root)
    {
        if (!OperatingSystem.IsLinux() || Environment.GetEnvironmentVariable("ENSOU_DEVELOPMENT_LINUX_FIXTURE") != "1")
            throw new InvalidOperationException("Completed export fixture is Linux development-only.");
        using var fixture = new Fixture(Path.Combine(root, "fixture"), preserve: true, nowUtc: DateTimeOffset.UtcNow);
        var candidate = fixture.CreateCandidate("pilot", "personal-fixture-1", 1, 1, 0);
        var operationId = Guid.NewGuid().ToString("N");
        var options = fixture.ProductionOptions(candidate, operationId);
        var first = fixture.Promoter.Promote(options);
        var before = SnapshotTree(fixture.FeedRoot);
        var snapshot = Path.Combine(root, "completed-export");
        Directory.CreateDirectory(snapshot);
        PersonalFeedCompletedOperationExport.Export(fixture.FeedRoot, fixture.TrustPath, operationId, snapshot);
        AssertTrue(before.SequenceEqual(SnapshotTree(fixture.FeedRoot), StringComparer.Ordinal), "Completed export mutated the feed.");
        AssertBytesEqual(File.ReadAllBytes(Path.Combine(fixture.OperationsRoot, operationId, "response.v1.json")),
            File.ReadAllBytes(Path.Combine(snapshot, "evidence", "operation-result")));
        AssertThrows<InvalidDataException>(() => PersonalFeedCompletedOperationExport.Export(fixture.FeedRoot, fixture.TrustPath, operationId, snapshot));
        AssertTrue(first.ProductionReceipt is not null, "Real production foundation omitted operation receipt.");
        var replay = fixture.Promoter.Promote(options);
        AssertTrue(replay.ProductionReceipt == first.ProductionReceipt, "Real operation replay changed receipt.");
        var second = Path.Combine(root, "export-under-lock");
        Directory.CreateDirectory(second);
        using (var held = new FileStream(Path.Combine(fixture.FeedRoot, "journal", "publication.lock"), FileMode.Open, FileAccess.Read, FileShare.None))
            AssertThrows<IOException>(() => PersonalFeedCompletedOperationExport.Export(fixture.FeedRoot, fixture.TrustPath, operationId, second));
        File.AppendAllText(Path.Combine(fixture.ReleasesRoot, candidate.Manifest.ReleaseSetId, "runtime.zip"), "drift");
        var drift = Path.Combine(root, "export-drift");
        Directory.CreateDirectory(drift);
        AssertThrows<InvalidDataException>(() => PersonalFeedCompletedOperationExport.Export(fixture.FeedRoot, fixture.TrustPath, operationId, drift));
        AssertFalse(File.Exists(Path.Combine(drift, "snapshot.v1.json")), "Drifted export falsely committed a snapshot.");
        Console.WriteLine($"PERSONAL-COMPLETED-EXPORT-FIXTURE-PASS real-promoter=true readonly=true replay=true lock-reject=true drift-reject=true snapshot={snapshot}");
    }

    internal sealed class Fixture : IDisposable
    {
        private readonly string _root;
        private readonly bool _preserve;
        private readonly DateTimeOffset _nowUtc;
        private readonly ECDsa _releaseSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _certificationSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public Fixture(
            string? root = null,
            bool preserve = false,
            bool initializeFeed = true,
            DateTimeOffset? nowUtc = null)
        {
            _root = root is null
                ? Path.Combine(
                    OperatingSystem.IsLinux() ? "/root" : Path.GetTempPath(),
                    $"ensou-personal-feed-{Guid.NewGuid():N}")
                : Path.GetFullPath(root);
            _preserve = preserve;
            _nowUtc = nowUtc ?? Now;
            if (Directory.Exists(_root) || File.Exists(_root))
            {
                throw new IOException("Personal feed fixture root must be new.");
            }
            Directory.CreateDirectory(_root);
            FeedRoot = Path.Combine(_root, "feed");
            Directory.CreateDirectory(FeedRoot);
            if (initializeFeed)
            {
                _ = PersonalFeedLayout.Initialize(FeedRoot);
            }
            TrustPath = Path.Combine(_root, "trust.json");
            File.WriteAllBytes(TrustPath, PersonalFeedJson.Serialize(CreateTrust()));
            TimeProvider = new FixedTimeProvider(_nowUtc);
            Promoter = new PersonalFeedPromoter(TimeProvider, null);
        }

        public string FeedRoot { get; }
        public string TrustPath { get; }
        public FixedTimeProvider TimeProvider { get; }
        public PersonalFeedPromoter Promoter { get; }
        public string ReleasesRoot => Path.Combine(FeedRoot, "public", "releases");

        public string ChannelHead(string channel) => Path.Combine(
            FeedRoot,
            "public",
            "channels",
            channel,
            "release-set.v2.json");

        public string JournalHead(string channel) => Path.Combine(
            FeedRoot,
            "journal",
            channel,
            "head.json");

        public string OperationsRoot => Path.Combine(FeedRoot, "journal", "operations");
        public string IdentityPath => Path.Combine(
            FeedRoot,
            PersonalFeedLayout.IdentityFileName);

        public string ResultPath(string operationId) =>
            Path.Combine(_root, $"promotion-result-{operationId}.json");

        public PersonalFeedProductionFoundation Foundation(
            string channel,
            string operationId,
            PersonalFeedRawStateExpectation? expectedChannelHead = null,
            PersonalFeedRawStateExpectation? expectedJournalHead = null,
            string? identitySha256 = null) => new(
                operationId,
                identitySha256
                    ?? PersonalFeedLayout.ReadInitializationResult(FeedRoot)
                        .FeedIdentitySha256,
                expectedChannelHead
                    ?? PersonalFeedOperationStore.Observe(
                        ChannelHead(channel),
                        PersonalReleaseSetContract.MaximumManifestBytes,
                        "test channel head"),
                expectedJournalHead
                    ?? PersonalFeedOperationStore.Observe(
                        JournalHead(channel),
                        128 * 1024,
                        "test journal head"));

        public PersonalFeedPromotionOptions ProductionOptions(
            Candidate candidate,
            string operationId,
            PersonalFeedRawStateExpectation? expectedChannelHead = null,
            PersonalFeedRawStateExpectation? expectedJournalHead = null,
            string? identitySha256 = null,
            string? resultPath = null) => Options(candidate) with
            {
                ProductionFoundation = Foundation(
                    candidate.Manifest.Channel,
                    operationId,
                    expectedChannelHead,
                    expectedJournalHead,
                    identitySha256),
                ResultReceiptPath = resultPath ?? ResultPath(operationId),
            };

        public PersonalFeedPromotionOptions Options(
            Candidate candidate,
            string? receipt = null,
            string? authorization = null,
            string? cleanDeviceLifecycle = null,
            string? twoUpdateUpgradeLifecycle = null,
            string? failureRecoveryLifecycle = null,
            string? productionGateEvidence = null) => new(
                candidate.Directory,
                FeedRoot,
                TrustPath,
                candidate.Manifest.Channel,
                receipt,
                authorization,
                cleanDeviceLifecycle,
                twoUpdateUpgradeLifecycle,
                failureRecoveryLifecycle,
                productionGateEvidence);

        public PersonalFeedPromotionOptions Options(
            Candidate candidate,
            StableCertification certification) => Options(
                candidate,
                certification.ReceiptPath,
                certification.AuthorizationPath,
                certification.CleanDeviceLifecyclePath,
                certification.TwoUpdateUpgradeLifecyclePath,
                certification.FailureRecoveryLifecyclePath,
                certification.ProductionGateEvidencePath);

        public string[] PromotionArguments(
            Candidate candidate,
            string? receipt = null,
            string? authorization = null,
            string? cleanDeviceLifecycle = null,
            string? twoUpdateUpgradeLifecycle = null,
            string? failureRecoveryLifecycle = null,
            string? productionGateEvidence = null)
        {
            var values = new List<string>
            {
                "promote",
                "--candidate",
                candidate.Directory,
                "--feed-root",
                FeedRoot,
                "--trust-policy",
                TrustPath,
                "--channel",
                candidate.Manifest.Channel,
            };
            if (receipt is not null
                && authorization is not null
                && cleanDeviceLifecycle is not null
                && twoUpdateUpgradeLifecycle is not null
                && failureRecoveryLifecycle is not null
                && productionGateEvidence is not null)
            {
                values.AddRange([
                    "--certified-distribution-receipt",
                    receipt,
                    "--stable-authorization",
                    authorization,
                    "--clean-device-lifecycle",
                    cleanDeviceLifecycle,
                    "--two-update-upgrade-lifecycle",
                    twoUpdateUpgradeLifecycle,
                    "--failure-recovery-lifecycle",
                    failureRecoveryLifecycle,
                    "--production-gate-evidence",
                    productionGateEvidence,
                ]);
            }
            return values.ToArray();
        }

        public string[] PromotionArguments(
            Candidate candidate,
            StableCertification certification) => PromotionArguments(
                candidate,
                certification.ReceiptPath,
                certification.AuthorizationPath,
                certification.CleanDeviceLifecyclePath,
                certification.TwoUpdateUpgradeLifecyclePath,
                certification.FailureRecoveryLifecyclePath,
                certification.ProductionGateEvidencePath);

        public string[] PreflightArguments(
            Candidate pilot,
            Candidate stable,
            StableCertification certification) =>
        [
            "preflight-distribution",
            "--trust-policy",
            TrustPath,
            "--pilot-manifest",
            Path.Combine(pilot.Directory, "release-set.v2.json"),
            "--stable-manifest",
            Path.Combine(stable.Directory, "release-set.v2.json"),
            "--production-gate-evidence",
            certification.ProductionGateEvidencePath,
            "--external-pilot-feed-evidence",
            certification.ExternalPilotFeedEvidencePath,
            "--clean-device-lifecycle",
            certification.CleanDeviceLifecyclePath,
            "--two-update-upgrade-lifecycle",
            certification.TwoUpdateUpgradeLifecyclePath,
            "--failure-recovery-lifecycle",
            certification.FailureRecoveryLifecyclePath,
        ];

        public Candidate CreateCandidate(
            string channel,
            string releaseSetId,
            long generation,
            long sequence,
            long minimum,
            string contentSalt = "default",
            IReadOnlyList<string>? revoked = null,
            string? launcherRepositoryCommit = null,
            string? harnessSourceTag = null,
            string? harnessSourceCommit = null)
        {
            var directory = Path.Combine(_root, $"candidate-{Guid.NewGuid():N}");
            Directory.CreateDirectory(directory);
            var artifacts = new List<PersonalReleaseArtifact>();
            var paths = new List<string>();
            foreach (var (component, fileName) in new[]
                     {
                         (PersonalReleaseSetContract.ClientBundleComponent, "client-bundle.zip"),
                         (PersonalReleaseSetContract.RuntimeComponent, "runtime.zip"),
                     })
            {
                var bytes = Encoding.UTF8.GetBytes($"{releaseSetId}:{component}:{contentSalt}");
                var path = Path.Combine(directory, fileName);
                File.WriteAllBytes(path, bytes);
                paths.Add(path);
                artifacts.Add(new PersonalReleaseArtifact
                {
                    Component = component,
                    ReleaseId = $"{component}-2026.08.26.1",
                    Uri = new Uri(
                        $"https://updates.example.test/v2/releases/{releaseSetId}/{fileName}"),
                    SizeBytes = bytes.Length,
                    Sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)),
                    CompleteTreeSha256 = Convert.ToHexStringLower(SHA256.HashData(
                        Encoding.UTF8.GetBytes($"tree:{releaseSetId}:{component}:{contentSalt}"))),
                    Signature = ZeroSignature(),
                });
            }
            var manifest = new PersonalReleaseSetManifest
            {
                SchemaVersion = PersonalReleaseSetContract.SchemaVersion,
                Product = PersonalReleaseSetContract.Product,
                Environment = PersonalReleaseSetContract.ProductionEnvironment,
                Channel = channel,
                ReleaseSetId = releaseSetId,
                Provenance = new PersonalReleaseProvenance
                {
                    LauncherRepositoryCommit = launcherRepositoryCommit ?? new string('a', 40),
                    HarnessSourceTag = harnessSourceTag ?? "v0.1.0-test",
                    HarnessSourceCommit = harnessSourceCommit ?? new string('b', 40),
                },
                Generation = generation,
                Sequence = sequence,
                MinAcceptedSequence = minimum,
                IssuedAtUtc = _nowUtc.AddMinutes(-1),
                ExpiresAtUtc = _nowUtc.AddDays(7),
                MaximumOfflineGraceSeconds = (long)TimeSpan.FromDays(7).TotalSeconds,
                StartupStub = new PersonalStartupStubCompatibility
                {
                    MinimumVersion = "1.0.0",
                    MaximumVersion = "1.0.0",
                },
                RevokedReleaseSetIds = revoked ?? [],
                Artifacts = artifacts,
                Signature = ZeroSignature(),
            };
            var signed = PersonalReleaseSetSigner.Sign(manifest, "personal-release-test", _releaseSigner);
            var manifestBytes = PersonalReleaseSetJson.SerializeSigned(signed);
            File.WriteAllBytes(Path.Combine(directory, "release-set.v2.json"), manifestBytes);
            return new Candidate(
                directory,
                signed,
                manifestBytes,
                Convert.ToHexStringLower(SHA256.HashData(manifestBytes)),
                paths);
        }

        public StableCertification CreateStableCertification(
            Candidate pilot,
            Candidate stable,
            DateTimeOffset? authorizationIssuedAt = null,
            DateTimeOffset? authorizationExpiresAt = null,
            Func<PersonalLifecycleEvidenceReceipt, PersonalLifecycleEvidenceReceipt>?
                evidenceMutator = null,
            Func<PersonalLifecycleEvidenceReceipt, byte[], byte[]>?
                evidenceBytesMutator = null,
            Func<PersonalCertifiedTestMatrix, PersonalCertifiedTestMatrix>?
                matrixMutator = null)
        {
            var cleanDevice = CreateLifecycleEvidence(
                PersonalLifecycleEvidenceContract.CleanDeviceLifecycle,
                pilot,
                stable,
                evidenceMutator,
                evidenceBytesMutator);
            var twoUpdate = CreateLifecycleEvidence(
                PersonalLifecycleEvidenceContract.TwoUpdateUpgradeLifecycle,
                pilot,
                stable,
                evidenceMutator,
                evidenceBytesMutator);
            var failureRecovery = CreateLifecycleEvidence(
                PersonalLifecycleEvidenceContract.FailureRecoveryLifecycle,
                pilot,
                stable,
                evidenceMutator,
                evidenceBytesMutator);
            var matrix = new PersonalCertifiedTestMatrix
            {
                CleanDeviceLifecycle = CreateReference(cleanDevice),
                TwoUpdateUpgradeLifecycle = CreateReference(twoUpdate),
                FailureRecoveryLifecycle = CreateReference(failureRecovery),
            };
            matrix = matrixMutator?.Invoke(matrix) ?? matrix;
            var trust = CreateTrust();
            var releaseKey = trust.ReleaseKeys.Single();
            var compiledTrust = new PersonalProductionGateCompiledTrust
            {
                SchemaVersion = 2,
                ProductionBuild = true,
                ManifestOrigin = trust.ManifestOrigin.AbsoluteUri,
                ArtifactOrigin = trust.ArtifactOrigin.AbsoluteUri,
                Product = trust.Product,
                Environment = trust.Environment,
                Channel = "stable",
                StartupStubVersion = trust.CertifiedStartupStubVersion,
                ReleaseKeyId = releaseKey.KeyId,
                ReleaseKeyX = releaseKey.X,
                ReleaseKeyY = releaseKey.Y,
                CanonicalLowSFromSequence = trust.CanonicalLowSFromSequence,
                AuthenticodeSignerSha256Thumbprint =
                    trust.ExpectedAuthenticodeSignerSha256Thumbprint,
            };
            var compiledTrustSha256 =
                PersonalProductionGateEvidence.ComputeCompiledTrustSha256(compiledTrust);
            var clientExecutables = new[]
            {
                "Ensou.Dsh.Bootstrapper.exe",
                "Ensou.Dsh.ClientBootstrapper.exe",
                "Ensou.Dsh.Launcher.exe",
                "Ensou.Dsh.Personal.Maintenance.exe",
            }.Select((fileName, index) => new PersonalProductionGateExecutable
            {
                FileName = fileName,
                SizeBytes = 10_000 + index,
                Sha256 = Hash($"executable:{fileName}"),
                AuthenticodeStatus = "Valid",
                SignatureType = "Authenticode",
                SignerSha256Thumbprint =
                    trust.ExpectedAuthenticodeSignerSha256Thumbprint,
                Timestamped = true,
                CompiledTrustSha256 = compiledTrustSha256,
            }).ToArray();
            var gate = new PersonalProductionGateEvidence
            {
                SchemaVersion = 1,
                EvidenceType = PersonalProductionGateEvidence.EvidenceTypeValue,
                Product = PersonalReleaseSetContract.Product,
                ReleaseSetId = stable.Manifest.ReleaseSetId,
                ProductionDistributionGate = true,
                CompiledTrust = compiledTrust,
                CompiledTrustSha256 = compiledTrustSha256,
                Installer = new PersonalProductionGateExecutable
                {
                    FileName = PersonalCertifiedInstaller.OfficialFileName,
                    SizeBytes = 123_456,
                    Sha256 = new string('c', 64),
                    AuthenticodeStatus = "Valid",
                    SignatureType = "Authenticode",
                    SignerSha256Thumbprint =
                        trust.ExpectedAuthenticodeSignerSha256Thumbprint,
                    Timestamped = true,
                    CompiledTrustSha256 = compiledTrustSha256,
                },
                ClientExecutables = clientExecutables,
                ClientBundle = new PersonalProductionGateArtifact
                {
                    FileName = "client-bundle.zip",
                    SizeBytes = stable.Manifest.ClientBundle.SizeBytes,
                    Sha256 = stable.Manifest.ClientBundle.Sha256,
                },
                Payload = new PersonalProductionGatePayload
                {
                    Manifest = new PersonalProductionGateArtifact
                    {
                        FileName = "release-set.v2.json",
                        SizeBytes = stable.ManifestBytes.LongLength,
                        Sha256 = stable.ManifestSha256,
                    },
                    StartupStub = new PersonalProductionGateArtifact
                    {
                        FileName = clientExecutables[0].FileName,
                        SizeBytes = clientExecutables[0].SizeBytes,
                        Sha256 = clientExecutables[0].Sha256,
                    },
                    ClientBundle = new PersonalProductionGateArtifact
                    {
                        FileName = "client-bundle.zip",
                        SizeBytes = stable.Manifest.ClientBundle.SizeBytes,
                        Sha256 = stable.Manifest.ClientBundle.Sha256,
                    },
                    Runtime = new PersonalProductionGateArtifact
                    {
                        FileName = "runtime.zip",
                        SizeBytes = stable.Manifest.Runtime.SizeBytes,
                        Sha256 = stable.Manifest.Runtime.Sha256,
                    },
                },
                ValidatedAtUtc = _nowUtc.AddHours(-3).ToString(
                    "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",
                    System.Globalization.CultureInfo.InvariantCulture),
            };
            var gatePath = Path.Combine(_root, $"production-gate-{Guid.NewGuid():N}.json");
            File.WriteAllBytes(gatePath, gate.SerializeCanonical());
            var gateSnapshot = PersonalProductionGateEvidenceSnapshot.Read(gatePath);
            var feed = new PersonalCertifiedFeedEvidence
            {
                PilotManifestUri = new Uri(
                    "https://updates.example.test/v2/channels/pilot/release-set.v2.json"),
                ExternalPilotManifestSha256 = pilot.ManifestSha256,
                VerifiedArtifactCount = 2,
                AllArtifactSignaturesValid = true,
                AllArtifactHashesValid = true,
                ImmutablePublication = true,
                AtomicChannelHead = true,
                VerifiedAtUtc = _nowUtc.AddHours(-2),
            };
            var feedEvidencePath = Path.Combine(
                _root,
                $"external-pilot-feed-{Guid.NewGuid():N}.json");
            File.WriteAllBytes(feedEvidencePath, feed.SerializeCanonical());
            var receipt = new PersonalCertifiedDistributionReceipt
            {
                SchemaVersion = 2,
                Product = PersonalReleaseSetContract.Product,
                SourceChannel = "pilot",
                TargetChannel = "stable",
                ReleaseSetId = stable.Manifest.ReleaseSetId,
                PilotManifestSha256 = pilot.ManifestSha256,
                StableManifestSha256 = stable.ManifestSha256,
                Artifacts = PersonalFeedArtifactReceipt.FromManifest(stable.Manifest),
                Installer = gate.ToCertifiedInstaller(),
                ProductionGateEvidence = PersonalProductionGateEvidenceReference.Create(
                    gateSnapshot),
                Feed = feed,
                Certification = matrix,
                ApprovedAtUtc = _nowUtc.AddHours(-1),
                DistributionAuthorized = true,
            };
            var receiptBytes = PersonalFeedJson.Serialize(receipt);
            var receiptPath = Path.Combine(_root, $"receipt-{Guid.NewGuid():N}.json");
            File.WriteAllBytes(receiptPath, receiptBytes);
            var placeholder = new PersonalStablePromotionAuthorization
            {
                SchemaVersion = 1,
                Product = PersonalReleaseSetContract.Product,
                Channel = "stable",
                ReleaseSetId = stable.Manifest.ReleaseSetId,
                PilotManifestSha256 = pilot.ManifestSha256,
                StableManifestSha256 = stable.ManifestSha256,
                CertificationReceiptSha256 = Convert.ToHexStringLower(SHA256.HashData(receiptBytes)),
                InstallerFileName = receipt.Installer.FileName,
                InstallerSizeBytes = receipt.Installer.SizeBytes,
                InstallerSha256 = receipt.Installer.Sha256,
                IssuedAtUtc = authorizationIssuedAt ?? _nowUtc.AddMinutes(-5),
                ExpiresAtUtc = authorizationExpiresAt ?? _nowUtc.AddDays(1),
                Signature = ZeroSignature(),
            };
            var authorization = placeholder with
            {
                Signature = Sign(
                    _certificationSigner,
                    "personal-certification-test",
                    PersonalStablePromotionAuthorization.CanonicalPayload(placeholder)),
            };
            var authorizationPath = Path.Combine(
                _root,
                $"authorization-{Guid.NewGuid():N}.json");
            File.WriteAllBytes(authorizationPath, PersonalFeedJson.Serialize(authorization));
            return new StableCertification(
                receiptPath,
                authorizationPath,
                cleanDevice.Path,
                twoUpdate.Path,
                failureRecovery.Path,
                gatePath,
                feedEvidencePath);
        }

        private LifecycleSidecar CreateLifecycleEvidence(
            string kind,
            Candidate pilot,
            Candidate stable,
            Func<PersonalLifecycleEvidenceReceipt, PersonalLifecycleEvidenceReceipt>?
                evidenceMutator,
            Func<PersonalLifecycleEvidenceReceipt, byte[], byte[]>?
                evidenceBytesMutator)
        {
            if (stable.Manifest.Sequence < 3)
            {
                throw new InvalidOperationException(
                    "Certified Stable test targets must leave room for two prior update sequences.");
            }
            var historySha256 = Hash($"{kind}:history-fixture");
            var workspaceSha256 = Hash($"{kind}:workspace-fixture");
            var witness = new PersonalLifecycleLocalDataWitness
            {
                HistoryBeforeSha256 = historySha256,
                HistoryAfterSha256 = historySha256,
                WorkspaceBeforeSha256 = workspaceSha256,
                WorkspaceAfterSha256 = workspaceSha256,
            };
            var witnessSha256 = PersonalFeedJson.Sha256(PersonalFeedJson.Serialize(witness));
            var gates = PersonalLifecycleEvidenceContract.RequiredGates(kind)
                .Select(gate =>
                {
                    var semantics = PersonalLifecycleGateEvidence.ExpectedSemantics(kind, gate);
                    return new PersonalLifecycleGateEvidence
                    {
                        Gate = gate,
                        Status = "PASS",
                        EvidenceSha256 = Hash($"{kind}:{gate}:evidence"),
                        ObservedProcessRole = semantics.Role,
                        ObservedProcessState = semantics.State,
                        ObservedProcessExecutableSha256 = Hash(
                            $"{kind}:{gate}:{semantics.Role}:executable"),
                        NetworkMode = semantics.NetworkMode,
                        LocalDataWitnessSha256 = witnessSha256,
                    };
                })
                .ToArray();
            IReadOnlyList<PersonalLifecycleUpdateHop> updateChain = [];
            if (string.Equals(
                    kind,
                    PersonalLifecycleEvidenceContract.TwoUpdateUpgradeLifecycle,
                    StringComparison.Ordinal))
            {
                var first = new PersonalLifecycleReleaseIdentity(
                    $"{stable.Manifest.ReleaseSetId}-previous-2",
                    stable.Manifest.Generation,
                    stable.Manifest.Sequence - 2,
                    Hash($"{stable.Manifest.ReleaseSetId}:previous-2:manifest"));
                var second = new PersonalLifecycleReleaseIdentity(
                    $"{stable.Manifest.ReleaseSetId}-previous-1",
                    stable.Manifest.Generation,
                    stable.Manifest.Sequence - 1,
                    Hash($"{stable.Manifest.ReleaseSetId}:previous-1:manifest"));
                var target = new PersonalLifecycleReleaseIdentity(
                    stable.Manifest.ReleaseSetId,
                    stable.Manifest.Generation,
                    stable.Manifest.Sequence,
                    pilot.ManifestSha256);
                updateChain =
                [
                    new PersonalLifecycleUpdateHop(first, second),
                    new PersonalLifecycleUpdateHop(second, target),
                ];
            }
            var value = new PersonalLifecycleEvidenceReceipt
            {
                SchemaVersion = PersonalLifecycleEvidenceContract.SchemaVersion,
                ReceiptType = PersonalLifecycleEvidenceContract.ReceiptType,
                Product = PersonalReleaseSetContract.Product,
                Environment = PersonalReleaseSetContract.ProductionEnvironment,
                Channel = "pilot",
                Kind = kind,
                TestRunId = Guid.NewGuid().ToString("D"),
                ReleaseSetId = stable.Manifest.ReleaseSetId,
                Generation = stable.Manifest.Generation,
                Sequence = stable.Manifest.Sequence,
                PilotManifestSha256 = pilot.ManifestSha256,
                Artifacts = PersonalFeedArtifactReceipt.FromManifest(stable.Manifest),
                CompletedAtUtc = _nowUtc.AddMinutes(-90),
                UpdateChain = updateChain,
                LocalDataWitness = witness,
                RequiredGates = gates,
            };
            value = evidenceMutator?.Invoke(value) ?? value;
            var bytes = evidenceMutator is null && evidenceBytesMutator is null
                ? value.SerializeCanonical()
                : PersonalFeedJson.Serialize(value);
            bytes = evidenceBytesMutator?.Invoke(value, bytes) ?? bytes;
            var path = Path.Combine(_root, $"{kind}-{Guid.NewGuid():N}.json");
            File.WriteAllBytes(path, bytes);
            return new LifecycleSidecar(path, bytes, value);
        }

        private static PersonalLifecycleEvidenceReference CreateReference(
            LifecycleSidecar sidecar) => new()
            {
                Kind = sidecar.Receipt.Kind,
                TestRunId = sidecar.Receipt.TestRunId,
                ReceiptSizeBytes = sidecar.Bytes.LongLength,
                ReceiptSha256 = Convert.ToHexStringLower(SHA256.HashData(sidecar.Bytes)),
                CompletedAtUtc = sidecar.Receipt.CompletedAtUtc,
            };

        private static string Hash(string value) => Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(value)));

        public byte[] CreateTrustWithSharedKey()
        {
            var key = PersonalReleaseSetSigner.ExportPublicKey("shared-test", _releaseSigner);
            return PersonalFeedJson.Serialize(new PersonalFeedTrustConfiguration
            {
                SchemaVersion = 1,
                Product = PersonalReleaseSetContract.Product,
                Environment = PersonalReleaseSetContract.ProductionEnvironment,
                ManifestOrigin = new Uri("https://updates.example.test/"),
                ArtifactOrigin = new Uri("https://updates.example.test/"),
                CertifiedStartupStubVersion = "1.0.0",
                ExpectedAuthenticodeSignerSha256Thumbprint = new string('d', 64),
                ReleaseKeys = [key],
                CertificationKeys = [key],
                CanonicalLowSFromSequence = 1,
                AllowedClockSkewSeconds = 120,
                MaximumOfflineGraceHours = 168,
            });
        }

        public byte[] CreateTrustBytes() => PersonalFeedJson.Serialize(CreateTrust());

        public byte[] CreateTrustWithCertificationAlias()
        {
            var trust = CreateTrust();
            var original = trust.CertificationKeys.Single();
            return PersonalFeedJson.Serialize(trust with
            {
                CertificationKeys =
                [
                    original,
                    original with { KeyId = "personal-certification-alias" },
                ],
            });
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

        private PersonalFeedTrustConfiguration CreateTrust() => new()
        {
            SchemaVersion = 1,
            Product = PersonalReleaseSetContract.Product,
            Environment = PersonalReleaseSetContract.ProductionEnvironment,
            ManifestOrigin = new Uri("https://updates.example.test/"),
            ArtifactOrigin = new Uri("https://updates.example.test/"),
            CertifiedStartupStubVersion = "1.0.0",
            ExpectedAuthenticodeSignerSha256Thumbprint = new string('d', 64),
            ReleaseKeys = [PersonalReleaseSetSigner.ExportPublicKey(
                "personal-release-test",
                _releaseSigner)],
            CertificationKeys = [PersonalReleaseSetSigner.ExportPublicKey(
                "personal-certification-test",
                _certificationSigner)],
            CanonicalLowSFromSequence = 1,
            AllowedClockSkewSeconds = 120,
            MaximumOfflineGraceHours = 168,
        };

        private static PersonalReleaseSignature ZeroSignature() => new()
        {
            Algorithm = PersonalReleaseSetContract.SignatureAlgorithm,
            KeyId = "placeholder",
            Value = PersonalReleaseBase64Url.Encode(new byte[64]),
        };

        private static PersonalReleaseSignature Sign(
            ECDsa signer,
            string keyId,
            ReadOnlySpan<byte> payload) => new()
            {
                Algorithm = PersonalReleaseSetContract.SignatureAlgorithm,
                KeyId = keyId,
                Value = PersonalReleaseBase64Url.Encode(signer.SignData(
                    payload,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
            };
    }

    internal sealed record Candidate(
        string Directory,
        PersonalReleaseSetManifest Manifest,
        byte[] ManifestBytes,
        string ManifestSha256,
        IReadOnlyList<string> ArtifactPaths);

    internal sealed record StableCertification(
        string ReceiptPath,
        string AuthorizationPath,
        string CleanDeviceLifecyclePath,
        string TwoUpdateUpgradeLifecyclePath,
        string FailureRecoveryLifecyclePath,
        string ProductionGateEvidencePath,
        string ExternalPilotFeedEvidencePath);

    internal sealed record LifecycleSidecar(
        string Path,
        byte[] Bytes,
        PersonalLifecycleEvidenceReceipt Receipt);

    internal sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class SimulatedCrashException : Exception;
}
