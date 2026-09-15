using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Installation;
using Ensou.Dsh.Enterprise.ReleasePublisher;

namespace Ensou.Dsh.Enterprise.ReleasePublisherTests;

internal static class Program
{
    private const string PrivateKeyCrashProbe =
        "--publisher-private-key-crash-probe";
    private static readonly string TempRoot = Path.Combine(
        Path.GetTempPath(),
        "ensou-dsh-enterprise-publisher-tests",
        Guid.NewGuid().ToString("N"));

    public static async Task<int> Main(string[] args)
    {
        if (args is
            [
                PrivateKeyCrashProbe,
                var configPath,
                var privateKeyPath,
                var ledgerPath,
                var outputDirectory,
                var markerPath
            ])
        {
            return RunPrivateKeyCrashProbe(
                configPath,
                privateKeyPath,
                ledgerPath,
                outputDirectory,
                markerPath);
        }
        Directory.CreateDirectory(TempRoot);
        var tests = new (string Name, Func<Task> Run)[]
        {
            ("publisher signs artifacts and manifest then self-verifies", PublisherRoundTripAsync),
            ("publisher rejects a Startup Stub protocol range excluding current Stub", PublisherRejectsIncompatibleStartupStubAsync),
            ("publisher ledger rejects sequence reuse and accepts advance", PublisherLedgerAsync),
            ("publication transaction recovers every exact crash window and blocks N+1", PublisherPublicationTransactionTests.CrashWindowsRecoverExactAsync),
            ("later publication recovers across the previous committed receipt", PublisherPublicationTransactionTests.LaterCrashWindowsRecoverAcrossPreviousReceiptAsync),
            ("publication transaction keeps committed success across late cleanup failure", PublisherPublicationTransactionTests.LateCleanupFailurePreservesSuccessAsync),
            ("publication pending state contains no plaintext manifest or private key", PublisherPublicationTransactionTests.ProtectedStateContainsNoPlaintextManifestOrKeyAsync),
            ("publication transaction rejects whole-root replay and schema downgrade", PublisherPublicationTransactionTests.ReplayAndSchemaDowngradeFailClosedAsync),
            ("publication receipt readback rejects committed output tamper", PublisherPublicationTransactionTests.CommittedReadbackDetectsTamperAsync),
            ("policy handoff binds result, manifest, journal, and locked exact paths", PolicyHandoffBindingAsync),
            ("publisher accepts private key only by file reference and never prints it", PrivateKeyBoundaryAsync),
            ("publisher holds the source private key and never stages its bytes", PrivateKeySourceLeaseAsync),
            ("publisher releases the source private key after capture failure", PrivateKeyCaptureFailureReleasesLeaseAsync),
            ("publisher crash leaves the source key but no staged key bytes", PrivateKeyCrashLeavesNoStagedSecretAsync),
            ("publisher rejects a reparse ancestor for private key", ReparseAncestorRejectedAsync),
            ("publisher validates an exact managed plugin-policy package", PluginPolicyPublishedAsync),
            ("production publisher verifies exact signed plugin admission", PluginPromotionAdmissionAsync),
            ("production publisher binds an exact multi-runtime plugin-policy handoff", PluginPromotionMultiRuntimeAdmissionAsync),
            ("production plugin promotion journal consumes only exact external authorization", PublisherPluginPromotionJournalTests.RunAsync),
            ("production publisher rejects each tampered plugin admission field", PluginPromotionTamperRejectedAsync),
            ("production plugin evidence rejects a reparse ancestor", PluginPromotionReparseRejectedAsync),
            ("publisher rejects skill candidates and plugin metadata drift", InvalidPluginPolicyRejectedAsync),
            ("publisher rejects missing runtime admission inputs", MissingRuntimeAdmissionRejectedAsync),
            ("runtime admission contract loads the active versions lock and managed patch manifest", ManagedPatchManifestContractAsync),
            ("runtime admission accepts only the reviewed exact source toolchain", PublisherRuntimeToolchainTests.RunAsync),
            ("publisher rejects tampered pinned source metadata", TamperedRuntimeMetadataRejectedAsync),
            ("publisher rejects runtime metadata not eligible for production promotion", NonPromotableRuntimeMetadataRejectedAsync),
            ("publisher rejects a mismatched runtime Web auth protocol", WrongRuntimeWebAuthProtocolRejectedAsync),
            ("publisher rejects the former rc2 runtime metadata", FormerRc2RuntimeMetadataRejectedAsync),
            ("publisher rejects runtime admission signed by the wrong key", WrongRuntimeAdmissionKeyRejectedAsync),
            ("publisher rejects runtime admission for the wrong metadata digest", WrongRuntimeAdmissionDigestRejectedAsync),
            ("publisher rejects artifact filePath and URI basename mismatch", ArtifactFileNameMismatchRejectedAsync),
            ("production publisher config cannot replace runtime-admission trust", ForgedProductionTrustRejectedAsync),
            ("production publisher fails closed without compiled runtime-admission trust", MissingProductionTrustRejectedAsync),
            ("runtime-admission trust cannot reuse the release-signing key", AdmissionKeyIndependenceAsync),
            ("plugin-admission trust is independent from runtime, brand, lease, and release keys", PluginAdmissionKeyIndependenceAsync),
            ("runtime-admission receipt expires after thirty days", StaleRuntimeAdmissionRejectedAsync),
            ("runtime source-release v2 exact admission and v1 compatibility", RuntimeSourceReleaseAdmissionAsync),
            ("publisher snapshots bytes and rejects concurrently mutable sources", InputSnapshotBoundaryAsync),
            ("journal intent snapshot never captures a release private key", PluginPromotionIntentSnapshotAsync),
            ("production trust fingerprint rejects placeholders and reused keys", ProductionTrustFingerprintAsync),
            ("Pilot preflight rejects development and unsigned inputs with a machine report", PilotReadinessFailClosedAsync),
            ("Pilot wrapper holds a deny-write Publisher handle across verify and launch", PilotPublisherReplacementWindowClosedAsync),
            ("published-artifact Authenticode gate rejects catalog-only and untimestamped signatures", PublishedArtifactAuthenticodeFailClosedAsync),
            ("Pilot preflight requires complete local-data API compatibility and whole-home rollback evidence", LocalDataCompatibilityEvidenceAsync),
            ("real text-only rc7 to rc2 evidence replays through Publisher admission", RealLocalDataEvidenceReplayAsync),
            ("Pilot preflight rejects missing or mismatched local-data certification", PilotReadinessCertificationFailClosedAsync),
            ("Pilot preflight rejects mismatched signed Launcher archive entries", PilotReadinessClientBindingFailClosedAsync),
            ("Pilot preflight admits one complete immutable production tuple", PilotReadinessAdmitAsync),
            ("Windows Pilot evidence requires an independent compiled ES256 attestation root", WindowsPilotEvidenceTrustTests.RunAsync),
        };
        if (args is ["--runtime-source-release-checks"])
        {
            tests = tests.Where(test => test.Run == RuntimeSourceReleaseAdmissionAsync).ToArray();
        }
        else if (args is ["--plugin-promotion-admission-checks"])
        {
            tests = tests.Where(test => test.Run == PluginPromotionAdmissionAsync
                || test.Run == PluginPromotionMultiRuntimeAdmissionAsync
                || test.Run == PluginPromotionTamperRejectedAsync).ToArray();
        }
        var failures = 0;
        try
        {
            foreach (var test in tests)
            {
                try
                {
                    await test.Run().ConfigureAwait(false);
                    Console.WriteLine($"PASS  {test.Name}");
                }
                catch (Exception exception)
                {
                    failures++;
                    Console.Error.WriteLine($"FAIL  {test.Name}");
                    Console.Error.WriteLine(exception);
                }
            }
        }
        finally
        {
            if (Directory.Exists(TempRoot))
            {
                Directory.Delete(TempRoot, recursive: true);
            }
        }
        Console.WriteLine($"{tests.Length - failures}/{tests.Length} publisher checks passed.");
        return failures == 0 ? 0 : 1;
    }

    private static Task RuntimeSourceReleaseAdmissionAsync()
    {
        var root = Path.Combine(TempRoot, "runtime-source-release");
        Directory.CreateDirectory(root);
        var archivePath = Path.Combine(root, "runtime.zip");
        var metadataPath = archivePath + ".metadata.json";
        var receiptPath = Path.Combine(root, "organization-admission.json");
        var hashEvidencePath = archivePath + ".sha256";
        const string releaseId = "managed-v2026.09.10.1";
        var archiveBytes = RandomNumberGenerator.GetBytes(512);
        File.WriteAllBytes(archivePath, archiveBytes);
        var metadata = JsonNode.Parse(File.ReadAllBytes(Path.Combine(
            FindRepositoryRootForContract(), "release", "examples", "source-runtime.metadata.json")))!.AsObject();
        metadata["releaseId"] = releaseId;
        metadata["builtAtUtc"] = DateTimeOffset.UtcNow.AddMinutes(-1);
        metadata["artifact"]!["fileName"] = Path.GetFileName(archivePath);
        metadata["artifact"]!["sizeBytes"] = archiveBytes.Length;
        metadata["artifact"]!["sha256"] = Digest(archiveBytes);
        File.WriteAllText(metadataPath, metadata.ToJsonString(), new UTF8Encoding(false));
        var metadataBytes = File.ReadAllBytes(metadataPath);
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = signer.ExportParameters(false);
        var trust = new PublisherRuntimeAdmissionTrust
        {
            KeyId = "runtime-source-release-fixture",
            X = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(key.Q.X!),
            Y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(key.Q.Y!),
        };
        var source = new PublisherRuntimeSourceRelease
        {
            Repository = "ensou/ensou-enterprise-system", GithubReleaseId = 12345,
            TagName = releaseId, TargetCommit = new string('a', 40), Immutable = true,
            Assets =
            [
                Asset("archive", 101, Path.GetFileName(archivePath), archiveBytes),
                Asset("metadata", 102, Path.GetFileName(metadataPath), metadataBytes),
                Asset("hash-evidence", 103, "runtime.zip.sha256",
                    Encoding.ASCII.GetBytes(Digest(archiveBytes) + "  runtime.zip\n")),
            ],
        };
        var v1 = new PublisherRuntimeAdmissionReceipt
        {
            SchemaVersion = 1, ReceiptType = PublisherRuntimeAdmissionReceipt.CurrentReceiptType,
            ReleaseId = releaseId, SourceRuntimeMetadataSha256 = Digest(metadataBytes),
            Decision = PublisherRuntimeAdmissionReceipt.AdmittedDecision,
            ReviewedAtUnixSeconds = DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeSeconds(),
            Signature = new EnterpriseReleaseSignature { Algorithm = "ES256", KeyId = trust.KeyId, Value = string.Empty },
        };
        var frozenV1 = "{\"schemaVersion\":1,\"receiptType\":\"ensou-dsh-runtime-organization-admission\",\"releaseId\":\""
            + releaseId + "\",\"sourceRuntimeMetadataSha256\":\"" + Digest(metadataBytes)
            + "\",\"decision\":\"admitted\",\"reviewedAtUnixSeconds\":" + v1.ReviewedAtUnixSeconds + "}";
        AssertEqual(frozenV1, Encoding.UTF8.GetString(PublisherRuntimeAdmissionCanonicalJson.Payload(v1)));
        v1 = Sign(v1);
        var v1Bytes = Serialize(v1);
        AssertTrue(!Encoding.UTF8.GetString(v1Bytes).Contains("sourceRelease", StringComparison.Ordinal));
        PublisherRuntimeAdmissionReceipt.Parse(v1Bytes).Verify(releaseId, Digest(metadataBytes), trust);
        AssertThrows<InvalidDataException>(() => v1.RequireExactSourceRelease(source.Repository, releaseId, source.TargetCommit));
        File.WriteAllBytes(receiptPath, v1Bytes);
        _ = PublisherRuntimeAdmissionValidator.ValidateFiles(archivePath, releaseId, metadataPath, receiptPath, trust);
        Console.WriteLine("PASS  frozen v1 payload and admission unchanged; v1 has no source origin");

        var v2 = Sign(v1 with { SchemaVersion = 2, SourceRelease = source });
        var parsed = PublisherRuntimeAdmissionReceipt.Parse(Serialize(v2));
        parsed.Verify(releaseId, Digest(metadataBytes), trust);
        _ = parsed.RequireExactSourceRelease(source.Repository, releaseId, source.TargetCommit);
        AssertThrows<InvalidDataException>(() => parsed.RequireExactSourceRelease("other/repository", releaseId, source.TargetCommit));
        AssertThrows<InvalidDataException>(() => parsed.RequireExactSourceRelease(source.Repository, "managed-v2026.09.10.2", source.TargetCommit));
        AssertThrows<InvalidDataException>(() => parsed.RequireExactSourceRelease(source.Repository, releaseId, new string('b', 40)));
        ValidateBoth(v2);
        var crlfAssets = source.Assets.ToArray();
        crlfAssets[2] = Asset("hash-evidence", 103, "runtime.zip.sha256", Encoding.ASCII.GetBytes(Digest(archiveBytes) + "  runtime.zip\r\n"));
        ValidateBoth(Sign(v2 with { SourceRelease = source with { Assets = crlfAssets } }));
        var maximumIdAssets = source.Assets.Select((asset, index) => asset with
        {
            GithubAssetId = PublisherRuntimeSourceRelease.MaximumGitHubId - index,
        }).ToArray();
        ValidateBoth(Sign(v2 with { SourceRelease = source with
        {
            GithubReleaseId = PublisherRuntimeSourceRelease.MaximumGitHubId, Assets = maximumIdAssets,
        } }));
        Console.WriteLine("PASS  real ES256 v2 LF/CRLF proofs validate files and locked snapshots");

        // Inspect actual canonical payload membership, including fields whose
        // shape checks would reject a tamper before cryptographic verification.
        using (var payload = JsonDocument.Parse(PublisherRuntimeAdmissionCanonicalJson.Payload(v2)))
        {
            var sourcePayload = payload.RootElement.GetProperty("sourceRelease");
            AssertTrue(sourcePayload.EnumerateObject().Select(property => property.Name).SequenceEqual(
                ["repository", "githubReleaseId", "tagName", "targetCommit", "immutable", "assets"]));
            foreach (var assetPayload in sourcePayload.GetProperty("assets").EnumerateArray())
            {
                AssertTrue(assetPayload.EnumerateObject().Select(property => property.Name).SequenceEqual(
                    ["role", "githubAssetId", "fileName", "sizeBytes", "sha256"]));
            }
        }

        foreach (var mutate in new Action<JsonObject>[]
        {
            value => value["sourceRelease"]!["repository"] = "other/repository",
            value => value["sourceRelease"]!["githubReleaseId"] = 12346,
            value => value["sourceRelease"]!["targetCommit"] = new string('b', 40),
            value => value["sourceRelease"]!["assets"]![0]!["githubAssetId"] = 999,
            value => value["sourceRelease"]!["assets"]![1]!["githubAssetId"] = 998,
            value => value["sourceRelease"]!["assets"]![2]!["githubAssetId"] = 997,
            value => value["sourceRelease"]!["assets"]![1]!["fileName"] = "other.metadata.json",
            value => value["sourceRelease"]!["assets"]![0]!["sizeBytes"] = 513,
            value => value["sourceRelease"]!["assets"]![1]!["sizeBytes"] = 1,
        })
        {
            var node = JsonNode.Parse(Serialize(v2))!.AsObject();
            mutate(node);
            var changed = PublisherRuntimeAdmissionReceipt.Parse(Encoding.UTF8.GetBytes(node.ToJsonString()));
            AssertTrue(!PublisherRuntimeAdmissionCanonicalJson.Payload(changed).SequenceEqual(PublisherRuntimeAdmissionCanonicalJson.Payload(v2)));
            AssertThrows<InvalidDataException>(() => changed.Verify(releaseId, Digest(metadataBytes), trust));
        }
        foreach (var mutate in new Action<JsonObject>[]
        {
            value => value["sourceRelease"] = null,
            value => value.Remove("sourceRelease"),
            value => value["sourceRelease"]!["extra"] = true,
            value => value["sourceRelease"]!["immutable"] = false,
            value => value["sourceRelease"]!["immutable"] = "true",
            value => value["sourceRelease"]!["repository"] = "../repo",
            value => value["sourceRelease"]!["githubReleaseId"] = "12345",
            value => value["sourceRelease"]!["githubReleaseId"] = 0,
            value => value["sourceRelease"]!["githubReleaseId"] = 9007199254740992L,
            value => value["sourceRelease"]!["tagName"] = "managed-v2026.09.10.2",
            value => value["sourceRelease"]!["targetCommit"] = new string('A', 40),
            value => value["sourceRelease"]!["assets"]![0]!["extra"] = true,
            value => value["sourceRelease"]!["assets"]![0]!["githubAssetId"] = "101",
            value => value["sourceRelease"]!["assets"]![0]!["githubAssetId"] = 102,
            value => value["sourceRelease"]!["assets"]![0]!["githubAssetId"] = 9007199254740992L,
            value => value["sourceRelease"]!["assets"]![0]!["role"] = "metadata",
            value => value["sourceRelease"]!["assets"]![0]!["fileName"] = "../runtime.zip",
            value => value["sourceRelease"]!["assets"]![1]!["fileName"] = "runtime.zip",
            value => value["sourceRelease"]!["assets"]![0]!["sizeBytes"] = "512",
            value => value["sourceRelease"]!["assets"]![0]!["sizeBytes"] = 8589934593L,
            value => value["sourceRelease"]!["assets"]![0]!["sizeBytes"] = 0,
            value => value["sourceRelease"]!["assets"]![0]!["githubAssetId"] = -1,
            value => value["sourceRelease"]!["assets"]![0]!["sha256"] = new string('A', 64),
            value => value["sourceRelease"]!["assets"]![2]!["sha256"] = new string('a', 64),
            value => value["sourceRelease"]!["assets"]![2]!["sizeBytes"] = 1,
            value => value["sourceRelease"]!["assets"]!.AsArray().RemoveAt(2),
        })
        {
            var node = JsonNode.Parse(Serialize(v2))!.AsObject(); mutate(node);
            AssertThrows<InvalidDataException>(() => PublisherRuntimeAdmissionReceipt.Parse(Encoding.UTF8.GetBytes(node.ToJsonString())));
        }
        foreach (var member in new[] { "repository", "githubReleaseId", "tagName", "targetCommit", "immutable", "assets" })
        {
            var node = JsonNode.Parse(Serialize(v2))!.AsObject(); node["sourceRelease"]!.AsObject().Remove(member);
            AssertThrows<InvalidDataException>(() => PublisherRuntimeAdmissionReceipt.Parse(Encoding.UTF8.GetBytes(node.ToJsonString())));
        }
        foreach (var member in new[] { "role", "githubAssetId", "fileName", "sizeBytes", "sha256" })
        {
            var node = JsonNode.Parse(Serialize(v2))!.AsObject(); node["sourceRelease"]!["assets"]![0]!.AsObject().Remove(member);
            AssertThrows<InvalidDataException>(() => PublisherRuntimeAdmissionReceipt.Parse(Encoding.UTF8.GetBytes(node.ToJsonString())));
        }
        var v1WithNull = Encoding.UTF8.GetString(v1Bytes).Replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"sourceRelease\":null", StringComparison.Ordinal);
        AssertThrows<InvalidDataException>(() => PublisherRuntimeAdmissionReceipt.Parse(Encoding.UTF8.GetBytes(v1WithNull)));
        var duplicate = Encoding.UTF8.GetString(Serialize(v2)).Replace("\"immutable\":true", "\"immutable\":true,\"immutable\":true", StringComparison.Ordinal);
        AssertThrows<InvalidDataException>(() => PublisherRuntimeAdmissionReceipt.Parse(Encoding.UTF8.GetBytes(duplicate)));
        foreach (var checksumRecord in new[]
        {
            Digest(archiveBytes) + " runtime.zip\n",
            Digest(archiveBytes) + "  runtime.zip\nextra\n",
            Digest(archiveBytes) + "  other.zip\n",
            Digest(archiveBytes).ToUpperInvariant() + "  runtime.zip\n",
        })
        {
            var assets = source.Assets.ToArray();
            assets[2] = Asset("hash-evidence", 103, "runtime.zip.sha256", Encoding.ASCII.GetBytes(checksumRecord));
            var invalidRecord = Sign(v2 with { SourceRelease = source with { Assets = assets } });
            AssertThrows<InvalidDataException>(() => PublisherRuntimeAdmissionReceipt.Parse(Serialize(invalidRecord)));
        }
        Console.WriteLine("PASS  v2 signatures and strict shape/type/ID/name/checksum negatives");
        foreach (var index in new[] { 0, 1 })
        {
            foreach (var mutate in new Func<PublisherRuntimeSourceAsset, PublisherRuntimeSourceAsset>[]
            {
                asset => asset with { SizeBytes = asset.SizeBytes + 1 },
                asset => asset with { FileName = "other-" + asset.FileName },
                asset => asset with { Sha256 = new string('d', 64) },
            })
            {
                var assets = source.Assets.ToArray(); assets[index] = mutate(assets[index]);
                assets[2] = Asset("hash-evidence", 103, assets[0].FileName + ".sha256",
                    Encoding.ASCII.GetBytes(assets[0].Sha256 + "  " + assets[0].FileName + "\n"));
                var mismatch = Sign(v2 with { SourceRelease = source with { Assets = assets } });
                File.WriteAllBytes(receiptPath, Serialize(mismatch));
                AssertThrows<InvalidDataException>(() => PublisherRuntimeAdmissionValidator.ValidateFiles(
                    archivePath, releaseId, metadataPath, receiptPath, trust));
                AssertThrows<InvalidDataException>(ValidateSnapshot);
            }
        }
        AssertThrows<InvalidDataException>(() => (v2 with { ReviewedAtUnixSeconds = DateTimeOffset.UtcNow.AddDays(-31).ToUnixTimeSeconds() }).Verify(releaseId, Digest(metadataBytes), trust));
        using var wrongSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var wrongSignature = v2 with { Signature = v2.Signature with { Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(wrongSigner.SignData(PublisherRuntimeAdmissionCanonicalJson.Payload(v2), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) } };
        AssertThrows<InvalidDataException>(() => wrongSignature.Verify(releaseId, Digest(metadataBytes), trust));
        Console.WriteLine("PASS  signed v2 archive/metadata snapshot mismatches and unchanged age/key rejection");

        File.WriteAllBytes(receiptPath, Serialize(v2));
        var exactHashBytes = Encoding.ASCII.GetBytes(Digest(archiveBytes) + "  runtime.zip\n");
        File.WriteAllBytes(hashEvidencePath, exactHashBytes);
        string[] commandArgs =
        [
            "--verify-runtime-source-admission", "--archive", archivePath, "--metadata", metadataPath,
            "--hash-evidence", hashEvidencePath, "--receipt", receiptPath,
            "--repository", source.Repository, "--tag", releaseId, "--build-commit", source.TargetCommit,
        ];
        var allPaths = new[] { archivePath, metadataPath, hashEvidencePath, receiptPath };
        var locksChecked = 0;
        var stdout = new SourceAdmissionTestWriter(() => RequireAllLocked());
        var stderr = new StringWriter();
        var commandExit = PublisherRuntimeSourceAdmissionCommand.RunCore(
            commandArgs, () => trust, stdout, stderr, () => RequireAllLocked());
        AssertEqual(0, commandExit);
        AssertEqual(2, locksChecked);
        AssertEqual(string.Empty, stderr.ToString());
        using (var proof = JsonDocument.Parse(stdout.ToString()))
        {
            AssertTrue(proof.RootElement.EnumerateObject().Select(property => property.Name).SequenceEqual(["receiptSha256", "sourceRelease"]));
            AssertEqual(Digest(Serialize(v2)), proof.RootElement.GetProperty("receiptSha256").GetString());
            AssertEqual(source.TargetCommit, proof.RootElement.GetProperty("sourceRelease").GetProperty("targetCommit").GetString());
        }
        RequireAllReleased();
        foreach (var (option, value) in new[]
        {
            ("--archive", "relative.zip"), ("--archive", root),
            ("--metadata", Path.Combine(root, "missing.json")),
            ("--hash-evidence", metadataPath), ("--receipt", string.Empty),
            ("--repository", "other/repository"), ("--tag", "managed-v2026.09.10.2"),
            ("--build-commit", new string('b', 40)),
        })
        {
            var args = commandArgs.ToArray();
            args[Array.IndexOf(args, option) + 1] = value;
            RequireCommandFailure(args);
        }
        foreach (var unknownOption in new[] { "--trust", "--public-key", "--private-key", "--config", "--authority", "--Archive" })
        {
            var args = commandArgs.ToArray(); args[1] = unknownOption;
            RequireCommandFailure(args);
        }
        var duplicateOption = commandArgs.ToArray(); duplicateOption[3] = "--archive";
        RequireCommandFailure(duplicateOption);
        RequireCommandFailure(commandArgs[..^2]);
        RequireCommandFailure([.. commandArgs, "--trust", "fixture"]);
        foreach (var mutate in new Action[]
        {
            () => File.WriteAllBytes(hashEvidencePath, Encoding.ASCII.GetBytes(Digest(archiveBytes) + "  other.zip\n")),
            () => File.WriteAllBytes(archivePath, RandomNumberGenerator.GetBytes(512)),
            () => File.WriteAllBytes(metadataPath, "{}"u8.ToArray()),
            () => File.WriteAllBytes(receiptPath, Serialize(v1)),
            () => File.WriteAllBytes(receiptPath, Serialize(wrongSignature)),
        })
        {
            mutate(); RequireCommandFailure(commandArgs);
            File.WriteAllBytes(hashEvidencePath, exactHashBytes);
            File.WriteAllBytes(archivePath, archiveBytes);
            File.WriteAllBytes(metadataPath, metadataBytes);
            File.WriteAllBytes(receiptPath, Serialize(v2));
        }
        using (var mutableHash = new FileStream(hashEvidencePath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
        {
            RequireCommandFailure(commandArgs, checkReleased: false);
        }
        RequireAllReleased();
        File.WriteAllBytes(receiptPath, Serialize(Sign(v2 with { SourceRelease = source with { Assets = crlfAssets } })));
        File.WriteAllBytes(hashEvidencePath, Encoding.ASCII.GetBytes(Digest(archiveBytes) + "  runtime.zip\r\n"));
        stdout = new SourceAdmissionTestWriter(() => RequireAllLocked()); stderr = new StringWriter();
        AssertEqual(0, PublisherRuntimeSourceAdmissionCommand.RunCore(commandArgs, () => trust, stdout, stderr));
        RequireAllReleased();

        // Invoke the actual Publisher entrypoint with a fixture receipt. The
        // public route must use compiled production trust, never test injection.
        var savedOut = Console.Out; var savedError = Console.Error;
        var productionOut = new StringWriter(); var productionError = new StringWriter();
        try
        {
            Console.SetOut(productionOut); Console.SetError(productionError);
            var publicExit = (int)typeof(PublisherArguments).Assembly.EntryPoint!.Invoke(null, [commandArgs])!;
            AssertEqual(1, publicExit);
        }
        finally { Console.SetOut(savedOut); Console.SetError(savedError); }
        AssertEqual(string.Empty, productionOut.ToString());
        AssertTrue(productionError.ToString().Contains("Runtime source-admission verification failed:", StringComparison.Ordinal));
        RequireAllReleased();
        Console.WriteLine("PASS  source-admission command strict args, exact four-file proof, locks, tamper rejection, disposal and compiled-only entrypoint");
        return Task.CompletedTask;

        void RequireAllLocked()
        {
            foreach (var path in allPaths)
            {
                AssertThrows<IOException>(() => { using var blocked = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite); });
            }
            locksChecked++;
        }
        void RequireAllReleased()
        {
            foreach (var path in allPaths)
            {
                using var released = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            }
        }
        void RequireCommandFailure(string[] args, bool checkReleased = true)
        {
            var failureOut = new StringWriter(); var failureError = new StringWriter();
            AssertEqual(1, PublisherRuntimeSourceAdmissionCommand.RunCore(args, () => trust, failureOut, failureError));
            AssertEqual(string.Empty, failureOut.ToString());
            AssertTrue(failureError.ToString().StartsWith("Runtime source-admission verification failed:", StringComparison.Ordinal));
            if (checkReleased) { RequireAllReleased(); }
        }

        static string Digest(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
        static PublisherRuntimeSourceAsset Asset(string role, long id, string name, byte[] bytes) =>
            new() { Role = role, GithubAssetId = id, FileName = name, SizeBytes = bytes.LongLength, Sha256 = Digest(bytes) };
        static byte[] Serialize(PublisherRuntimeAdmissionReceipt receipt) =>
            JsonSerializer.SerializeToUtf8Bytes(receipt, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        PublisherRuntimeAdmissionReceipt Sign(PublisherRuntimeAdmissionReceipt receipt) => receipt with
        {
            Signature = receipt.Signature with { Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(signer.SignData(
                PublisherRuntimeAdmissionCanonicalJson.Payload(receipt), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) },
        };
        void ValidateBoth(PublisherRuntimeAdmissionReceipt receipt)
        {
            File.WriteAllBytes(receiptPath, Serialize(receipt));
            _ = PublisherRuntimeAdmissionValidator.ValidateFiles(archivePath, releaseId, metadataPath, receiptPath, trust);
            ValidateSnapshot();
        }
        void ValidateSnapshot()
        {
            using var staging = PublisherInputStaging.Create();
            var snapshot = new PublisherSnapshotArtifact(new PublisherArtifact
            {
                Component = "runtime", ReleaseId = releaseId, FilePath = archivePath,
                Uri = new Uri("https://example.invalid/runtime.zip"),
            }, staging.Capture(archivePath), null, null, staging.Capture(metadataPath), staging.Capture(receiptPath));
            PublisherRuntimeAdmissionValidator.Validate(snapshot, trust);
        }
    }

    private sealed class SourceAdmissionTestWriter(Action onWrite) : StringWriter
    {
        public override void WriteLine(string? value)
        {
            onWrite();
            base.WriteLine(value);
        }
    }

    private static int RunPrivateKeyCrashProbe(
        string configPath,
        string privateKeyPath,
        string ledgerPath,
        string outputDirectory,
        string markerPath)
    {
        try
        {
            using var snapshot = PublisherInputSnapshot.Capture(
                new PublisherArguments(
                    configPath,
                    privateKeyPath,
                    ledgerPath,
                    outputDirectory),
                CreatePublisherJsonOptions());
            File.WriteAllText(
                markerPath,
                snapshot.StagingRootPath,
                new UTF8Encoding(false));
            Environment.Exit(37);
            return 37;
        }
        catch
        {
            try
            {
                File.WriteAllText(
                    markerPath,
                    "CAPTURE-FAILED",
                    new UTF8Encoding(false));
            }
            catch
            {
                // The explicit exit code remains the bounded child diagnostic.
            }
            return 38;
        }
    }

    private static async Task PublisherRoundTripAsync()
    {
        using var fixture = PublisherFixture.Create();
        var originalCurrentDirectory = Environment.CurrentDirectory;
        var unrelatedCurrentDirectory = Path.Combine(TempRoot, "unrelated-current-directory");
        Directory.CreateDirectory(unrelatedCurrentDirectory);
        ProcessResult run;
        try
        {
            Environment.CurrentDirectory = unrelatedCurrentDirectory;
            run = await fixture.RunAsync(sequence: 1, outputName: "release-1")
                .ConfigureAwait(false);
        }
        finally
        {
            Environment.CurrentDirectory = originalCurrentDirectory;
        }
        AssertEqual(0, run.ExitCode);
        var manifestBytes = File.ReadAllBytes(
            Path.Combine(fixture.Root, "release-1", "release-set.v2.json"));
        var manifest = EnterpriseReleaseSetManifest.Parse(manifestBytes);
        var publicKey = JsonSerializer.Deserialize<EnterpriseReleasePublicKey>(
            File.ReadAllBytes(Path.Combine(
                fixture.Root,
                "release-1",
                "release-public-key.v2.json")),
            new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
        EnterpriseReleaseSetValidator.Verify(
            manifest,
            new EnterpriseReleaseTrustPolicy
            {
                Product = EnterpriseReleaseSetContract.Product,
                Environment = EnterpriseReleaseSetContract.DevelopmentE2EEnvironment,
                ExpectedChannel = manifest.Channel,
                CurrentStartupStubProtocol =
                    EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                ManifestOrigin = new Uri("https://updates.example/"),
                ArtifactOrigin = new Uri("https://artifacts.example/"),
                TrustedKeys = [publicKey],
            },
            DateTimeOffset.UtcNow);
        AssertEqual(3, manifest.Artifacts.Count);
        foreach (var artifact in manifest.Artifacts)
        {
            var outputArtifact = Path.Combine(
                fixture.Root,
                "release-1",
                Path.GetFileName(artifact.Uri.LocalPath));
            using var stream = File.OpenRead(outputArtifact);
            AssertEqual(
                EnterpriseReleaseArchiveTreeHash.Compute(stream),
                artifact.CompleteTreeSha256);
        }
        AssertTrue(File.Exists(Path.Combine(fixture.Root, "release-1", "launcher-1.zip")));
        AssertTrue(File.Exists(Path.Combine(fixture.Root, "release-1", "runtime-1.zip")));
        AssertTrue(File.Exists(Path.Combine(
            fixture.Root,
            "release-1",
            "managed-plugin-policy-1.zip")));
    }

    private static async Task PublisherRejectsIncompatibleStartupStubAsync()
    {
        using var fixture = PublisherFixture.Create();
        var prepared = fixture.Prepare(sequence: 1, outputName: "incompatible-stub");
        var config = JsonNode.Parse(File.ReadAllText(prepared.Arguments.ConfigPath))!
            .AsObject();
        config["startupStub"] = new JsonObject
        {
            ["minimumProtocol"] = 2,
            ["maximumProtocol"] = 2,
        };
        File.WriteAllText(
            prepared.Arguments.ConfigPath,
            config.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));

        var run = await fixture.RunPreparedAsync(prepared).ConfigureAwait(false);

        AssertTrue(run.ExitCode != 0);
        AssertFalse(Directory.Exists(prepared.Arguments.OutputDirectory));
    }

    private static async Task PublisherLedgerAsync()
    {
        using var fixture = PublisherFixture.Create();
        AssertEqual(0, (await fixture.RunAsync(1, "first").ConfigureAwait(false)).ExitCode);
        var replay = await fixture.RunAsync(1, "replay").ConfigureAwait(false);
        AssertEqual(1, replay.ExitCode);
        AssertTrue(replay.StandardError.Contains("reuse or rollback", StringComparison.Ordinal));
        AssertFalse(Directory.Exists(Path.Combine(fixture.Root, "replay")));
        AssertEqual(0, (await fixture.RunAsync(2, "second").ConfigureAwait(false)).ExitCode);
        using var ledger = JsonDocument.Parse(File.ReadAllBytes(fixture.LedgerPath));
        AssertEqual(2L, ledger.RootElement.GetProperty("highestSequence").GetInt64());
    }

    private static Task PolicyHandoffBindingAsync()
    {
        using var fixture = PublisherFixture.Create();
        fixture.AssertPolicyHandoffBinding();
        return Task.CompletedTask;
    }

    private static async Task PrivateKeyBoundaryAsync()
    {
        using var fixture = PublisherFixture.Create();
        var secret = Convert.ToBase64String(File.ReadAllBytes(fixture.PrivateKeyPath));
        var run = await fixture.RunAsync(1, "safe").ConfigureAwait(false);
        AssertEqual(0, run.ExitCode);
        AssertFalse(run.StandardOutput.Contains(secret, StringComparison.Ordinal));
        AssertFalse(run.StandardError.Contains(secret, StringComparison.Ordinal));

        var pemPath = fixture.CreatePemPrivateKey();
        var pemSecret = File.ReadAllText(pemPath);
        var pemRun = await fixture.RunWithPrivateKeyPathAsync(2, "pem-safe", pemPath)
            .ConfigureAwait(false);
        AssertEqual(0, pemRun.ExitCode);
        AssertFalse(pemRun.StandardOutput.Contains(pemSecret, StringComparison.Ordinal));
        AssertFalse(pemRun.StandardError.Contains(pemSecret, StringComparison.Ordinal));

        var rejected = await fixture.RunWithRawKeyArgumentAsync(secret).ConfigureAwait(false);
        AssertEqual(1, rejected.ExitCode);
        AssertFalse(rejected.StandardOutput.Contains(secret, StringComparison.Ordinal));
        AssertFalse(rejected.StandardError.Contains(secret, StringComparison.Ordinal));
    }

    private static Task PrivateKeySourceLeaseAsync()
    {
        using var fixture = PublisherFixture.Create();
        var prepared = fixture.Prepare(41, "private-key-source-lease");
        var keyBytes = File.ReadAllBytes(fixture.PrivateKeyPath);
        try
        {
            using (var snapshot = PublisherInputSnapshot.Capture(
                prepared.Arguments,
                CreatePublisherJsonOptions()))
            {
                AssertPrivateKeyMutationsDenied(
                    fixture.PrivateKeyPath,
                    keyBytes);
                var importedBytes = snapshot.ReadPrivateKeyBytes();
                try
                {
                    AssertTrue(importedBytes.SequenceEqual(keyBytes));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(importedBytes);
                }
                AssertThrows<InvalidOperationException>(
                    () => snapshot.ReadPrivateKeyBytes());
                AssertPrivateKeyMutationsDenied(
                    fixture.PrivateKeyPath,
                    keyBytes);
                AssertNoPublisherStagingContains(keyBytes);
            }

            AssertPrivateKeyMutationsAllowed(
                fixture.PrivateKeyPath,
                keyBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }
        return Task.CompletedTask;
    }

    private static Task PrivateKeyCaptureFailureReleasesLeaseAsync()
    {
        using var fixture = PublisherFixture.Create();
        var prepared = fixture.Prepare(42, "private-key-capture-failure");
        var keyBytes = File.ReadAllBytes(fixture.PrivateKeyPath);
        try
        {
            using (var config = JsonDocument.Parse(
                File.ReadAllBytes(prepared.Arguments.ConfigPath)))
            {
                var missingArtifact = config.RootElement
                    .GetProperty("artifacts")[0]
                    .GetProperty("filePath")
                    .GetString()
                    ?? throw new InvalidDataException(
                        "Publisher test artifact path is missing.");
                File.Delete(missingArtifact);
            }

            AssertThrows<InvalidDataException>(() =>
            {
                using var _ = PublisherInputSnapshot.Capture(
                    prepared.Arguments,
                    CreatePublisherJsonOptions());
            });
            AssertNoPublisherStagingContains(keyBytes);
            AssertPrivateKeyMutationsAllowed(
                fixture.PrivateKeyPath,
                keyBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }
        return Task.CompletedTask;
    }

    private static async Task PrivateKeyCrashLeavesNoStagedSecretAsync()
    {
        using var fixture = PublisherFixture.Create();
        var prepared = fixture.Prepare(43, "private-key-crash");
        var keyBytes = File.ReadAllBytes(fixture.PrivateKeyPath);
        var markerPath = Path.Combine(
            fixture.Root,
            $"private-key-crash-{Guid.NewGuid():N}.marker");
        Process? child = null;
        string? stagingRoot = null;
        try
        {
            child = StartCurrentTestProcess(
                PrivateKeyCrashProbe,
                prepared.Arguments.ConfigPath,
                prepared.Arguments.PrivateKeyPath,
                prepared.Arguments.LedgerPath,
                prepared.Arguments.OutputDirectory,
                markerPath);
            using (var timeout = new CancellationTokenSource(
                TimeSpan.FromSeconds(20)))
            {
                await child.WaitForExitAsync(timeout.Token)
                    .ConfigureAwait(false);
            }
            AssertEqual(37, child.ExitCode);
            AssertTrue(File.Exists(markerPath));
            stagingRoot = RequirePublisherStagingRoot(
                File.ReadAllText(markerPath));
            AssertTrue(Directory.Exists(stagingRoot));
            AssertTrue(File.Exists(fixture.PrivateKeyPath));
            AssertTrue(File.ReadAllBytes(fixture.PrivateKeyPath)
                .SequenceEqual(keyBytes));
            AssertNoPublisherStagingContains(keyBytes);
            AssertPrivateKeyMutationsAllowed(
                fixture.PrivateKeyPath,
                keyBytes);
        }
        finally
        {
            TryKillTestProcess(child);
            child?.Dispose();
            if (stagingRoot is not null && Directory.Exists(stagingRoot))
            {
                Directory.Delete(stagingRoot, recursive: true);
            }
            CryptographicOperations.ZeroMemory(keyBytes);
        }
    }

    private static async Task ReparseAncestorRejectedAsync()
    {
        using var fixture = PublisherFixture.Create();
        var junction = Path.Combine(TempRoot, $"publisher-link-{Guid.NewGuid():N}");
        if (!TryCreateDirectoryJunction(junction, fixture.Root))
        {
            Console.WriteLine("SKIP  junction creation unavailable");
            return;
        }
        try
        {
            var run = await fixture.RunWithPrivateKeyPathAsync(
                1,
                "linked-key",
                Path.Combine(junction, Path.GetFileName(fixture.PrivateKeyPath)))
                .ConfigureAwait(false);
            AssertEqual(1, run.ExitCode);
            AssertTrue(run.StandardError.Contains("filesystem links", StringComparison.Ordinal)
                || run.StandardError.Contains("linked", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(junction);
        }
    }

    private static async Task PluginPolicyPublishedAsync()
    {
        using var fixture = PublisherFixture.Create();
        var run = await fixture.RunWithPluginAsync(1, "plugin-release")
            .ConfigureAwait(false);
        if (run.ExitCode != 0)
        {
            throw new InvalidOperationException(run.StandardError);
        }
        var manifest = EnterpriseReleaseSetManifest.Parse(File.ReadAllBytes(Path.Combine(
            fixture.Root,
            "plugin-release",
            "release-set.v2.json")));
        AssertEqual(3, manifest.Artifacts.Count);
        AssertTrue(manifest.PluginPolicy is not null);
    }

    private static async Task InvalidPluginPolicyRejectedAsync()
    {
        using var fixture = PublisherFixture.Create();
        var candidate = await fixture.RunWithPluginAsync(
            1,
            "candidate-rejected",
            rawSkillCandidate: true).ConfigureAwait(false);
        AssertEqual(1, candidate.ExitCode);
        AssertFalse(Directory.Exists(Path.Combine(fixture.Root, "candidate-rejected")));

        var drift = await fixture.RunWithPluginAsync(
            2,
            "metadata-rejected",
            metadataDrift: true).ConfigureAwait(false);
        AssertEqual(1, drift.ExitCode);
        AssertTrue(drift.StandardError.Contains("metadata", StringComparison.OrdinalIgnoreCase));
        AssertFalse(Directory.Exists(Path.Combine(fixture.Root, "metadata-rejected")));
    }

    private static async Task MissingRuntimeAdmissionRejectedAsync()
    {
        using var fixture = PublisherFixture.Create();
        var missingMetadata = await fixture.RunAdmissionScenarioAsync(
            1,
            "missing-runtime-metadata",
            RuntimeAdmissionScenario.MissingMetadata).ConfigureAwait(false);
        AssertEqual(1, missingMetadata.ExitCode);
        AssertTrue(missingMetadata.StandardError.Contains(
            "sourceRuntimeMetadataPath",
            StringComparison.Ordinal));

        var missingReceipt = await fixture.RunAdmissionScenarioAsync(
            2,
            "missing-runtime-receipt",
            RuntimeAdmissionScenario.MissingReceipt).ConfigureAwait(false);
        AssertEqual(1, missingReceipt.ExitCode);
        AssertTrue(missingReceipt.StandardError.Contains(
            "organizationAdmissionReceiptPath",
            StringComparison.Ordinal));
    }

    private static Task TamperedRuntimeMetadataRejectedAsync() =>
        AssertAdmissionScenarioRejectedAsync(
            RuntimeAdmissionScenario.TamperedMetadata,
            "pinned official source identity");

    private static Task NonPromotableRuntimeMetadataRejectedAsync() =>
        AssertAdmissionScenarioRejectedAsync(
            RuntimeAdmissionScenario.PromotionIneligible,
            "not eligible for production promotion");

    private static Task WrongRuntimeWebAuthProtocolRejectedAsync() =>
        AssertAdmissionScenarioRejectedAsync(
            RuntimeAdmissionScenario.WrongWebAuthProtocol,
            "pinned official source identity");

    private static Task FormerRc2RuntimeMetadataRejectedAsync() =>
        AssertAdmissionScenarioRejectedAsync(
            RuntimeAdmissionScenario.FormerRc2Metadata,
            "pinned official source identity");

    private static Task WrongRuntimeAdmissionKeyRejectedAsync() =>
        AssertAdmissionScenarioRejectedAsync(
            RuntimeAdmissionScenario.WrongKey,
            "signature verification failed");

    private static Task WrongRuntimeAdmissionDigestRejectedAsync() =>
        AssertAdmissionScenarioRejectedAsync(
            RuntimeAdmissionScenario.WrongDigest,
            "exact admitted metadata");

    private static Task ArtifactFileNameMismatchRejectedAsync() =>
        AssertAdmissionScenarioRejectedAsync(
            RuntimeAdmissionScenario.ArtifactFileNameMismatch,
            "filePath basename must match URI basename");

    private static Task ForgedProductionTrustRejectedAsync() =>
        AssertAdmissionScenarioRejectedAsync(
            RuntimeAdmissionScenario.ForgedProductionConfig,
            "must not come from publisher config");

    private static Task MissingProductionTrustRejectedAsync() =>
        AssertAdmissionScenarioRejectedAsync(
            RuntimeAdmissionScenario.MissingProductionTrust,
            "missing exact EnterpriseRuntimeAdmissionKeyId");

    private static Task AdmissionKeyIndependenceAsync()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicParameters = signer.ExportParameters(includePrivateParameters: false);
        var trust = new PublisherRuntimeAdmissionTrust
        {
            KeyId = "independent-name",
            X = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(publicParameters.Q.X!),
            Y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(publicParameters.Q.Y!),
        };
        AssertThrows<InvalidDataException>(() =>
            trust.RequireIndependentFrom("release-key", publicParameters));
        return Task.CompletedTask;
    }

    private static Task PluginAdmissionKeyIndependenceAsync()
    {
        using var pluginSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var runtimeSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var brandSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaseSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var releaseSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var plugin = Trust(pluginSigner, "plugin-admission-2026-01");
        var runtime = RuntimeTrust(runtimeSigner, "runtime-admission-2026-01");
        var brand = BrandTrust(brandSigner, "brand-authorization-2026-01");
        var lease = LeaseTrust(leaseSigner, "lease-2026-01");
        plugin.RequireIndependentFrom(runtime, brand, lease, "release-2026-01");
        plugin.RequireIndependentFromReleaseKey(
            "release-2026-01",
            releaseSigner.ExportParameters(includePrivateParameters: false));

        AssertThrows<InvalidDataException>(() =>
            Trust(runtimeSigner, "plugin-other-id")
                .RequireIndependentFrom(runtime, brand, lease, "release-2026-01"));
        AssertThrows<InvalidDataException>(() =>
            Trust(brandSigner, "plugin-other-id")
                .RequireIndependentFrom(runtime, brand, lease, "release-2026-01"));
        AssertThrows<InvalidDataException>(() =>
            Trust(leaseSigner, "plugin-other-id")
                .RequireIndependentFrom(runtime, brand, lease, "release-2026-01"));
        AssertThrows<InvalidDataException>(() =>
            plugin.RequireIndependentFrom(runtime, brand, lease, plugin.KeyId));
        AssertThrows<InvalidDataException>(() =>
            Trust(releaseSigner, "plugin-other-id").RequireIndependentFromReleaseKey(
                "release-2026-01",
                releaseSigner.ExportParameters(includePrivateParameters: false)));
        return Task.CompletedTask;

        static PublisherPluginAdmissionTrust Trust(ECDsa signer, string keyId)
        {
            var value = signer.ExportParameters(includePrivateParameters: false);
            return new PublisherPluginAdmissionTrust
            {
                KeyId = keyId,
                X = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(value.Q.X!),
                Y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(value.Q.Y!),
            };
        }

        static PublisherRuntimeAdmissionTrust RuntimeTrust(ECDsa signer, string keyId)
        {
            var value = signer.ExportParameters(includePrivateParameters: false);
            return new PublisherRuntimeAdmissionTrust
            {
                KeyId = keyId,
                X = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(value.Q.X!),
                Y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(value.Q.Y!),
            };
        }

        static PublisherBrandAuthorizationTrust BrandTrust(ECDsa signer, string keyId)
        {
            var value = signer.ExportParameters(includePrivateParameters: false);
            return new PublisherBrandAuthorizationTrust
            {
                KeyId = keyId,
                X = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(value.Q.X!),
                Y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(value.Q.Y!),
            };
        }

        static PublisherLeaseVerificationTrust LeaseTrust(ECDsa signer, string keyId)
        {
            var value = signer.ExportParameters(includePrivateParameters: false);
            return new PublisherLeaseVerificationTrust
            {
                KeyId = keyId,
                X = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(value.Q.X!),
                Y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(value.Q.Y!),
            };
        }
    }

    private static Task StaleRuntimeAdmissionRejectedAsync() =>
        AssertAdmissionScenarioRejectedAsync(
            RuntimeAdmissionScenario.StaleReceipt,
            "does not bind the exact admitted metadata");

    private static async Task AssertAdmissionScenarioRejectedAsync(
        RuntimeAdmissionScenario scenario,
        string error)
    {
        using var fixture = PublisherFixture.Create();
        var run = await fixture.RunAdmissionScenarioAsync(1, scenario.ToString(), scenario)
            .ConfigureAwait(false);
        AssertEqual(1, run.ExitCode);
        AssertTrue(run.StandardError.Contains(error, StringComparison.OrdinalIgnoreCase));
        AssertFalse(Directory.Exists(Path.Combine(fixture.Root, scenario.ToString())));
    }

    private static Task InputSnapshotBoundaryAsync()
    {
        var root = Path.Combine(TempRoot, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var pluginSource = Path.Combine(root, "managed-plugin-policy.zip");
        var metadataSource = Path.Combine(root, "managed-plugin-policy.artifact.json");
        var originalPlugin = RandomNumberGenerator.GetBytes(4096);
        var originalMetadata = "{\"schemaVersion\":1}\n"u8.ToArray();
        File.WriteAllBytes(pluginSource, originalPlugin);
        File.WriteAllBytes(metadataSource, originalMetadata);

        string stagingRoot;
        using (var staging = PublisherInputStaging.Create())
        {
            stagingRoot = staging.RootPath;
            var plugin = staging.Capture(pluginSource);
            var metadata = staging.Capture(metadataSource);

            ReplacePathAtomically(
                pluginSource,
                RandomNumberGenerator.GetBytes(8192));
            ReplacePathAtomically(
                metadataSource,
                "{\"swapped\":true}\n"u8.ToArray());

            var publishedPlugin = Path.Combine(root, "published-plugin.zip");
            var publishedMetadata = Path.Combine(root, "published-metadata.json");
            plugin.CopyNewVerified(publishedPlugin);
            metadata.CopyNewVerified(publishedMetadata);
            AssertTrue(File.ReadAllBytes(publishedPlugin).SequenceEqual(originalPlugin));
            AssertTrue(File.ReadAllBytes(publishedMetadata).SequenceEqual(originalMetadata));
            AssertEqual(
                Convert.ToHexStringLower(SHA256.HashData(originalPlugin)),
                plugin.Sha256);
            AssertEqual(
                Convert.ToHexStringLower(SHA256.HashData(originalMetadata)),
                metadata.Sha256);

            var mutableSource = Path.Combine(root, "concurrently-mutable.zip");
            File.WriteAllBytes(mutableSource, RandomNumberGenerator.GetBytes(1024));
            using var writer = new FileStream(
                mutableSource,
                FileMode.Open,
                FileAccess.ReadWrite,
                FileShare.ReadWrite);
            AssertThrows<IOException>(() => staging.Capture(mutableSource));
        }
        AssertFalse(Directory.Exists(stagingRoot));

        using (var fixture = PublisherFixture.Create())
        {
            var prepared = fixture.Prepare(7, "runtime-admission-snapshot");
            var metadataBytes = File.ReadAllBytes(prepared.MetadataPath);
            var receiptBytes = File.ReadAllBytes(prepared.ReceiptPath);
            using var snapshot = PublisherInputSnapshot.Capture(
                prepared.Arguments,
                new JsonSerializerOptions(JsonSerializerDefaults.Web)
                {
                    WriteIndented = true,
                    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
                });
            ReplacePathAtomically(prepared.MetadataPath, "{\"swapped\":true}"u8);
            ReplacePathAtomically(prepared.ReceiptPath, "{\"swapped\":true}"u8);
            var runtime = snapshot.Artifacts.Single(value =>
                value.Input.Component == EnterpriseReleaseSetContract.RuntimeComponent);
            AssertTrue(runtime.SourceRuntimeMetadata is not null);
            AssertTrue(runtime.OrganizationAdmissionReceipt is not null);
            AssertTrue(runtime.SourceRuntimeMetadata!
                .ReadAllBytes(4 * 1024 * 1024)
                .SequenceEqual(metadataBytes));
            AssertTrue(runtime.OrganizationAdmissionReceipt!
                .ReadAllBytes(512 * 1024)
                .SequenceEqual(receiptBytes));
        }
        return Task.CompletedTask;
    }

    private static Task PluginPromotionAdmissionAsync()
    {
        using var fixture = PluginPromotionAdmissionFixture.Create();
        fixture.ValidatePublisherConfigStructure(includeHandoff: true);
        fixture.ValidateUntilJournalGate();
        fixture.ValidatePortableRelocationUntilJournalGate();
        fixture.ValidateIdempotentLedgerReplayUntilJournalGate();
        return Task.CompletedTask;
    }

    private static Task PluginPromotionIntentSnapshotAsync()
    {
        using var fixture = PublisherFixture.Create();
        var prepared = fixture.Prepare(8, "intent-only-snapshot");
        using var snapshot = PublisherInputSnapshot.CaptureIntent(
            prepared.Arguments.ConfigPath,
            new JsonSerializerOptions(JsonSerializerDefaults.Web)
            {
                WriteIndented = true,
                UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            });
        AssertEqual(3, snapshot.Artifacts.Count);
        AssertThrows<InvalidOperationException>(() => snapshot.ReadPrivateKeyBytes());
        AssertFalse(snapshot.Artifacts.Any(value => value.PluginPromotion?.JournalAuthorization is not null));
        return Task.CompletedTask;
    }

    private static Task PluginPromotionTamperRejectedAsync()
    {
        var cases = new (string Name, Action<JsonObject, JsonObject, JsonObject, JsonObject> Mutate)[]
        {
            ("templateOnly", (handoff, _, _, _) =>
                handoff["publisherInputTemplate"]!["templateOnly"] = false),
            ("template releaseId", (handoff, _, _, _) =>
                handoff["publisherInputTemplate"]!["releaseId"] = "forged-plugin-release"),
            ("launcher tuple", (handoff, _, _, _) =>
                handoff["compatibility"]!["launcherReleaseIds"]![0] = "launcher-production-forged"),
            ("archive digest", (handoff, _, _, _) =>
                handoff["digests"]!["archiveSha256"] = new string('0', 64)),
            ("external evidence boundary", (handoff, _, _, _) =>
                handoff["verification"]!["repositoryRoot"] = Path.GetDirectoryName(
                    handoff["harnessCompatibility"]!["path"]!.GetValue<string>())),
            ("verifier script escape", (handoff, _, _, _) =>
                handoff["verification"]!["policyTestScript"]!["path"] =
                    Path.Combine(Path.GetTempPath(), "forged-policy-test.ps1")),
            ("verification HEAD", (handoff, _, _, _) =>
                handoff["verification"]!["headCommit"] = new string('a', 40)),
            ("receipt source tag", (_, receipt, _, _) =>
                receipt["harnessSourceTag"] = "dsh-v0.1.0-rc.7"),
            ("receipt producer", (_, receipt, _, _) =>
                receipt["producer"]!["component"] =
                    "Ensou.Dsh.Launcher.EnterprisePilotReadiness"),
            ("receipt Launcher bytes", (_, receipt, _, _) =>
                receipt["launcherArtifact"]!["sha256"] = new string('9', 64)),
            ("receipt producer UUID", (_, receipt, _, _) =>
                receipt["producer"]!["testRunId"] = "not-a-uuid"),
            ("receipt observation", (_, receipt, _, _) =>
                receipt["observations"]!["workspacePreserved"] = "FAIL"),
            ("receipt freshness", (_, receipt, _, _) =>
                receipt["observedAtUtc"] = DateTimeOffset.UtcNow.AddHours(-169)
                    .ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")),
            ("reservation archive tuple", (_, _, reservation, _) =>
                reservation["digests"]!["archiveSha256"] = new string('1', 64)),
            ("reservation environment", (_, _, reservation, _) =>
                reservation["targetEnvironment"] = "development-e2e"),
            ("ledger generation monotonicity", (_, _, _, ledger) =>
                ledger["highestPromotedGeneration"] = 1),
            ("ledger v1 downgrade", (_, _, _, ledger) =>
            {
                ledger.Clear();
                ledger["schemaVersion"] = 1;
                ledger["policyId"] = "11111111-2222-4333-8444-555555555555";
                ledger["highestPromotedGeneration"] = 0;
            }),
        };
        foreach (var testCase in cases)
        {
            using var fixture = PluginPromotionAdmissionFixture.Create();
            fixture.Mutate(testCase.Mutate);
            fixture.ValidateRejectedBeforeJournal();
        }
        using (var fixture = PluginPromotionAdmissionFixture.Create())
        {
            fixture.TamperHandoffObservedGeneration();
            fixture.ValidateRejectedBeforeJournal();
        }
        using (var fixture = PluginPromotionAdmissionFixture.Create())
        {
            fixture.TamperOrganizationAdmission();
            fixture.ValidateRejectedBeforeJournal();
        }
        using (var fixture = PluginPromotionAdmissionFixture.Create())
        {
            fixture.ValidateEverySignedOrganizationAdmissionFieldRejectsTamper();
        }
        using (var fixture = PluginPromotionAdmissionFixture.Create())
        {
            fixture.SignOrganizationAdmissionWithWrongKey();
            fixture.ValidateRejectedBeforeJournal();
        }
        using (var fixture = PluginPromotionAdmissionFixture.Create())
        {
            fixture.MakeOrganizationAdmissionStaleAndResign();
            fixture.ValidateRejectedBeforeJournal();
        }
        using (var fixture = PluginPromotionAdmissionFixture.Create())
        {
            fixture.ValidateRejectedBeforeJournal("plugin-test-placeholder");
        }
        using (var fixture = PluginPromotionAdmissionFixture.Create())
        {
            fixture.ValidateRejectedBeforeJournal("exact-plugin-release-id");
        }
        using (var fixture = PluginPromotionAdmissionFixture.Create())
        {
            fixture.ValidateRejectedBeforeJournal("plugin-ci-contract-20260825");
        }
        using (var fixture = PluginPromotionAdmissionFixture.Create())
        {
            fixture.ValidateNonDerivedReservationPathRejected();
        }
        using (var fixture = PluginPromotionAdmissionFixture.Create())
        {
            fixture.ValidateOrganizationAdmissionInsideRepositoryRejected();
        }
        using (var fixture = PluginPromotionAdmissionFixture.Create())
        {
            AssertThrows<InvalidDataException>(() =>
                fixture.ValidatePublisherConfigStructure(includeHandoff: false));
        }
        return Task.CompletedTask;
    }

    private static Task PluginPromotionReparseRejectedAsync()
    {
        using var fixture = PluginPromotionAdmissionFixture.Create();
        var junction = fixture.RedirectReceiptThroughJunction();
        if (junction is null)
        {
            Console.WriteLine("SKIP  plugin evidence junction creation unavailable");
            return Task.CompletedTask;
        }
        try
        {
            fixture.ValidateRejectedBeforeJournal();
        }
        finally
        {
            Directory.Delete(junction);
        }
        return Task.CompletedTask;
    }

    private static Task ProductionTrustFingerprintAsync()
    {
        using var releaseSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaseSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var release = releaseSigner.ExportParameters(includePrivateParameters: false);
        var lease = leaseSigner.ExportParameters(includePrivateParameters: false);
        var trust = new EnterpriseProductionTrustInputs(
            "https://updates.acme-corp.com/v2/channels/pilot/release-set.v2.json",
            "https://updates.acme-corp.com/",
            "https://artifacts.acme-corp.com/",
            "release-2026-01",
            PublisherRuntimeAdmissionEncoding.EncodeBase64Url(release.Q.X!),
            PublisherRuntimeAdmissionEncoding.EncodeBase64Url(release.Q.Y!),
            "https://control.acme-corp.com/",
            "https://authorization.acme-corp.com/",
            "https://gateway.acme-corp.com/",
            "https://managed-artifacts.acme-corp.com/",
            "lease-2026-01",
            PublisherRuntimeAdmissionEncoding.EncodeBase64Url(lease.Q.X!),
            PublisherRuntimeAdmissionEncoding.EncodeBase64Url(lease.Q.Y!),
            new string('a', 64));
        var first = EnterpriseProductionTrustFingerprint.ComputeSha256(trust);
        var second = EnterpriseProductionTrustFingerprint.ComputeSha256(trust);
        AssertEqual(64, first.Length);
        AssertEqual(first, second);
        AssertThrows<InvalidDataException>(() =>
            EnterpriseProductionTrustFingerprint.ComputeSha256(
                trust with { UpdateManifestOrigin = "https://updates.example.invalid/" }));
        AssertThrows<InvalidDataException>(() =>
            EnterpriseProductionTrustFingerprint.ComputeSha256(
                trust with { UpdateManifestOrigin = "https://updates.customer.example.com/" }));
        AssertThrows<InvalidDataException>(() =>
            EnterpriseProductionTrustFingerprint.ComputeSha256(trust with
            {
                LeaseKeyId = trust.ReleaseKeyId,
                LeaseKeyX = trust.ReleaseKeyX,
                LeaseKeyY = trust.ReleaseKeyY,
            }));
        AssertThrows<InvalidDataException>(() =>
            EnterpriseProductionTrustFingerprint.ComputeSha256(trust with
            {
                LeaseKeyId = "lease-alternate-encoding",
                LeaseKeyX = MakeNonCanonicalBase64Url(trust.ReleaseKeyX),
                LeaseKeyY = MakeNonCanonicalBase64Url(trust.ReleaseKeyY),
            }));
        return Task.CompletedTask;
    }

    private static string MakeNonCanonicalBase64Url(string value)
    {
        const string alphabet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        var characters = value.ToCharArray();
        var index = alphabet.IndexOf(characters[^1]);
        if (index < 0 || (index & 3) != 0)
        {
            throw new InvalidOperationException("Fixture coordinate is not canonical base64url.");
        }
        characters[^1] = alphabet[index + 1];
        return new string(characters);
    }

    private static Task PilotReadinessFailClosedAsync()
    {
        var root = Path.Combine(TempRoot, $"pilot-preflight-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        using var releaseSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaseSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var admissionSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var release = releaseSigner.ExportParameters(includePrivateParameters: false);
        var lease = leaseSigner.ExportParameters(includePrivateParameters: false);
        var admission = admissionSigner.ExportParameters(includePrivateParameters: false);

        var unsignedConfig = Path.Combine(root, "unsigned.json");
        WritePilotReadinessConfig(
            unsignedConfig,
            root,
            "production",
            "UNSIGNED_CANDIDATE",
            "https://updates.acme-corp.com/",
            release,
            lease,
            admission);
        var unsignedReport = Path.Combine(root, "unsigned-report.json");
        AssertEqual(1, EnterprisePilotReadinessCommand.Run(
            ["--pilot-readiness-config", unsignedConfig, "--report", unsignedReport]));
        using (var document = JsonDocument.Parse(File.ReadAllBytes(unsignedReport)))
        {
            AssertEqual("REJECT", document.RootElement.GetProperty("decision").GetString());
            AssertEqual("config-contract", document.RootElement.GetProperty("failureCode").GetString());
            AssertTrue(document.RootElement.GetProperty("publisherExecutableSha256")
                .GetString() is { Length: 64 });
        }
        var reportText = File.ReadAllText(unsignedReport);
        AssertFalse(reportText.Contains("UNSIGNED_CANDIDATE", StringComparison.Ordinal));
        AssertFalse(reportText.Contains(unsignedConfig, StringComparison.OrdinalIgnoreCase));

        var originalOutput = Console.Out;
        using var capturedOutput = new StringWriter();
        int stdoutExitCode;
        try
        {
            Console.SetOut(capturedOutput);
            stdoutExitCode = EnterprisePilotReadinessCommand.Run(
                ["--pilot-readiness-config", unsignedConfig, "--report-stdout"]);
        }
        finally
        {
            Console.SetOut(originalOutput);
        }
        AssertEqual(1, stdoutExitCode);
        using (var document = JsonDocument.Parse(capturedOutput.ToString()))
        {
            AssertEqual("REJECT", document.RootElement.GetProperty("decision").GetString());
            AssertEqual("config-contract", document.RootElement.GetProperty("failureCode").GetString());
        }

        var developmentConfig = Path.Combine(root, "development.json");
        WritePilotReadinessConfig(
            developmentConfig,
            root,
            "development-e2e",
            "SIGNED_RELEASE_SET",
            "https://updates.acme-corp.com/",
            release,
            lease,
            admission);
        var developmentReport = Path.Combine(root, "development-report.json");
        AssertEqual(1, EnterprisePilotReadinessCommand.Run(
            ["--pilot-readiness-config", developmentConfig, "--report", developmentReport]));

        var placeholderConfig = Path.Combine(root, "placeholder.json");
        WritePilotReadinessConfig(
            placeholderConfig,
            root,
            "production",
            "SIGNED_RELEASE_SET",
            "https://updates.example.invalid/",
            release,
            lease,
            admission);
        var placeholderReport = Path.Combine(root, "placeholder-report.json");
        AssertEqual(1, EnterprisePilotReadinessCommand.Run(
            ["--pilot-readiness-config", placeholderConfig, "--report", placeholderReport]));
        using (var document = JsonDocument.Parse(File.ReadAllBytes(placeholderReport)))
        {
            AssertEqual("REJECT", document.RootElement.GetProperty("decision").GetString());
            AssertEqual("config-contract", document.RootElement.GetProperty("failureCode").GetString());
        }

        var immutableReport = Path.Combine(root, "immutable-report.json");
        File.WriteAllText(immutableReport, "audit-sentinel", new UTF8Encoding(false));
        AssertEqual(2, EnterprisePilotReadinessCommand.Run(
            ["--pilot-readiness-config", placeholderConfig, "--report", immutableReport]));
        AssertEqual("audit-sentinel", File.ReadAllText(immutableReport));
        return Task.CompletedTask;
    }

    private static void WritePilotReadinessConfig(
        string path,
        string root,
        string environment,
        string artifactAuthorization,
        string manifestOrigin,
        ECParameters release,
        ECParameters lease,
        ECParameters admission)
    {
        var document = new
        {
            schemaVersion = 1,
            environment,
            channel = "pilot",
            runtimeIdentifier = "win-x64",
            layoutProfile = "enterprise",
            artifactAuthorization,
            releaseSetId = "enterprise-2026.08.25.1",
            generation = 1,
            sequence = 1,
            minAcceptedSequence = 0,
            releaseDirectory = Path.Combine(root, "release"),
            publisherLedgerPath = Path.Combine(root, "publisher-ledger.v2.json"),
            publisherLedgerSha256 = new string('b', 64),
            installerExecutablePath = Path.Combine(root, "Ensou.Dsh.Enterprise.Installer.exe"),
            bootstrapperExecutablePath = Path.Combine(root, "Ensou.Dsh.Enterprise.Bootstrapper.exe"),
            launcherExecutablePath = Path.Combine(root, "Ensou.Dsh.Enterprise.Launcher.exe"),
            clientBootstrapperExecutablePath = Path.Combine(
                root,
                "Ensou.Dsh.Enterprise.ClientBootstrapper.exe"),
            maintenanceExecutablePath = Path.Combine(
                root,
                "Ensou.Dsh.Enterprise.Maintenance.exe"),
            runtimeSourceMetadataPath = Path.Combine(root, "runtime.metadata.json"),
            runtimeAdmissionReceiptPath = Path.Combine(root, "runtime.admission.json"),
            pluginPolicyMetadataPath = Path.Combine(root, "plugin.metadata.json"),
            launcherTrust = new
            {
                updateManifestUri = new Uri(new Uri(manifestOrigin), "v2/channels/pilot/release-set.v2.json").AbsoluteUri,
                updateManifestOrigin = manifestOrigin,
                updateArtifactOrigin = "https://artifacts.acme-corp.com/",
                releaseKeyId = "release-2026-01",
                releaseKeyX = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(release.Q.X!),
                releaseKeyY = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(release.Q.Y!),
                controlPlaneOrigin = "https://control.acme-corp.com/",
                authorizationOrigin = "https://authorization.acme-corp.com/",
                gatewayOrigin = "https://gateway.acme-corp.com/",
                managedArtifactOrigin = "https://managed-artifacts.acme-corp.com/",
                leaseKeyId = "lease-2026-01",
                leaseKeyX = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(lease.Q.X!),
                leaseKeyY = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(lease.Q.Y!),
                authenticodeSignerSha256Thumbprint = new string('a', 64),
            },
            runtimeAdmissionKey = new
            {
                keyId = "runtime-admission-2026-01",
                x = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(admission.Q.X!),
                y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(admission.Q.Y!),
            },
            startupUpdateContract = new
            {
                checkOnEveryStartup = true,
                atomicReleaseSetActivation = true,
                bootstrapHealthRollback = true,
                maximumOfflineGraceHours = 168,
            },
            localDataCompatibilityEvidence = new
            {
                fromUpstreamTag = "dsh-v-old",
                toUpstreamTag = "dsh-v-new",
                sourceRuntimeArchiveSha256 = new string('b', 64),
                targetRuntimeArchiveSha256 = new string('d', 64),
                reportPath = Path.Combine(root, "local-data-compatibility-evidence.json"),
                reportSha256 = new string('c', 64),
                certification = new
                {
                    receiptPath = Path.Combine(root, "local-data-certification.v1.json"),
                    receiptSha256 = new string('e', 64),
                    certificationAudienceId = "22222222-2222-4222-8222-222222222222",
                },
            },
        };
        File.WriteAllText(
            path,
            JsonSerializer.Serialize(
                document,
                new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true }),
            new UTF8Encoding(false));
    }

    private static Task LocalDataCompatibilityEvidenceAsync()
    {
        var root = Path.Combine(TempRoot, $"local-data-evidence-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "local-data-compatibility-evidence.json");
        var sourceRuntimeSha256 = new string('a', 64);
        var targetRuntimeSha256 = new string('b', 64);

        WriteLocalDataCompatibilityEvidence(
            path,
            sourceRuntimeSha256,
            targetRuntimeSha256,
            rollbackUsedPreUpgradeBackup: true,
            allApiLanesCovered: true);
        var input = new PilotLocalDataCompatibilityEvidenceInput
        {
            FromUpstreamTag = "dsh-v-source",
            ToUpstreamTag = "dsh-v-target",
            SourceRuntimeArchiveSha256 = sourceRuntimeSha256,
            TargetRuntimeArchiveSha256 = targetRuntimeSha256,
            ReportPath = path,
            ReportSha256 = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))),
            Certification = new PilotLocalDataCompatibilityCertificationInput
            {
                ReceiptPath = Path.Combine(root, "unused-certification.json"),
                ReceiptSha256 = new string('c', 64),
                CertificationAudienceId = "22222222-2222-4222-8222-222222222222",
            },
        };
        var evidence = EnterprisePilotReadinessValidator.ValidateLocalDataCompatibilityEvidence(
            input,
            "dsh-v-target",
            targetRuntimeSha256);
        AssertTrue(evidence.Evidence.StartsWith(
            "dsh-v-source->dsh-v-target:",
            StringComparison.Ordinal));

        WriteLocalDataCompatibilityEvidence(
            path,
            sourceRuntimeSha256,
            targetRuntimeSha256,
            rollbackUsedPreUpgradeBackup: false,
            allApiLanesCovered: true);
        var unsafeInput = input with
        {
            ReportSha256 = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))),
        };
        AssertThrows<InvalidDataException>(() =>
            EnterprisePilotReadinessValidator.ValidateLocalDataCompatibilityEvidence(
                unsafeInput,
                "dsh-v-target",
                targetRuntimeSha256));

        WriteLocalDataCompatibilityEvidence(
            path,
            sourceRuntimeSha256,
            targetRuntimeSha256,
            rollbackUsedPreUpgradeBackup: true,
            allApiLanesCovered: false);
        var deferredInput = input with
        {
            ReportSha256 = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))),
        };
        AssertThrows<InvalidDataException>(() =>
            EnterprisePilotReadinessValidator.ValidateLocalDataCompatibilityEvidence(
                deferredInput,
                "dsh-v-target",
                targetRuntimeSha256));
        AssertThrows<InvalidDataException>(() =>
            EnterprisePilotReadinessValidator.ValidateLocalDataCompatibilityEvidence(
                deferredInput with { TargetRuntimeArchiveSha256 = new string('c', 64) },
                "dsh-v-target",
                targetRuntimeSha256));

        void AssertApiContractTamperRejected(Action<JsonObject> mutate)
        {
            WriteLocalDataCompatibilityEvidence(
                path,
                sourceRuntimeSha256,
                targetRuntimeSha256,
                rollbackUsedPreUpgradeBackup: true,
                allApiLanesCovered: true);
            var lanePath = Path.Combine(root, "results", "api-target-forward.json");
            var lane = JsonNode.Parse(File.ReadAllBytes(lanePath))!.AsObject();
            mutate(lane);
            var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web)
            {
                WriteIndented = true,
            };
            File.WriteAllText(
                lanePath,
                lane.ToJsonString(jsonOptions),
                new UTF8Encoding(false));
            var laneSha256 = Convert.ToHexStringLower(
                SHA256.HashData(File.ReadAllBytes(lanePath)));
            var laneBytes = new FileInfo(lanePath).Length;
            var relativeLanePath = Path.GetRelativePath(root, lanePath).Replace('\\', '/');
            var report = JsonNode.Parse(File.ReadAllBytes(path))!.AsObject();

            static void ReplaceEvidenceIdentity(
                JsonObject reference,
                long bytes,
                string sha256)
            {
                reference["bytes"] = bytes;
                reference["sha256"] = sha256;
            }

            ReplaceEvidenceIdentity(
                report["apiLanes"]!["targetForward"]!.AsObject(),
                laneBytes,
                laneSha256);
            var inventoryMatch = report["artifacts"]!.AsArray()
                .Select(item => item!.AsObject())
                .Single(item => string.Equals(
                    item["path"]!.GetValue<string>(),
                    relativeLanePath,
                    StringComparison.Ordinal));
            ReplaceEvidenceIdentity(inventoryMatch, laneBytes, laneSha256);
            File.WriteAllText(
                path,
                report.ToJsonString(jsonOptions),
                new UTF8Encoding(false));
            var tamperedInput = input with
            {
                ReportSha256 = Convert.ToHexStringLower(
                    SHA256.HashData(File.ReadAllBytes(path))),
            };
            AssertThrows<InvalidDataException>(() =>
                EnterprisePilotReadinessValidator.ValidateLocalDataCompatibilityEvidence(
                    tamperedInput,
                    "dsh-v-target",
                    targetRuntimeSha256));
        }

        foreach (var mutate in new Action<JsonObject>[]
                 {
                     lane => lane["sessionQuerySemanticParity"]!["errorCode"] = "other",
                     lane => lane["sessionQuerySemanticParity"]!["diagnosticClass"] = "other",
                     lane => lane["attachment"]!["requestImageNormalization"]!
                         ["publicPolicyRefusal"]!["stage"] = "other",
                     lane => lane["attachment"]!["requestImageNormalization"]!
                         ["publicPolicyRefusal"]!["code"] = "other",
                     lane => lane["attachment"]!["requestImageNormalization"]!
                         ["publicPolicyRefusal"]!["diagnosticClass"] = "other",
                     lane => lane["attachment"]!["requestImageNormalization"]!
                         ["publicPolicyRefusal"]!["provider"] = "other",
                     lane => lane["attachment"]!["requestImageNormalization"]!
                         ["publicPolicyRefusal"]!["model"] = "other",
                 })
        {
            AssertApiContractTamperRejected(mutate);
        }

        WriteLocalDataCompatibilityEvidence(
            path,
            sourceRuntimeSha256,
            targetRuntimeSha256,
            rollbackUsedPreUpgradeBackup: true,
            allApiLanesCovered: true);
        var traversal = JsonNode.Parse(File.ReadAllBytes(path))!.AsObject();
        traversal["testRunner"]!["path"] = "../outside-runner.ps1";
        File.WriteAllText(
            path,
            traversal.ToJsonString(new JsonSerializerOptions(JsonSerializerDefaults.Web)
            {
                WriteIndented = true,
            }),
            new UTF8Encoding(false));
        var traversalInput = input with
        {
            ReportSha256 = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))),
        };
        AssertThrows<InvalidDataException>(() =>
            EnterprisePilotReadinessValidator.ValidateLocalDataCompatibilityEvidence(
                traversalInput,
                "dsh-v-target",
                targetRuntimeSha256));
        return Task.CompletedTask;
    }

    private static Task PilotPublisherReplacementWindowClosedAsync()
    {
        var root = Path.Combine(TempRoot, $"publisher-lock-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var publisherPath = Path.Combine(root, "ReleasePublisher.exe");
        var replacementPath = Path.Combine(root, "replacement.exe");
        File.WriteAllBytes(publisherPath, RandomNumberGenerator.GetBytes(1024));
        File.WriteAllBytes(replacementPath, RandomNumberGenerator.GetBytes(1024));
        static void AssertReplacementDenied(Action action)
        {
            try
            {
                action();
            }
            catch (Exception exception) when (exception is IOException
                or UnauthorizedAccessException)
            {
                return;
            }
            throw new InvalidOperationException(
                "Locked Publisher executable unexpectedly allowed replacement.");
        }
        using (var locked = new FileStream(
                   publisherPath,
                   FileMode.Open,
                   FileAccess.Read,
                   FileShare.Read))
        {
            AssertReplacementDenied(() =>
                File.WriteAllBytes(publisherPath, RandomNumberGenerator.GetBytes(1024)));
            AssertReplacementDenied(() =>
                File.Move(replacementPath, publisherPath, overwrite: true));
        }

        var repository = new DirectoryInfo(AppContext.BaseDirectory);
        while (repository is not null
            && !File.Exists(Path.Combine(repository.FullName, "Ensou.Dsh.slnx")))
        {
            repository = repository.Parent;
        }
        if (repository is null)
        {
            throw new InvalidOperationException("Repository root was not found for wrapper test.");
        }
        var wrapper = File.ReadAllText(Path.Combine(
            repository.FullName,
            "scripts",
            "Test-EnterprisePilotReadiness.ps1"));
        var openIndex = wrapper.IndexOf(
            "$publisherLock = [IO.FileStream]::new",
            StringComparison.Ordinal);
        var denyWriteIndex = wrapper.IndexOf(
            "[IO.FileShare]::Read",
            openIndex,
            StringComparison.Ordinal);
        var signatureIndex = wrapper.IndexOf(
            "Get-AuthenticodeSignature",
            denyWriteIndex,
            StringComparison.Ordinal);
        var timestampIndex = wrapper.IndexOf(
            "$signature.TimeStamperCertificate",
            signatureIndex,
            StringComparison.Ordinal);
        var embeddedSignatureIndex = wrapper.IndexOf(
            "$signature.SignatureType",
            signatureIndex,
            StringComparison.Ordinal);
        var launchIndex = wrapper.IndexOf(
            "[Diagnostics.Process]::Start",
            timestampIndex,
            StringComparison.Ordinal);
        var disposeIndex = wrapper.LastIndexOf(
            "$publisherLock.Dispose()",
            StringComparison.Ordinal);
        AssertTrue(openIndex >= 0
            && denyWriteIndex > openIndex
            && signatureIndex > denyWriteIndex
            && embeddedSignatureIndex > signatureIndex
            && timestampIndex > embeddedSignatureIndex
            && launchIndex > timestampIndex
            && disposeIndex > launchIndex);
        AssertTrue(!wrapper.Contains(
            "Get-FileHash -LiteralPath $publisher",
            StringComparison.Ordinal));
        return Task.CompletedTask;
    }

    private static async Task PublishedArtifactAuthenticodeFailClosedAsync()
    {
        var repository = new DirectoryInfo(AppContext.BaseDirectory);
        while (repository is not null
            && !File.Exists(Path.Combine(repository.FullName, "Ensou.Dsh.slnx")))
        {
            repository = repository.Parent;
        }
        if (repository is null)
        {
            throw new InvalidOperationException(
                "Repository root was not found for published-artifact Authenticode test.");
        }

        var harnessPath = Path.Combine(
            TempRoot,
            $"published-authenticode-{Guid.NewGuid():N}.ps1");
        File.WriteAllText(
            harnessPath,
            """
            param(
                [Parameter(Mandatory = $true)][string]$GatePath,
                [Parameter(Mandatory = $true)][ValidateSet('catalog', 'no-timestamp')][string]$Scenario
            )
            $ErrorActionPreference = 'Stop'
            Set-StrictMode -Version Latest
            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile(
                $GatePath,
                [ref]$tokens,
                [ref]$errors)
            if ($errors.Count -ne 0) {
                throw 'Published-artifact gate did not parse.'
            }
            $functionAst = $ast.Find({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -ceq 'Assert-Authenticode'
            }, $true)
            if ($null -eq $functionAst) {
                throw 'Assert-Authenticode was not found.'
            }
            . ([scriptblock]::Create($functionAst.Extent.Text))

            $rsa = [Security.Cryptography.RSA]::Create(2048)
            $script:fixtureCertificate = $null
            try {
                $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                    'CN=Ensou published-artifact negative fixture',
                    $rsa,
                    [Security.Cryptography.HashAlgorithmName]::SHA256,
                    [Security.Cryptography.RSASignaturePadding]::Pkcs1)
                $script:fixtureCertificate = $request.CreateSelfSigned(
                    [DateTimeOffset]::UtcNow.AddMinutes(-1),
                    [DateTimeOffset]::UtcNow.AddMinutes(10))
                $script:RequireAuthenticode = $true
                $script:SignerSha256Thumbprint =
                    $script:fixtureCertificate.GetCertHashString(
                        [Security.Cryptography.HashAlgorithmName]::SHA256)
                $script:fixtureSignatureType = if ($Scenario -ceq 'catalog') {
                    'Catalog'
                } else {
                    'Authenticode'
                }
                $script:fixtureTimestamp = if ($Scenario -ceq 'catalog') {
                    $script:fixtureCertificate
                } else {
                    $null
                }
                function Get-AuthenticodeSignature {
                    param([Parameter(Mandatory = $true)][string]$LiteralPath)
                    [pscustomobject]@{
                        Status = [Management.Automation.SignatureStatus]::Valid
                        SignerCertificate = $script:fixtureCertificate
                        SignatureType = $script:fixtureSignatureType
                        TimeStamperCertificate = $script:fixtureTimestamp
                    }
                }

                $expected = if ($Scenario -ceq 'catalog') {
                    'embedded Authenticode signature'
                } else {
                    'no trusted Authenticode timestamp'
                }
                $rejected = $false
                try {
                    Assert-Authenticode -Executable 'fixture.exe'
                } catch {
                    if (-not $_.Exception.Message.Contains(
                            $expected,
                            [StringComparison]::Ordinal)) {
                        throw
                    }
                    $rejected = $true
                }
                if (-not $rejected) {
                    throw "Published-artifact gate admitted $Scenario signature fixture."
                }
                "PUBLISHED-AUTHENTICODE-$($Scenario.ToUpperInvariant())-REJECT-PASS"
            } finally {
                if ($null -ne $script:fixtureCertificate) {
                    $script:fixtureCertificate.Dispose()
                }
                $rsa.Dispose()
            }
            """,
            new UTF8Encoding(false));

        var gatePath = Path.Combine(
            repository.FullName,
            "scripts",
            "Test-EnterprisePublishedArtifacts.ps1");
        foreach (var scenario in new[] { "catalog", "no-timestamp" })
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "pwsh",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                },
            };
            foreach (var argument in new[]
                     {
                         "-NoLogo",
                         "-NoProfile",
                         "-File",
                         harnessPath,
                         "-GatePath",
                         gatePath,
                         "-Scenario",
                         scenario,
                     })
            {
                process.StartInfo.ArgumentList.Add(argument);
            }
            AssertTrue(process.Start());
            var standardOutput = process.StandardOutput.ReadToEndAsync();
            var standardError = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync().ConfigureAwait(false);
            var output = await standardOutput.ConfigureAwait(false);
            var error = await standardError.ConfigureAwait(false);
            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(
                    $"Published-artifact {scenario} Authenticode fixture failed: {error}");
            }
            AssertTrue(output.Contains(
                $"PUBLISHED-AUTHENTICODE-{scenario.ToUpperInvariant()}-REJECT-PASS",
                StringComparison.Ordinal));
        }
    }

    private static Task RealLocalDataEvidenceReplayAsync()
    {
        var repository = new DirectoryInfo(AppContext.BaseDirectory);
        while (repository is not null
            && !File.Exists(Path.Combine(repository.FullName, "Ensou.Dsh.slnx")))
        {
            repository = repository.Parent;
        }
        if (repository is null)
        {
            throw new InvalidOperationException(
                "Repository root was not found for local-data replay.");
        }
        var evidencePath = Path.Combine(
            repository.FullName,
            "out",
            "local-data-compatibility",
            "rc7-to-rc2-text-only-v1-20260825-01",
            "local-data-compatibility-evidence.json");
        if (!File.Exists(evidencePath))
        {
            return Task.CompletedTask;
        }
        using var document = JsonDocument.Parse(File.ReadAllBytes(evidencePath));
        var root = document.RootElement;
        var input = new PilotLocalDataCompatibilityEvidenceInput
        {
            FromUpstreamTag = root.GetProperty("fromUpstreamTag").GetString()!,
            ToUpstreamTag = root.GetProperty("toUpstreamTag").GetString()!,
            SourceRuntimeArchiveSha256 = root.GetProperty(
                "sourceRuntimeArchiveSha256").GetString()!,
            TargetRuntimeArchiveSha256 = root.GetProperty(
                "targetRuntimeArchiveSha256").GetString()!,
            ReportPath = evidencePath,
            ReportSha256 = Convert.ToHexStringLower(
                SHA256.HashData(File.ReadAllBytes(evidencePath))),
            Certification = new PilotLocalDataCompatibilityCertificationInput
            {
                ReceiptPath = Path.Combine(Path.GetDirectoryName(evidencePath)!, "not-used.json"),
                ReceiptSha256 = new string('0', 64),
                CertificationAudienceId = "22222222-2222-4222-8222-222222222222",
            },
        };
        var result = EnterprisePilotReadinessValidator.ValidateLocalDataCompatibilityEvidence(
            input,
            input.ToUpstreamTag,
            input.TargetRuntimeArchiveSha256);
        AssertEqual(
            root.GetProperty("testRunner").GetProperty("sha256").GetString(),
            result.RunnerSha256);
        AssertEqual(input.ReportSha256, result.ReportSha256);

        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = signer.ExportParameters(includePrivateParameters: false);
        var trust = new PublisherLocalDataCompatibilityCertificationTrust
        {
            KeyId = "real-evidence-replay-certification-key",
            X = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(publicKey.Q.X!),
            Y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(publicKey.Q.Y!),
        };
        var now = DateTimeOffset.UtcNow;
        var receipt = new PublisherLocalDataCompatibilityCertificationReceipt
        {
            SchemaVersion =
                PublisherLocalDataCompatibilityCertificationReceipt.CurrentSchemaVersion,
            ReceiptType =
                PublisherLocalDataCompatibilityCertificationReceipt.CurrentReceiptType,
            CertificationId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            Decision = PublisherLocalDataCompatibilityCertificationReceipt.PassedDecision,
            Environment =
                PublisherLocalDataCompatibilityCertificationReceipt.ProductionEnvironment,
            Channel = PublisherLocalDataCompatibilityCertificationReceipt.PilotChannel,
            DistributionScope =
                PublisherLocalDataCompatibilityCertificationReceipt.NamedCustomerPilotScope,
            CertificationAudienceId = input.Certification.CertificationAudienceId,
            FromUpstreamTag = input.FromUpstreamTag,
            ToUpstreamTag = input.ToUpstreamTag,
            SourceRuntimeZipSha256 = input.SourceRuntimeArchiveSha256,
            TargetRuntimeZipSha256 = input.TargetRuntimeArchiveSha256,
            EvidenceReportSha256 = result.ReportSha256,
            RunnerSha256 = result.RunnerSha256,
            IssuedAtUnixSeconds = now.AddMinutes(-1).ToUnixTimeSeconds(),
            ExpiresAtUnixSeconds = now.AddHours(24).ToUnixTimeSeconds(),
            Signature = new EnterpriseReleaseSignature
            {
                Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
                KeyId = trust.KeyId,
                Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(new byte[64]),
            },
        };
        receipt = receipt with
        {
            Signature = receipt.Signature with
            {
                Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(
                    signer.SignData(
                        PublisherLocalDataCompatibilityCertificationCanonicalJson.Payload(receipt),
                        HashAlgorithmName.SHA256,
                        DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
            },
        };
        var receiptBytes = JsonSerializer.SerializeToUtf8Bytes(
            receipt,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var certification = PublisherLocalDataCompatibilityCertificationValidator.Validate(
            receiptBytes,
            new PublisherLocalDataCompatibilityCertificationExpectation(
                input.Certification.CertificationAudienceId,
                input.FromUpstreamTag,
                input.ToUpstreamTag,
                input.SourceRuntimeArchiveSha256,
                input.TargetRuntimeArchiveSha256,
                result.ReportSha256,
                result.RunnerSha256),
            trust,
            now);
        AssertEqual(receipt.CertificationId, certification.CertificationId);
        return Task.CompletedTask;
    }

    private static Task PilotReadinessAdmitAsync()
    {
        using var fixture = PublisherFixture.Create();
        fixture.AssertCompletePilotReadinessAdmits();
        return Task.CompletedTask;
    }

    private static Task PilotReadinessCertificationFailClosedAsync()
    {
        foreach (var scenario in new[]
                 {
                     PilotLocalDataCertificationScenario.Missing,
                     PilotLocalDataCertificationScenario.Tampered,
                     PilotLocalDataCertificationScenario.WrongAudience,
                     PilotLocalDataCertificationScenario.WrongRunnerSha256,
                 })
        {
            using var fixture = PublisherFixture.Create();
            fixture.AssertPilotReadinessCertificationRejected(scenario);
        }
        return Task.CompletedTask;
    }

    private static Task PilotReadinessClientBindingFailClosedAsync()
    {
        foreach (var scenario in new[]
                 {
                     PilotClientBindingScenario.MismatchedClientBootstrapper,
                     PilotClientBindingScenario.MismatchedMaintenance,
                     PilotClientBindingScenario.MismatchedBuildProfileMarker,
                 })
        {
            using var fixture = PublisherFixture.Create();
            fixture.AssertPilotReadinessClientBindingRejected(scenario);
        }
        return Task.CompletedTask;
    }

    private static void WriteLocalDataCompatibilityEvidence(
        string path,
        string sourceRuntimeArchiveSha256,
        string targetRuntimeArchiveSha256,
        bool rollbackUsedPreUpgradeBackup,
        bool allApiLanesCovered,
        string fromUpstreamTag = "dsh-v-source",
        string toUpstreamTag = "dsh-v-target")
    {
        var root = Path.GetDirectoryName(path)!;
        var artifactsRoot = Path.Combine(root, "artifacts");
        var resultsRoot = Path.Combine(root, "results");
        Directory.CreateDirectory(artifactsRoot);
        Directory.CreateDirectory(resultsRoot);
        var runnerPath = Path.Combine(artifactsRoot, "local-data-runner.ps1");
        var transcriptPath = Path.Combine(root, "runner-transcript.jsonl");
        var fixturePath = Path.Combine(artifactsRoot, "historical-home.zip");
        var backupPath = Path.Combine(artifactsRoot, "pre-upgrade-home.zip");
        var forwardPath = Path.Combine(resultsRoot, "forward-result.json");
        var rollbackPath = Path.Combine(resultsRoot, "rollback-result.json");
        var sourceSeedPath = Path.Combine(resultsRoot, "api-source-seed.json");
        var targetForwardPath = Path.Combine(resultsRoot, "api-target-forward.json");
        var sourceRestoredPath = Path.Combine(resultsRoot, "api-source-restored.json");
        File.WriteAllText(runnerPath, "exact-local-data-test-runner", new UTF8Encoding(false));
        File.WriteAllText(
            transcriptPath,
            "{\"event\":\"local-data-compatibility-tested\"}\n",
            new UTF8Encoding(false));
        File.WriteAllText(
            fixturePath,
            "historical-jsonl-json-attachments-workspace-and-credentials",
            new UTF8Encoding(false));
        File.WriteAllText(
            backupPath,
            "exact-whole-home-pre-upgrade-backup",
            new UTF8Encoding(false));

        var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            WriteIndented = true,
        };
        static string FileSha256(string filePath) =>
            Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(filePath)));
        var recordedAtUtc = DateTimeOffset.UtcNow;
        var credentialsBefore = new string('c', 64);
        var credentialsAfter = new string('d', 64);
        var treeBefore = new string('e', 64);
        var workspaceTreeBefore = new string('f', 64);
        var attachmentSha256 = new string('1', 64);
        var queryMessageSha256 = new string('2', 64);
        var authoritativeFiles = new[]
        {
            "sessions/workspace/session/session.jsonl.zstd",
            "storages/workspace.json",
            "attachments/v1/objects/aa/aabbcc",
            "workspaces/compat-workspace/README.txt",
        };
        var normalizationCoverage =
            "not-applicable-managed-text-only-policy-public-refusal-proven";

        void WriteApiLane(
            string resultPath,
            string phase,
            string runtimeArchiveSha256)
        {
            var lane = new Dictionary<string, object?>
            {
                ["schemaVersion"] = 1,
                ["resultType"] = "ensou-dsh-cross-runtime-api-lane-result",
                ["phase"] = phase,
                ["decision"] = "PASS",
                ["runtimeArchiveSha256"] = runtimeArchiveSha256,
                ["runtimeBootPassed"] = true,
                ["priorStateExpectationPassed"] = true,
                ["sessionCreate"] = new
                {
                    passed = true,
                    sessionId = "compat-session",
                    agentPreset = "enterprise",
                },
                ["sessionApiResumeAppend"] = new
                {
                    passed = true,
                    priorStateExpectationPassed = true,
                    eventCountBefore = phase == "source-seed" ? 0 : 2,
                    eventCountAfter = phase == "source-seed" ? 2 : 4,
                    priorMarkersPreserved = phase == "source-seed"
                        ? Array.Empty<string>()
                        : new[] { "source-seed-prompt", "source-seed-response" },
                    appendedPromptMarker = $"{phase}-prompt",
                    appendedProviderMarker = $"{phase}-response",
                },
                ["conversationProviderRoundTrip"] = new
                {
                    passed = true,
                    promptMarker = $"{phase}-prompt",
                    responseMarker = $"{phase}-response",
                },
                ["sessionQuerySemanticParity"] = new
                {
                    passed = true,
                    queryAttempted = true,
                    mode = "managed-disabled-public-api-policy",
                    errorCode = "internal",
                    diagnosticClass = "session-query-open-at-never",
                    messageSha256 = queryMessageSha256,
                    sessionId = "compat-session",
                },
                ["attachment"] = new
                {
                    publicApiRoundTripPassed = true,
                    attachmentId = $"sha256:{attachmentSha256}",
                    returnedBytes = 68,
                    returnedSha256 = attachmentSha256,
                    metadata = new
                    {
                        attachmentId = $"sha256:{attachmentSha256}",
                        mediaType = "image/png",
                        bytes = 68,
                        width = 1,
                        height = 1,
                        name = "compat-fixture.png",
                    },
                    requestImageNormalization = new
                    {
                        status = "not-applicable-managed-text-only-policy",
                        publicPolicyRefusal = new
                        {
                            stage = phase == "target-forward"
                                ? "image-prompt"
                                : "select-model",
                            code = phase == "target-forward"
                                ? "attachment-error"
                                : "model-unavailable",
                            diagnosticClass = phase == "target-forward"
                                ? "managed-text-only-image-prompt-refusal"
                                : "managed-text-only-model-selection-refusal",
                            messageSha256 = queryMessageSha256,
                            provider = "deepseek-official",
                            model = "deepseek-v4-flash-vision-exp",
                        },
                        requestImageFiles = Array.Empty<string>(),
                    },
                },
                ["provider"] = new
                {
                    loopbackOnly = true,
                    requestCount = 1,
                    chatCompletionCount = 1,
                    fileRequestCount = 0,
                    requests = new[]
                    {
                        new
                        {
                            method = "POST",
                            path = "/v1/chat/completions",
                            kind = "chat-completions",
                            model = "deepseek-v4-flash",
                            stream = true,
                            responseMarker = $"{phase}-response",
                            requestSha256 = new string('8', 64),
                            imageProjectionCount = 0,
                            imageProjections = Array.Empty<string>(),
                        },
                    },
                },
                ["recordedAtUtc"] = recordedAtUtc,
            };
            if (phase == "target-forward")
            {
                lane["sourceMarkersPreserved"] = true;
            }
            if (phase == "source-restored")
            {
                lane["targetOnlyMarkerAbsentAfterRestore"] = true;
            }
            File.WriteAllText(
                resultPath,
                JsonSerializer.Serialize(lane, jsonOptions),
                new UTF8Encoding(false));
        }

        WriteApiLane(sourceSeedPath, "source-seed", sourceRuntimeArchiveSha256);
        WriteApiLane(targetForwardPath, "target-forward", targetRuntimeArchiveSha256);
        WriteApiLane(sourceRestoredPath, "source-restored", sourceRuntimeArchiveSha256);

        File.WriteAllText(
            forwardPath,
            JsonSerializer.Serialize(
                new
                {
                    schemaVersion = 1,
                    resultType = "ensou-dsh-local-data-forward-result",
                    fromUpstreamTag,
                    toUpstreamTag,
                    decision = "PASS",
                    sourceRuntimeArchiveSha256,
                    targetRuntimeArchiveSha256,
                    targetRuntimeBootPassed = true,
                    credentialsMigrationObserved = true,
                    credentialsLayoutBefore = "pre-release-flat",
                    credentialsLayoutAfter = "version-1-refs",
                    credentialsSha256Before = credentialsBefore,
                    credentialsSha256After = credentialsAfter,
                    authoritativeFilesPreserved = authoritativeFiles,
                    workspaceTreePreserved = true,
                    queryPersistence = new
                    {
                        classification = "memory-only-derived",
                        sqliteArtifactsBefore = Array.Empty<string>(),
                        sqliteArtifactsAfter = Array.Empty<string>(),
                    },
                    treeChanges = new[]
                    {
                        new { path = ".credentials.yaml", change = "content-changed" },
                    },
                    apiLanes = new
                    {
                        sourceSeedDecision = "PASS",
                        targetForwardDecision = "PASS",
                        fullSessionApiRoundTripPassed = true,
                        conversationProviderRoundTripPassed = true,
                        attachmentPublicApiRoundTripPassed = true,
                        sessionQuerySemanticParityPassed = true,
                        requestImageNormalization = normalizationCoverage,
                    },
                    recordedAtUtc,
                    coveredLanes = new[]
                    {
                        "exact-runtime-archive-and-internal-manifest-verification",
                        "rc7-flat-credentials-to-version-1-boot-migration",
                        "header-only-zstd-session-artifact-preservation",
                        "workspace-v2-json-storage-preservation",
                        "content-addressed-attachment-object-preservation",
                        "workspace-file-tree-preservation",
                        "zstd-session-v0-public-api-resume-append",
                        "loopback-fake-provider-conversation-roundtrip",
                        "attachment-public-api-byte-roundtrip",
                        "session-query-public-api-managed-disabled-policy-parity",
                    },
                    deferredLanes = Array.Empty<string>(),
                },
                jsonOptions),
            new UTF8Encoding(false));

        File.WriteAllText(
            rollbackPath,
            JsonSerializer.Serialize(
                new
                {
                    schemaVersion = 1,
                    resultType = "ensou-dsh-local-data-rollback-result",
                    fromUpstreamTag,
                    toUpstreamTag,
                    decision = "PASS",
                    inPlaceRollbackRefusedAsExpected = true,
                    refusalClass = "credentials-layout-refusal",
                    historicalFixtureSha256 = FileSha256(fixturePath),
                    backupArchiveSha256 = FileSha256(backupPath),
                    preUpgradeTreeSha256 = treeBefore,
                    restoredTreeSha256 = rollbackUsedPreUpgradeBackup
                        ? treeBefore
                        : new string('0', 64),
                    preUpgradeWorkspaceTreeSha256 = workspaceTreeBefore,
                    restoredWorkspaceTreeSha256 = workspaceTreeBefore,
                    backupRestoreByteExactPassed = true,
                    sourceRuntimeBootAfterRestorePassed = true,
                    sourceRuntimeAuthoritativeFilesPreservedAfterBoot = authoritativeFiles,
                    sqliteArtifactsAfterRestoreAndBoot = Array.Empty<string>(),
                    recordedAtUtc,
                },
                jsonOptions),
            new UTF8Encoding(false));

        object Evidence(string evidencePath) => new
        {
            path = Path.GetRelativePath(root, evidencePath).Replace('\\', '/'),
            bytes = new FileInfo(evidencePath).Length,
            sha256 = FileSha256(evidencePath),
        };
        var evidenceFiles = new[]
        {
            runnerPath,
            fixturePath,
            backupPath,
            forwardPath,
            rollbackPath,
            transcriptPath,
            sourceSeedPath,
            targetForwardPath,
            sourceRestoredPath,
        };
        File.WriteAllText(
            path,
            JsonSerializer.Serialize(
                new
                {
                    schemaVersion = 1,
                    evidenceType = "ensou-dsh-enterprise-local-data-compatibility",
                    decision = "PASS",
                    startedUtc = recordedAtUtc.AddMinutes(-1),
                    completedUtc = recordedAtUtc,
                    fromUpstreamTag,
                    toUpstreamTag,
                    sourceRuntimeArchiveSha256,
                    targetRuntimeArchiveSha256,
                    testRunner = Evidence(runnerPath),
                    historicalFixture = Evidence(fixturePath),
                    preUpgradeBackup = Evidence(backupPath),
                    forwardResult = Evidence(forwardPath),
                    rollbackResult = Evidence(rollbackPath),
                    transcript = Evidence(transcriptPath),
                    apiLanes = new
                    {
                        sourceSeed = Evidence(sourceSeedPath),
                        targetForward = Evidence(targetForwardPath),
                        sourceRestored = Evidence(sourceRestoredPath),
                    },
                    artifacts = evidenceFiles.Select(Evidence).ToArray(),
                    coverage = new
                    {
                        credentialsP0 = "covered",
                        canonicalWholeHomeBackupRestore = "covered",
                        workspaceTreeBackupRestore = "covered",
                        sameTreeOldRuntimeRefusal = "covered",
                        headerOnlySessionArtifact = "preserved-and-discovered-at-boot",
                        fullSessionApiRoundTrip = allApiLanesCovered ? "covered" : "deferred",
                        conversationProviderRoundTrip = "covered",
                        attachmentPublicApiRoundTrip = "covered",
                        sessionQuerySemanticParity = "covered",
                        requestImageNormalization = normalizationCoverage,
                        sqliteLocalDataGate =
                            "not-applicable-memory-only-derived-and-no-artifacts-observed",
                    },
                },
                jsonOptions),
            new UTF8Encoding(false));
    }

    private sealed class PluginPromotionAdmissionFixture : IDisposable
    {
        private const string PolicyId = "11111111-2222-4333-8444-555555555555";
        private const string LauncherReleaseId = "launcher-production-2026.08.25.1";
        private const string RuntimeReleaseId = "managed-v2026.08.25.3";
        private const string TargetRuntimeReleaseId = "managed-v2026.08.25.4";
        private const string PluginReleaseId = "plugins-production-2026.08.25.1";
        private const string LedgerNamespace = "pilot-tenant-plugin-policy";
        private const string TestRunId = "12345678-1234-4234-8234-123456789abc";
        private const string RunnerSha256 =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        private readonly string _root;
        private readonly string _archivePath;
        private readonly string _metadataPath;
        private readonly string _launcherPath;
        private readonly string _runtimePath;
        private readonly string _runtimeMetadataPath;
        private readonly string _receiptPath;
        private readonly string _reservationPath;
        private readonly string _ledgerPath;
        private readonly string _handoffPath;
        private readonly string _organizationAdmissionPath;
        private readonly string _runtimeReleaseId;
        private readonly ECDsa _admissionSigner;
        private readonly PublisherPluginAdmissionTrust _admissionTrust;
        private readonly JsonObject _handoff;
        private readonly JsonObject _receipt;
        private readonly JsonObject _reservation;
        private readonly JsonObject _ledger;
        private string _receiptInputPath;

        private PluginPromotionAdmissionFixture(
            string root,
            string archivePath,
            string metadataPath,
            string launcherPath,
            string runtimePath,
            string runtimeMetadataPath,
            string receiptPath,
            string reservationPath,
            string ledgerPath,
            string handoffPath,
            string organizationAdmissionPath,
            string runtimeReleaseId,
            ECDsa admissionSigner,
            PublisherPluginAdmissionTrust admissionTrust,
            JsonObject handoff,
            JsonObject receipt,
            JsonObject reservation,
            JsonObject ledger)
        {
            _root = root;
            _archivePath = archivePath;
            _metadataPath = metadataPath;
            _launcherPath = launcherPath;
            _runtimePath = runtimePath;
            _runtimeMetadataPath = runtimeMetadataPath;
            _receiptPath = receiptPath;
            _receiptInputPath = receiptPath;
            _reservationPath = reservationPath;
            _ledgerPath = ledgerPath;
            _handoffPath = handoffPath;
            _organizationAdmissionPath = organizationAdmissionPath;
            _runtimeReleaseId = runtimeReleaseId;
            _admissionSigner = admissionSigner;
            _admissionTrust = admissionTrust;
            _handoff = handoff;
            _receipt = receipt;
            _reservation = reservation;
            _ledger = ledger;
        }

        public static PluginPromotionAdmissionFixture Create() => Create(
            RuntimeReleaseId,
            [RuntimeReleaseId]);

        public static PluginPromotionAdmissionFixture CreateExactMultiRuntime(
            string selectedRuntimeReleaseId) => Create(
            selectedRuntimeReleaseId,
            [RuntimeReleaseId, TargetRuntimeReleaseId]);

        private static PluginPromotionAdmissionFixture Create(
            string runtimeReleaseId,
            IReadOnlyList<string> runtimeReleaseIds)
        {
            var root = Path.Combine(TempRoot, "plugin-admission-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            var archivePath = Path.Combine(root, $"managed-plugin-policy-{PolicyId}-g1.zip");
            var metadataPath = Path.Combine(
                root,
                $"managed-plugin-policy-{PolicyId}-g1.artifact.json");
            PublisherFixture.CreatePluginPolicyPackage(
                archivePath,
                metadataPath,
                LauncherReleaseId,
                runtimeReleaseId,
                metadataDrift: false,
                runtimeReleaseIds: runtimeReleaseIds);
            var inspection = EnterprisePluginPolicyArchiveValidator.Validate(
                archivePath,
                LauncherReleaseId,
                runtimeReleaseId);
            var metadataSha = HashFile(metadataPath);
            var launcherPath = Path.Combine(root, "launcher-production-2026.08.25.1.zip");
            var runtimePath = Path.Combine(root, runtimeReleaseId + ".zip");
            var runtimeMetadataPath = Path.Combine(root, runtimeReleaseId + ".source.json");
            File.WriteAllBytes(launcherPath, "signed launcher archive\n"u8.ToArray());
            File.WriteAllBytes(
                runtimePath,
                Encoding.UTF8.GetBytes("signed runtime archive: " + runtimeReleaseId + "\n"));
            File.WriteAllBytes(runtimeMetadataPath, "{\"schemaVersion\":1}\n"u8.ToArray());
            var now = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");
            var operationsRoot = Path.Combine(root, "protected-operations");
            Directory.CreateDirectory(operationsRoot);
            var ledgerPath = Path.Combine(operationsRoot, "plugin-generation.v2.json");
            var ledger = JsonSerializer.SerializeToNode(new
            {
                schemaVersion = 2,
                ledgerType = "managed-plugin-policy-generation",
                @namespace = LedgerNamespace,
                policyId = PolicyId,
                highestPromotedGeneration = 0,
                highestPromotedCandidate = (object?)null,
            })!.AsObject();
            WriteJson(ledgerPath, ledger);

            var receiptPath = Path.Combine(operationsRoot, "harness-compatibility.v1.json");
            var receipt = JsonSerializer.SerializeToNode(new
            {
                schemaVersion = 1,
                receiptType = "managed-plugin-harness-compatibility",
                producer = new
                {
                    component = "Ensou.Dsh.EnterprisePluginCompatibilityRunner",
                    testRunId = TestRunId,
                    fileName = "Ensou.Dsh.EnterprisePluginCompatibilityRunner.exe",
                    sizeBytes = 123456L,
                    sha256 = RunnerSha256,
                },
                result = "PASS",
                startedAtUtc = now,
                observedAtUtc = now,
                launcherReleaseId = LauncherReleaseId,
                launcherArtifact = new
                {
                    fileName = Path.GetFileName(launcherPath),
                    sizeBytes = new FileInfo(launcherPath).Length,
                    sha256 = HashFile(launcherPath),
                },
                runtimeReleaseId,
                runtimeArtifact = new
                {
                    fileName = Path.GetFileName(runtimePath),
                    sizeBytes = new FileInfo(runtimePath).Length,
                    sha256 = HashFile(runtimePath),
                    sourceMetadataSha256 = HashFile(runtimeMetadataPath),
                },
                harnessSourceTag = "dsh-v0.1.2-rc.1",
                policy = new
                {
                    policyId = PolicyId,
                    generation = 1,
                    archiveSha256 = inspection.ArchiveSha256,
                    metadataSha256 = metadataSha,
                    rawPolicySha256 = inspection.PolicySha256,
                    executionAdmissionReceiptSha256 = new string('e', 64),
                },
                plugins = inspection.SkillPacks.Select(skill => new
                {
                    skillId = skill.SkillId,
                    version = skill.Version,
                    root = skill.Root,
                    declaredTreeSha256 = skill.DeclaredTreeSha256,
                    commandExecuted = "PASS",
                    managedPolicyEnforced = "PASS",
                }).ToArray(),
                observations = new
                {
                    launcherBinarySelfCheck = "PASS",
                    runtimeHealth = "PASS",
                    pluginPolicyInstalled = "PASS",
                    pluginCommandExecuted = "PASS",
                    managedPolicyEnforced = "PASS",
                    startupUpdateCheck = "PASS",
                    rollbackRestoredPreviousRuntime = "PASS",
                    conversationHistoryPreserved = "PASS",
                    workspacePreserved = "PASS",
                },
            })!.AsObject();
            WriteJson(receiptPath, receipt);

            var reservationDirectory = Path.Combine(
                operationsRoot,
                Path.GetFileName(ledgerPath) + ".reservations.v1");
            Directory.CreateDirectory(reservationDirectory);
            var reservationPath = Path.Combine(
                reservationDirectory,
                $"managed-plugin-policy-{PolicyId}-g1.reservation.json");
            var reservation = JsonSerializer.SerializeToNode(new
            {
                schemaVersion = 1,
                reservationType = "managed-plugin-policy-generation",
                reservationStatus = "EXCLUSIVE_UNSIGNED_CANDIDATE_RESERVATION",
                policyId = PolicyId,
                generation = 1,
                targetEnvironment = "production-release-candidate",
                digests = new
                {
                    archiveSha256 = inspection.ArchiveSha256,
                    metadataSha256 = metadataSha,
                    rawPolicySha256 = inspection.PolicySha256,
                },
                harnessCompatibilityReceiptSha256 = HashFile(receiptPath),
                createdAtUtc = now,
            })!.AsObject();
            WriteJson(reservationPath, reservation);

            var metadata = JsonNode.Parse(File.ReadAllBytes(metadataPath))!.AsObject();
            var handoffPath = Path.Combine(
                root,
                $"managed-plugin-policy-{PolicyId}-g1.promotion-handoff.json");
            var scriptEvidence = new
            {
                path = Path.Combine(
                    root,
                    "reviewed-plugin-repository",
                    "scripts",
                    "contract.ps1"),
                sha256 = new string('a', 64),
            };
            var handoff = JsonSerializer.SerializeToNode(new
            {
                schemaVersion = 2,
                handoffType = "managed-plugin-policy-publisher-input-template",
                targetEnvironment = "production-release-candidate",
                promotionStatus = "UNSIGNED_PUBLISHER_REVIEW_REQUIRED",
                signingStatus = "UNSIGNED_CANDIDATE",
                productionSignaturePresent = false,
                policy = new
                {
                    policyId = PolicyId,
                    generation = 1,
                    critical = true,
                    revoked = false,
                    rawPolicyFileName = "plugin-policy.json",
                    rawPolicySizeBytes = inspection.PolicySizeBytes,
                    rawPolicySha256 = inspection.PolicySha256,
                },
                compatibility = new
                {
                    launcherReleaseIds = new[] { LauncherReleaseId },
                    runtimeReleaseIds,
                },
                digests = new
                {
                    archiveSha256 = inspection.ArchiveSha256,
                    archiveSizeBytes = inspection.ArchiveSizeBytes,
                    metadataSha256 = metadataSha,
                    metadataSizeBytes = new FileInfo(metadataPath).Length,
                    rawPolicySha256 = inspection.PolicySha256,
                    rawPolicySizeBytes = inspection.PolicySizeBytes,
                },
                publisherInputTemplate = new
                {
                    templateOnly = true,
                    directlyConsumable = false,
                    component = "plugin-policy",
                    filePath = archivePath,
                    policyMetadataPath = metadataPath,
                    fileName = Path.GetFileName(archivePath),
                    metadataFileName = Path.GetFileName(metadataPath),
                    signingStatusRequired = "UNSIGNED_CANDIDATE",
                    releaseId = (string?)null,
                    uri = (string?)null,
                    requiresReleasePublisherId = true,
                    requiresHttpsUri = true,
                    requiresIndependentPublisherRevalidation = true,
                },
                inputs = metadata["inputs"]!.DeepClone(),
                harnessCompatibility = new
                {
                    status = "EXTERNAL_RECEIPT_VALIDATED",
                    path = receiptPath,
                    sha256 = HashFile(receiptPath),
                    sizeBytes = new FileInfo(receiptPath).Length,
                    observedAtUtc = now,
                    testRunId = TestRunId,
                    harnessSourceTag = "dsh-v0.1.2-rc.1",
                },
                generationAdmission = new
                {
                    ledgerPath,
                    ledgerSha256 = HashFile(ledgerPath),
                    observedHighestPromotedGeneration = 0,
                    candidateGeneration = 1,
                    reservationPath,
                    reservationSha256 = HashFile(reservationPath),
                    reservationSizeBytes = new FileInfo(reservationPath).Length,
                    decision = "EXCLUSIVELY_RESERVED_UNSIGNED_CANDIDATE",
                },
                verification = new
                {
                    status = "UNSIGNED_CANDIDATE_CONTRACTS_VERIFIED",
                    repositoryRoot = Path.Combine(root, "reviewed-plugin-repository"),
                    headCommit = new string('d', 40),
                    repositoryClean = true,
                    relevantSourcePathsClean = true,
                    workingTreeOverrideUsed = false,
                    policyTestScript = scriptEvidence,
                    policyBuilderScript = scriptEvidence,
                    handoffScript = scriptEvidence,
                    skillArtifactTestScript = scriptEvidence,
                    compatibilityReceiptTestScript = scriptEvidence,
                    generationReservationScript = scriptEvidence,
                    skillArtifactVerification = "VERIFIED_BY_TEST_MANAGED_ARTIFACT",
                    policyTest = "All managed plugin policy contracts passed.",
                },
                signing = new
                {
                    status = "UNSIGNED_CANDIDATE",
                    privateKeyUsed = false,
                    signerActionRequired = "ReleasePublisher independently revalidates and signs.",
                },
            })!.AsObject();
            WriteJson(handoffPath, handoff);

            var admissionSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var admissionPublic = admissionSigner.ExportParameters(includePrivateParameters: false);
            var admissionTrust = new PublisherPluginAdmissionTrust
            {
                KeyId = "plugin-admission-test-2026-01",
                X = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(admissionPublic.Q.X!),
                Y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(admissionPublic.Q.Y!),
            };
            var organizationAdmissionPath = Path.Combine(
                operationsRoot,
                "plugin-organization-admission.v1.json");
            WriteOrganizationAdmission(
                organizationAdmissionPath,
                admissionSigner,
                admissionTrust.KeyId,
                archivePath,
                metadataPath,
                launcherPath,
                runtimePath,
                runtimeMetadataPath,
                receiptPath,
                reservationPath,
                ledgerPath,
                handoffPath,
                now,
                DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                runtimeReleaseId);
            return new PluginPromotionAdmissionFixture(
                root,
                archivePath,
                metadataPath,
                launcherPath,
                runtimePath,
                runtimeMetadataPath,
                receiptPath,
                reservationPath,
                ledgerPath,
                handoffPath,
                organizationAdmissionPath,
                runtimeReleaseId,
                admissionSigner,
                admissionTrust,
                handoff,
                receipt,
                reservation,
                ledger);
        }

        public void Mutate(Action<JsonObject, JsonObject, JsonObject, JsonObject> mutation)
        {
            mutation(_handoff, _receipt, _reservation, _ledger);
            WriteJson(_receiptPath, _receipt);
            _reservation["harnessCompatibilityReceiptSha256"] = HashFile(_receiptPath);
            WriteJson(_reservationPath, _reservation);
            WriteJson(_ledgerPath, _ledger);
            var harness = _handoff["harnessCompatibility"]!;
            harness["sha256"] = HashFile(_receiptPath);
            harness["sizeBytes"] = new FileInfo(_receiptPath).Length;
            harness["observedAtUtc"] = _receipt["observedAtUtc"]!.GetValue<string>();
            harness["testRunId"] = _receipt["producer"]!["testRunId"]!.GetValue<string>();
            harness["harnessSourceTag"] = _receipt["harnessSourceTag"]!.GetValue<string>();
            var generation = _handoff["generationAdmission"]!;
            generation["reservationSha256"] = HashFile(_reservationPath);
            generation["reservationSizeBytes"] = new FileInfo(_reservationPath).Length;
            generation["ledgerSha256"] = HashFile(_ledgerPath);
            generation["observedHighestPromotedGeneration"] =
                _ledger["highestPromotedGeneration"]!.GetValue<int>();
            WriteJson(_handoffPath, _handoff);
        }

        public void ValidateUntilJournalGate()
        {
            Validate();
        }

        public void ValidateRejectedBeforeJournal(string pluginReleaseId = PluginReleaseId)
        {
            try
            {
                Validate(pluginReleaseId);
            }
            catch (InvalidDataException)
            {
                return;
            }
            throw new InvalidOperationException(
                "Tampered plugin admission reached the append-only journal gate.");
        }

        public void ValidateRejectedBeforeJournalWithMessage(string expectedMessage)
        {
            try
            {
                Validate();
            }
            catch (InvalidDataException exception)
            {
                AssertTrue(
                    exception.Message.Contains(expectedMessage, StringComparison.Ordinal));
                return;
            }
            throw new InvalidOperationException(
                "Tampered plugin admission reached the append-only journal gate.");
        }

        public void ValidatePortableRelocationUntilJournalGate()
        {
            var relocatedRoot = Path.Combine(_root, "offline-signer-inputs");
            Directory.CreateDirectory(relocatedRoot);
            var archivePath = CopyPortable(_archivePath, relocatedRoot);
            var metadataPath = CopyPortable(_metadataPath, relocatedRoot);
            var receiptPath = CopyPortable(_receiptPath, relocatedRoot);
            var ledgerPath = CopyPortable(_ledgerPath, relocatedRoot);
            var reservationDirectory = Path.Combine(
                relocatedRoot,
                Path.GetFileName(ledgerPath) + ".reservations.v1");
            Directory.CreateDirectory(reservationDirectory);
            var reservationPath = CopyPortable(_reservationPath, reservationDirectory);
            var handoffPath = CopyPortable(_handoffPath, relocatedRoot);
            var organizationAdmissionPath = Path.Combine(
                relocatedRoot,
                Path.GetFileName(_organizationAdmissionPath));
            WriteOrganizationAdmission(
                organizationAdmissionPath,
                _admissionSigner,
                _admissionTrust.KeyId,
                archivePath,
                metadataPath,
                _launcherPath,
                _runtimePath,
                _runtimeMetadataPath,
                receiptPath,
                reservationPath,
                ledgerPath,
                handoffPath,
                _receipt["observedAtUtc"]!.GetValue<string>(),
                DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                _runtimeReleaseId);
            Validate(
                PluginReleaseId,
                archivePath,
                metadataPath,
                receiptPath,
                reservationPath,
                ledgerPath,
                handoffPath,
                organizationAdmissionPath);
        }

        public void ValidateIdempotentLedgerReplayUntilJournalGate()
        {
            var inspection = EnterprisePluginPolicyArchiveValidator.Validate(
                _archivePath,
                LauncherReleaseId,
                _runtimeReleaseId);
            _ledger["highestPromotedGeneration"] = inspection.Generation;
            _ledger["highestPromotedCandidate"] = JsonSerializer.SerializeToNode(new
            {
                generation = inspection.Generation,
                pluginReleaseId = PluginReleaseId,
                archiveSha256 = HashFile(_archivePath),
                metadataSha256 = HashFile(_metadataPath),
                rawPolicySha256 = inspection.PolicySha256,
                promotionHandoffSha256 = HashFile(_handoffPath),
                compatibilityReceiptSha256 = HashFile(_receiptPath),
                reservationSha256 = HashFile(_reservationPath),
                organizationAdmissionReceiptSha256 = HashFile(_organizationAdmissionPath),
                firstPublishedAtUtc = DateTimeOffset.UtcNow
                    .ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            });
            WriteJson(_ledgerPath, _ledger);
            ValidateUntilJournalGate();
        }

        public void TamperOrganizationAdmission()
        {
            var admission = JsonNode.Parse(File.ReadAllBytes(_organizationAdmissionPath))!.AsObject();
            admission["runtimeReleaseId"] = "managed-v2026.08.25.999";
            WriteJson(_organizationAdmissionPath, admission);
        }

        public void TamperHandoffObservedGeneration()
        {
            _handoff["generationAdmission"]!["observedHighestPromotedGeneration"] = 1;
            WriteJson(_handoffPath, _handoff);
        }

        public void MutateHandoffRuntimeReleaseIds(params string[] runtimeReleaseIds)
        {
            _handoff["compatibility"]!["runtimeReleaseIds"] =
                JsonSerializer.SerializeToNode(runtimeReleaseIds);
            WriteJson(_handoffPath, _handoff);
            WriteOrganizationAdmissionForCurrentHandoff(_runtimeReleaseId);
        }

        public void SignOrganizationAdmissionForRuntime(string runtimeReleaseId)
        {
            var admission = JsonSerializer.Deserialize<PublisherPluginOrganizationAdmissionReceipt>(
                File.ReadAllBytes(_organizationAdmissionPath),
                new JsonSerializerOptions(JsonSerializerDefaults.Web))! with
            {
                RuntimeReleaseId = runtimeReleaseId,
            };
            WriteJson(
                _organizationAdmissionPath,
                JsonSerializer.SerializeToNode(
                    SignAdmission(admission, _admissionSigner, _admissionTrust.KeyId),
                    new JsonSerializerOptions(JsonSerializerDefaults.Web))!);
        }

        private void WriteOrganizationAdmissionForCurrentHandoff(string runtimeReleaseId)
        {
            WriteOrganizationAdmission(
                _organizationAdmissionPath,
                _admissionSigner,
                _admissionTrust.KeyId,
                _archivePath,
                _metadataPath,
                _launcherPath,
                _runtimePath,
                _runtimeMetadataPath,
                _receiptPath,
                _reservationPath,
                _ledgerPath,
                _handoffPath,
                _receipt["observedAtUtc"]!.GetValue<string>(),
                DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                runtimeReleaseId);
        }

        public void ValidateRejectedWithCurrentRuntime(string runtimeReleaseId)
        {
            try
            {
                Validate(runtimeReleaseId: runtimeReleaseId);
            }
            catch (InvalidDataException)
            {
                return;
            }
            throw new InvalidOperationException(
                "A selected runtime absent from the exact policy compatibility set reached the journal gate.");
        }

        public void ValidateEverySignedOrganizationAdmissionFieldRejectsTamper()
        {
            var originalBytes = File.ReadAllBytes(_organizationAdmissionPath);
            var original = JsonNode.Parse(originalBytes)!.AsObject();
            try
            {
                foreach (var property in original.ToArray())
                {
                    if (string.Equals(property.Key, "signature", StringComparison.Ordinal))
                    {
                        continue;
                    }
                    var tampered = JsonNode.Parse(originalBytes)!.AsObject();
                    var value = tampered[property.Key]
                        ?? throw new InvalidOperationException(
                            $"Signed plugin admission field is unexpectedly null: {property.Key}");
                    if (value is JsonValue scalar && scalar.TryGetValue<bool>(out var boolean))
                    {
                        tampered[property.Key] = !boolean;
                    }
                    else if (value is JsonValue number && number.TryGetValue<long>(out var integer))
                    {
                        tampered[property.Key] = integer + 1;
                    }
                    else if (value is JsonValue text && text.TryGetValue<string>(out var raw))
                    {
                        tampered[property.Key] = raw + "-tampered";
                    }
                    else
                    {
                        throw new InvalidOperationException(
                            $"Unsupported signed plugin admission field type: {property.Key}");
                    }
                    WriteJson(_organizationAdmissionPath, tampered);
                    ValidateRejectedBeforeJournal();
                }
                var originalSignature = original["signature"]!.AsObject();
                foreach (var signatureProperty in originalSignature.ToArray())
                {
                    var tampered = JsonNode.Parse(originalBytes)!.AsObject();
                    var signature = tampered["signature"]!.AsObject();
                    signature[signatureProperty.Key] =
                        signature[signatureProperty.Key]!.GetValue<string>() + "-tampered";
                    WriteJson(_organizationAdmissionPath, tampered);
                    ValidateRejectedBeforeJournal();
                }
            }
            finally
            {
                File.WriteAllBytes(_organizationAdmissionPath, originalBytes);
            }
        }

        public void ValidateNonDerivedReservationPathRejected()
        {
            var untrustedDirectory = Path.Combine(_root, "untrusted-reservation-copy");
            Directory.CreateDirectory(untrustedDirectory);
            var copiedReservation = CopyPortable(_reservationPath, untrustedDirectory);
            try
            {
                Validate(reservationPath: copiedReservation);
            }
            catch (InvalidDataException)
            {
                return;
            }
            throw new InvalidOperationException(
                "A reservation outside the trusted ledger sibling path reached the journal gate.");
        }

        public void ValidateOrganizationAdmissionInsideRepositoryRejected()
        {
            var repositoryRoot = _handoff["verification"]!["repositoryRoot"]!.GetValue<string>();
            Directory.CreateDirectory(repositoryRoot);
            var copiedAdmission = CopyPortable(_organizationAdmissionPath, repositoryRoot);
            try
            {
                Validate(organizationAdmissionPath: copiedAdmission);
            }
            catch (InvalidDataException)
            {
                return;
            }
            throw new InvalidOperationException(
                "An organization admission receipt inside the source repository reached the journal gate.");
        }

        public void SignOrganizationAdmissionWithWrongKey()
        {
            var admission = JsonSerializer.Deserialize<PublisherPluginOrganizationAdmissionReceipt>(
                File.ReadAllBytes(_organizationAdmissionPath),
                new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
            using var wrongSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            admission = admission with
            {
                Signature = admission.Signature with
                {
                    Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(
                        wrongSigner.SignData(
                            PublisherPluginOrganizationAdmissionCanonicalJson.Payload(admission),
                            HashAlgorithmName.SHA256,
                            DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
                },
            };
            WriteJson(
                _organizationAdmissionPath,
                JsonSerializer.SerializeToNode(
                    admission,
                    new JsonSerializerOptions(JsonSerializerDefaults.Web))!);
        }

        public void MakeOrganizationAdmissionStaleAndResign()
        {
            var admission = JsonSerializer.Deserialize<PublisherPluginOrganizationAdmissionReceipt>(
                File.ReadAllBytes(_organizationAdmissionPath),
                new JsonSerializerOptions(JsonSerializerDefaults.Web))! with
            {
                ReviewedAtUnixSeconds = DateTimeOffset.UtcNow.AddHours(-169).ToUnixTimeSeconds(),
            };
            admission = SignAdmission(admission, _admissionSigner, _admissionTrust.KeyId);
            WriteJson(
                _organizationAdmissionPath,
                JsonSerializer.SerializeToNode(
                    admission,
                    new JsonSerializerOptions(JsonSerializerDefaults.Web))!);
        }

        private void Validate(
            string pluginReleaseId = PluginReleaseId,
            string? archivePath = null,
            string? metadataPath = null,
            string? receiptPath = null,
            string? reservationPath = null,
            string? ledgerPath = null,
            string? handoffPath = null,
            string? organizationAdmissionPath = null,
            string? runtimeReleaseId = null)
        {
            archivePath ??= _archivePath;
            metadataPath ??= _metadataPath;
            receiptPath ??= _receiptInputPath;
            reservationPath ??= _reservationPath;
            ledgerPath ??= _ledgerPath;
            handoffPath ??= _handoffPath;
            organizationAdmissionPath ??= _organizationAdmissionPath;
            runtimeReleaseId ??= _runtimeReleaseId;
            using var staging = PublisherInputStaging.Create();
            var archive = staging.Capture(archivePath);
            var metadata = staging.Capture(metadataPath);
            var handoff = staging.Capture(handoffPath);
            var discovered = PublisherPluginPromotionAdmission.Discover(
                handoff.ReadAllBytes(PublisherPluginPromotionAdmission.MaximumHandoffBytes));
            var receipt = staging.Capture(receiptPath);
            var reservation = staging.Capture(reservationPath);
            var ledger = staging.Capture(ledgerPath);
            var organizationAdmission = staging.Capture(organizationAdmissionPath);
            var promotion = new PublisherPluginPromotionSnapshot(
                discovered,
                archivePath,
                metadataPath,
                receiptPath,
                reservationPath,
                ledgerPath,
                organizationAdmissionPath,
                organizationAdmissionPath,
                handoff,
                receipt,
                reservation,
                ledger,
                organizationAdmission,
                organizationAdmission);
            var input = new PublisherArtifact
            {
                Component = EnterpriseReleaseSetContract.PluginPolicyComponent,
                ReleaseId = pluginReleaseId,
                FilePath = archive.StagedPath,
                Uri = new Uri(
                    $"https://artifacts.example.com/{Path.GetFileName(archivePath)}"),
                PolicyMetadataPath = metadata.StagedPath,
                PluginPromotionHandoffPath = handoff.StagedPath,
                PluginHarnessCompatibilityReceiptPath = receipt.StagedPath,
                PluginGenerationReservationPath = reservation.StagedPath,
                PluginGenerationLedgerPath = ledger.StagedPath,
                PluginGenerationLedgerNamespace = LedgerNamespace,
                PluginOrganizationAdmissionReceiptPath = organizationAdmission.StagedPath,
                PluginPromotionJournalAuthorizationPath = organizationAdmission.StagedPath,
            };
            var snapshot = new PublisherSnapshotArtifact(
                input,
                archive,
                metadata,
                promotion,
                null,
                null);
            var launcherFile = staging.Capture(_launcherPath);
            var launcher = new PublisherSnapshotArtifact(
                new PublisherArtifact
                {
                    Component = EnterpriseReleaseSetContract.LauncherComponent,
                    ReleaseId = LauncherReleaseId,
                    FilePath = launcherFile.StagedPath,
                    Uri = new Uri(
                        $"https://artifacts.example.com/{Path.GetFileName(_launcherPath)}"),
                },
                launcherFile,
                null,
                null,
                null,
                null);
            var runtimeFile = staging.Capture(_runtimePath);
            var runtimeMetadata = staging.Capture(_runtimeMetadataPath);
            var runtime = new PublisherSnapshotArtifact(
                new PublisherArtifact
                {
                    Component = EnterpriseReleaseSetContract.RuntimeComponent,
                    ReleaseId = runtimeReleaseId,
                    FilePath = runtimeFile.StagedPath,
                    Uri = new Uri(
                        $"https://artifacts.example.com/{Path.GetFileName(_runtimePath)}"),
                    SourceRuntimeMetadataPath = runtimeMetadata.StagedPath,
                },
                runtimeFile,
                null,
                null,
                runtimeMetadata,
                null);
            var inspection = EnterprisePluginPolicyArchiveValidator.Validate(
                archive.StagedPath,
                LauncherReleaseId,
                _runtimeReleaseId);
            var policyMetadata = PublisherPluginPolicyMetadata.Validate(
                metadata.StagedPath,
                archive.StagedPath,
                inspection);
            PublisherPluginPromotionAdmission.ValidateProduction(
                snapshot,
                inspection,
                policyMetadata,
                launcher,
                runtime,
                _admissionTrust,
                new PublisherPluginCompatibilityRunnerTrust
                {
                    Sha256 = RunnerSha256,
                },
                DateTimeOffset.UtcNow);
        }

        public void ValidatePublisherConfigStructure(bool includeHandoff)
        {
            var launcherPath = Path.Combine(_root, "launcher-production.zip");
            var runtimePath = Path.Combine(_root, "runtime-production.zip");
            var config = new PublisherConfig
            {
                Environment = EnterpriseReleaseSetContract.ProductionEnvironment,
                Channel = "pilot",
                ReleaseSetId = "publisher-production-set-1",
                KeyId = "release-production-2026-01",
                Generation = 1,
                Sequence = 1,
                MinAcceptedSequence = 0,
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddDays(2),
                StartupStub = new EnterpriseStartupStubCompatibility
                {
                    MinimumProtocol = EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                    MaximumProtocol = EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                },
                ManifestOrigin = new Uri("https://updates.example.com/"),
                ArtifactOrigin = new Uri("https://artifacts.example.com/"),
                RevokedReleaseSetIds = [],
                Artifacts =
                [
                    new PublisherArtifact
                    {
                        Component = EnterpriseReleaseSetContract.LauncherComponent,
                        ReleaseId = LauncherReleaseId,
                        FilePath = launcherPath,
                        Uri = new Uri($"https://artifacts.example.com/{Path.GetFileName(launcherPath)}"),
                    },
                    new PublisherArtifact
                    {
                        Component = EnterpriseReleaseSetContract.RuntimeComponent,
                        ReleaseId = RuntimeReleaseId,
                        FilePath = runtimePath,
                        Uri = new Uri($"https://artifacts.example.com/{Path.GetFileName(runtimePath)}"),
                        SourceRuntimeMetadataPath = Path.Combine(_root, "runtime.metadata.json"),
                        OrganizationAdmissionReceiptPath = Path.Combine(
                            _root,
                            "runtime.organization-admission.json"),
                    },
                    new PublisherArtifact
                    {
                        Component = EnterpriseReleaseSetContract.PluginPolicyComponent,
                        ReleaseId = "plugins-production-2026.08.25.1",
                        FilePath = _archivePath,
                        Uri = new Uri(
                            $"https://artifacts.example.com/{Path.GetFileName(_archivePath)}"),
                        PolicyMetadataPath = _metadataPath,
                        PluginPromotionHandoffPath = includeHandoff ? _handoffPath : null,
                        PluginHarnessCompatibilityReceiptPath = _receiptPath,
                        PluginGenerationReservationPath = _reservationPath,
                        PluginGenerationLedgerPath = _ledgerPath,
                        PluginGenerationLedgerNamespace = LedgerNamespace,
                        PluginOrganizationAdmissionReceiptPath = _organizationAdmissionPath,
                        PluginPromotionJournalAuthorizationPath = _organizationAdmissionPath,
                    },
                ],
            };
            config.ValidateStructure();
        }

        public string? RedirectReceiptThroughJunction()
        {
            var junction = Path.Combine(_root, "linked-plugin-evidence");
            if (!TryCreateDirectoryJunction(junction, Path.GetDirectoryName(_receiptPath)!))
            {
                return null;
            }
            _receiptInputPath = Path.Combine(
                junction,
                Path.GetFileName(_receiptPath));
            return junction;
        }

        public void Dispose()
        {
            _admissionSigner.Dispose();
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }

        private static void WriteJson(string path, JsonNode value) => File.WriteAllText(
            path,
            value.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) + "\n",
            new UTF8Encoding(false));

        private static string HashFile(string path) =>
            Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));

        private static string CopyPortable(string path, string directory)
        {
            var destination = Path.Combine(directory, Path.GetFileName(path));
            File.Copy(path, destination);
            return destination;
        }

        private static void WriteOrganizationAdmission(
            string path,
            ECDsa signer,
            string keyId,
            string archivePath,
            string metadataPath,
            string launcherPath,
            string runtimePath,
            string runtimeMetadataPath,
            string receiptPath,
            string reservationPath,
            string ledgerPath,
            string handoffPath,
            string compatibilityObservedAtUtc,
            long reviewedAtUnixSeconds,
            string runtimeReleaseId)
        {
            var inspection = EnterprisePluginPolicyArchiveValidator.Validate(
                archivePath,
                LauncherReleaseId,
                runtimeReleaseId);
            var ledger = PublisherPluginPromotionAdmission.ParseLedgerState(
                File.ReadAllBytes(ledgerPath));
            var admission = new PublisherPluginOrganizationAdmissionReceipt
            {
                SchemaVersion = PublisherPluginOrganizationAdmissionReceipt.CurrentSchemaVersion,
                ReceiptType = PublisherPluginOrganizationAdmissionReceipt.CurrentReceiptType,
                Decision = PublisherPluginOrganizationAdmissionReceipt.AdmittedDecision,
                ReviewedAtUnixSeconds = reviewedAtUnixSeconds,
                CompatibilityTestRunId = TestRunId,
                PolicyId = PolicyId,
                Generation = inspection.Generation,
                Critical = inspection.Critical,
                PluginReleaseId = PluginReleaseId,
                ArchiveSha256 = HashFile(archivePath),
                ArchiveSizeBytes = new FileInfo(archivePath).Length,
                MetadataSha256 = HashFile(metadataPath),
                MetadataSizeBytes = new FileInfo(metadataPath).Length,
                RawPolicySha256 = inspection.PolicySha256,
                RawPolicySizeBytes = inspection.PolicySizeBytes,
                LauncherReleaseId = LauncherReleaseId,
                LauncherArchiveSha256 = HashFile(launcherPath),
                LauncherArchiveSizeBytes = new FileInfo(launcherPath).Length,
                RuntimeReleaseId = runtimeReleaseId,
                RuntimeArchiveSha256 = HashFile(runtimePath),
                RuntimeArchiveSizeBytes = new FileInfo(runtimePath).Length,
                RuntimeSourceMetadataSha256 = HashFile(runtimeMetadataPath),
                HarnessSourceTag = "dsh-v0.1.2-rc.1",
                CompatibilityReceiptSha256 = HashFile(receiptPath),
                CompatibilityReceiptSizeBytes = new FileInfo(receiptPath).Length,
                CompatibilityObservedAtUtc = compatibilityObservedAtUtc,
                PromotionHandoffSha256 = HashFile(handoffPath),
                PromotionHandoffSizeBytes = new FileInfo(handoffPath).Length,
                ReservationSha256 = HashFile(reservationPath),
                ReservationSizeBytes = new FileInfo(reservationPath).Length,
                GenerationLedgerNamespace = LedgerNamespace,
                GenerationLedgerPathSha256 =
                    PublisherPluginOrganizationAdmissionReceipt.ComputeLedgerPathSha256(ledgerPath),
                GenerationLedgerSha256 = HashFile(ledgerPath),
                ObservedHighestPromotedGeneration = ledger.HighestPromotedGeneration,
                Signature = new EnterpriseReleaseSignature
                {
                    Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
                    KeyId = keyId,
                    Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(new byte[64]),
                },
            };
            admission = SignAdmission(admission, signer, keyId);
            WriteJson(
                path,
                JsonSerializer.SerializeToNode(
                    admission,
                    new JsonSerializerOptions(JsonSerializerDefaults.Web))!);
        }

        private static PublisherPluginOrganizationAdmissionReceipt SignAdmission(
            PublisherPluginOrganizationAdmissionReceipt admission,
            ECDsa signer,
            string keyId) => admission with
        {
            Signature = new EnterpriseReleaseSignature
            {
                Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
                KeyId = keyId,
                Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(
                    signer.SignData(
                        PublisherPluginOrganizationAdmissionCanonicalJson.Payload(admission),
                        HashAlgorithmName.SHA256,
                        DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
            },
        };
    }

    private enum RuntimeAdmissionScenario
    {
        Valid,
        MissingMetadata,
        MissingReceipt,
        TamperedMetadata,
        PromotionIneligible,
        WrongWebAuthProtocol,
        FormerRc2Metadata,
        WrongKey,
        WrongDigest,
        ArtifactFileNameMismatch,
        ForgedProductionConfig,
        MissingProductionTrust,
        StaleReceipt,
    }

    private enum PilotLocalDataCertificationScenario
    {
        Valid,
        Missing,
        Tampered,
        WrongAudience,
        WrongRunnerSha256,
    }

    private enum PilotClientBindingScenario
    {
        Valid,
        MismatchedClientBootstrapper,
        MismatchedMaintenance,
        MismatchedBuildProfileMarker,
    }

    private sealed class PublisherFixture : IDisposable
    {
        private readonly ECDsa _signer;
        private readonly ECDsa _admissionSigner;
        private readonly PublisherRuntimeAdmissionTrust _admissionTrust;

        private PublisherFixture(
            string root,
            string privateKeyPath,
            string ledgerPath,
            ECDsa signer,
            ECDsa admissionSigner,
            PublisherRuntimeAdmissionTrust admissionTrust)
        {
            Root = root;
            PrivateKeyPath = privateKeyPath;
            LedgerPath = ledgerPath;
            _signer = signer;
            _admissionSigner = admissionSigner;
            _admissionTrust = admissionTrust;
        }

        public string Root { get; }
        public string PrivateKeyPath { get; }
        public string LedgerPath { get; }

        public string CreatePemPrivateKey()
        {
            var path = Path.Combine(Root, "publisher.pem");
            File.WriteAllText(
                path,
                _signer.ExportPkcs8PrivateKeyPem(),
                Encoding.ASCII);
            return path;
        }

        public static PublisherFixture Create()
        {
            var root = Path.Combine(TempRoot, Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var admissionSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var admissionParameters = admissionSigner.ExportParameters(
                includePrivateParameters: false);
            var admissionTrust = new PublisherRuntimeAdmissionTrust
            {
                KeyId = "runtime-admission-test-key",
                X = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(
                    admissionParameters.Q.X!),
                Y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(
                    admissionParameters.Q.Y!),
            };
            var keyPath = Path.Combine(root, "publisher.pk8");
            File.WriteAllBytes(keyPath, signer.ExportPkcs8PrivateKey());
            return new PublisherFixture(
                root,
                keyPath,
                Path.Combine(root, "ledger", "pilot.v2.json"),
                signer,
                admissionSigner,
                admissionTrust);
        }

        public async Task<ProcessResult> RunAsync(long sequence, string outputName)
            => await RunWithPrivateKeyPathAsync(sequence, outputName, PrivateKeyPath)
                .ConfigureAwait(false);

        public void AssertPolicyHandoffBinding()
        {
            const string KeyId = "publisher-test-key";
            var now = new DateTimeOffset(2026, 8, 26, 2, 0, 0, TimeSpan.Zero);
            var sourceRoot = Path.Combine(Root, "policy-handoff");
            Directory.CreateDirectory(sourceRoot);
            var unsigned = new EnterpriseReleaseSignature
            {
                Algorithm = "ES256",
                KeyId = KeyId,
                Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(new byte[64]),
            };
            var artifacts = new[]
            {
                new EnterpriseReleaseArtifact
                {
                    Component = "launcher",
                    ReleaseId = "launcher-8",
                    Uri = new Uri("https://updates.example/v2/releases/pilot-8/launcher-8.zip"),
                    SizeBytes = 101,
                    Sha256 = new string('1', 64),
                    CompleteTreeSha256 = new string('4', 64),
                    Signature = unsigned,
                },
                new EnterpriseReleaseArtifact
                {
                    Component = "runtime",
                    ReleaseId = "runtime-8",
                    Uri = new Uri("https://updates.example/v2/releases/pilot-8/runtime-8.zip"),
                    SizeBytes = 202,
                    Sha256 = new string('2', 64),
                    CompleteTreeSha256 = new string('5', 64),
                    Signature = unsigned,
                },
                new EnterpriseReleaseArtifact
                {
                    Component = "plugin-policy",
                    ReleaseId = "plugin-8",
                    Uri = new Uri("https://updates.example/v2/releases/pilot-8/plugin-8.zip"),
                    SizeBytes = 303,
                    Sha256 = new string('3', 64),
                    CompleteTreeSha256 = new string('6', 64),
                    Signature = unsigned,
                },
            };
            var placeholder = new EnterpriseReleaseSetManifest
            {
                SchemaVersion = 2,
                Product = "ensou-dsh-enterprise",
                Environment = "production",
                Channel = "pilot",
                ReleaseSetId = "pilot-8",
                Generation = 8,
                Sequence = 8,
                MinAcceptedSequence = 3,
                IssuedAtUtc = now.AddMinutes(-1),
                ExpiresAtUtc = now.AddDays(8),
                StartupStub = new EnterpriseStartupStubCompatibility
                {
                    MinimumProtocol = EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                    MaximumProtocol = EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                },
                RevokedReleaseSetIds = [],
                Artifacts = artifacts,
                Signature = unsigned,
            };
            artifacts = artifacts.Select(artifact => artifact with
            {
                Signature = SignPolicyPayload(
                    KeyId,
                    EnterpriseReleaseCanonicalJson.ArtifactPayload(placeholder, artifact)),
            }).ToArray();
            var manifest = placeholder with { Artifacts = artifacts };
            manifest = manifest with
            {
                Signature = SignPolicyPayload(
                    KeyId,
                    EnterpriseReleaseCanonicalJson.ManifestPayload(manifest)),
            };
            var manifestPath = Path.Combine(sourceRoot, "release-set.v2.json");
            var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(
                manifest,
                new JsonSerializerOptions(JsonSerializerDefaults.Web));
            File.WriteAllBytes(manifestPath, manifestBytes);
            var manifestSha = HashBytes(manifestBytes);
            var publishedAt = now.AddMinutes(1);
            var journalPath = Path.Combine(sourceRoot, "promotion-journal.json");
            File.WriteAllText(
                journalPath,
                JsonSerializer.Serialize(new
                {
                    schemaVersion = 1,
                    channel = "pilot",
                    releaseSetId = "pilot-8",
                    generation = 8,
                    sequence = 8,
                    minAcceptedSequence = 3,
                    manifestSha256 = manifestSha,
                    previousEntrySha256 = new string('0', 64),
                    artifacts = artifacts.Select(artifact => new
                    {
                        component = artifact.Component,
                        releaseId = artifact.ReleaseId,
                        fileName = Path.GetFileName(artifact.Uri.AbsolutePath),
                        sizeBytes = artifact.SizeBytes,
                        sha256 = artifact.Sha256,
                    }),
                    publishedAtUtc = publishedAt.ToString(
                        "yyyy-MM-dd'T'HH:mm:ss'Z'",
                        System.Globalization.CultureInfo.InvariantCulture),
                }),
                new UTF8Encoding(false));
            var journalSha = HashFile(journalPath);
            var promotionResultPath = Path.Combine(
                sourceRoot,
                "promotion-result.v1.json");
            File.WriteAllText(
                promotionResultPath,
                JsonSerializer.Serialize(new
                {
                    schemaVersion = 1,
                    product = "ensou-dsh-enterprise",
                    environment = "production",
                    channel = "pilot",
                    releaseSetId = "pilot-8",
                    generation = 8,
                    sequence = 8,
                    minAcceptedSequence = 3,
                    manifestSha256 = manifestSha,
                    channelManifestPath =
                        "/srv/ensou-dsh-enterprise-feed/public/channels/pilot/release-set.v2.json",
                    promotionJournalEntryPath =
                        $"/srv/ensou-dsh-enterprise-feed/journal/pilot/{8:D20}-pilot-8-{manifestSha}.json",
                    promotionJournalSha256 = journalSha,
                    publishedAtUtc = publishedAt.ToString(
                        "yyyy-MM-dd'T'HH:mm:ss'Z'",
                        System.Globalization.CultureInfo.InvariantCulture),
                }),
                new UTF8Encoding(false));

            var output = Path.Combine(sourceRoot, "handoff.v1.json");
            var journalBefore = HashFile(journalPath);
            var manifestBefore = HashFile(manifestPath);
            var promotionResultBefore = HashFile(promotionResultPath);
            var privateKeyBefore = HashFile(PrivateKeyPath);
            var handoff = EnterprisePolicyHandoffCommand.Sign(
                new EnterprisePolicyHandoffSigningOptions(
                    journalPath,
                    manifestPath,
                    promotionResultPath,
                    "production",
                    PrivateKeyPath,
                    KeyId,
                    output,
                    168,
                    24),
                now.AddMinutes(2),
                () =>
                {
                    AssertFileReplacementDenied(() => ReplacePathAtomically(
                        journalPath,
                        "{\"attacker\":true}\n"u8));
                    AssertFileReplacementDenied(() => ReplacePathAtomically(
                        manifestPath,
                        "{\"attacker\":true}\n"u8));
                    AssertFileReplacementDenied(() => ReplacePathAtomically(
                        promotionResultPath,
                        "{\"attacker\":true}\n"u8));
                    AssertFileReplacementDenied(() => ReplacePathAtomically(
                        PrivateKeyPath,
                        RandomNumberGenerator.GetBytes(138)));
                });
            var publicParameters = _signer.ExportParameters(includePrivateParameters: false);
            handoff.Verify(
                "production",
                [
                    new EnterpriseReleasePublicKey(
                        KeyId,
                        PublisherRuntimeAdmissionEncoding.EncodeBase64Url(publicParameters.Q.X!),
                        PublisherRuntimeAdmissionEncoding.EncodeBase64Url(publicParameters.Q.Y!)),
                ],
                now.AddMinutes(2),
                TimeSpan.Zero);
            AssertEqual(HashFile(journalPath), handoff.PromotionJournalSha256);
            AssertEqual(HashFile(promotionResultPath), handoff.PromotionResultSha256);
            AssertFalse(string.Equals(
                Path.GetFullPath(manifestPath),
                "/srv/ensou-dsh-enterprise-feed/public/channels/pilot/release-set.v2.json",
                StringComparison.Ordinal));
            AssertEqual(journalBefore, HashFile(journalPath));
            AssertEqual(manifestBefore, HashFile(manifestPath));
            AssertEqual(promotionResultBefore, HashFile(promotionResultPath));
            AssertEqual(privateKeyBefore, HashFile(PrivateKeyPath));
            AssertThrows<InvalidDataException>(() =>
                (handoff with { PromotionResultSha256 = new string('f', 64) }).Verify(
                    "production",
                    [
                        new EnterpriseReleasePublicKey(
                            KeyId,
                            PublisherRuntimeAdmissionEncoding.EncodeBase64Url(publicParameters.Q.X!),
                            PublisherRuntimeAdmissionEncoding.EncodeBase64Url(publicParameters.Q.Y!)),
                    ],
                    now.AddMinutes(2),
                    TimeSpan.Zero));
            PromotionResultSource.RequireReceiptPaths(
                "development-e2e",
                "lab",
                8,
                "pilot-8",
                manifestSha,
                manifestPath,
                journalPath,
                manifestPath,
                journalPath);
            AssertThrows<InvalidDataException>(() =>
                PromotionResultSource.RequireReceiptPaths(
                    "development-e2e",
                    "lab",
                    8,
                    "pilot-8",
                    manifestSha,
                    manifestPath,
                    journalPath,
                    Path.Combine(sourceRoot, "different-manifest.json"),
                    journalPath));

            var tamperedPromotionResultPath = Path.Combine(
                sourceRoot,
                "tampered-promotion-result.v1.json");
            var tamperedPromotionResult = JsonNode.Parse(
                File.ReadAllText(promotionResultPath))!.AsObject();
            tamperedPromotionResult["promotionJournalSha256"] = new string('f', 64);
            File.WriteAllText(
                tamperedPromotionResultPath,
                tamperedPromotionResult.ToJsonString(),
                new UTF8Encoding(false));
            AssertThrows<InvalidDataException>(() =>
                EnterprisePolicyHandoffCommand.Sign(
                    new EnterprisePolicyHandoffSigningOptions(
                        journalPath,
                        manifestPath,
                        tamperedPromotionResultPath,
                        "production",
                        PrivateKeyPath,
                        KeyId,
                        Path.Combine(sourceRoot, "tampered-result-handoff.json"),
                        168,
                        24),
                    now.AddMinutes(2)));

            var wrongPathPromotionResultPath = Path.Combine(
                sourceRoot,
                "wrong-path-promotion-result.v1.json");
            var wrongPathPromotionResult = JsonNode.Parse(
                File.ReadAllText(promotionResultPath))!.AsObject();
            wrongPathPromotionResult["channelManifestPath"] = Path.Combine(
                sourceRoot,
                "not-the-locked-channel-manifest.json");
            File.WriteAllText(
                wrongPathPromotionResultPath,
                wrongPathPromotionResult.ToJsonString(),
                new UTF8Encoding(false));
            AssertThrows<InvalidDataException>(() =>
                EnterprisePolicyHandoffCommand.Sign(
                    new EnterprisePolicyHandoffSigningOptions(
                        journalPath,
                        manifestPath,
                        wrongPathPromotionResultPath,
                        "production",
                        PrivateKeyPath,
                        KeyId,
                        Path.Combine(sourceRoot, "wrong-result-path-handoff.json"),
                        168,
                        24),
                    now.AddMinutes(2)));

            var duplicatePromotionResultPath = Path.Combine(
                sourceRoot,
                "duplicate-promotion-result.v1.json");
            File.WriteAllText(
                duplicatePromotionResultPath,
                "{\"schemaVersion\":1," + File.ReadAllText(promotionResultPath)[1..],
                new UTF8Encoding(false));
            AssertThrows<JsonException>(() =>
                EnterprisePolicyHandoffCommand.Sign(
                    new EnterprisePolicyHandoffSigningOptions(
                        journalPath,
                        manifestPath,
                        duplicatePromotionResultPath,
                        "production",
                        PrivateKeyPath,
                        KeyId,
                        Path.Combine(sourceRoot, "duplicate-result-handoff.json"),
                        168,
                        24),
                    now.AddMinutes(2)));

            var exactBoundary = EnterprisePolicyHandoffCommand.Sign(
                new EnterprisePolicyHandoffSigningOptions(
                    journalPath,
                    manifestPath,
                    promotionResultPath,
                    "production",
                    PrivateKeyPath,
                    KeyId,
                    Path.Combine(sourceRoot, "exact-expiry-handoff.json"),
                    168,
                    24),
                now.AddDays(1));
            AssertEqual(manifest.ExpiresAtUtc, exactBoundary.ExpiresAtUtc);
            AssertThrows<InvalidDataException>(() =>
                EnterprisePolicyHandoffCommand.Sign(
                    new EnterprisePolicyHandoffSigningOptions(
                        journalPath,
                        manifestPath,
                        promotionResultPath,
                        "production",
                        PrivateKeyPath,
                        KeyId,
                        Path.Combine(sourceRoot, "over-expiry-handoff.json"),
                        168,
                        24),
                    now.AddDays(1).AddSeconds(1)));
            AssertThrows<InvalidDataException>(() =>
                EnterprisePolicyHandoffCommand.Sign(
                    new EnterprisePolicyHandoffSigningOptions(
                        journalPath,
                        manifestPath,
                        promotionResultPath,
                        "production",
                        PrivateKeyPath,
                        KeyId,
                        Path.Combine(sourceRoot, "expired-manifest-handoff.json"),
                        1,
                        0),
                    now.AddDays(8).AddMinutes(3)));
            AssertThrows<InvalidDataException>(() =>
                EnterprisePolicyHandoffCommand.Sign(
                    new EnterprisePolicyHandoffSigningOptions(
                        journalPath,
                        manifestPath,
                        promotionResultPath,
                        "production",
                        PrivateKeyPath,
                        KeyId,
                        Path.Combine(sourceRoot, "future-journal-handoff.json"),
                        1,
                        0),
                    now));

            var mismatchedManifestPath = Path.Combine(sourceRoot, "mismatched-release-set.v2.json");
            File.WriteAllBytes(
                mismatchedManifestPath,
                Encoding.UTF8.GetBytes(
                    Encoding.UTF8.GetString(manifestBytes).Replace(
                        "\"sequence\":8",
                        "\"sequence\":9",
                        StringComparison.Ordinal)));
            AssertThrows<InvalidDataException>(() =>
                EnterprisePolicyHandoffCommand.Sign(
                    new EnterprisePolicyHandoffSigningOptions(
                        journalPath,
                        mismatchedManifestPath,
                        promotionResultPath,
                        "production",
                        PrivateKeyPath,
                        KeyId,
                        Path.Combine(sourceRoot, "mismatch-handoff.json"),
                        168,
                        24),
                    now.AddMinutes(2)));

            AssertThrows<InvalidDataException>(() =>
                EnterprisePolicyHandoffCommand.Sign(
                    new EnterprisePolicyHandoffSigningOptions(
                        journalPath,
                        manifestPath,
                        promotionResultPath,
                        "production",
                        PrivateKeyPath,
                        "wrong-key-id",
                        Path.Combine(sourceRoot, "wrong-id-handoff.json"),
                        168,
                        24),
                    now.AddMinutes(2)));

            using var attacker = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var attackerPath = Path.Combine(sourceRoot, "attacker.pk8");
            File.WriteAllBytes(attackerPath, attacker.ExportPkcs8PrivateKey());
            AssertThrows<InvalidDataException>(() =>
                EnterprisePolicyHandoffCommand.Sign(
                    new EnterprisePolicyHandoffSigningOptions(
                        journalPath,
                        manifestPath,
                        promotionResultPath,
                        "production",
                        attackerPath,
                        KeyId,
                        Path.Combine(sourceRoot, "wrong-key-handoff.json"),
                        168,
                        24),
                    now.AddMinutes(2)));

            var junction = Path.Combine(TempRoot, $"policy-handoff-link-{Guid.NewGuid():N}");
            if (TryCreateDirectoryJunction(junction, Root))
            {
                try
                {
                    var linkedSourceRoot = Path.Combine(junction, "policy-handoff");
                    AssertThrows<InvalidDataException>(() =>
                        EnterprisePolicyHandoffCommand.Sign(
                            new EnterprisePolicyHandoffSigningOptions(
                                Path.Combine(linkedSourceRoot, "promotion-journal.json"),
                                manifestPath,
                                promotionResultPath,
                                "production",
                                PrivateKeyPath,
                                KeyId,
                                Path.Combine(sourceRoot, "linked-journal-handoff.json"),
                                168,
                                24),
                            now.AddMinutes(2)));
                    AssertThrows<InvalidDataException>(() =>
                        EnterprisePolicyHandoffCommand.Sign(
                            new EnterprisePolicyHandoffSigningOptions(
                                journalPath,
                                manifestPath,
                                Path.Combine(linkedSourceRoot, "promotion-result.v1.json"),
                                "production",
                                PrivateKeyPath,
                                KeyId,
                                Path.Combine(sourceRoot, "linked-result-handoff.json"),
                                168,
                                24),
                            now.AddMinutes(2)));
                    AssertThrows<InvalidDataException>(() =>
                        EnterprisePolicyHandoffCommand.Sign(
                            new EnterprisePolicyHandoffSigningOptions(
                                journalPath,
                                Path.Combine(linkedSourceRoot, "release-set.v2.json"),
                                promotionResultPath,
                                "production",
                                PrivateKeyPath,
                                KeyId,
                                Path.Combine(sourceRoot, "linked-manifest-handoff.json"),
                                168,
                                24),
                            now.AddMinutes(2)));
                    AssertThrows<InvalidDataException>(() =>
                        EnterprisePolicyHandoffCommand.Sign(
                            new EnterprisePolicyHandoffSigningOptions(
                                journalPath,
                                manifestPath,
                                promotionResultPath,
                                "production",
                                Path.Combine(junction, "publisher.pk8"),
                                KeyId,
                                Path.Combine(sourceRoot, "linked-key-handoff.json"),
                                168,
                                24),
                            now.AddMinutes(2)));
                    AssertThrows<InvalidDataException>(() =>
                        EnterprisePolicyHandoffCommand.Sign(
                            new EnterprisePolicyHandoffSigningOptions(
                                journalPath,
                                manifestPath,
                                promotionResultPath,
                                "production",
                                PrivateKeyPath,
                                KeyId,
                                Path.Combine(linkedSourceRoot, "linked-output-handoff.json"),
                                168,
                                24),
                            now.AddMinutes(2)));
                }
                finally
                {
                    Directory.Delete(junction);
                }
            }
        }

        private EnterpriseReleaseSignature SignPolicyPayload(
            string keyId,
            ReadOnlySpan<byte> payload) => new()
            {
                Algorithm = "ES256",
                KeyId = keyId,
                Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(_signer.SignData(
                    payload,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
            };

        public async Task<ProcessResult> RunWithPrivateKeyPathAsync(
            long sequence,
            string outputName,
            string privateKeyPath)
        {
            var prepared = Prepare(sequence, outputName, privateKeyPath);
            return await RunProcessAsync(prepared.ProcessArguments).ConfigureAwait(false);
        }

        public Task<ProcessResult> RunAdmissionScenarioAsync(
            long sequence,
            string outputName,
            RuntimeAdmissionScenario scenario)
        {
            var prepared = Prepare(sequence, outputName, PrivateKeyPath, scenario);
            return RunProcessAsync(prepared.ProcessArguments);
        }

        public Task<ProcessResult> RunPreparedAsync(PreparedPublisherRun prepared) =>
            RunProcessAsync(prepared.ProcessArguments);

        public PreparedPublisherRun Prepare(
            long sequence,
            string outputName,
            string? privateKeyPath = null,
            RuntimeAdmissionScenario scenario = RuntimeAdmissionScenario.Valid)
        {
            var launcher = Path.Combine(Root, $"launcher-{sequence}.zip");
            var runtime = Path.Combine(Root, $"runtime-{sequence}.zip");
            var plugin = Path.Combine(Root, $"managed-plugin-policy-{sequence}.zip");
            var pluginMetadata = Path.Combine(
                Root,
                $"managed-plugin-policy-{sequence}.artifact.json");
            var runtimeReleaseId = $"managed-v2026.08.25.{sequence}";
            var launcherReleaseId = $"launcher-{sequence}";
            CreateOpaqueArchive(
                launcher,
                "launcher.bin",
                RandomNumberGenerator.GetBytes(131 + (int)sequence));
            CreateOpaqueArchive(
                runtime,
                "runtime.bin",
                RandomNumberGenerator.GetBytes(197 + (int)sequence));
            var admission = CreateRuntimeAdmission(
                runtime,
                runtimeReleaseId,
                scenario);
            File.Delete(plugin);
            File.Delete(pluginMetadata);
            CreatePluginPolicyPackage(
                plugin,
                pluginMetadata,
                launcherReleaseId,
                runtimeReleaseId,
                metadataDrift: false);
            var environment = scenario is RuntimeAdmissionScenario.ForgedProductionConfig
                or RuntimeAdmissionScenario.MissingProductionTrust
                ? EnterpriseReleaseSetContract.ProductionEnvironment
                : EnterpriseReleaseSetContract.DevelopmentE2EEnvironment;
            var config = Path.Combine(Root, $"config-{outputName}.json");
            File.WriteAllText(config, JsonSerializer.Serialize(new
            {
                environment,
                channel = "pilot",
                releaseSetId = $"publisher-set-{sequence}",
                keyId = "publisher-test-key",
                generation = 1,
                sequence,
                minAcceptedSequence = 0,
                expiresAtUtc = DateTimeOffset.UtcNow.AddDays(2),
                startupStub = new
                {
                    minimumProtocol = EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                    maximumProtocol = EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                },
                manifestOrigin = "https://updates.example/",
                artifactOrigin = "https://artifacts.example/",
                revokedReleaseSetIds = Array.Empty<string>(),
                developmentRuntimeAdmissionTrust = scenario == RuntimeAdmissionScenario.MissingProductionTrust
                    ? null
                    : _admissionTrust,
                artifacts = new object[]
                {
                    new
                    {
                        component = "launcher",
                        releaseId = launcherReleaseId,
                        filePath = launcher,
                        uri = $"https://artifacts.example/launcher-{sequence}.zip",
                    },
                    new
                    {
                        component = "runtime",
                        releaseId = runtimeReleaseId,
                        filePath = runtime,
                        uri = scenario == RuntimeAdmissionScenario.ArtifactFileNameMismatch
                            ? "https://artifacts.example/different-runtime-name.zip"
                            : $"https://artifacts.example/runtime-{sequence}.zip",
                        sourceRuntimeMetadataPath = scenario == RuntimeAdmissionScenario.MissingMetadata
                            ? null
                            : admission.MetadataPath,
                        organizationAdmissionReceiptPath = scenario == RuntimeAdmissionScenario.MissingReceipt
                            ? null
                            : admission.ReceiptPath,
                    },
                    new
                    {
                        component = "plugin-policy",
                        releaseId = $"plugins-{sequence}",
                        filePath = plugin,
                        uri = $"https://artifacts.example/managed-plugin-policy-{sequence}.zip",
                        policyMetadataPath = pluginMetadata,
                    },
                },
            }, new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true }));
            var arguments = new PublisherArguments(
                config,
                privateKeyPath ?? PrivateKeyPath,
                LedgerPath,
                Path.Combine(Root, outputName));
            return new PreparedPublisherRun(
                arguments,
                admission.MetadataPath,
                admission.ReceiptPath,
                [
                    "--config", arguments.ConfigPath,
                    "--private-key-file", arguments.PrivateKeyPath,
                    "--ledger", arguments.LedgerPath,
                    "--output", arguments.OutputDirectory,
                ]);
        }

        public async Task<ProcessResult> RunWithPluginAsync(
            long sequence,
            string outputName,
            bool rawSkillCandidate = false,
            bool metadataDrift = false)
        {
            var launcherReleaseId = $"launcher-{sequence}";
            var runtimeReleaseId = $"managed-v2026.08.25.{sequence}";
            var launcher = Path.Combine(Root, $"{launcherReleaseId}.zip");
            var runtime = Path.Combine(Root, $"runtime-{sequence}.zip");
            CreateOpaqueArchive(
                launcher,
                "launcher.bin",
                RandomNumberGenerator.GetBytes(131 + (int)sequence));
            CreateOpaqueArchive(
                runtime,
                "runtime.bin",
                RandomNumberGenerator.GetBytes(197 + (int)sequence));
            var runtimeAdmission = CreateRuntimeAdmission(
                runtime,
                runtimeReleaseId,
                RuntimeAdmissionScenario.Valid);
            var plugin = Path.Combine(Root, $"managed-plugin-policy-{sequence}.zip");
            var metadata = Path.Combine(Root, $"managed-plugin-policy-{sequence}.artifact.json");
            if (rawSkillCandidate)
            {
                using (var archive = ZipFile.Open(plugin, ZipArchiveMode.Create))
                {
                    WriteZipEntry(archive, "mail-manager/SKILL.md", "candidate-only\n"u8);
                }
                File.WriteAllText(metadata, "{}", new UTF8Encoding(false));
            }
            else
            {
                CreatePluginPolicyPackage(
                    plugin,
                    metadata,
                    launcherReleaseId,
                    runtimeReleaseId,
                    metadataDrift);
            }

            var config = Path.Combine(Root, $"config-{outputName}.json");
            File.WriteAllText(config, JsonSerializer.Serialize(new
            {
                environment = "development-e2e",
                channel = "pilot",
                releaseSetId = $"publisher-set-{sequence}",
                keyId = "publisher-test-key",
                generation = 1,
                sequence,
                minAcceptedSequence = 0,
                expiresAtUtc = DateTimeOffset.UtcNow.AddDays(2),
                startupStub = new
                {
                    minimumProtocol = EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                    maximumProtocol = EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                },
                manifestOrigin = "https://updates.example/",
                artifactOrigin = "https://artifacts.example/",
                revokedReleaseSetIds = Array.Empty<string>(),
                developmentRuntimeAdmissionTrust = _admissionTrust,
                artifacts = new object[]
                {
                    new
                    {
                        component = "launcher",
                        releaseId = launcherReleaseId,
                        filePath = launcher,
                        uri = $"https://artifacts.example/{launcherReleaseId}.zip",
                    },
                    new
                    {
                        component = "runtime",
                        releaseId = runtimeReleaseId,
                        filePath = runtime,
                        uri = $"https://artifacts.example/runtime-{sequence}.zip",
                        sourceRuntimeMetadataPath = runtimeAdmission.MetadataPath,
                        organizationAdmissionReceiptPath = runtimeAdmission.ReceiptPath,
                    },
                    new
                    {
                        component = "plugin-policy",
                        releaseId = $"plugins-{sequence}",
                        filePath = plugin,
                        uri = $"https://artifacts.example/managed-plugin-policy-{sequence}.zip",
                        policyMetadataPath = metadata,
                    },
                },
            }, new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true }));
            return await RunProcessAsync(
                "--config", config,
                "--private-key-file", PrivateKeyPath,
                "--ledger", LedgerPath,
                "--output", Path.Combine(Root, outputName)).ConfigureAwait(false);
        }

        public Task<ProcessResult> RunWithRawKeyArgumentAsync(string secret)
        {
            var dummy = Path.Combine(Root, "dummy.json");
            File.WriteAllText(dummy, "{}");
            return RunProcessAsync(
                "--config", dummy,
                "--private-key", secret,
                "--ledger", LedgerPath,
                "--output", Path.Combine(Root, "raw-key"));
        }

        public void AssertCompletePilotReadinessAdmits() =>
            AssertCompletePilotReadiness(
                PilotLocalDataCertificationScenario.Valid,
                PilotClientBindingScenario.Valid);

        public void AssertPilotReadinessCertificationRejected(
            PilotLocalDataCertificationScenario scenario)
        {
            if (scenario == PilotLocalDataCertificationScenario.Valid)
            {
                throw new ArgumentException("A rejection scenario is required.", nameof(scenario));
            }
            AssertCompletePilotReadiness(scenario);
        }

        public void AssertPilotReadinessClientBindingRejected(
            PilotClientBindingScenario scenario)
        {
            if (scenario == PilotClientBindingScenario.Valid)
            {
                throw new ArgumentException("A client binding rejection scenario is required.", nameof(scenario));
            }
            AssertCompletePilotReadiness(
                PilotLocalDataCertificationScenario.Valid,
                scenario);
        }

        private void AssertCompletePilotReadiness(
            PilotLocalDataCertificationScenario certificationScenario,
            PilotClientBindingScenario clientBindingScenario = PilotClientBindingScenario.Valid)
        {
            const string releaseKeyId = "release-pilot-test-key";
            const string releaseSetId = "enterprise-pilot-complete-1";
            const string launcherReleaseId = "launcher-production-1";
            const string runtimeReleaseId = "managed-v2026.08.25.99";
            const string pluginReleaseId = "plugins-production-1";
            var releaseDirectory = Path.Combine(Root, "pilot-release");
            Directory.CreateDirectory(releaseDirectory);

            var launcherExecutable = Path.Combine(
                Root,
                EnterpriseInstallationLayout.LauncherExecutableName);
            var launcherBytes = RandomNumberGenerator.GetBytes(1024);
            File.WriteAllBytes(launcherExecutable, launcherBytes);
            var clientBootstrapperExecutable = Path.Combine(
                Root,
                EnterpriseInstallationLayout.ClientBootstrapperExecutableName);
            var clientBootstrapperBytes = RandomNumberGenerator.GetBytes(1024);
            File.WriteAllBytes(clientBootstrapperExecutable, clientBootstrapperBytes);
            var maintenanceExecutable = Path.Combine(
                Root,
                EnterpriseInstallationLayout.MaintenanceExecutableName);
            var maintenanceBytes = RandomNumberGenerator.GetBytes(1024);
            File.WriteAllBytes(maintenanceExecutable, maintenanceBytes);
            var buildProfile = new
            {
                schemaVersion = 1,
                layoutProfile = EnterpriseInstallationLayout.ProductionLayoutProfile,
            };
            var buildProfileBytes = JsonSerializer.SerializeToUtf8Bytes(
                buildProfile,
                new JsonSerializerOptions(JsonSerializerDefaults.Web));
            var archiveBuildProfileBytes = clientBindingScenario ==
                PilotClientBindingScenario.MismatchedBuildProfileMarker
                    ? JsonSerializer.SerializeToUtf8Bytes(
                        buildProfile,
                        new JsonSerializerOptions(JsonSerializerDefaults.Web)
                        {
                            WriteIndented = true,
                        })
                    : buildProfileBytes;
            var launcherArchive = Path.Combine(releaseDirectory, "launcher-production-1.zip");
            using (var archive = ZipFile.Open(launcherArchive, ZipArchiveMode.Create))
            {
                WriteZipEntry(
                    archive,
                    EnterpriseInstallationLayout.LauncherExecutableName,
                    launcherBytes);
                WriteZipEntry(
                    archive,
                    EnterpriseInstallationLayout.ClientBootstrapperExecutableName,
                    clientBindingScenario ==
                        PilotClientBindingScenario.MismatchedClientBootstrapper
                            ? RandomNumberGenerator.GetBytes(1024)
                            : clientBootstrapperBytes);
                WriteZipEntry(
                    archive,
                    EnterpriseInstallationLayout.MaintenanceExecutableName,
                    clientBindingScenario == PilotClientBindingScenario.MismatchedMaintenance
                        ? RandomNumberGenerator.GetBytes(1024)
                        : maintenanceBytes);
                WriteZipEntry(
                    archive,
                    EnterpriseInstallationLayout.BuildProfileMarkerFileName,
                    archiveBuildProfileBytes);
            }

            var runtimeArchive = Path.Combine(releaseDirectory, "runtime-production-1.zip");
            CreateOpaqueArchive(
                runtimeArchive,
                "runtime.bin",
                RandomNumberGenerator.GetBytes(2048));
            var runtimeAdmission = CreateRuntimeAdmission(
                runtimeArchive,
                runtimeReleaseId,
                RuntimeAdmissionScenario.Valid);
            using var runtimeMetadataDocument = JsonDocument.Parse(
                File.ReadAllBytes(runtimeAdmission.MetadataPath));
            var targetUpstreamTag = runtimeMetadataDocument.RootElement
                .GetProperty("sourceTag").GetString()
                ?? throw new InvalidDataException("Pilot fixture sourceTag is absent.");

            var pluginArchive = Path.Combine(releaseDirectory, "plugins-production-1.zip");
            var pluginMetadata = Path.Combine(Root, "plugins-production-1.artifact.json");
            CreatePluginPolicyPackage(
                pluginArchive,
                pluginMetadata,
                launcherReleaseId,
                runtimeReleaseId,
                metadataDrift: false);

            EnterpriseReleaseArtifact CreateArtifact(
                string component,
                string releaseId,
                string path)
            {
                return new EnterpriseReleaseArtifact
                {
                    Component = component,
                    ReleaseId = releaseId,
                    Uri = new Uri($"https://artifacts.acme-corp.com/{Path.GetFileName(path)}"),
                    SizeBytes = new FileInfo(path).Length,
                    Sha256 = HashFile(path),
                    CompleteTreeSha256 = HashFile(path),
                    Signature = new EnterpriseReleaseSignature
                    {
                        Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
                        KeyId = releaseKeyId,
                        Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(new byte[64]),
                    },
                };
            }

            var now = DateTimeOffset.UtcNow;
            var manifest = new EnterpriseReleaseSetManifest
            {
                SchemaVersion = EnterpriseReleaseSetContract.SchemaVersion,
                Product = EnterpriseReleaseSetContract.Product,
                Environment = EnterpriseReleaseSetContract.ProductionEnvironment,
                Channel = "pilot",
                ReleaseSetId = releaseSetId,
                Generation = 1,
                Sequence = 1,
                MinAcceptedSequence = 0,
                IssuedAtUtc = now,
                ExpiresAtUtc = now.AddDays(2),
                StartupStub = new EnterpriseStartupStubCompatibility
                {
                    MinimumProtocol = EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                    MaximumProtocol = EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                },
                RevokedReleaseSetIds = [],
                Artifacts =
                [
                    CreateArtifact(
                        EnterpriseReleaseSetContract.LauncherComponent,
                        launcherReleaseId,
                        launcherArchive),
                    CreateArtifact(
                        EnterpriseReleaseSetContract.RuntimeComponent,
                        runtimeReleaseId,
                        runtimeArchive),
                    CreateArtifact(
                        EnterpriseReleaseSetContract.PluginPolicyComponent,
                        pluginReleaseId,
                        pluginArchive),
                ],
                Signature = new EnterpriseReleaseSignature
                {
                    Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
                    KeyId = releaseKeyId,
                    Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(new byte[64]),
                },
            };
            manifest = manifest with
            {
                Artifacts = manifest.Artifacts.Select(artifact => artifact with
                {
                    Signature = artifact.Signature with
                    {
                        Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(
                            _signer.SignData(
                                EnterpriseReleaseCanonicalJson.ArtifactPayload(manifest, artifact),
                                HashAlgorithmName.SHA256,
                                DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
                    },
                }).ToArray(),
            };
            manifest = manifest with
            {
                Signature = manifest.Signature with
                {
                    Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(
                        _signer.SignData(
                            EnterpriseReleaseCanonicalJson.ManifestPayload(manifest),
                            HashAlgorithmName.SHA256,
                            DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
                },
            };
            var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web)
            {
                WriteIndented = true,
            };
            var manifestPath = Path.Combine(releaseDirectory, "release-set.v2.json");
            File.WriteAllText(
                manifestPath,
                JsonSerializer.Serialize(manifest, jsonOptions),
                new UTF8Encoding(false));
            var releaseParameters = _signer.ExportParameters(includePrivateParameters: false);
            var releasePublicKey = new EnterpriseReleasePublicKey(
                releaseKeyId,
                PublisherRuntimeAdmissionEncoding.EncodeBase64Url(releaseParameters.Q.X!),
                PublisherRuntimeAdmissionEncoding.EncodeBase64Url(releaseParameters.Q.Y!));
            File.WriteAllText(
                Path.Combine(releaseDirectory, "release-public-key.v2.json"),
                JsonSerializer.Serialize(releasePublicKey, jsonOptions),
                new UTF8Encoding(false));

            var ledgerPath = Path.Combine(Root, "pilot-publisher-ledger.v2.json");
            var ledger = new PublisherLedger(
                2,
                EnterpriseReleaseSetContract.ProductionEnvironment,
                "pilot",
                1,
                1,
                0,
                releaseSetId,
                HashBytes(EnterpriseReleaseCanonicalJson.ManifestPayload(manifest)),
                now);
            File.WriteAllText(
                ledgerPath,
                JsonSerializer.Serialize(ledger, jsonOptions),
                new UTF8Encoding(false));

            var migrationReportPath = Path.Combine(
                Root,
                "pilot-local-data-compatibility.json");
            var sourceRuntimeArchiveSha256 = new string('9', 64);
            var targetRuntimeArchiveSha256 = HashFile(runtimeArchive);
            WriteLocalDataCompatibilityEvidence(
                migrationReportPath,
                sourceRuntimeArchiveSha256,
                targetRuntimeArchiveSha256,
                rollbackUsedPreUpgradeBackup: true,
                allApiLanesCovered: true,
                fromUpstreamTag: "dsh-v0.1.0-rc.6",
                toUpstreamTag: targetUpstreamTag);
            var installerExecutable = Path.Combine(
                Root,
                EnterpriseInstallationLayout.InstallerExecutableName);
            var bootstrapperExecutable = Path.Combine(
                Root,
                EnterpriseInstallationLayout.BootstrapperExecutableName);
            File.WriteAllBytes(installerExecutable, RandomNumberGenerator.GetBytes(1024));
            File.WriteAllBytes(bootstrapperExecutable, RandomNumberGenerator.GetBytes(1024));
            File.WriteAllBytes(
                Path.Combine(
                    Root,
                    EnterpriseInstallationLayout.BuildProfileMarkerFileName),
                buildProfileBytes);

            using var leaseSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var leaseParameters = leaseSigner.ExportParameters(includePrivateParameters: false);
            var leaseTrust = new PublisherLeaseVerificationTrust
            {
                KeyId = "lease-pilot-test-key",
                X = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(leaseParameters.Q.X!),
                Y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(leaseParameters.Q.Y!),
            };
            using var brandSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var brandParameters = brandSigner.ExportParameters(includePrivateParameters: false);
            var brandTrust = new PublisherBrandAuthorizationTrust
            {
                KeyId = "brand-authorization-pilot-test-key",
                X = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(brandParameters.Q.X!),
                Y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(brandParameters.Q.Y!),
            };
            var brandEvidencePath = Path.Combine(Root, "pilot-brand-authorization.pdf");
            File.WriteAllText(
                brandEvidencePath,
                "retained written authorization for the exact named-customer Pilot brand use",
                new UTF8Encoding(false));
            var brandReceipt = new PublisherBrandAuthorizationReceipt
            {
                SchemaVersion = PublisherBrandAuthorizationReceipt.CurrentSchemaVersion,
                ReceiptType = PublisherBrandAuthorizationReceipt.CurrentReceiptType,
                AuthorizationId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                Decision = PublisherBrandAuthorizationReceipt.AuthorizedDecision,
                Environment = PublisherBrandAuthorizationReceipt.ProductionEnvironment,
                Channel = PublisherBrandAuthorizationReceipt.PilotChannel,
                DistributionScope = PublisherBrandAuthorizationReceipt.NamedCustomerPilotScope,
                DistributionAudienceId = "11111111-1111-4111-8111-111111111111",
                ReleaseBinding = new PublisherBrandReleaseReceiptBinding
                {
                    ReleaseSetId = releaseSetId,
                    Generation = 1,
                    Sequence = 1,
                    ReleaseSetManifestSha256 = HashFile(manifestPath),
                    LauncherReleaseId = launcherReleaseId,
                    LauncherArchiveSha256 = HashFile(launcherArchive),
                },
                Brand = new PublisherBrandReceiptProfile
                {
                    BrandProfileId = EnterpriseBrandContract.BrandProfileId,
                    BrandProfileSha256 = EnterpriseBrandContract.ProfileSha256,
                    ProductFamilyName = EnterpriseBrandContract.ProductFamilyName,
                    LauncherProductName = EnterpriseBrandContract.LauncherProductName,
                    InstallerProductName = EnterpriseBrandContract.InstallerProductName,
                    BootstrapperProductName = EnterpriseBrandContract.BootstrapperProductName,
                    DeveloperName = EnterpriseBrandContract.DeveloperName,
                    PresentationSha256 = EnterpriseBrandContract.PresentationSha256,
                    OfficialWhaleSvgSha256 = EnterpriseBrandContract.OfficialWhaleSvgSha256,
                    LauncherWhalePngSha256 = EnterpriseBrandContract.LauncherWhalePngSha256,
                    WindowsWhaleIcoSha256 = EnterpriseBrandContract.WindowsWhaleIcoSha256,
                },
                Evidence = new PublisherBrandReceiptEvidence
                {
                    DocumentSha256 = HashFile(brandEvidencePath),
                    SizeBytes = new FileInfo(brandEvidencePath).Length,
                    MediaType = "application/pdf",
                },
                Binaries = new PublisherBrandReceiptBinaries
                {
                    LauncherExecutableSha256 = HashFile(launcherExecutable),
                    BootstrapperExecutableSha256 = HashFile(bootstrapperExecutable),
                    InstallerExecutableSha256 = HashFile(installerExecutable),
                },
                ReviewedAtUnixSeconds = now.AddMinutes(-1).ToUnixTimeSeconds(),
                NotBeforeUnixSeconds = now.AddMinutes(-2).ToUnixTimeSeconds(),
                ExpiresAtUnixSeconds = now.AddDays(3).ToUnixTimeSeconds(),
                Signature = new EnterpriseReleaseSignature
                {
                    Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
                    KeyId = brandTrust.KeyId,
                    Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(new byte[64]),
                },
            };
            brandReceipt = brandReceipt with
            {
                Signature = brandReceipt.Signature with
                {
                    Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(
                        brandSigner.SignData(
                            PublisherBrandAuthorizationCanonicalJson.Payload(brandReceipt),
                            HashAlgorithmName.SHA256,
                            DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
                },
            };
            var brandReceiptPath = Path.Combine(Root, "pilot-brand-authorization.v1.json");
            File.WriteAllText(
                brandReceiptPath,
                JsonSerializer.Serialize(brandReceipt, jsonOptions),
                new UTF8Encoding(false));

            using var pluginAdmissionSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var pluginAdmissionParameters = pluginAdmissionSigner.ExportParameters(
                includePrivateParameters: false);
            var pluginAdmissionTrust = new PublisherPluginAdmissionTrust
            {
                KeyId = "plugin-admission-pilot-test-key",
                X = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(
                    pluginAdmissionParameters.Q.X!),
                Y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(
                    pluginAdmissionParameters.Q.Y!),
            };
            using var localDataCertificationSigner = ECDsa.Create(
                ECCurve.NamedCurves.nistP256);
            var localDataCertificationParameters = localDataCertificationSigner.ExportParameters(
                includePrivateParameters: false);
            var localDataCertificationTrust =
                new PublisherLocalDataCompatibilityCertificationTrust
                {
                    KeyId = "local-data-certification-pilot-test-key",
                    X = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(
                        localDataCertificationParameters.Q.X!),
                    Y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(
                        localDataCertificationParameters.Q.Y!),
                };
            using var localDataEvidenceDocument = JsonDocument.Parse(
                File.ReadAllBytes(migrationReportPath));
            var runnerSha256 = localDataEvidenceDocument.RootElement
                .GetProperty("testRunner")
                .GetProperty("sha256")
                .GetString() ?? throw new InvalidDataException(
                    "Pilot local-data fixture runner SHA-256 is absent.");
            const string localDataCertificationAudienceId =
                "22222222-2222-4222-8222-222222222222";
            var localDataCertificationReceipt =
                new PublisherLocalDataCompatibilityCertificationReceipt
                {
                    SchemaVersion =
                        PublisherLocalDataCompatibilityCertificationReceipt.CurrentSchemaVersion,
                    ReceiptType =
                        PublisherLocalDataCompatibilityCertificationReceipt.CurrentReceiptType,
                    CertificationId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    Decision =
                        PublisherLocalDataCompatibilityCertificationReceipt.PassedDecision,
                    Environment =
                        PublisherLocalDataCompatibilityCertificationReceipt.ProductionEnvironment,
                    Channel = PublisherLocalDataCompatibilityCertificationReceipt.PilotChannel,
                    DistributionScope =
                        PublisherLocalDataCompatibilityCertificationReceipt.NamedCustomerPilotScope,
                    CertificationAudienceId = localDataCertificationAudienceId,
                    FromUpstreamTag = "dsh-v0.1.0-rc.6",
                    ToUpstreamTag = targetUpstreamTag,
                    SourceRuntimeZipSha256 = sourceRuntimeArchiveSha256,
                    TargetRuntimeZipSha256 = targetRuntimeArchiveSha256,
                    EvidenceReportSha256 = HashFile(migrationReportPath),
                    RunnerSha256 = certificationScenario
                        == PilotLocalDataCertificationScenario.WrongRunnerSha256
                            ? new string('7', 64)
                            : runnerSha256,
                    IssuedAtUnixSeconds = now.AddMinutes(-1).ToUnixTimeSeconds(),
                    ExpiresAtUnixSeconds = now.AddHours(24).ToUnixTimeSeconds(),
                    Signature = new EnterpriseReleaseSignature
                    {
                        Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
                        KeyId = localDataCertificationTrust.KeyId,
                        Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(new byte[64]),
                    },
                };
            localDataCertificationReceipt = localDataCertificationReceipt with
            {
                Signature = localDataCertificationReceipt.Signature with
                {
                    Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(
                        localDataCertificationSigner.SignData(
                            PublisherLocalDataCompatibilityCertificationCanonicalJson.Payload(
                                localDataCertificationReceipt),
                            HashAlgorithmName.SHA256,
                            DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
                },
            };
            var localDataCertificationReceiptPath = Path.Combine(
                Root,
                "pilot-local-data-certification.v1.json");
            File.WriteAllText(
                localDataCertificationReceiptPath,
                JsonSerializer.Serialize(localDataCertificationReceipt, jsonOptions),
                new UTF8Encoding(false));
            if (certificationScenario == PilotLocalDataCertificationScenario.Tampered)
            {
                var tamperedReceipt = JsonNode.Parse(
                    File.ReadAllBytes(localDataCertificationReceiptPath))!.AsObject();
                tamperedReceipt["certificationId"] =
                    "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
                File.WriteAllText(
                    localDataCertificationReceiptPath,
                    tamperedReceipt.ToJsonString(jsonOptions),
                    new UTF8Encoding(false));
            }
            var configPath = Path.Combine(Root, "pilot-readiness-complete.json");
            var configDocument = JsonSerializer.SerializeToNode(new
                {
                    schemaVersion = 1,
                    environment = "production",
                    channel = "pilot",
                    runtimeIdentifier = "win-x64",
                    layoutProfile = "enterprise",
                    artifactAuthorization = "SIGNED_RELEASE_SET",
                    releaseSetId,
                    generation = 1,
                    sequence = 1,
                    minAcceptedSequence = 0,
                    releaseDirectory,
                    publisherLedgerPath = ledgerPath,
                    publisherLedgerSha256 = HashFile(ledgerPath),
                    installerExecutablePath = installerExecutable,
                    bootstrapperExecutablePath = bootstrapperExecutable,
                    launcherExecutablePath = launcherExecutable,
                    clientBootstrapperExecutablePath = clientBootstrapperExecutable,
                    maintenanceExecutablePath = maintenanceExecutable,
                    runtimeSourceMetadataPath = runtimeAdmission.MetadataPath,
                    runtimeAdmissionReceiptPath = runtimeAdmission.ReceiptPath,
                    pluginPolicyMetadataPath = pluginMetadata,
                    launcherTrust = new
                    {
                        updateManifestUri = "https://updates.acme-corp.com/v2/channels/pilot/release-set.v2.json",
                        updateManifestOrigin = "https://updates.acme-corp.com/",
                        updateArtifactOrigin = "https://artifacts.acme-corp.com/",
                        releaseKeyId,
                        releaseKeyX = releasePublicKey.X,
                        releaseKeyY = releasePublicKey.Y,
                        controlPlaneOrigin = "https://control.acme-corp.com/",
                        authorizationOrigin = "https://authorization.acme-corp.com/",
                        gatewayOrigin = "https://gateway.acme-corp.com/",
                        managedArtifactOrigin = "https://managed-artifacts.acme-corp.com/",
                        leaseKeyId = "lease-pilot-test-key",
                        leaseKeyX = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(
                            leaseParameters.Q.X!),
                        leaseKeyY = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(
                            leaseParameters.Q.Y!),
                        authenticodeSignerSha256Thumbprint = new string('a', 64),
                    },
                    runtimeAdmissionKey = new
                    {
                        keyId = _admissionTrust.KeyId,
                        x = _admissionTrust.X,
                        y = _admissionTrust.Y,
                    },
                    brandAuthorizationKey = new
                    {
                        keyId = brandTrust.KeyId,
                        x = brandTrust.X,
                        y = brandTrust.Y,
                    },
                    brandAuthorization = new
                    {
                        receiptPath = brandReceiptPath,
                        receiptSha256 = HashFile(brandReceiptPath),
                        evidencePath = brandEvidencePath,
                        evidenceSha256 = HashFile(brandEvidencePath),
                        distributionAudienceId = brandReceipt.DistributionAudienceId,
                    },
                    startupUpdateContract = new
                    {
                        checkOnEveryStartup = true,
                        atomicReleaseSetActivation = true,
                        bootstrapHealthRollback = true,
                        maximumOfflineGraceHours = 168,
                    },
                    localDataCompatibilityEvidence = new
                    {
                        fromUpstreamTag = "dsh-v0.1.0-rc.6",
                        toUpstreamTag = targetUpstreamTag,
                        sourceRuntimeArchiveSha256,
                        targetRuntimeArchiveSha256,
                        reportPath = migrationReportPath,
                        reportSha256 = HashFile(migrationReportPath),
                        certification = new
                        {
                            receiptPath = localDataCertificationReceiptPath,
                            receiptSha256 = HashFile(localDataCertificationReceiptPath),
                            certificationAudienceId = localDataCertificationAudienceId,
                        },
                    },
                }, jsonOptions)!.AsObject();
            var certificationInput = configDocument["localDataCompatibilityEvidence"]!
                .AsObject()["certification"]!.AsObject();
            if (certificationScenario == PilotLocalDataCertificationScenario.Missing)
            {
                configDocument["localDataCompatibilityEvidence"]!
                    .AsObject().Remove("certification");
            }
            else if (certificationScenario == PilotLocalDataCertificationScenario.WrongAudience)
            {
                certificationInput["certificationAudienceId"] =
                    "33333333-3333-4333-8333-333333333333";
            }
            File.WriteAllText(
                configPath,
                configDocument.ToJsonString(jsonOptions),
                new UTF8Encoding(false));

            var verifier = new RecordingPilotClientBinaryVerifier();
            PilotReadinessValidationResult Validate() =>
                EnterprisePilotReadinessValidator.Validate(
                    configPath,
                    verifier,
                    _admissionTrust,
                    brandTrust,
                    pluginAdmissionTrust,
                    leaseTrust,
                    localDataCertificationTrust);
            if (certificationScenario != PilotLocalDataCertificationScenario.Valid
                || clientBindingScenario != PilotClientBindingScenario.Valid)
            {
                AssertThrows<PilotReadinessException>(() => _ = Validate());
                AssertTrue(!verifier.Called);
                return;
            }
            var result = Validate();
            AssertTrue(verifier.Called);
            AssertTrue(result.Checks.Count >= 10);
            AssertTrue(result.Checks.All(check => check.Status == "PASS"));
            AssertTrue(result.Checks.Any(check => check.Id == "publisher-feed-head"));
            AssertTrue(result.Checks.Any(check => check.Id == "immutable-input-snapshot"));
            AssertTrue(result.Checks.Any(check =>
                check.Id == "local-data-compatibility-certification"));
            AssertEqual(
                localDataCertificationReceipt.CertificationId,
                result.LocalDataCertification.CertificationId);
        }

        public void Dispose()
        {
            _signer.Dispose();
            _admissionSigner.Dispose();
        }

        private RuntimeAdmissionFiles CreateRuntimeAdmission(
            string runtimePath,
            string releaseId,
            RuntimeAdmissionScenario scenario)
        {
            var metadataPath = runtimePath + ".metadata.json";
            var metadata = JsonNode.Parse(File.ReadAllBytes(Path.Combine(
                FindRepositoryRoot(),
                "release",
                "examples",
                "source-runtime.metadata.json")))!.AsObject();
            metadata["releaseId"] = releaseId;
            metadata["builtAtUtc"] = DateTimeOffset.UtcNow.AddMinutes(-1);
            var artifact = metadata["artifact"]!.AsObject();
            artifact["fileName"] = Path.GetFileName(runtimePath);
            artifact["sizeBytes"] = new FileInfo(runtimePath).Length;
            artifact["sha256"] = HashFile(runtimePath);
            if (scenario == RuntimeAdmissionScenario.TamperedMetadata)
            {
                metadata["sourceCommit"] = new string('0', 40);
            }
            else if (scenario == RuntimeAdmissionScenario.PromotionIneligible)
            {
                metadata["promotionEligible"] = false;
            }
            else if (scenario == RuntimeAdmissionScenario.WrongWebAuthProtocol)
            {
                metadata["runtimeWebAuthProtocol"] = "legacy-clean-root-v1";
            }
            else if (scenario == RuntimeAdmissionScenario.FormerRc2Metadata)
            {
                metadata["sourceTag"] = "dsh-v0.1.1-rc.2";
                metadata["runtimeWebAuthProtocol"] = "legacy-clean-root-v1";
            }
            File.WriteAllText(
                metadataPath,
                metadata.ToJsonString(new JsonSerializerOptions(JsonSerializerDefaults.Web)
                {
                    WriteIndented = true,
                }),
                new UTF8Encoding(false));

            var receiptPath = runtimePath + ".organization-admission.v1.json";
            var receipt = new PublisherRuntimeAdmissionReceipt
            {
                SchemaVersion = PublisherRuntimeAdmissionReceipt.CurrentSchemaVersion,
                ReceiptType = PublisherRuntimeAdmissionReceipt.CurrentReceiptType,
                ReleaseId = releaseId,
                SourceRuntimeMetadataSha256 = scenario == RuntimeAdmissionScenario.WrongDigest
                    ? new string('0', 64)
                    : HashFile(metadataPath),
                Decision = PublisherRuntimeAdmissionReceipt.AdmittedDecision,
                ReviewedAtUnixSeconds = (scenario == RuntimeAdmissionScenario.StaleReceipt
                    ? DateTimeOffset.UtcNow.AddDays(-31)
                    : DateTimeOffset.UtcNow).ToUnixTimeSeconds(),
                Signature = new EnterpriseReleaseSignature
                {
                    Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
                    KeyId = _admissionTrust.KeyId,
                    Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(new byte[64]),
                },
            };
            using var wrongSigner = scenario == RuntimeAdmissionScenario.WrongKey
                ? ECDsa.Create(ECCurve.NamedCurves.nistP256)
                : null;
            var signer = wrongSigner ?? _admissionSigner;
            receipt = receipt with
            {
                Signature = receipt.Signature with
                {
                    Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(signer.SignData(
                        PublisherRuntimeAdmissionCanonicalJson.Payload(receipt),
                        HashAlgorithmName.SHA256,
                        DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
                },
            };
            File.WriteAllText(
                receiptPath,
                JsonSerializer.Serialize(
                    receipt,
                    new JsonSerializerOptions(JsonSerializerDefaults.Web)
                    {
                        WriteIndented = true,
                    }),
                new UTF8Encoding(false));
            return new RuntimeAdmissionFiles(metadataPath, receiptPath);
        }

        public static void CreatePluginPolicyPackage(
            string archivePath,
            string metadataPath,
            string launcherReleaseId,
            string runtimeReleaseId,
            bool metadataDrift,
            IReadOnlyList<string>? runtimeReleaseIds = null)
        {
            runtimeReleaseIds ??= [runtimeReleaseId];
            var skillBytes = "managed skill\n"u8.ToArray();
            var policyJson = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                policyId = "11111111-2222-4333-8444-555555555555",
                generation = 1,
                skillsRoot = "skills",
                skillPacks = new[]
                {
                    new
                    {
                        skillId = "mail-manager",
                        version = "1.0.0",
                        root = "skills/mail-manager",
                        files = new[]
                        {
                            new
                            {
                                path = "skills/mail-manager/SKILL.md",
                                sha256 = HashBytes(skillBytes),
                                sizeBytes = skillBytes.LongLength,
                            },
                        },
                    },
                },
                compatibility = new
                {
                    launcherReleaseIds = new[] { launcherReleaseId },
                    runtimeReleaseIds,
                },
                revoked = false,
                critical = true,
            }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            var policyBytes = new byte[policyJson.Length + 1];
            policyJson.CopyTo(policyBytes, 0);
            policyBytes[^1] = (byte)'\n';
            using (var archive = ZipFile.Open(archivePath, ZipArchiveMode.Create))
            {
                WriteZipEntry(archive, "plugin-policy.json", policyBytes);
                WriteZipEntry(archive, "skills/mail-manager/SKILL.md", skillBytes);
            }
            var archiveInfo = new FileInfo(archivePath);
            var archiveHash = HashFile(archivePath);
            File.WriteAllText(metadataPath, JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                signingStatus = "UNSIGNED_CANDIDATE",
                builder = new
                {
                    zipMode = "store",
                    scriptSha256 = new string('a', 64),
                },
                policy = new
                {
                    policyId = "11111111-2222-4333-8444-555555555555",
                    generation = 1,
                    fileName = "plugin-policy.json",
                    sizeBytes = policyBytes.LongLength,
                    sha256 = HashBytes(policyBytes),
                    critical = true,
                    revoked = false,
                },
                compatibility = new
                {
                    launcherReleaseIds = new[] { launcherReleaseId },
                    runtimeReleaseIds,
                },
                inputs = new[]
                {
                    new
                    {
                        kind = "skill",
                        id = "mail-manager",
                        version = "1.0.0",
                        artifact = new
                        {
                            fileName = "mail-manager-1.0.0.zip",
                            sizeBytes = 123L,
                            sha256 = new string('b', 64),
                        },
                        metadata = new
                        {
                            fileName = "mail-manager-1.0.0.artifact.json",
                            sizeBytes = 456L,
                            sha256 = new string('c', 64),
                        },
                        source = new
                        {
                            commit = new string('d', 40),
                            tree = new string('e', 40),
                            builderBlob = new string('f', 40),
                        },
                    },
                },
                artifact = new
                {
                    fileName = Path.GetFileName(archivePath),
                    sizeBytes = archiveInfo.Length,
                    sha256 = metadataDrift ? new string('0', 64) : archiveHash,
                },
            }, new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true }),
                new UTF8Encoding(false));
        }

        private static void CreateOpaqueArchive(
            string archivePath,
            string entryPath,
            ReadOnlySpan<byte> bytes)
        {
            if (File.Exists(archivePath))
            {
                File.Delete(archivePath);
            }
            using var archive = ZipFile.Open(archivePath, ZipArchiveMode.Create);
            WriteZipEntry(archive, entryPath, bytes);
        }

        private static void WriteZipEntry(
            ZipArchive archive,
            string path,
            ReadOnlySpan<byte> bytes)
        {
            var entry = archive.CreateEntry(path, CompressionLevel.NoCompression);
            using var output = entry.Open();
            output.Write(bytes);
        }

        private static string HashFile(string path)
        {
            using var stream = File.OpenRead(path);
            return Convert.ToHexStringLower(SHA256.HashData(stream));
        }

        private static string HashBytes(ReadOnlySpan<byte> bytes) =>
            Convert.ToHexStringLower(SHA256.HashData(bytes));

        private async Task<ProcessResult> RunProcessAsync(params string[] arguments)
        {
            var repositoryRoot = FindRepositoryRoot();
            var publisherDll = Path.Combine(
                repositoryRoot,
                "src",
                "Ensou.Dsh.Enterprise.ReleasePublisher",
                "bin",
#if DEBUG
                "Debug",
#else
                "Release",
#endif
                "net10.0-windows",
                "Ensou.Dsh.Enterprise.ReleasePublisher.dll");
            if (!File.Exists(publisherDll))
            {
                throw new FileNotFoundException("Publisher test binary is missing.", publisherDll);
            }
            var startInfo = new ProcessStartInfo
            {
                FileName = "dotnet",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            startInfo.Environment[
                "ENSOU_DSH_ENTERPRISE_PUBLISHER_TEST_AUTHORITY_ROOT"] = Path.Combine(
                    Root,
                    "publication-authority");
            startInfo.ArgumentList.Add(publisherDll);
            foreach (var argument in arguments)
            {
                startInfo.ArgumentList.Add(argument);
            }
            using var process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("Publisher test process did not start.");
            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync().ConfigureAwait(false);
            return new ProcessResult(
                process.ExitCode,
                await outputTask.ConfigureAwait(false),
                await errorTask.ConfigureAwait(false));
        }

        private static string FindRepositoryRoot()
        {
            foreach (var origin in new[] { AppContext.BaseDirectory, Environment.CurrentDirectory })
            {
                var current = new DirectoryInfo(Path.GetFullPath(origin));
                while (current is not null)
                {
                    if (File.Exists(Path.Combine(current.FullName, "Ensou.Dsh.slnx")))
                    {
                        return current.FullName;
                    }
                    current = current.Parent;
                }
            }
            throw new DirectoryNotFoundException("Could not locate repository root.");
        }

        public sealed record PreparedPublisherRun(
            PublisherArguments Arguments,
            string MetadataPath,
            string ReceiptPath,
            string[] ProcessArguments);

        private sealed record RuntimeAdmissionFiles(
            string MetadataPath,
            string ReceiptPath);
    }

    private sealed class RecordingPilotClientBinaryVerifier : IPilotClientBinaryVerifier
    {
        public bool Called { get; private set; }

        public void Verify(
            PilotReadinessConfig config,
            string productionTrustSha256,
            PilotClientReleaseBinding releaseBinding)
        {
            AssertEqual("production", config.Environment);
            AssertEqual(64, productionTrustSha256.Length);
            AssertEqual("launcher-production-1", releaseBinding.LauncherReleaseId);
            AssertEqual("managed-v2026.08.25.99", releaseBinding.RuntimeReleaseId);
            AssertEqual(64, releaseBinding.LauncherArchiveSha256.Length);
            AssertEqual(64, releaseBinding.RuntimeArchiveSha256.Length);
            AssertEqual(
                EnterpriseInstallationLayout.ClientBootstrapperExecutableName,
                Path.GetFileName(config.ClientBootstrapperExecutablePath));
            AssertEqual(
                EnterpriseInstallationLayout.MaintenanceExecutableName,
                Path.GetFileName(config.MaintenanceExecutablePath));
            Called = true;
        }
    }

    private sealed record ProcessResult(
        int ExitCode,
        string StandardOutput,
        string StandardError);

    private static bool TryCreateDirectoryJunction(string junctionPath, string targetPath)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe",
            Arguments = $"/d /c mklink /J \"{junctionPath}\" \"{targetPath}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });
        if (process is null)
        {
            return false;
        }
        process.WaitForExit();
        return process.ExitCode == 0;
    }

    private static void ReplacePathAtomically(string path, ReadOnlySpan<byte> bytes)
    {
        var replacement = path + $".{Guid.NewGuid():N}.replacement";
        File.WriteAllBytes(replacement, bytes.ToArray());
        File.Move(replacement, path, overwrite: true);
    }

    private static Task ManagedPatchManifestContractAsync()
    {
        var repositoryRoot = FindRepositoryRootForContract();
        var versionsLockPath = Path.Combine(
            repositoryRoot,
            "versions",
            "locked.json");
        var versionsLockBytes = File.ReadAllBytes(versionsLockPath);
        using var versionsLockDocument = JsonDocument.Parse(versionsLockBytes);
        var versionsLock = versionsLockDocument.RootElement;
        var lockedPatch = versionsLock.GetProperty("managedPatch");
        var lockedManifestSha256 = lockedPatch.GetProperty("manifestSha256").GetString()!;
        var manifestPaths = Directory.EnumerateFiles(
                Path.Combine(repositoryRoot, "upstream-patches"),
                "manifest.json",
                SearchOption.AllDirectories)
            .Where(path => string.Equals(
                Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))),
                lockedManifestSha256,
                StringComparison.Ordinal))
            .ToArray();
        AssertEqual(1, manifestPaths.Length);
        var manifestPath = manifestPaths[0];
        var patchRoot = Path.GetDirectoryName(manifestPath)!;
        var manifestBytes = File.ReadAllBytes(manifestPath);
        using var manifestDocument = JsonDocument.Parse(manifestBytes);
        var manifest = manifestDocument.RootElement;
        var source = manifest.GetProperty("base");
        var patch = manifest.GetProperty("patch");
        var counts = manifest.GetProperty("counts");
        var policy = manifest.GetProperty("managedPolicy");
        var patchPath = Path.Combine(patchRoot, patch.GetProperty("file").GetString()!);
        var contract = PublisherManagedPatchManifestContract.Current;

        AssertEqual(
            contract.ManifestSha256,
            Convert.ToHexStringLower(SHA256.HashData(manifestBytes)));
        AssertEqual(
            contract.ManifestSha256,
            lockedManifestSha256);
        AssertEqual(
            contract.SourceRepository,
            source.GetProperty("repository").GetString());
        AssertEqual(
            contract.SourceTag,
            source.GetProperty("tag").GetString());
        AssertEqual(
            contract.SourceTag,
            versionsLock.GetProperty("officialTag").GetString());
        AssertEqual(
            contract.SourceCommit,
            source.GetProperty("commit").GetString());
        AssertEqual(
            contract.SourceCommit,
            versionsLock.GetProperty("officialCommit").GetString());
        AssertEqual(
            contract.SourceTree,
            source.GetProperty("tree").GetString());
        AssertEqual(
            contract.SourceTree,
            versionsLock.GetProperty("officialTree").GetString());
        AssertEqual(
            contract.DshVersion,
            versionsLock.GetProperty("dshVersion").GetString());
        AssertEqual(
            contract.BaseLockfileSha256,
            versionsLock.GetProperty("baseLockfileSha256").GetString());
        AssertEqual(
            contract.LockfileSha256,
            versionsLock.GetProperty("lockfileSha256").GetString());
        AssertEqual(
            contract.RuntimeWebAuthProtocol,
            versionsLock.GetProperty("runtimeWebAuthProtocol").GetString());
        AssertEqual(
            contract.PatchId,
            lockedPatch.GetProperty("id").GetString());
        AssertEqual(
            contract.ManifestSchema,
            manifest.GetProperty("schema").GetString());
        AssertEqual(
            contract.PatchSha256,
            patch.GetProperty("sha256").GetString());
        AssertEqual(
            contract.PatchSha256,
            lockedPatch.GetProperty("patchSha256").GetString());
        AssertEqual(
            contract.PatchBytes,
            patch.GetProperty("bytes").GetInt64());
        AssertEqual(
            contract.PatchBytes,
            new FileInfo(patchPath).Length);
        AssertEqual(
            contract.PatchSha256,
            Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(patchPath))));
        AssertEqual(
            contract.ChangedFileCount,
            counts.GetProperty("changedFiles").GetInt32());
        AssertEqual(
            contract.ModifiedPreimageCount,
            counts.GetProperty("modifiedFiles").GetInt32());
        AssertEqual(
            contract.ModifiedPreimageCount,
            source.GetProperty("modifiedPreimages").EnumerateObject().Count());
        AssertEqual(
            contract.HostCompositionCanonicalSha256,
            policy.GetProperty("hostCompositionCanonicalSha256").GetString());

        var schemaPath = Path.Combine(
            repositoryRoot,
            "release",
            "schemas",
            "source-runtime-metadata.schema.json");
        using var schemaDocument = JsonDocument.Parse(File.ReadAllBytes(schemaPath));
        var schemaProperties = schemaDocument.RootElement.GetProperty("properties");
        var schemaPatch = schemaProperties.GetProperty("managedPatch")
            .GetProperty("properties");
        var schemaPolicy = schemaProperties.GetProperty("managedPolicy")
            .GetProperty("properties");
        AssertEqual(
            contract.SourceTag,
            schemaProperties.GetProperty("sourceTag").GetProperty("const").GetString());
        AssertEqual(
            contract.SourceCommit,
            schemaProperties.GetProperty("sourceCommit").GetProperty("const").GetString());
        AssertEqual(
            contract.SourceTree,
            schemaProperties.GetProperty("sourceTree").GetProperty("const").GetString());
        AssertEqual(
            contract.DshVersion,
            schemaProperties.GetProperty("dshVersion").GetProperty("const").GetString());
        AssertEqual(
            contract.BaseLockfileSha256,
            schemaProperties.GetProperty("baseLockfileSha256").GetProperty("const").GetString());
        AssertEqual(
            contract.LockfileSha256,
            schemaProperties.GetProperty("lockfileSha256").GetProperty("const").GetString());
        AssertEqual(
            contract.RuntimeWebAuthProtocol,
            schemaProperties.GetProperty("runtimeWebAuthProtocol").GetProperty("const").GetString());
        AssertEqual(
            contract.PatchId,
            schemaPatch.GetProperty("id").GetProperty("const").GetString());
        AssertEqual(
            contract.ManifestSha256,
            schemaPatch.GetProperty("manifestSha256").GetProperty("const").GetString());
        AssertEqual(
            contract.PatchSha256,
            schemaPatch.GetProperty("patchSha256").GetProperty("const").GetString());
        AssertEqual(
            contract.PatchBytes,
            schemaPatch.GetProperty("patchBytes").GetProperty("const").GetInt64());
        AssertEqual(
            contract.ChangedFileCount,
            schemaPatch.GetProperty("changedFileCount").GetProperty("const").GetInt32());
        AssertEqual(
            contract.ModifiedPreimageCount,
            schemaPatch.GetProperty("modifiedPreimageCount").GetProperty("const").GetInt32());
        AssertEqual(
            contract.HostCompositionCanonicalSha256,
            schemaPolicy.GetProperty("hostCompositionCanonicalSha256")
                .GetProperty("const").GetString());

        var examplePath = Path.Combine(
            repositoryRoot,
            "release",
            "examples",
            "source-runtime.metadata.json");
        var exampleBytes = File.ReadAllBytes(examplePath);
        var example = JsonNode.Parse(exampleBytes)!.AsObject();
        AssertEqual(
            contract.PatchBytes,
            example["managedPatch"]!["patchBytes"]!.GetValue<long>());
        AssertEqual(
            contract.HostCompositionCanonicalSha256,
            example["managedPolicy"]!["hostCompositionCanonicalSha256"]!
                .GetValue<string>());

        var admissionSourceText = File.ReadAllText(Path.Combine(
            repositoryRoot,
            "src",
            "Ensou.Dsh.Enterprise.ReleasePublisher",
            "PublisherRuntimeAdmission.cs"));
        foreach (var generatedIdentityValue in new[]
                 {
                     contract.ManifestSha256,
                     contract.PatchSha256,
                     contract.HostCompositionCanonicalSha256,
                     contract.PatchBytes.ToString(),
                 })
        {
            AssertFalse(admissionSourceText.Contains(
                generatedIdentityValue,
                StringComparison.Ordinal));
        }

        var parsed = PublisherSourceRuntimeMetadata.Parse(exampleBytes);
        parsed.RequireExact(
            parsed.ReleaseId,
            parsed.Artifact.FileName,
            parsed.Artifact.SizeBytes,
            parsed.Artifact.Sha256);

        var formerPatchBytes = example.DeepClone().AsObject();
        formerPatchBytes["managedPatch"]!["patchBytes"] = 247300;
        AssertThrows<InvalidDataException>(() =>
            PublisherSourceRuntimeMetadata.Parse(
                JsonSerializer.SerializeToUtf8Bytes(formerPatchBytes)).RequireExact(
                    parsed.ReleaseId,
                    parsed.Artifact.FileName,
                    parsed.Artifact.SizeBytes,
                    parsed.Artifact.Sha256));

        var formerHostComposition = example.DeepClone().AsObject();
        formerHostComposition["managedPolicy"]!["hostCompositionCanonicalSha256"] =
            "8d21f27c58de780ecd9a4cd312cd8af3a9536c9eee423f016e2e8f7ce49ebee1";
        AssertThrows<InvalidDataException>(() =>
            PublisherSourceRuntimeMetadata.Parse(
                JsonSerializer.SerializeToUtf8Bytes(formerHostComposition)).RequireExact(
                    parsed.ReleaseId,
                    parsed.Artifact.FileName,
                    parsed.Artifact.SizeBytes,
                    parsed.Artifact.Sha256));

        return Task.CompletedTask;
    }

    private static Task PluginPromotionMultiRuntimeAdmissionAsync()
    {
        using (var initial = PluginPromotionAdmissionFixture.CreateExactMultiRuntime(
            "managed-v2026.08.25.3"))
        {
            initial.ValidateUntilJournalGate();
        }
        using (var target = PluginPromotionAdmissionFixture.CreateExactMultiRuntime(
            "managed-v2026.08.25.4"))
        {
            target.ValidateUntilJournalGate();
        }
        using (var subset = PluginPromotionAdmissionFixture.CreateExactMultiRuntime(
            "managed-v2026.08.25.3"))
        {
            subset.MutateHandoffRuntimeReleaseIds("managed-v2026.08.25.3");
            subset.ValidateRejectedBeforeJournalWithMessage(
                "Plugin promotion handoff compatibility does not exactly match");
        }
        using (var reordered = PluginPromotionAdmissionFixture.CreateExactMultiRuntime(
            "managed-v2026.08.25.3"))
        {
            reordered.MutateHandoffRuntimeReleaseIds(
                "managed-v2026.08.25.4",
                "managed-v2026.08.25.3");
            reordered.ValidateRejectedBeforeJournalWithMessage(
                "Plugin promotion handoff compatibility does not exactly match");
        }
        using (var extra = PluginPromotionAdmissionFixture.CreateExactMultiRuntime(
            "managed-v2026.08.25.3"))
        {
            extra.MutateHandoffRuntimeReleaseIds(
                "managed-v2026.08.25.3",
                "managed-v2026.08.25.4",
                "managed-v2026.08.25.999");
            extra.ValidateRejectedBeforeJournalWithMessage(
                "Plugin promotion handoff compatibility does not exactly match");
        }
        using (var currentAbsent = PluginPromotionAdmissionFixture.CreateExactMultiRuntime(
            "managed-v2026.08.25.3"))
        {
            currentAbsent.ValidateRejectedWithCurrentRuntime("managed-v2026.08.25.999");
        }
        using (var staleRuntimeProof = PluginPromotionAdmissionFixture.CreateExactMultiRuntime(
            "managed-v2026.08.25.4"))
        {
            staleRuntimeProof.SignOrganizationAdmissionForRuntime(
                "managed-v2026.08.25.3");
            staleRuntimeProof.ValidateRejectedBeforeJournalWithMessage(
                "Plugin organization admission receipt does not bind");
        }
        using (var wrongProof = PluginPromotionAdmissionFixture.CreateExactMultiRuntime(
            "managed-v2026.08.25.4"))
        {
            wrongProof.SignOrganizationAdmissionWithWrongKey();
            wrongProof.ValidateRejectedBeforeJournal();
        }
        return Task.CompletedTask;
    }

    private static Process StartCurrentTestProcess(params string[] arguments)
    {
        var processPath = Environment.ProcessPath
            ?? throw new InvalidOperationException(
                "Publisher tests process path is unavailable.");
        var startInfo = new ProcessStartInfo
        {
            FileName = processPath,
            WorkingDirectory = AppContext.BaseDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        if (string.Equals(
                Path.GetFileNameWithoutExtension(processPath),
                "dotnet",
                StringComparison.OrdinalIgnoreCase))
        {
            startInfo.ArgumentList.Add(
                Assembly.GetEntryAssembly()?.Location
                ?? throw new InvalidOperationException(
                    "Publisher tests entry assembly is unavailable."));
        }
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
        return Process.Start(startInfo)
            ?? throw new InvalidOperationException(
                "Publisher tests crash probe did not start.");
    }

    private static string RequirePublisherStagingRoot(string path)
    {
        var fullPath = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(path));
        var tempRoot = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(Path.GetTempPath()));
        if (!string.Equals(
                Path.GetDirectoryName(fullPath),
                tempRoot,
                StringComparison.OrdinalIgnoreCase)
            || !Path.GetFileName(fullPath).StartsWith(
                "ensou-dsh-release-publisher-",
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Publisher crash probe returned an unsafe staging root.");
        }
        return fullPath;
    }

    private static void TryKillTestProcess(Process? process)
    {
        try
        {
            if (process is not null && !process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5000);
            }
        }
        catch
        {
            // Preserve the test failure while containing only its own probe.
        }
    }

    private static JsonSerializerOptions CreatePublisherJsonOptions() =>
        new(JsonSerializerDefaults.Web)
        {
            WriteIndented = true,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        };

    private static void AssertPrivateKeyMutationsDenied(
        string keyPath,
        byte[] expectedBytes)
    {
        var replacement = keyPath + $".{Guid.NewGuid():N}.replacement";
        var renamed = keyPath + $".{Guid.NewGuid():N}.renamed";
        File.WriteAllBytes(replacement, expectedBytes);
        try
        {
            AssertFileReplacementDenied(() =>
            {
                using var writer = new FileStream(
                    keyPath,
                    FileMode.Open,
                    FileAccess.Write,
                    FileShare.ReadWrite | FileShare.Delete);
                writer.Write(expectedBytes);
                writer.Flush(flushToDisk: true);
            });
            AssertFileReplacementDenied(
                () => File.Move(replacement, keyPath, overwrite: true));
            AssertFileReplacementDenied(() => File.Move(keyPath, renamed));
            AssertFileReplacementDenied(() => File.Delete(keyPath));
            AssertTrue(File.ReadAllBytes(keyPath).SequenceEqual(expectedBytes));
        }
        finally
        {
            if (File.Exists(renamed) && !File.Exists(keyPath))
            {
                File.Move(renamed, keyPath);
            }
            if (!File.Exists(keyPath))
            {
                File.WriteAllBytes(keyPath, expectedBytes);
            }
            if (File.Exists(replacement))
            {
                File.Delete(replacement);
            }
            if (File.Exists(renamed))
            {
                File.Delete(renamed);
            }
        }
    }

    private static void AssertPrivateKeyMutationsAllowed(
        string keyPath,
        byte[] expectedBytes)
    {
        var replacement = keyPath + $".{Guid.NewGuid():N}.replacement";
        var renamed = keyPath + $".{Guid.NewGuid():N}.renamed";
        try
        {
            File.WriteAllBytes(keyPath, expectedBytes);
            File.WriteAllBytes(replacement, expectedBytes);
            File.Move(replacement, keyPath, overwrite: true);
            File.Move(keyPath, renamed);
            File.Move(renamed, keyPath);
            File.Delete(keyPath);
            AssertFalse(File.Exists(keyPath));
            File.WriteAllBytes(keyPath, expectedBytes);
            AssertTrue(File.ReadAllBytes(keyPath).SequenceEqual(expectedBytes));
        }
        finally
        {
            if (File.Exists(renamed) && !File.Exists(keyPath))
            {
                File.Move(renamed, keyPath);
            }
            if (!File.Exists(keyPath))
            {
                File.WriteAllBytes(keyPath, expectedBytes);
            }
            if (File.Exists(replacement))
            {
                File.Delete(replacement);
            }
            if (File.Exists(renamed))
            {
                File.Delete(renamed);
            }
        }
    }

    private static void AssertNoPublisherStagingContains(
        ReadOnlySpan<byte> secret)
    {
        var tempRoot = Path.GetFullPath(Path.GetTempPath());
        foreach (var root in Directory.EnumerateDirectories(
            tempRoot,
            "ensou-dsh-release-publisher-*",
            SearchOption.TopDirectoryOnly).ToArray())
        {
            var pending = new Stack<string>();
            pending.Push(root);
            while (pending.Count > 0)
            {
                var directory = pending.Pop();
                try
                {
                    if ((File.GetAttributes(directory)
                            & FileAttributes.ReparsePoint) != 0)
                    {
                        throw new InvalidDataException(
                            "Publisher staging scan encountered a filesystem link.");
                    }
                    foreach (var file in Directory.EnumerateFiles(
                        directory,
                        "*",
                        SearchOption.TopDirectoryOnly))
                    {
                        if (FileContainsBytes(file, secret))
                        {
                            throw new InvalidDataException(
                                "Publisher staging contains release private-key bytes.");
                        }
                    }
                    foreach (var child in Directory.EnumerateDirectories(
                        directory,
                        "*",
                        SearchOption.TopDirectoryOnly))
                    {
                        pending.Push(child);
                    }
                }
                catch (DirectoryNotFoundException)
                {
                    // A concurrently completed publisher removed its own
                    // staging directory after the top-level snapshot.
                }
            }
        }
    }

    private static bool FileContainsBytes(
        string path,
        ReadOnlySpan<byte> expected)
    {
        if (expected.IsEmpty)
        {
            return false;
        }
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            64 * 1024,
            FileOptions.SequentialScan);
        var buffer = new byte[(64 * 1024) + expected.Length - 1];
        var carry = 0;
        while (true)
        {
            var read = stream.Read(buffer, carry, buffer.Length - carry);
            var available = carry + read;
            for (var offset = 0;
                offset <= available - expected.Length;
                offset++)
            {
                if (buffer[offset] == expected[0]
                    && buffer.AsSpan(offset, expected.Length)
                        .SequenceEqual(expected))
                {
                    return true;
                }
            }
            if (read == 0)
            {
                return false;
            }
            carry = Math.Min(expected.Length - 1, available);
            buffer.AsSpan(available - carry, carry).CopyTo(buffer);
        }
    }

    private static void AssertTrue(bool value)
    {
        if (!value) throw new InvalidOperationException("Expected true.");
    }
    private static void AssertFalse(bool value) => AssertTrue(!value);
    private static void AssertEqual<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new InvalidOperationException($"Expected {expected}, actual {actual}.");
    }
    private static void AssertThrows<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }
        throw new InvalidOperationException(
            $"Expected {typeof(TException).Name} to be thrown.");
    }

    private static string FindRepositoryRootForContract()
    {
        foreach (var origin in new[] { AppContext.BaseDirectory, Environment.CurrentDirectory })
        {
            var current = new DirectoryInfo(Path.GetFullPath(origin));
            while (current is not null)
            {
                if (File.Exists(Path.Combine(current.FullName, "Ensou.Dsh.slnx")))
                {
                    return current.FullName;
                }
                current = current.Parent;
            }
        }
        throw new DirectoryNotFoundException("Could not locate repository root.");
    }

    private static void AssertFileReplacementDenied(Action action)
    {
        try
        {
            action();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return;
        }
        throw new InvalidOperationException("Expected locked source replacement to be denied.");
    }
}
