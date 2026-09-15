using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Ensou.Dsh.Enterprise.Installation;
using Ensou.Dsh.Enterprise.ReleasePublisher;
using Ensou.Dsh.EnterprisePluginCompatibilityRunner;

namespace Ensou.Dsh.EnterprisePluginCompatibilityRunnerTests;

internal static class Program
{
    private static readonly string TempRoot = Path.Combine(
        Path.GetTempPath(),
        "ensou-plugin-compatibility-runner-tests-" + Guid.NewGuid().ToString("N"));

    private static int Main()
    {
        Directory.CreateDirectory(TempRoot);
        var checks = new (string Name, Action Run)[]
        {
            ("signed execution admission binds exact plugin tree", SignedExecutionAdmission),
            ("candidate always-PASS reporter is rejected", CandidateReporterRejected),
            ("parent staging copies from the locked source object", LockedHandleStagesExactObject),
            ("identity-bound source snapshot denies replacement", SnapshotDeniesReplacement),
            ("strict evidence rejects unknown JSON fields", EvidenceRejectsUnknownFields),
        };
        var passed = 0;
        try
        {
            foreach (var check in checks)
            {
                check.Run();
                Console.WriteLine($"PASS  {check.Name}");
                passed++;
            }
            Console.WriteLine($"{passed}/{checks.Length} compatibility runner checks passed.");
            return 0;
        }
        finally
        {
            if (Directory.Exists(TempRoot))
            {
                Directory.Delete(TempRoot, recursive: true);
            }
        }
    }

    private static void SignedExecutionAdmission()
    {
        var root = NewRoot("signed-admission");
        const string launcherReleaseId = "launcher-production-2026.08.27.1";
        const string runtimeReleaseId = "managed-v2026.08.27.1";
        const string alternateRuntimeReleaseId = "managed-v2026.08.27.2";
        var archivePath = Path.Combine(root, "plugin-policy.zip");
        var skill = "# managed skill\n"u8.ToArray();
        var compatibility = "// production external compatibility gate\n"u8.ToArray();
        var policy = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = 1,
            policyId = "11111111-2222-4333-8444-555555555555",
            generation = 7,
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
                        FileEntry("skills/mail-manager/SKILL.md", skill),
                        FileEntry(
                            "skills/mail-manager/compatibility-test.mjs",
                            compatibility),
                    },
                },
            },
            compatibility = new
            {
                launcherReleaseIds = new[] { launcherReleaseId },
                runtimeReleaseIds = new[] { runtimeReleaseId, alternateRuntimeReleaseId },
            },
            revoked = false,
            critical = true,
        });
        using (var archive = ZipFile.Open(archivePath, ZipArchiveMode.Create))
        {
            WriteEntry(archive, "plugin-policy.json", policy);
            WriteEntry(archive, "skills/mail-manager/SKILL.md", skill);
            WriteEntry(
                archive,
                "skills/mail-manager/compatibility-test.mjs",
                compatibility);
        }
        var inspection = EnterprisePluginPolicyArchiveValidator.Validate(
            archivePath,
            launcherReleaseId,
            runtimeReleaseId);
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = signer.ExportParameters(false);
        var trust = new PublisherPluginAdmissionTrust
        {
            KeyId = "plugin-execution-test-v1",
            X = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(publicKey.Q.X!),
            Y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(publicKey.Q.Y!),
        };
        var metadataSha = new string('a', 64);
        var receipt = new PluginExecutionAdmissionReceipt
        {
            SchemaVersion = 1,
            ReceiptType = PluginExecutionAdmissionReceipt.CurrentReceiptType,
            Decision = PluginExecutionAdmissionReceipt.AdmittedDecision,
            ReviewedAtUnixSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            PolicyId = inspection.PolicyId,
            Generation = inspection.Generation,
            Critical = inspection.Critical,
            LauncherReleaseId = launcherReleaseId,
            RuntimeReleaseId = runtimeReleaseId,
            ArchiveSha256 = inspection.ArchiveSha256,
            ArchiveSizeBytes = inspection.ArchiveSizeBytes,
            MetadataSha256 = metadataSha,
            MetadataSizeBytes = 123,
            RawPolicySha256 = inspection.PolicySha256,
            RawPolicySizeBytes = inspection.PolicySizeBytes,
            SkillPacks = inspection.SkillPacks.Select(value =>
                new PluginExecutionAdmissionSkill
                {
                    SkillId = value.SkillId,
                    Version = value.Version,
                    Root = value.Root,
                    DeclaredTreeSha256 = value.DeclaredTreeSha256,
                }).ToArray(),
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
                Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(signer.SignData(
                    PluginExecutionAdmissionReceipt.CanonicalPayload(receipt),
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
            },
        };
        var receiptPath = Path.Combine(root, "execution-admission.json");
        WriteJson(receiptPath, receipt);
        _ = PluginExecutionAdmissionReceipt.ParseAndVerify(
            receiptPath,
            trust,
            inspection,
            inspection.ArchiveSha256,
            inspection.ArchiveSizeBytes,
            metadataSha,
            123,
            DateTimeOffset.UtcNow,
            launcherReleaseId,
            runtimeReleaseId);

        var alternateReceipt = receipt with
        {
            RuntimeReleaseId = alternateRuntimeReleaseId,
        };
        alternateReceipt = alternateReceipt with
        {
            Signature = alternateReceipt.Signature with
            {
                Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(signer.SignData(
                    PluginExecutionAdmissionReceipt.CanonicalPayload(alternateReceipt),
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
            },
        };
        WriteJson(receiptPath, alternateReceipt);
        _ = PluginExecutionAdmissionReceipt.ParseAndVerify(
            receiptPath,
            trust,
            inspection,
            inspection.ArchiveSha256,
            inspection.ArchiveSizeBytes,
            metadataSha,
            123,
            DateTimeOffset.UtcNow,
            launcherReleaseId,
            alternateRuntimeReleaseId);
        AssertThrows<InvalidDataException>(() =>
            PluginExecutionAdmissionReceipt.ParseAndVerify(
                receiptPath,
                trust,
                inspection,
                inspection.ArchiveSha256,
                inspection.ArchiveSizeBytes,
                metadataSha,
                123,
                DateTimeOffset.UtcNow,
                launcherReleaseId,
                runtimeReleaseId));
        AssertThrows<InvalidDataException>(() =>
            PluginExecutionAdmissionReceipt.ParseAndVerify(
                receiptPath,
                trust,
                inspection,
                inspection.ArchiveSha256,
                inspection.ArchiveSizeBytes,
                metadataSha,
                123,
                DateTimeOffset.UtcNow,
                launcherReleaseId,
                "managed-v2026.08.27.999"));
        AssertThrows<InvalidDataException>(() =>
            PluginExecutionAdmissionReceipt.ParseAndVerify(
                receiptPath,
                trust,
                inspection,
                inspection.ArchiveSha256,
                inspection.ArchiveSizeBytes,
                metadataSha,
                123,
                DateTimeOffset.UtcNow,
                launcherReleaseId,
                string.Empty));
        AssertThrows<InvalidDataException>(() =>
            PluginExecutionAdmissionReceipt.ParseAndVerify(
                receiptPath,
                trust,
                inspection,
                inspection.ArchiveSha256,
                inspection.ArchiveSizeBytes,
                metadataSha,
                123,
                DateTimeOffset.UtcNow,
                launcherReleaseId,
                null!));
        WriteJson(receiptPath, receipt);

        AssertThrows<InvalidDataException>(() =>
            PluginExecutionAdmissionReceipt.ParseAndVerify(
                receiptPath,
                trust,
                inspection,
                new string('0', 64),
                inspection.ArchiveSizeBytes,
                metadataSha,
                123,
                DateTimeOffset.UtcNow,
                launcherReleaseId,
                runtimeReleaseId));
        var unknown = JsonNode.Parse(File.ReadAllBytes(receiptPath))!.AsObject();
        unknown["unexpected"] = true;
        var unknownPath = Path.Combine(root, "execution-admission-unknown.json");
        File.WriteAllText(unknownPath, unknown.ToJsonString(), new UTF8Encoding(false));
        AssertThrows<InvalidDataException>(() =>
            PluginExecutionAdmissionReceipt.ParseAndVerify(
                unknownPath,
                trust,
                inspection,
                inspection.ArchiveSha256,
                inspection.ArchiveSizeBytes,
                metadataSha,
                123,
                DateTimeOffset.UtcNow,
                launcherReleaseId,
                runtimeReleaseId));
    }

    private static void CandidateReporterRejected()
    {
        var root = NewRoot("candidate-reporter");
        var forged = Path.Combine(root, "forged-runtime.zip");
        using (var archive = ZipFile.Open(forged, ZipArchiveMode.Create))
        {
            WriteEntry(
                archive,
                "enterprise-plugin-compatibility-probe/Ensou.Dsh.EnterprisePluginCompatibilityProbe.exe",
                "always PASS"u8.ToArray());
        }
        AssertThrows<InvalidDataException>(() =>
            InternalCompatibilityProbe.RejectCandidateProvidedCompatibilityReporter(forged));

        var normal = Path.Combine(root, "normal-runtime.zip");
        using (var archive = ZipFile.Open(normal, ZipArchiveMode.Create))
        {
            WriteEntry(archive, "node.exe", "runtime"u8.ToArray());
        }
        InternalCompatibilityProbe.RejectCandidateProvidedCompatibilityReporter(normal);
    }

    private static void SnapshotDeniesReplacement()
    {
        var root = NewRoot("snapshot");
        var source = Path.Combine(root, "source.bin");
        var replacement = Path.Combine(root, "replacement.bin");
        var snapshot = Path.Combine(root, "snapshot.bin");
        var bytes = RandomNumberGenerator.GetBytes(4096);
        File.WriteAllBytes(source, bytes);
        File.WriteAllBytes(replacement, RandomNumberGenerator.GetBytes(4096));
        var expected = new InternalProbeFile
        {
            Path = source,
            SizeBytes = bytes.LongLength,
            Sha256 = Hash(bytes),
        };
        using var input = InternalProbeInput.Capture(expected);
        input.CreateSnapshot(snapshot);
        AssertReplacementDenied(() => File.Move(replacement, source, overwrite: true));
        AssertReplacementDenied(() => File.WriteAllBytes(source, [1, 2, 3]));
        input.VerifyUnchanged();
        Equal(Hash(bytes), Hash(File.ReadAllBytes(snapshot)));
    }

    private static void LockedHandleStagesExactObject()
    {
        var root = NewRoot("locked-parent-stage");
        var source = Path.Combine(root, "source.bin");
        var replacement = Path.Combine(root, "replacement.bin");
        var bytes = RandomNumberGenerator.GetBytes(4096);
        File.WriteAllBytes(source, bytes);
        File.WriteAllBytes(replacement, RandomNumberGenerator.GetBytes(4096));

        using var sourceLock = PublisherSafeFile.OpenLockedRead(source);
        var sourceIdentity = PublisherSafeFile.GetIdentity(sourceLock);
        using var staging = PublisherInputStaging.Create();
        var staged = staging.CaptureFromLockedHandle(sourceLock, source);

        Equal(Hash(bytes), staged.Sha256);
        Equal(Hash(bytes), Hash(staged.ReadAllBytes(8192)));
        AssertReplacementDenied(() => File.Move(replacement, source, overwrite: true));
        PublisherSafeFile.RequireExpectedPathAndRegularFile(sourceLock, source);
        if (sourceIdentity != PublisherSafeFile.GetIdentity(sourceLock))
        {
            throw new InvalidOperationException(
                "Locked parent source identity changed during staging.");
        }
    }

    private static void EvidenceRejectsUnknownFields()
    {
        var bytes = "{\"schemaVersion\":1,\"unexpected\":true}"u8.ToArray();
        AssertThrows<InvalidDataException>(() =>
            PublisherRuntimeAdmissionJson.Parse<CompatibilityProbeEvidence>(
                bytes,
                "compatibility evidence"));
    }

    private static object FileEntry(string path, byte[] bytes) => new
    {
        path,
        sha256 = Hash(bytes),
        sizeBytes = bytes.LongLength,
    };

    private static void WriteEntry(ZipArchive archive, string name, byte[] bytes)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
        using var stream = entry.Open();
        stream.Write(bytes);
    }

    private static void WriteJson<T>(string path, T value) => File.WriteAllText(
        path,
        JsonSerializer.Serialize(
            value,
            new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true }),
        new UTF8Encoding(false));

    private static string NewRoot(string name)
    {
        var path = Path.Combine(TempRoot, name);
        Directory.CreateDirectory(path);
        return path;
    }

    private static string Hash(byte[] bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static void Equal(string expected, string actual)
    {
        if (!string.Equals(expected, actual, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Expected {expected}; actual {actual}.");
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

    private static void AssertReplacementDenied(Action action)
    {
        try
        {
            action();
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            return;
        }
        throw new InvalidOperationException(
            "Expected the identity-bound read handle to deny replacement.");
    }
}
