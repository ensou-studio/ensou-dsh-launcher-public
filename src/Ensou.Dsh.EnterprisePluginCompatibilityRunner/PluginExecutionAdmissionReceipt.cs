using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Installation;
using Ensou.Dsh.Enterprise.ReleasePublisher;

namespace Ensou.Dsh.EnterprisePluginCompatibilityRunner;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PluginExecutionAdmissionReceipt
{
    public const string CurrentReceiptType =
        "ensou-dsh-managed-plugin-execution-admission";
    public const string AdmittedDecision = "admitted-for-compatibility-execution";

    public required int SchemaVersion { get; init; }
    public required string ReceiptType { get; init; }
    public required string Decision { get; init; }
    public required long ReviewedAtUnixSeconds { get; init; }
    public required string PolicyId { get; init; }
    public required long Generation { get; init; }
    public required bool Critical { get; init; }
    public required string LauncherReleaseId { get; init; }
    public required string RuntimeReleaseId { get; init; }
    public required string ArchiveSha256 { get; init; }
    public required long ArchiveSizeBytes { get; init; }
    public required string MetadataSha256 { get; init; }
    public required long MetadataSizeBytes { get; init; }
    public required string RawPolicySha256 { get; init; }
    public required long RawPolicySizeBytes { get; init; }
    public required IReadOnlyList<PluginExecutionAdmissionSkill> SkillPacks { get; init; }
    public required EnterpriseReleaseSignature Signature { get; init; }

    public static PluginExecutionAdmissionReceipt ParseAndVerify(
        string receiptPath,
        PublisherPluginAdmissionTrust trust,
        EnterprisePluginPolicyArchiveInspection inspection,
        PublisherStagedInputFile archive,
        PublisherStagedInputFile metadata,
        DateTimeOffset now,
        string selectedLauncherReleaseId,
        string selectedRuntimeReleaseId) => ParseAndVerify(
            receiptPath,
            trust,
            inspection,
            archive.Sha256,
            archive.Length,
            metadata.Sha256,
            metadata.Length,
            now,
            selectedLauncherReleaseId,
            selectedRuntimeReleaseId);

    public static PluginExecutionAdmissionReceipt ParseAndVerify(
        string receiptPath,
        PublisherPluginAdmissionTrust trust,
        EnterprisePluginPolicyArchiveInspection inspection,
        string archiveSha256,
        long archiveSizeBytes,
        string metadataSha256,
        long metadataSizeBytes,
        DateTimeOffset now,
        string selectedLauncherReleaseId,
        string selectedRuntimeReleaseId)
    {
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentNullException.ThrowIfNull(inspection);
        if (string.IsNullOrWhiteSpace(selectedLauncherReleaseId)
            || string.IsNullOrWhiteSpace(selectedRuntimeReleaseId))
        {
            throw new InvalidDataException(
                "Plugin execution-admission selected release tuple is required.");
        }
        trust.Validate();
        using var stream = PublisherSafeFile.OpenLockedRead(receiptPath);
        if (stream.Length is <= 0 or > 512 * 1024)
        {
            throw new InvalidDataException(
                "Plugin execution-admission receipt size is invalid.");
        }
        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        var receipt = PublisherRuntimeAdmissionJson.Parse<PluginExecutionAdmissionReceipt>(
            bytes,
            "Plugin execution-admission receipt");
        receipt.Verify(
            trust,
            inspection,
            archiveSha256,
            archiveSizeBytes,
            metadataSha256,
            metadataSizeBytes,
            selectedLauncherReleaseId,
            selectedRuntimeReleaseId,
            now);
        return receipt;
    }

    private void Verify(
        PublisherPluginAdmissionTrust trust,
        EnterprisePluginPolicyArchiveInspection inspection,
        string archiveSha256,
        long archiveSizeBytes,
        string metadataSha256,
        long metadataSizeBytes,
        string selectedLauncherReleaseId,
        string selectedRuntimeReleaseId,
        DateTimeOffset now)
    {
        if (Signature is null
            || !string.Equals(
                Signature.Algorithm,
                EnterpriseReleaseSetContract.SignatureAlgorithm,
                StringComparison.Ordinal)
            || !string.Equals(Signature.KeyId, trust.KeyId, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Plugin execution-admission signature identity is invalid.");
        }
        var reviewed = DateTimeOffset.FromUnixTimeSeconds(ReviewedAtUnixSeconds);
        if (SchemaVersion != 1
            || !string.Equals(ReceiptType, CurrentReceiptType, StringComparison.Ordinal)
            || !string.Equals(Decision, AdmittedDecision, StringComparison.Ordinal)
            || reviewed > now.AddMinutes(5)
            || now - reviewed > TimeSpan.FromHours(168)
            || !string.Equals(PolicyId, inspection.PolicyId, StringComparison.Ordinal)
            || Generation != inspection.Generation
            || Critical != inspection.Critical
            || inspection.LauncherReleaseIds.Count is <= 0 or > 64
            || inspection.RuntimeReleaseIds.Count is <= 0 or > 64
            || !inspection.LauncherReleaseIds.Contains(
                LauncherReleaseId,
                StringComparer.Ordinal)
            || !inspection.RuntimeReleaseIds.Contains(
                RuntimeReleaseId,
                StringComparer.Ordinal)
            || !string.Equals(
                LauncherReleaseId,
                selectedLauncherReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                RuntimeReleaseId,
                selectedRuntimeReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(ArchiveSha256, archiveSha256, StringComparison.Ordinal)
            || ArchiveSizeBytes != archiveSizeBytes
            || !string.Equals(MetadataSha256, metadataSha256, StringComparison.Ordinal)
            || MetadataSizeBytes != metadataSizeBytes
            || !string.Equals(
                RawPolicySha256,
                inspection.PolicySha256,
                StringComparison.Ordinal)
            || RawPolicySizeBytes != inspection.PolicySizeBytes
            || SkillPacks is null
            || SkillPacks.Count != inspection.SkillPacks.Count)
        {
            throw new InvalidDataException(
                "Plugin execution-admission receipt does not bind the exact policy archive, metadata, compatibility tuple, and declared trees.");
        }
        var actualSkills = SkillPacks
            .OrderBy(skill => skill.SkillId, StringComparer.Ordinal)
            .ToArray();
        for (var index = 0; index < inspection.SkillPacks.Count; index++)
        {
            var actual = actualSkills[index];
            var expected = inspection.SkillPacks[index];
            if (!string.Equals(actual.SkillId, expected.SkillId, StringComparison.Ordinal)
                || !string.Equals(actual.Version, expected.Version, StringComparison.Ordinal)
                || !string.Equals(actual.Root, expected.Root, StringComparison.Ordinal)
                || !string.Equals(
                    actual.DeclaredTreeSha256,
                    expected.DeclaredTreeSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Plugin execution admission omitted or drifted declared skill tree {expected.SkillId}.");
            }
        }

        var signature = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
            Signature.Value,
            "plugin execution-admission signature",
            64);
        using var verifier = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
                    trust.X,
                    "plugin execution-admission key x",
                    32),
                Y = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
                    trust.Y,
                    "plugin execution-admission key y",
                    32),
            },
        });
        if (!verifier.VerifyData(
                CanonicalPayload(this),
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            throw new InvalidDataException(
                "Plugin execution-admission signature verification failed.");
        }
    }

    internal static byte[] CanonicalPayload(PluginExecutionAdmissionReceipt receipt)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", receipt.SchemaVersion);
            writer.WriteString("receiptType", receipt.ReceiptType);
            writer.WriteString("decision", receipt.Decision);
            writer.WriteNumber("reviewedAtUnixSeconds", receipt.ReviewedAtUnixSeconds);
            writer.WriteString("policyId", receipt.PolicyId);
            writer.WriteNumber("generation", receipt.Generation);
            writer.WriteBoolean("critical", receipt.Critical);
            writer.WriteString("launcherReleaseId", receipt.LauncherReleaseId);
            writer.WriteString("runtimeReleaseId", receipt.RuntimeReleaseId);
            writer.WriteString("archiveSha256", receipt.ArchiveSha256);
            writer.WriteNumber("archiveSizeBytes", receipt.ArchiveSizeBytes);
            writer.WriteString("metadataSha256", receipt.MetadataSha256);
            writer.WriteNumber("metadataSizeBytes", receipt.MetadataSizeBytes);
            writer.WriteString("rawPolicySha256", receipt.RawPolicySha256);
            writer.WriteNumber("rawPolicySizeBytes", receipt.RawPolicySizeBytes);
            writer.WriteStartArray("skillPacks");
            foreach (var skill in receipt.SkillPacks.OrderBy(
                         value => value.SkillId,
                         StringComparer.Ordinal))
            {
                writer.WriteStartObject();
                writer.WriteString("skillId", skill.SkillId);
                writer.WriteString("version", skill.Version);
                writer.WriteString("root", skill.Root);
                writer.WriteString("declaredTreeSha256", skill.DeclaredTreeSha256);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return stream.ToArray();
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PluginExecutionAdmissionSkill
{
    public required string SkillId { get; init; }
    public required string Version { get; init; }
    public required string Root { get; init; }
    public required string DeclaredTreeSha256 { get; init; }
}
