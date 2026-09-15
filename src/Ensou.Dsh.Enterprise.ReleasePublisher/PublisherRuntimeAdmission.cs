using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.ReleasePublisher;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherRuntimeAdmissionTrust
{
    public required string KeyId { get; init; }
    public required string X { get; init; }
    public required string Y { get; init; }

    public void Validate()
    {
        PublisherRuntimeAdmissionEncoding.ValidateToken(KeyId, "runtime-admission keyId", 64);
        var x = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(X, "runtime-admission key x", 32);
        var y = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(Y, "runtime-admission key y", 32);
        try
        {
            using var verifier = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y },
            });
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                "Runtime-admission trust is not a valid P-256 public key.",
                exception);
        }
    }

    public void RequireIndependentFrom(
        string releaseKeyId,
        ECParameters releasePublicParameters)
    {
        var admissionX = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
            X,
            "runtime-admission key x",
            32);
        var admissionY = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
            Y,
            "runtime-admission key y",
            32);
        if (string.Equals(KeyId, releaseKeyId, StringComparison.Ordinal)
            || releasePublicParameters.Q.X is null
            || releasePublicParameters.Q.Y is null
            || (CryptographicOperations.FixedTimeEquals(admissionX, releasePublicParameters.Q.X)
                && CryptographicOperations.FixedTimeEquals(
                    admissionY,
                    releasePublicParameters.Q.Y)))
        {
            throw new InvalidDataException(
                "Runtime-admission trust must be independent from the release-signing key.");
        }
    }
}

internal static class PublisherRuntimeAdmissionTrustResolver
{
    private const string KeyIdName = "EnterpriseRuntimeAdmissionKeyId";
    private const string KeyXName = "EnterpriseRuntimeAdmissionKeyX";
    private const string KeyYName = "EnterpriseRuntimeAdmissionKeyY";

    public static PublisherRuntimeAdmissionTrust Resolve(PublisherConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        if (config.Environment == EnterpriseReleaseSetContract.DevelopmentE2EEnvironment)
        {
            var developmentTrust = config.DevelopmentRuntimeAdmissionTrust
                ?? throw new InvalidDataException(
                    "Development-E2E publisher config requires isolated runtime-admission trust.");
            developmentTrust.Validate();
            return developmentTrust;
        }

        if (config.DevelopmentRuntimeAdmissionTrust is not null)
        {
            throw new InvalidDataException(
                "Production runtime-admission trust must not come from publisher config.");
        }

        return ResolveProduction();
    }

    public static PublisherRuntimeAdmissionTrust ResolveProduction()
    {
        var metadata = typeof(Program).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .ToArray();
        var trust = new PublisherRuntimeAdmissionTrust
        {
            KeyId = RequireSingle(metadata, KeyIdName),
            X = RequireSingle(metadata, KeyXName),
            Y = RequireSingle(metadata, KeyYName),
        };
        trust.Validate();
        return trust;
    }

    private static string RequireSingle(
        IReadOnlyList<AssemblyMetadataAttribute> metadata,
        string name)
    {
        var values = metadata
            .Where(value => string.Equals(value.Key, name, StringComparison.Ordinal))
            .Select(value => value.Value)
            .ToArray();
        if (values.Length != 1 || string.IsNullOrWhiteSpace(values[0]))
        {
            throw new InvalidDataException(
                $"Production publisher assembly is missing exact {name} trust metadata.");
        }
        return values[0]!;
    }
}

internal static class PublisherRuntimeAdmissionValidator
{
    public static void Validate(
        PublisherSnapshotArtifact runtime,
        PublisherRuntimeAdmissionTrust trust)
    {
        ArgumentNullException.ThrowIfNull(runtime);
        ArgumentNullException.ThrowIfNull(trust);
        var metadataFile = runtime.SourceRuntimeMetadata
            ?? throw new InvalidDataException("Runtime source metadata snapshot is missing.");
        var receiptFile = runtime.OrganizationAdmissionReceipt
            ?? throw new InvalidDataException("Runtime organization admission snapshot is missing.");

        var metadata = PublisherSourceRuntimeMetadata.Parse(
            metadataFile.ReadAllBytes(4 * 1024 * 1024));
        metadata.RequireExact(
            runtime.Input.ReleaseId,
            Path.GetFileName(runtime.Input.FilePath),
            runtime.File.Length,
            runtime.File.Sha256);

        var receipt = PublisherRuntimeAdmissionReceipt.Parse(
            receiptFile.ReadAllBytes(512 * 1024));
        receipt.Verify(runtime.Input.ReleaseId, metadataFile.Sha256, trust);
        receipt.SourceRelease?.RequireExactArtifacts(
            Path.GetFileName(runtime.Input.FilePath), runtime.File.Length, runtime.File.Sha256,
            Path.GetFileName(metadataFile.StagedPath), metadataFile.Length, metadataFile.Sha256);
    }

    public static PublisherSourceRuntimeMetadata ValidateFiles(
        string runtimeArchivePath,
        string runtimeReleaseId,
        string sourceRuntimeMetadataPath,
        string organizationAdmissionReceiptPath,
        PublisherRuntimeAdmissionTrust trust)
    {
        ArgumentNullException.ThrowIfNull(trust);
        PublisherPathGuard.RequireSafeExistingFile(runtimeArchivePath);
        PublisherPathGuard.RequireSafeExistingFile(sourceRuntimeMetadataPath);
        PublisherPathGuard.RequireSafeExistingFile(organizationAdmissionReceiptPath);
        var (runtimeLength, runtimeSha256) = HashLockedFile(runtimeArchivePath);
        var metadataBytes = ReadLockedFile(
            sourceRuntimeMetadataPath,
            4 * 1024 * 1024,
            "Runtime source metadata");
        var metadata = PublisherSourceRuntimeMetadata.Parse(metadataBytes);
        metadata.RequireExact(
            runtimeReleaseId,
            Path.GetFileName(runtimeArchivePath),
            runtimeLength,
            runtimeSha256);
        var receipt = PublisherRuntimeAdmissionReceipt.Parse(ReadLockedFile(
            organizationAdmissionReceiptPath,
            512 * 1024,
            "Runtime organization admission receipt"));
        receipt.Verify(
            runtimeReleaseId,
            Convert.ToHexStringLower(SHA256.HashData(metadataBytes)),
            trust);
        receipt.SourceRelease?.RequireExactArtifacts(
            Path.GetFileName(runtimeArchivePath), runtimeLength, runtimeSha256,
            Path.GetFileName(sourceRuntimeMetadataPath), metadataBytes.LongLength,
            Convert.ToHexStringLower(SHA256.HashData(metadataBytes)));
        return metadata;
    }

    private static (long Length, string Sha256) HashLockedFile(string path)
    {
        using var stream = PublisherSafeFile.OpenLockedRead(path);
        var expectedLength = stream.Length;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        long total = 0;
        while (true)
        {
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                break;
            }
            total = checked(total + read);
            if (total > expectedLength)
            {
                throw new IOException("Runtime archive grew while admission was verified.");
            }
            hash.AppendData(buffer, 0, read);
        }
        if (total != expectedLength || stream.Length != expectedLength)
        {
            throw new IOException("Runtime archive length changed while admission was verified.");
        }
        return (expectedLength, Convert.ToHexStringLower(hash.GetHashAndReset()));
    }

    private static byte[] ReadLockedFile(string path, int maximumBytes, string field)
    {
        using var stream = PublisherSafeFile.OpenLockedRead(path);
        if (stream.Length is <= 0 || stream.Length > maximumBytes)
        {
            throw new InvalidDataException($"{field} size is invalid.");
        }
        using var output = new MemoryStream(checked((int)stream.Length));
        stream.CopyTo(output);
        if (output.Length != stream.Length)
        {
            throw new IOException($"{field} length changed while it was read.");
        }
        return output.ToArray();
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherRuntimeAdmissionReceipt
{
    public const int CurrentSchemaVersion = 1;
    public const int SourceReleaseSchemaVersion = 2;
    public const string CurrentReceiptType = "ensou-dsh-runtime-organization-admission";
    public const string AdmittedDecision = "admitted";

    public required int SchemaVersion { get; init; }
    public required string ReceiptType { get; init; }
    public required string ReleaseId { get; init; }
    public required string SourceRuntimeMetadataSha256 { get; init; }
    public required string Decision { get; init; }
    public required long ReviewedAtUnixSeconds { get; init; }
    public required EnterpriseReleaseSignature Signature { get; init; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public PublisherRuntimeSourceRelease? SourceRelease { get; init; }

    public static PublisherRuntimeAdmissionReceipt Parse(byte[] bytes)
    {
        var receipt = PublisherRuntimeAdmissionJson.Parse<PublisherRuntimeAdmissionReceipt>(
            bytes,
            "Runtime organization admission receipt");
        using var document = JsonDocument.Parse(bytes);
        var present = document.RootElement.TryGetProperty("sourceRelease", out _);
        if ((receipt.SchemaVersion == CurrentSchemaVersion && present)
            || (receipt.SchemaVersion == SourceReleaseSchemaVersion
                && (!present || receipt.SourceRelease is null
                    || document.RootElement.GetProperty("schemaVersion").ValueKind != JsonValueKind.Number)))
        {
            throw new InvalidDataException("Runtime source-release proof must occur exactly in receipt v2.");
        }
        receipt.SourceRelease?.Validate(receipt.ReleaseId);
        return receipt;
    }

    // Call only after Verify with the existing organization-admission trust.
    // A valid historical v1 receipt never establishes immutable source origin.
    public PublisherRuntimeSourceRelease RequireExactSourceRelease(
        string expectedRepository, string expectedTagName, string expectedTargetCommit)
    {
        if (SchemaVersion != SourceReleaseSchemaVersion || SourceRelease is null)
        {
            throw new InvalidDataException("Immutable source-release admission requires receipt v2.");
        }
        SourceRelease.Validate(ReleaseId);
        if (!string.Equals(SourceRelease.Repository, expectedRepository, StringComparison.Ordinal)
            || !string.Equals(SourceRelease.TagName, expectedTagName, StringComparison.Ordinal)
            || !string.Equals(SourceRelease.TargetCommit, expectedTargetCommit, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Runtime source release differs from the expected build repository, tag or commit.");
        }
        return SourceRelease;
    }

    public void Verify(
        string expectedReleaseId,
        string expectedMetadataSha256,
        PublisherRuntimeAdmissionTrust trust)
    {
        if (SchemaVersion is not (CurrentSchemaVersion or SourceReleaseSchemaVersion)
            || (SchemaVersion == CurrentSchemaVersion && SourceRelease is not null)
            || (SchemaVersion == SourceReleaseSchemaVersion && SourceRelease is null)
            || !string.Equals(ReceiptType, CurrentReceiptType, StringComparison.Ordinal)
            || !string.Equals(ReleaseId, expectedReleaseId, StringComparison.Ordinal)
            || !string.Equals(
                SourceRuntimeMetadataSha256,
                expectedMetadataSha256,
                StringComparison.Ordinal)
            || !PublisherSourceRuntimeMetadata.IsManagedReleaseId(ReleaseId)
            || !PublisherSourceRuntimeMetadata.IsLowercaseSha256(SourceRuntimeMetadataSha256)
            || !string.Equals(Decision, AdmittedDecision, StringComparison.Ordinal)
            || ReviewedAtUnixSeconds <= 0
            || ReviewedAtUnixSeconds <= DateTimeOffset.UtcNow.AddDays(-30).ToUnixTimeSeconds()
            || ReviewedAtUnixSeconds > DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds()
            || Signature is null
            || !string.Equals(
                Signature.Algorithm,
                EnterpriseReleaseSetContract.SignatureAlgorithm,
                StringComparison.Ordinal)
            || !string.Equals(Signature.KeyId, trust.KeyId, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Runtime organization admission receipt does not bind the exact admitted metadata.");
        }

        SourceRelease?.Validate(ReleaseId);
        if (SourceRelease is not null
            && !string.Equals(SourceRelease.Assets[1].Sha256, expectedMetadataSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Runtime source release metadata differs from the admitted metadata.");
        }
        trust.Validate();
        var signature = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
            Signature.Value,
            "runtime-admission signature",
            64);
        using var verifier = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
                    trust.X,
                    "runtime-admission key x",
                    32),
                Y = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
                    trust.Y,
                    "runtime-admission key y",
                    32),
            },
        });
        if (!verifier.VerifyData(
                PublisherRuntimeAdmissionCanonicalJson.Payload(this),
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            throw new InvalidDataException(
                "Runtime organization admission receipt signature verification failed.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
[JsonNumberHandling(JsonNumberHandling.Strict)]
internal sealed record PublisherRuntimeSourceRelease
{
    public const long MaximumGitHubId = 9007199254740991;
    public const long MaximumAssetBytes = 8L * 1024 * 1024 * 1024;
    public required string Repository { get; init; }
    public required long GithubReleaseId { get; init; }
    public required string TagName { get; init; }
    public required string TargetCommit { get; init; }
    public required bool Immutable { get; init; }
    public required IReadOnlyList<PublisherRuntimeSourceAsset> Assets { get; init; }

    public void Validate(string expectedReleaseId)
    {
        var repositoryParts = Repository?.Split('/');
        if (repositoryParts is not { Length: 2 }
            || repositoryParts.Any(part => !IsSafeName(part, 100))
            || GithubReleaseId is <= 0 or > MaximumGitHubId
            || !string.Equals(TagName, expectedReleaseId, StringComparison.Ordinal)
            || !PublisherSourceRuntimeMetadata.IsManagedReleaseId(TagName)
            || TargetCommit is not { Length: 40 }
            || TargetCommit.Any(character => !(character is >= '0' and <= '9' or >= 'a' and <= 'f'))
            || !Immutable || Assets is not { Count: 3 })
        {
            throw new InvalidDataException("Runtime immutable source-release identity is invalid.");
        }
        string[] roles = ["archive", "metadata", "hash-evidence"];
        var ids = new HashSet<long>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < roles.Length; index++)
        {
            var asset = Assets[index];
            if (asset is null || !string.Equals(asset.Role, roles[index], StringComparison.Ordinal)
                || asset.GithubAssetId is <= 0 or > MaximumGitHubId || !ids.Add(asset.GithubAssetId)
                || !IsSafeName(asset.FileName, 255) || !names.Add(asset.FileName)
                || asset.SizeBytes is <= 0 or > MaximumAssetBytes
                || !PublisherSourceRuntimeMetadata.IsLowercaseSha256(asset.Sha256))
            {
                throw new InvalidDataException("Runtime source-release assets must be three exact ordered identities.");
            }
        }
        var archive = Assets[0];
        var evidence = Assets[2];
        if (!string.Equals(evidence.FileName, archive.FileName + ".sha256", StringComparison.Ordinal))
        {
            throw new InvalidDataException("Runtime hash-evidence filename differs from its archive.");
        }
        // The only admitted hash-evidence bytes are one exact ASCII checksum
        // record. Both established line endings are accepted, never extra text.
        var exactRecord = archive.Sha256 + "  " + archive.FileName;
        if (!MatchesRecord(exactRecord + "\n", evidence)
            && !MatchesRecord(exactRecord + "\r\n", evidence))
        {
            throw new InvalidDataException("Runtime hash-evidence bytes do not bind one canonical archive checksum record.");
        }
    }

    public void RequireExactArtifacts(
        string archiveName, long archiveBytes, string archiveSha256,
        string metadataName, long metadataBytes, string metadataSha256)
    {
        Validate(TagName);
        RequireAsset(Assets[0], archiveName, archiveBytes, archiveSha256);
        RequireAsset(Assets[1], metadataName, metadataBytes, metadataSha256);
    }

    private static void RequireAsset(PublisherRuntimeSourceAsset asset, string name, long bytes, string sha256)
    {
        if (!string.Equals(asset.FileName, name, StringComparison.Ordinal) || asset.SizeBytes != bytes
            || !string.Equals(asset.Sha256, sha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Runtime source-release {asset.Role} differs from the exact snapshot.");
        }
    }

    private static bool MatchesRecord(string record, PublisherRuntimeSourceAsset evidence)
    {
        var bytes = Encoding.ASCII.GetBytes(record);
        return evidence.SizeBytes == bytes.LongLength
            && string.Equals(evidence.Sha256, Convert.ToHexStringLower(SHA256.HashData(bytes)), StringComparison.Ordinal);
    }

    private static bool IsSafeName(string? value, int maximumLength) =>
        value is { Length: > 0 } && value.Length <= maximumLength
        && char.IsAsciiLetterOrDigit(value[0]) && value[^1] != '.'
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
[JsonNumberHandling(JsonNumberHandling.Strict)]
internal sealed record PublisherRuntimeSourceAsset
{
    public required string Role { get; init; }
    public required long GithubAssetId { get; init; }
    public required string FileName { get; init; }
    public required long SizeBytes { get; init; }
    public required string Sha256 { get; init; }
}

internal static class PublisherRuntimeAdmissionCanonicalJson
{
    public static byte[] Payload(PublisherRuntimeAdmissionReceipt receipt)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", receipt.SchemaVersion);
            writer.WriteString("receiptType", receipt.ReceiptType);
            writer.WriteString("releaseId", receipt.ReleaseId);
            writer.WriteString(
                "sourceRuntimeMetadataSha256",
                receipt.SourceRuntimeMetadataSha256);
            writer.WriteString("decision", receipt.Decision);
            writer.WriteNumber("reviewedAtUnixSeconds", receipt.ReviewedAtUnixSeconds);
            if (receipt.SchemaVersion == PublisherRuntimeAdmissionReceipt.SourceReleaseSchemaVersion)
            {
                var source = receipt.SourceRelease
                    ?? throw new InvalidDataException("Receipt v2 requires source-release proof.");
                writer.WritePropertyName("sourceRelease");
                writer.WriteStartObject();
                writer.WriteString("repository", source.Repository);
                writer.WriteNumber("githubReleaseId", source.GithubReleaseId);
                writer.WriteString("tagName", source.TagName);
                writer.WriteString("targetCommit", source.TargetCommit);
                writer.WriteBoolean("immutable", source.Immutable);
                writer.WritePropertyName("assets");
                writer.WriteStartArray();
                foreach (var asset in source.Assets)
                {
                    writer.WriteStartObject();
                    writer.WriteString("role", asset.Role);
                    writer.WriteNumber("githubAssetId", asset.GithubAssetId);
                    writer.WriteString("fileName", asset.FileName);
                    writer.WriteNumber("sizeBytes", asset.SizeBytes);
                    writer.WriteString("sha256", asset.Sha256);
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();
                writer.WriteEndObject();
            }
            writer.WriteEndObject();
        }
        return stream.ToArray();
    }
}

// ReleasePublisher consumes one build-embedded projection of the active
// versions lock and its digest-selected managed-patch manifest. The identity
// values below are data, not a second handwritten set of release constants.
internal sealed record PublisherManagedPatchManifestContract(
    string SourceRepository,
    string SourceTag,
    string SourceCommit,
    string SourceTree,
    string DshVersion,
    string BaseLockfileSha256,
    string LockfileSha256,
    string RuntimeWebAuthProtocol,
    string NodeVersion,
    string PnpmVersion,
    string NpmVersion,
    string PatchId,
    string ManifestSchema,
    string ManifestSha256,
    string PatchSha256,
    long PatchBytes,
    int ChangedFileCount,
    int ModifiedPreimageCount,
    string HostCompositionCanonicalSha256)
{
    private const string VersionsLockResourceName =
        "Ensou.Dsh.Enterprise.ReleasePublisher.Contract.versions.locked.json";
    private const string ManifestResourcePrefix =
        "Ensou.Dsh.Enterprise.ReleasePublisher.Contract.manifest.";
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
    private const bool IsEnterpriseDirectLocal = true;
    private const string ExpectedManifestSchema =
        "ensou.dsh.upstream-patch-manifest.v4";
    private const string ExpectedPatchVariant = "enterprise-direct-local-v1";
#else
    private const bool IsEnterpriseDirectLocal = false;
    private const string ExpectedManifestSchema =
        "ensou.dsh.upstream-patch-manifest.v3";
    private const string ExpectedPatchVariant = "enterprise-managed-v1";
#endif

    internal static bool EnterpriseDirectLocalAdmission => IsEnterpriseDirectLocal;

    internal static PublisherManagedPatchManifestContract Current { get; } = Load();

    private static PublisherManagedPatchManifestContract Load()
    {
        var assembly = typeof(PublisherManagedPatchManifestContract).Assembly;
        var versionsLockBytes = ReadEmbeddedResource(
            assembly,
            VersionsLockResourceName);
        using var versionsLockDocument = JsonDocument.Parse(versionsLockBytes);
        PublisherRuntimeAdmissionJson.RequireNoDuplicateMembers(
            versionsLockDocument.RootElement,
            "Embedded versions lock");
        var versionsLock = RequireObjectRoot(
            versionsLockDocument.RootElement,
            "Embedded versions lock");
        if (RequireInt32(versionsLock, "schemaVersion") != 4
            || !string.Equals(
                RequireString(versionsLock, "product"),
                "ensou-dsh-launcher",
                StringComparison.Ordinal)
            || !string.Equals(
                RequireString(versionsLock, "buildMode"),
                "official-source",
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Embedded versions lock is not the supported official-source contract.");
        }

        var lockedPatch = RequireObject(versionsLock, "managedPatch");
        var lockedPatchId = RequireString(lockedPatch, "id");
        var lockedManifestSha256 = RequireLowercaseSha256(
            lockedPatch,
            "manifestSha256");
        var lockedPatchSha256 = RequireLowercaseSha256(
            lockedPatch,
            "patchSha256");

        byte[]? activeManifestBytes = null;
        var matchingManifestCount = 0;
        foreach (var resourceName in assembly.GetManifestResourceNames()
                     .Where(name => name.StartsWith(
                         ManifestResourcePrefix,
                         StringComparison.Ordinal)))
        {
            var candidateBytes = ReadEmbeddedResource(assembly, resourceName);
            var candidateSha256 = Convert.ToHexStringLower(
                SHA256.HashData(candidateBytes));
            if (!string.Equals(
                    candidateSha256,
                    lockedManifestSha256,
                    StringComparison.Ordinal))
            {
                continue;
            }
            activeManifestBytes = candidateBytes;
            matchingManifestCount++;
        }
        if (matchingManifestCount != 1 || activeManifestBytes is null)
        {
            throw new InvalidDataException(
                "Embedded versions lock must select exactly one managed-patch manifest by SHA-256.");
        }

        using var manifestDocument = JsonDocument.Parse(activeManifestBytes);
        PublisherRuntimeAdmissionJson.RequireNoDuplicateMembers(
            manifestDocument.RootElement,
            "Embedded managed-patch manifest");
        var manifest = RequireObjectRoot(
            manifestDocument.RootElement,
            "Embedded managed-patch manifest");
        var manifestSchema = RequireString(manifest, "schema");
        if (!string.Equals(
                manifestSchema,
                ExpectedManifestSchema,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Embedded managed-patch manifest schema is not supported.");
        }

        var source = RequireObject(manifest, "base");
        var sourceRepository = RequireString(source, "repository");
        var sourceTag = RequireString(source, "tag");
        var sourceCommit = RequireString(source, "commit");
        var sourceTree = RequireString(source, "tree");
        var dshVersion = RequireString(versionsLock, "dshVersion");
        var nodeVersion = RequireString(versionsLock, "nodeVersion");
        var pnpmVersion = RequireString(versionsLock, "pnpmVersion");
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
        var npmVersion = RequireString(versionsLock, "npmVersion");
#else
        const string npmVersion = "11.9.0";
#endif
        if (!string.Equals(
                RequireString(versionsLock, "officialTag"),
                sourceTag,
                StringComparison.Ordinal)
            || !string.Equals(
                RequireString(versionsLock, "officialCommit"),
                sourceCommit,
                StringComparison.Ordinal)
            || !string.Equals(
                RequireString(versionsLock, "officialTree"),
                sourceTree,
                StringComparison.Ordinal)
            || !string.Equals(
                sourceTag,
                $"dsh-v{dshVersion}",
                StringComparison.Ordinal)
            || !string.Equals(
                lockedPatchId,
                $"{sourceTag}-{ExpectedPatchVariant}",
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Embedded versions lock and managed-patch source identity do not match.");
        }
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
        if (!string.Equals(
                RequireString(manifest, "patchVariant"),
                ExpectedPatchVariant,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Embedded managed-patch manifest variant is not the compiled admission contract.");
        }
#endif

        var patch = RequireObject(manifest, "patch");
        var patchSha256 = RequireLowercaseSha256(patch, "sha256");
        var patchBytes = RequireInt64(patch, "bytes");
        if (!string.Equals(
                patchSha256,
                lockedPatchSha256,
                StringComparison.Ordinal)
            || patchBytes <= 0)
        {
            throw new InvalidDataException(
                "Embedded versions lock and managed-patch bytes do not match.");
        }

        var counts = RequireObject(manifest, "counts");
        var changedFileCount = RequireInt32(counts, "changedFiles");
        var modifiedPreimageCount = RequireInt32(counts, "modifiedFiles");
        var modifiedPreimages = RequireObject(source, "modifiedPreimages");
        if (changedFileCount <= 0
            || modifiedPreimageCount <= 0
            || modifiedPreimageCount != modifiedPreimages.EnumerateObject().Count())
        {
            throw new InvalidDataException(
                "Embedded managed-patch file counts do not match its preimages.");
        }

        var lockfileChanges = RequireArray(manifest, "changes")
            .EnumerateArray()
            .Where(change => change.ValueKind == JsonValueKind.Object
                && change.TryGetProperty("path", out var path)
                && path.ValueKind == JsonValueKind.String
                && string.Equals(
                    path.GetString(),
                    "pnpm-lock.yaml",
                    StringComparison.Ordinal))
            .ToArray();
        if (lockfileChanges.Length != 1)
        {
            throw new InvalidDataException(
                "Embedded managed-patch manifest must bind exactly one pnpm lockfile change.");
        }
        var lockfileChange = lockfileChanges[0];
        var baseLockfileSha256 = RequireLowercaseSha256(
            RequireObject(lockfileChange, "preimage"),
            "sha256");
        var lockfileSha256 = RequireLowercaseSha256(
            RequireObject(lockfileChange, "postimage"),
            "sha256");
        if (!string.Equals(
                RequireLowercaseSha256(versionsLock, "baseLockfileSha256"),
                baseLockfileSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                RequireLowercaseSha256(versionsLock, "lockfileSha256"),
                lockfileSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Embedded versions lock and managed-patch lockfile digests do not match.");
        }

        var managedPolicy = RequireObject(manifest, "managedPolicy");
        return new PublisherManagedPatchManifestContract(
            sourceRepository,
            sourceTag,
            sourceCommit,
            sourceTree,
            dshVersion,
            baseLockfileSha256,
            lockfileSha256,
            RequireString(versionsLock, "runtimeWebAuthProtocol"),
            nodeVersion,
            pnpmVersion,
            npmVersion,
            lockedPatchId,
            manifestSchema,
            lockedManifestSha256,
            patchSha256,
            patchBytes,
            changedFileCount,
            modifiedPreimageCount,
            RequireLowercaseSha256(
                managedPolicy,
                "hostCompositionCanonicalSha256"));
    }

    private static byte[] ReadEmbeddedResource(Assembly assembly, string resourceName)
    {
        using var stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidDataException(
                $"Required embedded ReleasePublisher contract is missing: {resourceName}.");
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }

    private static JsonElement RequireObjectRoot(JsonElement value, string label)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException($"{label} must be a JSON object.");
        }
        return value;
    }

    private static JsonElement RequireObject(JsonElement parent, string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out var value)
            || value.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                $"Embedded ReleasePublisher contract field '{propertyName}' must be an object.");
        }
        return value;
    }

    private static JsonElement RequireArray(JsonElement parent, string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out var value)
            || value.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException(
                $"Embedded ReleasePublisher contract field '{propertyName}' must be an array.");
        }
        return value;
    }

    private static string RequireString(JsonElement parent, string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out var value)
            || value.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(value.GetString()))
        {
            throw new InvalidDataException(
                $"Embedded ReleasePublisher contract field '{propertyName}' must be a non-empty string.");
        }
        return value.GetString()!;
    }

    private static string RequireLowercaseSha256(
        JsonElement parent,
        string propertyName)
    {
        var value = RequireString(parent, propertyName);
        if (value.Length != 64
            || value.Any(character => character is not (>= '0' and <= '9')
                and not (>= 'a' and <= 'f')))
        {
            throw new InvalidDataException(
                $"Embedded ReleasePublisher contract field '{propertyName}' must be lowercase SHA-256.");
        }
        return value;
    }

    private static int RequireInt32(JsonElement parent, string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out var value)
            || !value.TryGetInt32(out var result))
        {
            throw new InvalidDataException(
                $"Embedded ReleasePublisher contract field '{propertyName}' must be an Int32.");
        }
        return result;
    }

    private static long RequireInt64(JsonElement parent, string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out var value)
            || !value.TryGetInt64(out var result))
        {
            throw new InvalidDataException(
                $"Embedded ReleasePublisher contract field '{propertyName}' must be an Int64.");
        }
        return result;
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherSourceRuntimeMetadata
{
    public required int SchemaVersion { get; init; }
    public required string ReleaseId { get; init; }
    public required bool PromotionEligible { get; init; }
    public required string ArtifactType { get; init; }
    public required bool SourceBuilt { get; init; }
    public required string Platform { get; init; }
    public required string SourceIdentity { get; init; }
    public required string SourceRepository { get; init; }
    public required string SourceTag { get; init; }
    public required string SourceCommit { get; init; }
    public required string SourceTree { get; init; }
    public required string DshVersion { get; init; }
    public required string BaseLockfileSha256 { get; init; }
    public required string LockfileSha256 { get; init; }
    public required string RuntimeWebAuthProtocol { get; init; }
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
    public required string RuntimeProfile { get; init; }
    public required string ManagedUpdateProtocol { get; init; }
#endif
    public required PublisherSourceRuntimeManagedPatch ManagedPatch { get; init; }
    public required PublisherSourceRuntimeManagedPolicy ManagedPolicy { get; init; }
    public required DateTimeOffset BuiltAtUtc { get; init; }
    public required PublisherSourceRuntimeToolchain Toolchain { get; init; }
    public required PublisherSourceRuntimeVerification Verification { get; init; }
    public required PublisherSourceRuntimeArtifact Artifact { get; init; }
    public required PublisherSourceRuntimeLicensing Licensing { get; init; }

    public static PublisherSourceRuntimeMetadata Parse(byte[] bytes) =>
        PublisherRuntimeAdmissionJson.Parse<PublisherSourceRuntimeMetadata>(
            bytes,
            "Source-runtime metadata");

    public void RequireExact(
        string releaseId,
        string archiveFileName,
        long archiveBytes,
        string archiveSha256)
    {
        var managedPatchContract = PublisherManagedPatchManifestContract.Current;
        if (!PromotionEligible)
        {
            throw new InvalidDataException(
                "Source-runtime metadata is not eligible for production promotion.");
        }

        if (
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
            SchemaVersion != 3
#else
            SchemaVersion != 2
#endif
            || !string.Equals(ReleaseId, releaseId, StringComparison.Ordinal)
            || !IsManagedReleaseId(ReleaseId)
            || !string.Equals(
                ArtifactType,
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
                "ensou-dsh-enterprise-direct-local-source-runtime",
#else
                "ensou-dsh-enterprise-managed-source-runtime",
#endif
                StringComparison.Ordinal)
            || !SourceBuilt
            || !string.Equals(Platform, "win32-x64", StringComparison.Ordinal)
            || !string.Equals(
                SourceIdentity,
                "github-https-tag-plus-ensou-managed-patch",
                StringComparison.Ordinal)
            || !string.Equals(
                SourceRepository,
                managedPatchContract.SourceRepository,
                StringComparison.Ordinal)
            || !string.Equals(
                SourceTag,
                managedPatchContract.SourceTag,
                StringComparison.Ordinal)
            || !string.Equals(
                SourceCommit,
                managedPatchContract.SourceCommit,
                StringComparison.Ordinal)
            || !string.Equals(
                SourceTree,
                managedPatchContract.SourceTree,
                StringComparison.Ordinal)
            || !string.Equals(
                DshVersion,
                managedPatchContract.DshVersion,
                StringComparison.Ordinal)
            || !string.Equals(
                BaseLockfileSha256,
                managedPatchContract.BaseLockfileSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                LockfileSha256,
                managedPatchContract.LockfileSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                RuntimeWebAuthProtocol,
                managedPatchContract.RuntimeWebAuthProtocol,
                StringComparison.Ordinal)
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
            || !string.Equals(
                RuntimeProfile,
                "enterprise-direct-local",
                StringComparison.Ordinal)
            || !string.Equals(
                ManagedUpdateProtocol,
                "enterprise-direct-local-v1",
                StringComparison.Ordinal)
#endif
            || BuiltAtUtc.Offset != TimeSpan.Zero
            || BuiltAtUtc <= DateTimeOffset.UnixEpoch
            || ManagedPatch is null
            || ManagedPolicy is null
            || Toolchain is null
            || Verification is null
            || Artifact is null
            || Licensing is null)
        {
            throw new InvalidDataException(
                "Source-runtime metadata does not contain the pinned official source identity.");
        }

        ManagedPatch.Validate();
        ManagedPolicy.Validate();
        Toolchain.Validate();
        Verification.Validate();
        Licensing.Validate();
        Artifact.Validate(archiveFileName, archiveBytes, archiveSha256);
    }

    internal static bool IsLowercaseSha256(string? value) =>
        value is { Length: 64 }
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    internal static bool IsManagedReleaseId(string? value)
    {
        if (value is null || !value.StartsWith("managed-v", StringComparison.Ordinal))
        {
            return false;
        }
        var parts = value[9..].Split('.', StringSplitOptions.None);
        return parts.Length == 4
            && parts[0].Length == 4
            && parts[1].Length == 2
            && parts[2].Length == 2
            && parts.All(part => part.Length > 0 && part.All(char.IsAsciiDigit))
            && parts[3][0] != '0';
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherSourceRuntimeManagedPatch
{
    public required string Id { get; init; }
    public required string ManifestSchema { get; init; }
    public required string ManifestSha256 { get; init; }
    public required string PatchSha256 { get; init; }
    public required long PatchBytes { get; init; }
    public required int ChangedFileCount { get; init; }
    public required int ModifiedPreimageCount { get; init; }

    public void Validate()
    {
        var managedPatchContract = PublisherManagedPatchManifestContract.Current;
        if (!string.Equals(
                Id,
                managedPatchContract.PatchId,
                StringComparison.Ordinal)
            || !string.Equals(
                ManifestSchema,
                managedPatchContract.ManifestSchema,
                StringComparison.Ordinal)
            || !string.Equals(
                ManifestSha256,
                managedPatchContract.ManifestSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                PatchSha256,
                managedPatchContract.PatchSha256,
                StringComparison.Ordinal)
            || PatchBytes != managedPatchContract.PatchBytes
            || ChangedFileCount != managedPatchContract.ChangedFileCount
            || ModifiedPreimageCount !=
                managedPatchContract.ModifiedPreimageCount)
        {
            throw new InvalidDataException("Source-runtime managed patch identity is not pinned.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherSourceRuntimeManagedPolicy
{
    public required string Signal { get; init; }
    public required string Profile { get; init; }
    public required string WebArguments { get; init; }
    public required string Model { get; init; }
    public required int MaxTokens { get; init; }
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
    public required string ModelBaseUrl { get; init; }
    public required string SearchBaseUrl { get; init; }
    public required string CredentialEnvironment { get; init; }
    public required string CredentialSource { get; init; }
    public required IReadOnlyList<string> LaunchEnvironmentProviderOverrides { get; init; }
    public required string SettingsProvider { get; init; }
#else
    public required string GatewayAllowedModel { get; init; }
    public required int GatewayMaxTokens { get; init; }
#endif
    public required string ManagedSkillsRootEnvironment { get; init; }
    public required string SandboxMode { get; init; }
    public required string SandboxMaximumMode { get; init; }
    public required string ApprovalPolicy { get; init; }
    public required IReadOnlyList<string> PermissionPresets { get; init; }
    public required string WorkspaceRootSource { get; init; }
    public required string RestoredSessionCwdPolicy { get; init; }
    public required string HostCompositionCanonicalSha256 { get; init; }
    public required string PresetCompositionCanonicalSha256 { get; init; }
    public required string PresetMetadataCanonicalSha256 { get; init; }
    public required string LoaderRootCanonicalSha256 { get; init; }
    public required string PluginResolutionPolicy { get; init; }

    public void Validate()
    {
        var managedPatchContract = PublisherManagedPatchManifestContract.Current;
        if (!string.Equals(Signal, "DSH_ENTERPRISE_MANAGED_BOOT=ensou-dsh-launcher/v1", StringComparison.Ordinal)
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
            || !string.Equals(Profile, "enterprise-direct-local", StringComparison.Ordinal)
#else
            || !string.Equals(Profile, "enterprise-managed", StringComparison.Ordinal)
#endif
            || !string.Equals(WebArguments, "--host 127.0.0.1 --port <canonical 1..65535>", StringComparison.Ordinal)
            || !string.Equals(Model, "deepseek-v4-flash", StringComparison.Ordinal)
            || MaxTokens != 8192
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
            || !string.Equals(ModelBaseUrl, "https://api.deepseek.com", StringComparison.Ordinal)
            || !string.Equals(SearchBaseUrl, "https://api.deepseek.com/anthropic/v1", StringComparison.Ordinal)
            || !string.Equals(CredentialEnvironment, "DEEPSEEK_API_KEY", StringComparison.Ordinal)
            || !string.Equals(CredentialSource, "@deepseek-ai/dsh-credentials-local writable local credential store", StringComparison.Ordinal)
            || LaunchEnvironmentProviderOverrides is null
            || !LaunchEnvironmentProviderOverrides.SequenceEqual(
                ["DEEPSEEK_BASE_URL", "DEEPSEEK_SEARCH_BASE_URL", "DEEPSEEK_API_KEY"],
                StringComparer.Ordinal)
            || !string.Equals(SettingsProvider, "@deepseek-ai/dsh-settings-file/composition-only", StringComparison.Ordinal)
#else
            || !string.Equals(GatewayAllowedModel, "deepseek-v4-flash", StringComparison.Ordinal)
            || GatewayMaxTokens != 8192
#endif
            || !string.Equals(ManagedSkillsRootEnvironment, "ENSOU_DSH_ENTERPRISE_SKILLS_ROOT", StringComparison.Ordinal)
            || !string.Equals(SandboxMode, "workspace-write", StringComparison.Ordinal)
            || !string.Equals(SandboxMaximumMode, "workspace-write", StringComparison.Ordinal)
            || !string.Equals(ApprovalPolicy, "ask", StringComparison.Ordinal)
            || PermissionPresets is null
            || !PermissionPresets.SequenceEqual(["workspace-write"], StringComparer.Ordinal)
            || !string.Equals(WorkspaceRootSource, "process.cwd()", StringComparison.Ordinal)
            || !string.Equals(RestoredSessionCwdPolicy, "must-equal-workspace-root", StringComparison.Ordinal)
            || !string.Equals(
                HostCompositionCanonicalSha256,
                managedPatchContract.HostCompositionCanonicalSha256,
                StringComparison.Ordinal)
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
            || !string.Equals(PresetCompositionCanonicalSha256, "e3c01ae98d9bf12e57e3ba270169f7059e3b098615e21b4db11fd377367ea546", StringComparison.Ordinal)
            || !string.Equals(PresetMetadataCanonicalSha256, "3590423cb2fb8809c0d11b18dec12f9e1df370a4f05dc93fff1c54e82abc75be", StringComparison.Ordinal)
#else
            || !string.Equals(PresetCompositionCanonicalSha256, "22044243781ab948f0c649843181835ab2b0b676246583ef675db4ad0f51b3b9", StringComparison.Ordinal)
            || !string.Equals(PresetMetadataCanonicalSha256, "4cb4661afe8d79f3687d1c58b401a2c072131dfd83a4c7389cec9e948f3d5eea", StringComparison.Ordinal)
#endif
            || !string.Equals(LoaderRootCanonicalSha256, "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945", StringComparison.Ordinal)
            || !string.Equals(PluginResolutionPolicy, "frozen exact installation map from managed base/web bundles; no ambient fallback", StringComparison.Ordinal))
        {
            throw new InvalidDataException("Source-runtime managed policy identity is not pinned.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherSourceRuntimeToolchain
{
    public required string NodeVersion { get; init; }
    public required string NodeSha256 { get; init; }
    public required string PnpmVersion { get; init; }
    public required string NpmVersion { get; init; }

    public void Validate()
    {
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
        var managedPatchContract = PublisherManagedPatchManifestContract.Current;
        if (!string.Equals(
                NodeVersion,
                managedPatchContract.NodeVersion,
                StringComparison.Ordinal)
            || !PublisherSourceRuntimeMetadata.IsLowercaseSha256(NodeSha256)
            || !string.Equals(
                PnpmVersion,
                managedPatchContract.PnpmVersion,
                StringComparison.Ordinal)
            || !string.Equals(
                NpmVersion,
                managedPatchContract.NpmVersion,
                StringComparison.Ordinal))
#else
        if (!string.Equals(NodeVersion, "24.19.0", StringComparison.Ordinal)
            || !PublisherSourceRuntimeMetadata.IsLowercaseSha256(NodeSha256)
            || !string.Equals(PnpmVersion, "11.7.0", StringComparison.Ordinal)
            || !string.Equals(NpmVersion, "11.9.0", StringComparison.Ordinal))
#endif
        {
            throw new InvalidDataException("Source-runtime toolchain identity is not pinned.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherSourceRuntimeVerification
{
    public required bool CleanCheckout { get; init; }
    public required bool TagCommitMatch { get; init; }
    public required bool RemoteTagCommitMatch { get; init; }
    public required bool TagSignatureVerified { get; init; }
    public required bool OfficialCheckoutUnchanged { get; init; }
    public required bool PatchManifestValidated { get; init; }
    public required bool PatchPreimagesVerified { get; init; }
    public required bool PatchApplyCheck { get; init; }
    public required bool PatchPostimagesVerified { get; init; }
    public required bool FrozenLockfileInstall { get; init; }
    public required bool ManagedFocusedTests { get; init; }
    public required bool ManagedWindowsExcludedFocusedTests { get; init; }
    public required bool ManagedChangedPackageTypeBuild { get; init; }
    public required bool ManagedCliBundle { get; init; }
    public required bool ManagedSourceGates { get; init; }
    public required string SourceBuild { get; init; }
    public required bool BuiltPackageInvariants { get; init; }
    public required string DeploymentMode { get; init; }
    public required bool RuntimeClosureAgainstPinnedSourceAndLock { get; init; }
    public required int RuntimeClosurePackageCount { get; init; }
    public required bool PortableCommandShimGate { get; init; }
    public required bool SymlinkFreeRuntime { get; init; }
    public required bool BundledNodeVersionSmoke { get; init; }
    public required IReadOnlyList<string> NativeModuleSmoke { get; init; }
    public required bool WebProfileDumpSmoke { get; init; }
    public required bool WebHttpSmoke { get; init; }
    public required bool ManagedExactEnvironmentSmoke { get; init; }
    public required bool ManagedWorkspaceCwdSmoke { get; init; }
    public required bool ManagedRefusalSmoke { get; init; }
    public required bool ExtractedArtifactHashManifestVerified { get; init; }
    public required bool ExtractedArtifactSmoke { get; init; }
    public required bool BuildToolingExcluded { get; init; }
    public required string WebSmokeUrl { get; init; }
    public required bool ExternalNetworkIsolation { get; init; }
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
    public required PublisherEnterpriseDirectLocalSmokeReceipt DirectLocalAssembledSmoke { get; init; }
    public required PublisherEnterpriseDirectLocalSmokeReceipt DirectLocalExtractedSmoke { get; init; }
#endif

    public void Validate()
    {
        if (!CleanCheckout
            || !TagCommitMatch
            || !RemoteTagCommitMatch
            || TagSignatureVerified
            || !OfficialCheckoutUnchanged
            || !PatchManifestValidated
            || !PatchPreimagesVerified
            || !PatchApplyCheck
            || !PatchPostimagesVerified
            || !FrozenLockfileInstall
            || !ManagedFocusedTests
            || !ManagedWindowsExcludedFocusedTests
            || !ManagedChangedPackageTypeBuild
            || !ManagedCliBundle
            || !ManagedSourceGates
            || !string.Equals(SourceBuild, "pnpm run build (reviewed managed patch applied)", StringComparison.Ordinal)
            || !BuiltPackageInvariants
            || !string.Equals(DeploymentMode, "pnpm-dedicated-lockfile-offline-deploy", StringComparison.Ordinal)
            || !RuntimeClosureAgainstPinnedSourceAndLock
            || RuntimeClosurePackageCount <= 0
            || !PortableCommandShimGate
            || !SymlinkFreeRuntime
            || !BundledNodeVersionSmoke
            || NativeModuleSmoke is null
            || !NativeModuleSmoke.SequenceEqual(["node-pty", "koffi"], StringComparer.Ordinal)
            || !WebProfileDumpSmoke
            || !WebHttpSmoke
            || !ManagedExactEnvironmentSmoke
            || !ManagedWorkspaceCwdSmoke
            || !ManagedRefusalSmoke
            || !ExtractedArtifactHashManifestVerified
            || !ExtractedArtifactSmoke
            || !BuildToolingExcluded
            || !string.Equals(WebSmokeUrl, "http://127.0.0.1:<ephemeral-port>/", StringComparison.Ordinal)
            || ExternalNetworkIsolation
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
            || DirectLocalAssembledSmoke is null
            || DirectLocalExtractedSmoke is null
#endif
            )
        {
            throw new InvalidDataException("Source-runtime verification facts are incomplete.");
        }
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
        DirectLocalAssembledSmoke.Validate();
        DirectLocalExtractedSmoke.Validate();
#endif
    }
}

#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherEnterpriseDirectLocalSmokeReceipt
{
    public required string Status { get; init; }
    public required string ResultStatus { get; init; }
    public required string Scope { get; init; }
    public required int Cycles { get; init; }
    public required bool KernelBootstrapVerified { get; init; }
    public required bool SettingsReadOnly { get; init; }
    public required bool CredentialsWritable { get; init; }
    public required bool ExactChildExited { get; init; }
    public required bool AuthenticationNegativesVerified { get; init; }
    public required bool LaunchRefusalsVerified { get; init; }
    public required int ModelRequestsSent { get; init; }
    public required int OutputBytes { get; init; }

    public void Validate()
    {
        if (!string.Equals(Status, "PASS", StringComparison.Ordinal)
            || !string.Equals(ResultStatus, "PASS", StringComparison.Ordinal)
            || !string.Equals(
                Scope,
                "BUILT_ENTERPRISE_DIRECT_LOCAL_RUNTIME_CAPABILITY_ONLY",
                StringComparison.Ordinal)
            || Cycles != 2
            || !KernelBootstrapVerified
            || !SettingsReadOnly
            || !CredentialsWritable
            || !ExactChildExited
            || !AuthenticationNegativesVerified
            || !LaunchRefusalsVerified
            || ModelRequestsSent != 0
            || OutputBytes < 0
            || OutputBytes > 8_388_608)
        {
            throw new InvalidDataException(
                "Enterprise direct-local runtime smoke receipt is not exact.");
        }
    }
}
#endif

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherSourceRuntimeArtifact
{
    public required string FileName { get; init; }
    public required long SizeBytes { get; init; }
    public required string Sha256 { get; init; }

    public void Validate(string expectedFileName, long expectedBytes, string expectedSha256)
    {
        if (!string.Equals(FileName, expectedFileName, StringComparison.Ordinal)
            || FileName != Path.GetFileName(FileName)
            || !FileName.EndsWith(".zip", StringComparison.Ordinal)
            || SizeBytes != expectedBytes
            || !string.Equals(Sha256, expectedSha256, StringComparison.Ordinal)
            || !PublisherSourceRuntimeMetadata.IsLowercaseSha256(Sha256))
        {
            throw new InvalidDataException(
                "Source-runtime metadata does not bind the exact runtime archive.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherSourceRuntimeLicensing
{
    public required string HarnessLicense { get; init; }
    public required bool NoticesIncluded { get; init; }
    public required bool OrganizationReviewRequired { get; init; }

    public void Validate()
    {
        if (!string.Equals(HarnessLicense, "MIT", StringComparison.Ordinal)
            || !NoticesIncluded
            || !OrganizationReviewRequired)
        {
            throw new InvalidDataException(
                "Source-runtime metadata does not require organization review.");
        }
    }
}

internal static class PublisherRuntimeAdmissionJson
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static T Parse<T>(byte[] bytes, string label)
        where T : class
    {
        if (bytes.Length <= 0)
        {
            throw new InvalidDataException($"{label} is empty.");
        }
        try
        {
            using var document = JsonDocument.Parse(
                bytes,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 32,
                });
            RequireNoDuplicateMembers(document.RootElement, label);
            return JsonSerializer.Deserialize<T>(bytes, Options)
                ?? throw new InvalidDataException($"{label} is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"{label} JSON is not the exact contract.", exception);
        }
    }

    internal static void RequireNoDuplicateMembers(JsonElement element, string label)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidDataException($"{label} contains duplicate JSON members.");
                }
                RequireNoDuplicateMembers(property.Value, label);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                RequireNoDuplicateMembers(item, label);
            }
        }
    }
}

internal static class PublisherRuntimeAdmissionEncoding
{
    public static void ValidateToken(string value, string field, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > maximumLength
            || value.Any(character => !(char.IsAsciiLetterOrDigit(character)
                || character is '-' or '_' or '.')))
        {
            throw new InvalidDataException($"{field} is invalid.");
        }
    }

    public static byte[] DecodeBase64Url(string value, string field, int expectedBytes)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(value)
                || value.Contains('=')
                || value.Any(character => !(char.IsAsciiLetterOrDigit(character)
                    || character is '-' or '_')))
            {
                throw new FormatException();
            }
            var normalized = value.Replace('-', '+').Replace('_', '/');
            normalized += (normalized.Length % 4) switch
            {
                0 => string.Empty,
                2 => "==",
                3 => "=",
                _ => throw new FormatException(),
            };
            var decoded = Convert.FromBase64String(normalized);
            if (decoded.Length != expectedBytes
                || !string.Equals(EncodeBase64Url(decoded), value, StringComparison.Ordinal))
            {
                throw new FormatException();
            }
            return decoded;
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException(
                $"{field} must be canonical base64url for exactly {expectedBytes} bytes.",
                exception);
        }
    }

    public static string EncodeBase64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
