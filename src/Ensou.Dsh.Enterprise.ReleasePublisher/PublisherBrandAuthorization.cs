using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.ReleasePublisher;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PilotBrandAuthorizationInput
{
    public required string ReceiptPath { get; init; }
    public required string ReceiptSha256 { get; init; }
    public required string EvidencePath { get; init; }
    public required string EvidenceSha256 { get; init; }
    public required string DistributionAudienceId { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherBrandAuthorizationTrust
{
    public required string KeyId { get; init; }
    public required string X { get; init; }
    public required string Y { get; init; }

    public void Validate()
    {
        PublisherRuntimeAdmissionEncoding.ValidateToken(
            KeyId,
            "brand-authorization keyId",
            64);
        var x = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
            X,
            "brand-authorization key x",
            32);
        var y = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
            Y,
            "brand-authorization key y",
            32);
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
                "Brand-authorization trust is not a valid P-256 public key.",
                exception);
        }
    }

    public void RequireIndependentFrom(
        PublisherRuntimeAdmissionTrust runtimeAdmissionTrust,
        EnterpriseProductionTrustInputs launcherTrust)
    {
        ArgumentNullException.ThrowIfNull(runtimeAdmissionTrust);
        ArgumentNullException.ThrowIfNull(launcherTrust);
        RequireIndependentFromKeys(runtimeAdmissionTrust,
            (launcherTrust.ReleaseKeyId, launcherTrust.ReleaseKeyX, launcherTrust.ReleaseKeyY),
            (launcherTrust.LeaseKeyId, launcherTrust.LeaseKeyX, launcherTrust.LeaseKeyY));
    }

    public void RequireIndependentFrom(
        PublisherRuntimeAdmissionTrust runtimeAdmissionTrust,
        EnterpriseDirectLocalProductionTrustInputs launcherTrust)
    {
        ArgumentNullException.ThrowIfNull(runtimeAdmissionTrust);
        ArgumentNullException.ThrowIfNull(launcherTrust);
        _ = EnterpriseDirectLocalProductionTrustFingerprint.ComputeSha256(launcherTrust);
        RequireIndependentFromKeys(runtimeAdmissionTrust,
            (launcherTrust.ReleaseKeyId, launcherTrust.ReleaseKeyX, launcherTrust.ReleaseKeyY),
            (launcherTrust.LeaseKeyId, launcherTrust.LeaseKeyX, launcherTrust.LeaseKeyY));
    }

    private void RequireIndependentFromKeys(
        PublisherRuntimeAdmissionTrust runtimeAdmissionTrust,
        (string KeyId, string X, string Y) release,
        (string KeyId, string X, string Y) lease)
    {
        Validate();
        runtimeAdmissionTrust.Validate();
        var brandX = DecodeCoordinate(X, "brand-authorization key x");
        var brandY = DecodeCoordinate(Y, "brand-authorization key y");
        foreach (var other in new[]
                 {
                     (runtimeAdmissionTrust.KeyId, runtimeAdmissionTrust.X, runtimeAdmissionTrust.Y),
                     release,
                     lease,
                 })
        {
            var otherX = DecodeCoordinate(other.Item2, "independent trust key x");
            var otherY = DecodeCoordinate(other.Item3, "independent trust key y");
            if (string.Equals(KeyId, other.Item1, StringComparison.Ordinal)
                || (CryptographicOperations.FixedTimeEquals(brandX, otherX)
                    && CryptographicOperations.FixedTimeEquals(brandY, otherY)))
            {
                throw new InvalidDataException(
                    "Brand authorization, runtime admission, release, and lease trust roots must be independent.");
            }
        }
    }

    private static byte[] DecodeCoordinate(string value, string field) =>
        PublisherRuntimeAdmissionEncoding.DecodeBase64Url(value, field, 32);
}

internal static class PublisherBrandAuthorizationTrustResolver
{
    private const string KeyIdName = "EnterpriseBrandAuthorizationKeyId";
    private const string KeyXName = "EnterpriseBrandAuthorizationKeyX";
    private const string KeyYName = "EnterpriseBrandAuthorizationKeyY";

    public static PublisherBrandAuthorizationTrust ResolveProduction()
    {
        var metadata = typeof(Program).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .ToArray();
        var trust = new PublisherBrandAuthorizationTrust
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

internal sealed record PublisherBrandReleaseBinding(
    string ReleaseSetId,
    long Generation,
    long Sequence,
    string ReleaseSetManifestSha256,
    DateTimeOffset ReleaseSetExpiresAtUtc,
    string LauncherReleaseId,
    string LauncherArchiveSha256);

internal sealed record PublisherBrandBinaryPaths(
    string LauncherExecutablePath,
    string BootstrapperExecutablePath,
    string InstallerExecutablePath);

internal sealed record PublisherBrandAuthorizationValidation(
    string AuthorizationId,
    string KeyId,
    string ReceiptSha256,
    string BrandProfileSha256,
    DateTimeOffset ExpiresAtUtc,
    string LauncherExecutableSha256,
    string BootstrapperExecutableSha256,
    string InstallerExecutableSha256);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherBrandAuthorizationReceipt
{
    public const int CurrentSchemaVersion = 1;
    public const string CurrentReceiptType =
        "ensou-dsh-enterprise-brand-authorization";
    public const string AuthorizedDecision = "authorized";
    public const string ProductionEnvironment = "production";
    public const string PilotChannel = "pilot";
    public const string NamedCustomerPilotScope = "named-customer-pilot";

    public required int SchemaVersion { get; init; }
    public required string ReceiptType { get; init; }
    public required string AuthorizationId { get; init; }
    public required string Decision { get; init; }
    public required string Environment { get; init; }
    public required string Channel { get; init; }
    public required string DistributionScope { get; init; }
    public required string DistributionAudienceId { get; init; }
    public required PublisherBrandReleaseReceiptBinding ReleaseBinding { get; init; }
    public required PublisherBrandReceiptProfile Brand { get; init; }
    public required PublisherBrandReceiptEvidence Evidence { get; init; }
    public required PublisherBrandReceiptBinaries Binaries { get; init; }
    public required long ReviewedAtUnixSeconds { get; init; }
    public required long NotBeforeUnixSeconds { get; init; }
    public required long ExpiresAtUnixSeconds { get; init; }
    public required EnterpriseReleaseSignature Signature { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherBrandReleaseReceiptBinding
{
    public required string ReleaseSetId { get; init; }
    public required long Generation { get; init; }
    public required long Sequence { get; init; }
    public required string ReleaseSetManifestSha256 { get; init; }
    public required string LauncherReleaseId { get; init; }
    public required string LauncherArchiveSha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherBrandReceiptProfile
{
    public required string BrandProfileId { get; init; }
    public required string BrandProfileSha256 { get; init; }
    public required string ProductFamilyName { get; init; }
    public required string LauncherProductName { get; init; }
    public required string InstallerProductName { get; init; }
    public required string BootstrapperProductName { get; init; }
    public required string DeveloperName { get; init; }
    public required string PresentationSha256 { get; init; }
    public required string OfficialWhaleSvgSha256 { get; init; }
    public required string LauncherWhalePngSha256 { get; init; }
    public required string WindowsWhaleIcoSha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherBrandReceiptEvidence
{
    public required string DocumentSha256 { get; init; }
    public required long SizeBytes { get; init; }
    public required string MediaType { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherBrandReceiptBinaries
{
    public required string LauncherExecutableSha256 { get; init; }
    public required string BootstrapperExecutableSha256 { get; init; }
    public required string InstallerExecutableSha256 { get; init; }
}

internal static class PublisherBrandAuthorizationValidator
{
    private const int MaximumReceiptBytes = 512 * 1024;
    private const long MaximumEvidenceBytes = 32L * 1024 * 1024;
    private static readonly TimeSpan MaximumReviewAge = TimeSpan.FromDays(30);
    private static readonly TimeSpan MaximumFutureSkew = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MaximumAuthorizationLifetime = TimeSpan.FromDays(90);
    private static readonly HashSet<string> AllowedEvidenceMediaTypes =
        new(StringComparer.Ordinal)
        {
            "application/pdf",
            "message/rfc822",
            "application/pkcs7-mime",
        };

    public static PublisherBrandAuthorizationValidation Validate(
        PilotBrandAuthorizationInput input,
        string receiptSnapshotPath,
        string evidenceSnapshotPath,
        PublisherBrandReleaseBinding release,
        PublisherBrandBinaryPaths binaries,
        PublisherBrandAuthorizationTrust trust,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(release);
        ArgumentNullException.ThrowIfNull(binaries);
        ArgumentNullException.ThrowIfNull(trust);
        if (nowUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException(
                "Brand authorization must be evaluated with UTC trusted time.");
        }
        RequireCanonicalUuid(input.DistributionAudienceId, "distribution audience id");
        RequireLowerSha256(input.ReceiptSha256, "brand-authorization receipt SHA-256");
        RequireLowerSha256(input.EvidenceSha256, "brand evidence SHA-256");

        var receiptBytes = ReadLockedFile(
            receiptSnapshotPath,
            MaximumReceiptBytes,
            "Brand-authorization receipt");
        var receiptSha256 = HashBytes(receiptBytes);
        if (!string.Equals(receiptSha256, input.ReceiptSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Brand-authorization receipt SHA-256 changed.");
        }
        var receipt = PublisherRuntimeAdmissionJson.Parse<PublisherBrandAuthorizationReceipt>(
            receiptBytes,
            "Brand-authorization receipt");
        VerifySignature(receipt, trust);

        var (evidenceLength, evidenceSha256) = HashLockedFile(
            evidenceSnapshotPath,
            MaximumEvidenceBytes,
            "Brand-authorization evidence");
        if (!string.Equals(evidenceSha256, input.EvidenceSha256, StringComparison.Ordinal)
            || receipt.Evidence is null
            || !string.Equals(
                receipt.Evidence.DocumentSha256,
                evidenceSha256,
                StringComparison.Ordinal)
            || receipt.Evidence.SizeBytes != evidenceLength
            || !AllowedEvidenceMediaTypes.Contains(receipt.Evidence.MediaType))
        {
            throw new InvalidDataException(
                "Brand-authorization evidence bytes or media contract are invalid.");
        }

        var launcherExecutableSha256 = HashLockedFile(
            binaries.LauncherExecutablePath,
            long.MaxValue,
            "Launcher executable").Sha256;
        var bootstrapperExecutableSha256 = HashLockedFile(
            binaries.BootstrapperExecutablePath,
            long.MaxValue,
            "Bootstrapper executable").Sha256;
        var installerExecutableSha256 = HashLockedFile(
            binaries.InstallerExecutablePath,
            long.MaxValue,
            "Installer executable").Sha256;
        RequireExactReceipt(
            receipt,
            input.DistributionAudienceId,
            release,
            launcherExecutableSha256,
            bootstrapperExecutableSha256,
            installerExecutableSha256,
            nowUtc);

        return new PublisherBrandAuthorizationValidation(
            receipt.AuthorizationId,
            trust.KeyId,
            receiptSha256,
            receipt.Brand.BrandProfileSha256,
            DateTimeOffset.FromUnixTimeSeconds(receipt.ExpiresAtUnixSeconds),
            launcherExecutableSha256,
            bootstrapperExecutableSha256,
            installerExecutableSha256);
    }

    private static void VerifySignature(
        PublisherBrandAuthorizationReceipt receipt,
        PublisherBrandAuthorizationTrust trust)
    {
        trust.Validate();
        if (receipt.ReleaseBinding is null
            || receipt.Brand is null
            || receipt.Evidence is null
            || receipt.Binaries is null
            || receipt.Signature is null
            || !string.Equals(
                receipt.Signature.Algorithm,
                EnterpriseReleaseSetContract.SignatureAlgorithm,
                StringComparison.Ordinal)
            || !string.Equals(receipt.Signature.KeyId, trust.KeyId, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Brand-authorization receipt signature header is invalid.");
        }
        var signature = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
            receipt.Signature.Value,
            "brand-authorization signature",
            64);
        using var verifier = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
                    trust.X,
                    "brand-authorization key x",
                    32),
                Y = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
                    trust.Y,
                    "brand-authorization key y",
                    32),
            },
        });
        if (!verifier.VerifyData(
                PublisherBrandAuthorizationCanonicalJson.Payload(receipt),
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            throw new InvalidDataException(
                "Brand-authorization receipt signature verification failed.");
        }
    }

    private static void RequireExactReceipt(
        PublisherBrandAuthorizationReceipt receipt,
        string distributionAudienceId,
        PublisherBrandReleaseBinding release,
        string launcherExecutableSha256,
        string bootstrapperExecutableSha256,
        string installerExecutableSha256,
        DateTimeOffset nowUtc)
    {
        RequireCanonicalUuid(receipt.AuthorizationId, "brand authorization id");
        RequireCanonicalUuid(receipt.DistributionAudienceId, "distribution audience id");
        if (receipt.SchemaVersion != PublisherBrandAuthorizationReceipt.CurrentSchemaVersion
            || !string.Equals(
                receipt.ReceiptType,
                PublisherBrandAuthorizationReceipt.CurrentReceiptType,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.Decision,
                PublisherBrandAuthorizationReceipt.AuthorizedDecision,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.Environment,
                PublisherBrandAuthorizationReceipt.ProductionEnvironment,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.Channel,
                PublisherBrandAuthorizationReceipt.PilotChannel,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.DistributionScope,
                PublisherBrandAuthorizationReceipt.NamedCustomerPilotScope,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.DistributionAudienceId,
                distributionAudienceId,
                StringComparison.Ordinal)
            || receipt.ReleaseBinding is null
            || receipt.Brand is null
            || receipt.Evidence is null
            || receipt.Binaries is null)
        {
            throw new InvalidDataException(
                "Brand-authorization receipt is not the exact production Pilot contract.");
        }
        if (!string.Equals(
                receipt.ReleaseBinding.ReleaseSetId,
                release.ReleaseSetId,
                StringComparison.Ordinal)
            || receipt.ReleaseBinding.Generation != release.Generation
            || receipt.ReleaseBinding.Sequence != release.Sequence
            || !string.Equals(
                receipt.ReleaseBinding.ReleaseSetManifestSha256,
                release.ReleaseSetManifestSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.ReleaseBinding.LauncherReleaseId,
                release.LauncherReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.ReleaseBinding.LauncherArchiveSha256,
                release.LauncherArchiveSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Brand authorization does not bind the exact signed release set.");
        }
        RequireLowerSha256(
            receipt.ReleaseBinding.ReleaseSetManifestSha256,
            "authorized release-set manifest SHA-256");
        RequireLowerSha256(
            receipt.ReleaseBinding.LauncherArchiveSha256,
            "authorized Launcher archive SHA-256");

        var brand = receipt.Brand;
        if (!string.Equals(
                brand.BrandProfileId,
                EnterpriseBrandContract.BrandProfileId,
                StringComparison.Ordinal)
            || !string.Equals(
                brand.BrandProfileSha256,
                EnterpriseBrandContract.ProfileSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                brand.ProductFamilyName,
                EnterpriseBrandContract.ProductFamilyName,
                StringComparison.Ordinal)
            || !string.Equals(
                brand.LauncherProductName,
                EnterpriseBrandContract.LauncherProductName,
                StringComparison.Ordinal)
            || !string.Equals(
                brand.InstallerProductName,
                EnterpriseBrandContract.InstallerProductName,
                StringComparison.Ordinal)
            || !string.Equals(
                brand.BootstrapperProductName,
                EnterpriseBrandContract.BootstrapperProductName,
                StringComparison.Ordinal)
            || !string.Equals(
                brand.DeveloperName,
                EnterpriseBrandContract.DeveloperName,
                StringComparison.Ordinal)
            || !string.Equals(
                brand.PresentationSha256,
                EnterpriseBrandContract.PresentationSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                brand.OfficialWhaleSvgSha256,
                EnterpriseBrandContract.OfficialWhaleSvgSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                brand.LauncherWhalePngSha256,
                EnterpriseBrandContract.LauncherWhalePngSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                brand.WindowsWhaleIcoSha256,
                EnterpriseBrandContract.WindowsWhaleIcoSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Brand authorization does not admit the exact product presentation and assets.");
        }

        if (!string.Equals(
                receipt.Binaries.LauncherExecutableSha256,
                launcherExecutableSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.Binaries.BootstrapperExecutableSha256,
                bootstrapperExecutableSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.Binaries.InstallerExecutableSha256,
                installerExecutableSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Brand authorization does not bind the exact final executables.");
        }
        RequireLowerSha256(
            receipt.Binaries.LauncherExecutableSha256,
            "authorized Launcher executable SHA-256");
        RequireLowerSha256(
            receipt.Binaries.BootstrapperExecutableSha256,
            "authorized Bootstrapper executable SHA-256");
        RequireLowerSha256(
            receipt.Binaries.InstallerExecutableSha256,
            "authorized Installer executable SHA-256");

        DateTimeOffset reviewedAt;
        DateTimeOffset notBefore;
        DateTimeOffset expiresAt;
        try
        {
            reviewedAt = DateTimeOffset.FromUnixTimeSeconds(receipt.ReviewedAtUnixSeconds);
            notBefore = DateTimeOffset.FromUnixTimeSeconds(receipt.NotBeforeUnixSeconds);
            expiresAt = DateTimeOffset.FromUnixTimeSeconds(receipt.ExpiresAtUnixSeconds);
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new InvalidDataException(
                "Brand-authorization receipt time is outside the supported range.",
                exception);
        }
        if (reviewedAt <= nowUtc - MaximumReviewAge
            || reviewedAt > nowUtc + MaximumFutureSkew
            || notBefore > nowUtc
            || expiresAt <= nowUtc
            || expiresAt <= reviewedAt
            || expiresAt > reviewedAt + MaximumAuthorizationLifetime
            || expiresAt < release.ReleaseSetExpiresAtUtc)
        {
            throw new InvalidDataException(
                "Brand authorization is stale, not yet valid, expired, or shorter than the release set.");
        }
    }

    private static (long Length, string Sha256) HashLockedFile(
        string path,
        long maximumBytes,
        string field)
    {
        using var stream = PublisherSafeFile.OpenLockedRead(path);
        var expectedLength = stream.Length;
        if (expectedLength <= 0 || expectedLength > maximumBytes)
        {
            throw new InvalidDataException($"{field} size is invalid.");
        }
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
                throw new IOException($"{field} grew while it was hashed.");
            }
            hash.AppendData(buffer, 0, read);
        }
        if (total != expectedLength || stream.Length != expectedLength)
        {
            throw new IOException($"{field} length changed while it was hashed.");
        }
        return (expectedLength, Convert.ToHexStringLower(hash.GetHashAndReset()));
    }

    private static byte[] ReadLockedFile(string path, int maximumBytes, string field)
    {
        using var stream = PublisherSafeFile.OpenLockedRead(path);
        if (stream.Length <= 0 || stream.Length > maximumBytes)
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

    private static string HashBytes(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static void RequireLowerSha256(string value, string field)
    {
        if (value is not { Length: 64 }
            || value.Any(character => character is not (>= '0' and <= '9')
                and not (>= 'a' and <= 'f')))
        {
            throw new InvalidDataException($"{field} is not canonical lowercase SHA-256.");
        }
    }

    private static void RequireCanonicalUuid(string value, string field)
    {
        if (!Guid.TryParseExact(value, "D", out var parsed)
            || !string.Equals(parsed.ToString("D"), value, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"{field} is not a canonical lowercase UUID.");
        }
    }
}

internal static class PublisherBrandAuthorizationCanonicalJson
{
    public static byte[] Payload(PublisherBrandAuthorizationReceipt receipt)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", receipt.SchemaVersion);
            writer.WriteString("receiptType", receipt.ReceiptType);
            writer.WriteString("authorizationId", receipt.AuthorizationId);
            writer.WriteString("decision", receipt.Decision);
            writer.WriteString("environment", receipt.Environment);
            writer.WriteString("channel", receipt.Channel);
            writer.WriteString("distributionScope", receipt.DistributionScope);
            writer.WriteString("distributionAudienceId", receipt.DistributionAudienceId);

            writer.WritePropertyName("releaseBinding");
            writer.WriteStartObject();
            writer.WriteString("releaseSetId", receipt.ReleaseBinding.ReleaseSetId);
            writer.WriteNumber("generation", receipt.ReleaseBinding.Generation);
            writer.WriteNumber("sequence", receipt.ReleaseBinding.Sequence);
            writer.WriteString(
                "releaseSetManifestSha256",
                receipt.ReleaseBinding.ReleaseSetManifestSha256);
            writer.WriteString("launcherReleaseId", receipt.ReleaseBinding.LauncherReleaseId);
            writer.WriteString(
                "launcherArchiveSha256",
                receipt.ReleaseBinding.LauncherArchiveSha256);
            writer.WriteEndObject();

            writer.WritePropertyName("brand");
            writer.WriteStartObject();
            writer.WriteString("brandProfileId", receipt.Brand.BrandProfileId);
            writer.WriteString("brandProfileSha256", receipt.Brand.BrandProfileSha256);
            writer.WriteString("productFamilyName", receipt.Brand.ProductFamilyName);
            writer.WriteString("launcherProductName", receipt.Brand.LauncherProductName);
            writer.WriteString("installerProductName", receipt.Brand.InstallerProductName);
            writer.WriteString(
                "bootstrapperProductName",
                receipt.Brand.BootstrapperProductName);
            writer.WriteString("developerName", receipt.Brand.DeveloperName);
            writer.WriteString("presentationSha256", receipt.Brand.PresentationSha256);
            writer.WriteString(
                "officialWhaleSvgSha256",
                receipt.Brand.OfficialWhaleSvgSha256);
            writer.WriteString(
                "launcherWhalePngSha256",
                receipt.Brand.LauncherWhalePngSha256);
            writer.WriteString(
                "windowsWhaleIcoSha256",
                receipt.Brand.WindowsWhaleIcoSha256);
            writer.WriteEndObject();

            writer.WritePropertyName("evidence");
            writer.WriteStartObject();
            writer.WriteString("documentSha256", receipt.Evidence.DocumentSha256);
            writer.WriteNumber("sizeBytes", receipt.Evidence.SizeBytes);
            writer.WriteString("mediaType", receipt.Evidence.MediaType);
            writer.WriteEndObject();

            writer.WritePropertyName("binaries");
            writer.WriteStartObject();
            writer.WriteString(
                "launcherExecutableSha256",
                receipt.Binaries.LauncherExecutableSha256);
            writer.WriteString(
                "bootstrapperExecutableSha256",
                receipt.Binaries.BootstrapperExecutableSha256);
            writer.WriteString(
                "installerExecutableSha256",
                receipt.Binaries.InstallerExecutableSha256);
            writer.WriteEndObject();

            writer.WriteNumber("reviewedAtUnixSeconds", receipt.ReviewedAtUnixSeconds);
            writer.WriteNumber("notBeforeUnixSeconds", receipt.NotBeforeUnixSeconds);
            writer.WriteNumber("expiresAtUnixSeconds", receipt.ExpiresAtUnixSeconds);
            writer.WriteEndObject();
        }
        return stream.ToArray();
    }
}
