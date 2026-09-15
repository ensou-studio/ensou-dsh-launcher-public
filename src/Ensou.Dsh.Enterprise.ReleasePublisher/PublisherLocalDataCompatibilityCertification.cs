using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.ReleasePublisher;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PilotLocalDataCompatibilityCertificationInput
{
    public required string ReceiptPath { get; init; }
    public required string ReceiptSha256 { get; init; }
    public required string CertificationAudienceId { get; init; }
}

internal sealed record PublisherLocalDataCompatibilityCertificationTrust
{
    public required string KeyId { get; init; }
    public required string X { get; init; }
    public required string Y { get; init; }

    public void Validate()
    {
        PublisherRuntimeAdmissionEncoding.ValidateToken(
            KeyId,
            "local-data certification keyId",
            64);
        var x = DecodeCoordinate(X, "local-data certification key x");
        var y = DecodeCoordinate(Y, "local-data certification key y");
        ValidateP256Point(x, y, "Local-data certification trust");
    }

    public void RequireIndependentFrom(
        PublisherRuntimeAdmissionTrust runtimeAdmissionTrust,
        PublisherPluginAdmissionTrust pluginAdmissionTrust,
        PublisherBrandAuthorizationTrust brandAuthorizationTrust,
        PublisherLeaseVerificationTrust leaseVerificationTrust,
        string releaseKeyId,
        string releaseKeyX,
        string releaseKeyY)
    {
        ArgumentNullException.ThrowIfNull(runtimeAdmissionTrust);
        ArgumentNullException.ThrowIfNull(pluginAdmissionTrust);
        ArgumentNullException.ThrowIfNull(brandAuthorizationTrust);
        ArgumentNullException.ThrowIfNull(leaseVerificationTrust);
        Validate();
        runtimeAdmissionTrust.Validate();
        pluginAdmissionTrust.Validate();
        brandAuthorizationTrust.Validate();
        leaseVerificationTrust.Validate();
        PublisherRuntimeAdmissionEncoding.ValidateToken(
            releaseKeyId,
            "release-signing keyId",
            64);
        var releaseX = DecodeCoordinate(releaseKeyX, "release-signing key x");
        var releaseY = DecodeCoordinate(releaseKeyY, "release-signing key y");
        ValidateP256Point(releaseX, releaseY, "Release-signing trust");

        var certificationX = DecodeCoordinate(X, "local-data certification key x");
        var certificationY = DecodeCoordinate(Y, "local-data certification key y");
        foreach (var other in new[]
                 {
                     (runtimeAdmissionTrust.KeyId,
                         runtimeAdmissionTrust.X,
                         runtimeAdmissionTrust.Y),
                     (pluginAdmissionTrust.KeyId,
                         pluginAdmissionTrust.X,
                         pluginAdmissionTrust.Y),
                     (brandAuthorizationTrust.KeyId,
                         brandAuthorizationTrust.X,
                         brandAuthorizationTrust.Y),
                     (leaseVerificationTrust.KeyId,
                         leaseVerificationTrust.X,
                         leaseVerificationTrust.Y),
                     (releaseKeyId, releaseKeyX, releaseKeyY),
                 })
        {
            var otherX = DecodeCoordinate(other.Item2, "independent trust key x");
            var otherY = DecodeCoordinate(other.Item3, "independent trust key y");
            if (string.Equals(KeyId, other.Item1, StringComparison.Ordinal)
                || (CryptographicOperations.FixedTimeEquals(certificationX, otherX)
                    && CryptographicOperations.FixedTimeEquals(certificationY, otherY)))
            {
                throw new InvalidDataException(
                    "Local-data certification, release, runtime admission, plugin admission, brand authorization, and lease trust roots must be independent.");
            }
        }
    }

    private static byte[] DecodeCoordinate(string value, string field) =>
        PublisherRuntimeAdmissionEncoding.DecodeBase64Url(value, field, 32);

    private static void ValidateP256Point(byte[] x, byte[] y, string label)
    {
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
                $"{label} is not a valid P-256 public key.",
                exception);
        }
    }
}

internal static class PublisherLocalDataCompatibilityCertificationTrustResolver
{
    private const string KeyIdName = "EnterpriseLocalDataCertificationKeyId";
    private const string KeyXName = "EnterpriseLocalDataCertificationKeyX";
    private const string KeyYName = "EnterpriseLocalDataCertificationKeyY";

    public static PublisherLocalDataCompatibilityCertificationTrust ResolveProduction()
    {
        var metadata = typeof(Program).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .ToArray();
        var trust = new PublisherLocalDataCompatibilityCertificationTrust
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

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherLocalDataCompatibilityCertificationReceipt
{
    public const int CurrentSchemaVersion = 1;
    public const string CurrentReceiptType =
        "ensou-dsh-enterprise-local-data-compatibility-certification";
    public const string PassedDecision = "PASS";
    public const string ProductionEnvironment = "production";
    public const string PilotChannel = "pilot";
    public const string NamedCustomerPilotScope = "named-customer-pilot";

    public required int SchemaVersion { get; init; }
    public required string ReceiptType { get; init; }
    public required string CertificationId { get; init; }
    public required string Decision { get; init; }
    public required string Environment { get; init; }
    public required string Channel { get; init; }
    public required string DistributionScope { get; init; }
    public required string CertificationAudienceId { get; init; }
    public required string FromUpstreamTag { get; init; }
    public required string ToUpstreamTag { get; init; }
    public required string SourceRuntimeZipSha256 { get; init; }
    public required string TargetRuntimeZipSha256 { get; init; }
    public required string EvidenceReportSha256 { get; init; }
    public required string RunnerSha256 { get; init; }
    public required long IssuedAtUnixSeconds { get; init; }
    public required long ExpiresAtUnixSeconds { get; init; }
    public required EnterpriseReleaseSignature Signature { get; init; }

    public static PublisherLocalDataCompatibilityCertificationReceipt Parse(byte[] bytes) =>
        PublisherRuntimeAdmissionJson.Parse<PublisherLocalDataCompatibilityCertificationReceipt>(
            bytes,
            "Local-data compatibility certification receipt");
}

internal sealed record PublisherLocalDataCompatibilityCertificationExpectation(
    string CertificationAudienceId,
    string FromUpstreamTag,
    string ToUpstreamTag,
    string SourceRuntimeZipSha256,
    string TargetRuntimeZipSha256,
    string EvidenceReportSha256,
    string RunnerSha256);

internal sealed record PublisherLocalDataCompatibilityCertificationValidation(
    string CertificationId,
    string KeyId,
    string ReceiptSha256,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc);

internal static class PublisherLocalDataCompatibilityCertificationValidator
{
    private const int MaximumReceiptBytes = 128 * 1024;
    private static readonly TimeSpan MaximumFutureSkew = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MaximumIssueAge = TimeSpan.FromHours(24);
    private static readonly TimeSpan MaximumLifetime = TimeSpan.FromHours(72);

    public static PublisherLocalDataCompatibilityCertificationValidation Validate(
        byte[] receiptBytes,
        PublisherLocalDataCompatibilityCertificationExpectation expected,
        PublisherLocalDataCompatibilityCertificationTrust trust,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(receiptBytes);
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(trust);
        if (nowUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException(
                "Local-data certification must be evaluated with UTC trusted time.");
        }
        if (receiptBytes.Length is <= 0 or > MaximumReceiptBytes)
        {
            throw new InvalidDataException(
                "Local-data compatibility certification receipt has an invalid size.");
        }
        ValidateExpectation(expected);
        trust.Validate();

        var receipt = PublisherLocalDataCompatibilityCertificationReceipt.Parse(receiptBytes);
        RequireExactContract(receipt, expected);
        var issuedAtUtc = ParseUnixSeconds(
            receipt.IssuedAtUnixSeconds,
            "local-data certification issuedAtUnixSeconds");
        var expiresAtUtc = ParseUnixSeconds(
            receipt.ExpiresAtUnixSeconds,
            "local-data certification expiresAtUnixSeconds");
        if (issuedAtUtc > nowUtc + MaximumFutureSkew
            || issuedAtUtc < nowUtc - MaximumIssueAge
            || expiresAtUtc <= nowUtc
            || expiresAtUtc <= issuedAtUtc
            || expiresAtUtc - issuedAtUtc > MaximumLifetime)
        {
            throw new InvalidDataException(
                "Local-data compatibility certification is stale, expired, future-dated, or not short-lived.");
        }

        VerifySignature(receipt, trust);
        return new PublisherLocalDataCompatibilityCertificationValidation(
            receipt.CertificationId,
            trust.KeyId,
            Convert.ToHexStringLower(SHA256.HashData(receiptBytes)),
            issuedAtUtc,
            expiresAtUtc);
    }

    private static void ValidateExpectation(
        PublisherLocalDataCompatibilityCertificationExpectation expected)
    {
        RequireCanonicalUuid(
            expected.CertificationAudienceId,
            "expected certification audience id");
        RequireUpstreamTag(expected.FromUpstreamTag, "expected source upstream tag");
        RequireUpstreamTag(expected.ToUpstreamTag, "expected target upstream tag");
        if (string.Equals(
                expected.FromUpstreamTag,
                expected.ToUpstreamTag,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Local-data certification must bind a real upstream transition.");
        }
        RequireLowerSha256(expected.SourceRuntimeZipSha256, "expected source runtime ZIP SHA-256");
        RequireLowerSha256(expected.TargetRuntimeZipSha256, "expected target runtime ZIP SHA-256");
        RequireLowerSha256(expected.EvidenceReportSha256, "expected evidence report SHA-256");
        RequireLowerSha256(expected.RunnerSha256, "expected runner SHA-256");
    }

    private static void RequireExactContract(
        PublisherLocalDataCompatibilityCertificationReceipt receipt,
        PublisherLocalDataCompatibilityCertificationExpectation expected)
    {
        RequireCanonicalUuid(receipt.CertificationId, "certification id");
        RequireCanonicalUuid(receipt.CertificationAudienceId, "certification audience id");
        RequireUpstreamTag(receipt.FromUpstreamTag, "source upstream tag");
        RequireUpstreamTag(receipt.ToUpstreamTag, "target upstream tag");
        RequireLowerSha256(receipt.SourceRuntimeZipSha256, "source runtime ZIP SHA-256");
        RequireLowerSha256(receipt.TargetRuntimeZipSha256, "target runtime ZIP SHA-256");
        RequireLowerSha256(receipt.EvidenceReportSha256, "evidence report SHA-256");
        RequireLowerSha256(receipt.RunnerSha256, "runner SHA-256");
        if (receipt.SchemaVersion
                != PublisherLocalDataCompatibilityCertificationReceipt.CurrentSchemaVersion
            || !string.Equals(
                receipt.ReceiptType,
                PublisherLocalDataCompatibilityCertificationReceipt.CurrentReceiptType,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.Decision,
                PublisherLocalDataCompatibilityCertificationReceipt.PassedDecision,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.Environment,
                PublisherLocalDataCompatibilityCertificationReceipt.ProductionEnvironment,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.Channel,
                PublisherLocalDataCompatibilityCertificationReceipt.PilotChannel,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.DistributionScope,
                PublisherLocalDataCompatibilityCertificationReceipt.NamedCustomerPilotScope,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.CertificationAudienceId,
                expected.CertificationAudienceId,
                StringComparison.Ordinal)
            || !string.Equals(receipt.FromUpstreamTag, expected.FromUpstreamTag, StringComparison.Ordinal)
            || !string.Equals(receipt.ToUpstreamTag, expected.ToUpstreamTag, StringComparison.Ordinal)
            || !string.Equals(
                receipt.SourceRuntimeZipSha256,
                expected.SourceRuntimeZipSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.TargetRuntimeZipSha256,
                expected.TargetRuntimeZipSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.EvidenceReportSha256,
                expected.EvidenceReportSha256,
                StringComparison.Ordinal)
            || !string.Equals(receipt.RunnerSha256, expected.RunnerSha256, StringComparison.Ordinal)
            || receipt.Signature is null
            || !string.Equals(
                receipt.Signature.Algorithm,
                EnterpriseReleaseSetContract.SignatureAlgorithm,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Local-data compatibility certification does not bind the exact production named-customer Pilot evidence.");
        }
    }

    private static void VerifySignature(
        PublisherLocalDataCompatibilityCertificationReceipt receipt,
        PublisherLocalDataCompatibilityCertificationTrust trust)
    {
        if (!string.Equals(receipt.Signature.KeyId, trust.KeyId, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Local-data certification signature keyId is not trusted.");
        }
        var signature = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
            receipt.Signature.Value,
            "local-data certification signature",
            64);
        using var verifier = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
                    trust.X,
                    "local-data certification key x",
                    32),
                Y = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
                    trust.Y,
                    "local-data certification key y",
                    32),
            },
        });
        if (!verifier.VerifyData(
                PublisherLocalDataCompatibilityCertificationCanonicalJson.Payload(receipt),
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            throw new InvalidDataException(
                "Local-data compatibility certification signature verification failed.");
        }
    }

    private static DateTimeOffset ParseUnixSeconds(long value, string field)
    {
        try
        {
            if (value <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(value));
            }
            return DateTimeOffset.FromUnixTimeSeconds(value);
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new InvalidDataException($"{field} is outside the supported range.", exception);
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

    private static void RequireUpstreamTag(string value, string field)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length < 6
            || value.Length > 64
            || !value.StartsWith("dsh-v", StringComparison.Ordinal)
            || value.Any(character => !(char.IsAsciiLetterOrDigit(character)
                || character is '-' or '.')))
        {
            throw new InvalidDataException($"{field} is not a canonical Harness upstream tag.");
        }
    }

    private static void RequireLowerSha256(string value, string field)
    {
        if (value is not { Length: 64 }
            || value.Any(character => character is not (>= '0' and <= '9')
                and not (>= 'a' and <= 'f')))
        {
            throw new InvalidDataException($"{field} is not canonical lowercase SHA-256.");
        }
    }
}

internal static class PublisherLocalDataCompatibilityCertificationCanonicalJson
{
    public static byte[] Payload(
        PublisherLocalDataCompatibilityCertificationReceipt receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", receipt.SchemaVersion);
            writer.WriteString("receiptType", receipt.ReceiptType);
            writer.WriteString("certificationId", receipt.CertificationId);
            writer.WriteString("decision", receipt.Decision);
            writer.WriteString("environment", receipt.Environment);
            writer.WriteString("channel", receipt.Channel);
            writer.WriteString("distributionScope", receipt.DistributionScope);
            writer.WriteString("certificationAudienceId", receipt.CertificationAudienceId);
            writer.WriteString("fromUpstreamTag", receipt.FromUpstreamTag);
            writer.WriteString("toUpstreamTag", receipt.ToUpstreamTag);
            writer.WriteString("sourceRuntimeZipSha256", receipt.SourceRuntimeZipSha256);
            writer.WriteString("targetRuntimeZipSha256", receipt.TargetRuntimeZipSha256);
            writer.WriteString("evidenceReportSha256", receipt.EvidenceReportSha256);
            writer.WriteString("runnerSha256", receipt.RunnerSha256);
            writer.WriteNumber("issuedAtUnixSeconds", receipt.IssuedAtUnixSeconds);
            writer.WriteNumber("expiresAtUnixSeconds", receipt.ExpiresAtUnixSeconds);
            writer.WriteEndObject();
        }
        return stream.ToArray();
    }
}
