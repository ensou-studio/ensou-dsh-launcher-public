using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.FeedPromoter;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseFeedTrustConfiguration
{
    public required int SchemaVersion { get; init; }
    public required string Product { get; init; }
    public required string Environment { get; init; }
    public required Uri ManifestOrigin { get; init; }
    public required Uri ArtifactOrigin { get; init; }
    public required IReadOnlyList<EnterpriseReleasePublicKey> ReleaseKeys { get; init; }
    public required IReadOnlyList<EnterpriseReleasePublicKey> CertificationKeys { get; init; }
    public int AllowedClockSkewSeconds { get; init; } = 120;
    public int MaximumOfflineGraceHours { get; init; } = 168;

    public static EnterpriseFeedTrustConfiguration Parse(
        ReadOnlySpan<byte> json,
        string expectedChannel)
    {
        if (json.Length is <= 0 or > 256 * 1024)
        {
            throw new InvalidDataException("Enterprise feed trust document size is invalid.");
        }
        try
        {
            EnterpriseReleaseJson.RequireNoDuplicateMembers(json);
            var value = JsonSerializer.Deserialize<EnterpriseFeedTrustConfiguration>(
                json,
                FeedJson.Options)
                ?? throw new InvalidDataException("Enterprise feed trust document is empty.");
            _ = value.ToReleasePolicy(expectedChannel);
            RequireKeyRing(value.CertificationKeys, "certification");
            return value;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Enterprise feed trust JSON is invalid.", exception);
        }
    }

    public EnterpriseReleaseTrustPolicy ToReleasePolicy(string expectedChannel)
    {
        if (SchemaVersion != 1
            || AllowedClockSkewSeconds is < 0 or > 600
            || MaximumOfflineGraceHours is < 1 or > 336)
        {
            throw new InvalidDataException("Enterprise feed trust configuration is invalid.");
        }
        RequireKeyRing(ReleaseKeys, "release");
        var policy = new EnterpriseReleaseTrustPolicy
        {
            Product = Product,
            Environment = Environment,
            ExpectedChannel = expectedChannel,
            CurrentStartupStubProtocol =
                EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
            ManifestOrigin = ManifestOrigin,
            ArtifactOrigin = ArtifactOrigin,
            TrustedKeys = ReleaseKeys,
            AllowedClockSkew = TimeSpan.FromSeconds(AllowedClockSkewSeconds),
            MaximumOfflineGrace = TimeSpan.FromHours(MaximumOfflineGraceHours),
        };
        policy.Validate();
        return policy;
    }

    private static void RequireKeyRing(
        IReadOnlyList<EnterpriseReleasePublicKey>? keys,
        string label)
    {
        if (keys is null
            || keys.Count is <= 0 or > 16
            || keys.Select(key => key.KeyId).Distinct(StringComparer.Ordinal).Count() != keys.Count)
        {
            throw new InvalidDataException($"Enterprise {label} key ring is invalid.");
        }
        foreach (var key in keys)
        {
            EnterpriseReleaseSetValidator.ValidateToken(key.KeyId, $"{label} keyId", 64);
            if (EnterpriseBase64Url.Decode(key.X, $"{label} public key x").Length != 32
                || EnterpriseBase64Url.Decode(key.Y, $"{label} public key y").Length != 32)
            {
                throw new InvalidDataException(
                    $"Enterprise {label} keys must be P-256 coordinates.");
            }
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseStablePromotionAuthorization
{
    public required int SchemaVersion { get; init; }
    public required string Product { get; init; }
    public required string Channel { get; init; }
    public required string ReleaseSetId { get; init; }
    public required string ManifestSha256 { get; init; }
    public required string CertificationReceiptSha256 { get; init; }
    public required string InstallerFileName { get; init; }
    public required long InstallerSizeBytes { get; init; }
    public required string InstallerSha256 { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset ExpiresAtUtc { get; init; }
    public required EnterpriseReleaseSignature Signature { get; init; }

    public static EnterpriseStablePromotionAuthorization Parse(ReadOnlySpan<byte> json)
    {
        if (json.Length is <= 0 or > 128 * 1024)
        {
            throw new InvalidDataException("Stable promotion authorization size is invalid.");
        }
        try
        {
            EnterpriseReleaseJson.RequireNoDuplicateMembers(json);
            return JsonSerializer.Deserialize<EnterpriseStablePromotionAuthorization>(
                       json,
                       FeedJson.Options)
                   ?? throw new InvalidDataException("Stable promotion authorization is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Stable promotion authorization JSON is invalid.", exception);
        }
    }

    public static byte[] CanonicalPayload(EnterpriseStablePromotionAuthorization value) =>
        Encoding.UTF8.GetBytes(string.Join(
            '\n',
            "ensou-dsh-enterprise-stable-promotion-authorization-v1",
            value.Product,
            value.Channel,
            value.ReleaseSetId,
            value.ManifestSha256,
            value.CertificationReceiptSha256,
            value.InstallerFileName,
            value.InstallerSizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            value.InstallerSha256,
            value.IssuedAtUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
            value.ExpiresAtUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture)));

    public void Verify(
        EnterpriseFeedTrustConfiguration trust,
        EnterpriseReleaseSetManifest manifest,
        string manifestSha256,
        EnterpriseCertifiedDistributionReceipt receipt,
        string receiptSha256,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(receipt);
        if (SchemaVersion != 1
            || !string.Equals(Product, EnterpriseReleaseSetContract.Product, StringComparison.Ordinal)
            || !string.Equals(Channel, "stable", StringComparison.Ordinal)
            || !string.Equals(ReleaseSetId, manifest.ReleaseSetId, StringComparison.Ordinal)
            || !string.Equals(ManifestSha256, manifestSha256, StringComparison.Ordinal)
            || !string.Equals(CertificationReceiptSha256, receiptSha256, StringComparison.Ordinal)
            || !string.Equals(InstallerFileName, receipt.Installer.FileName, StringComparison.Ordinal)
            || InstallerSizeBytes != receipt.Installer.SizeBytes
            || !string.Equals(InstallerSha256, receipt.Installer.Sha256, StringComparison.Ordinal)
            || !EnterpriseReleaseValueValidator.IsSha256(ManifestSha256)
            || !EnterpriseReleaseValueValidator.IsSha256(CertificationReceiptSha256)
            || !EnterpriseReleaseValueValidator.IsSha256(InstallerSha256)
            || IssuedAtUtc.Offset != TimeSpan.Zero
            || ExpiresAtUtc.Offset != TimeSpan.Zero
            || IssuedAtUtc > nowUtc + TimeSpan.FromSeconds(trust.AllowedClockSkewSeconds)
            || ExpiresAtUtc < nowUtc - TimeSpan.FromSeconds(trust.AllowedClockSkewSeconds)
            || ExpiresAtUtc <= IssuedAtUtc
            || ExpiresAtUtc - IssuedAtUtc > TimeSpan.FromDays(7)
            || receipt.ApprovedAtUtc > IssuedAtUtc
                + TimeSpan.FromSeconds(trust.AllowedClockSkewSeconds)
            || receipt.Feed.VerifiedAtUtc > receipt.ApprovedAtUtc)
        {
            throw new InvalidDataException("Stable promotion authorization is invalid or expired.");
        }
        EnterpriseEs256SignatureVerifier.Verify(
            Signature,
            CanonicalPayload(this),
            trust.CertificationKeys);
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseCertifiedDistributionReceipt
{
    public required int SchemaVersion { get; init; }
    public required string Product { get; init; }
    public required string Channel { get; init; }
    public required string ReleaseSetId { get; init; }
    public required string ManifestSha256 { get; init; }
    public required CertifiedInstaller Installer { get; init; }
    public required CertifiedFeed Feed { get; init; }
    public required CertifiedTestMatrix Certification { get; init; }
    public required DateTimeOffset ApprovedAtUtc { get; init; }
    public required bool DistributionAuthorized { get; init; }

    public static EnterpriseCertifiedDistributionReceipt Parse(ReadOnlySpan<byte> json)
    {
        if (json.Length is <= 0 or > 512 * 1024)
        {
            throw new InvalidDataException("Certified distribution receipt size is invalid.");
        }
        try
        {
            EnterpriseReleaseJson.RequireNoDuplicateMembers(json);
            return JsonSerializer.Deserialize<EnterpriseCertifiedDistributionReceipt>(
                       json,
                       FeedJson.Options)
                   ?? throw new InvalidDataException("Certified distribution receipt is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Certified distribution receipt JSON is invalid.", exception);
        }
    }

    public void Verify(
        EnterpriseReleaseSetManifest manifest,
        string manifestSha256,
        EnterpriseReleaseTrustPolicy policy)
    {
        var certifiedPilotUri = new Uri(
            policy.ManifestOrigin,
            "v2/channels/pilot/release-set.v2.json").AbsoluteUri;
        if (SchemaVersion != 1
            || !string.Equals(Product, EnterpriseReleaseSetContract.Product, StringComparison.Ordinal)
            || !string.Equals(Channel, "stable", StringComparison.Ordinal)
            || !string.Equals(ReleaseSetId, manifest.ReleaseSetId, StringComparison.Ordinal)
            || !string.Equals(ManifestSha256, manifestSha256, StringComparison.Ordinal)
            || !DistributionAuthorized
            || ApprovedAtUtc.Offset != TimeSpan.Zero
            || Installer is null
            || !Installer.IsValid()
            || Feed is null
            || !Feed.IsValid(certifiedPilotUri, manifestSha256, manifest.Artifacts.Count)
            || Certification is null
            || !Certification.IsValid()
            || ApprovedAtUtc < Feed.VerifiedAtUtc)
        {
            throw new InvalidDataException(
                "Certified distribution receipt does not authorize these exact stable bytes.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record CertifiedInstaller
{
    public required string FileName { get; init; }
    public required long SizeBytes { get; init; }
    public required string Sha256 { get; init; }
    public required string AuthenticodeStatus { get; init; }
    public required string SignerSha256Thumbprint { get; init; }
    public required bool Timestamped { get; init; }

    public bool IsValid() =>
        !string.IsNullOrWhiteSpace(FileName)
        && FileName == Path.GetFileName(FileName)
        && FileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
        && !FileName.Any(char.IsControl)
        && SizeBytes > 0
        && EnterpriseReleaseValueValidator.IsSha256(Sha256)
        && string.Equals(AuthenticodeStatus, "Valid", StringComparison.Ordinal)
        && EnterpriseReleaseValueValidator.IsSha256(SignerSha256Thumbprint)
        && Timestamped;
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record CertifiedFeed
{
    public required Uri ManifestUri { get; init; }
    public required string ExternalManifestSha256 { get; init; }
    public required int VerifiedArtifactCount { get; init; }
    public required bool AllArtifactSignaturesValid { get; init; }
    public required bool AllArtifactHashesValid { get; init; }
    public required bool ImmutablePublication { get; init; }
    public required bool AtomicChannelHead { get; init; }
    public required DateTimeOffset VerifiedAtUtc { get; init; }

    public bool IsValid(string expectedUri, string manifestSha256, int artifactCount) =>
        ManifestUri is not null
        && string.Equals(ManifestUri.AbsoluteUri, expectedUri, StringComparison.Ordinal)
        && string.Equals(ExternalManifestSha256, manifestSha256, StringComparison.Ordinal)
        && VerifiedArtifactCount == artifactCount
        && AllArtifactSignaturesValid
        && AllArtifactHashesValid
        && ImmutablePublication
        && AtomicChannelHead
        && VerifiedAtUtc.Offset == TimeSpan.Zero;
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record CertifiedTestMatrix
{
    public required bool CleanInstallPassed { get; init; }
    public required bool OldInstallUpgradePassed { get; init; }
    public required bool ActualRuntimeStarted { get; init; }
    public required bool WebUiOpened { get; init; }
    public bool? EnterprisePluginLoaded { get; init; }
    public required bool WholeHomeRestorePassed { get; init; }
    public required bool InterruptionMatrixPassed { get; init; }
    public required bool WeakNetworkResumePassed { get; init; }
    public required bool OfflineAndReplayMatrixPassed { get; init; }
    public required bool SameBytesAsPilot { get; init; }
    public required bool PilotSoakPassed { get; init; }
    public required string CleanDeviceEvidenceSha256 { get; init; }
    public required string UpgradeDeviceEvidenceSha256 { get; init; }
    public required string FailureMatrixEvidenceSha256 { get; init; }

    public bool IsValid() =>
        CleanInstallPassed
        && OldInstallUpgradePassed
        && ActualRuntimeStarted
        && WebUiOpened
        && EnterprisePluginLoaded == true
        && WholeHomeRestorePassed
        && InterruptionMatrixPassed
        && WeakNetworkResumePassed
        && OfflineAndReplayMatrixPassed
        && SameBytesAsPilot
        && PilotSoakPassed
        && EnterpriseReleaseValueValidator.IsSha256(CleanDeviceEvidenceSha256)
        && EnterpriseReleaseValueValidator.IsSha256(UpgradeDeviceEvidenceSha256)
        && EnterpriseReleaseValueValidator.IsSha256(FailureMatrixEvidenceSha256);
}

internal static class FeedJson
{
    public static JsonSerializerOptions Options { get; } = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = true,
    };

    public static byte[] Serialize<T>(T value) =>
        JsonSerializer.SerializeToUtf8Bytes(value, Options);

    public static string Sha256(ReadOnlySpan<byte> value) =>
        Convert.ToHexStringLower(SHA256.HashData(value));
}
