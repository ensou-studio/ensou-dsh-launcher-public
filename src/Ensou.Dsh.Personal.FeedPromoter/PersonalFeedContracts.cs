using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.Personal.FeedPromoter;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalFeedTrustConfiguration
{
    public required int SchemaVersion { get; init; }
    public required string Product { get; init; }
    public required string Environment { get; init; }
    public required Uri ManifestOrigin { get; init; }
    public required Uri ArtifactOrigin { get; init; }
    public required string CertifiedStartupStubVersion { get; init; }
    public required string ExpectedAuthenticodeSignerSha256Thumbprint { get; init; }
    public required IReadOnlyList<PersonalReleasePublicKey> ReleaseKeys { get; init; }
    public required IReadOnlyList<PersonalReleasePublicKey> CertificationKeys { get; init; }
    public required long CanonicalLowSFromSequence { get; init; }
    public int AllowedClockSkewSeconds { get; init; } = 120;
    public int MaximumOfflineGraceHours { get; init; } = 168;

    public static PersonalFeedTrustConfiguration Parse(ReadOnlySpan<byte> json)
    {
        if (json.Length is <= 0 or > 256 * 1024)
        {
            throw new InvalidDataException("Personal feed trust document size is invalid.");
        }
        try
        {
            PersonalFeedJson.RequireNoDuplicateMembers(json);
            var value = JsonSerializer.Deserialize<PersonalFeedTrustConfiguration>(
                json,
                PersonalFeedJson.Options)
                ?? throw new InvalidDataException("Personal feed trust document is empty.");
            value.Validate();
            return value;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Personal feed trust JSON is invalid.", exception);
        }
    }

    public PersonalReleaseTrustPolicy ToReleasePolicy(string channel)
    {
        PersonalReleaseSetValidator.ValidateChannel(channel);
        Validate();
        var policy = new PersonalReleaseTrustPolicy
        {
            Product = Product,
            Environment = Environment,
            Channel = channel,
            ArtifactOrigin = ArtifactOrigin,
            StartupStubVersion = CertifiedStartupStubVersion,
            TrustedKeys = ReleaseKeys,
            CanonicalLowSFromSequence = CanonicalLowSFromSequence,
            AllowedClockSkew = TimeSpan.FromSeconds(AllowedClockSkewSeconds),
            MaximumOfflineGrace = TimeSpan.FromHours(MaximumOfflineGraceHours),
        };
        policy.Validate();
        return policy;
    }

    public void Validate()
    {
        if (SchemaVersion != 1
            || !string.Equals(Product, PersonalReleaseSetContract.Product, StringComparison.Ordinal)
            || !string.Equals(
                Environment,
                PersonalReleaseSetContract.ProductionEnvironment,
                StringComparison.Ordinal)
            || AllowedClockSkewSeconds is < 0 or > 600
            || MaximumOfflineGraceHours is < 1 or > 336
            || CanonicalLowSFromSequence is <= 0
                or > PersonalReleaseSetContract.MaximumSafeInteger)
        {
            throw new InvalidDataException("Personal feed trust configuration is invalid.");
        }
        RequireCanonicalHttpsOrigin(ManifestOrigin, "manifest origin");
        RequireCanonicalHttpsOrigin(ArtifactOrigin, "artifact origin");
        _ = PersonalReleaseVersion.Compare(
            CertifiedStartupStubVersion,
            CertifiedStartupStubVersion);
        if (!PersonalReleaseSetValidator.IsSha256(
                ExpectedAuthenticodeSignerSha256Thumbprint))
        {
            throw new InvalidDataException(
                "Personal feed trust must pin one Authenticode signer SHA-256 thumbprint.");
        }
        RequireKeyRing(ReleaseKeys, "release");
        RequireKeyRing(CertificationKeys, "certification");
        if (ReleaseKeys.Any(release => CertificationKeys.Any(certification =>
                string.Equals(release.KeyId, certification.KeyId, StringComparison.Ordinal)
                || (string.Equals(release.X, certification.X, StringComparison.Ordinal)
                    && string.Equals(release.Y, certification.Y, StringComparison.Ordinal)))))
        {
            throw new InvalidDataException(
                "Personal release and certification key rings must be independent.");
        }
    }

    private static void RequireKeyRing(
        IReadOnlyList<PersonalReleasePublicKey>? keys,
        string label)
    {
        if (keys is null
            || keys.Count is <= 0 or > 16
            || keys.Select(key => key.KeyId).Distinct(StringComparer.Ordinal).Count() != keys.Count)
        {
            throw new InvalidDataException($"Personal {label} key ring is invalid.");
        }
        var publicPoints = new HashSet<string>(StringComparer.Ordinal);
        foreach (var key in keys)
        {
            PersonalReleaseSetValidator.ValidateToken(key.KeyId, $"{label} keyId", 64);
            var x = PersonalReleaseBase64Url.Decode(key.X, $"{label} public key x");
            var y = PersonalReleaseBase64Url.Decode(key.Y, $"{label} public key y");
            if (x.Length != 32 || y.Length != 32)
            {
                throw new InvalidDataException(
                    $"Personal {label} keys must be P-256 coordinates.");
            }
            if (!publicPoints.Add(Convert.ToHexString(x) + Convert.ToHexString(y)))
            {
                throw new InvalidDataException(
                    $"Personal {label} key ring contains the same P-256 point under multiple key IDs.");
            }
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
                    $"Personal {label} key is not a valid P-256 point.",
                    exception);
            }
        }
    }

    internal static void RequireCanonicalHttpsOrigin(Uri? uri, string label)
    {
        if (uri is null
            || !uri.IsAbsoluteUri
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || !string.Equals(uri.AbsolutePath, "/", StringComparison.Ordinal)
            || !uri.OriginalString.All(character =>
                char.IsAscii(character) && character > ' ' && character is not '"' and not '\\'))
        {
            throw new InvalidDataException($"Personal feed {label} must be one canonical HTTPS origin.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalCertifiedDistributionReceipt
{
    public required int SchemaVersion { get; init; }
    public required string Product { get; init; }
    public required string SourceChannel { get; init; }
    public required string TargetChannel { get; init; }
    public required string ReleaseSetId { get; init; }
    public required string PilotManifestSha256 { get; init; }
    public required string StableManifestSha256 { get; init; }
    public required IReadOnlyList<PersonalFeedArtifactReceipt> Artifacts { get; init; }
    public required PersonalCertifiedInstaller Installer { get; init; }
    public required PersonalProductionGateEvidenceReference ProductionGateEvidence { get; init; }
    public required PersonalCertifiedFeedEvidence Feed { get; init; }
    public required PersonalCertifiedTestMatrix Certification { get; init; }
    public required DateTimeOffset ApprovedAtUtc { get; init; }
    public required bool DistributionAuthorized { get; init; }

    public static PersonalCertifiedDistributionReceipt Parse(ReadOnlySpan<byte> json)
    {
        if (json.Length is <= 0 or > 512 * 1024)
        {
            throw new InvalidDataException("Personal certification receipt size is invalid.");
        }
        try
        {
            PersonalFeedJson.RequireNoDuplicateMembers(json);
            var value = JsonSerializer.Deserialize<PersonalCertifiedDistributionReceipt>(
                       json,
                       PersonalFeedJson.Options)
                   ?? throw new InvalidDataException("Personal certification receipt is empty.");
            var canonical = PersonalFeedJson.Serialize(value);
            if (!json.SequenceEqual(canonical))
            {
                throw new InvalidDataException(
                    "Personal certification receipt must use strict canonical JSON.");
            }
            return value;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Personal certification receipt JSON is invalid.", exception);
        }
    }

    internal void Verify(
        PersonalReleaseSetManifest pilot,
        string pilotManifestSha256,
        PersonalReleaseSetManifest stable,
        string stableManifestSha256,
        PersonalFeedTrustConfiguration trust,
        PersonalLifecycleEvidenceSet lifecycleEvidence,
        PersonalProductionGateEvidenceSnapshot? gateEvidence = null)
    {
        ArgumentNullException.ThrowIfNull(pilot);
        ArgumentNullException.ThrowIfNull(stable);
        ArgumentNullException.ThrowIfNull(trust);
        var expectedArtifacts = PersonalFeedArtifactReceipt.FromManifest(stable);
        var pilotArtifacts = PersonalFeedArtifactReceipt.FromManifest(pilot);
        var expectedPilotUri = new Uri(
            trust.ManifestOrigin,
            "v2/channels/pilot/release-set.v2.json").AbsoluteUri;
        if (SchemaVersion != 2
            || !string.Equals(Product, PersonalReleaseSetContract.Product, StringComparison.Ordinal)
            || !string.Equals(SourceChannel, "pilot", StringComparison.Ordinal)
            || !string.Equals(TargetChannel, "stable", StringComparison.Ordinal)
            || !string.Equals(ReleaseSetId, stable.ReleaseSetId, StringComparison.Ordinal)
            || !string.Equals(ReleaseSetId, pilot.ReleaseSetId, StringComparison.Ordinal)
            || !string.Equals(PilotManifestSha256, pilotManifestSha256, StringComparison.Ordinal)
            || !string.Equals(StableManifestSha256, stableManifestSha256, StringComparison.Ordinal)
            || !PersonalReleaseSetValidator.IsSha256(PilotManifestSha256)
            || !PersonalReleaseSetValidator.IsSha256(StableManifestSha256)
            || Artifacts is null
            || Artifacts.Count != 2
            || !Artifacts.SequenceEqual(expectedArtifacts)
            || !pilotArtifacts.SequenceEqual(expectedArtifacts)
            || Installer is null
            || !Installer.IsValid(trust.ExpectedAuthenticodeSignerSha256Thumbprint)
            || ProductionGateEvidence is null
            || Feed is null
            || !Feed.IsValid(expectedPilotUri, pilotManifestSha256)
            || Certification is null
            || ApprovedAtUtc.Offset != TimeSpan.Zero
            || ApprovedAtUtc < Feed.VerifiedAtUtc
            || !DistributionAuthorized)
        {
            throw new InvalidDataException(
                "Personal certification receipt does not authorize these exact Pilot and Stable bytes.");
        }
        Certification.Verify(
            lifecycleEvidence,
            stable,
            pilotManifestSha256,
            ApprovedAtUtc);
        if (gateEvidence is not null)
        {
            ProductionGateEvidence.RequireExact(gateEvidence, ApprovedAtUtc);
        }
    }

    public byte[] SerializeCanonical() => PersonalFeedJson.Serialize(this);
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalFeedArtifactReceipt(
    string Component,
    string ReleaseId,
    string FileName,
    long SizeBytes,
    string Sha256,
    string CompleteTreeSha256)
{
    public static IReadOnlyList<PersonalFeedArtifactReceipt> FromManifest(
        PersonalReleaseSetManifest manifest) => manifest.Artifacts.Select(artifact => new PersonalFeedArtifactReceipt(
            artifact.Component,
            artifact.ReleaseId,
            Path.GetFileName(Uri.UnescapeDataString(artifact.Uri.AbsolutePath)),
            artifact.SizeBytes,
            artifact.Sha256,
            artifact.CompleteTreeSha256)).ToArray();

    public bool IsValid() =>
        (Component is PersonalReleaseSetContract.ClientBundleComponent
            or PersonalReleaseSetContract.RuntimeComponent)
        && !string.IsNullOrWhiteSpace(ReleaseId)
        && FileName == Path.GetFileName(FileName)
        && SizeBytes > 0
        && PersonalReleaseSetValidator.IsSha256(Sha256)
        && PersonalReleaseSetValidator.IsSha256(CompleteTreeSha256);
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalCertifiedInstaller
{
    public const string OfficialFileName = "Ensou.Dsh.Personal.Installer.exe";

    public required string FileName { get; init; }
    public required long SizeBytes { get; init; }
    public required string Sha256 { get; init; }
    public required string AuthenticodeStatus { get; init; }
    public required string SignatureType { get; init; }
    public required string SignerSha256Thumbprint { get; init; }
    public required bool Timestamped { get; init; }

    public bool IsValid(string expectedSignerSha256Thumbprint) =>
        string.Equals(FileName, OfficialFileName, StringComparison.Ordinal)
        && !FileName.Any(char.IsControl)
        && SizeBytes > 0
        && PersonalReleaseSetValidator.IsSha256(Sha256)
        && string.Equals(AuthenticodeStatus, "Valid", StringComparison.Ordinal)
        && string.Equals(SignatureType, "Authenticode", StringComparison.Ordinal)
        && PersonalReleaseSetValidator.IsSha256(SignerSha256Thumbprint)
        && string.Equals(
            SignerSha256Thumbprint,
            expectedSignerSha256Thumbprint,
            StringComparison.OrdinalIgnoreCase)
        && Timestamped;
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalCertifiedFeedEvidence
{
    public required Uri PilotManifestUri { get; init; }
    public required string ExternalPilotManifestSha256 { get; init; }
    public required int VerifiedArtifactCount { get; init; }
    public required bool AllArtifactSignaturesValid { get; init; }
    public required bool AllArtifactHashesValid { get; init; }
    public required bool ImmutablePublication { get; init; }
    public required bool AtomicChannelHead { get; init; }
    public required DateTimeOffset VerifiedAtUtc { get; init; }

    public static PersonalCertifiedFeedEvidence ParseCanonical(ReadOnlySpan<byte> json)
    {
        if (json.Length is <= 0 or > 128 * 1024)
        {
            throw new InvalidDataException(
                "Personal external Pilot feed evidence size is invalid.");
        }
        PersonalFeedJson.RequireNoDuplicateMembers(json);
        var value = JsonSerializer.Deserialize<PersonalCertifiedFeedEvidence>(
                json,
                PersonalFeedJson.Options)
            ?? throw new InvalidDataException(
                "Personal external Pilot feed evidence is empty.");
        if (!json.SequenceEqual(PersonalFeedJson.Serialize(value)))
        {
            throw new InvalidDataException(
                "Personal external Pilot feed evidence must use canonical JSON.");
        }
        return value;
    }

    public byte[] SerializeCanonical() => PersonalFeedJson.Serialize(this);

    public bool IsValid(string expectedUri, string expectedManifestSha256) =>
        PilotManifestUri is not null
        && string.Equals(PilotManifestUri.AbsoluteUri, expectedUri, StringComparison.Ordinal)
        && string.Equals(
            ExternalPilotManifestSha256,
            expectedManifestSha256,
            StringComparison.Ordinal)
        && VerifiedArtifactCount == 2
        && AllArtifactSignaturesValid
        && AllArtifactHashesValid
        && ImmutablePublication
        && AtomicChannelHead
        && VerifiedAtUtc.Offset == TimeSpan.Zero;
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalCertifiedTestMatrix
{
    public required PersonalLifecycleEvidenceReference CleanDeviceLifecycle { get; init; }
    public required PersonalLifecycleEvidenceReference TwoUpdateUpgradeLifecycle { get; init; }
    public required PersonalLifecycleEvidenceReference FailureRecoveryLifecycle { get; init; }

    internal void Verify(
        PersonalLifecycleEvidenceSet evidence,
        PersonalReleaseSetManifest target,
        string pilotManifestSha256,
        DateTimeOffset approvedAtUtc)
    {
        if (CleanDeviceLifecycle is null
            || TwoUpdateUpgradeLifecycle is null
            || FailureRecoveryLifecycle is null)
        {
            throw new InvalidDataException(
                "Personal certification must reference all three lifecycle evidence receipts.");
        }
        CleanDeviceLifecycle.RequireExact(
            evidence.CleanDevice,
            PersonalLifecycleEvidenceContract.CleanDeviceLifecycle,
            approvedAtUtc);
        TwoUpdateUpgradeLifecycle.RequireExact(
            evidence.TwoUpdateUpgrade,
            PersonalLifecycleEvidenceContract.TwoUpdateUpgradeLifecycle,
            approvedAtUtc);
        FailureRecoveryLifecycle.RequireExact(
            evidence.FailureRecovery,
            PersonalLifecycleEvidenceContract.FailureRecoveryLifecycle,
            approvedAtUtc);

        var snapshots = new[]
        {
            evidence.CleanDevice,
            evidence.TwoUpdateUpgrade,
            evidence.FailureRecovery,
        };
        if (snapshots.Select(snapshot => snapshot.RawSha256)
                .Distinct(StringComparer.Ordinal).Count() != snapshots.Length
            || snapshots.Select(snapshot => snapshot.Receipt.TestRunId)
                .Distinct(StringComparer.Ordinal).Count() != snapshots.Length)
        {
            throw new InvalidDataException(
                "Personal lifecycle receipts must come from three distinct exact test runs.");
        }
        foreach (var snapshot in snapshots)
        {
            snapshot.Receipt.VerifyTarget(target, pilotManifestSha256);
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalStablePromotionAuthorization
{
    public required int SchemaVersion { get; init; }
    public required string Product { get; init; }
    public required string Channel { get; init; }
    public required string ReleaseSetId { get; init; }
    public required string PilotManifestSha256 { get; init; }
    public required string StableManifestSha256 { get; init; }
    public required string CertificationReceiptSha256 { get; init; }
    public required string InstallerFileName { get; init; }
    public required long InstallerSizeBytes { get; init; }
    public required string InstallerSha256 { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset ExpiresAtUtc { get; init; }
    public required PersonalReleaseSignature Signature { get; init; }

    public static PersonalStablePromotionAuthorization Parse(ReadOnlySpan<byte> json)
    {
        if (json.Length is <= 0 or > 128 * 1024)
        {
            throw new InvalidDataException("Personal Stable authorization size is invalid.");
        }
        try
        {
            PersonalFeedJson.RequireNoDuplicateMembers(json);
            return JsonSerializer.Deserialize<PersonalStablePromotionAuthorization>(
                       json,
                       PersonalFeedJson.Options)
                   ?? throw new InvalidDataException("Personal Stable authorization is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Personal Stable authorization JSON is invalid.", exception);
        }
    }

    public static byte[] CanonicalPayload(PersonalStablePromotionAuthorization value) =>
        Encoding.UTF8.GetBytes(string.Join(
            '\n',
            "ensou-dsh-personal-stable-promotion-authorization-v1",
            value.Product,
            value.Channel,
            value.ReleaseSetId,
            value.PilotManifestSha256,
            value.StableManifestSha256,
            value.CertificationReceiptSha256,
            value.InstallerFileName,
            value.InstallerSizeBytes.ToString(CultureInfo.InvariantCulture),
            value.InstallerSha256,
            PersonalFeedJson.FormatTimestamp(value.IssuedAtUtc),
            PersonalFeedJson.FormatTimestamp(value.ExpiresAtUtc)));

    public void Verify(
        PersonalFeedTrustConfiguration trust,
        PersonalReleaseSetManifest stable,
        string pilotManifestSha256,
        string stableManifestSha256,
        PersonalCertifiedDistributionReceipt receipt,
        string receiptSha256,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentNullException.ThrowIfNull(stable);
        ArgumentNullException.ThrowIfNull(receipt);
        if (SchemaVersion != 1
            || !string.Equals(Product, PersonalReleaseSetContract.Product, StringComparison.Ordinal)
            || !string.Equals(Channel, "stable", StringComparison.Ordinal)
            || !string.Equals(ReleaseSetId, stable.ReleaseSetId, StringComparison.Ordinal)
            || !string.Equals(PilotManifestSha256, pilotManifestSha256, StringComparison.Ordinal)
            || !string.Equals(StableManifestSha256, stableManifestSha256, StringComparison.Ordinal)
            || !string.Equals(CertificationReceiptSha256, receiptSha256, StringComparison.Ordinal)
            || !string.Equals(InstallerFileName, receipt.Installer.FileName, StringComparison.Ordinal)
            || InstallerSizeBytes != receipt.Installer.SizeBytes
            || !string.Equals(InstallerSha256, receipt.Installer.Sha256, StringComparison.Ordinal)
            || !PersonalReleaseSetValidator.IsSha256(PilotManifestSha256)
            || !PersonalReleaseSetValidator.IsSha256(StableManifestSha256)
            || !PersonalReleaseSetValidator.IsSha256(CertificationReceiptSha256)
            || !PersonalReleaseSetValidator.IsSha256(InstallerSha256)
            || IssuedAtUtc.Offset != TimeSpan.Zero
            || ExpiresAtUtc.Offset != TimeSpan.Zero
            || IssuedAtUtc > nowUtc + TimeSpan.FromSeconds(trust.AllowedClockSkewSeconds)
            || ExpiresAtUtc < nowUtc - TimeSpan.FromSeconds(trust.AllowedClockSkewSeconds)
            || ExpiresAtUtc <= IssuedAtUtc
            || ExpiresAtUtc - IssuedAtUtc > TimeSpan.FromDays(7)
            || receipt.ApprovedAtUtc > IssuedAtUtc
                + TimeSpan.FromSeconds(trust.AllowedClockSkewSeconds))
        {
            throw new InvalidDataException("Personal Stable authorization is invalid or expired.");
        }
        PersonalFeedSignatureVerifier.Verify(
            Signature,
            CanonicalPayload(this),
            trust.CertificationKeys,
            "Stable authorization");
    }
}

internal static class PersonalFeedSignatureVerifier
{
    public static void Verify(
        PersonalReleaseSignature? signature,
        ReadOnlySpan<byte> payload,
        IReadOnlyList<PersonalReleasePublicKey> trustedKeys,
        string label)
    {
        if (signature is null
            || !string.Equals(
                signature.Algorithm,
                PersonalReleaseSetContract.SignatureAlgorithm,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Personal {label} signature algorithm is invalid.");
        }
        var key = trustedKeys.SingleOrDefault(candidate => string.Equals(
            candidate.KeyId,
            signature.KeyId,
            StringComparison.Ordinal))
            ?? throw new InvalidDataException($"Personal {label} signature key is not trusted.");
        var signatureBytes = PersonalReleaseBase64Url.Decode(signature.Value, $"{label} signature");
        if (signatureBytes.Length != 64)
        {
            throw new InvalidDataException($"Personal {label} signature length is invalid.");
        }
        try
        {
            using var verifier = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = PersonalReleaseBase64Url.Decode(key.X, $"{label} public key x"),
                    Y = PersonalReleaseBase64Url.Decode(key.Y, $"{label} public key y"),
                },
            });
            if (!verifier.VerifyData(
                    payload,
                    signatureBytes,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                throw new InvalidDataException($"Personal {label} signature verification failed.");
            }
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                $"Personal {label} signature verification failed.",
                exception);
        }
    }
}

internal static class PersonalFeedJson
{
    private const string TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'";

    public static JsonSerializerOptions Options { get; } = CreateOptions();

    public static byte[] Serialize<T>(T value) =>
        JsonSerializer.SerializeToUtf8Bytes(value, Options);

    public static string Sha256(ReadOnlySpan<byte> value) =>
        Convert.ToHexStringLower(SHA256.HashData(value));

    public static string FormatTimestamp(DateTimeOffset value)
    {
        if (value.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException("Personal feed timestamps must use UTC.");
        }
        return value.ToString(TimestampFormat, CultureInfo.InvariantCulture);
    }

    public static void RequireNoDuplicateMembers(ReadOnlySpan<byte> json)
    {
        using var document = JsonDocument.Parse(json.ToArray(), new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 32,
        });
        RequireNoDuplicateMembers(document.RootElement, "$");
    }

    private static void RequireNoDuplicateMembers(JsonElement value, string path)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidDataException(
                        $"Personal feed JSON contains duplicate member '{property.Name}' at {path}.");
                }
                RequireNoDuplicateMembers(property.Value, $"{path}.{property.Name}");
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in value.EnumerateArray())
            {
                RequireNoDuplicateMembers(item, $"{path}[{index++}]");
            }
        }
    }

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            AllowTrailingCommas = false,
            MaxDepth = 32,
            NumberHandling = JsonNumberHandling.Strict,
            PropertyNameCaseInsensitive = false,
            ReadCommentHandling = JsonCommentHandling.Disallow,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            WriteIndented = true,
        };
        options.Converters.Add(new PersonalFeedUtcDateTimeOffsetConverter());
        return options;
    }

    private sealed class PersonalFeedUtcDateTimeOffsetConverter : JsonConverter<DateTimeOffset>
    {
        public override DateTimeOffset Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.String
                || !DateTimeOffset.TryParseExact(
                    reader.GetString(),
                    TimestampFormat,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out var value))
            {
                throw new JsonException(
                    "Personal feed timestamps must be exact UTC with seven fractional digits.");
            }
            return value;
        }

        public override void Write(
            Utf8JsonWriter writer,
            DateTimeOffset value,
            JsonSerializerOptions options) => writer.WriteStringValue(FormatTimestamp(value));
    }
}
