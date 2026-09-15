using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Ensou.Dsh.Contracts;

public static class PersonalReleaseSetContract
{
    public const int SchemaVersion = 2;
    public const int MaximumManifestBytes = 512 * 1024;
    public const long MaximumSafeInteger = 9_007_199_254_740_991L;
    public const string Product = "ensou-dsh-personal";
    public const string ProductionEnvironment = "production";
    public const string SignatureAlgorithm = "ES256";
    public const string ClientBundleComponent = "client-bundle";
    public const string RuntimeComponent = "runtime";
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalReleaseSignature
{
    public required string Algorithm { get; init; }

    public required string KeyId { get; init; }

    public required string Value { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalReleaseProvenance
{
    public required string LauncherRepositoryCommit { get; init; }

    public required string HarnessSourceTag { get; init; }

    public required string HarnessSourceCommit { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalStartupStubCompatibility
{
    public required string MinimumVersion { get; init; }

    public required string MaximumVersion { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalReleaseArtifact
{
    public required string Component { get; init; }

    public required string ReleaseId { get; init; }

    public required Uri Uri { get; init; }

    public required long SizeBytes { get; init; }

    public required string Sha256 { get; init; }

    public required string CompleteTreeSha256 { get; init; }

    public PersonalReleaseSignature? Signature { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalReleaseSetManifest
{
    public required int SchemaVersion { get; init; }

    public required string Product { get; init; }

    public required string Environment { get; init; }

    public required string Channel { get; init; }

    public required string ReleaseSetId { get; init; }

    public required PersonalReleaseProvenance Provenance { get; init; }

    public required long Generation { get; init; }

    public required long Sequence { get; init; }

    public required long MinAcceptedSequence { get; init; }

    public required DateTimeOffset IssuedAtUtc { get; init; }

    public required DateTimeOffset ExpiresAtUtc { get; init; }

    public required long MaximumOfflineGraceSeconds { get; init; }

    public required PersonalStartupStubCompatibility StartupStub { get; init; }

    public required IReadOnlyList<string> RevokedReleaseSetIds { get; init; }

    public required IReadOnlyList<PersonalReleaseArtifact> Artifacts { get; init; }

    public PersonalReleaseSignature? Signature { get; init; }

    [JsonIgnore]
    public PersonalReleaseArtifact ClientBundle => RequireArtifact(
        PersonalReleaseSetContract.ClientBundleComponent);

    [JsonIgnore]
    public PersonalReleaseArtifact Runtime => RequireArtifact(
        PersonalReleaseSetContract.RuntimeComponent);

    private PersonalReleaseArtifact RequireArtifact(string component) =>
        Artifacts.SingleOrDefault(artifact => string.Equals(
            artifact.Component,
            component,
            StringComparison.Ordinal))
        ?? throw new InvalidDataException($"Personal release-set is missing {component}.");
}

public sealed record PersonalReleasePublicKey(string KeyId, string X, string Y);

public sealed record PersonalReleaseTrustPolicy
{
    public required string Product { get; init; }

    public required string Environment { get; init; }

    public required string Channel { get; init; }

    public required Uri ArtifactOrigin { get; init; }

    public required string StartupStubVersion { get; init; }

    public required IReadOnlyList<PersonalReleasePublicKey> TrustedKeys { get; init; }

    // Schema v2 predates canonical low-S enforcement. A sequence-bound cutover
    // lets an already-published feed admit only its audited legacy prefix while
    // requiring one canonical signature representation for every new release.
    public long CanonicalLowSFromSequence { get; init; } = 1;

    public TimeSpan AllowedClockSkew { get; init; } = TimeSpan.FromMinutes(2);

    public TimeSpan MaximumOfflineGrace { get; init; } = TimeSpan.FromDays(7);

    public void Validate()
    {
        if (!string.Equals(Product, PersonalReleaseSetContract.Product, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Personal release trust product is invalid.");
        }

        PersonalReleaseSetValidator.ValidateToken(Environment, "environment", 64);
        PersonalReleaseSetValidator.ValidateChannel(Channel);
        PersonalReleaseVersion.Compare(StartupStubVersion, StartupStubVersion);
        ValidateCanonicalOrigin(ArtifactOrigin);

        if (AllowedClockSkew < TimeSpan.Zero || AllowedClockSkew > TimeSpan.FromMinutes(10)
            || MaximumOfflineGrace < TimeSpan.FromHours(1)
            || MaximumOfflineGrace > TimeSpan.FromDays(14)
            || CanonicalLowSFromSequence is <= 0
                or > PersonalReleaseSetContract.MaximumSafeInteger)
        {
            throw new InvalidDataException("Personal release time policy is invalid.");
        }

        if (TrustedKeys is null
            || TrustedKeys.Count is <= 0 or > 16
            || TrustedKeys.Select(key => key.KeyId).Distinct(StringComparer.Ordinal).Count()
                != TrustedKeys.Count)
        {
            throw new InvalidDataException("Personal release key ring is invalid.");
        }

        var publicPoints = new HashSet<string>(StringComparer.Ordinal);
        foreach (var key in TrustedKeys)
        {
            PersonalReleaseSetValidator.ValidateToken(key.KeyId, "keyId", 64);
            var x = PersonalReleaseBase64Url.Decode(key.X, "public key x");
            var y = PersonalReleaseBase64Url.Decode(key.Y, "public key y");
            if (x.Length != 32 || y.Length != 32)
            {
                throw new InvalidDataException("Personal release keys must be P-256 coordinates.");
            }

            if (!publicPoints.Add(Convert.ToHexString(x) + Convert.ToHexString(y)))
            {
                throw new InvalidDataException(
                    "Personal release key ring contains the same P-256 point under multiple key IDs.");
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
                throw new InvalidDataException("Personal release key is not a valid P-256 point.", exception);
            }
        }
    }

    public void RequireArtifactUri(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        var printableAscii = uri.OriginalString.All(character =>
            char.IsAscii(character) && character > ' ' && character is not '"' and not '\\');
        if (!printableAscii
            || !uri.IsAbsoluteUri
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || !string.Equals(
                uri.GetLeftPart(UriPartial.Authority),
                ArtifactOrigin.GetLeftPart(UriPartial.Authority),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Personal artifact URI is outside the pinned HTTPS origin.");
        }
    }

    private static void ValidateCanonicalOrigin(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        var printableAscii = uri.OriginalString.All(character =>
            char.IsAscii(character) && character > ' ' && character is not '"' and not '\\');
        if (!printableAscii
            || !uri.IsAbsoluteUri
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || uri.AbsolutePath != "/")
        {
            throw new InvalidDataException("Personal artifact origin must be one canonical HTTPS origin.");
        }
    }
}

public sealed record VerifiedPersonalReleaseSetManifest(
    PersonalReleaseSetManifest Manifest,
    string CanonicalSignedManifestSha256,
    DateTimeOffset VerifiedAtUtc);

public static partial class PersonalReleaseSetValidator
{
    private static readonly string[] RequiredComponents =
    [
        PersonalReleaseSetContract.ClientBundleComponent,
        PersonalReleaseSetContract.RuntimeComponent,
    ];

    public static VerifiedPersonalReleaseSetManifest ParseAndVerify(
        ReadOnlySpan<byte> utf8Json,
        PersonalReleaseTrustPolicy policy,
        DateTimeOffset nowUtc)
    {
        var manifest = PersonalReleaseSetJson.Parse(utf8Json);
        Verify(manifest, policy, nowUtc);
        var canonicalSigned = PersonalReleaseSetJson.SerializeSigned(manifest);
        return new VerifiedPersonalReleaseSetManifest(
            manifest,
            Convert.ToHexStringLower(SHA256.HashData(canonicalSigned)),
            nowUtc);
    }

    public static void Verify(
        PersonalReleaseSetManifest manifest,
        PersonalReleaseTrustPolicy policy,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(policy);
        if (nowUtc.Offset != TimeSpan.Zero || nowUtc <= DateTimeOffset.UnixEpoch)
        {
            throw new InvalidDataException("Personal release verification time must be valid UTC.");
        }

        policy.Validate();
        ValidateRequiredValues(manifest);
        if (manifest.SchemaVersion != PersonalReleaseSetContract.SchemaVersion
            || !string.Equals(manifest.Product, policy.Product, StringComparison.Ordinal)
            || !string.Equals(manifest.Environment, policy.Environment, StringComparison.Ordinal)
            || !string.Equals(manifest.Channel, policy.Channel, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal release-set product, environment, or channel does not match this client.");
        }

        ValidateToken(manifest.Environment, "environment", 64);
        ValidateChannel(manifest.Channel);
        ValidateReleaseId(manifest.ReleaseSetId, "releaseSetId");
        ValidateProvenance(manifest.Provenance);
        ValidateOrdering(manifest);
        ValidateValidityWindow(manifest, policy, nowUtc);
        RequireStartupStubCompatible(manifest.StartupStub, policy.StartupStubVersion);
        ValidateRevocations(manifest);
        var requireCanonicalLowS = manifest.Sequence >= policy.CanonicalLowSFromSequence;
        ValidateArtifacts(manifest, policy, requireCanonicalLowS);

        VerifySignature(
            manifest.Signature!,
            PersonalReleaseCanonicalJson.ManifestPayload(manifest),
            policy,
            requireCanonicalLowS);
    }

    public static void ValidateToken(string value, string field, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > maximumLength
            || value.Any(character => !(char.IsAsciiLetterOrDigit(character)
                || character is '-' or '_' or '.')))
        {
            throw new InvalidDataException($"Personal release {field} is invalid.");
        }
    }

    public static void ValidateChannel(string value)
    {
        if (value is not "lab" and not "pilot" and not "stable")
        {
            throw new InvalidDataException(
                "Personal release channel must be lab, pilot, or stable.");
        }
    }

    public static void ValidateReleaseId(string value, string field)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > 128
            || !ReleaseIdPattern().IsMatch(value))
        {
            throw new InvalidDataException($"Personal release {field} is invalid.");
        }
    }

    public static bool IsSha256(string? value) =>
        value is not null && Sha256Pattern().IsMatch(value);

    private static void ValidateRequiredValues(PersonalReleaseSetManifest manifest)
    {
        if (string.IsNullOrWhiteSpace(manifest.Product)
            || string.IsNullOrWhiteSpace(manifest.Environment)
            || string.IsNullOrWhiteSpace(manifest.Channel)
            || string.IsNullOrWhiteSpace(manifest.ReleaseSetId)
            || manifest.Provenance is null
            || manifest.StartupStub is null
            || manifest.RevokedReleaseSetIds is null
            || manifest.Artifacts is null
            || manifest.Signature is null
            || string.IsNullOrWhiteSpace(manifest.Signature.Algorithm)
            || string.IsNullOrWhiteSpace(manifest.Signature.KeyId)
            || string.IsNullOrWhiteSpace(manifest.Signature.Value)
            || manifest.Artifacts.Any(artifact => artifact is null
                || string.IsNullOrWhiteSpace(artifact.Component)
                || string.IsNullOrWhiteSpace(artifact.ReleaseId)
                || artifact.Uri is null
                || string.IsNullOrWhiteSpace(artifact.Sha256)
                || string.IsNullOrWhiteSpace(artifact.CompleteTreeSha256)
                || artifact.Signature is null
                || string.IsNullOrWhiteSpace(artifact.Signature.Algorithm)
                || string.IsNullOrWhiteSpace(artifact.Signature.KeyId)
                || string.IsNullOrWhiteSpace(artifact.Signature.Value)))
        {
            throw new InvalidDataException("Personal release-set is missing required values.");
        }
    }

    private static void ValidateProvenance(PersonalReleaseProvenance provenance)
    {
        if (!GitCommitPattern().IsMatch(provenance.LauncherRepositoryCommit ?? string.Empty)
            || !GitCommitPattern().IsMatch(provenance.HarnessSourceCommit ?? string.Empty))
        {
            throw new InvalidDataException("Personal release provenance commit is invalid.");
        }

        ValidateToken(provenance.HarnessSourceTag, "Harness source tag", 128);
    }

    private static void ValidateOrdering(PersonalReleaseSetManifest manifest)
    {
        if (manifest.Generation is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || manifest.Sequence is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || manifest.MinAcceptedSequence < 0
            || manifest.MinAcceptedSequence > manifest.Sequence)
        {
            throw new InvalidDataException("Personal release-set ordering is invalid.");
        }
    }

    private static void ValidateValidityWindow(
        PersonalReleaseSetManifest manifest,
        PersonalReleaseTrustPolicy policy,
        DateTimeOffset nowUtc)
    {
        if (manifest.IssuedAtUtc.Offset != TimeSpan.Zero
            || manifest.ExpiresAtUtc.Offset != TimeSpan.Zero
            || manifest.IssuedAtUtc <= DateTimeOffset.UnixEpoch
            || manifest.ExpiresAtUtc <= manifest.IssuedAtUtc
            || manifest.IssuedAtUtc > nowUtc + policy.AllowedClockSkew
            || manifest.ExpiresAtUtc < nowUtc - policy.AllowedClockSkew
            || manifest.ExpiresAtUtc - manifest.IssuedAtUtc > TimeSpan.FromDays(31)
            || manifest.MaximumOfflineGraceSeconds < (long)TimeSpan.FromHours(1).TotalSeconds
            || manifest.MaximumOfflineGraceSeconds > (long)policy.MaximumOfflineGrace.TotalSeconds
            || manifest.MaximumOfflineGraceSeconds > (long)TimeSpan.FromDays(14).TotalSeconds)
        {
            throw new InvalidDataException("Personal release-set validity or offline-grace window is invalid.");
        }
    }

    public static void ValidateStartupStubRange(
        PersonalStartupStubCompatibility startupStub)
    {
        ArgumentNullException.ThrowIfNull(startupStub);
        if (string.IsNullOrWhiteSpace(startupStub.MinimumVersion)
            || string.IsNullOrWhiteSpace(startupStub.MaximumVersion)
            || PersonalReleaseVersion.Compare(
                startupStub.MinimumVersion,
                startupStub.MaximumVersion) > 0)
        {
            throw new InvalidDataException(
                "Personal release-set Startup Stub compatibility range is invalid.");
        }
    }

    public static void RequireStartupStubCompatible(
        PersonalStartupStubCompatibility startupStub,
        string installedVersion)
    {
        ValidateStartupStubRange(startupStub);
        if (PersonalReleaseVersion.Compare(installedVersion, startupStub.MinimumVersion) < 0
            || PersonalReleaseVersion.Compare(installedVersion, startupStub.MaximumVersion) > 0)
        {
            throw new InvalidDataException(
                "Personal release-set is incompatible with the installed Startup Stub.");
        }
    }

    private static void ValidateRevocations(PersonalReleaseSetManifest manifest)
    {
        if (manifest.RevokedReleaseSetIds.Count > 1_000
            || manifest.RevokedReleaseSetIds.Distinct(StringComparer.Ordinal).Count()
                != manifest.RevokedReleaseSetIds.Count
            || !manifest.RevokedReleaseSetIds.SequenceEqual(
                manifest.RevokedReleaseSetIds.Order(StringComparer.Ordinal),
                StringComparer.Ordinal)
            || manifest.RevokedReleaseSetIds.Contains(manifest.ReleaseSetId, StringComparer.Ordinal))
        {
            throw new InvalidDataException("Personal release-set revocation list is invalid.");
        }

        foreach (var releaseSetId in manifest.RevokedReleaseSetIds)
        {
            ValidateReleaseId(releaseSetId, "revoked releaseSetId");
        }
    }

    private static void ValidateArtifacts(
        PersonalReleaseSetManifest manifest,
        PersonalReleaseTrustPolicy policy,
        bool requireCanonicalLowS)
    {
        if (manifest.Artifacts.Count != RequiredComponents.Length
            || manifest.Artifacts.Select(artifact => artifact.Component)
                .Distinct(StringComparer.Ordinal).Count() != RequiredComponents.Length
            || !manifest.Artifacts.Select(artifact => artifact.Component)
                .SequenceEqual(RequiredComponents, StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "Personal release-set must contain client-bundle then runtime exactly once.");
        }

        foreach (var artifact in manifest.Artifacts)
        {
            ValidateReleaseId(artifact.ReleaseId, "artifact releaseId");
            policy.RequireArtifactUri(artifact.Uri);
            var maximumSize = artifact.Component switch
            {
                PersonalReleaseSetContract.ClientBundleComponent => 1L * 1024 * 1024 * 1024,
                PersonalReleaseSetContract.RuntimeComponent => 8L * 1024 * 1024 * 1024,
                _ => throw new InvalidDataException("Personal release artifact component is invalid."),
            };
            if (artifact.SizeBytes <= 0
                || artifact.SizeBytes > maximumSize
                || !IsSha256(artifact.Sha256)
                || !IsSha256(artifact.CompleteTreeSha256))
            {
                throw new InvalidDataException("Personal release artifact bounds or digest is invalid.");
            }

            VerifySignature(
                artifact.Signature!,
                PersonalReleaseCanonicalJson.ArtifactPayload(manifest, artifact),
                policy,
                requireCanonicalLowS);
        }
    }

    private static void VerifySignature(
        PersonalReleaseSignature signature,
        ReadOnlySpan<byte> payload,
        PersonalReleaseTrustPolicy policy,
        bool requireCanonicalLowS)
    {
        if (!string.Equals(
                signature.Algorithm,
                PersonalReleaseSetContract.SignatureAlgorithm,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("Personal release signature algorithm is invalid.");
        }

        var key = policy.TrustedKeys.SingleOrDefault(candidate => string.Equals(
            candidate.KeyId,
            signature.KeyId,
            StringComparison.Ordinal))
            ?? throw new InvalidDataException("Personal release signature key is not trusted.");
        var signatureBytes = PersonalReleaseBase64Url.Decode(signature.Value, "signature");
        if (signatureBytes.Length != 64)
        {
            throw new InvalidDataException("Personal ES256 signature length is invalid.");
        }
        PersonalReleaseEs256Signature.RequireValid(signatureBytes, requireCanonicalLowS);

        try
        {
            using var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = PersonalReleaseBase64Url.Decode(key.X, "public key x"),
                    Y = PersonalReleaseBase64Url.Decode(key.Y, "public key y"),
                },
            });
            if (!ecdsa.VerifyData(
                    payload,
                    signatureBytes,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                throw new InvalidDataException("Personal release signature verification failed.");
            }
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException("Personal release signature verification failed.", exception);
        }
    }

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex ReleaseIdPattern();

    [GeneratedRegex("^[0-9a-f]{40}$", RegexOptions.CultureInvariant)]
    private static partial Regex GitCommitPattern();

    [GeneratedRegex("^[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256Pattern();
}

internal static class PersonalReleaseEs256Signature
{
    private static readonly byte[] CurveOrder = Convert.FromHexString(
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    private static readonly byte[] CurveOrderHalf = Convert.FromHexString(
        "7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8");

    public static void RequireValid(
        ReadOnlySpan<byte> signature,
        bool requireCanonicalLowS)
    {
        if (signature.Length != 64)
        {
            throw new InvalidDataException("Personal ES256 signature length is invalid.");
        }

        var r = signature[..32];
        var s = signature[32..];
        if (IsZero(r)
            || r.SequenceCompareTo(CurveOrder) >= 0
            || IsZero(s)
            || s.SequenceCompareTo(CurveOrder) >= 0)
        {
            throw new InvalidDataException("Personal ES256 signature scalar is invalid.");
        }
        if (requireCanonicalLowS && s.SequenceCompareTo(CurveOrderHalf) > 0)
        {
            throw new InvalidDataException(
                "Personal ES256 signature must use canonical low-S form.");
        }
    }

    public static void RequireCanonicalLowS(ReadOnlySpan<byte> signature)
    {
        RequireValid(signature, requireCanonicalLowS: true);
    }

    public static void NormalizeLowS(Span<byte> signature)
    {
        if (signature.Length != 64)
        {
            throw new InvalidDataException("Personal ES256 signature length is invalid.");
        }

        var r = signature[..32];
        var s = signature[32..];
        if (IsZero(r)
            || r.SequenceCompareTo(CurveOrder) >= 0
            || IsZero(s)
            || s.SequenceCompareTo(CurveOrder) >= 0)
        {
            throw new InvalidDataException("Personal ES256 signer returned an invalid scalar.");
        }

        if (s.SequenceCompareTo(CurveOrderHalf) > 0)
        {
            Span<byte> normalized = stackalloc byte[32];
            SubtractUnsigned(CurveOrder, s, normalized);
            normalized.CopyTo(s);
            CryptographicOperations.ZeroMemory(normalized);
        }

        RequireCanonicalLowS(signature);
    }

    private static bool IsZero(ReadOnlySpan<byte> value)
    {
        byte combined = 0;
        foreach (var current in value)
        {
            combined |= current;
        }
        return combined == 0;
    }

    private static void SubtractUnsigned(
        ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right,
        Span<byte> destination)
    {
        if (left.Length != right.Length || destination.Length != left.Length)
        {
            throw new InvalidDataException("Personal ES256 scalar width is invalid.");
        }

        var borrow = 0;
        for (var index = left.Length - 1; index >= 0; index--)
        {
            var difference = left[index] - right[index] - borrow;
            if (difference < 0)
            {
                difference += 256;
                borrow = 1;
            }
            else
            {
                borrow = 0;
            }
            destination[index] = (byte)difference;
        }

        if (borrow != 0)
        {
            throw new InvalidDataException("Personal ES256 scalar subtraction underflowed.");
        }
    }
}

public static class PersonalReleaseCanonicalJson
{
    public static byte[] ArtifactPayload(
        PersonalReleaseSetManifest manifest,
        PersonalReleaseArtifact artifact) => Encoding.UTF8.GetBytes(string.Join(
            '\n',
            "ensou-dsh-personal-artifact-v2",
            manifest.Product,
            manifest.Environment,
            manifest.Channel,
            manifest.ReleaseSetId,
            manifest.Generation.ToString(CultureInfo.InvariantCulture),
            manifest.Sequence.ToString(CultureInfo.InvariantCulture),
            artifact.Component,
            artifact.ReleaseId,
            artifact.Uri.AbsoluteUri,
            artifact.SizeBytes.ToString(CultureInfo.InvariantCulture),
            artifact.Sha256,
            artifact.CompleteTreeSha256));

    public static byte[] ManifestPayload(PersonalReleaseSetManifest manifest) =>
        PersonalReleaseSetJson.WriteManifest(manifest, includeManifestSignature: false);

    public static byte[] SignedManifest(PersonalReleaseSetManifest manifest) =>
        PersonalReleaseSetJson.WriteManifest(manifest, includeManifestSignature: true);
}

public static class PersonalReleaseSetSigner
{
    public static PersonalReleaseSetManifest Sign(
        PersonalReleaseSetManifest unsignedManifest,
        string keyId,
        ECDsa signingKey)
    {
        ArgumentNullException.ThrowIfNull(unsignedManifest);
        ArgumentNullException.ThrowIfNull(signingKey);
        PersonalReleaseSetValidator.ValidateToken(keyId, "keyId", 64);
        if (unsignedManifest.Artifacts is null || unsignedManifest.Artifacts.Count != 2)
        {
            throw new InvalidDataException("Personal release-set must contain two artifacts before signing.");
        }

        var signedArtifacts = unsignedManifest.Artifacts
            .Select(artifact => artifact with
            {
                Signature = CreateSignature(
                    PersonalReleaseCanonicalJson.ArtifactPayload(unsignedManifest, artifact),
                    keyId,
                    signingKey),
            })
            .ToArray();
        var withArtifactSignatures = unsignedManifest with
        {
            Artifacts = signedArtifacts,
            Signature = null,
        };
        return withArtifactSignatures with
        {
            Signature = CreateSignature(
                PersonalReleaseCanonicalJson.ManifestPayload(withArtifactSignatures),
                keyId,
                signingKey),
        };
    }

    public static PersonalReleasePublicKey ExportPublicKey(string keyId, ECDsa signingKey)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        PersonalReleaseSetValidator.ValidateToken(keyId, "keyId", 64);
        var parameters = signingKey.ExportParameters(includePrivateParameters: false);
        if (parameters.Q.X is not { Length: 32 } x || parameters.Q.Y is not { Length: 32 } y)
        {
            throw new InvalidDataException("Personal release signing key must use P-256.");
        }

        return new PersonalReleasePublicKey(
            keyId,
            PersonalReleaseBase64Url.Encode(x),
            PersonalReleaseBase64Url.Encode(y));
    }

    private static PersonalReleaseSignature CreateSignature(
        ReadOnlySpan<byte> payload,
        string keyId,
        ECDsa signingKey)
    {
        var signature = signingKey.SignData(
            payload,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        if (signature.Length != 64)
        {
            throw new InvalidDataException("Personal release signing key must use P-256.");
        }
        try
        {
            PersonalReleaseEs256Signature.NormalizeLowS(signature);
            return new PersonalReleaseSignature
            {
                Algorithm = PersonalReleaseSetContract.SignatureAlgorithm,
                KeyId = keyId,
                Value = PersonalReleaseBase64Url.Encode(signature),
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signature);
        }
    }
}

public static class PersonalReleaseSetJson
{
    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 32,
    };

    private static readonly JsonSerializerOptions SerializerOptions = CreateOptions();

    public static PersonalReleaseSetManifest Parse(ReadOnlySpan<byte> utf8Json)
    {
        if (utf8Json.Length is <= 0 or > PersonalReleaseSetContract.MaximumManifestBytes)
        {
            throw new InvalidDataException("Personal release-set manifest size is invalid.");
        }

        try
        {
            using var document = JsonDocument.Parse(utf8Json.ToArray(), DocumentOptions);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException("Personal release-set manifest must be one JSON object.");
            }
            RejectDuplicateProperties(document.RootElement, "$");
            return JsonSerializer.Deserialize<PersonalReleaseSetManifest>(utf8Json, SerializerOptions)
                ?? throw new InvalidDataException("Personal release-set manifest is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Personal release-set manifest JSON is invalid.", exception);
        }
    }

    public static byte[] SerializeSigned(PersonalReleaseSetManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        if (manifest.Signature is null || manifest.Artifacts.Any(artifact => artifact.Signature is null))
        {
            throw new InvalidDataException("Personal release-set is not fully signed.");
        }
        return WriteManifest(manifest, includeManifestSignature: true);
    }

    internal static byte[] WriteManifest(
        PersonalReleaseSetManifest manifest,
        bool includeManifestSignature)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
        {
            Indented = false,
            SkipValidation = false,
        }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", manifest.SchemaVersion);
            writer.WriteString("product", manifest.Product);
            writer.WriteString("environment", manifest.Environment);
            writer.WriteString("channel", manifest.Channel);
            writer.WriteString("releaseSetId", manifest.ReleaseSetId);
            writer.WritePropertyName("provenance");
            writer.WriteStartObject();
            writer.WriteString("launcherRepositoryCommit", manifest.Provenance.LauncherRepositoryCommit);
            writer.WriteString("harnessSourceTag", manifest.Provenance.HarnessSourceTag);
            writer.WriteString("harnessSourceCommit", manifest.Provenance.HarnessSourceCommit);
            writer.WriteEndObject();
            writer.WriteNumber("generation", manifest.Generation);
            writer.WriteNumber("sequence", manifest.Sequence);
            writer.WriteNumber("minAcceptedSequence", manifest.MinAcceptedSequence);
            WriteTimestamp(writer, "issuedAtUtc", manifest.IssuedAtUtc);
            WriteTimestamp(writer, "expiresAtUtc", manifest.ExpiresAtUtc);
            writer.WriteNumber("maximumOfflineGraceSeconds", manifest.MaximumOfflineGraceSeconds);
            writer.WritePropertyName("startupStub");
            writer.WriteStartObject();
            writer.WriteString("minimumVersion", manifest.StartupStub.MinimumVersion);
            writer.WriteString("maximumVersion", manifest.StartupStub.MaximumVersion);
            writer.WriteEndObject();
            writer.WritePropertyName("revokedReleaseSetIds");
            writer.WriteStartArray();
            foreach (var revoked in manifest.RevokedReleaseSetIds)
            {
                writer.WriteStringValue(revoked);
            }
            writer.WriteEndArray();
            writer.WritePropertyName("artifacts");
            writer.WriteStartArray();
            foreach (var artifact in manifest.Artifacts)
            {
                writer.WriteStartObject();
                writer.WriteString("component", artifact.Component);
                writer.WriteString("releaseId", artifact.ReleaseId);
                writer.WriteString("uri", artifact.Uri.AbsoluteUri);
                writer.WriteNumber("sizeBytes", artifact.SizeBytes);
                writer.WriteString("sha256", artifact.Sha256);
                writer.WriteString("completeTreeSha256", artifact.CompleteTreeSha256);
                WriteSignature(writer, artifact.Signature);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            if (includeManifestSignature)
            {
                WriteSignature(writer, manifest.Signature);
            }
            writer.WriteEndObject();
        }
        return stream.ToArray();
    }

    private static void WriteSignature(Utf8JsonWriter writer, PersonalReleaseSignature? signature)
    {
        if (signature is null)
        {
            throw new InvalidDataException("Personal release signature is missing.");
        }

        writer.WritePropertyName("signature");
        writer.WriteStartObject();
        writer.WriteString("algorithm", signature.Algorithm);
        writer.WriteString("keyId", signature.KeyId);
        writer.WriteString("value", signature.Value);
        writer.WriteEndObject();
    }

    private static void WriteTimestamp(Utf8JsonWriter writer, string name, DateTimeOffset value) =>
        writer.WriteString(name, PersonalUtcDateTimeOffsetConverter.Format(value));

    private static void RejectDuplicateProperties(JsonElement element, string path)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidDataException(
                        $"Personal release-set contains duplicate property '{property.Name}' at {path}.");
                }
                RejectDuplicateProperties(property.Value, $"{path}.{property.Name}");
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in element.EnumerateArray())
            {
                RejectDuplicateProperties(item, $"{path}[{index++}]");
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
        };
        options.Converters.Add(new PersonalUtcDateTimeOffsetConverter());
        return options;
    }
}

public static partial class PersonalReleaseVersion
{
    public static int Compare(string left, string right)
    {
        var leftVersion = Parse(left, nameof(left));
        var rightVersion = Parse(right, nameof(right));
        var core = leftVersion.Core.Zip(rightVersion.Core)
            .Select(pair => pair.First.CompareTo(pair.Second))
            .FirstOrDefault(comparison => comparison != 0);
        if (core != 0)
        {
            return core;
        }

        if (leftVersion.Prerelease.Length == 0 || rightVersion.Prerelease.Length == 0)
        {
            return leftVersion.Prerelease.Length == rightVersion.Prerelease.Length
                ? 0
                : leftVersion.Prerelease.Length == 0 ? 1 : -1;
        }

        var count = Math.Max(leftVersion.Prerelease.Length, rightVersion.Prerelease.Length);
        for (var index = 0; index < count; index++)
        {
            if (index == leftVersion.Prerelease.Length)
            {
                return -1;
            }
            if (index == rightVersion.Prerelease.Length)
            {
                return 1;
            }

            var leftPart = leftVersion.Prerelease[index];
            var rightPart = rightVersion.Prerelease[index];
            var leftNumeric = leftPart.All(char.IsAsciiDigit);
            var rightNumeric = rightPart.All(char.IsAsciiDigit);
            var comparison = leftNumeric && rightNumeric
                ? CompareNumericIdentifier(leftPart, rightPart)
                : leftNumeric ? -1
                : rightNumeric ? 1
                : string.Compare(leftPart, rightPart, StringComparison.Ordinal);
            if (comparison != 0)
            {
                return comparison;
            }
        }
        return 0;
    }

    private static int CompareNumericIdentifier(string left, string right)
    {
        var lengthComparison = left.Length.CompareTo(right.Length);
        return lengthComparison != 0
            ? lengthComparison
            : string.Compare(left, right, StringComparison.Ordinal);
    }

    private static ParsedVersion Parse(string value, string field)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > 128
            || !SemanticVersionPattern().IsMatch(value))
        {
            throw new InvalidDataException($"Personal release {field} semantic version is invalid.");
        }

        var withoutBuild = value.Split('+', 2)[0];
        var versionParts = withoutBuild.Split('-', 2);
        var core = versionParts[0].Split('.').Select(part =>
        {
            if (!ulong.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out var number))
            {
                throw new InvalidDataException($"Personal release {field} semantic version is invalid.");
            }
            return number;
        }).ToArray();
        var prerelease = versionParts.Length == 2 ? versionParts[1].Split('.') : [];
        return new ParsedVersion(core, prerelease);
    }

    private sealed record ParsedVersion(ulong[] Core, string[] Prerelease);

    [GeneratedRegex(
        "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\\+([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?$",
        RegexOptions.CultureInvariant)]
    private static partial Regex SemanticVersionPattern();
}

public static class PersonalReleaseBase64Url
{
    public static byte[] Decode(string value, string field)
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
            if (!string.Equals(Encode(decoded), value, StringComparison.Ordinal))
            {
                throw new FormatException();
            }
            return decoded;
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException($"Personal release {field} is not canonical base64url.", exception);
        }
    }

    public static string Encode(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

internal sealed class PersonalUtcDateTimeOffsetConverter : JsonConverter<DateTimeOffset>
{
    private const string TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'";

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
            throw new JsonException("Personal release timestamps must be exact UTC with seven fractional digits.");
        }
        return value;
    }

    public override void Write(
        Utf8JsonWriter writer,
        DateTimeOffset value,
        JsonSerializerOptions options) => writer.WriteStringValue(Format(value));

    public static string Format(DateTimeOffset value)
    {
        if (value.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException("Personal release timestamps must use UTC.");
        }
        return value.ToString(TimestampFormat, CultureInfo.InvariantCulture);
    }
}
