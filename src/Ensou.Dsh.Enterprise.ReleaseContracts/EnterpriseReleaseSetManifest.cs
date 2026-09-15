using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ensou.Dsh.Enterprise.Installation;

public static class EnterpriseReleaseSetContract
{
    public const int SchemaVersion = 2;
    public const string Product = "ensou-dsh-enterprise";
    public const string ProductionEnvironment = "production";
    public const string DevelopmentE2EEnvironment = "development-e2e";
    public const string LabChannel = "lab";
    public const string PilotChannel = "pilot";
    public const string StableChannel = "stable";
    public const string SignatureAlgorithm = "ES256";
    public const int CurrentStartupStubProtocol = 1;
    public const string LauncherComponent = "launcher";
    public const string RuntimeComponent = "runtime";
    public const string PluginPolicyComponent = "plugin-policy";

    public static string EnvironmentForDevelopmentE2E(bool isDevelopmentE2E) =>
        isDevelopmentE2E ? DevelopmentE2EEnvironment : ProductionEnvironment;

    public static string ChannelForDevelopmentE2E(bool isDevelopmentE2E) =>
        isDevelopmentE2E ? LabChannel : StableChannel;

    public static bool IsSupportedChannel(string channel) =>
        channel is LabChannel or PilotChannel or StableChannel;
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseStartupStubCompatibility
{
    public required int MinimumProtocol { get; init; }

    public required int MaximumProtocol { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseReleaseSignature
{
    public required string Algorithm { get; init; }

    public required string KeyId { get; init; }

    public required string Value { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseReleaseArtifact
{
    public required string Component { get; init; }

    public required string ReleaseId { get; init; }

    public required Uri Uri { get; init; }

    public required long SizeBytes { get; init; }

    public required string Sha256 { get; init; }

    public required string CompleteTreeSha256 { get; init; }

    public required EnterpriseReleaseSignature Signature { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseReleaseSetManifest
{
    public required int SchemaVersion { get; init; }

    public required string Product { get; init; }

    public required string Environment { get; init; }

    public required string Channel { get; init; }

    public required string ReleaseSetId { get; init; }

    public required long Generation { get; init; }

    public required long Sequence { get; init; }

    public required long MinAcceptedSequence { get; init; }

    public required DateTimeOffset IssuedAtUtc { get; init; }

    public required DateTimeOffset ExpiresAtUtc { get; init; }

    public required EnterpriseStartupStubCompatibility StartupStub { get; init; }

    public required IReadOnlyList<string> RevokedReleaseSetIds { get; init; }

    public required IReadOnlyList<EnterpriseReleaseArtifact> Artifacts { get; init; }

    public required EnterpriseReleaseSignature Signature { get; init; }

    public EnterpriseReleaseArtifact Launcher => RequireArtifact(
        EnterpriseReleaseSetContract.LauncherComponent);

    public EnterpriseReleaseArtifact Runtime => RequireArtifact(
        EnterpriseReleaseSetContract.RuntimeComponent);

    public EnterpriseReleaseArtifact? PluginPolicy => Artifacts.SingleOrDefault(
        artifact => string.Equals(
            artifact.Component,
            EnterpriseReleaseSetContract.PluginPolicyComponent,
            StringComparison.Ordinal));

    public static EnterpriseReleaseSetManifest Parse(ReadOnlySpan<byte> utf8Json)
    {
        if (utf8Json.Length is <= 0 or > 512 * 1024)
        {
            throw new InvalidDataException("Enterprise release-set manifest size is invalid.");
        }

        try
        {
            EnterpriseReleaseJson.RequireNoDuplicateMembers(utf8Json);
            return JsonSerializer.Deserialize<EnterpriseReleaseSetManifest>(
                       utf8Json,
                       EnterpriseReleaseSetJson.Options)
                   ?? throw new InvalidDataException(
                       "Enterprise release-set manifest is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Enterprise release-set manifest JSON is invalid.",
                exception);
        }
    }

    private EnterpriseReleaseArtifact RequireArtifact(string component) =>
        Artifacts.SingleOrDefault(artifact => string.Equals(
            artifact.Component,
            component,
            StringComparison.Ordinal))
        ?? throw new InvalidDataException(
            $"Enterprise release-set is missing {component}.");
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseReleasePublicKey(string KeyId, string X, string Y);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseReleaseTrustPolicy
{
    public required string Product { get; init; }

    public required string Environment { get; init; }

    public required string ExpectedChannel { get; init; }

    public required int CurrentStartupStubProtocol { get; init; }

    public required Uri ManifestOrigin { get; init; }

    public required Uri ArtifactOrigin { get; init; }

    public required IReadOnlyList<EnterpriseReleasePublicKey> TrustedKeys { get; init; }

    public TimeSpan AllowedClockSkew { get; init; } = TimeSpan.FromMinutes(2);

    public TimeSpan MaximumOfflineGrace { get; init; } = TimeSpan.FromDays(7);

    public TimeSpan ManifestRequestTimeout { get; init; } = TimeSpan.FromSeconds(10);

    public TimeSpan ArtifactReadIdleTimeout { get; init; } = TimeSpan.FromSeconds(30);

    public void Validate()
    {
        if (!string.Equals(Product, EnterpriseReleaseSetContract.Product, StringComparison.Ordinal)
            || Environment is not EnterpriseReleaseSetContract.ProductionEnvironment
                and not EnterpriseReleaseSetContract.DevelopmentE2EEnvironment)
        {
            throw new InvalidDataException("Enterprise release trust identity is invalid.");
        }

        EnterpriseReleaseSetValidator.ValidateToken(
            ExpectedChannel,
            "expected channel",
            64);
        if (!EnterpriseReleaseSetContract.IsSupportedChannel(ExpectedChannel))
        {
            throw new InvalidDataException(
                "Enterprise release trust channel is invalid.");
        }

        if (CurrentStartupStubProtocol <= 0)
        {
            throw new InvalidDataException(
                "Enterprise release trust Startup Stub protocol is invalid.");
        }

        ValidateOrigin(ManifestOrigin, nameof(ManifestOrigin));
        ValidateOrigin(ArtifactOrigin, nameof(ArtifactOrigin));
        if (AllowedClockSkew < TimeSpan.Zero || AllowedClockSkew > TimeSpan.FromMinutes(10))
        {
            throw new InvalidDataException("Enterprise release clock skew is invalid.");
        }
        if (MaximumOfflineGrace < TimeSpan.FromHours(1)
            || MaximumOfflineGrace > TimeSpan.FromDays(14))
        {
            throw new InvalidDataException("Enterprise update offline grace is invalid.");
        }
        if (ManifestRequestTimeout < TimeSpan.FromMilliseconds(100)
            || ManifestRequestTimeout > TimeSpan.FromSeconds(30)
            || ArtifactReadIdleTimeout < TimeSpan.FromSeconds(1)
            || ArtifactReadIdleTimeout > TimeSpan.FromMinutes(2))
        {
            throw new InvalidDataException("Enterprise update request timeouts are invalid.");
        }

        if (TrustedKeys.Count is <= 0 or > 16
            || TrustedKeys.Select(key => key.KeyId)
                .Distinct(StringComparer.Ordinal)
                .Count() != TrustedKeys.Count)
        {
            throw new InvalidDataException("Enterprise release key ring is invalid.");
        }

        foreach (var key in TrustedKeys)
        {
            EnterpriseReleaseSetValidator.ValidateToken(key.KeyId, "keyId", 64);
            if (EnterpriseBase64Url.Decode(key.X, "public key x").Length != 32
                || EnterpriseBase64Url.Decode(key.Y, "public key y").Length != 32)
            {
                throw new InvalidDataException(
                    "Enterprise release keys must be P-256 coordinates.");
            }
        }
    }

    public void RequireArtifactUri(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        if (!uri.IsAbsoluteUri
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Fragment)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.Equals(uri.GetLeftPart(UriPartial.Authority),
                ArtifactOrigin.GetLeftPart(UriPartial.Authority),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Enterprise artifact URI is outside the pinned HTTPS origin.");
        }
    }

    private static void ValidateOrigin(Uri uri, string field)
    {
        if (!uri.IsAbsoluteUri
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || uri.AbsolutePath != "/")
        {
            throw new InvalidDataException($"{field} must be one canonical HTTPS origin.");
        }
    }
}

public static class EnterpriseReleaseSetValidator
{
    public static void Verify(
        EnterpriseReleaseSetManifest manifest,
        EnterpriseReleaseTrustPolicy policy,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(policy);
        policy.Validate();

        if (string.IsNullOrWhiteSpace(manifest.Product)
            || string.IsNullOrWhiteSpace(manifest.Environment)
            || string.IsNullOrWhiteSpace(manifest.Channel)
            || string.IsNullOrWhiteSpace(manifest.ReleaseSetId)
            || manifest.RevokedReleaseSetIds is null
            || manifest.RevokedReleaseSetIds.Any(string.IsNullOrWhiteSpace)
            || manifest.Artifacts is null
            || manifest.StartupStub is null
            || manifest.Signature is null
            || string.IsNullOrWhiteSpace(manifest.Signature.Algorithm)
            || string.IsNullOrWhiteSpace(manifest.Signature.KeyId)
            || string.IsNullOrWhiteSpace(manifest.Signature.Value)
            || manifest.Artifacts.Any(artifact => artifact is null
                || string.IsNullOrWhiteSpace(artifact.Component)
                || string.IsNullOrWhiteSpace(artifact.ReleaseId)
                || string.IsNullOrWhiteSpace(artifact.Sha256)
                || artifact.Uri is null
                || artifact.Signature is null
                || string.IsNullOrWhiteSpace(artifact.Signature.Algorithm)
                || string.IsNullOrWhiteSpace(artifact.Signature.KeyId)
                || string.IsNullOrWhiteSpace(artifact.Signature.Value)))
        {
            throw new InvalidDataException(
                "Enterprise release-set is missing required values.");
        }


        ValidateStartupStubCompatibility(
            manifest.StartupStub,
            policy.CurrentStartupStubProtocol);

        ValidateToken(manifest.Channel, "channel", 64);
        if (manifest.SchemaVersion != EnterpriseReleaseSetContract.SchemaVersion
            || !string.Equals(manifest.Product, policy.Product, StringComparison.Ordinal)
            || !string.Equals(manifest.Environment, policy.Environment, StringComparison.Ordinal)
            || !string.Equals(
                manifest.Channel,
                policy.ExpectedChannel,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise release-set product, environment, or channel does not match this client.");
        }

        EnterpriseReleaseValueValidator.ValidateReleaseId(manifest.ReleaseSetId);
        if (manifest.Generation <= 0
            || manifest.Sequence <= 0
            || manifest.MinAcceptedSequence < 0
            || manifest.MinAcceptedSequence > manifest.Sequence)
        {
            throw new InvalidDataException("Enterprise release-set ordering is invalid.");
        }

        if (manifest.IssuedAtUtc.Offset != TimeSpan.Zero
            || manifest.ExpiresAtUtc.Offset != TimeSpan.Zero
            || manifest.IssuedAtUtc <= DateTimeOffset.UnixEpoch
            || manifest.ExpiresAtUtc <= manifest.IssuedAtUtc
            || manifest.IssuedAtUtc > nowUtc + policy.AllowedClockSkew
            || manifest.ExpiresAtUtc < nowUtc - policy.AllowedClockSkew
            || manifest.ExpiresAtUtc - manifest.IssuedAtUtc > TimeSpan.FromDays(31))
        {
            throw new InvalidDataException("Enterprise release-set validity window is invalid or expired.");
        }

        if (manifest.RevokedReleaseSetIds.Count > 1_000
            || manifest.RevokedReleaseSetIds.Distinct(StringComparer.Ordinal).Count()
                != manifest.RevokedReleaseSetIds.Count
            || manifest.RevokedReleaseSetIds.Contains(manifest.ReleaseSetId, StringComparer.Ordinal))
        {
            throw new InvalidDataException("Enterprise release-set revocation list is invalid.");
        }
        foreach (var revoked in manifest.RevokedReleaseSetIds)
        {
            EnterpriseReleaseValueValidator.ValidateReleaseId(revoked);
        }

        if (manifest.Artifacts.Count != 3
            || manifest.Artifacts.Select(artifact => artifact.Component)
                .Distinct(StringComparer.Ordinal).Count() != manifest.Artifacts.Count)
        {
            throw new InvalidDataException("Enterprise release-set artifact list is invalid.");
        }

        _ = manifest.Launcher;
        _ = manifest.Runtime;
        _ = manifest.PluginPolicy
            ?? throw new InvalidDataException(
                "Enterprise release-set is missing required plugin-policy.");
        foreach (var artifact in manifest.Artifacts)
        {
            ValidateArtifact(manifest, artifact, policy);
        }

        EnterpriseEs256SignatureVerifier.Verify(
            manifest.Signature,
            EnterpriseReleaseCanonicalJson.ManifestPayload(manifest),
            policy.TrustedKeys);
    }

    public static void ValidateToken(string value, string field, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > maximumLength
            || value.Any(character => !(char.IsAsciiLetterOrDigit(character)
                || character is '-' or '_' or '.')))
        {
            throw new InvalidDataException($"Enterprise release {field} is invalid.");
        }
    }

    public static void ValidateStartupStubCompatibility(
        EnterpriseStartupStubCompatibility startupStub,
        int currentProtocol)
    {
        ValidateStartupStubRange(startupStub);
        if (currentProtocol <= 0
            || currentProtocol < startupStub.MinimumProtocol
            || currentProtocol > startupStub.MaximumProtocol)
        {
            throw new InvalidDataException(
                "Enterprise release-set is incompatible with this Startup Stub protocol.");
        }
    }

    public static void ValidateStartupStubRange(
        EnterpriseStartupStubCompatibility startupStub)
    {
        ArgumentNullException.ThrowIfNull(startupStub);
        if (startupStub.MinimumProtocol <= 0
            || startupStub.MaximumProtocol < startupStub.MinimumProtocol)
        {
            throw new InvalidDataException(
                "Enterprise release-set Startup Stub protocol range is invalid.");
        }
    }

    private static void ValidateArtifact(
        EnterpriseReleaseSetManifest manifest,
        EnterpriseReleaseArtifact artifact,
        EnterpriseReleaseTrustPolicy policy)
    {
        if (artifact.Component is not EnterpriseReleaseSetContract.LauncherComponent
            and not EnterpriseReleaseSetContract.RuntimeComponent
            and not EnterpriseReleaseSetContract.PluginPolicyComponent)
        {
            throw new InvalidDataException("Enterprise release artifact component is invalid.");
        }

        EnterpriseReleaseValueValidator.ValidateReleaseId(artifact.ReleaseId);
        policy.RequireArtifactUri(artifact.Uri);
        var maximum = artifact.Component switch
        {
            EnterpriseReleaseSetContract.LauncherComponent => 1L * 1024 * 1024 * 1024,
            EnterpriseReleaseSetContract.RuntimeComponent => 8L * 1024 * 1024 * 1024,
            _ => 512L * 1024 * 1024,
        };
        if (artifact.SizeBytes <= 0 || artifact.SizeBytes > maximum
            || !EnterpriseReleaseValueValidator.IsSha256(artifact.Sha256)
            || !EnterpriseReleaseValueValidator.IsSha256(
                artifact.CompleteTreeSha256))
        {
            throw new InvalidDataException("Enterprise release artifact bounds are invalid.");
        }

        EnterpriseEs256SignatureVerifier.Verify(
            artifact.Signature,
            EnterpriseReleaseCanonicalJson.ArtifactPayload(manifest, artifact),
            policy.TrustedKeys);
    }
}

public static class EnterpriseEs256SignatureVerifier
{
    public static void Verify(
        EnterpriseReleaseSignature signature,
        ReadOnlySpan<byte> payload,
        IReadOnlyList<EnterpriseReleasePublicKey> trustedKeys)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(trustedKeys);
        if (!string.Equals(
                signature.Algorithm,
                EnterpriseReleaseSetContract.SignatureAlgorithm,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("Enterprise release signature algorithm is invalid.");
        }

        var key = trustedKeys.SingleOrDefault(candidate => string.Equals(
            candidate.KeyId,
            signature.KeyId,
            StringComparison.Ordinal))
            ?? throw new InvalidDataException("Enterprise release signature key is not trusted.");
        var signatureBytes = EnterpriseBase64Url.Decode(signature.Value, "signature");
        if (signatureBytes.Length != 64)
        {
            throw new InvalidDataException("Enterprise ES256 signature length is invalid.");
        }

        using var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = EnterpriseBase64Url.Decode(key.X, "public key x"),
                Y = EnterpriseBase64Url.Decode(key.Y, "public key y"),
            },
        });
        if (!ecdsa.VerifyData(
                payload,
                signatureBytes,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            throw new InvalidDataException("Enterprise release signature verification failed.");
        }
    }
}

public static class EnterpriseReleaseValueValidator
{
    public static void ValidateReleaseId(string releaseId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(releaseId);
        if (releaseId.Length > 128
            || !char.IsAsciiLetterOrDigit(releaseId[0])
            || releaseId.Any(character => !(char.IsAsciiLetterOrDigit(character)
                || character is '.' or '_' or '+' or '-')))
        {
            throw new InvalidDataException("Enterprise releaseId is not canonical.");
        }
    }

    public static bool IsSha256(string value) =>
        value is not null
        && value.Length == 64
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

public static class EnterpriseReleaseCanonicalJson
{
    public static byte[] ArtifactPayload(
        EnterpriseReleaseSetManifest manifest,
        EnterpriseReleaseArtifact artifact) => Encoding.UTF8.GetBytes(string.Join(
            '\n',
            "ensou-dsh-enterprise-artifact-v2",
            manifest.Product,
            manifest.Environment,
            manifest.ReleaseSetId,
            artifact.Component,
            artifact.ReleaseId,
            artifact.SizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            artifact.Sha256,
            artifact.CompleteTreeSha256,
            artifact.Uri.AbsoluteUri));

    public static byte[] ManifestPayload(EnterpriseReleaseSetManifest manifest)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", manifest.SchemaVersion);
            writer.WriteString("product", manifest.Product);
            writer.WriteString("environment", manifest.Environment);
            writer.WriteString("channel", manifest.Channel);
            writer.WriteString("releaseSetId", manifest.ReleaseSetId);
            writer.WriteNumber("generation", manifest.Generation);
            writer.WriteNumber("sequence", manifest.Sequence);
            writer.WriteNumber("minAcceptedSequence", manifest.MinAcceptedSequence);
            writer.WriteString("issuedAtUtc", manifest.IssuedAtUtc);
            writer.WriteString("expiresAtUtc", manifest.ExpiresAtUtc);
            writer.WritePropertyName("startupStub");
            writer.WriteStartObject();
            writer.WriteNumber("minimumProtocol", manifest.StartupStub.MinimumProtocol);
            writer.WriteNumber("maximumProtocol", manifest.StartupStub.MaximumProtocol);
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
            writer.WriteEndObject();
        }
        return stream.ToArray();
    }

    private static void WriteSignature(Utf8JsonWriter writer, EnterpriseReleaseSignature signature)
    {
        writer.WritePropertyName("signature");
        writer.WriteStartObject();
        writer.WriteString("algorithm", signature.Algorithm);
        writer.WriteString("keyId", signature.KeyId);
        writer.WriteString("value", signature.Value);
        writer.WriteEndObject();
    }
}

public static class EnterpriseBase64Url
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
            throw new InvalidDataException($"Enterprise release {field} is not base64url.", exception);
        }
    }

    public static string Encode(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

internal static class EnterpriseReleaseSetJson
{
    public static JsonSerializerOptions Options { get; } = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

}

public static class EnterpriseReleaseJson
{
    public static void RequireNoDuplicateMembers(ReadOnlySpan<byte> utf8Json)
    {
        var objectMembers = new Stack<HashSet<string>>();
        var reader = new Utf8JsonReader(
            utf8Json,
            new JsonReaderOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 32,
            });
        while (reader.Read())
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.StartObject:
                    objectMembers.Push(new HashSet<string>(StringComparer.Ordinal));
                    break;
                case JsonTokenType.EndObject:
                    if (objectMembers.Count == 0)
                    {
                        throw new JsonException("Unexpected JSON object terminator.");
                    }
                    _ = objectMembers.Pop();
                    break;
                case JsonTokenType.PropertyName:
                    if (objectMembers.Count == 0
                        || !objectMembers.Peek().Add(reader.GetString()
                            ?? throw new JsonException("JSON member name is empty.")))
                    {
                        throw new JsonException("Enterprise release JSON contains duplicate members.");
                    }
                    break;
            }
        }
        if (objectMembers.Count != 0)
        {
            throw new JsonException("Enterprise release JSON object is incomplete.");
        }
    }
}
