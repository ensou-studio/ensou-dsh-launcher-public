using System.Buffers;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ensou.Dsh.Enterprise.Installation;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseReleaseManifestTrustProbeKey(
    string Algorithm,
    string Purpose,
    string KeyId,
    string X,
    string Y);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseReleaseManifestTrustProbeCompatibility(
    int StartupStubProtocol);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseReleaseManifestTrustProbe(
    int SchemaVersion,
    string ProbeType,
    string Edition,
    string Product,
    string Environment,
    string Channel,
    string ManifestUri,
    string ManifestOrigin,
    string ArtifactOrigin,
    string AuthenticodeSignerSha256Thumbprint,
    EnterpriseReleaseManifestTrustProbeKey ReleaseManifestTrust,
    EnterpriseReleaseManifestTrustProbeCompatibility ReleaseCompatibility);

public enum EnterpriseReleaseManifestTrustProbeRole
{
    StableBootstrapper,
    VersionedClientBootstrapper,
    Launcher,
}

/// <summary>
/// Canonical, public proof of the one release-manifest trust root compiled into
/// every production executable that selects or starts an Enterprise release.
/// Role identity is deliberately validated before this role-neutral payload is
/// emitted, so all three executables produce byte-identical trust evidence.
/// </summary>
public static class EnterpriseReleaseManifestTrustProbeContract
{
    public const int SchemaVersion = 1;
    public const string ProbeType =
        "ensou-dsh-enterprise-release-manifest-trust-probe-v1";
    public const string Edition = "Enterprise";
    public const string ReleaseManifestSigningPurpose =
        "release-manifest-signing";
    public const string Command = "--release-manifest-trust-probe";
    public const int MaximumCanonicalBytes = 32 * 1024;
    public const string FailureMessage =
        "Ensou DSH Enterprise release manifest trust probe failed.";

    private static readonly JsonSerializerOptions StrictJson = new(
        JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static bool IsExactCommand(IReadOnlyList<string> args) =>
        args is [Command];

    public static EnterpriseReleaseManifestTrustProbe Create(
        EnterpriseCompiledReleaseTrust trust,
        string authenticodeSignerSha256Thumbprint)
    {
        ArgumentNullException.ThrowIfNull(trust);
        trust.Policy.Validate();
        if (trust.Policy.TrustedKeys.Count != 1)
        {
            throw new InvalidDataException(
                "Enterprise release manifest trust probe requires exactly one ES256 release key.");
        }
        var key = trust.Policy.TrustedKeys[0];
        var probe = new EnterpriseReleaseManifestTrustProbe(
            SchemaVersion,
            ProbeType,
            Edition,
            trust.Policy.Product,
            trust.Policy.Environment,
            trust.Policy.ExpectedChannel,
            trust.ManifestUri.AbsoluteUri,
            trust.Policy.ManifestOrigin.AbsoluteUri,
            trust.Policy.ArtifactOrigin.AbsoluteUri,
            EnterpriseProductionTrustFingerprint.RequireSha256Thumbprint(
                authenticodeSignerSha256Thumbprint),
            new EnterpriseReleaseManifestTrustProbeKey(
                EnterpriseReleaseSetContract.SignatureAlgorithm,
                ReleaseManifestSigningPurpose,
                key.KeyId,
                key.X,
                key.Y),
            new EnterpriseReleaseManifestTrustProbeCompatibility(
                trust.Policy.CurrentStartupStubProtocol));
        Validate(probe);
        return probe;
    }

    public static byte[] LoadCanonicalBytes(
        Assembly assembly,
        EnterpriseInstallationLayout layout)
    {
        ArgumentNullException.ThrowIfNull(assembly);
        ArgumentNullException.ThrowIfNull(layout);
        var trust = EnterpriseCompiledReleaseTrustLoader.LoadRequired(assembly, layout);
        var signer = EnterpriseAuthenticodeVerifier.GetCompiledSignerSha256Thumbprint();
        return SerializeCanonical(Create(trust, signer));
    }

    public static byte[] SerializeCanonical(
        EnterpriseReleaseManifestTrustProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        Validate(probe);
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(
                   buffer,
                   new JsonWriterOptions
                   {
                       Indented = false,
                       SkipValidation = false,
                   }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", probe.SchemaVersion);
            writer.WriteString("probeType", probe.ProbeType);
            writer.WriteString("edition", probe.Edition);
            writer.WriteString("product", probe.Product);
            writer.WriteString("environment", probe.Environment);
            writer.WriteString("channel", probe.Channel);
            writer.WriteString("manifestUri", probe.ManifestUri);
            writer.WriteString("manifestOrigin", probe.ManifestOrigin);
            writer.WriteString("artifactOrigin", probe.ArtifactOrigin);
            writer.WriteString(
                "authenticodeSignerSha256Thumbprint",
                probe.AuthenticodeSignerSha256Thumbprint);
            writer.WritePropertyName("releaseManifestTrust");
            writer.WriteStartObject();
            writer.WriteString("algorithm", probe.ReleaseManifestTrust.Algorithm);
            writer.WriteString("purpose", probe.ReleaseManifestTrust.Purpose);
            writer.WriteString("keyId", probe.ReleaseManifestTrust.KeyId);
            writer.WriteString("x", probe.ReleaseManifestTrust.X);
            writer.WriteString("y", probe.ReleaseManifestTrust.Y);
            writer.WriteEndObject();
            writer.WritePropertyName("releaseCompatibility");
            writer.WriteStartObject();
            writer.WriteNumber(
                "startupStubProtocol",
                probe.ReleaseCompatibility.StartupStubProtocol);
            writer.WriteEndObject();
            writer.WriteEndObject();
        }
        return buffer.WrittenSpan.ToArray();
    }

    public static EnterpriseReleaseManifestTrustProbe ParseCanonical(
        ReadOnlySpan<byte> utf8Json)
    {
        if (utf8Json.Length is <= 0 or > MaximumCanonicalBytes
            || utf8Json.Length >= 3
                && utf8Json[0] == 0xEF
                && utf8Json[1] == 0xBB
                && utf8Json[2] == 0xBF)
        {
            throw new InvalidDataException(
                "Enterprise release manifest trust probe size or encoding is invalid.");
        }
        try
        {
            EnterpriseReleaseJson.RequireNoDuplicateMembers(utf8Json);
            var probe = JsonSerializer.Deserialize<EnterpriseReleaseManifestTrustProbe>(
                            utf8Json,
                            StrictJson)
                        ?? throw new InvalidDataException(
                            "Enterprise release manifest trust probe is empty.");
            Validate(probe);
            var canonical = SerializeCanonical(probe);
            if (!utf8Json.SequenceEqual(canonical))
            {
                throw new InvalidDataException(
                    "Enterprise release manifest trust probe is not canonical JSON.");
            }
            return probe;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Enterprise release manifest trust probe JSON is invalid.",
                exception);
        }
    }

    public static EnterpriseReleaseManifestTrustProbe RequireExact(
        ReadOnlySpan<byte> utf8Json,
        EnterpriseCompiledReleaseTrust expectedTrust,
        string expectedAuthenticodeSignerSha256Thumbprint)
    {
        var parsed = ParseCanonical(utf8Json);
        var expected = SerializeCanonical(Create(
            expectedTrust,
            expectedAuthenticodeSignerSha256Thumbprint));
        if (!utf8Json.SequenceEqual(expected))
        {
            throw new InvalidDataException(
                "Enterprise release manifest trust probe does not match the expected compiled trust.");
        }
        return parsed;
    }

    public static void WriteCanonical(Stream output, ReadOnlySpan<byte> canonicalBytes)
    {
        ArgumentNullException.ThrowIfNull(output);
        _ = ParseCanonical(canonicalBytes);
        output.Write(canonicalBytes);
        output.Flush();
    }

    public static void WriteCanonicalToStandardOutput(ReadOnlySpan<byte> canonicalBytes)
    {
        using var output = Console.OpenStandardOutput();
        WriteCanonical(output, canonicalBytes);
    }

    public static void WriteBoundedFailureToStandardError()
    {
        try
        {
            using var error = Console.OpenStandardError();
            WriteBoundedFailure(error);
        }
        catch
        {
            // A machine command must still terminate without opening desktop
            // UI when its diagnostic stream is unavailable.
        }
    }

    internal static void WriteBoundedFailure(Stream error)
    {
        ArgumentNullException.ThrowIfNull(error);
        var bytes = System.Text.Encoding.UTF8.GetBytes(FailureMessage);
        if (bytes.Length > 256)
        {
            throw new InvalidOperationException(
                "Enterprise release manifest trust probe failure text is unbounded.");
        }
        error.Write(bytes);
        error.Flush();
    }

    private static void Validate(EnterpriseReleaseManifestTrustProbe probe)
    {
        var manifestUri = RequireCanonicalHttpsUri(
            probe.ManifestUri,
            "manifest URI",
            originOnly: false);
        var manifestOrigin = RequireCanonicalHttpsUri(
            probe.ManifestOrigin,
            "manifest origin",
            originOnly: true);
        _ = RequireCanonicalHttpsUri(
            probe.ArtifactOrigin,
            "artifact origin",
            originOnly: true);
        if (probe.SchemaVersion != SchemaVersion
            || !string.Equals(probe.ProbeType, ProbeType, StringComparison.Ordinal)
            || !string.Equals(probe.Edition, Edition, StringComparison.Ordinal)
            || !string.Equals(
                probe.Product,
                EnterpriseReleaseSetContract.Product,
                StringComparison.Ordinal)
            || !string.Equals(
                probe.Environment,
                EnterpriseReleaseSetContract.ProductionEnvironment,
                StringComparison.Ordinal)
            || !string.Equals(
                probe.Channel,
                EnterpriseReleaseSetContract.StableChannel,
                StringComparison.Ordinal)
            || !string.Equals(
                manifestUri.GetLeftPart(UriPartial.Authority),
                manifestOrigin.GetLeftPart(UriPartial.Authority),
                StringComparison.Ordinal)
            || probe.ReleaseManifestTrust is null
            || !string.Equals(
                probe.ReleaseManifestTrust.Algorithm,
                EnterpriseReleaseSetContract.SignatureAlgorithm,
                StringComparison.Ordinal)
            || !string.Equals(
                probe.ReleaseManifestTrust.Purpose,
                ReleaseManifestSigningPurpose,
                StringComparison.Ordinal)
            || probe.ReleaseCompatibility is null
            || probe.ReleaseCompatibility.StartupStubProtocol
                != EnterpriseReleaseSetContract.CurrentStartupStubProtocol)
        {
            throw new InvalidDataException(
                "Enterprise release manifest trust probe identity or compatibility is invalid.");
        }
        if (!string.Equals(
                probe.AuthenticodeSignerSha256Thumbprint,
                EnterpriseProductionTrustFingerprint.RequireSha256Thumbprint(
                    probe.AuthenticodeSignerSha256Thumbprint),
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise release manifest trust probe signer thumbprint is not canonical.");
        }
        RequireReleaseKey(probe.ReleaseManifestTrust);
    }

    private static Uri RequireCanonicalHttpsUri(
        string value,
        string label,
        bool originOnly)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(uri.Host)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || originOnly && uri.AbsolutePath != "/"
            || !string.Equals(value, uri.AbsoluteUri, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Enterprise release manifest trust probe {label} is not canonical HTTPS.");
        }
        return uri;
    }

    private static void RequireReleaseKey(EnterpriseReleaseManifestTrustProbeKey key)
    {
        EnterpriseReleaseSetValidator.ValidateToken(key.KeyId, "release keyId", 64);
        var x = EnterpriseBase64Url.Decode(key.X, "release public key x");
        var y = EnterpriseBase64Url.Decode(key.Y, "release public key y");
        if (x.Length != 32 || y.Length != 32)
        {
            throw new InvalidDataException(
                "Enterprise release manifest trust probe requires one P-256 public key.");
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
                "Enterprise release manifest trust probe public key is not a P-256 point.",
                exception);
        }
    }
}

/// <summary>
/// Role-specific admission performed before emitting the role-neutral trust
/// probe. The role never enters the probe bytes; release artifact receipts bind
/// the role separately.
/// </summary>
public static class EnterpriseReleaseManifestTrustProbeRoleIdentity
{
    public static void RequireCurrent(
        Assembly assembly,
        string executablePath,
        EnterpriseReleaseManifestTrustProbeRole role)
    {
        ArgumentNullException.ThrowIfNull(assembly);
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        var executable = Path.GetFullPath(executablePath);
        if (!File.Exists(executable)
            || (File.GetAttributes(executable) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Enterprise release manifest trust probe executable is missing or linked.");
        }
        var version = FileVersionInfo.GetVersionInfo(executable);
        RequireObservedForTests(
            role,
            assembly.GetName().Name,
            assembly.GetCustomAttribute<AssemblyProductAttribute>()?.Product,
            assembly.GetCustomAttribute<AssemblyCompanyAttribute>()?.Company,
            Path.GetFileName(executable),
            version.ProductName,
            version.CompanyName);
    }

    internal static void RequireObservedForTests(
        EnterpriseReleaseManifestTrustProbeRole role,
        string? assemblyName,
        string? assemblyProduct,
        string? assemblyCompany,
        string? executableFileName,
        string? executableProduct,
        string? executableCompany)
    {
        var expected = role switch
        {
            EnterpriseReleaseManifestTrustProbeRole.StableBootstrapper => new RoleContract(
                "Ensou.Dsh.Enterprise.Bootstrapper",
                EnterpriseBrandContract.BootstrapperProductName,
                EnterpriseInstallationLayout.BootstrapperExecutableName),
            EnterpriseReleaseManifestTrustProbeRole.VersionedClientBootstrapper => new RoleContract(
                "Ensou.Dsh.Enterprise.ClientBootstrapper",
                "Ensou DSH Enterprise Versioned Bootstrapper",
                EnterpriseInstallationLayout.ClientBootstrapperExecutableName),
            EnterpriseReleaseManifestTrustProbeRole.Launcher => new RoleContract(
                "Ensou.Dsh.Enterprise.Launcher",
                EnterpriseBrandContract.LauncherProductName,
                EnterpriseInstallationLayout.LauncherExecutableName),
            _ => throw new InvalidDataException(
                "Enterprise release manifest trust probe role is invalid."),
        };
        if (!string.Equals(assemblyName, expected.AssemblyName, StringComparison.Ordinal)
            || !string.Equals(assemblyProduct, expected.ProductName, StringComparison.Ordinal)
            || !string.Equals(
                assemblyCompany,
                EnterpriseBrandContract.DeveloperName,
                StringComparison.Ordinal)
            || !string.Equals(
                executableFileName,
                expected.ExecutableFileName,
                StringComparison.OrdinalIgnoreCase)
            || !string.Equals(executableProduct, expected.ProductName, StringComparison.Ordinal)
            || !string.Equals(
                executableCompany,
                EnterpriseBrandContract.DeveloperName,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise release manifest trust probe executable role identity is invalid.");
        }
    }

    private sealed record RoleContract(
        string AssemblyName,
        string ProductName,
        string ExecutableFileName);
}
