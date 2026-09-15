using System.Security.Cryptography;
using System.Text;

namespace Ensou.Dsh.Enterprise.Installation;

/// <summary>
/// Canonical public trust inputs compiled into an employee Pilot Launcher.
/// This contract intentionally contains no provider secret or private key.
/// </summary>
public sealed record EnterpriseProductionTrustInputs(
    string UpdateManifestUri,
    string UpdateManifestOrigin,
    string UpdateArtifactOrigin,
    string ReleaseKeyId,
    string ReleaseKeyX,
    string ReleaseKeyY,
    string ControlPlaneOrigin,
    string AuthorizationOrigin,
    string GatewayOrigin,
    string ManagedArtifactOrigin,
    string LeaseKeyId,
    string LeaseKeyX,
    string LeaseKeyY,
    string AuthenticodeSignerSha256Thumbprint);

public static class EnterpriseProductionTrustFingerprint
{
    public const string ContractId = "ensou-dsh-enterprise-production-trust-v1";
    public const string PilotUpdateContractId =
        "release-set-v2-startup-check-atomic-health-rollback-offline-7d-plugin-policy-v1";

    public static string ComputeSha256(EnterpriseProductionTrustInputs inputs)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        var manifestUri = RequireManifestUri(inputs.UpdateManifestUri, inputs.UpdateManifestOrigin);
        var manifestOrigin = RequireOrigin(inputs.UpdateManifestOrigin, nameof(inputs.UpdateManifestOrigin));
        var updateArtifactOrigin = RequireOrigin(
            inputs.UpdateArtifactOrigin,
            nameof(inputs.UpdateArtifactOrigin));
        var controlOrigin = RequireOrigin(inputs.ControlPlaneOrigin, nameof(inputs.ControlPlaneOrigin));
        var authorizationOrigin = RequireOrigin(
            inputs.AuthorizationOrigin,
            nameof(inputs.AuthorizationOrigin));
        var gatewayOrigin = RequireOrigin(inputs.GatewayOrigin, nameof(inputs.GatewayOrigin));
        var managedArtifactOrigin = RequireOrigin(
            inputs.ManagedArtifactOrigin,
            nameof(inputs.ManagedArtifactOrigin));
        RequirePublicKey(inputs.ReleaseKeyId, inputs.ReleaseKeyX, inputs.ReleaseKeyY, "release");
        RequirePublicKey(inputs.LeaseKeyId, inputs.LeaseKeyX, inputs.LeaseKeyY, "lease");
        if (string.Equals(inputs.ReleaseKeyId, inputs.LeaseKeyId, StringComparison.Ordinal)
            || (string.Equals(inputs.ReleaseKeyX, inputs.LeaseKeyX, StringComparison.Ordinal)
                && string.Equals(inputs.ReleaseKeyY, inputs.LeaseKeyY, StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "Production release and lease trust roots must be independent.");
        }

        var signer = RequireSha256Thumbprint(inputs.AuthenticodeSignerSha256Thumbprint);
        var payload = string.Join(
            '\n',
            ContractId,
            PilotUpdateContractId,
            manifestUri.AbsoluteUri,
            manifestOrigin.AbsoluteUri,
            updateArtifactOrigin.AbsoluteUri,
            inputs.ReleaseKeyId,
            inputs.ReleaseKeyX,
            inputs.ReleaseKeyY,
            controlOrigin.AbsoluteUri,
            authorizationOrigin.AbsoluteUri,
            gatewayOrigin.AbsoluteUri,
            managedArtifactOrigin.AbsoluteUri,
            inputs.LeaseKeyId,
            inputs.LeaseKeyX,
            inputs.LeaseKeyY,
            signer);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
    }

    public static string RequireSha256Thumbprint(string value)
    {
        if (value is not { Length: 64 }
            || value.Any(character => !(character is >= '0' and <= '9'
                or >= 'a' and <= 'f'
                or >= 'A' and <= 'F')))
        {
            throw new InvalidDataException(
                "Production Authenticode signer SHA-256 thumbprint is invalid.");
        }
        return value.ToLowerInvariant();
    }

    internal static Uri RequireManifestUri(string value, string expectedOrigin)
    {
        var uri = RequireHttpsUri(value, "update manifest URI", originOnly: false);
        var origin = RequireOrigin(expectedOrigin, "update manifest origin");
        if (!string.Equals(
                uri.GetLeftPart(UriPartial.Authority),
                origin.GetLeftPart(UriPartial.Authority),
                StringComparison.OrdinalIgnoreCase)
            || uri.AbsolutePath == "/")
        {
            throw new InvalidDataException(
                "Production update manifest URI must be below its pinned HTTPS origin.");
        }
        return uri;
    }

    internal static Uri RequireOrigin(string value, string field) =>
        RequireHttpsUri(value, field, originOnly: true);

    private static Uri RequireHttpsUri(string value, string field, bool originOnly)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(uri.Host)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || (originOnly && uri.AbsolutePath != "/")
            || IsPlaceholderHost(uri.Host))
        {
            throw new InvalidDataException($"Production {field} is not an organization HTTPS endpoint.");
        }
        return uri;
    }

    private static bool IsPlaceholderHost(string host)
    {
        var normalized = host.TrimEnd('.').ToLowerInvariant();
        return normalized is "localhost" or "example.com" or "example.org" or "example.net"
            || normalized.EndsWith(".localhost", StringComparison.Ordinal)
            || normalized.EndsWith(".example.com", StringComparison.Ordinal)
            || normalized.EndsWith(".example.org", StringComparison.Ordinal)
            || normalized.EndsWith(".example.net", StringComparison.Ordinal)
            || normalized.EndsWith(".invalid", StringComparison.Ordinal)
            || normalized.EndsWith(".example", StringComparison.Ordinal)
            || normalized.EndsWith(".test", StringComparison.Ordinal)
            || System.Net.IPAddress.TryParse(normalized, out var address)
                && System.Net.IPAddress.IsLoopback(address);
    }

    internal static void RequirePublicKey(string keyId, string xValue, string yValue, string field)
    {
        EnterpriseReleaseSetValidator.ValidateToken(keyId, $"{field} keyId", 64);
        var x = EnterpriseBase64Url.Decode(xValue, $"{field} public key x");
        var y = EnterpriseBase64Url.Decode(yValue, $"{field} public key y");
        if (x.Length != 32 || y.Length != 32)
        {
            throw new InvalidDataException($"Production {field} public key must use P-256.");
        }
        try
        {
            using var verifier = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y },
            });
        }
        catch (Exception exception) when (
            exception is CryptographicException or PlatformNotSupportedException)
        {
            throw new InvalidDataException(
                $"Production {field} public key is not a valid P-256 point.",
                exception);
        }
    }
}
