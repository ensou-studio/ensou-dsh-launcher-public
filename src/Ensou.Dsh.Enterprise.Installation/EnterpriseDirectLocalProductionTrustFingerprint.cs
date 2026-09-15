using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ensou.Dsh.Enterprise.Installation;

/// <summary>
/// Public trust for the direct-local Launcher. No gateway origin or provider
/// credential can be represented by this versioned contract.
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseDirectLocalProductionTrustInputs(
    string RuntimeProfile,
    string ApiProvider,
    string UpdateManifestUri,
    string UpdateManifestOrigin,
    string UpdateArtifactOrigin,
    string ReleaseKeyId,
    string ReleaseKeyX,
    string ReleaseKeyY,
    string ControlPlaneOrigin,
    string AuthorizationOrigin,
    string ManagedArtifactOrigin,
    string LeaseKeyId,
    string LeaseKeyX,
    string LeaseKeyY,
    string AuthenticodeSignerSha256Thumbprint);

public static class EnterpriseDirectLocalProductionTrustFingerprint
{
    public const string ContractId = "ensou-dsh-enterprise-production-trust-v2";
    public const string RuntimeProfile = "enterprise-direct-local";
    public const string ApiProvider = "deepseek";

    /// <summary>Reads exact, bounded public JSON inputs without duplicate or case aliases.</summary>
    public static EnterpriseDirectLocalProductionTrustInputs Parse(ReadOnlySpan<byte> utf8Json)
    {
        if (utf8Json.Length is < 2 or > 16_384)
        {
            throw new InvalidDataException("Direct-local production trust JSON size is invalid.");
        }
        try
        {
            using var document = JsonDocument.Parse(utf8Json.ToArray(),
                new JsonDocumentOptions { MaxDepth = 2 });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException("Direct-local production trust must be an object.");
            }
            var required = new HashSet<string>(StringComparer.Ordinal)
            {
                "runtimeProfile", "apiProvider", "updateManifestUri", "updateManifestOrigin",
                "updateArtifactOrigin", "releaseKeyId", "releaseKeyX", "releaseKeyY",
                "controlPlaneOrigin", "authorizationOrigin", "managedArtifactOrigin",
                "leaseKeyId", "leaseKeyX", "leaseKeyY", "authenticodeSignerSha256Thumbprint",
            };
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (!required.Remove(property.Name) || property.Value.ValueKind != JsonValueKind.String)
                {
                    throw new InvalidDataException(
                        "Direct-local production trust contains duplicate, unknown or invalid fields.");
                }
            }
            if (required.Count != 0)
            {
                throw new InvalidDataException("Direct-local production trust fields are missing.");
            }
            var inputs = document.RootElement.Deserialize<EnterpriseDirectLocalProductionTrustInputs>(
                new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    PropertyNameCaseInsensitive = false,
                    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
                }) ?? throw new InvalidDataException("Direct-local production trust is empty.");
            _ = ComputeSha256(inputs);
            return inputs;
        }
        catch (JsonException)
        {
            // Do not forward parser text containing attacker-supplied field values.
            throw new InvalidDataException("Direct-local production trust JSON is invalid.");
        }
    }

    public static string ComputeSha256(EnterpriseDirectLocalProductionTrustInputs inputs)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        if (!string.Equals(inputs.RuntimeProfile, RuntimeProfile, StringComparison.Ordinal)
            || !string.Equals(inputs.ApiProvider, ApiProvider, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Direct-local production trust requires the exact runtime profile and provider.");
        }

        var manifestUri = EnterpriseProductionTrustFingerprint.RequireManifestUri(
            inputs.UpdateManifestUri, inputs.UpdateManifestOrigin);
        var manifestOrigin = EnterpriseProductionTrustFingerprint.RequireOrigin(
            inputs.UpdateManifestOrigin, nameof(inputs.UpdateManifestOrigin));
        var artifactOrigin = EnterpriseProductionTrustFingerprint.RequireOrigin(
            inputs.UpdateArtifactOrigin, nameof(inputs.UpdateArtifactOrigin));
        var controlOrigin = EnterpriseProductionTrustFingerprint.RequireOrigin(
            inputs.ControlPlaneOrigin, nameof(inputs.ControlPlaneOrigin));
        var authorizationOrigin = EnterpriseProductionTrustFingerprint.RequireOrigin(
            inputs.AuthorizationOrigin, nameof(inputs.AuthorizationOrigin));
        var managedArtifactOrigin = EnterpriseProductionTrustFingerprint.RequireOrigin(
            inputs.ManagedArtifactOrigin, nameof(inputs.ManagedArtifactOrigin));
        EnterpriseProductionTrustFingerprint.RequirePublicKey(
            inputs.ReleaseKeyId, inputs.ReleaseKeyX, inputs.ReleaseKeyY, "release");
        EnterpriseProductionTrustFingerprint.RequirePublicKey(
            inputs.LeaseKeyId, inputs.LeaseKeyX, inputs.LeaseKeyY, "lease");
        if (string.Equals(inputs.ReleaseKeyId, inputs.LeaseKeyId, StringComparison.Ordinal)
            || (string.Equals(inputs.ReleaseKeyX, inputs.LeaseKeyX, StringComparison.Ordinal)
                && string.Equals(inputs.ReleaseKeyY, inputs.LeaseKeyY, StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "Production release and lease trust roots must be independent.");
        }

        var signer = EnterpriseProductionTrustFingerprint.RequireSha256Thumbprint(
            inputs.AuthenticodeSignerSha256Thumbprint);
        // Fixed LF order, no terminal LF, canonical Uri.AbsoluteUri strings and
        // lowercase signer digest. v1's payload and contract ID stay unchanged.
        var payload = string.Join(
            '\n',
            ContractId,
            EnterpriseProductionTrustFingerprint.PilotUpdateContractId,
            inputs.RuntimeProfile,
            inputs.ApiProvider,
            manifestUri.AbsoluteUri,
            manifestOrigin.AbsoluteUri,
            artifactOrigin.AbsoluteUri,
            inputs.ReleaseKeyId,
            inputs.ReleaseKeyX,
            inputs.ReleaseKeyY,
            controlOrigin.AbsoluteUri,
            authorizationOrigin.AbsoluteUri,
            managedArtifactOrigin.AbsoluteUri,
            inputs.LeaseKeyId,
            inputs.LeaseKeyX,
            inputs.LeaseKeyY,
            signer);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
    }
}
