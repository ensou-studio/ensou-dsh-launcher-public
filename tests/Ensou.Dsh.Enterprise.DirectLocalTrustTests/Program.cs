using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Ensou.Dsh.Enterprise.Installation;

try
{
    return Run();
}
catch (Exception exception)
{
    Console.Error.WriteLine($"FAIL direct-local production-trust checks: {exception.GetType().Name}");
    return 1;
}

static int Run()
{
using var releaseSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
using var leaseSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
using var replacementSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var release = releaseSigner.ExportParameters(false);
var lease = leaseSigner.ExportParameters(false);
var replacement = replacementSigner.ExportParameters(false);
var trust = new EnterpriseDirectLocalProductionTrustInputs(
    "enterprise-direct-local", "deepseek",
    "https://updates.example.invalid:8443/dsh/pilot/release-set.v2.json",
    "https://updates.example.invalid:8443/", "https://artifacts.example.invalid:8443/",
    "release-test", Encode(release.Q.X!), Encode(release.Q.Y!),
    "https://control.example.invalid:8443/", "https://authorization.example.invalid:8443/",
    "https://managed.example.invalid:8443/",
    "lease-test", Encode(lease.Q.X!), Encode(lease.Q.Y!), new string('a', 64));
var count = 0;

// These are public synthetic trust inputs. No endpoint is contacted, no private
// key is exported, and no OS certificate store or actual signer is used.
var first = EnterpriseDirectLocalProductionTrustFingerprint.ComputeSha256(trust);
Check(first == EnterpriseDirectLocalProductionTrustFingerprint.ComputeSha256(trust), "determinism");
Check(first.Length == 64 && first.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f'), "lowercase digest");
Check(first == Hash(string.Join('\n',
    "ensou-dsh-enterprise-production-trust-v2",
    "release-set-v2-startup-check-atomic-health-rollback-offline-7d-plugin-policy-v1",
    "enterprise-direct-local", "deepseek", trust.UpdateManifestUri,
    trust.UpdateManifestOrigin, trust.UpdateArtifactOrigin, trust.ReleaseKeyId,
    trust.ReleaseKeyX, trust.ReleaseKeyY, trust.ControlPlaneOrigin, trust.AuthorizationOrigin,
    trust.ManagedArtifactOrigin, trust.LeaseKeyId, trust.LeaseKeyX, trust.LeaseKeyY,
    trust.AuthenticodeSignerSha256Thumbprint)), "exact v2 canonical field order");
Check(first == EnterpriseDirectLocalProductionTrustFingerprint.ComputeSha256(trust with
{
    AuthenticodeSignerSha256Thumbprint = new string('A', 64),
}), "signer casing normalization");

foreach (var changed in new[]
{
    trust with { UpdateManifestUri = "https://updates.example.invalid:8443/dsh/pilot/next.json" },
    trust with { UpdateManifestUri = "https://next.example.invalid:8443/dsh/pilot/next.json", UpdateManifestOrigin = "https://next.example.invalid:8443/" },
    trust with { UpdateArtifactOrigin = "https://next.example.invalid:8443/" },
    trust with { ReleaseKeyId = "release-next" },
    trust with { ReleaseKeyX = Encode(replacement.Q.X!), ReleaseKeyY = Encode(replacement.Q.Y!) },
    trust with { ControlPlaneOrigin = "https://next.example.invalid:8443/" },
    trust with { AuthorizationOrigin = "https://next.example.invalid:8443/" },
    trust with { ManagedArtifactOrigin = "https://next.example.invalid:8443/" },
    trust with { LeaseKeyId = "lease-next" },
    trust with { LeaseKeyX = Encode(replacement.Q.X!), LeaseKeyY = Encode(replacement.Q.Y!) },
    trust with { AuthenticodeSignerSha256Thumbprint = new string('b', 64) },
})
{
    Check(first != EnterpriseDirectLocalProductionTrustFingerprint.ComputeSha256(changed), "every variable trust input is bound");
}

foreach (var invalid in new[]
{
    trust with { RuntimeProfile = "enterprise-managed" },
    trust with { RuntimeProfile = "ENTERPRISE-DIRECT-LOCAL" },
    trust with { RuntimeProfile = null! },
    trust with { ApiProvider = "other" },
    trust with { ApiProvider = "DeepSeek" },
    trust with { ApiProvider = null! },
    trust with { UpdateManifestUri = "http://updates.example.invalid:8443/release.json" },
    trust with { UpdateManifestUri = trust.UpdateManifestOrigin },
    trust with { UpdateManifestOrigin = "https://different.example.invalid:8443/" },
    trust with { UpdateArtifactOrigin = "https://artifacts.example.invalid/" },
    trust with { ControlPlaneOrigin = "https://localhost:8443/" },
    trust with { AuthorizationOrigin = "https://authorization.example.invalid:8443/path" },
    trust with { ManagedArtifactOrigin = "https://user@managed.example.invalid:8443/" },
    trust with { LeaseKeyId = trust.ReleaseKeyId },
    trust with { LeaseKeyX = trust.ReleaseKeyX, LeaseKeyY = trust.ReleaseKeyY },
    trust with { ReleaseKeyId = "release\ninjected" },
    trust with { ReleaseKeyX = Encode(new byte[31]) },
    trust with { LeaseKeyX = new string('A', 43), LeaseKeyY = new string('A', 43) },
    trust with { AuthenticodeSignerSha256Thumbprint = "not-a-thumbprint" },
})
{
    Reject<InvalidDataException>(() => EnterpriseDirectLocalProductionTrustFingerprint.ComputeSha256(invalid));
}
Reject<ArgumentNullException>(() => EnterpriseDirectLocalProductionTrustFingerprint.ComputeSha256(null!));

var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);
var validJson = JsonSerializer.Serialize(trust, jsonOptions);
var roundTrip = EnterpriseDirectLocalProductionTrustFingerprint.Parse(Encoding.UTF8.GetBytes(validJson));
Check(first == EnterpriseDirectLocalProductionTrustFingerprint.ComputeSha256(roundTrip), "strict direct JSON round trip");
var mixed = JsonNode.Parse(validJson)!.AsObject();
mixed["gatewayOrigin"] = "https://gateway.example.invalid:8443/";
Reject<JsonException>(() => JsonSerializer.Deserialize<EnterpriseDirectLocalProductionTrustInputs>(mixed.ToJsonString(), jsonOptions));
foreach (var invalidJson in new[]
{
    mixed.ToJsonString(),
    validJson.Replace("\"runtimeProfile\":", "\"RuntimeProfile\":", StringComparison.Ordinal),
    validJson.Replace("\"apiProvider\":\"deepseek\"", "\"apiProvider\":\"deepseek\",\"apiProvider\":\"deepseek\"", StringComparison.Ordinal),
    validJson.Replace("\"apiProvider\":\"deepseek\",", "", StringComparison.Ordinal),
    validJson.Replace("\"apiProvider\":\"deepseek\"", "\"apiProvider\":null", StringComparison.Ordinal),
    "[]", "null", "{", new string(' ', 16_385),
})
{
    Reject<InvalidDataException>(() => EnterpriseDirectLocalProductionTrustFingerprint.Parse(Encoding.UTF8.GetBytes(invalidJson)));
}
Check(typeof(EnterpriseDirectLocalProductionTrustInputs).GetProperty("GatewayOrigin") is null, "no gateway field in v2 type");

var legacy = new EnterpriseProductionTrustInputs(
    trust.UpdateManifestUri, trust.UpdateManifestOrigin, trust.UpdateArtifactOrigin,
    trust.ReleaseKeyId, trust.ReleaseKeyX, trust.ReleaseKeyY, trust.ControlPlaneOrigin,
    trust.AuthorizationOrigin, "https://gateway.example.invalid:8443/", trust.ManagedArtifactOrigin,
    trust.LeaseKeyId, trust.LeaseKeyX, trust.LeaseKeyY, trust.AuthenticodeSignerSha256Thumbprint);
var legacyHash = EnterpriseProductionTrustFingerprint.ComputeSha256(legacy);
Check(legacyHash == Hash(string.Join('\n',
    "ensou-dsh-enterprise-production-trust-v1",
    "release-set-v2-startup-check-atomic-health-rollback-offline-7d-plugin-policy-v1",
    legacy.UpdateManifestUri, legacy.UpdateManifestOrigin, legacy.UpdateArtifactOrigin,
    legacy.ReleaseKeyId, legacy.ReleaseKeyX, legacy.ReleaseKeyY, legacy.ControlPlaneOrigin,
    legacy.AuthorizationOrigin, legacy.GatewayOrigin, legacy.ManagedArtifactOrigin,
    legacy.LeaseKeyId, legacy.LeaseKeyX, legacy.LeaseKeyY,
    legacy.AuthenticodeSignerSha256Thumbprint)), "original v1 canonical payload unchanged");
Check(legacyHash != first, "v1 and v2 domain separation");
Reject<InvalidDataException>(() => EnterpriseProductionTrustFingerprint.ComputeSha256(legacy with { GatewayOrigin = "" }));
Reject<JsonException>(() => JsonSerializer.Deserialize<EnterpriseDirectLocalProductionTrustInputs>(JsonSerializer.Serialize(legacy, jsonOptions), jsonOptions));
Console.WriteLine($"PASS {count} direct-local production-trust foundation checks; legacy v1 preserved; no endpoint, signing or system-trust operation.");
return 0;

void Check(bool condition, string label)
{
    if (!condition) throw new InvalidOperationException(label);
    count++;
}

void Reject<T>(Action action) where T : Exception
{
    try { action(); }
    catch (T) { count++; return; }
    throw new InvalidOperationException($"Expected {typeof(T).Name}.");
}

static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
