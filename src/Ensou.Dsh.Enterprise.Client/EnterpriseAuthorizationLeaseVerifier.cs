using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Enterprise.Contracts;

namespace Ensou.Dsh.Enterprise.Client;

public sealed record EnterpriseAuthorizationLeasePublicKey(
    string KeyId,
    string X,
    string Y)
{
    public override string ToString() => $"Enterprise authorization lease key {KeyId}";
}

public enum EnterpriseAuthorizationLeaseRuntimeProfile
{
    EnterpriseManagedGatewayV1 = 1,
    EnterpriseDirectLocalV2 = 2,
}

public sealed class EnterpriseAuthorizationLeaseTrustPolicy
{
    private const int MaximumPinnedKeys = 16;
    private readonly IReadOnlyDictionary<string, EnterpriseAuthorizationLeasePublicKey> _keys;

    public EnterpriseAuthorizationLeaseTrustPolicy(
        Uri issuerOrigin,
        Uri gatewayOrigin,
        Uri artifactOrigin,
        IEnumerable<EnterpriseAuthorizationLeasePublicKey> pinnedKeys)
        : this(
            issuerOrigin,
            gatewayOrigin,
            artifactOrigin,
            pinnedKeys,
            EnterpriseAuthorizationLeaseRuntimeProfile.EnterpriseManagedGatewayV1)
    {
    }

    private EnterpriseAuthorizationLeaseTrustPolicy(
        Uri issuerOrigin,
        Uri? gatewayOrigin,
        Uri artifactOrigin,
        IEnumerable<EnterpriseAuthorizationLeasePublicKey> pinnedKeys,
        EnterpriseAuthorizationLeaseRuntimeProfile runtimeProfile)
    {
        IssuerOrigin = ValidateOrigin(issuerOrigin, nameof(issuerOrigin));
        _gatewayOrigin = gatewayOrigin is null
            ? null
            : ValidateOrigin(gatewayOrigin, nameof(gatewayOrigin));
        ArtifactOrigin = ValidateOrigin(artifactOrigin, nameof(artifactOrigin));
        RuntimeProfile = runtimeProfile;
        if (!Enum.IsDefined(runtimeProfile)
            || runtimeProfile == EnterpriseAuthorizationLeaseRuntimeProfile.EnterpriseManagedGatewayV1
                && _gatewayOrigin is null
            || runtimeProfile == EnterpriseAuthorizationLeaseRuntimeProfile.EnterpriseDirectLocalV2
                && _gatewayOrigin is not null)
        {
            throw new ArgumentException(
                "Enterprise authorization lease runtime profile and gateway origin are inconsistent.",
                nameof(runtimeProfile));
        }
        ArgumentNullException.ThrowIfNull(pinnedKeys);

        var keys = new Dictionary<string, EnterpriseAuthorizationLeasePublicKey>(
            StringComparer.Ordinal);
        foreach (var key in pinnedKeys)
        {
            ArgumentNullException.ThrowIfNull(key);
            ValidateKeyId(key.KeyId);
            ValidateP256Point(key);
            if (!keys.TryAdd(key.KeyId, key))
            {
                throw new ArgumentException(
                    "Enterprise authorization lease key IDs must be unique.",
                    nameof(pinnedKeys));
            }
        }

        if (keys.Count is 0 or > MaximumPinnedKeys)
        {
            throw new ArgumentException(
                $"Enterprise builds must pin between 1 and {MaximumPinnedKeys} lease keys.",
                nameof(pinnedKeys));
        }

        _keys = keys;
    }

    private readonly Uri? _gatewayOrigin;

    public static EnterpriseAuthorizationLeaseTrustPolicy CreateEnterpriseDirectLocal(
        Uri issuerOrigin,
        Uri artifactOrigin,
        IEnumerable<EnterpriseAuthorizationLeasePublicKey> pinnedKeys) => new(
            issuerOrigin,
            gatewayOrigin: null,
            artifactOrigin,
            pinnedKeys,
            EnterpriseAuthorizationLeaseRuntimeProfile.EnterpriseDirectLocalV2);

    public Uri IssuerOrigin { get; }

    public Uri GatewayOrigin => _gatewayOrigin
        ?? throw new InvalidOperationException(
            "Enterprise direct-local lease trust has no gateway origin.");

    public Uri ArtifactOrigin { get; }

    public EnterpriseAuthorizationLeaseRuntimeProfile RuntimeProfile { get; }

    public bool IsEnterpriseDirectLocal =>
        RuntimeProfile == EnterpriseAuthorizationLeaseRuntimeProfile.EnterpriseDirectLocalV2;

    internal bool TryGetKey(
        string keyId,
        out EnterpriseAuthorizationLeasePublicKey key) =>
        _keys.TryGetValue(keyId, out key!);

    internal static void ValidateKeyId(string keyId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        if (keyId.Length > 128
            || keyId.All(char.IsWhiteSpace)
            || keyId.Any(character => character is < (char)0x20 or > (char)0x7e))
        {
            throw new InvalidDataException(
                "Enterprise authorization lease key ID must be 1-128 printable ASCII characters.");
        }
    }

    private static Uri ValidateOrigin(Uri value, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);
        if (!value.IsAbsoluteUri
            || !string.Equals(value.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(value.UserInfo)
            || !string.IsNullOrEmpty(value.Query)
            || !string.IsNullOrEmpty(value.Fragment)
            || value.AbsolutePath != "/")
        {
            throw new ArgumentException(
                "Enterprise authorization lease trust origins must be exact HTTPS origins.",
                parameterName);
        }

        return new UriBuilder(Uri.UriSchemeHttps, value.Host, value.Port).Uri;
    }

    private static void ValidateP256Point(EnterpriseAuthorizationLeasePublicKey key)
    {
        var x = EnterpriseBindingValidation.Base64UrlDecode(key.X, "lease_key.x", 32);
        var y = EnterpriseBindingValidation.Base64UrlDecode(key.Y, "lease_key.y", 32);
        try
        {
            if (x.Length != 32 || y.Length != 32)
            {
                throw new InvalidDataException(
                    "Enterprise authorization lease keys must use 32-byte P-256 coordinates.");
            }

            try
            {
                using var publicKey = ECDsa.Create(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint { X = x, Y = y },
                });
            }
            catch (Exception exception) when (
                exception is CryptographicException or PlatformNotSupportedException)
            {
                throw new InvalidDataException(
                    "Enterprise authorization lease key is not a valid P-256 public point.",
                    exception);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(x);
            CryptographicOperations.ZeroMemory(y);
        }
    }
}

public sealed record EnterpriseAuthorizationEpochState(
    long AuthorizationEpoch,
    long EntitlementEpoch,
    long BindingEpoch,
    string ApiAllocationId,
    long AllocationEpoch,
    string ApiProfileId,
    long ApiProfileVersion,
    string PluginPolicyId,
    long PluginPolicyGeneration,
    string PluginPolicySha256,
    string RolloutChannel);

public sealed record EnterpriseAuthorizationLeaseVerificationContext(
    string ExpectedBindingId,
    string ExpectedInstallationId,
    string ExpectedDeviceKeyThumbprint,
    DateTimeOffset EvaluationTimeUtc,
    DateTimeOffset MinimumTrustedTimeUtc,
    EnterpriseAuthorizationEpochState? ExpectedEpochState = null);

public sealed record EnterpriseAuthorizationLeaseClaims(
    int SchemaVersion,
    string LeaseId,
    string Issuer,
    string Subject,
    string BindingId,
    string InstallationId,
    string DeviceKeyThumbprint,
    long AuthorizationEpoch,
    long EntitlementEpoch,
    long BindingEpoch,
    string ApiAllocationId,
    long AllocationEpoch,
    string ApiProfileId,
    long ApiProfileVersion,
    string PluginPolicyId,
    long PluginPolicyGeneration,
    string PluginPolicySha256,
    string RolloutChannel,
    string? GatewayOrigin,
    string? RuntimeProfile,
    string? ApiProvider,
    string ArtifactOrigin,
    string SupportDisplay,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset NotBeforeUtc,
    DateTimeOffset ExpiresAtUtc)
{
    public EnterpriseAuthorizationEpochState ToEpochState() => new(
        AuthorizationEpoch,
        EntitlementEpoch,
        BindingEpoch,
        ApiAllocationId,
        AllocationEpoch,
        ApiProfileId,
        ApiProfileVersion,
        PluginPolicyId,
        PluginPolicyGeneration,
        PluginPolicySha256,
        RolloutChannel);

    public override string ToString() =>
        "Enterprise authorization lease claims [REDACTED]";
}

public sealed class EnterpriseVerifiedAuthorizationLease
{
    internal EnterpriseVerifiedAuthorizationLease(
        EnterpriseSignedLeaseEnvelope envelope,
        EnterpriseAuthorizationLeaseClaims claims,
        EnterpriseAccessSnapshot accessSnapshot)
    {
        Envelope = envelope;
        Claims = claims;
        AccessSnapshot = accessSnapshot;
    }

    public EnterpriseSignedLeaseEnvelope Envelope { get; }

    public EnterpriseAuthorizationLeaseClaims Claims { get; }

    public EnterpriseAccessSnapshot AccessSnapshot { get; }

    public override string ToString() => "Enterprise verified authorization lease [REDACTED]";
}

public sealed class EnterpriseAuthorizationLeaseVerifier
{
    private const int MinimumCompactJwsLength = 128;
    private const int MaximumCompactJwsLength = 8192;
    private const long MaximumSafeInteger = 9_007_199_254_740_991;
    private const long MaximumUnixSecond = 253_402_300_799;
    private const string ExpectedAudience = "ensou-dsh-enterprise-launcher";
    private const string ExpectedType = "ensou-dsh-lease+jwt";
    private static readonly TimeSpan MaximumLeaseLifetime = TimeSpan.FromMinutes(15);
    private static readonly HashSet<string> CommonPayloadMembers = new(
        [
            "schema_version",
            "jti",
            "iss",
            "aud",
            "sub",
            "binding_id",
            "installation_id",
            "device_key_thumbprint",
            "employee_state",
            "device_state",
            "api_allocation_state",
            "auth_epoch",
            "entitlement_epoch",
            "binding_epoch",
            "api_allocation_id",
            "allocation_epoch",
            "api_profile_id",
            "api_profile_version",
            "plugin_policy_id",
            "plugin_policy_generation",
            "plugin_policy_sha256",
            "rollout_channel",
            "artifact_origin",
            "support_display",
            "iat",
            "nbf",
            "exp",
        ],
        StringComparer.Ordinal);
    private static readonly HashSet<string> LegacyRequiredPayloadMembers = new(
        CommonPayloadMembers.Append("gateway_origin"),
        StringComparer.Ordinal);
    private static readonly HashSet<string> DirectLocalRequiredPayloadMembers = new(
        CommonPayloadMembers
            .Append("runtime_profile")
            .Append("api_provider"),
        StringComparer.Ordinal);

    private readonly EnterpriseAuthorizationLeaseTrustPolicy _trustPolicy;

    public EnterpriseAuthorizationLeaseVerifier(
        EnterpriseAuthorizationLeaseTrustPolicy trustPolicy)
    {
        _trustPolicy = trustPolicy ?? throw new ArgumentNullException(nameof(trustPolicy));
    }

    public EnterpriseVerifiedAuthorizationLease Verify(
        string compactJws,
        EnterpriseAuthorizationLeaseVerificationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        ValidateContext(context);
        var segments = SplitCompactJws(compactJws);
        var keyId = ReadAndValidateHeader(segments[0]);
        if (!_trustPolicy.TryGetKey(keyId, out var key))
        {
            throw new InvalidDataException(
                "Enterprise authorization lease references an unpinned signing key.");
        }

        VerifySignature(segments, key);
        var claims = ReadAndValidateClaims(segments[1]);
        ValidateClaimsAgainstTrust(claims, context);

        var trustedFloor = context.MinimumTrustedTimeUtc > claims.IssuedAtUtc
            ? context.MinimumTrustedTimeUtc
            : claims.IssuedAtUtc;
        var snapshot = new EnterpriseAccessSnapshot
        {
            Employee = EmployeeAuthorizationState.Active,
            Device = DeviceBindingState.Active,
            ApiAllocation = ApiAllocationState.Active,
            ControlPlane = ControlPlaneConnectivity.Available,
            LeaseSignatureValid = true,
            AuthorizationEpochMatches = true,
            ClockTrusted = true,
            TrustedTimeFloorUtc = trustedFloor,
            LeaseIssuedAtUtc = claims.IssuedAtUtc,
            LeaseExpiresAtUtc = claims.ExpiresAtUtc,
            PluginPolicyId = claims.PluginPolicyId,
            PluginPolicyGeneration = claims.PluginPolicyGeneration,
            PluginPolicySha256 = claims.PluginPolicySha256,
            RuntimeProfile = claims.RuntimeProfile,
            ApiProvider = claims.ApiProvider,
        };

        return new EnterpriseVerifiedAuthorizationLease(
            new EnterpriseSignedLeaseEnvelope(
                compactJws,
                segments[0],
                segments[1],
                segments[2]),
            claims,
            snapshot);
    }

    public EnterpriseVerifiedAuthorizationLease VerifyPersistedCredential(
        EnterprisePersistedBindingCredential credential,
        EnterpriseEnrollmentDeviceContext device)
    {
        ArgumentNullException.ThrowIfNull(credential);
        return VerifyPersistedCredential(
            credential,
            device,
            credential.Receipt.ServerTimeUtc,
            credential.Receipt.ServerTimeUtc);
    }

    public EnterpriseVerifiedAuthorizationLease VerifyPersistedCredential(
        EnterprisePersistedBindingCredential credential,
        EnterpriseEnrollmentDeviceContext device,
        DateTimeOffset evaluationTimeUtc,
        DateTimeOffset minimumTrustedTimeUtc)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(device);
        var receipt = credential.Receipt;
        var installationId = device.Installation.InstallId.ToString("D");
        if (!string.Equals(
                receipt.InstallationId,
                installationId,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.DeviceKeyThumbprint,
                device.DeviceKey.Thumbprint,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise binding credential belongs to another installation or device key.");
        }

        var verified = Verify(
            credential.AuthorizationLease,
            new EnterpriseAuthorizationLeaseVerificationContext(
                receipt.BindingId,
                installationId,
                device.DeviceKey.Thumbprint,
                evaluationTimeUtc,
                minimumTrustedTimeUtc,
                receipt.EpochState));
        if (!string.Equals(
                verified.Claims.LeaseId,
                receipt.LeaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                verified.Claims.Subject,
                receipt.EmployeeAuthorizationId,
                StringComparison.Ordinal)
            || verified.Claims.ExpiresAtUtc != receipt.LeaseExpiresAtUtc)
        {
            throw new InvalidDataException(
                "Enterprise persisted receipt does not match its pinned signed lease.");
        }

        return verified;
    }

    private static string[] SplitCompactJws(string compactJws)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(compactJws);
        if (compactJws.Length is < MinimumCompactJwsLength or > MaximumCompactJwsLength
            || compactJws.Any(character => character > 0x7f
                || char.IsControl(character)
                || char.IsWhiteSpace(character)))
        {
            throw new InvalidDataException(
                "Enterprise authorization lease is not a bounded compact JWS.");
        }

        var segments = compactJws.Split('.');
        if (segments.Length != 3 || segments.Any(string.IsNullOrEmpty))
        {
            throw new InvalidDataException(
                "Enterprise authorization lease must contain exactly three compact JWS segments.");
        }

        return segments;
    }

    private static string ReadAndValidateHeader(string segment)
    {
        var bytes = EnterpriseBindingValidation.Base64UrlDecode(
            segment,
            "authorization_lease.header",
            2048);
        try
        {
            using var document = JsonDocument.Parse(bytes, StrictJsonDocumentOptions(maxDepth: 4));
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException(
                    "Enterprise authorization lease protected header is outside the supported profile.");
            }

            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
            {
                if (!names.Add(property.Name)
                    || property.Name is not "alg" and not "kid" and not "typ")
                {
                    throw new InvalidDataException(
                        "Enterprise authorization lease protected header contains duplicate or unknown members.");
                }
            }

            if (names.Count != 3
                || GetRequiredString(root, "alg") != "ES256"
                || GetRequiredString(root, "typ") != ExpectedType)
            {
                throw new InvalidDataException(
                    "Enterprise authorization lease protected header is outside the supported profile.");
            }

            var keyId = GetRequiredString(root, "kid");
            EnterpriseAuthorizationLeaseTrustPolicy.ValidateKeyId(keyId);
            return keyId;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Enterprise authorization lease protected header must be exact JSON.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static void VerifySignature(
        IReadOnlyList<string> segments,
        EnterpriseAuthorizationLeasePublicKey key)
    {
        var signingInput = Encoding.ASCII.GetBytes($"{segments[0]}.{segments[1]}");
        var signature = EnterpriseBindingValidation.Base64UrlDecode(
            segments[2],
            "authorization_lease.signature",
            64);
        var x = EnterpriseBindingValidation.Base64UrlDecode(key.X, "lease_key.x", 32);
        var y = EnterpriseBindingValidation.Base64UrlDecode(key.Y, "lease_key.y", 32);
        try
        {
            if (signature.Length != 64 || x.Length != 32 || y.Length != 32)
            {
                throw new InvalidDataException(
                    "Enterprise authorization lease must use ES256 P1363 material.");
            }

            using var publicKey = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y },
            });
            if (!publicKey.VerifyData(
                    signingInput,
                    signature,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                throw new InvalidDataException(
                    "Enterprise authorization lease signature is invalid.");
            }
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                "Enterprise authorization lease signature cannot be verified as ES256 P1363.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signingInput);
            CryptographicOperations.ZeroMemory(signature);
            CryptographicOperations.ZeroMemory(x);
            CryptographicOperations.ZeroMemory(y);
        }
    }

    private EnterpriseAuthorizationLeaseClaims ReadAndValidateClaims(string segment)
    {
        var bytes = EnterpriseBindingValidation.Base64UrlDecode(
            segment,
            "authorization_lease.payload",
            8192);
        try
        {
            using var document = JsonDocument.Parse(bytes, StrictJsonDocumentOptions(maxDepth: 16));
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException(
                    "Enterprise authorization lease payload must be one exact JSON object.");
            }

            var requiredPayloadMembers = _trustPolicy.IsEnterpriseDirectLocal
                ? DirectLocalRequiredPayloadMembers
                : LegacyRequiredPayloadMembers;
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
            {
                if (!names.Add(property.Name)
                    || !requiredPayloadMembers.Contains(property.Name))
                {
                    throw new InvalidDataException(
                        "Enterprise authorization lease payload contains duplicate or unknown members.");
                }
            }

            if (names.Count != requiredPayloadMembers.Count
                || requiredPayloadMembers.Any(required => !names.Contains(required)))
            {
                throw new InvalidDataException(
                    "Enterprise authorization lease payload is missing required profile members.");
            }

            var expectedSchemaVersion = _trustPolicy.IsEnterpriseDirectLocal ? 2 : 1;
            if (GetRequiredInteger(root, "schema_version", 0, 2)
                != expectedSchemaVersion)
            {
                throw new InvalidDataException(
                    "Enterprise authorization lease schema version is unsupported.");
            }

            var leaseId = GetCanonicalUuid(root, "jti");
            var issuer = GetRequiredString(root, "iss");
            if (GetRequiredString(root, "aud") != ExpectedAudience)
            {
                throw new InvalidDataException(
                    "Enterprise authorization lease audience is invalid.");
            }

            var subject = GetCanonicalUuid(root, "sub");
            var bindingId = GetCanonicalUuid(root, "binding_id");
            var installationId = GetCanonicalUuid(root, "installation_id");
            var thumbprint = GetRequiredString(root, "device_key_thumbprint");
            EnterpriseBindingValidation.ValidateCanonicalBase64Url(
                thumbprint,
                "authorization_lease.device_key_thumbprint",
                32);

            if (GetRequiredString(root, "employee_state") != "ACTIVE"
                || GetRequiredString(root, "device_state") != "ACTIVE"
                || GetRequiredString(root, "api_allocation_state") != "ACTIVE")
            {
                throw new InvalidDataException(
                    "Enterprise authorization lease raw states must all be ACTIVE.");
            }

            var authorizationEpoch = GetPositiveSafeInteger(root, "auth_epoch");
            var entitlementEpoch = GetPositiveSafeInteger(root, "entitlement_epoch");
            var bindingEpoch = GetPositiveSafeInteger(root, "binding_epoch");
            var apiAllocationId = GetCanonicalUuid(root, "api_allocation_id");
            var allocationEpoch = GetPositiveSafeInteger(root, "allocation_epoch");
            var apiProfileId = GetCanonicalUuid(root, "api_profile_id");
            var apiProfileVersion = GetPositiveSafeInteger(root, "api_profile_version");
            var pluginPolicyId = GetCanonicalUuid(root, "plugin_policy_id");
            var pluginPolicyGeneration = GetPositiveSafeInteger(
                root,
                "plugin_policy_generation");
            var pluginPolicySha256 = GetRequiredString(root, "plugin_policy_sha256");
            EnterpriseBindingValidation.ValidateCanonicalLowercaseSha256(
                pluginPolicySha256,
                "authorization_lease.plugin_policy_sha256");
            var rolloutChannel = GetRequiredString(root, "rollout_channel");
            if (rolloutChannel is not "LAB" and not "PILOT" and not "STABLE")
            {
                throw new InvalidDataException(
                    "Enterprise authorization lease rollout channel is invalid.");
            }

            string? gatewayOrigin = null;
            string? runtimeProfile = null;
            string? apiProvider = null;
            if (_trustPolicy.IsEnterpriseDirectLocal)
            {
                runtimeProfile = GetRequiredString(root, "runtime_profile");
                apiProvider = GetRequiredString(root, "api_provider");
                if (!string.Equals(
                        runtimeProfile,
                        "enterprise-direct-local",
                        StringComparison.Ordinal)
                    || !string.Equals(apiProvider, "deepseek", StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "Enterprise direct-local authorization lease runtime profile is invalid.");
                }
            }
            else
            {
                gatewayOrigin = GetRequiredString(root, "gateway_origin");
            }
            var artifactOrigin = GetRequiredString(root, "artifact_origin");
            var supportDisplay = GetRequiredString(root, "support_display");
            EnterpriseBindingValidation.ValidateDeviceLabel(
                supportDisplay,
                "authorization_lease.support_display");

            var issuedAt = GetUnixSecond(root, "iat");
            var notBefore = GetUnixSecond(root, "nbf");
            var expiresAt = GetUnixSecond(root, "exp");
            if (notBefore > issuedAt
                || issuedAt >= expiresAt
                || expiresAt - issuedAt > (long)MaximumLeaseLifetime.TotalSeconds)
            {
                throw new InvalidDataException(
                    "Enterprise authorization lease time claims are inconsistent.");
            }

            return new EnterpriseAuthorizationLeaseClaims(
                expectedSchemaVersion,
                leaseId,
                issuer,
                subject,
                bindingId,
                installationId,
                thumbprint,
                authorizationEpoch,
                entitlementEpoch,
                bindingEpoch,
                apiAllocationId,
                allocationEpoch,
                apiProfileId,
                apiProfileVersion,
                pluginPolicyId,
                pluginPolicyGeneration,
                pluginPolicySha256,
                rolloutChannel,
                gatewayOrigin,
                runtimeProfile,
                apiProvider,
                artifactOrigin,
                supportDisplay,
                DateTimeOffset.FromUnixTimeSeconds(issuedAt),
                DateTimeOffset.FromUnixTimeSeconds(notBefore),
                DateTimeOffset.FromUnixTimeSeconds(expiresAt));
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Enterprise authorization lease payload must be exact JSON.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private void ValidateClaimsAgainstTrust(
        EnterpriseAuthorizationLeaseClaims claims,
        EnterpriseAuthorizationLeaseVerificationContext context)
    {
        if (!string.Equals(
                claims.Issuer,
                _trustPolicy.IssuerOrigin.AbsoluteUri,
                StringComparison.Ordinal)
            || !string.Equals(
                claims.ArtifactOrigin,
                _trustPolicy.ArtifactOrigin.AbsoluteUri,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise authorization lease contains an untrusted origin.");
        }

        if (_trustPolicy.IsEnterpriseDirectLocal)
        {
            if (claims.SchemaVersion != 2
                || claims.GatewayOrigin is not null
                || !string.Equals(
                    claims.RuntimeProfile,
                    "enterprise-direct-local",
                    StringComparison.Ordinal)
                || !string.Equals(claims.ApiProvider, "deepseek", StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Enterprise authorization lease does not match direct-local trust.");
            }
        }
        else if (claims.SchemaVersion != 1
            || claims.RuntimeProfile is not null
            || claims.ApiProvider is not null
            || !string.Equals(
                claims.GatewayOrigin,
                _trustPolicy.GatewayOrigin.AbsoluteUri,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise authorization lease does not match managed-gateway trust.");
        }

        if (!string.Equals(claims.BindingId, context.ExpectedBindingId, StringComparison.Ordinal)
            || !string.Equals(
                claims.InstallationId,
                context.ExpectedInstallationId,
                StringComparison.Ordinal)
            || !string.Equals(
                claims.DeviceKeyThumbprint,
                context.ExpectedDeviceKeyThumbprint,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise authorization lease is not bound to this installation and device.");
        }

        if (context.ExpectedEpochState is not null
            && context.ExpectedEpochState != claims.ToEpochState())
        {
            throw new InvalidDataException(
                "Enterprise authorization lease epochs or policy state do not match accepted local state.");
        }

        if (context.EvaluationTimeUtc < context.MinimumTrustedTimeUtc
            || context.EvaluationTimeUtc < claims.IssuedAtUtc
            || context.EvaluationTimeUtc < claims.NotBeforeUtc
            || context.EvaluationTimeUtc >= claims.ExpiresAtUtc)
        {
            throw new InvalidDataException(
                "Enterprise authorization lease is not valid at the trusted evaluation time.");
        }
    }

    private static void ValidateContext(
        EnterpriseAuthorizationLeaseVerificationContext context)
    {
        EnterpriseBindingValidation.CanonicalizeUuid(
            context.ExpectedBindingId,
            nameof(context.ExpectedBindingId));
        EnterpriseBindingValidation.CanonicalizeUuid(
            context.ExpectedInstallationId,
            nameof(context.ExpectedInstallationId));
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            context.ExpectedDeviceKeyThumbprint,
            nameof(context.ExpectedDeviceKeyThumbprint),
            32);
        if (context.EvaluationTimeUtc.Offset != TimeSpan.Zero
            || context.MinimumTrustedTimeUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException(
                "Enterprise authorization lease verification requires UTC trusted times.");
        }
    }

    private static JsonDocumentOptions StrictJsonDocumentOptions(int maxDepth) => new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = maxDepth,
    };

    private static string GetCanonicalUuid(JsonElement root, string memberName) =>
        EnterpriseBindingValidation.CanonicalizeUuid(
            GetRequiredString(root, memberName),
            $"authorization_lease.{memberName}");

    private static string GetRequiredString(JsonElement root, string memberName)
    {
        var value = root.GetProperty(memberName);
        if (value.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException(
                $"Enterprise authorization lease member {memberName} must be a JSON string.");
        }

        return value.GetString()
            ?? throw new InvalidDataException(
                $"Enterprise authorization lease member {memberName} is missing.");
    }

    private static long GetPositiveSafeInteger(JsonElement root, string memberName) =>
        GetRequiredInteger(root, memberName, 1, MaximumSafeInteger);

    private static long GetUnixSecond(JsonElement root, string memberName) =>
        GetRequiredInteger(root, memberName, 0, MaximumUnixSecond);

    private static long GetRequiredInteger(
        JsonElement root,
        string memberName,
        long minimum,
        long maximum)
    {
        var value = root.GetProperty(memberName);
        var rawText = value.GetRawText();
        if (value.ValueKind != JsonValueKind.Number
            || rawText.Length == 0
            || rawText.Any(character => !char.IsAsciiDigit(character))
            || !value.TryGetInt64(out var parsed)
            || parsed < minimum
            || parsed > maximum)
        {
            throw new InvalidDataException(
                $"Enterprise authorization lease member {memberName} must be a bounded JSON integer.");
        }

        return parsed;
    }
}
