using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Ensou.Dsh.Enterprise.Client;

using var fixture = new LeaseFixture();
var tests = new (string Name, Action Run)[]
{
    ("direct trust admits exact signed schema-v2 claims", fixture.DirectV2Admits),
    ("direct trust rejects legacy and mixed gateway leases", fixture.DirectRejectsLegacyAndMixed),
    ("legacy trust remains schema-v1 only", fixture.LegacyRemainsV1Only),
    ("direct profile and provider are exact", fixture.DirectProfileIsExact),
    ("signature identity epoch and time guards remain", fixture.ExistingGuardsRemain),
    ("persisted direct lease rebinds exact receipt and device", fixture.PersistedLeaseRebinds),
};

var failures = 0;
foreach (var test in tests)
{
    try
    {
        test.Run();
        Console.WriteLine($"PASS {test.Name}");
    }
    catch (Exception exception)
    {
        failures++;
        Console.Error.WriteLine($"FAIL {test.Name}: {exception}");
    }
}

Console.WriteLine($"{tests.Length - failures}/{tests.Length} direct-local lease tests passed.");
return failures == 0 ? 0 : 1;

internal sealed class LeaseFixture : IDisposable
{
    private const string LeaseId = "10203040-5060-4070-8090-a0b0c0d0e0f0";
    private const string Subject = "11223344-5566-4778-8990-aabbccddeeff";
    private const string BindingId = "22334455-6677-4889-9011-bbccddeeff00";
    private const string InstallationId = "33445566-7788-4990-8122-ccddeeff0011";
    private const string ApiAllocationId = "44556677-8899-4001-8233-ddeeff001122";
    private const string ApiProfileId = "55667788-9900-4112-8344-eeff00112233";
    private const string PluginPolicyId = "66778899-0011-4223-8455-ff0011223344";
    private const string PluginPolicySha256 =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string Issuer = "https://control.corp.example/";
    private const string Gateway = "https://gateway.corp.example/";
    private const string Artifact = "https://artifacts.corp.example/";
    private static readonly DateTimeOffset IssuedAt =
        DateTimeOffset.FromUnixTimeSeconds(1_789_356_600);

    private readonly ECDsa _signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly string _headerSegment;
    private readonly EnterpriseAuthorizationLeaseTrustPolicy _legacyTrust;
    private readonly EnterpriseAuthorizationLeaseTrustPolicy _directTrust;
    private readonly string _thumbprint = Encode(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray());

    public LeaseFixture()
    {
        var parameters = _signer.ExportParameters(false);
        var publicKey = new EnterpriseAuthorizationLeasePublicKey(
            "lease-test-key",
            Encode(parameters.Q.X!),
            Encode(parameters.Q.Y!));
        _headerSegment = Encode(Encoding.UTF8.GetBytes(
            "{\"alg\":\"ES256\",\"kid\":\"lease-test-key\",\"typ\":\"ensou-dsh-lease+jwt\"}"));
        _legacyTrust = new(
            new Uri(Issuer),
            new Uri(Gateway),
            new Uri(Artifact),
            [publicKey]);
        _directTrust = EnterpriseAuthorizationLeaseTrustPolicy.CreateEnterpriseDirectLocal(
            new Uri(Issuer),
            new Uri(Artifact),
            [publicKey]);
    }

    public void DirectV2Admits()
    {
        var verified = DirectVerifier().Verify(Sign(DirectPayload()), Context());
        Equal(2, verified.Claims.SchemaVersion);
        Equal("enterprise-direct-local", verified.Claims.RuntimeProfile);
        Equal("deepseek", verified.Claims.ApiProvider);
        Equal<string?>(null, verified.Claims.GatewayOrigin);
        Equal("enterprise-direct-local", verified.AccessSnapshot.RuntimeProfile);
        Equal("deepseek", verified.AccessSnapshot.ApiProvider);
        True(verified.AccessSnapshot.LeaseSignatureValid);
        True(_directTrust.IsEnterpriseDirectLocal);
        Throws<InvalidOperationException>(() => _ = _directTrust.GatewayOrigin);
    }

    public void DirectRejectsLegacyAndMixed()
    {
        Throws<InvalidDataException>(() => DirectVerifier().Verify(
            Sign(LegacyPayload()),
            Context()));

        var mixed = DirectPayload();
        mixed["gateway_origin"] = Gateway;
        Throws<InvalidDataException>(() => DirectVerifier().Verify(Sign(mixed), Context()));

        var missing = DirectPayload();
        missing.Remove("api_provider");
        Throws<InvalidDataException>(() => DirectVerifier().Verify(Sign(missing), Context()));
    }

    public void LegacyRemainsV1Only()
    {
        var verified = LegacyVerifier().Verify(Sign(LegacyPayload()), Context());
        Equal(1, verified.Claims.SchemaVersion);
        Equal(Gateway, verified.Claims.GatewayOrigin);
        Equal<string?>(null, verified.Claims.RuntimeProfile);
        Equal<string?>(null, verified.Claims.ApiProvider);

        Throws<InvalidDataException>(() => LegacyVerifier().Verify(
            Sign(DirectPayload()),
            Context()));
        var mixed = LegacyPayload();
        mixed["runtime_profile"] = "enterprise-direct-local";
        mixed["api_provider"] = "deepseek";
        Throws<InvalidDataException>(() => LegacyVerifier().Verify(Sign(mixed), Context()));
    }

    public void DirectProfileIsExact()
    {
        foreach (var mutation in new Action<JsonObject>[]
        {
            payload => payload["runtime_profile"] = "enterprise-managed",
            payload => payload["api_provider"] = "gateway",
            payload => payload["schema_version"] = 1,
            payload => payload["runtimeProfile"] = "enterprise-direct-local",
        })
        {
            var payload = DirectPayload();
            mutation(payload);
            Throws<InvalidDataException>(() => DirectVerifier().Verify(Sign(payload), Context()));
        }

        var duplicateText = JsonSerializer.Serialize(DirectPayload()).Replace(
            "\"api_provider\":\"deepseek\"",
            "\"api_provider\":\"deepseek\",\"api_provider\":\"deepseek\"",
            StringComparison.Ordinal);
        Throws<InvalidDataException>(() => DirectVerifier().Verify(
            SignRaw(duplicateText),
            Context()));
    }

    public void ExistingGuardsRemain()
    {
        var compact = Sign(DirectPayload());
        var segments = compact.Split('.');
        var tamperedPayload = DirectPayload();
        tamperedPayload["api_profile_version"] = 9;
        var tamperedPayloadSegment = Encode(JsonSerializer.SerializeToUtf8Bytes(tamperedPayload));
        Throws<InvalidDataException>(() => DirectVerifier().Verify(
            $"{segments[0]}.{tamperedPayloadSegment}.{segments[2]}",
            Context()));

        Throws<InvalidDataException>(() => DirectVerifier().Verify(
            compact,
            Context() with { ExpectedBindingId = Guid.NewGuid().ToString("D") }));
        Throws<InvalidDataException>(() => DirectVerifier().Verify(
            compact,
            Context() with
            {
                ExpectedEpochState = EpochState() with { AllocationEpoch = 2 },
            }));
        Throws<InvalidDataException>(() => DirectVerifier().Verify(
            compact,
            Context() with { EvaluationTimeUtc = IssuedAt.AddMinutes(15) }));
    }

    public void PersistedLeaseRebinds()
    {
        var compact = Sign(DirectPayload());
        var credential = new EnterprisePersistedBindingCredential(
            new string('r', 43),
            compact,
            Receipt());
        var device = new EnterpriseEnrollmentDeviceContext(
            new EnterpriseInstallationIdentity(
                Guid.Parse(InstallationId),
                IssuedAt.AddDays(-1)),
            new EnterpriseDevicePublicIdentity("EC", "P-256", "x", "y", _thumbprint));
        var verified = DirectVerifier().VerifyPersistedCredential(credential, device);
        Equal("enterprise-direct-local", verified.Claims.RuntimeProfile);
        Throws<InvalidDataException>(() => DirectVerifier().VerifyPersistedCredential(
            credential,
            device,
            IssuedAt.AddMinutes(15),
            IssuedAt));
        Throws<InvalidDataException>(() => DirectVerifier().VerifyPersistedCredential(
            credential,
            device,
            IssuedAt,
            IssuedAt.AddSeconds(1)));

        var wrongReceipt = credential with
        {
            Receipt = credential.Receipt with { LeaseId = Guid.NewGuid().ToString("D") },
        };
        Throws<InvalidDataException>(() =>
            DirectVerifier().VerifyPersistedCredential(wrongReceipt, device));
        var wrongDevice = device with
        {
            DeviceKey = device.DeviceKey with { Thumbprint = Encode(new byte[32]) },
        };
        Throws<InvalidDataException>(() =>
            DirectVerifier().VerifyPersistedCredential(credential, wrongDevice));
    }

    public void Dispose() => _signer.Dispose();

    private EnterpriseAuthorizationLeaseVerifier LegacyVerifier() => new(_legacyTrust);

    private EnterpriseAuthorizationLeaseVerifier DirectVerifier() => new(_directTrust);

    private EnterpriseAuthorizationLeaseVerificationContext Context() => new(
        BindingId,
        InstallationId,
        _thumbprint,
        IssuedAt,
        IssuedAt,
        EpochState());

    private static EnterpriseAuthorizationEpochState EpochState() => new(
        4,
        5,
        6,
        ApiAllocationId,
        7,
        ApiProfileId,
        8,
        PluginPolicyId,
        9,
        PluginPolicySha256,
        "PILOT");

    private EnterpriseBindingReceipt Receipt() => new(
        BindingId,
        InstallationId,
        _thumbprint,
        Subject,
        LeaseId,
        EpochState(),
        IssuedAt,
        IssuedAt.AddMinutes(15),
        "ignored-by-verifier");

    private JsonObject LegacyPayload()
    {
        var payload = CommonPayload(1);
        payload.Insert(21, "gateway_origin", Gateway);
        return payload;
    }

    private JsonObject DirectPayload()
    {
        var payload = CommonPayload(2);
        payload.Insert(18, "runtime_profile", "enterprise-direct-local");
        payload.Insert(19, "api_provider", "deepseek");
        return payload;
    }

    private JsonObject CommonPayload(int schemaVersion) => new()
    {
        ["schema_version"] = schemaVersion,
        ["jti"] = LeaseId,
        ["iss"] = Issuer,
        ["aud"] = "ensou-dsh-enterprise-launcher",
        ["sub"] = Subject,
        ["binding_id"] = BindingId,
        ["installation_id"] = InstallationId,
        ["device_key_thumbprint"] = _thumbprint,
        ["employee_state"] = "ACTIVE",
        ["device_state"] = "ACTIVE",
        ["api_allocation_state"] = "ACTIVE",
        ["auth_epoch"] = 4,
        ["entitlement_epoch"] = 5,
        ["binding_epoch"] = 6,
        ["api_allocation_id"] = ApiAllocationId,
        ["allocation_epoch"] = 7,
        ["api_profile_id"] = ApiProfileId,
        ["api_profile_version"] = 8,
        ["plugin_policy_id"] = PluginPolicyId,
        ["plugin_policy_generation"] = 9,
        ["plugin_policy_sha256"] = PluginPolicySha256,
        ["rollout_channel"] = "PILOT",
        ["artifact_origin"] = Artifact,
        ["support_display"] = "Enterprise IT",
        ["iat"] = IssuedAt.ToUnixTimeSeconds(),
        ["nbf"] = IssuedAt.ToUnixTimeSeconds(),
        ["exp"] = IssuedAt.AddMinutes(15).ToUnixTimeSeconds(),
    };

    private string Sign(JsonObject payload) => SignRaw(JsonSerializer.Serialize(payload));

    private string SignRaw(string payloadJson)
    {
        var payloadSegment = Encode(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = Encoding.ASCII.GetBytes($"{_headerSegment}.{payloadSegment}");
        var signature = _signer.SignData(
            signingInput,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        try
        {
            return $"{_headerSegment}.{payloadSegment}.{Encode(signature)}";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signingInput);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static string Encode(byte[] value) => Convert.ToBase64String(value)
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');

    private static void True(bool value)
    {
        if (!value)
        {
            throw new InvalidOperationException("Expected true.");
        }
    }

    private static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected {expected}; actual {actual}.");
        }
    }

    private static void Throws<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }
        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }
}
