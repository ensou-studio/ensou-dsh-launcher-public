using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Enterprise.Installation;
using Ensou.Dsh.Enterprise.ReleasePublisher;

namespace Ensou.Dsh.Enterprise.LocalDataCertificationTests;

internal static class Program
{
    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web) { WriteIndented = true };

    private static int Main()
    {
        var tests = new (string Name, Action Run)[]
        {
            ("signed ES256 P1363 certification admits", SignedCertificationAdmits),
            ("signature and evidence tamper reject", TamperRejects),
            ("expired or long-lived certification rejects", TimeWindowRejects),
            ("wrong audience or signer rejects", AudienceAndSignerReject),
            ("certification key reuse rejects", KeyReuseRejects),
            ("missing compiled certification trust rejects", MissingCompiledTrustRejects),
            ("receipt JSON is strict", StrictJsonRejects),
        };
        var failures = new List<string>();
        foreach (var test in tests)
        {
            try
            {
                test.Run();
                Console.WriteLine($"PASS {test.Name}");
            }
            catch (Exception exception)
            {
                failures.Add($"{test.Name}: {exception.Message}");
                Console.Error.WriteLine($"FAIL {test.Name}: {exception}");
            }
        }
        if (failures.Count == 0)
        {
            Console.WriteLine($"Local-data certification tests passed: {tests.Length}.");
            return 0;
        }
        Console.Error.WriteLine($"Local-data certification tests failed: {failures.Count}.");
        return 1;
    }

    private static void SignedCertificationAdmits()
    {
        using var fixture = Fixture.Create();
        var bytes = fixture.SerializeSigned(fixture.Receipt);
        var result = fixture.Validate(bytes);
        AssertEqual(fixture.Receipt.CertificationId, result.CertificationId);
        AssertEqual(fixture.Trust.KeyId, result.KeyId);
        AssertEqual(
            Convert.ToHexStringLower(SHA256.HashData(bytes)),
            result.ReceiptSha256);
        var parsed = PublisherLocalDataCompatibilityCertificationReceipt.Parse(bytes);
        AssertEqual(
            64,
            PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
                parsed.Signature.Value,
                "test signature",
                64).Length);
    }

    private static void TamperRejects()
    {
        using var fixture = Fixture.Create();
        var signed = fixture.SerializeSigned(fixture.Receipt);
        var parsed = PublisherLocalDataCompatibilityCertificationReceipt.Parse(signed);
        var signature = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
            parsed.Signature.Value,
            "test signature",
            64);
        signature[0] ^= 0x01;
        var badSignature = parsed with
        {
            Signature = parsed.Signature with
            {
                Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(signature),
            },
        };
        AssertThrows<InvalidDataException>(
            () => fixture.Validate(JsonSerializer.SerializeToUtf8Bytes(badSignature, JsonOptions)));

        var changedEvidence = parsed with
        {
            EvidenceReportSha256 = Hash("hand-written replacement evidence"),
        };
        AssertThrows<InvalidDataException>(
            () => fixture.Validate(JsonSerializer.SerializeToUtf8Bytes(changedEvidence, JsonOptions)));
    }

    private static void TimeWindowRejects()
    {
        using var fixture = Fixture.Create();
        var expired = fixture.Receipt with
        {
            ExpiresAtUnixSeconds = fixture.Now.AddSeconds(-1).ToUnixTimeSeconds(),
        };
        AssertThrows<InvalidDataException>(() => fixture.Validate(fixture.SerializeSigned(expired)));

        var longLived = fixture.Receipt with
        {
            ExpiresAtUnixSeconds = fixture.Now.AddHours(73).ToUnixTimeSeconds(),
        };
        AssertThrows<InvalidDataException>(() => fixture.Validate(fixture.SerializeSigned(longLived)));

        var stale = fixture.Receipt with
        {
            IssuedAtUnixSeconds = fixture.Now.AddHours(-25).ToUnixTimeSeconds(),
        };
        AssertThrows<InvalidDataException>(() => fixture.Validate(fixture.SerializeSigned(stale)));
    }

    private static void AudienceAndSignerReject()
    {
        using var fixture = Fixture.Create();
        var bytes = fixture.SerializeSigned(fixture.Receipt);
        var wrongAudience = fixture.Expected with
        {
            CertificationAudienceId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        };
        AssertThrows<InvalidDataException>(() => fixture.Validate(bytes, wrongAudience));

        using var wrongSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var wrongTrust = Trust("local-data-certification-wrong", wrongSigner);
        AssertThrows<InvalidDataException>(() => fixture.Validate(bytes, trust: wrongTrust));
    }

    private static void KeyReuseRejects()
    {
        using var fixture = Fixture.Create();
        using var runtimeKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var pluginKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var brandKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaseKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var releaseKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var runtime = RuntimeTrust("runtime-admission-v1", runtimeKey);
        var plugin = PluginTrust("plugin-admission-v1", pluginKey);
        var brand = BrandTrust("brand-authorization-v1", brandKey);
        var lease = LeaseTrust("lease-v1", leaseKey);
        var release = releaseKey.ExportParameters(includePrivateParameters: false);
        var releaseX = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(release.Q.X!);
        var releaseY = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(release.Q.Y!);

        fixture.Trust.RequireIndependentFrom(
            runtime,
            plugin,
            brand,
            lease,
            "release-v1",
            releaseX,
            releaseY);

        foreach (var reused in new[]
                 {
                     Trust("runtime-admission-v1", runtimeKey),
                     Trust("local-data-reuse-plugin", pluginKey),
                     Trust("local-data-reuse-brand", brandKey),
                     Trust("local-data-reuse-lease", leaseKey),
                     Trust("local-data-reuse-release", releaseKey),
                 })
        {
            AssertThrows<InvalidDataException>(() => reused.RequireIndependentFrom(
                runtime,
                plugin,
                brand,
                lease,
                "release-v1",
                releaseX,
                releaseY));
        }
    }

    private static void StrictJsonRejects()
    {
        using var fixture = Fixture.Create();
        var json = Encoding.UTF8.GetString(fixture.SerializeSigned(fixture.Receipt));
        var duplicate = json.Replace(
            "\"schemaVersion\": 1,",
            "\"schemaVersion\": 1,\n  \"schemaVersion\": 1,",
            StringComparison.Ordinal);
        AssertThrows<InvalidDataException>(
            () => fixture.Validate(Encoding.UTF8.GetBytes(duplicate)));

        var unknown = json.Replace(
            "\"receiptType\":",
            "\"unexpected\": true,\n  \"receiptType\":",
            StringComparison.Ordinal);
        AssertThrows<InvalidDataException>(
            () => fixture.Validate(Encoding.UTF8.GetBytes(unknown)));
    }

    private static void MissingCompiledTrustRejects() =>
        AssertThrows<InvalidDataException>(
            () => _ = PublisherLocalDataCompatibilityCertificationTrustResolver.ResolveProduction());

    private static PublisherLocalDataCompatibilityCertificationTrust Trust(
        string keyId,
        ECDsa key)
    {
        var parameters = key.ExportParameters(includePrivateParameters: false);
        return new PublisherLocalDataCompatibilityCertificationTrust
        {
            KeyId = keyId,
            X = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(parameters.Q.X!),
            Y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(parameters.Q.Y!),
        };
    }

    private static PublisherRuntimeAdmissionTrust RuntimeTrust(string keyId, ECDsa key)
    {
        var parameters = key.ExportParameters(includePrivateParameters: false);
        return new PublisherRuntimeAdmissionTrust
        {
            KeyId = keyId,
            X = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(parameters.Q.X!),
            Y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(parameters.Q.Y!),
        };
    }

    private static PublisherPluginAdmissionTrust PluginTrust(string keyId, ECDsa key)
    {
        var parameters = key.ExportParameters(includePrivateParameters: false);
        return new PublisherPluginAdmissionTrust
        {
            KeyId = keyId,
            X = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(parameters.Q.X!),
            Y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(parameters.Q.Y!),
        };
    }

    private static PublisherBrandAuthorizationTrust BrandTrust(string keyId, ECDsa key)
    {
        var parameters = key.ExportParameters(includePrivateParameters: false);
        return new PublisherBrandAuthorizationTrust
        {
            KeyId = keyId,
            X = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(parameters.Q.X!),
            Y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(parameters.Q.Y!),
        };
    }

    private static PublisherLeaseVerificationTrust LeaseTrust(string keyId, ECDsa key)
    {
        var parameters = key.ExportParameters(includePrivateParameters: false);
        return new PublisherLeaseVerificationTrust
        {
            KeyId = keyId,
            X = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(parameters.Q.X!),
            Y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(parameters.Q.Y!),
        };
    }

    private static string Hash(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static void AssertEqual<T>(T expected, T actual)
        where T : notnull
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected '{expected}', got '{actual}'.");
        }
    }

    private static void AssertThrows<TException>(Action action)
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

    private sealed class Fixture : IDisposable
    {
        private Fixture(
            DateTimeOffset now,
            ECDsa signer,
            PublisherLocalDataCompatibilityCertificationTrust trust,
            PublisherLocalDataCompatibilityCertificationExpectation expected,
            PublisherLocalDataCompatibilityCertificationReceipt receipt)
        {
            Now = now;
            Signer = signer;
            Trust = trust;
            Expected = expected;
            Receipt = receipt;
        }

        public DateTimeOffset Now { get; }
        public ECDsa Signer { get; }
        public PublisherLocalDataCompatibilityCertificationTrust Trust { get; }
        public PublisherLocalDataCompatibilityCertificationExpectation Expected { get; }
        public PublisherLocalDataCompatibilityCertificationReceipt Receipt { get; }

        public static Fixture Create()
        {
            var now = new DateTimeOffset(2026, 8, 25, 12, 0, 0, TimeSpan.Zero);
            var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var trust = Program.Trust("local-data-certification-v1", signer);
            var expected = new PublisherLocalDataCompatibilityCertificationExpectation(
                "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "dsh-v0.1.0-rc.7",
                "dsh-v0.1.1-rc.2",
                Hash("source runtime ZIP"),
                Hash("target runtime ZIP"),
                Hash("complete evidence report"),
                Hash("certification runner"));
            var receipt = new PublisherLocalDataCompatibilityCertificationReceipt
            {
                SchemaVersion =
                    PublisherLocalDataCompatibilityCertificationReceipt.CurrentSchemaVersion,
                ReceiptType =
                    PublisherLocalDataCompatibilityCertificationReceipt.CurrentReceiptType,
                CertificationId = "11111111-1111-1111-1111-111111111111",
                Decision = PublisherLocalDataCompatibilityCertificationReceipt.PassedDecision,
                Environment =
                    PublisherLocalDataCompatibilityCertificationReceipt.ProductionEnvironment,
                Channel = PublisherLocalDataCompatibilityCertificationReceipt.PilotChannel,
                DistributionScope =
                    PublisherLocalDataCompatibilityCertificationReceipt.NamedCustomerPilotScope,
                CertificationAudienceId = expected.CertificationAudienceId,
                FromUpstreamTag = expected.FromUpstreamTag,
                ToUpstreamTag = expected.ToUpstreamTag,
                SourceRuntimeZipSha256 = expected.SourceRuntimeZipSha256,
                TargetRuntimeZipSha256 = expected.TargetRuntimeZipSha256,
                EvidenceReportSha256 = expected.EvidenceReportSha256,
                RunnerSha256 = expected.RunnerSha256,
                IssuedAtUnixSeconds = now.AddMinutes(-1).ToUnixTimeSeconds(),
                ExpiresAtUnixSeconds = now.AddHours(24).ToUnixTimeSeconds(),
                Signature = new EnterpriseReleaseSignature
                {
                    Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
                    KeyId = trust.KeyId,
                    Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(new byte[64]),
                },
            };
            return new Fixture(now, signer, trust, expected, receipt);
        }

        public byte[] SerializeSigned(
            PublisherLocalDataCompatibilityCertificationReceipt unsignedReceipt)
        {
            var signature = Signer.SignData(
                PublisherLocalDataCompatibilityCertificationCanonicalJson.Payload(unsignedReceipt),
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            var signed = unsignedReceipt with
            {
                Signature = unsignedReceipt.Signature with
                {
                    Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
                    KeyId = Trust.KeyId,
                    Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(signature),
                },
            };
            return JsonSerializer.SerializeToUtf8Bytes(signed, JsonOptions);
        }

        public PublisherLocalDataCompatibilityCertificationValidation Validate(
            byte[] bytes,
            PublisherLocalDataCompatibilityCertificationExpectation? expected = null,
            PublisherLocalDataCompatibilityCertificationTrust? trust = null) =>
            PublisherLocalDataCompatibilityCertificationValidator.Validate(
                bytes,
                expected ?? Expected,
                trust ?? Trust,
                Now);

        public void Dispose() => Signer.Dispose();
    }
}
