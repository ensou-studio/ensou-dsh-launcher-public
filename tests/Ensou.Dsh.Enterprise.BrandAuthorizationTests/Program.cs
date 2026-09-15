using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Enterprise.Installation;
using Ensou.Dsh.Enterprise.ReleasePublisher;

namespace Ensou.Dsh.Enterprise.BrandAuthorizationTests;

internal static class Program
{
    private static readonly string TempRoot = Path.Combine(
        Path.GetTempPath(),
        "ensou-dsh-brand-authorization-tests");
    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web) { WriteIndented = true };

    private static int Main()
    {
        Directory.CreateDirectory(TempRoot);
        var tests = new (string Name, Action Run)[]
        {
            ("exact signed brand authorization admits", ExactReceiptAdmits),
            ("wrong signer and signature tamper reject", WrongSignerAndTamperReject),
            ("brand presentation and assets are exact", BrandProfileDriftRejects),
            ("written evidence bytes are bound", EvidenceDriftRejects),
            ("release and final executables are bound", ReleaseAndBinaryDriftRejects),
            ("audience and time window fail closed", AudienceAndTimeReject),
            ("brand trust is independent", IndependentTrustRequired),
            ("receipt JSON is strict", StrictJsonRequired),
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
            Console.WriteLine($"Brand authorization tests passed: {tests.Length}.");
            return 0;
        }
        Console.Error.WriteLine($"Brand authorization tests failed: {failures.Count}.");
        return 1;
    }

    private static void ExactReceiptAdmits()
    {
        using var fixture = Fixture.Create();
        var result = fixture.Validate();
        AssertEqual(fixture.Receipt.AuthorizationId, result.AuthorizationId);
        AssertEqual(EnterpriseBrandContract.ProfileSha256, result.BrandProfileSha256);
        AssertEqual(fixture.Trust.KeyId, result.KeyId);
        AssertEqual(fixture.ReceiptSha256, result.ReceiptSha256);
    }

    private static void WrongSignerAndTamperReject()
    {
        using var fixture = Fixture.Create();
        using var wrongSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var wrong = wrongSigner.ExportParameters(includePrivateParameters: false);
        var wrongTrust = new PublisherBrandAuthorizationTrust
        {
            KeyId = fixture.Trust.KeyId,
            X = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(wrong.Q.X!),
            Y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(wrong.Q.Y!),
        };
        AssertThrows<InvalidDataException>(() => fixture.Validate(trust: wrongTrust));

        var tampered = fixture.Receipt with
        {
            DistributionScope = "named-customer-pilot-tampered",
        };
        fixture.WriteReceiptWithoutSigning(tampered);
        AssertThrows<InvalidDataException>(() => fixture.Validate());
    }

    private static void BrandProfileDriftRejects()
    {
        using var fixture = Fixture.Create();
        fixture.WriteSignedReceipt(fixture.Receipt with
        {
            Brand = fixture.Receipt.Brand with { DeveloperName = "different developer" },
        });
        AssertThrows<InvalidDataException>(() => fixture.Validate());

        fixture.WriteSignedReceipt(fixture.Receipt with
        {
            Brand = fixture.Receipt.Brand with
            {
                LauncherWhalePngSha256 = new string('0', 64),
            },
        });
        AssertThrows<InvalidDataException>(() => fixture.Validate());
    }

    private static void EvidenceDriftRejects()
    {
        using var fixture = Fixture.Create();
        File.AppendAllText(fixture.EvidencePath, "changed", new UTF8Encoding(false));
        AssertThrows<InvalidDataException>(() => fixture.Validate());

        using var mediaFixture = Fixture.Create();
        mediaFixture.WriteSignedReceipt(mediaFixture.Receipt with
        {
            Evidence = mediaFixture.Receipt.Evidence with
            {
                MediaType = "application/octet-stream",
            },
        });
        AssertThrows<InvalidDataException>(() => mediaFixture.Validate());
    }

    private static void ReleaseAndBinaryDriftRejects()
    {
        using var fixture = Fixture.Create();
        var wrongRelease = fixture.Release with
        {
            ReleaseSetManifestSha256 = new string('0', 64),
        };
        AssertThrows<InvalidDataException>(() => fixture.Validate(release: wrongRelease));

        File.AppendAllText(
            fixture.Binaries.LauncherExecutablePath,
            "changed",
            new UTF8Encoding(false));
        AssertThrows<InvalidDataException>(() => fixture.Validate());
    }

    private static void AudienceAndTimeReject()
    {
        using var fixture = Fixture.Create();
        var wrongAudience = fixture.Input with
        {
            DistributionAudienceId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        };
        AssertThrows<InvalidDataException>(() => fixture.Validate(input: wrongAudience));

        fixture.WriteSignedReceipt(fixture.Receipt with
        {
            ReviewedAtUnixSeconds = fixture.Now.AddDays(-31).ToUnixTimeSeconds(),
            NotBeforeUnixSeconds = fixture.Now.AddDays(-31).ToUnixTimeSeconds(),
        });
        AssertThrows<InvalidDataException>(() => fixture.Validate());

        fixture.WriteSignedReceipt(fixture.Receipt with
        {
            ExpiresAtUnixSeconds = fixture.Now.AddMinutes(-1).ToUnixTimeSeconds(),
        });
        AssertThrows<InvalidDataException>(() => fixture.Validate());

        fixture.WriteSignedReceipt(fixture.Receipt with
        {
            ExpiresAtUnixSeconds = fixture.Now.AddDays(91).ToUnixTimeSeconds(),
        });
        AssertThrows<InvalidDataException>(() => fixture.Validate());
    }

    private static void IndependentTrustRequired()
    {
        using var fixture = Fixture.Create();
        using var releaseSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaseSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var release = releaseSigner.ExportParameters(includePrivateParameters: false);
        var lease = leaseSigner.ExportParameters(includePrivateParameters: false);
        var launcherTrust = new EnterpriseProductionTrustInputs(
            "https://updates.acme-corp.com/v2/channels/pilot/release-set.v2.json",
            "https://updates.acme-corp.com/",
            "https://artifacts.acme-corp.com/",
            "release-test-key",
            PublisherRuntimeAdmissionEncoding.EncodeBase64Url(release.Q.X!),
            PublisherRuntimeAdmissionEncoding.EncodeBase64Url(release.Q.Y!),
            "https://control.acme-corp.com/",
            "https://authorization.acme-corp.com/",
            "https://gateway.acme-corp.com/",
            "https://managed-artifacts.acme-corp.com/",
            "lease-test-key",
            PublisherRuntimeAdmissionEncoding.EncodeBase64Url(lease.Q.X!),
            PublisherRuntimeAdmissionEncoding.EncodeBase64Url(lease.Q.Y!),
            new string('a', 64));
        var runtime = new PublisherRuntimeAdmissionTrust
        {
            KeyId = "runtime-test-key",
            X = fixture.Trust.X,
            Y = fixture.Trust.Y,
        };
        AssertThrows<InvalidDataException>(() =>
            fixture.Trust.RequireIndependentFrom(runtime, launcherTrust));
    }

    private static void StrictJsonRequired()
    {
        using var fixture = Fixture.Create();
        var raw = File.ReadAllText(fixture.ReceiptPath);
        var duplicate = raw.Replace(
            "\"schemaVersion\": 1,",
            "\"schemaVersion\": 1,\n  \"schemaVersion\": 1,",
            StringComparison.Ordinal);
        File.WriteAllText(fixture.ReceiptPath, duplicate, new UTF8Encoding(false));
        fixture.RefreshReceiptHash();
        AssertThrows<InvalidDataException>(() => fixture.Validate());
    }

    private sealed class Fixture : IDisposable
    {
        private readonly ECDsa _signer;
        private readonly string _root;

        private Fixture(
            string root,
            ECDsa signer,
            DateTimeOffset now,
            PublisherBrandAuthorizationTrust trust,
            PublisherBrandReleaseBinding release,
            PublisherBrandBinaryPaths binaries,
            string evidencePath,
            string receiptPath,
            PublisherBrandAuthorizationReceipt receipt,
            PilotBrandAuthorizationInput input)
        {
            _root = root;
            _signer = signer;
            Now = now;
            Trust = trust;
            Release = release;
            Binaries = binaries;
            EvidencePath = evidencePath;
            ReceiptPath = receiptPath;
            Receipt = receipt;
            Input = input;
        }

        public DateTimeOffset Now { get; }
        public PublisherBrandAuthorizationTrust Trust { get; }
        public PublisherBrandReleaseBinding Release { get; }
        public PublisherBrandBinaryPaths Binaries { get; }
        public string EvidencePath { get; }
        public string ReceiptPath { get; }
        public PublisherBrandAuthorizationReceipt Receipt { get; private set; }
        public PilotBrandAuthorizationInput Input { get; private set; }
        public string ReceiptSha256 => HashFile(ReceiptPath);

        public static Fixture Create()
        {
            var root = Path.Combine(TempRoot, Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            var launcher = Path.Combine(root, "Ensou.Dsh.Enterprise.Launcher.exe");
            var bootstrapper = Path.Combine(root, "Ensou.Dsh.Enterprise.Bootstrapper.exe");
            var installer = Path.Combine(root, "Ensou.Dsh.Enterprise.Installer.exe");
            File.WriteAllBytes(launcher, RandomNumberGenerator.GetBytes(1024));
            File.WriteAllBytes(bootstrapper, RandomNumberGenerator.GetBytes(1024));
            File.WriteAllBytes(installer, RandomNumberGenerator.GetBytes(1024));
            var evidencePath = Path.Combine(root, "written-brand-permission.pdf");
            File.WriteAllText(
                evidencePath,
                "exact retained written brand authorization evidence",
                new UTF8Encoding(false));

            var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var parameters = signer.ExportParameters(includePrivateParameters: false);
            var trust = new PublisherBrandAuthorizationTrust
            {
                KeyId = "brand-authorization-test-key",
                X = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(parameters.Q.X!),
                Y = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(parameters.Q.Y!),
            };
            var now = DateTimeOffset.UtcNow;
            var release = new PublisherBrandReleaseBinding(
                "enterprise-pilot-test-1",
                1,
                1,
                new string('1', 64),
                now.AddDays(2),
                "launcher-production-test-1",
                new string('2', 64));
            var binaries = new PublisherBrandBinaryPaths(launcher, bootstrapper, installer);
            var receipt = new PublisherBrandAuthorizationReceipt
            {
                SchemaVersion = PublisherBrandAuthorizationReceipt.CurrentSchemaVersion,
                ReceiptType = PublisherBrandAuthorizationReceipt.CurrentReceiptType,
                AuthorizationId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                Decision = PublisherBrandAuthorizationReceipt.AuthorizedDecision,
                Environment = PublisherBrandAuthorizationReceipt.ProductionEnvironment,
                Channel = PublisherBrandAuthorizationReceipt.PilotChannel,
                DistributionScope = PublisherBrandAuthorizationReceipt.NamedCustomerPilotScope,
                DistributionAudienceId = "11111111-1111-1111-1111-111111111111",
                ReleaseBinding = new PublisherBrandReleaseReceiptBinding
                {
                    ReleaseSetId = release.ReleaseSetId,
                    Generation = release.Generation,
                    Sequence = release.Sequence,
                    ReleaseSetManifestSha256 = release.ReleaseSetManifestSha256,
                    LauncherReleaseId = release.LauncherReleaseId,
                    LauncherArchiveSha256 = release.LauncherArchiveSha256,
                },
                Brand = new PublisherBrandReceiptProfile
                {
                    BrandProfileId = EnterpriseBrandContract.BrandProfileId,
                    BrandProfileSha256 = EnterpriseBrandContract.ProfileSha256,
                    ProductFamilyName = EnterpriseBrandContract.ProductFamilyName,
                    LauncherProductName = EnterpriseBrandContract.LauncherProductName,
                    InstallerProductName = EnterpriseBrandContract.InstallerProductName,
                    BootstrapperProductName = EnterpriseBrandContract.BootstrapperProductName,
                    DeveloperName = EnterpriseBrandContract.DeveloperName,
                    PresentationSha256 = EnterpriseBrandContract.PresentationSha256,
                    OfficialWhaleSvgSha256 = EnterpriseBrandContract.OfficialWhaleSvgSha256,
                    LauncherWhalePngSha256 = EnterpriseBrandContract.LauncherWhalePngSha256,
                    WindowsWhaleIcoSha256 = EnterpriseBrandContract.WindowsWhaleIcoSha256,
                },
                Evidence = new PublisherBrandReceiptEvidence
                {
                    DocumentSha256 = HashFile(evidencePath),
                    SizeBytes = new FileInfo(evidencePath).Length,
                    MediaType = "application/pdf",
                },
                Binaries = new PublisherBrandReceiptBinaries
                {
                    LauncherExecutableSha256 = HashFile(launcher),
                    BootstrapperExecutableSha256 = HashFile(bootstrapper),
                    InstallerExecutableSha256 = HashFile(installer),
                },
                ReviewedAtUnixSeconds = now.AddMinutes(-1).ToUnixTimeSeconds(),
                NotBeforeUnixSeconds = now.AddMinutes(-2).ToUnixTimeSeconds(),
                ExpiresAtUnixSeconds = now.AddDays(3).ToUnixTimeSeconds(),
                Signature = new EnterpriseReleaseSignature
                {
                    Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
                    KeyId = trust.KeyId,
                    Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(new byte[64]),
                },
            };
            var receiptPath = Path.Combine(root, "brand-authorization.v1.json");
            var fixture = new Fixture(
                root,
                signer,
                now,
                trust,
                release,
                binaries,
                evidencePath,
                receiptPath,
                receipt,
                new PilotBrandAuthorizationInput
                {
                    ReceiptPath = receiptPath,
                    ReceiptSha256 = new string('0', 64),
                    EvidencePath = evidencePath,
                    EvidenceSha256 = HashFile(evidencePath),
                    DistributionAudienceId = receipt.DistributionAudienceId,
                });
            fixture.WriteSignedReceipt(receipt);
            return fixture;
        }

        public PublisherBrandAuthorizationValidation Validate(
            PilotBrandAuthorizationInput? input = null,
            PublisherBrandReleaseBinding? release = null,
            PublisherBrandAuthorizationTrust? trust = null) =>
            PublisherBrandAuthorizationValidator.Validate(
                input ?? Input,
                ReceiptPath,
                EvidencePath,
                release ?? Release,
                Binaries,
                trust ?? Trust,
                Now);

        public void WriteSignedReceipt(PublisherBrandAuthorizationReceipt receipt)
        {
            var signature = _signer.SignData(
                PublisherBrandAuthorizationCanonicalJson.Payload(receipt),
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            Receipt = receipt with
            {
                Signature = receipt.Signature with
                {
                    Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(signature),
                },
            };
            WriteReceiptWithoutSigning(Receipt);
        }

        public void WriteReceiptWithoutSigning(PublisherBrandAuthorizationReceipt receipt)
        {
            Receipt = receipt;
            File.WriteAllText(
                ReceiptPath,
                JsonSerializer.Serialize(receipt, JsonOptions),
                new UTF8Encoding(false));
            RefreshReceiptHash();
        }

        public void RefreshReceiptHash() => Input = Input with
        {
            ReceiptSha256 = HashFile(ReceiptPath),
        };

        public void Dispose()
        {
            _signer.Dispose();
            try
            {
                Directory.Delete(_root, recursive: true);
            }
            catch
            {
                // A failed test keeps diagnostics in the bounded temp fixture.
            }
        }
    }

    private static string HashFile(string path) =>
        Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));

    private static void AssertEqual<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected {expected}, actual {actual}.");
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
        throw new InvalidOperationException(
            $"Expected {typeof(TException).Name} to be thrown.");
    }
}
