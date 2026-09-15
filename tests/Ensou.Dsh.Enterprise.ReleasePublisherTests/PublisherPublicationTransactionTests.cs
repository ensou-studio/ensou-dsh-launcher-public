using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Enterprise.Installation;
using Ensou.Dsh.Enterprise.ReleasePublisher;

namespace Ensou.Dsh.Enterprise.ReleasePublisherTests;

internal static class PublisherPublicationTransactionTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public static Task CrashWindowsRecoverExactAsync()
    {
        var stages = new[]
        {
            PublisherPublicationCommitStage.PendingCommitted,
            PublisherPublicationCommitStage.LedgerCommitted,
            PublisherPublicationCommitStage.AnchorCommitted,
            PublisherPublicationCommitStage.OutputFileCommitted,
            PublisherPublicationCommitStage.ManifestCommitted,
            PublisherPublicationCommitStage.ReceiptCommitted,
        };
        foreach (var stage in stages)
        {
            using var fixture = Fixture.Create($"crash-{stage}");
            var first = fixture.CreateRequest(1, "release-1");
            var injected = false;
            AssertThrows<InjectedCrash>(() =>
                new PublisherPublicationTransaction(
                    observed =>
                    {
                        if (!injected && observed == stage)
                        {
                            injected = true;
                            throw new InjectedCrash(stage);
                        }
                    },
                    fixture.AuthorityRoot).Publish(first));
            AssertTrue(injected);

            var later = fixture.CreateRequest(2, "release-2");
            var blocked = AssertThrows<InvalidOperationException>(() =>
                new PublisherPublicationTransaction(
                    authorityRoot: fixture.AuthorityRoot).TryRecoverOrReadExact(
                        fixture.CreateProbe(later)));
            AssertTrue(blocked.Message.Contains(
                "rejected before recovery",
                StringComparison.Ordinal));
            AssertFalse(Directory.Exists(later.OutputDirectory));

            var exactRetry = fixture.CreateRequest(1, "release-1");
            var recovered = new PublisherPublicationTransaction(
                authorityRoot: fixture.AuthorityRoot).TryRecoverOrReadExact(
                    fixture.CreateProbe(exactRetry))
                ?? throw new InvalidOperationException("Exact pending recovery was not found.");
            AssertTrue(recovered.IsExactCommittedRetry);
            fixture.AssertExactOutput(recovered.OutputDirectory, sequence: 1);

            var receiptRetry = new PublisherPublicationTransaction(
                authorityRoot: fixture.AuthorityRoot).TryRecoverOrReadExact(
                    fixture.CreateProbe(fixture.CreateRequest(1, "release-1")))
                ?? throw new InvalidOperationException("Exact committed receipt was not found.");
            AssertTrue(receiptRetry.IsExactCommittedRetry);
            fixture.AssertExactOutput(receiptRetry.OutputDirectory, sequence: 1);
        }
        return Task.CompletedTask;
    }

    public static Task LaterCrashWindowsRecoverAcrossPreviousReceiptAsync()
    {
        var stages = new[]
        {
            PublisherPublicationCommitStage.PendingCommitted,
            PublisherPublicationCommitStage.LedgerCommitted,
            PublisherPublicationCommitStage.AnchorCommitted,
            PublisherPublicationCommitStage.OutputFileCommitted,
            PublisherPublicationCommitStage.ManifestCommitted,
            PublisherPublicationCommitStage.ReceiptCommitted,
        };
        foreach (var stage in stages)
        {
            using var fixture = Fixture.Create($"later-crash-{stage}");
            _ = new PublisherPublicationTransaction(
                authorityRoot: fixture.AuthorityRoot).Publish(
                    fixture.CreateRequest(1, "release-1"));

            var second = fixture.CreateRequest(2, "release-2");
            var injected = false;
            AssertThrows<InjectedCrash>(() =>
                new PublisherPublicationTransaction(
                    observed =>
                    {
                        if (!injected && observed == stage)
                        {
                            injected = true;
                            throw new InjectedCrash(stage);
                        }
                    },
                    fixture.AuthorityRoot).Publish(second));
            AssertTrue(injected);

            var blocked = AssertThrows<InvalidOperationException>(() =>
                new PublisherPublicationTransaction(
                    authorityRoot: fixture.AuthorityRoot).TryRecoverOrReadExact(
                        fixture.CreateProbe(fixture.CreateRequest(3, "release-3"))));
            AssertTrue(blocked.Message.Contains(
                "rejected before recovery",
                StringComparison.Ordinal));

            var recovered = new PublisherPublicationTransaction(
                authorityRoot: fixture.AuthorityRoot).TryRecoverOrReadExact(
                    fixture.CreateProbe(fixture.CreateRequest(2, "release-2")))
                ?? throw new InvalidOperationException(
                    "Exact later pending recovery was not found.");
            AssertTrue(recovered.IsExactCommittedRetry);
            fixture.AssertExactOutput(recovered.OutputDirectory, sequence: 2);
            var previous = EnterpriseReleaseSetManifest.Parse(File.ReadAllBytes(Path.Combine(
                fixture.DataRoot,
                "release-1",
                PublisherPublicationTransaction.ManifestFileName)));
            AssertEqual(1L, previous.Sequence);
        }
        return Task.CompletedTask;
    }

    public static Task LateCleanupFailurePreservesSuccessAsync()
    {
        using var fixture = Fixture.Create("late-cleanup");
        var request = fixture.CreateRequest(1, "release-1");
        var pendingPath = PublisherPublicationTransaction.GetAnchorPath(
            request,
            fixture.AuthorityRoot) + ".pending.v2";
        FileStream? cleanupBlocker = null;
        var result = new PublisherPublicationTransaction(
            stage =>
            {
                if (stage == PublisherPublicationCommitStage.ReceiptCommitted)
                {
                    cleanupBlocker = new FileStream(
                        pendingPath,
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.None);
                }
            },
            fixture.AuthorityRoot).Publish(request);
        AssertTrue(cleanupBlocker is not null);
        AssertTrue(File.Exists(pendingPath));
        AssertFalse(result.IsExactCommittedRetry);
        fixture.AssertExactOutput(result.OutputDirectory, sequence: 1);
        cleanupBlocker!.Dispose();

        var retry = new PublisherPublicationTransaction(
            authorityRoot: fixture.AuthorityRoot).TryRecoverOrReadExact(
                fixture.CreateProbe(fixture.CreateRequest(1, "release-1")))
            ?? throw new InvalidOperationException(
                "Committed publication was lost after late cleanup failed.");
        AssertTrue(retry.IsExactCommittedRetry);
        AssertFalse(File.Exists(pendingPath));
        return Task.CompletedTask;
    }

    public static Task ProtectedStateContainsNoPlaintextManifestOrKeyAsync()
    {
        using var fixture = Fixture.Create("protected-state");
        var request = fixture.CreateRequest(1, "release-1");
        AssertThrows<InjectedCrash>(() =>
            new PublisherPublicationTransaction(
                stage =>
                {
                    if (stage == PublisherPublicationCommitStage.PendingCommitted)
                    {
                        throw new InjectedCrash(stage);
                    }
                },
                fixture.AuthorityRoot).Publish(request));
        AssertFalse(Directory.Exists(request.OutputDirectory));
        AssertFalse(File.Exists(request.LedgerPath));
        foreach (var file in Directory.EnumerateFiles(fixture.AuthorityRoot))
        {
            var bytes = File.ReadAllBytes(file);
            AssertFalse(Contains(bytes, request.ManifestBytes));
            AssertFalse(Contains(bytes, fixture.PrivateKeyBytes));
        }
        AssertFalse(typeof(PublisherPublicationRequest).GetProperties()
            .Any(property => property.Name.Contains("PrivateKey", StringComparison.Ordinal)));
        return Task.CompletedTask;
    }

    public static Task ReplayAndSchemaDowngradeFailClosedAsync()
    {
        using (var fixture = Fixture.Create("whole-root-replay"))
        {
            var first = fixture.CreateRequest(1, "release-1");
            _ = new PublisherPublicationTransaction(
                authorityRoot: fixture.AuthorityRoot).Publish(first);
            var oldLedger = File.ReadAllBytes(fixture.LedgerPath);
            _ = new PublisherPublicationTransaction(
                authorityRoot: fixture.AuthorityRoot).Publish(
                    fixture.CreateRequest(2, "release-2"));
            File.WriteAllBytes(fixture.LedgerPath, oldLedger);
            var replay = AssertThrows<InvalidDataException>(() =>
                new PublisherPublicationTransaction(
                    authorityRoot: fixture.AuthorityRoot).Publish(
                        fixture.CreateRequest(2, "release-2")));
            AssertTrue(replay.Message.Contains("replayed", StringComparison.Ordinal));
        }

        using (var fixture = Fixture.Create("schema-downgrade"))
        {
            var request = fixture.CreateRequest(1, "release-1");
            _ = new PublisherPublicationTransaction(
                authorityRoot: fixture.AuthorityRoot).Publish(request);
            var anchorPath = PublisherPublicationTransaction.GetAnchorPath(
                request,
                fixture.AuthorityRoot);
            var protectedBytes = File.ReadAllBytes(anchorPath);
            var entropy = fixture.ComputeAuthorityEntropy();
            var plaintext = ProtectedData.Unprotect(
                protectedBytes,
                entropy,
                DataProtectionScope.CurrentUser);
            try
            {
                var json = Encoding.UTF8.GetString(plaintext);
                json = json.Replace(
                    "\"schemaVersion\": 2",
                    "\"schemaVersion\": 1",
                    StringComparison.Ordinal);
                var downgraded = ProtectedData.Protect(
                    Encoding.UTF8.GetBytes(json),
                    entropy,
                    DataProtectionScope.CurrentUser);
                File.WriteAllBytes(anchorPath, downgraded);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
                CryptographicOperations.ZeroMemory(protectedBytes);
                CryptographicOperations.ZeroMemory(entropy);
            }
            var downgrade = AssertThrows<InvalidDataException>(() =>
                new PublisherPublicationTransaction(
                    authorityRoot: fixture.AuthorityRoot).Publish(
                        fixture.CreateRequest(1, "release-1")));
            AssertTrue(downgrade.Message.Contains("downgraded", StringComparison.Ordinal));
        }
        return Task.CompletedTask;
    }

    public static Task CommittedReadbackDetectsTamperAsync()
    {
        using var fixture = Fixture.Create("readback-tamper");
        var request = fixture.CreateRequest(1, "release-1");
        var committed = new PublisherPublicationTransaction(
            authorityRoot: fixture.AuthorityRoot).Publish(request);
        File.AppendAllText(committed.ManifestPath, " ", Encoding.UTF8);
        var tamper = AssertThrows<InvalidDataException>(() =>
            new PublisherPublicationTransaction(
                authorityRoot: fixture.AuthorityRoot).Publish(
                    fixture.CreateRequest(1, "release-1")));
        AssertTrue(tamper.Message.Contains("size or digest", StringComparison.Ordinal));
        return Task.CompletedTask;
    }

    private static bool Contains(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        if (needle.IsEmpty || needle.Length > haystack.Length)
        {
            return false;
        }
        for (var index = 0; index <= haystack.Length - needle.Length; index++)
        {
            if (haystack.Slice(index, needle.Length).SequenceEqual(needle))
            {
                return true;
            }
        }
        return false;
    }

    private sealed class Fixture : IDisposable
    {
        private readonly ECDsa _signer;
        private readonly IReadOnlyList<ArtifactSource> _artifacts;

        private Fixture(
            string root,
            string dataRoot,
            string authorityRoot,
            ECDsa signer,
            byte[] privateKeyBytes,
            IReadOnlyList<ArtifactSource> artifacts)
        {
            Root = root;
            DataRoot = dataRoot;
            AuthorityRoot = authorityRoot;
            _signer = signer;
            PrivateKeyBytes = privateKeyBytes;
            _artifacts = artifacts;
            LedgerPath = Path.Combine(dataRoot, "publisher-ledger.v2.json");
        }

        public string Root { get; }
        public string DataRoot { get; }
        public string AuthorityRoot { get; }
        public string LedgerPath { get; }
        public byte[] PrivateKeyBytes { get; }

        public static Fixture Create(string name)
        {
            var root = Path.Combine(
                Path.GetTempPath(),
                "ensou-enterprise-publication-transaction-tests",
                $"{name}-{Guid.NewGuid():N}");
            var dataRoot = Path.Combine(root, "data");
            var authorityRoot = Path.Combine(root, "authority");
            var inputs = Path.Combine(dataRoot, "inputs");
            Directory.CreateDirectory(inputs);
            Directory.CreateDirectory(authorityRoot);
            var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var privateKey = signer.ExportPkcs8PrivateKey();
            var artifacts = new[]
            {
                CreateArtifact(inputs, "launcher.zip", "launcher payload"),
                CreateArtifact(inputs, "runtime.zip", "runtime payload"),
                CreateArtifact(inputs, "plugin-policy.zip", "plugin policy payload"),
            };
            return new Fixture(
                root,
                dataRoot,
                authorityRoot,
                signer,
                privateKey,
                artifacts);
        }

        public PublisherPublicationRequest CreateRequest(long sequence, string outputName)
        {
            var parameters = _signer.ExportParameters(includePrivateParameters: false);
            var keyId = "enterprise-release-test-key";
            var publicKey = new EnterpriseReleasePublicKey(
                keyId,
                Base64Url(parameters.Q.X!),
                Base64Url(parameters.Q.Y!));
            var placeholderSignature = new EnterpriseReleaseSignature
            {
                Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
                KeyId = keyId,
                Value = Base64Url(new byte[64]),
            };
            var artifacts = new[]
            {
                ManifestArtifact(
                    EnterpriseReleaseSetContract.LauncherComponent,
                    $"launcher-{sequence}",
                    _artifacts[0],
                    placeholderSignature),
                ManifestArtifact(
                    EnterpriseReleaseSetContract.RuntimeComponent,
                    $"runtime-{sequence}",
                    _artifacts[1],
                    placeholderSignature),
                ManifestArtifact(
                    EnterpriseReleaseSetContract.PluginPolicyComponent,
                    $"plugin-policy-{sequence}",
                    _artifacts[2],
                    placeholderSignature),
            };
            var manifest = new EnterpriseReleaseSetManifest
            {
                SchemaVersion = EnterpriseReleaseSetContract.SchemaVersion,
                Product = EnterpriseReleaseSetContract.Product,
                Environment = EnterpriseReleaseSetContract.DevelopmentE2EEnvironment,
                Channel = EnterpriseReleaseSetContract.LabChannel,
                ReleaseSetId = $"release-set-{sequence}",
                Generation = sequence,
                Sequence = sequence,
                MinAcceptedSequence = 0,
                IssuedAtUtc = DateTimeOffset.UtcNow,
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddDays(1),
                StartupStub = new EnterpriseStartupStubCompatibility
                {
                    MinimumProtocol = 1,
                    MaximumProtocol = 1,
                },
                RevokedReleaseSetIds = [],
                Artifacts = artifacts,
                Signature = placeholderSignature,
            };
            artifacts = artifacts.Select(value => value with
            {
                Signature = Sign(
                    keyId,
                    EnterpriseReleaseCanonicalJson.ArtifactPayload(manifest, value)),
            }).ToArray();
            manifest = manifest with { Artifacts = artifacts };
            manifest = manifest with
            {
                Signature = Sign(
                    keyId,
                    EnterpriseReleaseCanonicalJson.ManifestPayload(manifest)),
            };

            var trust = new EnterpriseReleaseTrustPolicy
            {
                Product = EnterpriseReleaseSetContract.Product,
                Environment = EnterpriseReleaseSetContract.DevelopmentE2EEnvironment,
                ExpectedChannel = EnterpriseReleaseSetContract.LabChannel,
                CurrentStartupStubProtocol = 1,
                ManifestOrigin = new Uri("https://updates.example.test/"),
                ArtifactOrigin = new Uri("https://artifacts.example.test/"),
                TrustedKeys = [publicKey],
            };
            EnterpriseReleaseSetValidator.Verify(manifest, trust, DateTimeOffset.UtcNow);
            var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, JsonOptions);
            var publicKeyBytes = JsonSerializer.SerializeToUtf8Bytes(publicKey, JsonOptions);
            var ledger = new PublisherLedger(
                2,
                manifest.Environment,
                manifest.Channel,
                manifest.Generation,
                manifest.Sequence,
                manifest.MinAcceptedSequence,
                manifest.ReleaseSetId,
                Hash(EnterpriseReleaseCanonicalJson.ManifestPayload(manifest)),
                DateTimeOffset.UtcNow);
            return new PublisherPublicationRequest(
                LedgerPath,
                Path.Combine(DataRoot, outputName),
                ledger,
                Hash(Encoding.UTF8.GetBytes($"config-{sequence}")),
                Hash(Encoding.UTF8.GetBytes("stable-input-set")),
                manifestBytes,
                publicKeyBytes,
                _artifacts.Select(value => new PublisherPublicationSource(
                    value.FileName,
                    value.Path,
                    value.SizeBytes,
                    value.Sha256)).ToArray());
        }

        public byte[] ComputeAuthorityEntropy() => SHA256.HashData(Encoding.UTF8.GetBytes(
            string.Join(
                '|',
                EnterpriseReleaseSetContract.Product,
                EnterpriseReleaseSetContract.DevelopmentE2EEnvironment,
                EnterpriseReleaseSetContract.LabChannel,
                Path.GetFullPath(LedgerPath).ToUpperInvariant(),
                "enterprise-release-publication-dpapi-v2")));

        public PublisherPublicationProbe CreateProbe(PublisherPublicationRequest request) => new(
            request.LedgerPath,
            request.OutputDirectory,
            request.LedgerAfter.Environment,
            request.LedgerAfter.Channel,
            request.LedgerAfter.ReleaseSetId,
            request.LedgerAfter.HighestGeneration,
            request.LedgerAfter.HighestSequence,
            request.LedgerAfter.MinAcceptedSequence,
            request.ConfigSha256,
            request.InputSetSha256,
            request.PublicKeyBytes,
            request.Artifacts);

        public void AssertExactOutput(string outputDirectory, long sequence)
        {
            var paths = Directory.EnumerateFileSystemEntries(outputDirectory).ToArray();
            AssertEqual(5, paths.Length);
            var manifest = EnterpriseReleaseSetManifest.Parse(
                File.ReadAllBytes(Path.Combine(
                    outputDirectory,
                    PublisherPublicationTransaction.ManifestFileName)));
            AssertEqual(sequence, manifest.Sequence);
            foreach (var source in _artifacts)
            {
                var output = Path.Combine(outputDirectory, source.FileName);
                AssertTrue(File.Exists(output));
                AssertEqual(source.Sha256, Hash(File.ReadAllBytes(output)));
            }
            using var ledger = JsonDocument.Parse(File.ReadAllBytes(LedgerPath));
            AssertEqual(
                sequence,
                ledger.RootElement.GetProperty("highestSequence").GetInt64());
        }

        public void Dispose()
        {
            _signer.Dispose();
            CryptographicOperations.ZeroMemory(PrivateKeyBytes);
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }

        private EnterpriseReleaseSignature Sign(string keyId, ReadOnlySpan<byte> payload) => new()
        {
            Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
            KeyId = keyId,
            Value = Base64Url(_signer.SignData(
                payload,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
        };

        private static EnterpriseReleaseArtifact ManifestArtifact(
            string component,
            string releaseId,
            ArtifactSource source,
            EnterpriseReleaseSignature signature) => new()
        {
            Component = component,
            ReleaseId = releaseId,
            Uri = new Uri($"https://artifacts.example.test/{source.FileName}"),
            SizeBytes = source.SizeBytes,
            Sha256 = source.Sha256,
            CompleteTreeSha256 = source.Sha256,
            Signature = signature,
        };

        private static ArtifactSource CreateArtifact(
            string root,
            string fileName,
            string contents)
        {
            var path = Path.Combine(root, fileName);
            File.WriteAllText(path, contents, new UTF8Encoding(false));
            var bytes = File.ReadAllBytes(path);
            return new ArtifactSource(fileName, path, bytes.LongLength, Hash(bytes));
        }
    }

    private sealed record ArtifactSource(
        string FileName,
        string Path,
        long SizeBytes,
        string Sha256);

    private sealed class InjectedCrash(PublisherPublicationCommitStage stage)
        : Exception($"Injected crash after {stage}.");

    private static EnterpriseReleaseSignature Sign(
        ECDsa signer,
        string keyId,
        ReadOnlySpan<byte> payload) => new()
        {
            Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
            KeyId = keyId,
            Value = Base64Url(signer.SignData(
                payload,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
        };

    private static string Base64Url(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Hash(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static TException AssertThrows<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException exception)
        {
            return exception;
        }
        throw new InvalidOperationException(
            $"Expected {typeof(TException).Name} was not thrown.");
    }

    private static void AssertTrue(bool value)
    {
        if (!value)
        {
            throw new InvalidOperationException("Expected true.");
        }
    }

    private static void AssertFalse(bool value) => AssertTrue(!value);

    private static void AssertEqual<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException(
                $"Expected '{expected}', got '{actual}'.");
        }
    }
}
