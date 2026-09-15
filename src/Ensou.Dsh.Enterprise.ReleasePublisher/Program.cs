using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.ReleasePublisher;

internal static class Program
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private static int Main(string[] args)
    {
        if (PublisherRuntimeSourceAdmissionCommand.IsRequested(args))
        {
            return PublisherRuntimeSourceAdmissionCommand.Run(args);
        }
        if (PublisherWindowsPilotEvidenceCommand.IsRequested(args))
        {
            return PublisherWindowsPilotEvidenceCommand.Run(args);
        }
        if (PublisherPluginPromotionJournalCommand.IsRequested(args))
        {
            return PublisherPluginPromotionJournalCommand.Run(args);
        }
        if (PilotReadinessArguments.IsRequested(args))
        {
            return EnterprisePilotReadinessCommand.Run(args);
        }
        if (EnterprisePolicyHandoffCommand.IsRequested(args))
        {
            return EnterprisePolicyHandoffCommand.Run(args);
        }
        try
        {
            var arguments = PublisherArguments.Parse(args);
            Publish(arguments);
            Console.WriteLine("Enterprise release-set published and self-verified.");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"Release publisher failed: {exception.Message}");
            return 1;
        }
    }

    private static void Publish(PublisherArguments arguments)
    {
        PublisherPathGuard.RequireSafeExistingFile(arguments.ConfigPath);
        PublisherPathGuard.RequireSafeExistingFile(arguments.PrivateKeyPath);
        PublisherPathGuard.RequireSafeDestination(arguments.LedgerPath);
        PublisherPathGuard.RequireSafeDestination(arguments.OutputDirectory);
        using var inputs = PublisherInputSnapshot.Capture(arguments, JsonOptions);
        var config = inputs.Config;

        using var signer = LoadPkcs8P256(inputs.ReadPrivateKeyBytes());
        var publicParameters = signer.ExportParameters(includePrivateParameters: false);
        inputs.RuntimeAdmissionTrust.RequireIndependentFrom(config.KeyId, publicParameters);
        inputs.PluginAdmissionTrust?.RequireIndependentFromReleaseKey(
            config.KeyId,
            publicParameters);
        var publicKey = new EnterpriseReleasePublicKey(
            config.KeyId,
            Base64Url(publicParameters.Q.X!),
            Base64Url(publicParameters.Q.Y!));
        var publicKeyBytes = JsonSerializer.SerializeToUtf8Bytes(publicKey, JsonOptions);
        var artifactSources = inputs.Artifacts.Select(value => new PublisherPublicationSource(
            Path.GetFileName(value.Input.Uri.AbsolutePath),
            value.File.StagedPath,
            value.File.Length,
            value.File.Sha256)).ToArray();
        var trust = new EnterpriseReleaseTrustPolicy
        {
            Product = EnterpriseReleaseSetContract.Product,
            Environment = config.Environment,
            ExpectedChannel = config.Channel,
            CurrentStartupStubProtocol =
                EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
            ManifestOrigin = config.ManifestOrigin,
            ArtifactOrigin = config.ArtifactOrigin,
            TrustedKeys = [publicKey],
        };
        string? developmentAuthorityRoot = null;
#if DEBUG
        if (string.Equals(
                config.Environment,
                EnterpriseReleaseSetContract.DevelopmentE2EEnvironment,
                StringComparison.Ordinal))
        {
            developmentAuthorityRoot = Environment.GetEnvironmentVariable(
                "ENSOU_DSH_ENTERPRISE_PUBLISHER_TEST_AUTHORITY_ROOT");
        }
#endif
        var publicationTransaction = new PublisherPublicationTransaction(
            authorityRoot: developmentAuthorityRoot);
        var exactPublication = publicationTransaction.TryRecoverOrReadExact(
            new PublisherPublicationProbe(
                arguments.LedgerPath,
                arguments.OutputDirectory,
                config.Environment,
                config.Channel,
                config.ReleaseSetId,
                config.Generation,
                config.Sequence,
                config.MinAcceptedSequence,
                inputs.ConfigSha256,
                inputs.InputSetSha256,
                publicKeyBytes,
                artifactSources));
        if (exactPublication is not null)
        {
            var committed = EnterpriseReleaseSetManifest.Parse(
                File.ReadAllBytes(exactPublication.ManifestPath));
            EnterpriseReleaseSetValidator.Verify(committed, trust, DateTimeOffset.UtcNow);
            return;
        }
        if (inputs.PluginPromotionJournalTrust is not null)
        {
            inputs.PluginPromotionJournalTrust.RequireIndependentFrom(
                (config.KeyId,
                    Base64Url(publicParameters.Q.X!),
                    Base64Url(publicParameters.Q.Y!),
                    "release signing"));
            var intent = CreatePluginPromotionJournalIntent(config, inputs.Artifacts);
            var pluginPromotion = inputs.Artifacts.Single(value =>
                    value.Input.Component == EnterpriseReleaseSetContract.PluginPolicyComponent)
                .PluginPromotion
                ?? throw new InvalidDataException(
                    "Production plugin promotion journal input snapshot is missing.");
            var journalAuthorization = pluginPromotion.JournalAuthorization
                ?? throw new InvalidDataException(
                    "Production plugin promotion journal authorization input snapshot is missing.");
            _ = PublisherPluginPromotionJournal.Consume(
                journalAuthorization.ReadAllBytes(256 * 1024),
                inputs.PluginPromotionJournalTrust,
                intent,
                DateTimeOffset.UtcNow);
        }
        var unsignedSignature = new EnterpriseReleaseSignature
        {
            Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
            KeyId = config.KeyId,
            Value = Base64Url(new byte[64]),
        };
        var artifacts = inputs.Artifacts.Select(input => new EnterpriseReleaseArtifact
        {
            Component = input.Input.Component,
            ReleaseId = input.Input.ReleaseId,
            Uri = input.Input.Uri,
            SizeBytes = input.File.Length,
            Sha256 = input.File.Sha256,
            CompleteTreeSha256 = input.File.ComputeArchiveTreeSha256(),
            Signature = unsignedSignature,
        }).ToArray();
        var placeholder = new EnterpriseReleaseSetManifest
        {
            SchemaVersion = 2,
            Product = EnterpriseReleaseSetContract.Product,
            Environment = config.Environment,
            Channel = config.Channel,
            ReleaseSetId = config.ReleaseSetId,
            Generation = config.Generation,
            Sequence = config.Sequence,
            MinAcceptedSequence = config.MinAcceptedSequence,
            IssuedAtUtc = DateTimeOffset.UtcNow,
            ExpiresAtUtc = config.ExpiresAtUtc,
            StartupStub = config.StartupStub,
            RevokedReleaseSetIds = config.RevokedReleaseSetIds,
            Artifacts = artifacts,
            Signature = unsignedSignature,
        };
        artifacts = artifacts.Select(artifact => artifact with
        {
            Signature = Sign(
                signer,
                config.KeyId,
                EnterpriseReleaseCanonicalJson.ArtifactPayload(placeholder, artifact)),
        }).ToArray();
        var manifest = placeholder with { Artifacts = artifacts };
        manifest = manifest with
        {
            Signature = Sign(
                signer,
                config.KeyId,
                EnterpriseReleaseCanonicalJson.ManifestPayload(manifest)),
        };

        EnterpriseReleaseSetValidator.Verify(manifest, trust, DateTimeOffset.UtcNow);

        var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, JsonOptions);
        var ledger = new PublisherLedger(
            2,
            config.Environment,
            config.Channel,
            config.Generation,
            config.Sequence,
            config.MinAcceptedSequence,
            config.ReleaseSetId,
            Convert.ToHexStringLower(SHA256.HashData(
                EnterpriseReleaseCanonicalJson.ManifestPayload(manifest))),
            DateTimeOffset.UtcNow);
        var publication = publicationTransaction.Publish(
            new PublisherPublicationRequest(
                arguments.LedgerPath,
                arguments.OutputDirectory,
                ledger,
                inputs.ConfigSha256,
                inputs.InputSetSha256,
                manifestBytes,
                publicKeyBytes,
                artifactSources));
        var persistedManifestBytes = File.ReadAllBytes(publication.ManifestPath);
        var parsed = EnterpriseReleaseSetManifest.Parse(persistedManifestBytes);
        EnterpriseReleaseSetValidator.Verify(parsed, trust, DateTimeOffset.UtcNow);
    }

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

    internal static PublisherPluginPromotionJournalIntent CreatePluginPromotionJournalIntent(
        PublisherConfig config,
        IReadOnlyList<PublisherSnapshotArtifact> artifacts)
    {
        var launcher = artifacts.Single(value =>
            value.Input.Component == EnterpriseReleaseSetContract.LauncherComponent);
        var runtime = artifacts.Single(value =>
            value.Input.Component == EnterpriseReleaseSetContract.RuntimeComponent);
        var plugin = artifacts.Single(value =>
            value.Input.Component == EnterpriseReleaseSetContract.PluginPolicyComponent);
        var promotion = plugin.PluginPromotion
            ?? throw new InvalidDataException(
                "Production plugin promotion snapshot is missing.");
        var pluginMetadata = plugin.PolicyMetadata
            ?? throw new InvalidDataException(
                "Production plugin metadata snapshot is missing.");
        var runtimeMetadata = runtime.SourceRuntimeMetadata
            ?? throw new InvalidDataException(
                "Production runtime metadata snapshot is missing.");
        var organizationAdmission = PublisherPluginOrganizationAdmissionReceipt.Parse(
            promotion.OrganizationAdmissionReceipt.ReadAllBytes(1024 * 1024));

        return new PublisherPluginPromotionJournalIntent(
            config.Environment,
            config.Channel,
            config.ReleaseSetId,
            config.KeyId,
            config.Generation,
            config.Sequence,
            config.MinAcceptedSequence,
            CreateArtifactIdentity(launcher),
            CreateArtifactIdentity(runtime),
            CreateArtifactIdentity(plugin),
            organizationAdmission.PolicyId,
            organizationAdmission.Generation,
            pluginMetadata.Sha256,
            organizationAdmission.RawPolicySha256,
            promotion.Handoff.Sha256,
            promotion.CompatibilityReceipt.Sha256,
            promotion.Reservation.Sha256,
            runtimeMetadata.Sha256,
            plugin.Input.PluginGenerationLedgerNamespace
                ?? throw new InvalidDataException(
                    "Production plugin generation ledger namespace is missing."),
            organizationAdmission.GenerationLedgerPathSha256,
            promotion.Ledger.Sha256,
            promotion.OrganizationAdmissionReceipt.Sha256);
    }

    private static PublisherPluginPromotionArtifactIdentity CreateArtifactIdentity(
        PublisherSnapshotArtifact artifact) => new(
            artifact.Input.Component,
            artifact.Input.ReleaseId,
            artifact.Input.Uri.AbsoluteUri,
            artifact.File.Length,
            artifact.File.Sha256,
            artifact.File.ComputeArchiveTreeSha256());

    private static ECDsa LoadPkcs8P256(byte[] bytes)
    {
        var signer = ECDsa.Create();
        try
        {
            if (bytes.AsSpan().StartsWith("-----BEGIN PRIVATE KEY-----"u8))
            {
                var pem = System.Text.Encoding.ASCII.GetChars(bytes);
                try
                {
                    signer.ImportFromPem(pem);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(
                        System.Runtime.InteropServices.MemoryMarshal.AsBytes(pem.AsSpan()));
                }
            }
            else
            {
                signer.ImportPkcs8PrivateKey(bytes, out var consumed);
                if (consumed != bytes.Length)
                {
                    throw new InvalidDataException("PKCS8 key file has trailing data.");
                }
            }
            var parameters = signer.ExportParameters(includePrivateParameters: false);
            if (parameters.Q.X?.Length != 32 || parameters.Q.Y?.Length != 32)
            {
                throw new InvalidDataException("Publisher key must use P-256.");
            }
            return signer;
        }
        catch
        {
            signer.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static string Base64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

internal static class PublisherPluginPromotionJournalCommand
{
    private const string InitializeCommand = "--initialize-plugin-promotion-journal";
    private const string ChallengeCommand = "--plugin-promotion-journal-challenge";
    private const string IntentCommand = "--plugin-promotion-journal-intent";
    private static readonly JsonSerializerOptions OutputJson = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public static bool IsRequested(string[] args) => args.Length > 0
        && args[0] is InitializeCommand or ChallengeCommand or IntentCommand;

    public static int Run(string[] args)
    {
        try
        {
            if (args.Length > 0 && args[0] == IntentCommand)
            {
                return WriteIntent(args);
            }
            if (args.Length != 1)
            {
                throw new ArgumentException(
                    $"Usage: {InitializeCommand} | {ChallengeCommand} | {IntentCommand} --config <absolute-json>");
            }
            var trust = PublisherPluginPromotionJournalTrustResolver.ResolveProduction();
            var state = args[0] switch
            {
                InitializeCommand => PublisherPluginPromotionJournal.Initialize(trust),
                ChallengeCommand => PublisherPluginPromotionJournal.ReadChallenge(trust),
                _ => throw new ArgumentException("Unknown plugin promotion journal command."),
            };
            var challenge = PublisherPluginPromotionJournalChallenge.Create(
                state,
                DateTimeOffset.UtcNow);
            Console.WriteLine(JsonSerializer.Serialize(challenge, OutputJson));
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(
                $"Plugin promotion journal command failed: {exception.Message}");
            return 1;
        }
    }

    private static int WriteIntent(string[] args)
    {
        if (args.Length != 3 || !string.Equals(args[1], "--config", StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(args[2]) || !Path.IsPathFullyQualified(args[2]))
        {
            throw new ArgumentException(
                $"Usage: {IntentCommand} --config <absolute-json>");
        }

        PublisherPathGuard.RequireSafeExistingFile(args[2]);
        using var inputs = PublisherInputSnapshot.CaptureIntent(args[2], OutputJson);
        if (!string.Equals(
                inputs.Config.Environment,
                EnterpriseReleaseSetContract.ProductionEnvironment,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Plugin promotion journal intent export requires a production publisher config.");
        }
        if (inputs.PluginPromotionJournalTrust is null)
        {
            throw new InvalidDataException(
                "Production plugin promotion journal trust is missing from the verified input snapshot.");
        }

        // This path only reads locked input snapshots. It must not initialize,
        // read, or consume the CurrentUser journal, and it has no private-key
        // argument by design.
        var intent = Program.CreatePluginPromotionJournalIntent(
            inputs.Config,
            inputs.Artifacts);
        _ = intent.CanonicalPayload();
        Console.WriteLine(JsonSerializer.Serialize(intent, OutputJson));
        return 0;
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginPromotionJournalChallenge
{
    public required int SchemaVersion { get; init; }
    public required string ChallengeType { get; init; }
    public required string JournalInstanceId { get; init; }
    public required long ExpectedStateRevision { get; init; }
    public required string ExpectedHeadSha256 { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset ExpiresAtUtc { get; init; }

    public static PublisherPluginPromotionJournalChallenge Create(
        PublisherPluginPromotionJournalInitialization state,
        DateTimeOffset nowUtc)
    {
        if (nowUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException(
                "Plugin promotion journal challenge clock must be UTC.");
        }
        return new PublisherPluginPromotionJournalChallenge
        {
            SchemaVersion = 1,
            ChallengeType = "managed-plugin-promotion-journal-challenge",
            JournalInstanceId = state.JournalInstanceId,
            ExpectedStateRevision = state.StateRevision,
            ExpectedHeadSha256 = state.HeadSha256,
            IssuedAtUtc = nowUtc,
            ExpiresAtUtc = nowUtc.AddMinutes(15),
        };
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherArtifact
{
    public required string Component { get; init; }
    public required string ReleaseId { get; init; }
    public required string FilePath { get; init; }
    public required Uri Uri { get; init; }
    public string? PolicyMetadataPath { get; init; }
    public string? PluginPromotionHandoffPath { get; init; }
    public string? PluginHarnessCompatibilityReceiptPath { get; init; }
    public string? PluginGenerationReservationPath { get; init; }
    public string? PluginGenerationLedgerPath { get; init; }
    public string? PluginGenerationLedgerNamespace { get; init; }
    public string? PluginOrganizationAdmissionReceiptPath { get; init; }
    public string? PluginPromotionJournalAuthorizationPath { get; init; }
    public string? SourceRuntimeMetadataPath { get; init; }
    public string? OrganizationAdmissionReceiptPath { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherConfig
{
    public required string Environment { get; init; }
    public required string Channel { get; init; }
    public required string ReleaseSetId { get; init; }
    public required string KeyId { get; init; }
    public required long Generation { get; init; }
    public required long Sequence { get; init; }
    public required long MinAcceptedSequence { get; init; }
    public required DateTimeOffset ExpiresAtUtc { get; init; }
    public required EnterpriseStartupStubCompatibility StartupStub { get; init; }
    public required Uri ManifestOrigin { get; init; }
    public required Uri ArtifactOrigin { get; init; }
    public required IReadOnlyList<string> RevokedReleaseSetIds { get; init; }
    public required IReadOnlyList<PublisherArtifact> Artifacts { get; init; }
    public PublisherRuntimeAdmissionTrust? DevelopmentRuntimeAdmissionTrust { get; init; }

    public PublisherAdmissionTrusts Validate(
        IReadOnlyList<PublisherSnapshotArtifact> snapshotArtifacts)
    {
        ValidateStructure();
        if (snapshotArtifacts.Count != Artifacts.Count)
        {
            throw new InvalidDataException("Publisher input snapshot is incomplete.");
        }
        foreach (var artifact in snapshotArtifacts)
        {
            PublisherPathGuard.RequireSafeExistingFile(artifact.Input.FilePath);
        }
        var launcher = snapshotArtifacts.Single(value =>
            value.Input.Component == EnterpriseReleaseSetContract.LauncherComponent);
        var runtime = snapshotArtifacts.Single(value =>
            value.Input.Component == EnterpriseReleaseSetContract.RuntimeComponent);
        var launcherReleaseId = launcher.Input.ReleaseId;
        var runtimeReleaseId = runtime.Input.ReleaseId;
        var runtimeAdmissionTrust = PublisherRuntimeAdmissionTrustResolver.Resolve(this);
        PublisherPluginAdmissionTrust? pluginAdmissionTrust = null;
        PublisherPluginCompatibilityRunnerTrust? pluginCompatibilityRunnerTrust = null;
        PublisherPluginPromotionJournalTrust? pluginPromotionJournalTrust = null;
        if (Environment == EnterpriseReleaseSetContract.ProductionEnvironment
            && snapshotArtifacts.Any(value =>
                value.Input.Component == EnterpriseReleaseSetContract.PluginPolicyComponent))
        {
            pluginAdmissionTrust = PublisherPluginAdmissionTrustResolver.ResolveProduction();
            pluginCompatibilityRunnerTrust =
                PublisherPluginCompatibilityRunnerTrustResolver.ResolveProduction();
            pluginPromotionJournalTrust =
                PublisherPluginPromotionJournalTrustResolver.ResolveProduction();
            pluginAdmissionTrust.RequireIndependentFrom(
                runtimeAdmissionTrust,
                PublisherBrandAuthorizationTrustResolver.ResolveProduction(),
                PublisherLeaseVerificationTrustResolver.ResolveProduction(),
                KeyId);
            var brandTrust = PublisherBrandAuthorizationTrustResolver.ResolveProduction();
            var leaseTrust = PublisherLeaseVerificationTrustResolver.ResolveProduction();
            var localDataTrust =
                PublisherLocalDataCompatibilityCertificationTrustResolver.ResolveProduction();
            pluginPromotionJournalTrust.RequireIndependentFrom(
                (runtimeAdmissionTrust.KeyId, runtimeAdmissionTrust.X, runtimeAdmissionTrust.Y,
                    "runtime admission"),
                (pluginAdmissionTrust.KeyId, pluginAdmissionTrust.X, pluginAdmissionTrust.Y,
                    "plugin admission"),
                (brandTrust.KeyId, brandTrust.X, brandTrust.Y, "brand authorization"),
                (leaseTrust.KeyId, leaseTrust.X, leaseTrust.Y, "lease"),
                (localDataTrust.KeyId, localDataTrust.X, localDataTrust.Y,
                    "local-data certification"));
        }
        foreach (var artifact in snapshotArtifacts)
        {
            if (artifact.Input.Component == EnterpriseReleaseSetContract.PluginPolicyComponent)
            {
                PublisherPathGuard.RequireSafeExistingFile(artifact.Input.PolicyMetadataPath!);
                var inspection = EnterprisePluginPolicyArchiveValidator.Validate(
                    artifact.Input.FilePath,
                    launcherReleaseId,
                    runtimeReleaseId);
                var policyMetadata = PublisherPluginPolicyMetadata.Validate(
                    artifact.Input.PolicyMetadataPath!,
                    artifact.Input.FilePath,
                    inspection);
                if (Environment == EnterpriseReleaseSetContract.ProductionEnvironment)
                {
                    PublisherPluginPromotionAdmission.ValidateProduction(
                        artifact,
                        inspection,
                        policyMetadata,
                        launcher,
                        runtime,
                        pluginAdmissionTrust
                            ?? throw new InvalidDataException(
                                "Production plugin-admission trust is missing."),
                        pluginCompatibilityRunnerTrust
                            ?? throw new InvalidDataException(
                                "Production plugin compatibility runner trust is missing."),
                        DateTimeOffset.UtcNow);
                }
            }
        }
        PublisherRuntimeAdmissionValidator.Validate(runtime, runtimeAdmissionTrust);
        return new PublisherAdmissionTrusts(
            runtimeAdmissionTrust,
            pluginAdmissionTrust,
            pluginCompatibilityRunnerTrust,
            pluginPromotionJournalTrust);
    }

    public void ValidateStructure()
    {
        if (Environment is not EnterpriseReleaseSetContract.ProductionEnvironment
            and not EnterpriseReleaseSetContract.DevelopmentE2EEnvironment
            || Generation <= 0
            || Sequence <= 0
            || MinAcceptedSequence < 0
            || MinAcceptedSequence > Sequence
            || ExpiresAtUtc.Offset != TimeSpan.Zero
            || ExpiresAtUtc <= DateTimeOffset.UtcNow.AddMinutes(5)
            || ExpiresAtUtc > DateTimeOffset.UtcNow.AddDays(31)
            || StartupStub is null)
        {
            throw new InvalidDataException("Publisher ordering or expiry is invalid.");
        }
        var inputTrust = new EnterpriseReleaseTrustPolicy
        {
            Product = EnterpriseReleaseSetContract.Product,
            Environment = Environment,
            ExpectedChannel = Channel,
            CurrentStartupStubProtocol =
                EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
            ManifestOrigin = ManifestOrigin,
            ArtifactOrigin = ArtifactOrigin,
            TrustedKeys = [new EnterpriseReleasePublicKey(KeyId, Base64Url(new byte[32]), Base64Url(new byte[32]))],
        };
        inputTrust.Validate();
        EnterpriseReleaseSetValidator.ValidateStartupStubCompatibility(
            StartupStub,
            inputTrust.CurrentStartupStubProtocol);
        if (Artifacts is null
            || Artifacts.Count != 3
            || Artifacts.Any(value => value is null
                || value.Uri is null
                || !value.Uri.IsAbsoluteUri)
            || Artifacts.Select(value => value.Component).Distinct(StringComparer.Ordinal).Count()
                != Artifacts.Count
            || !Artifacts.Any(value => value.Component == EnterpriseReleaseSetContract.LauncherComponent)
            || !Artifacts.Any(value => value.Component == EnterpriseReleaseSetContract.RuntimeComponent)
            || !Artifacts.Any(value => value.Component == EnterpriseReleaseSetContract.PluginPolicyComponent)
            || Artifacts.Select(value => value.Uri.AbsoluteUri)
                .Distinct(StringComparer.Ordinal).Count() != Artifacts.Count
            || Artifacts.Select(value => Path.GetFileName(value.Uri.AbsolutePath))
                .Distinct(StringComparer.OrdinalIgnoreCase).Count() != Artifacts.Count)
        {
            throw new InvalidDataException("Publisher artifact set is invalid.");
        }
        if (Environment == EnterpriseReleaseSetContract.ProductionEnvironment)
        {
            if (DevelopmentRuntimeAdmissionTrust is not null)
            {
                throw new InvalidDataException(
                    "Production runtime-admission trust must not come from publisher config.");
            }
        }
        foreach (var artifact in Artifacts)
        {
            if (artifact is null
                || string.IsNullOrWhiteSpace(artifact.FilePath)
                || !Path.IsPathFullyQualified(artifact.FilePath))
            {
                throw new InvalidDataException("Publisher artifact path must be absolute.");
            }

            var inputFileName = Path.GetFileName(artifact.FilePath);
            var outputFileName = Path.GetFileName(artifact.Uri.AbsolutePath);
            PublisherPathGuard.RequireSafeArtifactFileName(
                inputFileName,
                "Publisher artifact input filename");
            PublisherPathGuard.RequireSafeArtifactFileName(
                outputFileName,
                "Publisher artifact URI filename");
            if (!string.Equals(inputFileName, outputFileName, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Publisher artifact filePath basename must match URI basename exactly.");
            }
        }
        foreach (var artifact in Artifacts)
        {
            if (artifact.Component == EnterpriseReleaseSetContract.PluginPolicyComponent)
            {
                if (string.IsNullOrWhiteSpace(artifact.PolicyMetadataPath))
                {
                    throw new InvalidDataException(
                        "Plugin-policy publisher input requires policyMetadataPath.");
                }
                if (!Path.IsPathFullyQualified(artifact.PolicyMetadataPath))
                {
                    throw new InvalidDataException(
                        "Plugin-policy metadata path must be absolute.");
                }
                if (Environment == EnterpriseReleaseSetContract.ProductionEnvironment
                    && new[]
                    {
                        artifact.PluginPromotionHandoffPath,
                        artifact.PluginHarnessCompatibilityReceiptPath,
                        artifact.PluginGenerationReservationPath,
                        artifact.PluginGenerationLedgerPath,
                        artifact.PluginOrganizationAdmissionReceiptPath,
                        artifact.PluginPromotionJournalAuthorizationPath,
                    }.Any(value => string.IsNullOrWhiteSpace(value)
                        || !Path.IsPathFullyQualified(value!)))
                {
                    throw new InvalidDataException(
                        "Production plugin-policy input requires absolute handoff, compatibility receipt, reservation, live ledger, organization admission receipt, and promotion journal authorization paths.");
                }
                if (Environment == EnterpriseReleaseSetContract.ProductionEnvironment)
                {
                    ValidatePluginGenerationLedgerNamespace(
                        artifact.PluginGenerationLedgerNamespace);
                }
                if (Environment == EnterpriseReleaseSetContract.DevelopmentE2EEnvironment
                    && (artifact.PluginPromotionHandoffPath is not null
                        || artifact.PluginHarnessCompatibilityReceiptPath is not null
                        || artifact.PluginGenerationReservationPath is not null
                        || artifact.PluginGenerationLedgerPath is not null
                        || artifact.PluginGenerationLedgerNamespace is not null
                        || artifact.PluginOrganizationAdmissionReceiptPath is not null
                        || artifact.PluginPromotionJournalAuthorizationPath is not null))
                {
                    throw new InvalidDataException(
                        "Development-E2E plugin-policy input must not consume a production promotion handoff.");
                }
            }
            else if (artifact.PolicyMetadataPath is not null
                || artifact.PluginPromotionHandoffPath is not null
                || artifact.PluginHarnessCompatibilityReceiptPath is not null
                || artifact.PluginGenerationReservationPath is not null
                || artifact.PluginGenerationLedgerPath is not null
                || artifact.PluginGenerationLedgerNamespace is not null
                || artifact.PluginOrganizationAdmissionReceiptPath is not null
                || artifact.PluginPromotionJournalAuthorizationPath is not null)
            {
                throw new InvalidDataException(
                    "Plugin-policy admission inputs are allowed only for the plugin-policy artifact.");
            }

            if (artifact.Component == EnterpriseReleaseSetContract.RuntimeComponent)
            {
                if (string.IsNullOrWhiteSpace(artifact.SourceRuntimeMetadataPath)
                    || string.IsNullOrWhiteSpace(artifact.OrganizationAdmissionReceiptPath)
                    || !Path.IsPathFullyQualified(artifact.SourceRuntimeMetadataPath)
                    || !Path.IsPathFullyQualified(artifact.OrganizationAdmissionReceiptPath))
                {
                    throw new InvalidDataException(
                        "Runtime publisher input requires absolute sourceRuntimeMetadataPath and organizationAdmissionReceiptPath.");
                }
            }
            else if (artifact.SourceRuntimeMetadataPath is not null
                || artifact.OrganizationAdmissionReceiptPath is not null)
            {
                throw new InvalidDataException(
                    "Runtime admission inputs are allowed only for the runtime artifact.");
            }
        }

        if (Environment == EnterpriseReleaseSetContract.DevelopmentE2EEnvironment)
        {
            (DevelopmentRuntimeAdmissionTrust
                ?? throw new InvalidDataException(
                    "Development-E2E publisher config requires isolated runtime-admission trust."))
                .Validate();
        }
    }

    private static void ValidatePluginGenerationLedgerNamespace(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > 128
            || !char.IsAsciiLetterOrDigit(value[0])
            || value.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '.' and not '_' and not '+' and not '-'))
        {
            throw new InvalidDataException("Plugin generation ledger namespace is invalid.");
        }
    }

    private static string Base64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

internal sealed record PublisherAdmissionTrusts(
    PublisherRuntimeAdmissionTrust Runtime,
    PublisherPluginAdmissionTrust? Plugin,
    PublisherPluginCompatibilityRunnerTrust? PluginCompatibilityRunner,
    PublisherPluginPromotionJournalTrust? PluginPromotionJournal);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginPolicyMetadata
{
    public required int SchemaVersion { get; init; }
    public required string SigningStatus { get; init; }
    public required PublisherPluginPolicyBuilder Builder { get; init; }
    public required PublisherPluginPolicyIdentity Policy { get; init; }
    public required PublisherPluginPolicyCompatibility Compatibility { get; init; }
    public required IReadOnlyList<PublisherPluginPolicyInput> Inputs { get; init; }
    public required PublisherPluginPolicyArtifact Artifact { get; init; }

    public static PublisherPluginPolicyMetadata Validate(
        string metadataPath,
        string archivePath,
        EnterprisePluginPolicyArchiveInspection inspection)
    {
        if (!Path.IsPathFullyQualified(metadataPath)
            || !File.Exists(metadataPath)
            || (File.GetAttributes(metadataPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Plugin-policy metadata must be an existing absolute regular file.");
        }
        var bytes = File.ReadAllBytes(metadataPath);
        if (bytes.Length is <= 0 or > 4 * 1024 * 1024)
        {
            throw new InvalidDataException("Plugin-policy metadata size is invalid.");
        }
        try
        {
            using var document = JsonDocument.Parse(
                bytes,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 32,
                });
            RequireNoDuplicateMembers(document.RootElement);
            var metadata = JsonSerializer.Deserialize<PublisherPluginPolicyMetadata>(
                bytes,
                new JsonSerializerOptions(JsonSerializerDefaults.Web)
                {
                    PropertyNameCaseInsensitive = false,
                    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
                }) ?? throw new InvalidDataException("Plugin-policy metadata is empty.");
            metadata.RequireExact(archivePath, inspection);
            return metadata;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Plugin-policy metadata is not the exact artifact contract.",
                exception);
        }
    }

    private void RequireExact(
        string archivePath,
        EnterprisePluginPolicyArchiveInspection inspection)
    {
        if (SchemaVersion != 1
            || !string.Equals(SigningStatus, "UNSIGNED_CANDIDATE", StringComparison.Ordinal)
            || Builder is null
            || !string.Equals(Builder.ZipMode, "store", StringComparison.Ordinal)
            || !IsLowercaseSha256(Builder.ScriptSha256)
            || Policy is null
            || !string.Equals(Policy.PolicyId, inspection.PolicyId, StringComparison.Ordinal)
            || Policy.Generation != inspection.Generation
            || !string.Equals(
                Policy.FileName,
                EnterprisePluginPolicyContract.PolicyFileName,
                StringComparison.Ordinal)
            || Policy.SizeBytes != inspection.PolicySizeBytes
            || !string.Equals(Policy.Sha256, inspection.PolicySha256, StringComparison.Ordinal)
            || Policy.Critical != inspection.Critical
            || Policy.Revoked
            || Compatibility is null
            || !Compatibility.LauncherReleaseIds.SequenceEqual(
                inspection.LauncherReleaseIds,
                StringComparer.Ordinal)
            || !Compatibility.RuntimeReleaseIds.SequenceEqual(
                inspection.RuntimeReleaseIds,
                StringComparer.Ordinal)
            || Artifact is null
            || !string.Equals(
                Artifact.FileName,
                Path.GetFileName(archivePath),
                StringComparison.Ordinal)
            || Artifact.SizeBytes != inspection.ArchiveSizeBytes
            || !string.Equals(Artifact.Sha256, inspection.ArchiveSha256, StringComparison.Ordinal)
            || Inputs is null
            || Inputs.Count is <= 0 or > 256
            || Inputs.Select(value => value.Id).Distinct(StringComparer.Ordinal).Count()
                != Inputs.Count)
        {
            throw new InvalidDataException(
                "Plugin-policy metadata does not match the validated archive bytes.");
        }
        foreach (var input in Inputs)
        {
            input.Validate();
        }
    }

    private static void RequireNoDuplicateMembers(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidDataException(
                        "Plugin-policy metadata contains duplicate JSON members.");
                }
                RequireNoDuplicateMembers(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                RequireNoDuplicateMembers(item);
            }
        }
    }

    internal static bool IsLowercaseSha256(string? value) =>
        value is { Length: 64 }
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    internal static bool IsGitObjectId(string? value) =>
        value is { Length: 40 }
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    internal static void ValidateMetadataFile(string? fileName, long sizeBytes, string? sha256)
    {
        if (string.IsNullOrWhiteSpace(fileName)
            || fileName != Path.GetFileName(fileName)
            || sizeBytes <= 0
            || !IsLowercaseSha256(sha256))
        {
            throw new InvalidDataException("Plugin-policy input metadata is invalid.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginPolicyBuilder
{
    public required string ZipMode { get; init; }
    public required string ScriptSha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginPolicyIdentity
{
    public required string PolicyId { get; init; }
    public required long Generation { get; init; }
    public required string FileName { get; init; }
    public required long SizeBytes { get; init; }
    public required string Sha256 { get; init; }
    public required bool Critical { get; init; }
    public required bool Revoked { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginPolicyCompatibility
{
    public required IReadOnlyList<string> LauncherReleaseIds { get; init; }
    public required IReadOnlyList<string> RuntimeReleaseIds { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginPolicyInput
{
    public required string Kind { get; init; }
    public required string Id { get; init; }
    public required string Version { get; init; }
    public required PublisherPluginPolicyInputFile Artifact { get; init; }
    public required PublisherPluginPolicyInputFile Metadata { get; init; }
    public required PublisherPluginPolicySource Source { get; init; }

    public void Validate()
    {
        if (!string.Equals(Kind, "skill", StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(Id)
            || string.IsNullOrWhiteSpace(Version)
            || Artifact is null
            || Metadata is null
            || Source is null
            || !PublisherPluginPolicyMetadata.IsGitObjectId(Source.Commit)
            || !PublisherPluginPolicyMetadata.IsGitObjectId(Source.Tree)
            || !PublisherPluginPolicyMetadata.IsGitObjectId(Source.BuilderBlob))
        {
            throw new InvalidDataException("Plugin-policy input provenance is invalid.");
        }
        PublisherPluginPolicyMetadata.ValidateMetadataFile(
            Artifact.FileName,
            Artifact.SizeBytes,
            Artifact.Sha256);
        PublisherPluginPolicyMetadata.ValidateMetadataFile(
            Metadata.FileName,
            Metadata.SizeBytes,
            Metadata.Sha256);
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginPolicyInputFile
{
    public required string FileName { get; init; }
    public required long SizeBytes { get; init; }
    public required string Sha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginPolicySource
{
    public required string Commit { get; init; }
    public required string Tree { get; init; }
    public required string BuilderBlob { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginPolicyArtifact
{
    public required string FileName { get; init; }
    public required long SizeBytes { get; init; }
    public required string Sha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherLedger(
    int SchemaVersion,
    string Environment,
    string Channel,
    long HighestGeneration,
    long HighestSequence,
    long MinAcceptedSequence,
    string ReleaseSetId,
    string ManifestPayloadSha256,
    DateTimeOffset PublishedAtUtc)
{
    public void Validate(PublisherConfig config)
    {
        if (SchemaVersion != 2
            || !string.Equals(Environment, config.Environment, StringComparison.Ordinal)
            || !string.Equals(Channel, config.Channel, StringComparison.Ordinal)
            || HighestGeneration <= 0
            || HighestSequence <= 0
            || MinAcceptedSequence < 0
            || MinAcceptedSequence > HighestSequence
            || ManifestPayloadSha256.Length != 64)
        {
            throw new InvalidDataException("Publisher ledger is invalid or belongs to another feed.");
        }
    }
}

internal sealed record PublisherArguments(
    string ConfigPath,
    string PrivateKeyPath,
    string LedgerPath,
    string OutputDirectory)
{
    public static PublisherArguments Parse(string[] args)
    {
        if (args.Length != 8)
        {
            throw new ArgumentException(
                "Usage: --config <json> --private-key-file <pkcs8> --ledger <json> --output <new-dir>");
        }
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < args.Length; index += 2)
        {
            if (!values.TryAdd(args[index], args[index + 1]))
            {
                throw new ArgumentException("Publisher argument was repeated.");
            }
        }
        return new PublisherArguments(
            Require(values, "--config", requireFile: true),
            Require(values, "--private-key-file", requireFile: true),
            Path.GetFullPath(Require(values, "--ledger", requireFile: false)),
            Path.GetFullPath(Require(values, "--output", requireFile: false)));
    }

    private static string Require(
        IReadOnlyDictionary<string, string> values,
        string name,
        bool requireFile)
    {
        if (!values.TryGetValue(name, out var value) || string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"Publisher requires {name}.");
        }
        var full = Path.GetFullPath(value);
        if (requireFile && !File.Exists(full))
        {
            throw new FileNotFoundException($"Publisher input for {name} was not found.", full);
        }
        if (requireFile)
        {
            PublisherPathGuard.RequireSafeExistingFile(full);
        }
        else
        {
            PublisherPathGuard.RequireSafeDestination(full);
        }
        return full;
    }
}

internal static class PublisherPathGuard
{
    public static void RequireSafeArtifactFileName(string? fileName, string field)
    {
        if (string.IsNullOrWhiteSpace(fileName)
            || fileName is "." or ".."
            || fileName != Path.GetFileName(fileName)
            || fileName.Any(char.IsControl)
            || fileName.IndexOfAny(['\\', '/', ':', '*', '?', '"', '<', '>', '|']) >= 0
            || fileName.EndsWith(' ')
            || fileName.EndsWith('.'))
        {
            throw new InvalidDataException($"{field} is not a safe regular filename.");
        }
    }

    public static void RequireSafeExistingFile(string path)
    {
        var full = Path.GetFullPath(path);
        if (!Path.IsPathFullyQualified(path)
            || !File.Exists(full)
            || (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Publisher input file is missing, relative, or linked.");
        }
        RequireSafeExistingAncestors(Path.GetDirectoryName(full)!);
    }

    public static void RequireSafeDestination(string path)
    {
        var full = Path.GetFullPath(path);
        if (!Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException("Publisher destination must be absolute.");
        }
        if (File.Exists(full) || Directory.Exists(full))
        {
            if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("Publisher destination may not be a filesystem link.");
            }
        }
        var current = Directory.Exists(full) ? full : Path.GetDirectoryName(full)!;
        while (!Directory.Exists(current))
        {
            current = Path.GetDirectoryName(current)
                ?? throw new InvalidDataException("Publisher destination has no existing ancestor.");
        }
        RequireSafeExistingAncestors(current);
    }

    public static void RequireSafeExistingDirectory(string path)
    {
        var full = Path.GetFullPath(path);
        if (!Path.IsPathFullyQualified(path)
            || !Directory.Exists(full)
            || (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Publisher directory is missing, relative, or linked.");
        }
        RequireSafeExistingAncestors(full);
    }

    private static void RequireSafeExistingAncestors(string directory)
    {
        var current = new DirectoryInfo(Path.GetFullPath(directory));
        while (current is not null)
        {
            if (current.Exists
                && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Publisher paths may not cross filesystem links.");
            }
            current = current.Parent;
        }
    }
}
