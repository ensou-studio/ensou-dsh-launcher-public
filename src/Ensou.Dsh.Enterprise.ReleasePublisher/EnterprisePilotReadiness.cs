using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.ReleasePublisher;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PilotReadinessPublicKey
{
    public required string KeyId { get; init; }
    public required string X { get; init; }
    public required string Y { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PilotStartupUpdateContract
{
    public required bool CheckOnEveryStartup { get; init; }
    public required bool AtomicReleaseSetActivation { get; init; }
    public required bool BootstrapHealthRollback { get; init; }
    public required int MaximumOfflineGraceHours { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PilotLocalDataCompatibilityEvidenceInput
{
    public required string FromUpstreamTag { get; init; }
    public required string ToUpstreamTag { get; init; }
    public required string SourceRuntimeArchiveSha256 { get; init; }
    public required string TargetRuntimeArchiveSha256 { get; init; }
    public required string ReportPath { get; init; }
    public required string ReportSha256 { get; init; }
    public required PilotLocalDataCompatibilityCertificationInput Certification { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PilotLocalDataCompatibilityEvidenceReport
{
    public const string CurrentEvidenceType =
        "ensou-dsh-enterprise-local-data-compatibility";

    public required int SchemaVersion { get; init; }
    public required string EvidenceType { get; init; }
    public required string Decision { get; init; }
    public required DateTimeOffset StartedUtc { get; init; }
    public required DateTimeOffset CompletedUtc { get; init; }
    public required string FromUpstreamTag { get; init; }
    public required string ToUpstreamTag { get; init; }
    public required string SourceRuntimeArchiveSha256 { get; init; }
    public required string TargetRuntimeArchiveSha256 { get; init; }
    public required PilotLocalDataEvidenceFile TestRunner { get; init; }
    public required PilotLocalDataEvidenceFile HistoricalFixture { get; init; }
    public required PilotLocalDataEvidenceFile PreUpgradeBackup { get; init; }
    public required PilotLocalDataEvidenceFile ForwardResult { get; init; }
    public required PilotLocalDataEvidenceFile RollbackResult { get; init; }
    public required PilotLocalDataEvidenceFile Transcript { get; init; }
    public required PilotLocalDataApiLaneEvidence ApiLanes { get; init; }
    public required IReadOnlyList<PilotLocalDataEvidenceFile> Artifacts { get; init; }
    public required IReadOnlyDictionary<string, string> Coverage { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PilotLocalDataEvidenceFile
{
    public required string Path { get; init; }
    public required long Bytes { get; init; }
    public required string Sha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PilotLocalDataApiLaneEvidence
{
    public required PilotLocalDataEvidenceFile SourceSeed { get; init; }
    public required PilotLocalDataEvidenceFile TargetForward { get; init; }
    public required PilotLocalDataEvidenceFile SourceRestored { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PilotReadinessConfig
{
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
    internal const int CurrentSchemaVersion = 2;
#else
    internal const int CurrentSchemaVersion = 1;
#endif
    public required int SchemaVersion { get; init; }
    public required string Environment { get; init; }
    public required string Channel { get; init; }
    public required string RuntimeIdentifier { get; init; }
    public required string LayoutProfile { get; init; }
    public required string ArtifactAuthorization { get; init; }
    public required string ReleaseSetId { get; init; }
    public required long Generation { get; init; }
    public required long Sequence { get; init; }
    public required long MinAcceptedSequence { get; init; }
    public required string ReleaseDirectory { get; init; }
    public required string PublisherLedgerPath { get; init; }
    public required string PublisherLedgerSha256 { get; init; }
    public required string InstallerExecutablePath { get; init; }
    public required string BootstrapperExecutablePath { get; init; }
    public required string LauncherExecutablePath { get; init; }
    public required string ClientBootstrapperExecutablePath { get; init; }
    public required string MaintenanceExecutablePath { get; init; }
    public required string RuntimeSourceMetadataPath { get; init; }
    public required string RuntimeAdmissionReceiptPath { get; init; }
    public required string PluginPolicyMetadataPath { get; init; }
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
    public required EnterpriseDirectLocalProductionTrustInputs LauncherDirectLocalTrust { get; init; }

    // Shared binary, origin and key checks consume the real v2 inputs without
    // fabricating a gateway origin or accepting the legacy JSON property.
    [JsonIgnore]
    public EnterpriseDirectLocalProductionTrustInputs LauncherTrust => LauncherDirectLocalTrust;
#else
    public required EnterpriseProductionTrustInputs LauncherTrust { get; init; }
#endif
    public required PilotReadinessPublicKey RuntimeAdmissionKey { get; init; }
    public required PilotReadinessPublicKey BrandAuthorizationKey { get; init; }
    public required PilotBrandAuthorizationInput BrandAuthorization { get; init; }
    public required PilotStartupUpdateContract StartupUpdateContract { get; init; }
    public required PilotLocalDataCompatibilityEvidenceInput LocalDataCompatibilityEvidence { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PilotReadinessCheck(
    string Id,
    string Status,
    string Evidence);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PilotReadinessReport
{
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
    public const int CurrentSchemaVersion = 2;
    public string ProductionTrustContractId => EnterpriseDirectLocalProductionTrustFingerprint.ContractId;
    public string RuntimeProfile => EnterpriseDirectLocalProductionTrustFingerprint.RuntimeProfile;
    public string ApiProvider => EnterpriseDirectLocalProductionTrustFingerprint.ApiProvider;
#else
    public const int CurrentSchemaVersion = 1;
#endif
    public const string CurrentReportType = "ensou-dsh-enterprise-pilot-readiness";

    public required int SchemaVersion { get; init; }
    public required string ReportType { get; init; }
    public required string Decision { get; init; }
    public required DateTimeOffset GeneratedAtUtc { get; init; }
    public required string Environment { get; init; }
    public required string Channel { get; init; }
    public required string PublisherExecutableSha256 { get; init; }
    public string? ReleaseSetId { get; init; }
    public long? Generation { get; init; }
    public long? Sequence { get; init; }
    public required string UpdateContractId { get; init; }
    public string? BrandAuthorizationId { get; init; }
    public string? BrandAuthorizationKeyId { get; init; }
    public string? BrandAuthorizationReceiptSha256 { get; init; }
    public DateTimeOffset? BrandAuthorizationExpiresAtUtc { get; init; }
    public string? LocalDataCertificationId { get; init; }
    public string? LocalDataCertificationKeyId { get; init; }
    public string? LocalDataCertificationReceiptSha256 { get; init; }
    public DateTimeOffset? LocalDataCertificationExpiresAtUtc { get; init; }
    public required IReadOnlyList<PilotReadinessCheck> Checks { get; init; }
    public string? FailureCode { get; init; }
    public string? FailureMessage { get; init; }
}

internal sealed record PilotReadinessArguments(
    string ConfigPath,
    string? ReportPath,
    bool EmitReportToStandardOutput)
{
    public static bool IsRequested(string[] args) =>
        args.Contains("--pilot-readiness-config", StringComparer.Ordinal);

    public static PilotReadinessArguments Parse(string[] args)
    {
        const string stdoutFlag = "--report-stdout";
        if (args.Length == 3 &&
            (string.Equals(args[0], stdoutFlag, StringComparison.Ordinal)
                && string.Equals(
                    args[1],
                    "--pilot-readiness-config",
                    StringComparison.Ordinal)
                && !string.IsNullOrWhiteSpace(args[2])
             || string.Equals(
                    args[0],
                    "--pilot-readiness-config",
                    StringComparison.Ordinal)
                && !string.IsNullOrWhiteSpace(args[1])
                && string.Equals(args[2], stdoutFlag, StringComparison.Ordinal)))
        {
            var stdoutConfigPath = Path.GetFullPath(
                string.Equals(args[0], stdoutFlag, StringComparison.Ordinal)
                    ? args[2]
                    : args[1]);
            PublisherPathGuard.RequireSafeExistingFile(stdoutConfigPath);
            return new PilotReadinessArguments(
                stdoutConfigPath,
                ReportPath: null,
                EmitReportToStandardOutput: true);
        }

        if (args.Length != 4)
        {
            throw new ArgumentException(
                "Usage: --pilot-readiness-config <json> --report <json>");
        }
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < args.Length; index += 2)
        {
            if (!values.TryAdd(args[index], args[index + 1]))
            {
                throw new ArgumentException("Pilot readiness argument was repeated.");
            }
        }
        if (!values.TryGetValue("--pilot-readiness-config", out var config)
            || !values.TryGetValue("--report", out var report)
            || string.IsNullOrWhiteSpace(config)
            || string.IsNullOrWhiteSpace(report))
        {
            throw new ArgumentException(
                "Pilot readiness requires --pilot-readiness-config and --report.");
        }
        var configPath = Path.GetFullPath(config);
        var reportPath = Path.GetFullPath(report);
        PublisherPathGuard.RequireSafeExistingFile(configPath);
        PublisherPathGuard.RequireSafeDestination(reportPath);
        if (File.Exists(reportPath) || Directory.Exists(reportPath))
        {
            throw new ArgumentException(
                "Pilot readiness report path must be a new create-only file.");
        }
        return new PilotReadinessArguments(
            configPath,
            reportPath,
            EmitReportToStandardOutput: false);
    }
}

internal sealed record PilotReadinessConfigRead(
    PilotReadinessConfig Config,
    string Sha256);

internal sealed record PilotLocalDataCompatibilityValidation(
    string Evidence,
    string ReportSha256,
    string RunnerSha256);

internal interface IPilotClientBinaryVerifier
{
    void Verify(
        PilotReadinessConfig config,
        string productionTrustSha256,
        PilotClientReleaseBinding releaseBinding);
}

internal sealed record PilotClientReleaseBinding(
    string LauncherReleaseId,
    string RuntimeReleaseId,
    string LauncherArchiveSha256,
    string RuntimeArchiveSha256);

internal sealed class ProductionPilotClientBinaryVerifier : IPilotClientBinaryVerifier
{
    public void Verify(
        PilotReadinessConfig config,
        string productionTrustSha256,
        PilotClientReleaseBinding releaseBinding)
    {
        VerifyBinary(
            config.BootstrapperExecutablePath,
            ["--binary-self-check"],
            config.LauncherTrust.AuthenticodeSignerSha256Thumbprint);
        var bootstrapperSha256 = ComputeFileSha256(config.BootstrapperExecutablePath);
        VerifyBinary(
            config.LauncherExecutablePath,
            ["--production-trust-self-check", productionTrustSha256],
            config.LauncherTrust.AuthenticodeSignerSha256Thumbprint);
        VerifyBinary(
            config.ClientBootstrapperExecutablePath,
            ["--binary-self-check"],
            config.LauncherTrust.AuthenticodeSignerSha256Thumbprint);
        VerifyBinary(
            config.MaintenanceExecutablePath,
            ["--binary-self-check"],
            config.LauncherTrust.AuthenticodeSignerSha256Thumbprint);
        VerifyBinary(
            config.InstallerExecutablePath,
            [
                "--production-payload-self-check",
                releaseBinding.LauncherReleaseId,
                releaseBinding.RuntimeReleaseId,
                releaseBinding.LauncherArchiveSha256,
                releaseBinding.RuntimeArchiveSha256,
                bootstrapperSha256,
            ],
            config.LauncherTrust.AuthenticodeSignerSha256Thumbprint);
        VerifyBinary(
            config.BootstrapperExecutablePath,
            ["--brand-self-check", EnterpriseBrandContract.ProfileSha256],
            config.LauncherTrust.AuthenticodeSignerSha256Thumbprint);
        VerifyBinary(
            config.LauncherExecutablePath,
            ["--brand-self-check", EnterpriseBrandContract.ProfileSha256],
            config.LauncherTrust.AuthenticodeSignerSha256Thumbprint);
        VerifyBinary(
            config.InstallerExecutablePath,
            ["--brand-self-check", EnterpriseBrandContract.ProfileSha256],
            config.LauncherTrust.AuthenticodeSignerSha256Thumbprint);
    }

    private static string ComputeFileSha256(string path)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            1024 * 1024,
            FileOptions.SequentialScan);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    private static void VerifyBinary(
        string executablePath,
        IReadOnlyList<string> arguments,
        string signerSha256Thumbprint)
    {
        var executable = Path.GetFullPath(executablePath);
        PublisherPathGuard.RequireSafeExistingFile(executable);
        if (!string.Equals(Path.GetExtension(executable), ".exe", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Pilot client binary path must identify an executable.");
        }
        EnterpriseAuthenticodeVerifier.RequireTrustedSignature(
            executable,
            signerSha256Thumbprint);

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executable,
                WorkingDirectory = Path.GetDirectoryName(executable)
                    ?? throw new InvalidDataException("Pilot client binary has no parent directory."),
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            },
        };
        foreach (var argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }
        var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var temporaryRoot = Path.GetTempPath();
        process.StartInfo.Environment.Clear();
        process.StartInfo.Environment["SystemRoot"] = systemRoot;
        process.StartInfo.Environment["WINDIR"] = systemRoot;
        process.StartInfo.Environment["TEMP"] = temporaryRoot;
        process.StartInfo.Environment["TMP"] = temporaryRoot;
        process.StartInfo.Environment["PATH"] = Path.Combine(
            systemRoot,
            "System32");
        process.StartInfo.Environment["DOTNET_ROOT"] = Path.Combine(
            temporaryRoot,
            "ensou-no-system-dotnet");
        process.StartInfo.Environment["DOTNET_MULTILEVEL_LOOKUP"] = "0";
        process.StartInfo.Environment["DOTNET_EnableDiagnostics"] = "0";
        process.StartInfo.Environment["COMPlus_EnableDiagnostics"] = "0";
        if (!process.Start())
        {
            throw new InvalidOperationException("Pilot client self-check process did not start.");
        }
        if (!process.WaitForExit(30_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("Pilot client self-check exceeded 30 seconds.");
        }
        if (process.ExitCode != 0)
        {
            throw new InvalidDataException(
                $"Pilot client self-check failed with exit code {process.ExitCode}.");
        }
    }
}

internal sealed class PilotReadinessException(
    string code,
    string message,
    Exception? innerException = null,
    IReadOnlyList<PilotReadinessCheck>? completedChecks = null) : Exception(message, innerException)
{
    public string Code { get; } = code;
    public IReadOnlyList<PilotReadinessCheck> CompletedChecks { get; } =
        completedChecks ?? [];
}

internal sealed class PilotReadinessValidationResult(
    PilotReadinessConfig config,
    IReadOnlyList<PilotReadinessCheck> checks,
    PublisherBrandAuthorizationValidation brandAuthorization,
    PublisherLocalDataCompatibilityCertificationValidation localDataCertification)
{
    public PilotReadinessConfig Config { get; } = config;
    public IReadOnlyList<PilotReadinessCheck> Checks { get; } = checks;
    public PublisherBrandAuthorizationValidation BrandAuthorization { get; } =
        brandAuthorization;
    public PublisherLocalDataCompatibilityCertificationValidation LocalDataCertification { get; } =
        localDataCertification;
}

internal static class EnterprisePilotReadinessValidator
{
    private const int MaximumConfigBytes = 1024 * 1024;
    private const long MaximumJsonSafeInteger = 9_007_199_254_740_991;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static PilotReadinessValidationResult Validate(
        string configPath,
        IPilotClientBinaryVerifier? binaryVerifier = null,
        PublisherRuntimeAdmissionTrust? compiledRuntimeAdmissionTrust = null,
        PublisherBrandAuthorizationTrust? compiledBrandAuthorizationTrust = null,
        PublisherPluginAdmissionTrust? compiledPluginAdmissionTrust = null,
        PublisherLeaseVerificationTrust? compiledLeaseVerificationTrust = null,
        PublisherLocalDataCompatibilityCertificationTrust? compiledLocalDataCertificationTrust = null)
    {
        var checks = new List<PilotReadinessCheck>();
        PilotReadinessConfigRead configRead = RunCheck(
            checks,
            "config-contract",
            () => ReadAndValidateConfig(configPath),
            _ => "strict production Pilot input");
        var config = configRead.Config;

        using var snapshot = RunCheck(
            checks,
            "immutable-input-snapshot",
            () => PilotReadinessInputSnapshot.Capture(
                config,
                configPath,
                configRead.Sha256),
            value => value.SnapshotId);

        var trustSha256 = RunCheck(
            checks,
            "launcher-public-trust",
            () => ComputeLauncherTrustSha256(config),
            value => value);

        var runtimeAdmissionTrust = RunCheck(
            checks,
            "runtime-admission-trust",
            () => RequireRuntimeAdmissionTrust(config, compiledRuntimeAdmissionTrust),
            value => value.KeyId);

        var brandAuthorizationTrust = RunCheck(
            checks,
            "brand-authorization-trust",
            () => RequireBrandAuthorizationTrust(
                config,
                runtimeAdmissionTrust,
                compiledBrandAuthorizationTrust),
            value => value.KeyId);

        var pluginAdmissionTrust = RunCheck(
            checks,
            "plugin-admission-trust",
            () => RequirePluginAdmissionTrust(compiledPluginAdmissionTrust),
            value => value.KeyId);

        var leaseVerificationTrust = RunCheck(
            checks,
            "lease-verification-trust",
            () => RequireLeaseVerificationTrust(config, compiledLeaseVerificationTrust),
            value => value.KeyId);

        var localDataCertificationTrust = RunCheck(
            checks,
            "local-data-certification-trust",
            () => RequireLocalDataCertificationTrust(
                config,
                runtimeAdmissionTrust,
                pluginAdmissionTrust,
                brandAuthorizationTrust,
                leaseVerificationTrust,
                compiledLocalDataCertificationTrust),
            value => value.KeyId);

        var release = RunCheck(
            checks,
            "signed-release-set",
            () => ValidateReleaseSet(config, snapshot),
            value => $"{value.Manifest.ReleaseSetId}:{value.Manifest.Sequence}:{value.ManifestSha256}");

        RunCheck(
            checks,
            "publisher-feed-head",
            () => ValidatePublisherLedger(config, release, snapshot.PublisherLedgerPath),
            value => value);

        var runtimeMetadata = RunCheck(
            checks,
            "runtime-artifact-admission",
            () =>
            {
                return PublisherRuntimeAdmissionValidator.ValidateFiles(
                    release.RuntimeArchivePath,
                    release.Manifest.Runtime.ReleaseId,
                    snapshot.RuntimeSourceMetadataPath,
                    snapshot.RuntimeAdmissionReceiptPath,
                    runtimeAdmissionTrust);
            },
            value => $"{value.SourceTag}:{release.Manifest.Runtime.Sha256}");

        var localDataCompatibility = RunCheck(
            checks,
            "local-data-compatibility-rollback",
            () => ValidateLocalDataCompatibilityEvidence(
                config.LocalDataCompatibilityEvidence with
                {
                    ReportPath = snapshot.DataMigrationReportPath,
                },
                runtimeMetadata.SourceTag,
                release.Manifest.Runtime.Sha256,
                snapshot.MigrationEvidencePaths,
                snapshot.OriginalDataMigrationReportPath),
            value => value.Evidence);

        var localDataCertification = RunCheck(
            checks,
            "local-data-compatibility-certification",
            () => ValidateLocalDataCompatibilityCertification(
                config.LocalDataCompatibilityEvidence,
                snapshot.LocalDataCertificationReceiptPath,
                localDataCompatibility,
                localDataCertificationTrust),
            value => $"{value.CertificationId}:{value.ReceiptSha256}");

        RunCheck(
            checks,
            "plugin-policy-artifact",
            () =>
            {
                var inspection = EnterprisePluginPolicyArchiveValidator.Validate(
                    release.PluginPolicyArchivePath,
                    release.Manifest.Launcher.ReleaseId,
                    release.Manifest.Runtime.ReleaseId);
                PublisherPluginPolicyMetadata.Validate(
                    snapshot.PluginPolicyMetadataPath,
                    release.PluginPolicyArchivePath,
                    inspection);
                return $"{inspection.PolicyId}:{inspection.Generation}:{inspection.ArchiveSha256}";
            },
            value => value);

        RunCheck(
            checks,
            "launcher-artifact-binding",
            () =>
            {
                RequireLauncherArtifactBinding(
                    release.LauncherArchivePath,
                    snapshot.LauncherExecutablePath,
                    snapshot.ClientBootstrapperExecutablePath,
                    snapshot.MaintenanceExecutablePath,
                    snapshot.LauncherBuildProfilePath);
                return release.Manifest.Launcher.Sha256;
            },
            value => value);

        var brandAuthorization = RunCheck(
            checks,
            "brand-authorization-receipt",
            () => PublisherBrandAuthorizationValidator.Validate(
                config.BrandAuthorization,
                snapshot.BrandAuthorizationReceiptPath,
                snapshot.BrandAuthorizationEvidencePath,
                new PublisherBrandReleaseBinding(
                    release.Manifest.ReleaseSetId,
                    release.Manifest.Generation,
                    release.Manifest.Sequence,
                    release.ManifestSha256,
                    release.Manifest.ExpiresAtUtc,
                    release.Manifest.Launcher.ReleaseId,
                    release.Manifest.Launcher.Sha256),
                new PublisherBrandBinaryPaths(
                    snapshot.LauncherExecutablePath,
                    snapshot.BootstrapperExecutablePath,
                    snapshot.InstallerExecutablePath),
                brandAuthorizationTrust,
                DateTimeOffset.UtcNow),
            value => $"{value.AuthorizationId}:{value.ReceiptSha256}");

        RunCheck(
            checks,
            "signed-production-client",
            () =>
            {
                (binaryVerifier ?? new ProductionPilotClientBinaryVerifier())
                    .Verify(
                        config with
                        {
                            InstallerExecutablePath = snapshot.InstallerExecutablePath,
                            BootstrapperExecutablePath = snapshot.BootstrapperExecutablePath,
                            LauncherExecutablePath = snapshot.LauncherExecutablePath,
                            ClientBootstrapperExecutablePath =
                                snapshot.ClientBootstrapperExecutablePath,
                            MaintenanceExecutablePath = snapshot.MaintenanceExecutablePath,
                        },
                        trustSha256,
                        new PilotClientReleaseBinding(
                            release.Manifest.Launcher.ReleaseId,
                            release.Manifest.Runtime.ReleaseId,
                            release.Manifest.Launcher.Sha256,
                            release.Manifest.Runtime.Sha256));
                return EnterpriseProductionTrustFingerprint.PilotUpdateContractId;
            },
            value => value);

        RunCheck(
            checks,
            "brand-final-binary-binding",
            () =>
            {
                if (!string.Equals(
                        HashFile(snapshot.LauncherExecutablePath),
                        brandAuthorization.LauncherExecutableSha256,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        HashFile(snapshot.BootstrapperExecutablePath),
                        brandAuthorization.BootstrapperExecutableSha256,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        HashFile(snapshot.InstallerExecutablePath),
                        brandAuthorization.InstallerExecutableSha256,
                        StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "Authorized production client bytes changed after brand self-check.");
                }
                return brandAuthorization.BrandProfileSha256;
            },
            value => value);

        RunCheck(
            checks,
            "source-inputs-unchanged",
            () =>
            {
                snapshot.RequireOriginalsUnchanged();
                return snapshot.SnapshotId;
            },
            value => value);

        return new PilotReadinessValidationResult(
            config,
            checks,
            brandAuthorization,
            localDataCertification);
    }

    internal static string ComputeLauncherTrustSha256(PilotReadinessConfig config)
    {
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
        return EnterpriseDirectLocalProductionTrustFingerprint.ComputeSha256(config.LauncherTrust);
#else
        return EnterpriseProductionTrustFingerprint.ComputeSha256(config.LauncherTrust);
#endif
    }

    internal static PilotReadinessConfigRead ReadAndValidateConfig(string path)
    {
        PublisherPathGuard.RequireSafeExistingFile(path);
        using var lockedConfig = PublisherSafeFile.OpenLockedRead(path);
        if (lockedConfig.Length is <= 0 or > MaximumConfigBytes)
        {
            throw new InvalidDataException("Pilot readiness config size is invalid.");
        }
        using var configBytes = new MemoryStream(checked((int)lockedConfig.Length));
        lockedConfig.CopyTo(configBytes);
        if (configBytes.Length != lockedConfig.Length)
        {
            throw new IOException(
                "Pilot readiness config changed while its locked bytes were read.");
        }
        var bytes = configBytes.ToArray();
        var raw = Encoding.UTF8.GetString(bytes);
        if (raw.Contains("UNSIGNED_CANDIDATE", StringComparison.OrdinalIgnoreCase)
            || raw.Contains("development-e2e", StringComparison.OrdinalIgnoreCase)
            || raw.Contains("example.invalid", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Pilot readiness config contains a development, unsigned, or placeholder value.");
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
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
            // JsonIgnore accessors are otherwise silently ignored by System.Text.Json.
            // Explicitly forbid the old serialized member even when its value is null.
            if (document.RootElement.ValueKind != JsonValueKind.Object
                || document.RootElement.TryGetProperty("launcherTrust", out _)
                || !document.RootElement.TryGetProperty("launcherDirectLocalTrust", out var directTrust))
            {
                throw new InvalidDataException("Direct-local Pilot requires only launcherDirectLocalTrust.");
            }
            _ = EnterpriseDirectLocalProductionTrustFingerprint.Parse(
                Encoding.UTF8.GetBytes(directTrust.GetRawText()));
#endif
            var config = JsonSerializer.Deserialize<PilotReadinessConfig>(bytes, JsonOptions)
                ?? throw new InvalidDataException("Pilot readiness config is empty.");
            RequireExactConfig(config);
            return new PilotReadinessConfigRead(config, HashBytes(bytes));
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                $"Pilot readiness config is not the exact v{PilotReadinessConfig.CurrentSchemaVersion} contract.",
                exception);
        }
    }

    internal static void RequireExactConfig(PilotReadinessConfig config)
    {
        if (config.SchemaVersion != PilotReadinessConfig.CurrentSchemaVersion
            || !string.Equals(
                config.Environment,
                EnterpriseReleaseSetContract.ProductionEnvironment,
                StringComparison.Ordinal)
            || !string.Equals(config.Channel, "pilot", StringComparison.Ordinal)
            || !string.Equals(config.RuntimeIdentifier, "win-x64", StringComparison.Ordinal)
            || !string.Equals(
                config.LayoutProfile,
                EnterpriseInstallationLayout.ProductionLayoutProfile,
                StringComparison.Ordinal)
            || !string.Equals(
                config.ArtifactAuthorization,
                "SIGNED_RELEASE_SET",
                StringComparison.Ordinal)
            || config.Generation <= 0
            || config.Generation > MaximumJsonSafeInteger
            || config.Sequence <= 0
            || config.Sequence > MaximumJsonSafeInteger
            || config.MinAcceptedSequence < 0
            || config.MinAcceptedSequence > MaximumJsonSafeInteger
            || config.MinAcceptedSequence > config.Sequence
            || config.PublisherLedgerSha256 is not { Length: 64 }
            || config.PublisherLedgerSha256.Any(character =>
                !(character is >= '0' and <= '9' or >= 'a' and <= 'f'))
            || config.StartupUpdateContract is null
            || !config.StartupUpdateContract.CheckOnEveryStartup
            || !config.StartupUpdateContract.AtomicReleaseSetActivation
            || !config.StartupUpdateContract.BootstrapHealthRollback
            || config.StartupUpdateContract.MaximumOfflineGraceHours != 7 * 24
            || config.LauncherTrust is null
            || config.RuntimeAdmissionKey is null
            || config.BrandAuthorizationKey is null
            || config.BrandAuthorization is null
            || config.BrandAuthorization.ReceiptSha256 is not { Length: 64 }
            || config.BrandAuthorization.ReceiptSha256.Any(character =>
                !(character is >= '0' and <= '9' or >= 'a' and <= 'f'))
            || config.BrandAuthorization.EvidenceSha256 is not { Length: 64 }
            || config.BrandAuthorization.EvidenceSha256.Any(character =>
                !(character is >= '0' and <= '9' or >= 'a' and <= 'f'))
            || !Guid.TryParseExact(
                config.BrandAuthorization.DistributionAudienceId,
                "D",
                out var distributionAudienceId)
            || !string.Equals(
                distributionAudienceId.ToString("D"),
                config.BrandAuthorization.DistributionAudienceId,
                StringComparison.Ordinal)
            || config.LocalDataCompatibilityEvidence is null
            || !IsCanonicalUpstreamTag(config.LocalDataCompatibilityEvidence.FromUpstreamTag)
            || !IsCanonicalUpstreamTag(config.LocalDataCompatibilityEvidence.ToUpstreamTag)
            || string.Equals(
                config.LocalDataCompatibilityEvidence.FromUpstreamTag,
                config.LocalDataCompatibilityEvidence.ToUpstreamTag,
                StringComparison.Ordinal)
            || !IsLowerSha256(
                config.LocalDataCompatibilityEvidence.SourceRuntimeArchiveSha256)
            || !IsLowerSha256(
                config.LocalDataCompatibilityEvidence.TargetRuntimeArchiveSha256)
            || config.LocalDataCompatibilityEvidence.ReportSha256 is not { Length: 64 }
            || config.LocalDataCompatibilityEvidence.ReportSha256.Any(character =>
                !(character is >= '0' and <= '9' or >= 'a' and <= 'f'))
            || config.LocalDataCompatibilityEvidence.Certification is null
            || !IsLowerSha256(
                config.LocalDataCompatibilityEvidence.Certification.ReceiptSha256)
            || !Guid.TryParseExact(
                config.LocalDataCompatibilityEvidence.Certification.CertificationAudienceId,
                "D",
                out var certificationAudienceId)
            || !string.Equals(
                certificationAudienceId.ToString("D"),
                config.LocalDataCompatibilityEvidence.Certification.CertificationAudienceId,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Pilot readiness config does not assert the exact production update contract.");
        }
        if (string.IsNullOrWhiteSpace(config.ReleaseSetId)
            || config.ReleaseSetId.Length > 128
            || !char.IsAsciiLetterOrDigit(config.ReleaseSetId[0])
            || config.ReleaseSetId.Any(character => !(char.IsAsciiLetterOrDigit(character)
                || character is '.' or '_' or '+' or '-')))
        {
            throw new InvalidDataException("Pilot releaseSetId is not canonical.");
        }
        foreach (var path in new[]
                 {
                     config.ReleaseDirectory,
                     config.PublisherLedgerPath,
                     config.InstallerExecutablePath,
                     config.BootstrapperExecutablePath,
                     config.LauncherExecutablePath,
                     config.ClientBootstrapperExecutablePath,
                     config.MaintenanceExecutablePath,
                     config.RuntimeSourceMetadataPath,
                     config.RuntimeAdmissionReceiptPath,
                     config.PluginPolicyMetadataPath,
                     config.BrandAuthorization.ReceiptPath,
                     config.BrandAuthorization.EvidencePath,
                     config.LocalDataCompatibilityEvidence.ReportPath,
                     config.LocalDataCompatibilityEvidence.Certification.ReceiptPath,
                 })
        {
            if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            {
                throw new InvalidDataException(
                    "Pilot readiness file and directory paths must be absolute.");
            }
        }
        if (string.Equals(
                Path.GetFullPath(config.BrandAuthorization.ReceiptPath),
                Path.GetFullPath(config.BrandAuthorization.EvidencePath),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Brand authorization receipt and written evidence must be distinct files.");
        }
        if (string.Equals(
                Path.GetFullPath(config.LocalDataCompatibilityEvidence.ReportPath),
                Path.GetFullPath(
                    config.LocalDataCompatibilityEvidence.Certification.ReceiptPath),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Local-data evidence report and certification receipt must be distinct files.");
        }
    }

    internal static PilotLocalDataCompatibilityValidation ValidateLocalDataCompatibilityEvidence(
        PilotLocalDataCompatibilityEvidenceInput input,
        string admittedRuntimeUpstreamTag,
        string admittedRuntimeArchiveSha256,
        IReadOnlyDictionary<string, string>? evidenceSnapshotPaths = null,
        string? reportIdentityPath = null)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!string.Equals(
                input.ToUpstreamTag,
                admittedRuntimeUpstreamTag,
                StringComparison.Ordinal)
            || !IsLowerSha256(admittedRuntimeArchiveSha256)
            || !string.Equals(
                input.TargetRuntimeArchiveSha256,
                admittedRuntimeArchiveSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Local-data evidence target does not match the admitted runtime artifact.");
        }
        if (!IsLowerSha256(input.SourceRuntimeArchiveSha256)
            || !IsLowerSha256(input.TargetRuntimeArchiveSha256)
            || string.Equals(
                input.SourceRuntimeArchiveSha256,
                input.TargetRuntimeArchiveSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Local-data evidence must bind distinct exact source and target runtime archives.");
        }

        PublisherPathGuard.RequireSafeExistingFile(input.ReportPath);
        var bytes = ReadBounded(
            input.ReportPath,
            4 * 1024 * 1024,
            "local-data compatibility evidence");
        RequireNoDuplicateJsonMembers(bytes, "local-data compatibility evidence");
        if (!string.Equals(HashBytes(bytes), input.ReportSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Local-data compatibility evidence SHA-256 changed.");
        }
        var report = JsonSerializer.Deserialize<PilotLocalDataCompatibilityEvidenceReport>(
            bytes,
            JsonOptions) ?? throw new InvalidDataException(
                "Local-data compatibility evidence report is empty.");
        if (report.TestRunner is null
            || report.HistoricalFixture is null
            || report.PreUpgradeBackup is null
            || report.ForwardResult is null
            || report.RollbackResult is null
            || report.Transcript is null
            || report.ApiLanes is null
            || report.ApiLanes.SourceSeed is null
            || report.ApiLanes.TargetForward is null
            || report.ApiLanes.SourceRestored is null
            || report.Artifacts is null
            || report.Coverage is null)
        {
            throw new InvalidDataException(
                "Local-data compatibility evidence is missing a required member.");
        }
        var now = DateTimeOffset.UtcNow;
        if (report.SchemaVersion != 1
            || !string.Equals(
                report.EvidenceType,
                PilotLocalDataCompatibilityEvidenceReport.CurrentEvidenceType,
                StringComparison.Ordinal)
            || !string.Equals(report.Decision, "PASS", StringComparison.Ordinal)
            || !string.Equals(
                report.FromUpstreamTag,
                input.FromUpstreamTag,
                StringComparison.Ordinal)
            || !string.Equals(
                report.ToUpstreamTag,
                input.ToUpstreamTag,
                StringComparison.Ordinal)
            || !string.Equals(
                report.SourceRuntimeArchiveSha256,
                input.SourceRuntimeArchiveSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                report.TargetRuntimeArchiveSha256,
                input.TargetRuntimeArchiveSha256,
                StringComparison.Ordinal)
            || report.StartedUtc.Offset != TimeSpan.Zero
            || report.CompletedUtc.Offset != TimeSpan.Zero
            || report.StartedUtc <= now.AddDays(-30)
            || report.StartedUtc > now.AddMinutes(5)
            || report.CompletedUtc < report.StartedUtc
            || report.CompletedUtc > now.AddMinutes(5)
            || report.CompletedUtc - report.StartedUtc > TimeSpan.FromHours(4))
        {
            throw new InvalidDataException(
                "Local-data evidence does not bind a recent passing exact runtime transition.");
        }
        ValidateLocalDataCoverage(report.Coverage);

        var identityPath = Path.GetFullPath(reportIdentityPath ?? input.ReportPath);
        var semanticReferences = new (PilotLocalDataEvidenceFile Evidence, string Field, long MaximumBytes)[]
        {
            (report.TestRunner, "local-data test runner", 4L * 1024 * 1024),
            (report.HistoricalFixture, "historical local-data fixture", 8L * 1024 * 1024 * 1024),
            (report.PreUpgradeBackup, "pre-upgrade whole-home backup", 8L * 1024 * 1024 * 1024),
            (report.ForwardResult, "local-data forward result", 4L * 1024 * 1024),
            (report.RollbackResult, "local-data rollback result", 4L * 1024 * 1024),
            (report.Transcript, "local-data test transcript", 128L * 1024 * 1024),
            (report.ApiLanes.SourceSeed, "source API seed result", 4L * 1024 * 1024),
            (report.ApiLanes.TargetForward, "target API forward result", 4L * 1024 * 1024),
            (report.ApiLanes.SourceRestored, "restored source API result", 4L * 1024 * 1024),
        };
        var semanticPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var validated = new Dictionary<string, PilotLocalDataEvidenceValidation>(
            StringComparer.Ordinal);
        foreach (var item in semanticReferences)
        {
            var value = ValidateLocalDataEvidenceFile(
                item.Evidence,
                item.Field,
                item.MaximumBytes,
                allowEmpty: false,
                identityPath,
                evidenceSnapshotPaths);
            if (!semanticPaths.Add(value.OriginalPath))
            {
                throw new InvalidDataException(
                    "Local-data semantic evidence references must use distinct files.");
            }
            validated.Add(item.Field, value);
        }

        if (report.Artifacts is null
            || report.Artifacts.Count < semanticReferences.Length
            || report.Artifacts.Count > 512)
        {
            throw new InvalidDataException(
                "Local-data evidence artifact inventory size is invalid.");
        }
        var inventoryPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var artifact in report.Artifacts)
        {
            var value = ValidateLocalDataEvidenceFile(
                artifact,
                "local-data evidence artifact",
                8L * 1024 * 1024 * 1024,
                allowEmpty: true,
                identityPath,
                evidenceSnapshotPaths);
            if (!inventoryPaths.Add(value.OriginalPath))
            {
                throw new InvalidDataException(
                    "Local-data evidence artifact inventory repeats a path.");
            }
        }
        if (!semanticPaths.IsSubsetOf(inventoryPaths))
        {
            throw new InvalidDataException(
                "Local-data evidence artifact inventory omits a semantic result.");
        }

        ValidateLocalDataForwardResult(
            validated["local-data forward result"].SnapshotPath,
            report);
        ValidateLocalDataRollbackResult(
            validated["local-data rollback result"].SnapshotPath,
            report);
        var sourceApi = ValidateLocalDataApiLaneResult(
            validated["source API seed result"].SnapshotPath,
            "source-seed",
            report.SourceRuntimeArchiveSha256,
            report);
        var targetApi = ValidateLocalDataApiLaneResult(
            validated["target API forward result"].SnapshotPath,
            "target-forward",
            report.TargetRuntimeArchiveSha256,
            report);
        var restoredApi = ValidateLocalDataApiLaneResult(
            validated["restored source API result"].SnapshotPath,
            "source-restored",
            report.SourceRuntimeArchiveSha256,
            report);
        if (!string.Equals(
                sourceApi.QueryErrorCode,
                targetApi.QueryErrorCode,
                StringComparison.Ordinal)
            || !string.Equals(
                sourceApi.QueryErrorCode,
                restoredApi.QueryErrorCode,
                StringComparison.Ordinal)
            || !string.Equals(
                sourceApi.QueryDiagnosticClass,
                targetApi.QueryDiagnosticClass,
                StringComparison.Ordinal)
            || !string.Equals(
                sourceApi.QueryDiagnosticClass,
                restoredApi.QueryDiagnosticClass,
                StringComparison.Ordinal)
            || !string.Equals(
                sourceApi.QueryMessageSha256,
                targetApi.QueryMessageSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                sourceApi.QueryMessageSha256,
                restoredApi.QueryMessageSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Session-query managed policy semantics changed across the runtime transition.");
        }
        if (!string.Equals(sourceApi.SessionId, targetApi.SessionId, StringComparison.Ordinal)
            || !string.Equals(sourceApi.SessionId, restoredApi.SessionId, StringComparison.Ordinal)
            || sourceApi.PriorMarkersPreserved.Count != 0
            || !targetApi.PriorMarkersPreserved.Contains(
                sourceApi.AppendedPromptMarker,
                StringComparer.Ordinal)
            || !targetApi.PriorMarkersPreserved.Contains(
                sourceApi.AppendedProviderMarker,
                StringComparer.Ordinal)
            || !restoredApi.PriorMarkersPreserved.Contains(
                sourceApi.AppendedPromptMarker,
                StringComparer.Ordinal)
            || !restoredApi.PriorMarkersPreserved.Contains(
                sourceApi.AppendedProviderMarker,
                StringComparer.Ordinal)
            || restoredApi.PriorMarkersPreserved.Contains(
                targetApi.AppendedPromptMarker,
                StringComparer.Ordinal)
            || restoredApi.PriorMarkersPreserved.Contains(
                targetApi.AppendedProviderMarker,
                StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "Session markers do not prove forward resume and byte-exact source restore.");
        }
        if (!string.Equals(
                sourceApi.AttachmentSha256,
                targetApi.AttachmentSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                sourceApi.AttachmentSha256,
                restoredApi.AttachmentSha256,
                StringComparison.Ordinal)
            || sourceApi.AttachmentBytes != targetApi.AttachmentBytes
            || sourceApi.AttachmentBytes != restoredApi.AttachmentBytes)
        {
            throw new InvalidDataException(
                "Attachment public-API bytes changed across the runtime transition.");
        }
        var capturedRunnerSha256 = HashFile(
            validated["local-data test runner"].SnapshotPath);
        if (!string.Equals(
                capturedRunnerSha256,
                report.TestRunner.Sha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Captured local-data test runner changed after evidence validation.");
        }
        return new PilotLocalDataCompatibilityValidation(
            $"{report.FromUpstreamTag}->{report.ToUpstreamTag}:"
                + $"{report.TargetRuntimeArchiveSha256}:{input.ReportSha256}",
            input.ReportSha256,
            capturedRunnerSha256);
    }

    private static PublisherLocalDataCompatibilityCertificationValidation
        ValidateLocalDataCompatibilityCertification(
            PilotLocalDataCompatibilityEvidenceInput input,
            string receiptPath,
            PilotLocalDataCompatibilityValidation compatibility,
            PublisherLocalDataCompatibilityCertificationTrust trust)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(compatibility);
        ArgumentNullException.ThrowIfNull(trust);
        PublisherPathGuard.RequireSafeExistingFile(receiptPath);
        var receiptBytes = ReadBounded(
            receiptPath,
            128 * 1024,
            "local-data compatibility certification receipt");
        var receiptSha256 = HashBytes(receiptBytes);
        if (!string.Equals(
                receiptSha256,
                input.Certification.ReceiptSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Local-data compatibility certification receipt SHA-256 changed.");
        }
        var validation = PublisherLocalDataCompatibilityCertificationValidator.Validate(
            receiptBytes,
            new PublisherLocalDataCompatibilityCertificationExpectation(
                input.Certification.CertificationAudienceId,
                input.FromUpstreamTag,
                input.ToUpstreamTag,
                input.SourceRuntimeArchiveSha256,
                input.TargetRuntimeArchiveSha256,
                compatibility.ReportSha256,
                compatibility.RunnerSha256),
            trust,
            DateTimeOffset.UtcNow);
        if (!string.Equals(
                validation.ReceiptSha256,
                input.Certification.ReceiptSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Validated local-data compatibility certification receipt identity changed.");
        }
        return validation;
    }

    private static void ValidateLocalDataCoverage(
        IReadOnlyDictionary<string, string> coverage)
    {
        ArgumentNullException.ThrowIfNull(coverage);
        var expected = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["credentialsP0"] = "covered",
            ["canonicalWholeHomeBackupRestore"] = "covered",
            ["workspaceTreeBackupRestore"] = "covered",
            ["sameTreeOldRuntimeRefusal"] = "covered",
            ["headerOnlySessionArtifact"] = "preserved-and-discovered-at-boot",
            ["fullSessionApiRoundTrip"] = "covered",
            ["conversationProviderRoundTrip"] = "covered",
            ["attachmentPublicApiRoundTrip"] = "covered",
            ["sessionQuerySemanticParity"] = "covered",
            ["sqliteLocalDataGate"] =
                "not-applicable-memory-only-derived-and-no-artifacts-observed",
        };
        if (coverage.Count != expected.Count + 1)
        {
            throw new InvalidDataException(
                "Local-data evidence coverage does not contain the exact Pilot lanes.");
        }
        foreach (var item in expected)
        {
            if (!coverage.TryGetValue(item.Key, out var actual)
                || !string.Equals(actual, item.Value, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Local-data Pilot coverage lane '{item.Key}' is not complete.");
            }
        }
        if (!coverage.TryGetValue("requestImageNormalization", out var normalization)
            || !string.Equals(
                normalization,
                "not-applicable-managed-text-only-policy-public-refusal-proven",
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Local-data request-image normalization coverage is not admissible.");
        }
        if (coverage.Any(item => item.Value.Contains(
                "deferred",
                StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidDataException(
                "Local-data Pilot evidence may not contain a deferred lane.");
        }
    }

    private static PilotLocalDataEvidenceValidation ValidateLocalDataEvidenceFile(
        PilotLocalDataEvidenceFile evidence,
        string field,
        long maximumBytes,
        bool allowEmpty,
        string reportIdentityPath,
        IReadOnlyDictionary<string, string>? evidenceSnapshotPaths)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        if (!IsLowerSha256(evidence.Sha256)
            || evidence.Bytes < 0
            || (!allowEmpty && evidence.Bytes == 0)
            || evidence.Bytes > maximumBytes)
        {
            throw new InvalidDataException($"{field} reference is not canonical.");
        }
        var originalPath = ResolveLocalDataEvidencePath(
            reportIdentityPath,
            evidence.Path);
        var path = originalPath;
        if (evidenceSnapshotPaths is not null
            && !evidenceSnapshotPaths.TryGetValue(originalPath, out path))
        {
            throw new InvalidDataException(
                $"{field} is absent from the immutable readiness snapshot.");
        }
        PublisherPathGuard.RequireSafeExistingFile(path);
        var length = new FileInfo(path).Length;
        if (length != evidence.Bytes
            || length > maximumBytes
            || (!allowEmpty && length == 0)
            || !string.Equals(HashFile(path), evidence.Sha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"{field} bytes or SHA-256 are invalid.");
        }
        return new PilotLocalDataEvidenceValidation(originalPath, path);
    }

    private static string ResolveLocalDataEvidencePath(
        string reportIdentityPath,
        string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath)
            || relativePath.Length > 1024
            || Path.IsPathFullyQualified(relativePath)
            || relativePath.Contains('\\', StringComparison.Ordinal)
            || relativePath.Any(character => character is '\0' or '\r' or '\n' or '\t'))
        {
            throw new InvalidDataException(
                "Local-data evidence paths must be canonical forward-slash relative paths.");
        }
        var segments = relativePath.Split('/');
        if (segments.Length == 0
            || segments.Any(segment => string.IsNullOrWhiteSpace(segment)
                || segment is "." or ".."))
        {
            throw new InvalidDataException(
                "Local-data evidence path contains an invalid segment.");
        }
        var reportPath = Path.GetFullPath(reportIdentityPath);
        var root = Path.GetDirectoryName(reportPath)
            ?? throw new InvalidDataException(
                "Local-data evidence report has no parent directory.");
        var candidate = Path.GetFullPath(Path.Combine(root, Path.Combine(segments)));
        var boundary = root.TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!candidate.StartsWith(boundary, StringComparison.OrdinalIgnoreCase)
            || string.Equals(candidate, reportPath, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(
                Path.GetRelativePath(root, candidate).Replace('\\', '/'),
                relativePath,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Local-data evidence path escapes its immutable report directory.");
        }
        return candidate;
    }

    private static void ValidateLocalDataForwardResult(
        string path,
        PilotLocalDataCompatibilityEvidenceReport report)
    {
        var root = ReadLocalDataResult(path, "local-data forward result");
        RequireOnlyJsonProperties(
            root,
            "schemaVersion", "resultType", "fromUpstreamTag", "toUpstreamTag",
            "decision", "sourceRuntimeArchiveSha256", "targetRuntimeArchiveSha256",
            "targetRuntimeBootPassed", "credentialsMigrationObserved",
            "credentialsLayoutBefore", "credentialsLayoutAfter",
            "credentialsSha256Before", "credentialsSha256After",
            "authoritativeFilesPreserved", "workspaceTreePreserved",
            "queryPersistence", "treeChanges", "apiLanes", "recordedAtUtc",
            "coveredLanes", "deferredLanes");
        RequireJsonInteger(root, "schemaVersion", 1);
        RequireJsonString(root, "resultType", "ensou-dsh-local-data-forward-result");
        RequireJsonString(root, "fromUpstreamTag", report.FromUpstreamTag);
        RequireJsonString(root, "toUpstreamTag", report.ToUpstreamTag);
        RequireJsonString(root, "decision", "PASS");
        RequireJsonString(
            root,
            "sourceRuntimeArchiveSha256",
            report.SourceRuntimeArchiveSha256);
        RequireJsonString(
            root,
            "targetRuntimeArchiveSha256",
            report.TargetRuntimeArchiveSha256);
        RequireJsonBoolean(root, "targetRuntimeBootPassed", true);
        RequireJsonBoolean(root, "credentialsMigrationObserved", true);
        RequireJsonString(root, "credentialsLayoutBefore", "pre-release-flat");
        RequireJsonString(root, "credentialsLayoutAfter", "version-1-refs");
        var credentialsBefore = RequireJsonSha256(root, "credentialsSha256Before");
        var credentialsAfter = RequireJsonSha256(root, "credentialsSha256After");
        if (string.Equals(credentialsBefore, credentialsAfter, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Local-data forward result did not observe the credentials migration.");
        }
        RequireJsonBoolean(root, "workspaceTreePreserved", true);
        var authoritative = RequireJsonStringArray(
            root,
            "authoritativeFilesPreserved",
            minimumCount: 4);
        if (!authoritative.Any(pathValue =>
                pathValue.EndsWith("session.jsonl.zstd", StringComparison.Ordinal))
            || !authoritative.Any(pathValue =>
                pathValue.StartsWith("attachments/v1/objects/", StringComparison.Ordinal))
            || !authoritative.Contains("storages/workspace.json", StringComparer.Ordinal)
            || !authoritative.Any(pathValue =>
                pathValue.StartsWith("workspaces/", StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "Local-data forward result omits an authoritative data family.");
        }
        var query = RequireJsonObject(root, "queryPersistence");
        RequireOnlyJsonProperties(
            query,
            "classification", "sqliteArtifactsBefore", "sqliteArtifactsAfter");
        RequireJsonString(query, "classification", "memory-only-derived");
        RequireJsonEmptyArray(query, "sqliteArtifactsBefore");
        RequireJsonEmptyArray(query, "sqliteArtifactsAfter");

        var api = RequireJsonObject(root, "apiLanes");
        RequireOnlyJsonProperties(
            api,
            "sourceSeedDecision", "targetForwardDecision",
            "fullSessionApiRoundTripPassed", "conversationProviderRoundTripPassed",
            "attachmentPublicApiRoundTripPassed", "sessionQuerySemanticParityPassed",
            "requestImageNormalization");
        RequireJsonString(api, "sourceSeedDecision", "PASS");
        RequireJsonString(api, "targetForwardDecision", "PASS");
        RequireJsonBoolean(api, "fullSessionApiRoundTripPassed", true);
        RequireJsonBoolean(api, "conversationProviderRoundTripPassed", true);
        RequireJsonBoolean(api, "attachmentPublicApiRoundTripPassed", true);
        RequireJsonBoolean(api, "sessionQuerySemanticParityPassed", true);
        var normalization = RequireJsonString(api, "requestImageNormalization");
        if (!string.Equals(
                normalization,
                "not-applicable-managed-text-only-policy-public-refusal-proven",
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Forward local-data API summary has an invalid request-image result.");
        }

        var requiredLanes = new[]
        {
            "exact-runtime-archive-and-internal-manifest-verification",
            "rc7-flat-credentials-to-version-1-boot-migration",
            "header-only-zstd-session-artifact-preservation",
            "workspace-v2-json-storage-preservation",
            "content-addressed-attachment-object-preservation",
            "workspace-file-tree-preservation",
            "zstd-session-v0-public-api-resume-append",
            "loopback-fake-provider-conversation-roundtrip",
            "attachment-public-api-byte-roundtrip",
            "session-query-public-api-managed-disabled-policy-parity",
        };
        var covered = RequireJsonStringArray(
            root,
            "coveredLanes",
            requiredLanes.Length);
        if (covered.Count != requiredLanes.Length
            || requiredLanes.Any(lane => !covered.Contains(lane, StringComparer.Ordinal)))
        {
            throw new InvalidDataException(
                "Forward local-data result does not cover the exact Pilot lanes.");
        }
        RequireJsonEmptyArray(root, "deferredLanes");
        RequireRecentLocalDataTime(root, "recordedAtUtc", report.CompletedUtc);
    }

    private static void ValidateLocalDataRollbackResult(
        string path,
        PilotLocalDataCompatibilityEvidenceReport report)
    {
        var root = ReadLocalDataResult(path, "local-data rollback result");
        RequireOnlyJsonProperties(
            root,
            "schemaVersion", "resultType", "fromUpstreamTag", "toUpstreamTag",
            "decision", "inPlaceRollbackRefusedAsExpected", "refusalClass",
            "historicalFixtureSha256", "backupArchiveSha256",
            "preUpgradeTreeSha256", "restoredTreeSha256",
            "preUpgradeWorkspaceTreeSha256", "restoredWorkspaceTreeSha256",
            "backupRestoreByteExactPassed", "sourceRuntimeBootAfterRestorePassed",
            "sourceRuntimeAuthoritativeFilesPreservedAfterBoot",
            "sqliteArtifactsAfterRestoreAndBoot", "recordedAtUtc");
        RequireJsonInteger(root, "schemaVersion", 1);
        RequireJsonString(root, "resultType", "ensou-dsh-local-data-rollback-result");
        RequireJsonString(root, "fromUpstreamTag", report.FromUpstreamTag);
        RequireJsonString(root, "toUpstreamTag", report.ToUpstreamTag);
        RequireJsonString(root, "decision", "PASS");
        RequireJsonBoolean(root, "inPlaceRollbackRefusedAsExpected", true);
        RequireJsonString(root, "refusalClass", "credentials-layout-refusal");
        RequireJsonString(
            root,
            "historicalFixtureSha256",
            report.HistoricalFixture.Sha256);
        RequireJsonString(
            root,
            "backupArchiveSha256",
            report.PreUpgradeBackup.Sha256);
        var treeBefore = RequireJsonSha256(root, "preUpgradeTreeSha256");
        RequireJsonString(root, "restoredTreeSha256", treeBefore);
        var workspaceBefore = RequireJsonSha256(
            root,
            "preUpgradeWorkspaceTreeSha256");
        RequireJsonString(root, "restoredWorkspaceTreeSha256", workspaceBefore);
        RequireJsonBoolean(root, "backupRestoreByteExactPassed", true);
        RequireJsonBoolean(root, "sourceRuntimeBootAfterRestorePassed", true);
        _ = RequireJsonStringArray(
            root,
            "sourceRuntimeAuthoritativeFilesPreservedAfterBoot",
            minimumCount: 4);
        RequireJsonEmptyArray(root, "sqliteArtifactsAfterRestoreAndBoot");
        RequireRecentLocalDataTime(root, "recordedAtUtc", report.CompletedUtc);
    }

    private static PilotLocalDataApiLaneBinding ValidateLocalDataApiLaneResult(
        string path,
        string phase,
        string expectedRuntimeArchiveSha256,
        PilotLocalDataCompatibilityEvidenceReport report)
    {
        var root = ReadLocalDataResult(path, $"{phase} API result");
        RequireOnlyJsonProperties(
            root,
            "schemaVersion", "resultType", "phase", "decision",
            "runtimeArchiveSha256", "runtimeBootPassed",
            "priorStateExpectationPassed", "sourceMarkersPreserved",
            "targetOnlyMarkerAbsentAfterRestore", "sessionCreate",
            "sessionApiResumeAppend", "conversationProviderRoundTrip",
            "sessionQuerySemanticParity", "attachment", "provider", "recordedAtUtc");
        RequireJsonInteger(root, "schemaVersion", 1);
        RequireJsonString(
            root,
            "resultType",
            "ensou-dsh-cross-runtime-api-lane-result");
        RequireJsonString(root, "phase", phase);
        RequireJsonString(root, "decision", "PASS");
        RequireJsonString(
            root,
            "runtimeArchiveSha256",
            expectedRuntimeArchiveSha256);
        RequireJsonBoolean(root, "runtimeBootPassed", true);
        RequireJsonBoolean(root, "priorStateExpectationPassed", true);
        if (phase == "target-forward")
        {
            RequireJsonBoolean(root, "sourceMarkersPreserved", true);
            if (root.TryGetProperty("targetOnlyMarkerAbsentAfterRestore", out _))
            {
                throw new InvalidDataException(
                    "Target-forward API evidence contains a restored-source-only property.");
            }
        }
        else if (phase == "source-restored")
        {
            RequireJsonBoolean(root, "targetOnlyMarkerAbsentAfterRestore", true);
            if (root.TryGetProperty("sourceMarkersPreserved", out _))
            {
                throw new InvalidDataException(
                    "Restored-source API evidence contains a target-only property.");
            }
        }
        else if (root.TryGetProperty("sourceMarkersPreserved", out _)
            || root.TryGetProperty("targetOnlyMarkerAbsentAfterRestore", out _))
        {
            throw new InvalidDataException(
                "Source-seed API evidence contains a later-phase-only property.");
        }

        var sessionCreate = RequireJsonObject(root, "sessionCreate");
        RequireOnlyJsonProperties(
            sessionCreate,
            "passed", "sessionId", "agentPreset");
        RequireJsonBoolean(sessionCreate, "passed", true);
        var sessionId = RequireJsonString(sessionCreate, "sessionId");
        RequireJsonString(sessionCreate, "agentPreset", "enterprise");
        var resume = RequireJsonObject(root, "sessionApiResumeAppend");
        RequireOnlyJsonProperties(
            resume,
            "passed", "priorStateExpectationPassed", "eventCountBefore",
            "eventCountAfter", "priorMarkersPreserved", "appendedPromptMarker",
            "appendedProviderMarker");
        RequireJsonBoolean(resume, "passed", true);
        RequireJsonBoolean(resume, "priorStateExpectationPassed", true);
        var before = RequireJsonInteger(resume, "eventCountBefore");
        var after = RequireJsonInteger(resume, "eventCountAfter");
        if (before < 0 || after <= before)
        {
            throw new InvalidDataException(
                $"{phase} API result did not append session events.");
        }
        var priorMarkers = RequireJsonStringArray(
            resume,
            "priorMarkersPreserved",
            phase == "source-seed" ? 0 : 2);
        var appendedPromptMarker = RequireJsonString(
            resume,
            "appendedPromptMarker");
        var appendedProviderMarker = RequireJsonString(
            resume,
            "appendedProviderMarker");
        var providerRoundTrip = RequireJsonObject(
            root,
            "conversationProviderRoundTrip");
        RequireOnlyJsonProperties(
            providerRoundTrip,
            "passed", "promptMarker", "responseMarker");
        RequireJsonBoolean(providerRoundTrip, "passed", true);
        RequireJsonString(
            providerRoundTrip,
            "promptMarker",
            appendedPromptMarker);
        RequireJsonString(
            providerRoundTrip,
            "responseMarker",
            appendedProviderMarker);

        var query = RequireJsonObject(root, "sessionQuerySemanticParity");
        RequireOnlyJsonProperties(
            query,
            "passed", "queryAttempted", "mode", "errorCode",
            "diagnosticClass", "messageSha256", "sessionId");
        RequireJsonBoolean(query, "passed", true);
        RequireJsonBoolean(query, "queryAttempted", true);
        RequireJsonString(
            query,
            "mode",
            "managed-disabled-public-api-policy");
        const string queryErrorCode = "internal";
        const string queryDiagnosticClass = "session-query-open-at-never";
        RequireJsonString(query, "errorCode", queryErrorCode);
        RequireJsonString(query, "diagnosticClass", queryDiagnosticClass);
        var queryMessageSha256 = RequireJsonSha256(query, "messageSha256");
        RequireJsonString(query, "sessionId", sessionId);

        var attachment = RequireJsonObject(root, "attachment");
        RequireOnlyJsonProperties(
            attachment,
            "publicApiRoundTripPassed", "attachmentId", "returnedBytes",
            "returnedSha256", "metadata", "requestImageNormalization");
        RequireJsonBoolean(attachment, "publicApiRoundTripPassed", true);
        var returnedBytes = RequireJsonInteger(attachment, "returnedBytes");
        if (returnedBytes <= 0)
        {
            throw new InvalidDataException(
                $"{phase} API result returned an empty attachment.");
        }
        var returnedSha256 = RequireJsonSha256(attachment, "returnedSha256");
        RequireJsonString(
            attachment,
            "attachmentId",
            $"sha256:{returnedSha256}");
        var attachmentMetadata = RequireJsonObject(attachment, "metadata");
        RequireOnlyJsonProperties(
            attachmentMetadata,
            "attachmentId", "mediaType", "bytes", "width", "height", "name");
        RequireJsonString(
            attachmentMetadata,
            "attachmentId",
            $"sha256:{returnedSha256}");
        RequireJsonString(attachmentMetadata, "mediaType", "image/png");
        RequireJsonInteger(attachmentMetadata, "bytes", returnedBytes);
        if (RequireJsonInteger(attachmentMetadata, "width") <= 0
            || RequireJsonInteger(attachmentMetadata, "height") <= 0)
        {
            throw new InvalidDataException(
                $"{phase} API result has invalid attachment dimensions.");
        }
        _ = RequireJsonString(attachmentMetadata, "name");
        var normalization = RequireJsonObject(
            attachment,
            "requestImageNormalization");
        RequireOnlyJsonProperties(
            normalization,
            "status", "publicPolicyRefusal", "requestImageFiles");
        RequireJsonString(
            normalization,
            "status",
            "not-applicable-managed-text-only-policy");
        var refusal = RequireJsonObject(normalization, "publicPolicyRefusal");
        RequireOnlyJsonProperties(
            refusal,
            "stage", "code", "diagnosticClass", "messageSha256",
            "provider", "model");
        var refusalStage = RequireJsonString(refusal, "stage");
        var refusalCode = RequireJsonString(refusal, "code");
        var refusalDiagnosticClass = RequireJsonString(refusal, "diagnosticClass");
        if (!((refusalStage == "select-model"
                    && refusalCode == "model-unavailable"
                    && refusalDiagnosticClass
                        == "managed-text-only-model-selection-refusal")
                || (refusalStage == "image-prompt"
                    && refusalCode == "attachment-error"
                    && refusalDiagnosticClass
                        == "managed-text-only-image-prompt-refusal")))
        {
            throw new InvalidDataException(
                $"{phase} API result has an invalid managed text-only refusal tuple.");
        }
        _ = RequireJsonSha256(refusal, "messageSha256");
        RequireJsonString(refusal, "provider", "deepseek-official");
        RequireJsonString(refusal, "model", "deepseek-v4-flash-vision-exp");
        RequireJsonEmptyArray(normalization, "requestImageFiles");

        var provider = RequireJsonObject(root, "provider");
        RequireOnlyJsonProperties(
            provider,
            "loopbackOnly", "requestCount", "chatCompletionCount",
            "fileRequestCount", "requests");
        RequireJsonBoolean(provider, "loopbackOnly", true);
        var requestCount = RequireJsonInteger(provider, "requestCount");
        var requests = RequireJsonArray(provider, "requests");
        if (requestCount <= 0
            || RequireJsonInteger(provider, "chatCompletionCount") != requestCount
            || RequireJsonInteger(provider, "fileRequestCount") != 0
            || requests.GetArrayLength() != requestCount)
        {
            throw new InvalidDataException(
                $"{phase} API result did not use the loopback fake provider as required.");
        }
        foreach (var request in requests.EnumerateArray())
        {
            RequireOnlyJsonProperties(
                request,
                "method", "path", "kind", "model", "stream", "responseMarker",
                "requestSha256", "imageProjectionCount", "imageProjections");
            RequireJsonString(request, "method", "POST");
            RequireJsonString(request, "path", "/v1/chat/completions");
            RequireJsonString(request, "kind", "chat-completions");
            RequireJsonString(request, "model", "deepseek-v4-flash");
            RequireJsonBoolean(request, "stream", true);
            RequireJsonString(request, "responseMarker", appendedProviderMarker);
            _ = RequireJsonSha256(request, "requestSha256");
            RequireJsonInteger(request, "imageProjectionCount", 0);
            RequireJsonEmptyArray(request, "imageProjections");
        }
        if (root.TryGetProperty("failure", out _))
        {
            throw new InvalidDataException(
                $"{phase} API result contains a failure object.");
        }
        RequireRecentLocalDataTime(root, "recordedAtUtc", report.CompletedUtc);
        return new PilotLocalDataApiLaneBinding(
            sessionId,
            appendedPromptMarker,
            appendedProviderMarker,
            priorMarkers,
            queryErrorCode,
            queryDiagnosticClass,
            queryMessageSha256,
            returnedSha256,
            returnedBytes);
    }

    private static JsonElement ReadLocalDataResult(string path, string field)
    {
        var bytes = ReadBounded(path, 4 * 1024 * 1024, field);
        RequireNoDuplicateJsonMembers(bytes, field);
        using var document = JsonDocument.Parse(bytes);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException($"{field} must be a JSON object.");
        }
        return document.RootElement.Clone();
    }

    private static JsonElement RequireJsonProperty(
        JsonElement value,
        string name,
        JsonValueKind kind)
    {
        if (value.ValueKind != JsonValueKind.Object
            || !value.TryGetProperty(name, out var property)
            || property.ValueKind != kind)
        {
            throw new InvalidDataException(
                $"Local-data evidence property '{name}' is missing or invalid.");
        }
        return property;
    }

    private static void RequireOnlyJsonProperties(
        JsonElement value,
        params string[] allowedNames)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                "Local-data evidence value must be a JSON object.");
        }
        var allowed = new HashSet<string>(allowedNames, StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            if (!allowed.Remove(property.Name))
            {
                throw new InvalidDataException(
                    $"Local-data evidence contains unexpected property '{property.Name}'.");
            }
        }
    }

    private static JsonElement RequireJsonObject(JsonElement value, string name) =>
        RequireJsonProperty(value, name, JsonValueKind.Object);

    private static JsonElement RequireJsonArray(JsonElement value, string name) =>
        RequireJsonProperty(value, name, JsonValueKind.Array);

    private static string RequireJsonString(JsonElement value, string name)
    {
        var result = RequireJsonProperty(value, name, JsonValueKind.String).GetString();
        if (string.IsNullOrWhiteSpace(result) || result.Length > 4096)
        {
            throw new InvalidDataException(
                $"Local-data evidence property '{name}' is empty or too long.");
        }
        return result;
    }

    private static void RequireJsonString(
        JsonElement value,
        string name,
        string expected)
    {
        if (!string.Equals(
                RequireJsonString(value, name),
                expected,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Local-data evidence property '{name}' does not match its binding.");
        }
    }

    private static string RequireJsonSha256(JsonElement value, string name)
    {
        var result = RequireJsonString(value, name);
        if (!IsLowerSha256(result))
        {
            throw new InvalidDataException(
                $"Local-data evidence property '{name}' is not lowercase SHA-256.");
        }
        return result;
    }

    private static long RequireJsonInteger(JsonElement value, string name)
    {
        var property = RequireJsonProperty(value, name, JsonValueKind.Number);
        if (!property.TryGetInt64(out var result))
        {
            throw new InvalidDataException(
                $"Local-data evidence property '{name}' is not an integer.");
        }
        return result;
    }

    private static void RequireJsonInteger(
        JsonElement value,
        string name,
        long expected)
    {
        if (RequireJsonInteger(value, name) != expected)
        {
            throw new InvalidDataException(
                $"Local-data evidence property '{name}' does not match its binding.");
        }
    }

    private static void RequireJsonBoolean(
        JsonElement value,
        string name,
        bool expected)
    {
        var property = value.ValueKind == JsonValueKind.Object
            && value.TryGetProperty(name, out var candidate)
            ? candidate
            : default;
        if (property.ValueKind is not (JsonValueKind.True or JsonValueKind.False)
            || property.GetBoolean() != expected)
        {
            throw new InvalidDataException(
                $"Local-data evidence property '{name}' does not match its binding.");
        }
    }

    private static IReadOnlyList<string> RequireJsonStringArray(
        JsonElement value,
        string name,
        int minimumCount)
    {
        var array = RequireJsonArray(value, name);
        if (array.GetArrayLength() < minimumCount || array.GetArrayLength() > 4096)
        {
            throw new InvalidDataException(
                $"Local-data evidence array '{name}' has an invalid size.");
        }
        var items = new List<string>(array.GetArrayLength());
        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (var element in array.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.String
                || string.IsNullOrWhiteSpace(element.GetString())
                || element.GetString()!.Length > 4096
                || !unique.Add(element.GetString()!))
            {
                throw new InvalidDataException(
                    $"Local-data evidence array '{name}' is not canonical.");
            }
            items.Add(element.GetString()!);
        }
        return items;
    }

    private static void RequireJsonEmptyArray(JsonElement value, string name)
    {
        if (RequireJsonArray(value, name).GetArrayLength() != 0)
        {
            throw new InvalidDataException(
                $"Local-data evidence array '{name}' must be empty.");
        }
    }

    private static void RequireRecentLocalDataTime(
        JsonElement value,
        string name,
        DateTimeOffset completedAtUtc)
    {
        var text = RequireJsonString(value, name);
        if (!DateTimeOffset.TryParse(
                text,
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.RoundtripKind,
                out var recordedAtUtc)
            || !IsRecentEvidenceTime(recordedAtUtc, completedAtUtc))
        {
            throw new InvalidDataException(
                $"Local-data evidence timestamp '{name}' is stale or inconsistent.");
        }
    }

    private sealed record PilotLocalDataEvidenceValidation(
        string OriginalPath,
        string SnapshotPath);

    private sealed record PilotLocalDataApiLaneBinding(
        string SessionId,
        string AppendedPromptMarker,
        string AppendedProviderMarker,
        IReadOnlyList<string> PriorMarkersPreserved,
        string QueryErrorCode,
        string QueryDiagnosticClass,
        string QueryMessageSha256,
        string AttachmentSha256,
        long AttachmentBytes);

    private static bool IsRecentEvidenceTime(
        DateTimeOffset recordedAtUtc,
        DateTimeOffset reportCompletedAtUtc) =>
        recordedAtUtc.Offset == TimeSpan.Zero
        && recordedAtUtc > DateTimeOffset.UtcNow.AddDays(-30)
        && recordedAtUtc <= DateTimeOffset.UtcNow.AddMinutes(5)
        && recordedAtUtc >= reportCompletedAtUtc.AddHours(-24)
        && recordedAtUtc <= reportCompletedAtUtc.AddMinutes(5);

    private static bool IsCanonicalUpstreamTag(string value) =>
        value is { Length: >= 6 and <= 128 }
        && value.StartsWith("dsh-v", StringComparison.Ordinal)
        && value[5..].All(character => char.IsAsciiLetterOrDigit(character)
            || character is '.' or '_' or '+' or '-');

    private static bool IsLowerSha256(string value) =>
        value is { Length: 64 }
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static PublisherRuntimeAdmissionTrust RequireRuntimeAdmissionTrust(
        PilotReadinessConfig config,
        PublisherRuntimeAdmissionTrust? suppliedTrust)
    {
        var compiled = suppliedTrust ?? PublisherRuntimeAdmissionTrustResolver.ResolveProduction();
        compiled.Validate();
        if (!string.Equals(compiled.KeyId, config.RuntimeAdmissionKey.KeyId, StringComparison.Ordinal)
            || !string.Equals(compiled.X, config.RuntimeAdmissionKey.X, StringComparison.Ordinal)
            || !string.Equals(compiled.Y, config.RuntimeAdmissionKey.Y, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Pilot runtime-admission key does not match the production publisher trust root.");
        }
        if (string.Equals(compiled.KeyId, config.LauncherTrust.ReleaseKeyId, StringComparison.Ordinal)
            || string.Equals(compiled.KeyId, config.LauncherTrust.LeaseKeyId, StringComparison.Ordinal)
            || (string.Equals(compiled.X, config.LauncherTrust.ReleaseKeyX, StringComparison.Ordinal)
                && string.Equals(compiled.Y, config.LauncherTrust.ReleaseKeyY, StringComparison.Ordinal))
            || (string.Equals(compiled.X, config.LauncherTrust.LeaseKeyX, StringComparison.Ordinal)
                && string.Equals(compiled.Y, config.LauncherTrust.LeaseKeyY, StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "Runtime-admission, release, and lease trust roots must be independent.");
        }
        return compiled;
    }

    private static PublisherBrandAuthorizationTrust RequireBrandAuthorizationTrust(
        PilotReadinessConfig config,
        PublisherRuntimeAdmissionTrust runtimeAdmissionTrust,
        PublisherBrandAuthorizationTrust? suppliedTrust)
    {
        var compiled = suppliedTrust
            ?? PublisherBrandAuthorizationTrustResolver.ResolveProduction();
        compiled.Validate();
        if (!string.Equals(
                compiled.KeyId,
                config.BrandAuthorizationKey.KeyId,
                StringComparison.Ordinal)
            || !string.Equals(
                compiled.X,
                config.BrandAuthorizationKey.X,
                StringComparison.Ordinal)
            || !string.Equals(
                compiled.Y,
                config.BrandAuthorizationKey.Y,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Pilot brand-authorization key does not match the production publisher trust root.");
        }
        compiled.RequireIndependentFrom(runtimeAdmissionTrust, config.LauncherTrust);
        return compiled;
    }

    private static PublisherPluginAdmissionTrust RequirePluginAdmissionTrust(
        PublisherPluginAdmissionTrust? suppliedTrust)
    {
        var compiled = suppliedTrust ?? PublisherPluginAdmissionTrustResolver.ResolveProduction();
        compiled.Validate();
        return compiled;
    }

    private static PublisherLeaseVerificationTrust RequireLeaseVerificationTrust(
        PilotReadinessConfig config,
        PublisherLeaseVerificationTrust? suppliedTrust)
    {
        var compiled = suppliedTrust ?? PublisherLeaseVerificationTrustResolver.ResolveProduction();
        compiled.Validate();
        if (!string.Equals(
                compiled.KeyId,
                config.LauncherTrust.LeaseKeyId,
                StringComparison.Ordinal)
            || !string.Equals(
                compiled.X,
                config.LauncherTrust.LeaseKeyX,
                StringComparison.Ordinal)
            || !string.Equals(
                compiled.Y,
                config.LauncherTrust.LeaseKeyY,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Compiled Publisher lease trust does not match the Launcher's production lease root.");
        }
        return compiled;
    }

    private static PublisherLocalDataCompatibilityCertificationTrust
        RequireLocalDataCertificationTrust(
            PilotReadinessConfig config,
            PublisherRuntimeAdmissionTrust runtimeAdmissionTrust,
            PublisherPluginAdmissionTrust pluginAdmissionTrust,
            PublisherBrandAuthorizationTrust brandAuthorizationTrust,
            PublisherLeaseVerificationTrust leaseVerificationTrust,
            PublisherLocalDataCompatibilityCertificationTrust? suppliedTrust)
    {
        var compiled = suppliedTrust
            ?? PublisherLocalDataCompatibilityCertificationTrustResolver.ResolveProduction();
        compiled.RequireIndependentFrom(
            runtimeAdmissionTrust,
            pluginAdmissionTrust,
            brandAuthorizationTrust,
            leaseVerificationTrust,
            config.LauncherTrust.ReleaseKeyId,
            config.LauncherTrust.ReleaseKeyX,
            config.LauncherTrust.ReleaseKeyY);
        return compiled;
    }

    private static PilotReleaseSetFiles ValidateReleaseSet(
        PilotReadinessConfig config,
        PilotReadinessInputSnapshot snapshot)
    {
        var manifestPath = snapshot.ReleaseManifestPath;
        var publicKeyPath = snapshot.ReleasePublicKeyPath;
        PublisherPathGuard.RequireSafeExistingFile(manifestPath);
        PublisherPathGuard.RequireSafeExistingFile(publicKeyPath);
        var manifestBytes = ReadBounded(manifestPath, 512 * 1024, "release-set manifest");
        var keyBytes = ReadBounded(publicKeyPath, 64 * 1024, "release public key");
        RequireNoDuplicateJsonMembers(manifestBytes, "release-set manifest");
        RequireNoDuplicateJsonMembers(keyBytes, "release public key");
        var manifest = EnterpriseReleaseSetManifest.Parse(manifestBytes);
        var publicKey = JsonSerializer.Deserialize<EnterpriseReleasePublicKey>(keyBytes, JsonOptions)
            ?? throw new InvalidDataException("Release public key file is empty.");
        if (!string.Equals(publicKey.KeyId, config.LauncherTrust.ReleaseKeyId, StringComparison.Ordinal)
            || !string.Equals(publicKey.X, config.LauncherTrust.ReleaseKeyX, StringComparison.Ordinal)
            || !string.Equals(publicKey.Y, config.LauncherTrust.ReleaseKeyY, StringComparison.Ordinal)
            || !string.Equals(manifest.Channel, config.Channel, StringComparison.Ordinal)
            || !string.Equals(manifest.ReleaseSetId, config.ReleaseSetId, StringComparison.Ordinal)
            || manifest.Generation != config.Generation
            || manifest.Sequence != config.Sequence
            || manifest.MinAcceptedSequence != config.MinAcceptedSequence
            || manifest.PluginPolicy is null
            || manifest.Artifacts.Count != 3)
        {
            throw new InvalidDataException(
                "Signed release-set does not match the exact Pilot readiness identity.");
        }
        var policy = new EnterpriseReleaseTrustPolicy
        {
            Product = EnterpriseReleaseSetContract.Product,
            Environment = EnterpriseReleaseSetContract.ProductionEnvironment,
            ExpectedChannel = config.Channel,
            CurrentStartupStubProtocol =
                EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
            ManifestOrigin = new Uri(config.LauncherTrust.UpdateManifestOrigin, UriKind.Absolute),
            ArtifactOrigin = new Uri(config.LauncherTrust.UpdateArtifactOrigin, UriKind.Absolute),
            TrustedKeys = [publicKey],
        };
        EnterpriseReleaseSetValidator.Verify(manifest, policy, DateTimeOffset.UtcNow);

        var localArtifacts = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var artifact in manifest.Artifacts)
        {
            var fileName = Path.GetFileName(artifact.Uri.AbsolutePath);
            PublisherPathGuard.RequireSafeArtifactFileName(fileName, "Pilot artifact URI filename");
            if (!snapshot.ReleaseArtifacts.TryGetValue(artifact.Component, out var path))
            {
                throw new InvalidDataException(
                    "Pilot immutable snapshot is missing a signed artifact component.");
            }
            PublisherPathGuard.RequireSafeExistingFile(path);
            var info = new FileInfo(path);
            if (info.Length != artifact.SizeBytes
                || !string.Equals(HashFile(path), artifact.Sha256, StringComparison.Ordinal)
                || !localArtifacts.TryAdd(artifact.Component, path))
            {
                throw new InvalidDataException(
                    "Pilot artifact bytes do not match the signed release-set.");
            }
        }
        return new PilotReleaseSetFiles(
            manifest,
            HashBytes(manifestBytes),
            localArtifacts[EnterpriseReleaseSetContract.LauncherComponent],
            localArtifacts[EnterpriseReleaseSetContract.RuntimeComponent],
            localArtifacts[EnterpriseReleaseSetContract.PluginPolicyComponent]);
    }

    private static string ValidatePublisherLedger(
        PilotReadinessConfig config,
        PilotReleaseSetFiles release,
        string publisherLedgerPath)
    {
        PublisherPathGuard.RequireSafeExistingFile(publisherLedgerPath);
        var bytes = ReadBounded(publisherLedgerPath, 128 * 1024, "publisher ledger");
        RequireNoDuplicateJsonMembers(bytes, "publisher ledger");
        if (!string.Equals(
                HashBytes(bytes),
                config.PublisherLedgerSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("Publisher feed-head ledger SHA-256 changed.");
        }
        var ledger = JsonSerializer.Deserialize<PublisherLedger>(bytes, JsonOptions)
            ?? throw new InvalidDataException("Publisher feed-head ledger is empty.");
        var manifestPayloadSha256 = HashBytes(
            EnterpriseReleaseCanonicalJson.ManifestPayload(release.Manifest));
        if (ledger.SchemaVersion != 2
            || !string.Equals(
                ledger.Environment,
                EnterpriseReleaseSetContract.ProductionEnvironment,
                StringComparison.Ordinal)
            || !string.Equals(ledger.Channel, config.Channel, StringComparison.Ordinal)
            || ledger.HighestGeneration != release.Manifest.Generation
            || ledger.HighestSequence != release.Manifest.Sequence
            || ledger.MinAcceptedSequence != release.Manifest.MinAcceptedSequence
            || !string.Equals(
                ledger.ReleaseSetId,
                release.Manifest.ReleaseSetId,
                StringComparison.Ordinal)
            || !string.Equals(
                ledger.ManifestPayloadSha256,
                manifestPayloadSha256,
                StringComparison.Ordinal)
            || ledger.PublishedAtUtc.Offset != TimeSpan.Zero
            || ledger.PublishedAtUtc <= DateTimeOffset.UtcNow.AddDays(-30)
            || ledger.PublishedAtUtc > DateTimeOffset.UtcNow.AddMinutes(5))
        {
            throw new InvalidDataException(
                "Signed release-set is not the exact current production publisher feed head.");
        }
        return $"{ledger.ReleaseSetId}:{ledger.HighestSequence}:{config.PublisherLedgerSha256}";
    }

    private static void RequireLauncherArtifactBinding(
        string launcherArchivePath,
        string launcherExecutablePath,
        string clientBootstrapperExecutablePath,
        string maintenanceExecutablePath,
        string launcherBuildProfilePath)
    {
        PublisherPathGuard.RequireSafeExistingFile(launcherArchivePath);
        PublisherPathGuard.RequireSafeExistingFile(launcherExecutablePath);
        PublisherPathGuard.RequireSafeExistingFile(clientBootstrapperExecutablePath);
        PublisherPathGuard.RequireSafeExistingFile(maintenanceExecutablePath);
        PublisherPathGuard.RequireSafeExistingFile(launcherBuildProfilePath);
        using var archive = ZipFile.OpenRead(launcherArchivePath);
        RequireArchiveExecutableBinding(
            archive,
            EnterpriseInstallationLayout.LauncherExecutableName,
            launcherExecutablePath);
        RequireArchiveExecutableBinding(
            archive,
            EnterpriseInstallationLayout.ClientBootstrapperExecutableName,
            clientBootstrapperExecutablePath);
        RequireArchiveExecutableBinding(
            archive,
            EnterpriseInstallationLayout.MaintenanceExecutableName,
            maintenanceExecutablePath);
        var markerEntry = RequireExactRootArchiveEntry(
            archive,
            EnterpriseInstallationLayout.BuildProfileMarkerFileName);
        RequireArchiveFileBinding(
            markerEntry,
            launcherBuildProfilePath,
            EnterpriseInstallationLayout.BuildProfileMarkerFileName);
        using var markerStream = markerEntry.Open();
        using var markerOutput = new MemoryStream();
        markerStream.CopyTo(markerOutput);
        if (markerOutput.Length is <= 0 or > 4096)
        {
            throw new InvalidDataException("Launcher build-profile marker size is invalid.");
        }
        var marker = JsonSerializer.Deserialize<PilotBuildProfileMarker>(
            markerOutput.ToArray(),
            JsonOptions) ?? throw new InvalidDataException("Launcher build-profile marker is empty.");
        if (marker.SchemaVersion != 1
            || !string.Equals(
                marker.LayoutProfile,
                EnterpriseInstallationLayout.ProductionLayoutProfile,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("Launcher archive is not the production layout profile.");
        }
    }

    private static void RequireArchiveExecutableBinding(
        ZipArchive archive,
        string entryName,
        string executablePath)
    {
        var entry = RequireExactRootArchiveEntry(archive, entryName);
        RequireArchiveFileBinding(entry, executablePath, entryName);
    }

    private static void RequireArchiveFileBinding(
        ZipArchiveEntry entry,
        string publishedPath,
        string entryName)
    {
        var published = new FileInfo(publishedPath);
        if (entry.Length != published.Length)
        {
            throw new InvalidDataException(
                $"Signed Launcher archive {entryName} size is not the published file size.");
        }
        using var entryStream = entry.Open();
        if (!string.Equals(
                HashStream(entryStream, entry.Length),
                HashFile(publishedPath),
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Signed Launcher archive {entryName} is not the published file bytes.");
        }
    }

    private static ZipArchiveEntry RequireExactRootArchiveEntry(
        ZipArchive archive,
        string entryName)
    {
        var entries = archive.Entries.Where(entry => string.Equals(
            entry.FullName.Replace('\\', '/'),
            entryName,
            StringComparison.OrdinalIgnoreCase)).ToArray();
        if (entries.Length != 1
            || !string.Equals(
                entries[0].FullName.Replace('\\', '/'),
                entryName,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Signed Launcher archive must contain one exact root entry: {entryName}.");
        }
        return entries[0];
    }

    private static T RunCheck<T>(
        List<PilotReadinessCheck> checks,
        string id,
        Func<T> action,
        Func<T, string> evidence)
    {
        try
        {
            var value = action();
            checks.Add(new PilotReadinessCheck(id, "PASS", evidence(value)));
            return value;
        }
        catch (PilotReadinessException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException
            or CryptographicException
            or InvalidDataException
            or InvalidOperationException
            or IOException
            or JsonException
            or UnauthorizedAccessException)
        {
            throw new PilotReadinessException(
                id,
                exception.Message,
                exception,
                checks.ToArray());
        }
    }

    private static byte[] ReadBounded(string path, int maximumBytes, string field)
    {
        var info = new FileInfo(path);
        if (info.Length is <= 0 || info.Length > maximumBytes)
        {
            throw new InvalidDataException($"Pilot {field} size is invalid.");
        }
        return File.ReadAllBytes(path);
    }

    private static string HashFile(string path)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            1024 * 1024,
            FileOptions.SequentialScan);
        return HashStream(stream, stream.Length);
    }

    private static string HashStream(Stream stream, long expectedLength)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        long total = 0;
        while (true)
        {
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                break;
            }
            total = checked(total + read);
            if (total > expectedLength)
            {
                throw new IOException("Pilot artifact grew while it was hashed.");
            }
            hash.AppendData(buffer, 0, read);
        }
        if (total != expectedLength)
        {
            throw new IOException("Pilot artifact length changed while it was hashed.");
        }
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static string HashBytes(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static void RequireNoDuplicateJsonMembers(byte[] bytes, string field)
    {
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
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"Pilot {field} JSON is invalid.", exception);
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
                        "Pilot readiness JSON contains a duplicate member.");
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

    private sealed class PilotReadinessInputSnapshot : IDisposable
    {
        private readonly PublisherInputStaging _staging;

        private PilotReadinessInputSnapshot(
            PublisherInputStaging staging,
            string snapshotId,
            string releaseManifestPath,
            string releasePublicKeyPath,
            IReadOnlyDictionary<string, string> releaseArtifacts,
            string publisherLedgerPath,
            string runtimeSourceMetadataPath,
            string runtimeAdmissionReceiptPath,
            string pluginPolicyMetadataPath,
            string brandAuthorizationReceiptPath,
            string brandAuthorizationEvidencePath,
            string dataMigrationReportPath,
            string localDataCertificationReceiptPath,
            string originalDataMigrationReportPath,
            IReadOnlyDictionary<string, string> migrationEvidencePaths,
            string installerExecutablePath,
            string bootstrapperExecutablePath,
            string launcherExecutablePath,
            string clientBootstrapperExecutablePath,
            string maintenanceExecutablePath,
            string launcherBuildProfilePath,
            IReadOnlyList<PilotSnapshotOriginal> originals)
        {
            _staging = staging;
            SnapshotId = snapshotId;
            ReleaseManifestPath = releaseManifestPath;
            ReleasePublicKeyPath = releasePublicKeyPath;
            ReleaseArtifacts = releaseArtifacts;
            PublisherLedgerPath = publisherLedgerPath;
            RuntimeSourceMetadataPath = runtimeSourceMetadataPath;
            RuntimeAdmissionReceiptPath = runtimeAdmissionReceiptPath;
            PluginPolicyMetadataPath = pluginPolicyMetadataPath;
            BrandAuthorizationReceiptPath = brandAuthorizationReceiptPath;
            BrandAuthorizationEvidencePath = brandAuthorizationEvidencePath;
            DataMigrationReportPath = dataMigrationReportPath;
            LocalDataCertificationReceiptPath = localDataCertificationReceiptPath;
            OriginalDataMigrationReportPath = originalDataMigrationReportPath;
            MigrationEvidencePaths = migrationEvidencePaths;
            InstallerExecutablePath = installerExecutablePath;
            BootstrapperExecutablePath = bootstrapperExecutablePath;
            LauncherExecutablePath = launcherExecutablePath;
            ClientBootstrapperExecutablePath = clientBootstrapperExecutablePath;
            MaintenanceExecutablePath = maintenanceExecutablePath;
            LauncherBuildProfilePath = launcherBuildProfilePath;
            Originals = originals;
        }

        public string SnapshotId { get; }
        public string ReleaseManifestPath { get; }
        public string ReleasePublicKeyPath { get; }
        public IReadOnlyDictionary<string, string> ReleaseArtifacts { get; }
        public string PublisherLedgerPath { get; }
        public string RuntimeSourceMetadataPath { get; }
        public string RuntimeAdmissionReceiptPath { get; }
        public string PluginPolicyMetadataPath { get; }
        public string BrandAuthorizationReceiptPath { get; }
        public string BrandAuthorizationEvidencePath { get; }
        public string DataMigrationReportPath { get; }
        public string LocalDataCertificationReceiptPath { get; }
        public string OriginalDataMigrationReportPath { get; }
        public IReadOnlyDictionary<string, string> MigrationEvidencePaths { get; }
        public string InstallerExecutablePath { get; }
        public string BootstrapperExecutablePath { get; }
        public string LauncherExecutablePath { get; }
        public string ClientBootstrapperExecutablePath { get; }
        public string MaintenanceExecutablePath { get; }
        public string LauncherBuildProfilePath { get; }
        private IReadOnlyList<PilotSnapshotOriginal> Originals { get; }

        public static PilotReadinessInputSnapshot Capture(
            PilotReadinessConfig config,
            string configPath,
            string expectedConfigSha256)
        {
            var staging = PublisherInputStaging.Create();
            try
            {
                var originals = new List<PilotSnapshotOriginal>();
                PublisherStagedInputFile CaptureFile(string path)
                {
                    var originalPath = Path.GetFullPath(path);
                    var stagedFile = staging.Capture(originalPath);
                    originals.Add(new PilotSnapshotOriginal(
                        originalPath,
                        stagedFile.Length,
                        stagedFile.Sha256));
                    return stagedFile;
                }

                if (!IsLowerSha256(expectedConfigSha256))
                {
                    throw new InvalidDataException(
                        "Pilot readiness config identity is invalid.");
                }
                var configFile = CaptureFile(configPath);
                if (!string.Equals(
                        configFile.Sha256,
                        expectedConfigSha256,
                        StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "Pilot readiness config changed between validation and immutable capture.");
                }
                var releaseRoot = Path.GetFullPath(config.ReleaseDirectory);
                PublisherPathGuard.RequireSafeExistingDirectory(releaseRoot);
                var manifestFile = CaptureFile(Path.Combine(
                    releaseRoot,
                    "release-set.v2.json"));
                var publicKeyFile = CaptureFile(Path.Combine(
                    releaseRoot,
                    "release-public-key.v2.json"));
                var manifestBytes = manifestFile.ReadAllBytes(512 * 1024);
                RequireNoDuplicateJsonMembers(manifestBytes, "release-set manifest");
                var manifest = EnterpriseReleaseSetManifest.Parse(manifestBytes);
                var artifacts = new Dictionary<string, string>(StringComparer.Ordinal);
                foreach (var artifact in manifest.Artifacts)
                {
                    var fileName = Path.GetFileName(artifact.Uri.AbsolutePath);
                    PublisherPathGuard.RequireSafeArtifactFileName(
                        fileName,
                        "Pilot artifact URI filename");
                    var staged = CaptureFile(Path.Combine(releaseRoot, fileName));
                    if (!artifacts.TryAdd(artifact.Component, staged.StagedPath))
                    {
                        throw new InvalidDataException(
                            "Signed release-set repeats an artifact component.");
                    }
                }

                var ledger = CaptureFile(config.PublisherLedgerPath);
                var runtimeMetadata = CaptureFile(config.RuntimeSourceMetadataPath);
                var runtimeReceipt = CaptureFile(config.RuntimeAdmissionReceiptPath);
                var pluginMetadata = CaptureFile(config.PluginPolicyMetadataPath);
                var brandAuthorizationReceipt = CaptureFile(
                    config.BrandAuthorization.ReceiptPath);
                var brandAuthorizationEvidence = CaptureFile(
                    config.BrandAuthorization.EvidencePath);
                var localDataReportOriginalPath = Path.GetFullPath(
                    config.LocalDataCompatibilityEvidence.ReportPath);
                var migrationReport = CaptureFile(localDataReportOriginalPath);
                var localDataCertificationReceipt = CaptureFile(
                    config.LocalDataCompatibilityEvidence.Certification.ReceiptPath);
                if (!string.Equals(
                        localDataCertificationReceipt.Sha256,
                        config.LocalDataCompatibilityEvidence.Certification.ReceiptSha256,
                        StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "Local-data certification receipt changed before immutable capture.");
                }
                var migrationBytes = migrationReport.ReadAllBytes(4 * 1024 * 1024);
                RequireNoDuplicateJsonMembers(
                    migrationBytes,
                    "local-data compatibility evidence");
                var migration = JsonSerializer.Deserialize<
                    PilotLocalDataCompatibilityEvidenceReport>(
                        migrationBytes,
                        JsonOptions) ?? throw new InvalidDataException(
                            "Local-data compatibility evidence report is empty.");
                if (migration.ApiLanes is null || migration.Artifacts is null)
                {
                    throw new InvalidDataException(
                        "Local-data compatibility evidence is missing API lanes or artifacts.");
                }
                var migrationPaths = new Dictionary<string, string>(
                    StringComparer.OrdinalIgnoreCase);
                var migrationReferences = new List<PilotLocalDataEvidenceFile>
                {
                    migration.TestRunner,
                    migration.HistoricalFixture,
                    migration.PreUpgradeBackup,
                    migration.ForwardResult,
                    migration.RollbackResult,
                    migration.Transcript,
                    migration.ApiLanes.SourceSeed,
                    migration.ApiLanes.TargetForward,
                    migration.ApiLanes.SourceRestored,
                };
                migrationReferences.AddRange(migration.Artifacts);
                var declaredReferences = new Dictionary<
                    string,
                    PilotLocalDataEvidenceFile>(StringComparer.OrdinalIgnoreCase);
                foreach (var evidence in migrationReferences)
                {
                    if (evidence is null
                        || string.IsNullOrWhiteSpace(evidence.Path)
                        || !IsLowerSha256(evidence.Sha256)
                        || evidence.Bytes < 0)
                    {
                        throw new InvalidDataException(
                            "Local-data evidence contains an invalid file reference.");
                    }
                    var original = ResolveLocalDataEvidencePath(
                        localDataReportOriginalPath,
                        evidence.Path);
                    if (declaredReferences.TryGetValue(original, out var existing))
                    {
                        if (existing.Bytes != evidence.Bytes
                            || !string.Equals(
                                existing.Sha256,
                                evidence.Sha256,
                                StringComparison.Ordinal))
                        {
                            throw new InvalidDataException(
                                "Local-data evidence repeats a path with conflicting bytes.");
                        }
                        continue;
                    }
                    var staged = CaptureFile(original);
                    if (staged.Length != evidence.Bytes
                        || !string.Equals(
                            staged.Sha256,
                            evidence.Sha256,
                            StringComparison.Ordinal)
                        || !migrationPaths.TryAdd(original, staged.StagedPath)
                        || !declaredReferences.TryAdd(original, evidence))
                    {
                        throw new InvalidDataException(
                            "Local-data evidence reference does not match captured bytes.");
                    }
                }

                var installer = CaptureFile(config.InstallerExecutablePath);
                var launcher = CaptureFile(config.LauncherExecutablePath);
                var bootstrapper = CaptureFile(config.BootstrapperExecutablePath);
                var clientBootstrapper = CaptureFile(
                    config.ClientBootstrapperExecutablePath);
                var maintenance = CaptureFile(config.MaintenanceExecutablePath);
                var launcherBuildProfilePath = Path.Combine(
                    Path.GetDirectoryName(Path.GetFullPath(config.LauncherExecutablePath))!,
                    EnterpriseInstallationLayout.BuildProfileMarkerFileName);
                var launcherBuildProfile = staging.CaptureAlongside(
                    launcher,
                    launcherBuildProfilePath);
                originals.Add(new PilotSnapshotOriginal(
                    Path.GetFullPath(launcherBuildProfilePath),
                    launcherBuildProfile.Length,
                    launcherBuildProfile.Sha256));
                var bootstrapperBuildProfilePath = Path.Combine(
                    Path.GetDirectoryName(Path.GetFullPath(config.BootstrapperExecutablePath))!,
                    EnterpriseInstallationLayout.BuildProfileMarkerFileName);
                var bootstrapperBuildProfile = staging.CaptureAlongside(
                    bootstrapper,
                    bootstrapperBuildProfilePath);
                originals.Add(new PilotSnapshotOriginal(
                    Path.GetFullPath(bootstrapperBuildProfilePath),
                    bootstrapperBuildProfile.Length,
                    bootstrapperBuildProfile.Sha256));
                var identityBytes = Encoding.UTF8.GetBytes(string.Join(
                    '\n',
                    configFile.Sha256,
                    manifestFile.Sha256,
                    publicKeyFile.Sha256,
                    ledger.Sha256,
                    runtimeMetadata.Sha256,
                    runtimeReceipt.Sha256,
                    pluginMetadata.Sha256,
                    brandAuthorizationReceipt.Sha256,
                    brandAuthorizationEvidence.Sha256,
                    migrationReport.Sha256,
                    localDataCertificationReceipt.Sha256,
                    installer.Sha256,
                    bootstrapper.Sha256,
                    bootstrapperBuildProfile.Sha256,
                    launcher.Sha256,
                    clientBootstrapper.Sha256,
                    maintenance.Sha256,
                    launcherBuildProfile.Sha256));
                var snapshotId = HashBytes(identityBytes);
                return new PilotReadinessInputSnapshot(
                    staging,
                    snapshotId,
                    manifestFile.StagedPath,
                    publicKeyFile.StagedPath,
                    artifacts,
                    ledger.StagedPath,
                    runtimeMetadata.StagedPath,
                    runtimeReceipt.StagedPath,
                    pluginMetadata.StagedPath,
                    brandAuthorizationReceipt.StagedPath,
                    brandAuthorizationEvidence.StagedPath,
                    migrationReport.StagedPath,
                    localDataCertificationReceipt.StagedPath,
                    localDataReportOriginalPath,
                    migrationPaths,
                    installer.StagedPath,
                    bootstrapper.StagedPath,
                    launcher.StagedPath,
                    clientBootstrapper.StagedPath,
                    maintenance.StagedPath,
                    launcherBuildProfile.StagedPath,
                    originals);
            }
            catch
            {
                staging.Dispose();
                throw;
            }
        }

        public void RequireOriginalsUnchanged()
        {
            foreach (var original in Originals)
            {
                PublisherPathGuard.RequireSafeExistingFile(original.Path);
                var info = new FileInfo(original.Path);
                if (info.Length != original.Length
                    || !string.Equals(
                        HashFile(original.Path),
                        original.Sha256,
                        StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "A Pilot readiness source input changed after its immutable snapshot was captured.");
                }
            }
        }

        public void Dispose() => _staging.Dispose();
    }

    private sealed record PilotSnapshotOriginal(string Path, long Length, string Sha256);

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record PilotBuildProfileMarker
    {
        public required int SchemaVersion { get; init; }
        public required string LayoutProfile { get; init; }
    }

    private sealed record PilotReleaseSetFiles(
        EnterpriseReleaseSetManifest Manifest,
        string ManifestSha256,
        string LauncherArchivePath,
        string RuntimeArchivePath,
        string PluginPolicyArchivePath);
}

internal static class EnterprisePilotReadinessCommand
{
    private static readonly JsonSerializerOptions ReportJsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public static int Run(string[] args)
    {
        PilotReadinessArguments arguments;
        try
        {
            arguments = PilotReadinessArguments.Parse(args);
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"Pilot readiness arguments failed: {exception.Message}");
            return 2;
        }

        var checks = new List<PilotReadinessCheck>();
        PilotReadinessReport report;
        var publisherExecutableSha256 = ComputePublisherExecutableSha256();
        try
        {
            var result = EnterprisePilotReadinessValidator.Validate(arguments.ConfigPath);
            checks.AddRange(result.Checks);
            report = new PilotReadinessReport
            {
                SchemaVersion = PilotReadinessReport.CurrentSchemaVersion,
                ReportType = PilotReadinessReport.CurrentReportType,
                Decision = "ADMIT",
                GeneratedAtUtc = DateTimeOffset.UtcNow,
                Environment = result.Config.Environment,
                Channel = result.Config.Channel,
                PublisherExecutableSha256 = publisherExecutableSha256,
                ReleaseSetId = result.Config.ReleaseSetId,
                Generation = result.Config.Generation,
                Sequence = result.Config.Sequence,
                UpdateContractId = EnterpriseProductionTrustFingerprint.PilotUpdateContractId,
                BrandAuthorizationId = result.BrandAuthorization.AuthorizationId,
                BrandAuthorizationKeyId = result.BrandAuthorization.KeyId,
                BrandAuthorizationReceiptSha256 =
                    result.BrandAuthorization.ReceiptSha256,
                BrandAuthorizationExpiresAtUtc =
                    result.BrandAuthorization.ExpiresAtUtc,
                LocalDataCertificationId =
                    result.LocalDataCertification.CertificationId,
                LocalDataCertificationKeyId =
                    result.LocalDataCertification.KeyId,
                LocalDataCertificationReceiptSha256 =
                    result.LocalDataCertification.ReceiptSha256,
                LocalDataCertificationExpiresAtUtc =
                    result.LocalDataCertification.ExpiresAtUtc,
                Checks = checks,
                FailureCode = null,
                FailureMessage = null,
            };
        }
        catch (PilotReadinessException exception)
        {
            checks.AddRange(exception.CompletedChecks);
            checks.Add(new PilotReadinessCheck(exception.Code, "FAIL", "fail-closed"));
            report = RejectedReport(
                checks,
                exception.Code,
                exception.Message,
                publisherExecutableSha256);
        }
        catch (Exception exception)
        {
            const string failureCode = "unexpected-validation-failure";
            checks.Add(new PilotReadinessCheck(failureCode, "FAIL", "fail-closed"));
            report = RejectedReport(
                checks,
                failureCode,
                exception.Message,
                publisherExecutableSha256);
        }

        if (arguments.EmitReportToStandardOutput)
        {
            Console.Out.Write(JsonSerializer.Serialize(report, ReportJsonOptions));
        }
        else
        {
            WriteReportAtomically(
                arguments.ReportPath
                    ?? throw new InvalidOperationException(
                        "Pilot readiness report path is unavailable."),
                report);
        }
        if (report.Decision == "ADMIT")
        {
            if (!arguments.EmitReportToStandardOutput)
            {
                Console.WriteLine("Enterprise Pilot readiness admitted; machine report written.");
            }
            return 0;
        }
        Console.Error.WriteLine(
            $"Enterprise Pilot readiness rejected: {report.FailureCode}: {report.FailureMessage}");
        return 1;
    }

    private static PilotReadinessReport RejectedReport(
        IReadOnlyList<PilotReadinessCheck> checks,
        string code,
        string message,
        string publisherExecutableSha256) => new()
        {
            SchemaVersion = PilotReadinessReport.CurrentSchemaVersion,
            ReportType = PilotReadinessReport.CurrentReportType,
            Decision = "REJECT",
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            Environment = "production",
            Channel = "pilot",
            PublisherExecutableSha256 = publisherExecutableSha256,
            ReleaseSetId = null,
            Generation = null,
            Sequence = null,
            UpdateContractId = EnterpriseProductionTrustFingerprint.PilotUpdateContractId,
            BrandAuthorizationId = null,
            BrandAuthorizationKeyId = null,
            BrandAuthorizationReceiptSha256 = null,
            BrandAuthorizationExpiresAtUtc = null,
            LocalDataCertificationId = null,
            LocalDataCertificationKeyId = null,
            LocalDataCertificationReceiptSha256 = null,
            LocalDataCertificationExpiresAtUtc = null,
            Checks = checks,
            FailureCode = code,
            FailureMessage = $"Pilot readiness check '{code}' failed closed.",
        };

    private static string ComputePublisherExecutableSha256()
    {
        var path = Environment.ProcessPath
            ?? throw new InvalidOperationException(
                "ReleasePublisher executable identity is unavailable.");
        PublisherPathGuard.RequireSafeExistingFile(path);
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            1024 * 1024,
            FileOptions.SequentialScan);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    private static void WriteReportAtomically(string path, PilotReadinessReport report)
    {
        PublisherPathGuard.RequireSafeDestination(path);
        var parent = Path.GetDirectoryName(path)
            ?? throw new InvalidDataException("Pilot readiness report path has no parent directory.");
        Directory.CreateDirectory(parent);
        PublisherPathGuard.RequireSafeExistingDirectory(parent);
        var temporary = Path.Combine(
            parent,
            $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(report, ReportJsonOptions);
            using (var stream = new FileStream(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       64 * 1024,
                       FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: false);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }
}
