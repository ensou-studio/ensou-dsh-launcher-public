using System.Net;
using System.Diagnostics;
using System.IO.Compression;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Enterprise.Client;
using Ensou.Dsh.Enterprise.Contracts;
using Ensou.Dsh.Enterprise.FeedPromoter;
using Ensou.Dsh.Enterprise.Installation;
using Ensou.Dsh.Enterprise.Launcher;
using Ensou.Dsh.Host;

namespace Ensou.Dsh.Enterprise.DevelopmentE2ETests;

[SupportedOSPlatform("windows")]
internal static partial class Program
{
    private static readonly Uri SignedLabManifestUri = new(
        "https://updates.example/v2/channels/lab/release-set.v2.json");
    private static readonly Uri DevelopmentArtifactOrigin = new(
        "https://updates.example/");
    private const string DevelopmentReleaseKeyId = "lifecycle-key";
    private const string DevelopmentMachineFailurePrefix =
        "ENSOU_DSH_E2E_MACHINE_FAILURE_V1";
    private const int MaximumDevelopmentMachineStandardErrorLength = 2048;
    private const int MaximumDevelopmentMachineFailureMessageLength = 512;
    private const string DevelopmentFixtureInputDirectoryName =
        ".ensou-dsh-enterprise-development-e2e-inputs";

    public static async Task<int> Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("The enterprise Development E2E runner requires Windows.");
            return 2;
        }

        RunnerOptions? options = null;
        try
        {
            options = RunnerOptions.Parse(args);
            object evidence = options.Phase switch
            {
                RunnerPhase.ArtifactFixtureContract => RunArtifactFixtureContract(options),
                RunnerPhase.HttpsArtifactFixtureContract =>
                    await DevelopmentHttpsArtifactServerTests.RunAsync().ConfigureAwait(false),
                RunnerPhase.InstallPluginPolicy =>
                    await RunInstallPluginPolicyAsync(options).ConfigureAwait(false),
                RunnerPhase.EnrollChat => await RunEnrollChatAsync(options).ConfigureAwait(false),
                RunnerPhase.RefreshChat => await RunRefreshChatAsync(options).ConfigureAwait(false),
                RunnerPhase.ApplyReleaseUpdate =>
                    await RunApplyReleaseUpdateAsync(options).ConfigureAwait(false),
                RunnerPhase.PrepareLauncherUpdate =>
                    await RunPrepareLauncherUpdateAsync(options).ConfigureAwait(false),
                RunnerPhase.AutomaticReleaseUpdate =>
                    await RunAutomaticReleaseUpdateAsync(options).ConfigureAwait(false),
                RunnerPhase.InstalledLauncherUpdate =>
                    await RunAutomaticReleaseUpdateAsync(options).ConfigureAwait(false),
                RunnerPhase.RefreshUpdateRequired =>
                    await RunRefreshUpdateRequiredAsync(options).ConfigureAwait(false),
                RunnerPhase.RefreshWaitDenied => await RunRefreshWaitDeniedAsync(options)
                    .ConfigureAwait(false),
                RunnerPhase.AssertEnrollmentRequired => AssertEnrollmentRequired(options),
                _ => throw new ArgumentOutOfRangeException(),
            };
            WriteEvidence(options.EvidencePath, new
            {
                schemaVersion = 1,
                status = "passed",
                phase = RunnerOptions.ToWireValue(options.Phase),
                completedAtUtc = DateTimeOffset.UtcNow,
                evidence,
            });
            return 0;
        }
        catch (Exception exception)
        {
            if (options is not null)
            {
                TryWriteFailureEvidence(options, exception);
            }

            Console.Error.WriteLine(
                "Development E2E phase failed closed: "
                + $"{SanitizeDevelopmentFailureEvidenceType(exception)}: "
                + SanitizeDevelopmentFailureEvidenceMessage(exception.Message));
            return 1;
        }
    }

    private static object RunArtifactFixtureContract(RunnerOptions options)
    {
        const string initialReleaseSetId = "fixture-contract-sequence-1";
        const string updateReleaseSetId = "fixture-contract-sequence-2";
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicParameters = signer.ExportParameters(false);
        var content = new Dictionary<Uri, byte[]>();
        var launcherBytes = CreateFixtureArchive("launcher.txt", "launcher-sequence-bytes");
        var runtimeBytes = CreateFixtureArchive("runtime.txt", "runtime-sequence-bytes");
        var targetRuntimeBytes = CreateFixtureArchive("runtime.txt", "runtime-target-sequence-bytes");
        var targetLauncherBytes = CreateFixtureArchive("launcher.txt", "launcher-target-sequence-bytes");
        var pluginPolicyBytes = CreateFixtureArchive("plugin.txt", "plugin-sequence-bytes");
        var initialArtifacts = CreateReleaseArtifacts(
            initialReleaseSetId,
            "launcher-fixture",
            launcherBytes,
            "runtime-fixture",
            runtimeBytes,
            "plugin-fixture",
            pluginPolicyBytes,
            content);
        var updateArtifacts = CreateReleaseArtifacts(
            updateReleaseSetId,
            "launcher-fixture",
            launcherBytes,
            "runtime-fixture",
            runtimeBytes,
            "plugin-fixture",
            pluginPolicyBytes,
            content);
        var targetUpdateArtifacts = CreateReleaseArtifacts(
            "fixture-contract-distinct-target-sequence-2",
            "launcher-fixture",
            launcherBytes,
            "runtime-target-fixture",
            targetRuntimeBytes,
            "plugin-target-fixture",
            pluginPolicyBytes,
            content);
        var launcherUpdateArtifacts = CreateReleaseArtifacts(
            "fixture-contract-distinct-launcher-sequence-3",
            "launcher-target-fixture",
            targetLauncherBytes,
            "runtime-fixture",
            runtimeBytes,
            "plugin-fixture",
            pluginPolicyBytes,
            content);
        var initialRuntime = initialArtifacts.Single(artifact =>
            string.Equals(
                artifact.Component,
                EnterpriseReleaseSetContract.RuntimeComponent,
                StringComparison.Ordinal));
        var sameRuntimeUpdate = updateArtifacts.Single(artifact =>
            string.Equals(
                artifact.Component,
                EnterpriseReleaseSetContract.RuntimeComponent,
                StringComparison.Ordinal));
        var targetRuntimeUpdate = targetUpdateArtifacts.Single(artifact =>
            string.Equals(
                artifact.Component,
                EnterpriseReleaseSetContract.RuntimeComponent,
                StringComparison.Ordinal));
        var initialLauncher = initialArtifacts.Single(artifact => string.Equals(
            artifact.Component,
            EnterpriseReleaseSetContract.LauncherComponent,
            StringComparison.Ordinal));
        var targetLauncherUpdate = launcherUpdateArtifacts.Single(artifact => string.Equals(
            artifact.Component,
            EnterpriseReleaseSetContract.LauncherComponent,
            StringComparison.Ordinal));
        var launcherUpdateRuntime = launcherUpdateArtifacts.Single(artifact => string.Equals(
            artifact.Component,
            EnterpriseReleaseSetContract.RuntimeComponent,
            StringComparison.Ordinal));
        var launcherUpdatePolicy = launcherUpdateArtifacts.Single(artifact => string.Equals(
            artifact.Component,
            EnterpriseReleaseSetContract.PluginPolicyComponent,
            StringComparison.Ordinal));
        if (!string.Equals(initialRuntime.ReleaseId, sameRuntimeUpdate.ReleaseId, StringComparison.Ordinal)
            || !string.Equals(initialRuntime.Sha256, sameRuntimeUpdate.Sha256, StringComparison.Ordinal)
            || !string.Equals(
                initialRuntime.CompleteTreeSha256,
                sameRuntimeUpdate.CompleteTreeSha256,
                StringComparison.Ordinal)
            || string.Equals(initialRuntime.ReleaseId, targetRuntimeUpdate.ReleaseId, StringComparison.Ordinal)
            || string.Equals(initialRuntime.Sha256, targetRuntimeUpdate.Sha256, StringComparison.Ordinal)
            || string.Equals(
                initialRuntime.CompleteTreeSha256,
                targetRuntimeUpdate.CompleteTreeSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Development release fixture contract did not distinguish same-runtime and target-runtime tuples.");
        }
        if (string.Equals(initialLauncher.ReleaseId, targetLauncherUpdate.ReleaseId, StringComparison.Ordinal)
            || string.Equals(initialLauncher.Sha256, targetLauncherUpdate.Sha256, StringComparison.Ordinal)
            || string.Equals(
                initialLauncher.CompleteTreeSha256,
                targetLauncherUpdate.CompleteTreeSha256,
                StringComparison.Ordinal)
            || !string.Equals(initialRuntime.ReleaseId, launcherUpdateRuntime.ReleaseId, StringComparison.Ordinal)
            || !string.Equals(initialRuntime.Sha256, launcherUpdateRuntime.Sha256, StringComparison.Ordinal)
            || !string.Equals(
                initialRuntime.CompleteTreeSha256,
                launcherUpdateRuntime.CompleteTreeSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                initialArtifacts.Single(artifact => artifact.Component == EnterpriseReleaseSetContract.PluginPolicyComponent).Sha256,
                launcherUpdatePolicy.Sha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Development release fixture contract did not isolate the distinct Launcher tuple.");
        }
        RunnerOptions.ValidateTargetOptionCounts(0, 0);
        AssertThrows<ArgumentException>(() => RunnerOptions.ValidateTargetOptionCounts(1, 0));
        AssertThrows<ArgumentException>(() => RunnerOptions.ValidateTargetOptionCounts(0, 1));
        AssertThrows<ArgumentException>(() => RunnerOptions.ValidateTargetOptionCounts(8, 2));
        AssertInstalledLauncherRuntimeProfileOptionContract(options);
        AssertInstalledLauncherControlPlaneTrustEnvironmentContract(options);
        AssertRuntimeHostOptionsContract();
        if (content.Count != initialArtifacts.Count + updateArtifacts.Count + targetUpdateArtifacts.Count
            + launcherUpdateArtifacts.Count)
        {
            throw new InvalidDataException(
                "Development release fixture contract did not create two disjoint artifact maps.");
        }

        var issuedAtUtc = WholeSecond(DateTimeOffset.UtcNow.AddMinutes(-1));
        var initialManifest = CreateSignedManifest(
            signer,
            initialReleaseSetId,
            generation: 1,
            sequence: 1,
            minAcceptedSequence: 0,
            issuedAtUtc,
            issuedAtUtc.AddHours(4),
            initialArtifacts);
        var updateManifest = CreateSignedManifest(
            signer,
            updateReleaseSetId,
            generation: 2,
            sequence: 2,
            minAcceptedSequence: 1,
            issuedAtUtc,
            issuedAtUtc.AddHours(4),
            updateArtifacts);
        var targetManifest = CreateSignedManifest(
            signer,
            "fixture-contract-distinct-target-sequence-2",
            generation: 2,
            sequence: 2,
            minAcceptedSequence: 1,
            issuedAtUtc,
            issuedAtUtc.AddHours(4),
            targetUpdateArtifacts);
        var launcherTargetManifest = CreateSignedManifest(
            signer,
            "fixture-contract-distinct-launcher-sequence-3",
            generation: 3,
            sequence: 3,
            minAcceptedSequence: 2,
            issuedAtUtc,
            issuedAtUtc.AddHours(4),
            launcherUpdateArtifacts);
        var trust = new EnterpriseReleaseTrustPolicy
        {
            Product = EnterpriseReleaseSetContract.Product,
            Environment = EnterpriseReleaseSetContract.DevelopmentE2EEnvironment,
            ExpectedChannel = EnterpriseReleaseSetContract.LabChannel,
            CurrentStartupStubProtocol = EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
            ManifestOrigin = new Uri("https://updates.example/"),
            ArtifactOrigin = DevelopmentArtifactOrigin,
            TrustedKeys = [new EnterpriseReleasePublicKey(
                DevelopmentReleaseKeyId,
                Base64Url(publicParameters.Q.X!),
                Base64Url(publicParameters.Q.Y!))],
        };
        EnterpriseReleaseSetValidator.Verify(initialManifest, trust, DateTimeOffset.UtcNow);
        EnterpriseReleaseSetValidator.Verify(updateManifest, trust, DateTimeOffset.UtcNow);
        EnterpriseReleaseSetValidator.Verify(targetManifest, trust, DateTimeOffset.UtcNow);
        EnterpriseReleaseSetValidator.Verify(launcherTargetManifest, trust, DateTimeOffset.UtcNow);

        var initialManifestBytes = SerializeReleaseDocument(initialManifest);
        var updateManifestBytes = SerializeReleaseDocument(updateManifest);
        var initialHttpContent = CreateExactManifestHttpContentMap(
            initialManifest,
            initialManifestBytes,
            content);
        var updateHttpContent = CreateExactManifestHttpContentMap(
            updateManifest,
            updateManifestBytes,
            content);
        RequireManifestHttpContentMap(
            initialManifest,
            initialManifestBytes,
            initialHttpContent,
            requireExactCount: true);
        RequireManifestHttpContentMap(
            updateManifest,
            updateManifestBytes,
            updateHttpContent,
            requireExactCount: true);
        AssertThrows<InvalidDataException>(() => CreateSignedManifest(
            signer,
            updateReleaseSetId,
            generation: 2,
            sequence: 2,
            minAcceptedSequence: 1,
            issuedAtUtc,
            issuedAtUtc.AddHours(4),
            initialArtifacts));

        var boundaryRoot = Path.Combine(
            Path.GetTempPath(),
            $"ensou-dsh-fixture-boundary-{options.IsolationIdentifier}");
        var boundaryLocalAppDataRoot = Path.Combine(boundaryRoot, "local-app-data");
        var boundaryUserProfileRoot = Path.Combine(boundaryRoot, "user-profile");
        var boundaryLayout = EnterpriseInstallationLayout.CreateDevelopmentE2E(
            boundaryLocalAppDataRoot,
            boundaryUserProfileRoot);
        var healthStartInfo = new ProcessStartInfo();
        ApplyDevelopmentUpdateTrustEnvironment(
            healthStartInfo,
            boundaryLayout,
            new EnterpriseCompiledReleaseTrust(SignedLabManifestUri, trust),
            options.IsolationIdentifier);
        if (!string.Equals(
                healthStartInfo.Environment["ENSOU_DSH_E2E_LOCAL_APP_DATA_ROOT"],
                boundaryLayout.LocalAppDataRoot,
                StringComparison.Ordinal)
            || !string.Equals(
                healthStartInfo.Environment["ENSOU_DSH_E2E_USER_PROFILE_ROOT"],
                boundaryLayout.UserProfileRoot,
                StringComparison.Ordinal)
            || !string.Equals(
                healthStartInfo.Environment["ENSOU_DSH_E2E_ISOLATION_ID"],
                options.IsolationIdentifier,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Development Launcher health probe did not receive the exact isolated filesystem identity.");
        }
        var snapshotName = $".lifecycle-policy-{Guid.Empty:N}";
        AssertThrows<InvalidDataException>(() => RequireDevelopmentFixtureSnapshotDirectory(
            Path.Combine(
                boundaryLocalAppDataRoot,
                DevelopmentFixtureInputDirectoryName,
                $".lifecycle-launcher-policy-{Guid.Empty:N}"),
            boundaryLocalAppDataRoot,
            boundaryLayout.ManagedRoot,
            boundaryLayout.PackageRoot));
        var allowedSnapshot = Path.Combine(
            boundaryLocalAppDataRoot,
            DevelopmentFixtureInputDirectoryName,
            snapshotName);
        var resolvedAllowedSnapshot = RequireDevelopmentFixtureSnapshotDirectory(
            allowedSnapshot,
            boundaryLocalAppDataRoot,
            boundaryLayout.ManagedRoot,
            boundaryLayout.PackageRoot);
        if (!string.Equals(
            resolvedAllowedSnapshot,
            Path.GetFullPath(allowedSnapshot),
            StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Development fixture snapshot boundary changed an allowed exact path.");
        }
        AssertThrows<InvalidDataException>(() => RequireDevelopmentFixtureSnapshotDirectory(
            Path.Combine(
                boundaryLayout.ManagedRoot,
                DevelopmentFixtureInputDirectoryName,
                snapshotName),
            boundaryLocalAppDataRoot,
            boundaryLayout.ManagedRoot,
            boundaryLayout.PackageRoot));
        TestDevelopmentLauncherHealthProbeDiagnostics();
        AssertThrows<InvalidDataException>(() => RequireDevelopmentFixtureSnapshotDirectory(
            Path.Combine(
                boundaryLayout.PackageRoot,
                DevelopmentFixtureInputDirectoryName,
                snapshotName),
            boundaryLocalAppDataRoot,
            boundaryLayout.ManagedRoot,
            boundaryLayout.PackageRoot));
        AssertThrows<InvalidDataException>(() => RequireDevelopmentFixtureSnapshotDirectory(
            Path.Combine(
                boundaryRoot,
                "outside-local-app-data",
                DevelopmentFixtureInputDirectoryName,
                snapshotName),
            boundaryLocalAppDataRoot,
            boundaryLayout.ManagedRoot,
            boundaryLayout.PackageRoot));
        TestPostUpdateSentinelRequiresExisting();
        TestLocalDataSentinelDefaultIsReadOnly();

        return new
        {
            isolationId = options.IsolationIdentifier,
            initialReleaseSetId,
            updateReleaseSetId,
            initialArtifactUris = initialManifest.Artifacts.Select(value => value.Uri.AbsoluteUri),
            updateArtifactUris = updateManifest.Artifacts.Select(value => value.Uri.AbsoluteUri),
            initialContentCount = initialHttpContent.Count,
            updateContentCount = updateHttpContent.Count,
            mismatchedParentBindingRejected = true,
            fixtureSnapshotBoundaryValidated = true,
            launcherHealthDiagnosticsContractValidated = true,
            launcherHealthFilesystemEnvironmentValidated = true,
            postUpdateSentinelDeletionRejected = true,
            defaultSentinelChecksRejectDeletionAndTampering = true,
        };
    }

    private static void TestPostUpdateSentinelRequiresExisting()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            $"ensou-dsh-sentinel-regression-{Guid.NewGuid():N}");
        try
        {
            foreach (var sentinelName in new[]
            {
                "development-e2e-preserve.txt",
                "development-e2e-history.jsonl",
            })
            {
                var caseRoot = Path.Combine(root, sentinelName);
                var paths = EnterpriseManagedPaths.CreateDevelopmentE2E(
                    Path.Combine(caseRoot, "local-app-data"),
                    Path.Combine(caseRoot, "user-profile"));
                _ = EnsureLocalDataSentinels(paths, "sentinel-regression", requireExisting: false);
                var sentinel = sentinelName == "development-e2e-preserve.txt"
                    ? Path.Combine(paths.WorkspaceRoot, sentinelName)
                    : Path.Combine(paths.HarnessHome, "history", sentinelName);
                File.Delete(sentinel);
                AssertThrows<InvalidDataException>(() => EnsureLocalDataSentinels(
                    paths,
                    "sentinel-regression",
                    requireExisting: true));
                if (File.Exists(sentinel))
                {
                    throw new InvalidDataException(
                        "Post-update sentinel validation recreated a deleted file.");
                }
            }
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static void TestLocalDataSentinelDefaultIsReadOnly()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            $"ensou-dsh-sentinel-default-{Guid.NewGuid():N}");
        try
        {
            foreach (var isHistory in new[] { false, true })
            {
                foreach (var mutation in new[] { "delete-file", "delete-directory", "change-content" })
                {
                    var caseRoot = Path.Combine(root, $"{isHistory}-{mutation}");
                    var paths = EnterpriseManagedPaths.CreateDevelopmentE2E(
                        Path.Combine(caseRoot, "local-app-data"),
                        Path.Combine(caseRoot, "user-profile"));
                    var seeded = EnsureLocalDataSentinels(
                        paths, "sentinel-default", requireExisting: false);
                    if (seeded != EnsureLocalDataSentinels(paths, "sentinel-default"))
                    {
                        throw new InvalidDataException("Read-only sentinel check changed intact data.");
                    }
                    var sentinel = isHistory
                        ? Path.Combine(paths.HarnessHome, "history", "development-e2e-history.jsonl")
                        : Path.Combine(paths.WorkspaceRoot, "development-e2e-preserve.txt");
                    if (mutation == "delete-file")
                        File.Delete(sentinel);
                    else if (mutation == "delete-directory")
                        Directory.Delete(Path.GetDirectoryName(sentinel)!, recursive: true);
                    else
                        File.WriteAllText(sentinel, "changed-synthetic-data", new UTF8Encoding(false));

                    AssertThrows<InvalidDataException>(() =>
                        EnsureLocalDataSentinels(paths, "sentinel-default"));
                    if (mutation != "change-content" && File.Exists(sentinel))
                        throw new InvalidDataException("Default sentinel check recreated missing data.");
                    if (mutation == "change-content"
                        && File.ReadAllText(sentinel) != "changed-synthetic-data")
                        throw new InvalidDataException("Default sentinel check rewrote changed data.");
                }
            }

            var missing = EnterpriseManagedPaths.CreateDevelopmentE2E(
                Path.Combine(root, "missing", "local-app-data"),
                Path.Combine(root, "missing", "user-profile"));
            AssertThrows<InvalidDataException>(() =>
                EnsureWorkspaceSentinel(missing, "sentinel-default"));
            AssertThrows<InvalidDataException>(() =>
                EnsureLocalDataSentinels(missing, "sentinel-default"));
            if (Directory.Exists(missing.WorkspaceRoot) || Directory.Exists(missing.HarnessHome))
                throw new InvalidDataException("Default sentinel check created an absent data directory.");
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }

    private static void TestDevelopmentLauncherHealthProbeDiagnostics()
    {
        var valid = new DevelopmentLauncherHealthProbeDiagnostics();
        valid.Capture(
            1,
            new BoundedStandardError(
                $"{DevelopmentMachineFailurePrefix}\tInvalidOperationException\t"
                    + "Exact source-build WebUI health validation failed.\r\n",
                Truncated: false));
        if (valid.ExitCode != 1
            || !string.Equals(valid.DiagnosticStatus, "parsed", StringComparison.Ordinal)
            || !string.Equals(
                valid.ExceptionType,
                "InvalidOperationException",
                StringComparison.Ordinal)
            || !string.Equals(
                valid.Message,
                "Exact source-build WebUI health validation failed.",
                StringComparison.Ordinal)
            || valid.StandardErrorTruncated)
        {
            throw new InvalidDataException(
                "Development Launcher health diagnostic contract did not preserve a safe exact line.");
        }

        foreach (var rejected in new[]
        {
            new BoundedStandardError(
                $"{DevelopmentMachineFailurePrefix}\tInvalidOperationException\tBearer value",
                Truncated: false),
            new BoundedStandardError(
                $"{DevelopmentMachineFailurePrefix}\tInvalidOperationException\t"
                    + new string('A', 32),
                Truncated: false),
            new BoundedStandardError(
                $"{DevelopmentMachineFailurePrefix}\tInvalidOperationException\tfirst\nsecond",
                Truncated: false),
            new BoundedStandardError(
                $"{DevelopmentMachineFailurePrefix}\tInvalidOperationException\tbounded",
                Truncated: true),
        })
        {
            var diagnostics = new DevelopmentLauncherHealthProbeDiagnostics();
            diagnostics.Capture(1, rejected);
            if (diagnostics.ExceptionType is not null || diagnostics.Message is not null)
            {
                throw new InvalidDataException(
                    "Development Launcher health diagnostic contract accepted unsafe stderr.");
            }
        }

        var timeout = new DevelopmentLauncherHealthProbeDiagnostics();
        timeout.CaptureTimeout();
        if (!string.Equals(timeout.DiagnosticStatus, "timeout", StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Development Launcher health diagnostic timeout status was not stable.");
        }

        if (!string.Equals(
                SanitizeDevelopmentFailureEvidenceMessage("Bearer exposed-value"),
                "Diagnostic message was redacted.",
                StringComparison.Ordinal)
            || SanitizeDevelopmentFailureEvidenceMessage(
                    "prefix " + new string('A', 32) + " suffix")
                .Contains(new string('A', 32), StringComparison.Ordinal)
            || SanitizeDevelopmentFailureEvidenceMessage("first\r\nsecond")
                .Contains('\n')
            || SanitizeDevelopmentFailureEvidenceMessage(new string('x', 600)).Length
                > MaximumDevelopmentMachineFailureMessageLength)
        {
            throw new InvalidDataException(
                "Development failure evidence sanitizer accepted unsafe diagnostic text.");
        }
    }

    private static async Task<object> RunInstallPluginPolicyAsync(RunnerOptions options)
    {
        var localAppDataRoot = RequireOption(options.LocalAppDataRoot, "local-app-data-root");
        var userProfileRoot = RequireOption(options.UserProfileRoot, "user-profile-root");
        var launcherReleaseId = RequireOption(options.LauncherReleaseId, "launcher-release-id");
        var runtimeReleaseId = RequireOption(options.RuntimeReleaseId, "runtime-release-id");
        var pluginPolicyReleaseId = RequireOption(
            options.PluginPolicyReleaseId,
            "plugin-policy-release-id");
        var launcherArchivePath = RequireOption(options.LauncherArchivePath, "launcher-archive");
        var runtimeArchivePath = RequireOption(options.RuntimeArchivePath, "runtime-archive");
        var pluginPolicyArchivePath = RequireOption(
            options.PluginPolicyArchivePath,
            "plugin-policy-archive");
        var expectedPolicyId = RequireOption(options.ExpectedPluginPolicyId, "plugin-policy-id");
        var expectedPolicyGeneration = options.ExpectedPluginPolicyGeneration
            ?? throw new ArgumentException("--plugin-policy-generation is required.");
        var expectedPolicySha256 = RequireOption(
            options.ExpectedPluginPolicySha256,
            "plugin-policy-sha256");
        var expectedArchiveSha256 = RequireOption(
            options.ExpectedPluginArchiveSha256,
            "plugin-archive-sha256");
        var target = options.GetTargetReleaseTuple();
        var directLocal = string.Equals(
            options.RuntimeProfile,
            EnterpriseDirectLocalRuntimeProfile,
            StringComparison.Ordinal);
        var releasePrivateKeyPath = RequireOption(
            options.ReleasePrivateKeyPath,
            "release-private-key");
        var initialManifestOutputPath = RequireOption(
            options.InitialManifestOutputPath,
            "initial-manifest-output");
        var initialJournalOutputPath = RequireOption(
            options.InitialJournalOutputPath,
            "initial-journal-output");
        var initialPromotionResultOutputPath = RequireOption(
            options.InitialPromotionResultOutputPath,
            "initial-promotion-result-output");
        var updateManifestOutputPath = RequireOption(
            options.UpdateManifestOutputPath,
            "update-manifest-output");
        var updateJournalOutputPath = RequireOption(
            options.UpdateJournalOutputPath,
            "update-journal-output");
        var updatePromotionResultOutputPath = RequireOption(
            options.UpdatePromotionResultOutputPath,
            "update-promotion-result-output");

        var layout = EnterpriseInstallationLayout.CreateDevelopmentE2E(
            localAppDataRoot,
            userProfileRoot);
        var pointerStore = new EnterpriseReleaseSetPointerStore(layout);
        var initial = pointerStore.ReadRequired();
        if (initial.Current.PluginPolicy is not null
            || initial.Current.Sequence != 0
            || !string.Equals(
                initial.Current.Launcher.ReleaseId,
                launcherReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                initial.Current.Runtime.ReleaseId,
                runtimeReleaseId,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Development policy install did not begin from the exact initial Launcher/runtime tuple.");
        }

        var launcherBytes = ReadArtifactBytes(
            launcherArchivePath,
            initial.Current.Launcher.ArchiveSha256,
            1L * 1024 * 1024 * 1024);
        var runtimeBytes = ReadArtifactBytes(
            runtimeArchivePath,
            initial.Current.Runtime.ArchiveSha256,
            8L * 1024 * 1024 * 1024);
        var pluginPolicyBytes = ReadArtifactBytes(
            pluginPolicyArchivePath,
            expectedArchiveSha256,
            512L * 1024 * 1024);
        var targetRuntimeBytes = target is null
            ? runtimeBytes
            : ReadArtifactBytes(
                target.RuntimeArchivePath,
                HashFile(target.RuntimeArchivePath),
                8L * 1024 * 1024 * 1024);
        var targetPluginPolicyBytes = target is null
            ? pluginPolicyBytes
            : ReadArtifactBytes(
                target.PluginPolicyArchivePath,
                target.PluginArchiveSha256,
                512L * 1024 * 1024);

        var capturedPolicyDirectory = RequireDevelopmentFixtureSnapshotDirectory(
            Path.Combine(
                localAppDataRoot,
                DevelopmentFixtureInputDirectoryName,
                $".lifecycle-policy-{Guid.NewGuid():N}"),
            localAppDataRoot,
            layout.ManagedRoot,
            layout.PackageRoot);
        Directory.CreateDirectory(capturedPolicyDirectory);
        var capturedPolicyPath = Path.Combine(capturedPolicyDirectory, "plugin-policy.zip");
        try
        {
            File.WriteAllBytes(capturedPolicyPath, pluginPolicyBytes);
            var inspection = EnterprisePluginPolicyArchiveValidator.Validate(
                capturedPolicyPath,
                launcherReleaseId,
                runtimeReleaseId);
            if (!string.Equals(inspection.PolicyId, expectedPolicyId, StringComparison.Ordinal)
                || inspection.Generation != expectedPolicyGeneration
                || !string.Equals(
                    inspection.PolicySha256,
                    expectedPolicySha256,
                    StringComparison.Ordinal)
                || !string.Equals(
                    inspection.ArchiveSha256,
                    expectedArchiveSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Captured plugin-policy bytes do not match the reviewed policy identity.");
            }

            var incompatibleLauncher = launcherReleaseId + "-incompatible";
            AssertThrows<InvalidDataException>(() =>
                EnterprisePluginPolicyArchiveValidator.Validate(
                    capturedPolicyPath,
                    incompatibleLauncher,
                    runtimeReleaseId));

            if (target is not null)
            {
                var capturedTargetPolicyPath = Path.Combine(
                    capturedPolicyDirectory,
                    "target-plugin-policy.zip");
                File.WriteAllBytes(capturedTargetPolicyPath, targetPluginPolicyBytes);
                var targetInspection = EnterprisePluginPolicyArchiveValidator.Validate(
                    capturedTargetPolicyPath,
                    launcherReleaseId,
                    target.RuntimeReleaseId);
                if (!string.Equals(
                        targetInspection.PolicyId,
                        target.PluginPolicyId,
                        StringComparison.Ordinal)
                    || targetInspection.Generation != target.PluginPolicyGeneration
                    || !string.Equals(
                        targetInspection.PolicySha256,
                        target.PluginPolicySha256,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        targetInspection.ArchiveSha256,
                        target.PluginArchiveSha256,
                        StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "Captured target plugin-policy bytes do not match the reviewed target policy identity.");
                }

                AssertThrows<InvalidDataException>(() =>
                    EnterprisePluginPolicyArchiveValidator.Validate(
                        capturedTargetPolicyPath,
                        launcherReleaseId,
                        target.RuntimeReleaseId + "-incompatible"));
            }

            using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var publicParameters = signer.ExportParameters(false);
            var content = new Dictionary<Uri, byte[]>();
            var initialReleaseSetId = $"lifecycle-{options.IsolationIdentifier}";
            var updateReleaseSetId = $"{initialReleaseSetId}-update";
            var initialUnsignedArtifacts = CreateReleaseArtifacts(
                initialReleaseSetId,
                launcherReleaseId,
                launcherBytes,
                runtimeReleaseId,
                runtimeBytes,
                pluginPolicyReleaseId,
                pluginPolicyBytes,
                content);
            var updateUnsignedArtifacts = CreateReleaseArtifacts(
                updateReleaseSetId,
                launcherReleaseId,
                launcherBytes,
                target?.RuntimeReleaseId ?? runtimeReleaseId,
                targetRuntimeBytes,
                target?.PluginPolicyReleaseId ?? pluginPolicyReleaseId,
                targetPluginPolicyBytes,
                content);
            var initialRuntimeArtifact = initialUnsignedArtifacts.Single(artifact =>
                string.Equals(
                    artifact.Component,
                    EnterpriseReleaseSetContract.RuntimeComponent,
                    StringComparison.Ordinal));
            var updateRuntimeArtifact = updateUnsignedArtifacts.Single(artifact =>
                string.Equals(
                    artifact.Component,
                    EnterpriseReleaseSetContract.RuntimeComponent,
                    StringComparison.Ordinal));
            if (target is not null
                && (string.Equals(
                        initialRuntimeArtifact.ReleaseId,
                        updateRuntimeArtifact.ReleaseId,
                        StringComparison.Ordinal)
                    || string.Equals(
                        initialRuntimeArtifact.Sha256,
                        updateRuntimeArtifact.Sha256,
                        StringComparison.Ordinal)
                    || string.Equals(
                        initialRuntimeArtifact.CompleteTreeSha256,
                        updateRuntimeArtifact.CompleteTreeSha256,
                        StringComparison.Ordinal)))
            {
                throw new InvalidDataException(
                    "A target runtime tuple must differ in release identity, archive bytes, and complete tree.");
            }
            if (content.Count != initialUnsignedArtifacts.Count + updateUnsignedArtifacts.Count)
            {
                throw new InvalidDataException(
                    "Development release fixture artifact content URIs are not distinct by releaseSetId.");
            }
            var issuedAtUtc = WholeSecond(DateTimeOffset.UtcNow.AddMinutes(-1));
            var expiresAtUtc = issuedAtUtc.AddHours(4);
            var initialManifest = CreateSignedManifest(
                signer,
                initialReleaseSetId,
                generation: 1,
                sequence: 1,
                minAcceptedSequence: 0,
                issuedAtUtc,
                expiresAtUtc,
                initialUnsignedArtifacts);
            var updateManifest = CreateSignedManifest(
                signer,
                updateReleaseSetId,
                generation: 2,
                sequence: 2,
                minAcceptedSequence: 1,
                issuedAtUtc,
                expiresAtUtc,
                updateUnsignedArtifacts);
            var initialManifestBytes = SerializeReleaseDocument(initialManifest);
            var updateManifestBytes = SerializeReleaseDocument(updateManifest);
            RequireCanonicalUtcTimestamps(initialManifestBytes, expectedCount: 2);
            RequireCanonicalUtcTimestamps(updateManifestBytes, expectedCount: 2);
            RequireManifestArtifactContent(initialManifest, content);
            RequireManifestArtifactContent(updateManifest, content);
            var releasePublicKey = new EnterpriseReleasePublicKey(
                DevelopmentReleaseKeyId,
                Base64Url(publicParameters.Q.X!),
                Base64Url(publicParameters.Q.Y!));
            var initialPromotion = PromoteDevelopmentCandidate(
                Path.Combine(
                    Path.GetDirectoryName(initialPromotionResultOutputPath)!,
                    "feed-sequence-1"),
                initialPromotionResultOutputPath,
                initialManifest,
                initialManifestBytes,
                content,
                releasePublicKey);
            var updatePromotion = PromoteDevelopmentCandidate(
                Path.Combine(
                    Path.GetDirectoryName(updatePromotionResultOutputPath)!,
                    "feed-sequence-2"),
                updatePromotionResultOutputPath,
                updateManifest,
                updateManifestBytes,
                content,
                releasePublicKey);
            var privateKeyBytes = signer.ExportPkcs8PrivateKey();
            try
            {
                WriteNewFile(releasePrivateKeyPath, privateKeyBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privateKeyBytes);
            }
            WriteNewFile(
                initialManifestOutputPath,
                File.ReadAllBytes(initialPromotion.ChannelManifestPath));
            WriteNewFile(
                initialJournalOutputPath,
                File.ReadAllBytes(initialPromotion.JournalEntryPath));
            WriteNewFile(
                updateManifestOutputPath,
                File.ReadAllBytes(updatePromotion.ChannelManifestPath));
            WriteNewFile(
                updateJournalOutputPath,
                File.ReadAllBytes(updatePromotion.JournalEntryPath));
            if (!content.TryAdd(SignedLabManifestUri, initialManifestBytes))
            {
                throw new InvalidDataException(
                    "Development release fixture manifest URI is duplicated.");
            }
            RequireManifestHttpContentMap(
                initialManifest,
                initialManifestBytes,
                content,
                requireExactCount: false);

            var trust = new EnterpriseReleaseTrustPolicy
            {
                Product = EnterpriseReleaseSetContract.Product,
                Environment = EnterpriseReleaseSetContract.DevelopmentE2EEnvironment,
                ExpectedChannel = EnterpriseReleaseSetContract.LabChannel,
                CurrentStartupStubProtocol =
                    EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                ManifestOrigin = new Uri("https://updates.example/"),
                ArtifactOrigin = DevelopmentArtifactOrigin,
                TrustedKeys = [new EnterpriseReleasePublicKey(
                    DevelopmentReleaseKeyId,
                    Base64Url(publicParameters.Q.X!),
                    Base64Url(publicParameters.Q.Y!))],
            };
            var compiledReleaseTrust = new EnterpriseCompiledReleaseTrust(
                SignedLabManifestUri,
                trust);
            var verificationTime = DateTimeOffset.UtcNow;
            EnterpriseReleaseSetValidator.Verify(initialManifest, trust, verificationTime);
            EnterpriseReleaseSetValidator.Verify(updateManifest, trust, verificationTime);
            if (directLocal)
            {
                var unchanged = new EnterpriseReleaseSetPointerStore(
                    layout,
                    compiledReleaseTrust).ReadRequired();
                if (unchanged.Previous is not null
                    || unchanged.Current.Generation != 0
                    || unchanged.Current.Sequence != 0
                    || unchanged.Current.MinAcceptedSequence != 0
                    || unchanged.Current.PluginPolicy is not null
                    || unchanged.Current.HealthState != EnterpriseReleaseHealthStates.Healthy
                    || unchanged.Current.HealthToken is not null
                    || !ReleaseSetCurrentMatches(unchanged.Current, initial.Current))
                {
                    throw new InvalidDataException(
                        "Direct-local initial release must remain at healthy sequence zero until authenticated enrollment commits a signed lease.");
                }

                return new
                {
                    releaseSetState = "initial-sequence-zero-awaiting-authenticated-enrollment",
                    healthState = unchanged.Current.HealthState,
                    activeReleaseSequence = unchanged.Current.Sequence,
                    signedInitialReleaseStaged = false,
                    signedInitialReleaseHealthy = false,
                    activePolicyAvailable = false,
                    launcherReleaseId,
                    runtimeReleaseId,
                    pluginPolicyReleaseId,
                    targetRuntimeReleaseId = updateRuntimeArtifact.ReleaseId,
                    targetRuntimeArchiveSha256 = updateRuntimeArtifact.Sha256,
                    targetRuntimeCompleteTreeSha256 = updateRuntimeArtifact.CompleteTreeSha256,
                    targetPluginPolicyReleaseId = target?.PluginPolicyReleaseId ?? pluginPolicyReleaseId,
                    targetPluginPolicyId = target?.PluginPolicyId ?? expectedPolicyId,
                    targetPluginPolicyGeneration = target?.PluginPolicyGeneration ?? expectedPolicyGeneration,
                    targetPluginPolicySha256 = target?.PluginPolicySha256 ?? expectedPolicySha256,
                    sameRuntimeCompatibilityFixture = target is null,
                    policyId = inspection.PolicyId,
                    generation = inspection.Generation,
                    rawPolicySha256 = inspection.PolicySha256,
                    archiveSha256 = expectedArchiveSha256,
                    skillsTreeSha256 = (string?)null,
                    incompatibleArchiveRejected = true,
                    alternateRawPolicyBindingRejected = false,
                    releaseSetId = initialManifest.ReleaseSetId,
                    releaseGeneration = initialManifest.Generation,
                    releaseSequence = initialManifest.Sequence,
                    minAcceptedSequence = initialManifest.MinAcceptedSequence,
                    manifestSha256 = Hash(initialManifestBytes),
                    updateReleaseSetId = updateManifest.ReleaseSetId,
                    updateGeneration = updateManifest.Generation,
                    updateSequence = updateManifest.Sequence,
                    updateMinAcceptedSequence = updateManifest.MinAcceptedSequence,
                    updateManifestSha256 = Hash(updateManifestBytes),
                    releaseUpdateTrust = new
                    {
                        manifestUri = compiledReleaseTrust.ManifestUri.AbsoluteUri,
                        manifestOrigin = compiledReleaseTrust.Policy.ManifestOrigin.AbsoluteUri,
                        artifactOrigin = compiledReleaseTrust.Policy.ArtifactOrigin.AbsoluteUri,
                        releasePolicyKeyId = releasePublicKey.KeyId,
                        releasePolicyKeyX = releasePublicKey.X,
                        releasePolicyKeyY = releasePublicKey.Y,
                    },
                };
            }
            using var httpClient = new HttpClient(new StaticHandler(content));
            var staged = await new EnterpriseReleaseStartupCoordinator(
                    layout,
                    SignedLabManifestUri,
                    trust,
                    httpClient)
                .CheckOnEveryStartupAsync()
                .ConfigureAwait(false);
            if (!staged.RequiresBootstrapHealthCheck
                || !string.Equals(staged.State, "pending-health", StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Signed plugin-policy release-set did not enter pending health verification.");
            }

            var healthProbeDiagnostics = new DevelopmentLauncherHealthProbeDiagnostics();
            var health = await new EnterpriseBootstrapHealthGate(
                    layout,
                    EnterpriseBootstrapHealthGate.ColdStartTimeout,
                    compiledReleaseTrust)
                .EnsureHealthyAsync((launcherPath, healthToken, timeout, cancellationToken) =>
                    RunInstalledLauncherHealthProbeAsync(
                        layout,
                        launcherPath,
                        healthToken,
                        timeout,
                        cancellationToken,
                        compiledReleaseTrust,
                        options,
                        healthProbeDiagnostics,
                        requireControlPlaneTrust: false))
                .ConfigureAwait(false);
            if (!health.Healthy)
            {
                throw new DevelopmentLauncherHealthProbeException(healthProbeDiagnostics);
            }

            var healthyPointer = pointerStore.ReadRequired();
            var activePolicy = pointerStore.ReadActivePluginPolicyRequired();
            if (healthyPointer.Current.HealthState != EnterpriseReleaseHealthStates.Healthy
                || !string.Equals(
                    healthyPointer.Current.PluginPolicy?.ReleaseId,
                    pluginPolicyReleaseId,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Plugin-policy release-set was not atomically activated as healthy.");
            }
            activePolicy.RequireLeaseBinding(
                expectedPolicyId,
                expectedPolicyGeneration,
                expectedPolicySha256);

            var rawPolicyBytes = ReadPolicyBytes(pluginPolicyBytes);
            var alternateRawBytes = new byte[rawPolicyBytes.Length + 1];
            rawPolicyBytes.CopyTo(alternateRawBytes, 0);
            alternateRawBytes[^1] = (byte)' ';
            var alternatePolicy = EnterprisePluginPolicy.Parse(alternateRawBytes);
            var alternatePolicySha256 = Hash(alternateRawBytes);
            if (!string.Equals(alternatePolicy.PolicyId, expectedPolicyId, StringComparison.Ordinal)
                || alternatePolicy.Generation != expectedPolicyGeneration
                || string.Equals(
                    alternatePolicySha256,
                    expectedPolicySha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "The same-id/generation alternate raw-policy negative case is invalid.");
            }
            AssertThrows<InvalidDataException>(() => activePolicy.RequireLeaseBinding(
                expectedPolicyId,
                expectedPolicyGeneration,
                alternatePolicySha256));

            return new
            {
                releaseSetState = staged.State,
                healthState = healthyPointer.Current.HealthState,
                launcherReleaseId,
                runtimeReleaseId,
                pluginPolicyReleaseId,
                targetRuntimeReleaseId = updateRuntimeArtifact.ReleaseId,
                targetRuntimeArchiveSha256 = updateRuntimeArtifact.Sha256,
                targetRuntimeCompleteTreeSha256 = updateRuntimeArtifact.CompleteTreeSha256,
                targetPluginPolicyReleaseId = target?.PluginPolicyReleaseId ?? pluginPolicyReleaseId,
                targetPluginPolicyId = target?.PluginPolicyId ?? expectedPolicyId,
                targetPluginPolicyGeneration = target?.PluginPolicyGeneration ?? expectedPolicyGeneration,
                targetPluginPolicySha256 = target?.PluginPolicySha256 ?? expectedPolicySha256,
                sameRuntimeCompatibilityFixture = target is null,
                policyId = activePolicy.PolicyId,
                generation = activePolicy.Generation,
                rawPolicySha256 = activePolicy.PolicySha256,
                archiveSha256 = expectedArchiveSha256,
                skillsTreeSha256 = activePolicy.SkillsTreeSha256,
                incompatibleArchiveRejected = true,
                alternateRawPolicyBindingRejected = true,
                releaseSetId = initialManifest.ReleaseSetId,
                releaseGeneration = initialManifest.Generation,
                releaseSequence = initialManifest.Sequence,
                minAcceptedSequence = initialManifest.MinAcceptedSequence,
                manifestSha256 = Hash(initialManifestBytes),
                updateReleaseSetId = updateManifest.ReleaseSetId,
                updateGeneration = updateManifest.Generation,
                updateSequence = updateManifest.Sequence,
                updateMinAcceptedSequence = updateManifest.MinAcceptedSequence,
                updateManifestSha256 = Hash(updateManifestBytes),
                releaseUpdateTrust = new
                {
                    manifestUri = compiledReleaseTrust.ManifestUri.AbsoluteUri,
                    manifestOrigin = compiledReleaseTrust.Policy.ManifestOrigin.AbsoluteUri,
                    artifactOrigin = compiledReleaseTrust.Policy.ArtifactOrigin.AbsoluteUri,
                    releasePolicyKeyId = releasePublicKey.KeyId,
                    releasePolicyKeyX = releasePublicKey.X,
                    releasePolicyKeyY = releasePublicKey.Y,
                },
            };
        }
        finally
        {
            if (Directory.Exists(capturedPolicyDirectory))
            {
                var resolved = RequireDevelopmentFixtureSnapshotDirectory(
                    capturedPolicyDirectory,
                    localAppDataRoot,
                    layout.ManagedRoot,
                    layout.PackageRoot);
                Directory.Delete(resolved, recursive: true);
            }
        }
    }

    private static string RequireDevelopmentFixtureSnapshotDirectory(
        string snapshotDirectory,
        string localAppDataRoot,
        string managedRoot,
        string packageRoot)
    {
        if (!Path.IsPathFullyQualified(snapshotDirectory)
            || !Path.IsPathFullyQualified(localAppDataRoot)
            || !Path.IsPathFullyQualified(managedRoot)
            || !Path.IsPathFullyQualified(packageRoot))
        {
            throw new InvalidDataException(
                "Development fixture snapshot boundaries must be absolute paths.");
        }

        var resolvedSnapshot = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(snapshotDirectory));
        var resolvedLocalAppData = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(localAppDataRoot));
        var resolvedManagedRoot = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(managedRoot));
        var resolvedPackageRoot = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(packageRoot));
        var expectedFixtureRoot = Path.Combine(
            resolvedLocalAppData,
            DevelopmentFixtureInputDirectoryName);
        var snapshotName = Path.GetFileName(resolvedSnapshot);
        const string snapshotPrefix = ".lifecycle-policy-";
        var snapshotId = snapshotName.StartsWith(snapshotPrefix, StringComparison.Ordinal)
            ? snapshotName[snapshotPrefix.Length..]
            : string.Empty;
        if (string.Equals(
                resolvedSnapshot,
                resolvedLocalAppData,
                StringComparison.OrdinalIgnoreCase)
            || !IsSameOrDescendant(resolvedSnapshot, resolvedLocalAppData)
            || IsSameOrDescendant(resolvedSnapshot, resolvedManagedRoot)
            || IsSameOrDescendant(resolvedSnapshot, resolvedPackageRoot)
            || !string.Equals(
                Path.GetDirectoryName(resolvedSnapshot),
                expectedFixtureRoot,
                StringComparison.OrdinalIgnoreCase)
            || !Guid.TryParseExact(snapshotId, "N", out _))
        {
            throw new InvalidDataException(
                "Development fixture snapshot must be an exact isolated local-app-data child outside managed and package roots.");
        }
        return resolvedSnapshot;
    }

    private static bool IsSameOrDescendant(string candidate, string root)
    {
        var resolvedCandidate = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate));
        var resolvedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        return string.Equals(resolvedCandidate, resolvedRoot, StringComparison.OrdinalIgnoreCase)
            || resolvedCandidate.StartsWith(
                resolvedRoot + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase);
    }

    private static string RequireOption(string? value, string name) =>
        !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new ArgumentException($"--{name} is required.");

    private static byte[] ReadArtifactBytes(
        string path,
        string expectedSha256,
        long maximumBytes)
    {
        var fullPath = Path.GetFullPath(path);
        if (!Path.IsPathFullyQualified(path)
            || !File.Exists(fullPath)
            || expectedSha256.Length != 64
            || expectedSha256.Any(character => character is not (>= '0' and <= '9')
                and not (>= 'a' and <= 'f')))
        {
            throw new InvalidDataException("Development release artifact input is invalid.");
        }
        for (FileSystemInfo? current = new FileInfo(fullPath);
             current is not null;
             current = current switch
             {
                 FileInfo file => file.Directory,
                 DirectoryInfo directory => directory.Parent,
                 _ => null,
             })
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Development release artifact path contains a filesystem link.");
            }
        }

        using var input = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.SequentialScan);
        if (input.Length is <= 0
            || input.Length > maximumBytes
            || input.Length > int.MaxValue)
        {
            throw new InvalidDataException("Development release artifact size is invalid.");
        }
        using var output = new MemoryStream(checked((int)input.Length));
        input.CopyTo(output);
        if (output.Length != input.Length)
        {
            throw new EndOfStreamException("Development release artifact length changed while reading.");
        }
        var bytes = output.ToArray();
        if (!string.Equals(Hash(bytes), expectedSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Development release artifact SHA-256 changed.");
        }
        return bytes;
    }

    private static IReadOnlyList<EnterpriseReleaseArtifact> CreateReleaseArtifacts(
        string releaseSetId,
        string launcherReleaseId,
        byte[] launcherBytes,
        string runtimeReleaseId,
        byte[] runtimeBytes,
        string pluginPolicyReleaseId,
        byte[] pluginPolicyBytes,
        IDictionary<Uri, byte[]> content) =>
        [
            CreateArtifact(
                releaseSetId,
                EnterpriseReleaseSetContract.LauncherComponent,
                launcherReleaseId,
                launcherBytes,
                content),
            CreateArtifact(
                releaseSetId,
                EnterpriseReleaseSetContract.RuntimeComponent,
                runtimeReleaseId,
                runtimeBytes,
                content),
            CreateArtifact(
                releaseSetId,
                EnterpriseReleaseSetContract.PluginPolicyComponent,
                pluginPolicyReleaseId,
                pluginPolicyBytes,
                content),
        ];

    private static EnterpriseReleaseArtifact CreateArtifact(
        string releaseSetId,
        string component,
        string releaseId,
        byte[] bytes,
        IDictionary<Uri, byte[]> content)
    {
        var uri = CreateImmutableArtifactUri(releaseSetId, releaseId);
        if (content.ContainsKey(uri))
        {
            throw new InvalidDataException(
                "Development release fixture artifact URI is duplicated.");
        }
        content.Add(uri, bytes);
        using var archiveStream = new MemoryStream(bytes, writable: false);
        return new EnterpriseReleaseArtifact
        {
            Component = component,
            ReleaseId = releaseId,
            Uri = uri,
            SizeBytes = bytes.LongLength,
            Sha256 = Hash(bytes),
            CompleteTreeSha256 = EnterpriseReleaseArchiveTreeHash.Compute(archiveStream),
            Signature = CreateSignature(new byte[64]),
        };
    }

    private static Uri CreateImmutableArtifactUri(string releaseSetId, string releaseId)
    {
        if (string.IsNullOrWhiteSpace(releaseSetId) || string.IsNullOrWhiteSpace(releaseId))
        {
            throw new InvalidDataException(
                "Development release fixture immutable artifact identity is missing.");
        }
        var fileName = $"{releaseId}.zip";
        return new Uri(
            DevelopmentArtifactOrigin,
            $"v2/releases/{Uri.EscapeDataString(releaseSetId)}/{Uri.EscapeDataString(fileName)}");
    }

    private static void RequireImmutableArtifactLayout(
        string releaseSetId,
        IReadOnlyList<EnterpriseReleaseArtifact> artifacts)
    {
        var requiredComponents = new HashSet<string>(StringComparer.Ordinal)
        {
            EnterpriseReleaseSetContract.LauncherComponent,
            EnterpriseReleaseSetContract.RuntimeComponent,
            EnterpriseReleaseSetContract.PluginPolicyComponent,
        };
        var observedUris = new HashSet<string>(StringComparer.Ordinal);
        if (artifacts.Count != requiredComponents.Count)
        {
            throw new InvalidDataException(
                "Development release fixture artifact component count is not exact.");
        }
        foreach (var artifact in artifacts)
        {
            var expected = CreateImmutableArtifactUri(releaseSetId, artifact.ReleaseId);
            if (!requiredComponents.Remove(artifact.Component)
                || !observedUris.Add(artifact.Uri.AbsoluteUri)
                || !string.Equals(
                    artifact.Uri.AbsoluteUri,
                    expected.AbsoluteUri,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Development release fixture artifact URI is not bound to its exact releaseSetId.");
            }
        }
        if (requiredComponents.Count != 0)
        {
            throw new InvalidDataException(
                "Development release fixture artifact component set is incomplete.");
        }
    }

    private static void RequireManifestArtifactContent(
        EnterpriseReleaseSetManifest manifest,
        IReadOnlyDictionary<Uri, byte[]> content)
    {
        RequireImmutableArtifactLayout(manifest.ReleaseSetId, manifest.Artifacts);
        foreach (var artifact in manifest.Artifacts)
        {
            if (!content.TryGetValue(artifact.Uri, out var bytes)
                || bytes.LongLength != artifact.SizeBytes
                || !string.Equals(Hash(bytes), artifact.Sha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Development release fixture content map does not match its signed manifest.");
            }
        }
    }

    private static Dictionary<Uri, byte[]> CreateExactManifestHttpContentMap(
        EnterpriseReleaseSetManifest manifest,
        byte[] manifestBytes,
        IReadOnlyDictionary<Uri, byte[]> artifactContent)
    {
        RequireManifestArtifactContent(manifest, artifactContent);
        var content = new Dictionary<Uri, byte[]>
        {
            [SignedLabManifestUri] = manifestBytes,
        };
        foreach (var artifact in manifest.Artifacts)
        {
            content.Add(artifact.Uri, artifactContent[artifact.Uri]);
        }
        return content;
    }

    private static void RequireManifestHttpContentMap(
        EnterpriseReleaseSetManifest manifest,
        byte[] manifestBytes,
        IReadOnlyDictionary<Uri, byte[]> content,
        bool requireExactCount)
    {
        RequireManifestArtifactContent(manifest, content);
        if (!content.TryGetValue(SignedLabManifestUri, out var observedManifestBytes)
            || !observedManifestBytes.AsSpan().SequenceEqual(manifestBytes)
            || (requireExactCount && content.Count != manifest.Artifacts.Count + 1))
        {
            throw new InvalidDataException(
                "Development release fixture HTTP content map is not exact.");
        }
    }

    private static byte[] CreateFixtureArchive(string entryName, string value)
    {
        using var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = archive.CreateEntry(entryName, CompressionLevel.NoCompression);
            using var entryStream = entry.Open();
            var bytes = Encoding.UTF8.GetBytes(value);
            entryStream.Write(bytes);
        }
        return output.ToArray();
    }

    private static EnterpriseReleaseSetManifest CreateSignedManifest(
        ECDsa signer,
        string releaseSetId,
        long generation,
        long sequence,
        long minAcceptedSequence,
        DateTimeOffset issuedAtUtc,
        DateTimeOffset expiresAtUtc,
        IReadOnlyList<EnterpriseReleaseArtifact> unsignedArtifacts)
    {
        RequireImmutableArtifactLayout(releaseSetId, unsignedArtifacts);
        var placeholder = new EnterpriseReleaseSetManifest
        {
            SchemaVersion = EnterpriseReleaseSetContract.SchemaVersion,
            Product = EnterpriseReleaseSetContract.Product,
            Environment = EnterpriseReleaseSetContract.DevelopmentE2EEnvironment,
            Channel = "lab",
            ReleaseSetId = releaseSetId,
            Generation = generation,
            Sequence = sequence,
            MinAcceptedSequence = minAcceptedSequence,
            IssuedAtUtc = issuedAtUtc,
            ExpiresAtUtc = expiresAtUtc,
            StartupStub = new EnterpriseStartupStubCompatibility
            {
                MinimumProtocol = EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                MaximumProtocol = EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
            },
            RevokedReleaseSetIds = [],
            Artifacts = unsignedArtifacts,
            Signature = CreateSignature(new byte[64]),
        };
        var artifacts = unsignedArtifacts.Select(artifact => artifact with
        {
            Signature = Sign(
                signer,
                EnterpriseReleaseCanonicalJson.ArtifactPayload(placeholder, artifact)),
        }).ToArray();
        var manifest = placeholder with { Artifacts = artifacts };
        return manifest with
        {
            Signature = Sign(
                signer,
                EnterpriseReleaseCanonicalJson.ManifestPayload(manifest)),
        };
    }

    private static byte[] SerializeReleaseDocument<T>(T value)
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            WriteIndented = true,
        };
        options.Converters.Add(new EnterpriseWholeSecondUtcJsonConverter());
        return JsonSerializer.SerializeToUtf8Bytes(value, options);
    }

    private static void RequireCanonicalUtcTimestamps(
        ReadOnlyMemory<byte> json,
        int expectedCount)
    {
        using var document = JsonDocument.Parse(json);
        var observed = 0;
        Visit(document.RootElement);
        if (observed != expectedCount)
        {
            throw new InvalidDataException(
                "Development release fixture timestamp count is not exact.");
        }

        void Visit(JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                foreach (var property in element.EnumerateObject())
                {
                    if (property.Name.EndsWith("AtUtc", StringComparison.Ordinal))
                    {
                        observed++;
                        var value = property.Value.ValueKind == JsonValueKind.String
                            ? property.Value.GetString()
                            : null;
                        if (value is null
                            || !DateTimeOffset.TryParseExact(
                                value,
                                "yyyy-MM-dd'T'HH:mm:ss'Z'",
                                System.Globalization.CultureInfo.InvariantCulture,
                                System.Globalization.DateTimeStyles.AssumeUniversal
                                    | System.Globalization.DateTimeStyles.AdjustToUniversal,
                                out var parsed)
                            || parsed.Offset != TimeSpan.Zero
                            || parsed.Ticks % TimeSpan.TicksPerSecond != 0)
                        {
                            throw new InvalidDataException(
                                "Development release fixture timestamp is not canonical UTC.");
                        }
                    }
                    Visit(property.Value);
                }
            }
            else if (element.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in element.EnumerateArray())
                {
                    Visit(item);
                }
            }
        }
    }

    private static EnterpriseFeedPromotionResult PromoteDevelopmentCandidate(
        string fixtureRoot,
        string resultReceiptPath,
        EnterpriseReleaseSetManifest manifest,
        ReadOnlySpan<byte> manifestBytes,
        IReadOnlyDictionary<Uri, byte[]> content,
        EnterpriseReleasePublicKey releaseKey)
    {
        var fullFixtureRoot = Path.GetFullPath(fixtureRoot);
        if (!Path.IsPathFullyQualified(fixtureRoot)
            || Directory.Exists(fullFixtureRoot)
            || File.Exists(fullFixtureRoot))
        {
            throw new InvalidDataException(
                "Development FeedPromoter fixture root must be a new absolute path.");
        }
        Directory.CreateDirectory(fullFixtureRoot);
        var feedRoot = Path.Combine(fullFixtureRoot, "feed");
        Directory.CreateDirectory(Path.Combine(feedRoot, "staging"));
        Directory.CreateDirectory(Path.Combine(feedRoot, "public", "releases"));
        foreach (var channel in new[] { "lab", "pilot", "stable" })
        {
            Directory.CreateDirectory(Path.Combine(feedRoot, "public", "channels", channel));
            Directory.CreateDirectory(Path.Combine(feedRoot, "journal", channel));
        }

        var trustPath = Path.Combine(fullFixtureRoot, "trust.v1.json");
        WriteNewFile(
            trustPath,
            SerializeReleaseDocument(new EnterpriseFeedTrustConfiguration
            {
                SchemaVersion = 1,
                Product = EnterpriseReleaseSetContract.Product,
                Environment = EnterpriseReleaseSetContract.DevelopmentE2EEnvironment,
                ManifestOrigin = new Uri("https://updates.example/"),
                ArtifactOrigin = DevelopmentArtifactOrigin,
                ReleaseKeys = [releaseKey],
                CertificationKeys = [releaseKey],
                AllowedClockSkewSeconds = 120,
                MaximumOfflineGraceHours = 168,
            }));

        var candidateRoot = Path.Combine(fullFixtureRoot, "candidate");
        Directory.CreateDirectory(candidateRoot);
        WriteNewFile(
            Path.Combine(candidateRoot, "release-set.v2.json"),
            manifestBytes);
        foreach (var artifact in manifest.Artifacts)
        {
            if (!content.TryGetValue(artifact.Uri, out var artifactBytes))
            {
                throw new InvalidDataException(
                    $"Development FeedPromoter candidate is missing {artifact.Component} bytes.");
            }
            WriteNewFile(
                Path.Combine(candidateRoot, Path.GetFileName(artifact.Uri.AbsolutePath)),
                artifactBytes);
        }

        var result = new EnterpriseFeedPromoter().Promote(
            new EnterpriseFeedPromotionOptions(
                candidateRoot,
                feedRoot,
                trustPath,
                manifest.Channel));
        Ensou.Dsh.Enterprise.FeedPromoter.Program.WriteResultReceipt(
            resultReceiptPath,
            result);
        if (!string.Equals(result.Environment, manifest.Environment, StringComparison.Ordinal)
            || !string.Equals(result.ReleaseSetId, manifest.ReleaseSetId, StringComparison.Ordinal)
            || result.Generation != manifest.Generation
            || result.Sequence != manifest.Sequence
            || result.MinAcceptedSequence != manifest.MinAcceptedSequence
            || !string.Equals(result.ManifestSha256, Hash(manifestBytes), StringComparison.Ordinal)
            || !File.Exists(result.ChannelManifestPath)
            || !File.Exists(result.JournalEntryPath))
        {
            throw new InvalidDataException(
                "Development FeedPromoter result does not bind the exact signed candidate.");
        }
        return result;
    }

    private static byte[] CreatePromotionJournalBytes(
        EnterpriseReleaseSetManifest manifest,
        ReadOnlySpan<byte> manifestBytes,
        string previousEntrySha256,
        DateTimeOffset publishedAtUtc) => SerializeReleaseDocument(new
        {
            schemaVersion = 1,
            channel = manifest.Channel,
            releaseSetId = manifest.ReleaseSetId,
            generation = manifest.Generation,
            sequence = manifest.Sequence,
            minAcceptedSequence = manifest.MinAcceptedSequence,
            manifestSha256 = Hash(manifestBytes),
            previousEntrySha256,
            artifacts = manifest.Artifacts.Select(artifact => new
            {
                component = artifact.Component,
                releaseId = artifact.ReleaseId,
                fileName = Path.GetFileName(artifact.Uri.AbsolutePath),
                sizeBytes = artifact.SizeBytes,
                sha256 = artifact.Sha256,
            }).ToArray(),
            publishedAtUtc,
        });

    private static void WriteNewFile(string path, ReadOnlySpan<byte> bytes)
    {
        var fullPath = Path.GetFullPath(path);
        var parent = Path.GetDirectoryName(fullPath)
            ?? throw new InvalidDataException("Development release output has no parent directory.");
        if (!Path.IsPathFullyQualified(path)
            || !Directory.Exists(parent)
            || File.Exists(fullPath)
            || (File.GetAttributes(parent) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Development release output must be a new file below an existing local directory.");
        }

        using var output = new FileStream(
            fullPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            4096,
            FileOptions.WriteThrough);
        output.Write(bytes);
        output.Flush(flushToDisk: true);
    }

    private static DateTimeOffset WholeSecond(DateTimeOffset value) =>
        new(value.UtcTicks - value.UtcTicks % TimeSpan.TicksPerSecond, TimeSpan.Zero);

    private static EnterpriseReleaseSignature Sign(ECDsa signer, ReadOnlySpan<byte> payload) =>
        CreateSignature(signer.SignData(
            payload,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

    private static EnterpriseReleaseSignature CreateSignature(byte[] value) => new()
    {
        Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
        KeyId = DevelopmentReleaseKeyId,
        Value = Base64Url(value),
    };

    private static byte[] ReadPolicyBytes(byte[] archiveBytes)
    {
        using var input = new MemoryStream(archiveBytes, writable: false);
        using var archive = new ZipArchive(input, ZipArchiveMode.Read, leaveOpen: false);
        var entries = archive.Entries
            .Where(entry => string.Equals(
                entry.FullName,
                EnterprisePluginPolicyContract.PolicyFileName,
                StringComparison.Ordinal))
            .ToArray();
        if (entries.Length != 1 || entries[0].Length is <= 0 or > 4 * 1024 * 1024)
        {
            throw new InvalidDataException(
                "Captured plugin-policy archive does not contain one bounded root policy.");
        }
        using var entry = entries[0].Open();
        using var output = new MemoryStream(checked((int)entries[0].Length));
        entry.CopyTo(output);
        if (output.Length != entries[0].Length)
        {
            throw new EndOfStreamException("Captured raw plugin policy was truncated.");
        }
        return output.ToArray();
    }

    private static async Task<int> RunInstalledLauncherHealthProbeAsync(
        EnterpriseInstallationLayout layout,
        string launcherPath,
        string healthToken,
        TimeSpan timeout,
        CancellationToken cancellationToken,
        EnterpriseCompiledReleaseTrust compiledReleaseTrust,
        RunnerOptions options,
        DevelopmentLauncherHealthProbeDiagnostics diagnostics,
        bool requireControlPlaneTrust = true)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(compiledReleaseTrust);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(diagnostics);
        if (timeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = launcherPath,
                WorkingDirectory = Path.GetDirectoryName(launcherPath)
                    ?? throw new InvalidDataException("Installed Launcher has no parent directory."),
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardError = true,
                StandardErrorEncoding = Encoding.UTF8,
            },
        };
        ApplyDevelopmentUpdateTrustEnvironment(
            process.StartInfo,
            layout,
            compiledReleaseTrust,
            options.IsolationIdentifier);
        if (requireControlPlaneTrust)
        {
            ApplyDevelopmentControlPlaneTrustEnvironment(process.StartInfo, options);
        }
        else
        {
            ClearDevelopmentControlPlaneTrustEnvironment(process.StartInfo);
        }
        process.StartInfo.ArgumentList.Add("--installation-self-check");
        process.StartInfo.ArgumentList.Add("--release-health-token");
        process.StartInfo.ArgumentList.Add(healthToken);
        if (!process.Start())
        {
            throw new InvalidOperationException("Installed Launcher health process did not start.");
        }
        var standardErrorTask = ReadBoundedStandardErrorAsync(
            process.StandardError,
            cancellationToken);
        try
        {
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            var standardError = await standardErrorTask.ConfigureAwait(false);
            diagnostics.Capture(process.ExitCode, standardError);
            return process.ExitCode;
        }
        catch (OperationCanceledException)
        {
            diagnostics.CaptureTimeout();
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch
            {
                // The health process may have exited concurrently with cancellation.
            }
            try
            {
                await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                // The original bounded health timeout remains authoritative.
            }
            try
            {
                _ = await standardErrorTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // The bounded diagnostic reader shares the authoritative timeout.
            }
            throw;
        }
    }

    private static async Task<BoundedStandardError> ReadBoundedStandardErrorAsync(
        StreamReader reader,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(reader);
        var buffer = new char[256];
        var captured = new StringBuilder(MaximumDevelopmentMachineStandardErrorLength);
        var truncated = false;
        try
        {
            while (true)
            {
                var read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }
                var available = MaximumDevelopmentMachineStandardErrorLength - captured.Length;
                if (available > 0)
                {
                    captured.Append(buffer, 0, Math.Min(read, available));
                }
                if (read > available)
                {
                    truncated = true;
                }
            }
            return new BoundedStandardError(captured.ToString(), truncated);
        }
        finally
        {
            Array.Clear(buffer);
        }
    }

    private static void ApplyDevelopmentUpdateTrustEnvironment(
        ProcessStartInfo startInfo,
        EnterpriseInstallationLayout layout,
        EnterpriseCompiledReleaseTrust compiledReleaseTrust,
        string isolationIdentifier)
    {
        ArgumentNullException.ThrowIfNull(startInfo);
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(compiledReleaseTrust);
        _ = EnterpriseDeviceProofKeyStore.CreateDevelopmentE2E(isolationIdentifier);
        compiledReleaseTrust.Validate(layout);
        if (!layout.IsDevelopmentE2E
            || !string.Equals(
                compiledReleaseTrust.Policy.ExpectedChannel,
                EnterpriseReleaseSetContract.LabChannel,
                StringComparison.Ordinal)
            || compiledReleaseTrust.Policy.TrustedKeys.Count != 1)
        {
            throw new InvalidDataException(
                "Development Launcher health probe has invalid public update trust.");
        }

        var releaseKey = compiledReleaseTrust.Policy.TrustedKeys[0];
        var publicTrust = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["ENSOU_DSH_E2E_UPDATE_MANIFEST_URI"] =
                compiledReleaseTrust.ManifestUri.AbsoluteUri,
            ["ENSOU_DSH_E2E_UPDATE_MANIFEST_ORIGIN"] =
                compiledReleaseTrust.Policy.ManifestOrigin.AbsoluteUri,
            ["ENSOU_DSH_E2E_UPDATE_ARTIFACT_ORIGIN"] =
                compiledReleaseTrust.Policy.ArtifactOrigin.AbsoluteUri,
            ["ENSOU_DSH_E2E_UPDATE_KEY_ID"] = releaseKey.KeyId,
            ["ENSOU_DSH_E2E_UPDATE_KEY_X"] = releaseKey.X,
            ["ENSOU_DSH_E2E_UPDATE_KEY_Y"] = releaseKey.Y,
            ["ENSOU_DSH_E2E_LOCAL_APP_DATA_ROOT"] = layout.LocalAppDataRoot,
            ["ENSOU_DSH_E2E_USER_PROFILE_ROOT"] = layout.UserProfileRoot,
            ["ENSOU_DSH_E2E_ISOLATION_ID"] = isolationIdentifier,
        };
        if (publicTrust.Values.Any(string.IsNullOrWhiteSpace))
        {
            throw new InvalidDataException(
                "Development Launcher health probe has incomplete public update trust.");
        }
        foreach (var value in publicTrust)
        {
            startInfo.Environment[value.Key] = value.Value;
        }
    }

    private static void AssertThrows<T>(Action action) where T : Exception
    {
        try
        {
            action();
        }
        catch (T)
        {
            return;
        }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }

    private static string SanitizeDevelopmentFailureEvidenceType(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        var value = exception.GetType().Name;
        return value.Length is >= 1 and <= 128
            && value.All(char.IsAsciiLetterOrDigit)
                ? value
                : "Exception";
    }

    private static string SanitizeDevelopmentFailureEvidenceMessage(string? message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return "No diagnostic message was provided.";
        }
        foreach (var sensitiveLabel in new[]
        {
            "api key", "api_key", "api-key", "authorization", "bearer",
            "cookie", "password", "private key", "secret",
        })
        {
            if (message.Contains(sensitiveLabel, StringComparison.OrdinalIgnoreCase))
            {
                return "Diagnostic message was redacted.";
            }
        }

        var normalized = new StringBuilder(
            Math.Min(message.Length, MaximumDevelopmentMachineFailureMessageLength));
        var previousWasSpace = false;
        foreach (var character in message)
        {
            if (normalized.Length >= MaximumDevelopmentMachineFailureMessageLength)
            {
                break;
            }
            if (char.IsControl(character) || char.IsWhiteSpace(character))
            {
                if (!previousWasSpace && normalized.Length > 0)
                {
                    normalized.Append(' ');
                }
                previousWasSpace = true;
                continue;
            }
            normalized.Append(character);
            previousWasSpace = false;
        }
        var bounded = normalized.ToString().Trim();
        if (bounded.Length == 0)
        {
            return "No diagnostic message was provided.";
        }

        var redacted = new StringBuilder(bounded.Length);
        for (var index = 0; index < bounded.Length;)
        {
            if (!IsPotentialDevelopmentDiagnosticSecretCharacter(bounded[index]))
            {
                redacted.Append(bounded[index++]);
                continue;
            }
            var end = index + 1;
            while (end < bounded.Length
                && IsPotentialDevelopmentDiagnosticSecretCharacter(bounded[end]))
            {
                end++;
            }
            if (end - index >= 32)
            {
                redacted.Append("<redacted>");
            }
            else
            {
                redacted.Append(bounded, index, end - index);
            }
            index = end;
        }
        return redacted.ToString();
    }

    private static bool IsPotentialDevelopmentDiagnosticSecretCharacter(char value) =>
        char.IsAsciiLetterOrDigit(value) || value is '_' or '-' or '+' or '=';

    private static string Hash(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static string CompleteTreeSha256(byte[] archiveBytes)
    {
        using var archiveStream = new MemoryStream(archiveBytes, writable: false);
        return EnterpriseReleaseArchiveTreeHash.Compute(archiveStream);
    }

    private static void AssertInstalledLauncherRuntimeProfileOptionContract(
        RunnerOptions fixtureOptions)
    {
        string[] Arguments(string? runtimeProfile)
        {
            if (runtimeProfile is null)
            {
                return
                [
                    "--phase", "installed-launcher-update",
                    "--isolation-id", fixtureOptions.IsolationIdentifier,
                    "--evidence", fixtureOptions.EvidencePath,
                ];
            }
            return
            [
                "--phase", "installed-launcher-update",
                "--isolation-id", fixtureOptions.IsolationIdentifier,
                "--evidence", fixtureOptions.EvidencePath,
                "--runtime-profile", runtimeProfile,
            ];
        }

        var managed = RunnerOptions.Parse(Arguments(EnterpriseManagedRuntimeProfile));
        var direct = RunnerOptions.Parse(Arguments(EnterpriseDirectLocalRuntimeProfile));
        if (!string.Equals(
                managed.RuntimeProfile,
                EnterpriseManagedRuntimeProfile,
                StringComparison.Ordinal)
            || !string.Equals(
                direct.RuntimeProfile,
                EnterpriseDirectLocalRuntimeProfile,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Installed Launcher runtime-profile options were not preserved exactly.");
        }

        AssertThrows<ArgumentException>(() => RunnerOptions.Parse(Arguments(null)));
        AssertThrows<ArgumentException>(() =>
            RunnerOptions.Parse(Arguments("enterprise-unknown")));
    }

    private static void AssertRuntimeHostOptionsContract()
    {
        var fixtureRoot = Path.Combine(
            Path.GetTempPath(),
            "ensou-dsh-development-runtime-options-contract");
        var runtimeDirectory = Path.Combine(fixtureRoot, "runtime");
        var dataDirectory = Path.Combine(fixtureRoot, "data");
        var logDirectory = Path.Combine(fixtureRoot, "logs");
        var workspaceRoot = Path.Combine(dataDirectory, "workspaces");
        var pluginRoot = Path.Combine(fixtureRoot, "plugins");
        var skillsRoot = Path.Combine(pluginRoot, "skills");
        const int fixedPort = 3080;
        var gatewayOrigin = new Uri("https://gateway.example/");

        if (!string.Equals(
                RequireNetworkRuntimeProfile(
                    EnterpriseManagedRuntimeProfile,
                    gatewayOrigin),
                EnterpriseManagedRuntimeProfile,
                StringComparison.Ordinal)
            || !string.Equals(
                RequireNetworkRuntimeProfile(
                    EnterpriseDirectLocalRuntimeProfile,
                    gatewayOrigin: null),
                EnterpriseDirectLocalRuntimeProfile,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The Runtime transport selector did not preserve its exact profile identity.");
        }
        AssertThrows<ArgumentException>(() => RequireNetworkRuntimeProfile(
            EnterpriseManagedRuntimeProfile,
            gatewayOrigin: null));
        AssertThrows<ArgumentException>(() => RequireNetworkRuntimeProfile(
            EnterpriseDirectLocalRuntimeProfile,
            gatewayOrigin));
        AssertThrows<ArgumentException>(() => RequireNetworkRuntimeProfile(
            "enterprise-unknown",
            gatewayOrigin: null));

        var managed = CreateRuntimeHostOptions(
            EnterpriseManagedRuntimeProfile,
            runtimeDirectory,
            dataDirectory,
            logDirectory,
            workspaceRoot,
            fixedPort,
            pluginRoot,
            skillsRoot);
        var direct = CreateRuntimeHostOptions(
            EnterpriseDirectLocalRuntimeProfile,
            runtimeDirectory,
            dataDirectory,
            logDirectory,
            workspaceRoot,
            fixedPort,
            pluginRoot,
            skillsRoot);
        if (!managed.IsEnterpriseManaged
            || managed.IsEnterpriseDirectLocal
            || !string.Equals(
                managed.Profile,
                DshRuntimeOptions.EnterpriseManagedProfile,
                StringComparison.Ordinal)
            || direct.IsEnterpriseManaged
            || !direct.IsEnterpriseDirectLocal
            || !string.Equals(
                direct.Profile,
                DshRuntimeOptions.EnterpriseDirectLocalProfile,
                StringComparison.Ordinal)
            || direct.ControlledEnvironment is not null
            || direct.AdditionalArguments is not null
            || direct.Port != fixedPort
            || direct.EnterpriseManagedFixedPort != fixedPort)
        {
            throw new InvalidDataException(
                "The real Runtime Host options factory mixed managed and direct-local execution contracts.");
        }

        AssertThrows<ArgumentException>(() => CreateRuntimeHostOptions(
            "enterprise-unknown",
            runtimeDirectory,
            dataDirectory,
            logDirectory,
            workspaceRoot,
            fixedPort,
            pluginRoot,
            skillsRoot));
    }

    private static string RequireNetworkRuntimeProfile(
        string? runtimeProfile,
        Uri? gatewayOrigin)
    {
        var selected = runtimeProfile switch
        {
            EnterpriseManagedRuntimeProfile => EnterpriseManagedRuntimeProfile,
            EnterpriseDirectLocalRuntimeProfile => EnterpriseDirectLocalRuntimeProfile,
            _ => throw new ArgumentException(
                "The network lifecycle phase requires one explicit supported runtime profile."),
        };
        if (string.Equals(
                selected,
                EnterpriseDirectLocalRuntimeProfile,
                StringComparison.Ordinal))
        {
            if (gatewayOrigin is not null)
            {
                throw new ArgumentException(
                    "The direct-local network lifecycle must not receive a gateway origin.");
            }
        }
        else if (gatewayOrigin is null)
        {
            throw new ArgumentException(
                "The managed network lifecycle requires its pinned gateway origin.");
        }
        return selected;
    }

    private static DshRuntimeOptions CreateRuntimeHostOptions(
        string runtimeProfile,
        string runtimeDirectory,
        string dataDirectory,
        string logDirectory,
        string workspaceRoot,
        int fixedPort,
        string pluginRoot,
        string skillsRoot) => runtimeProfile switch
        {
            EnterpriseManagedRuntimeProfile => DshRuntimeOptions.CreateEnterpriseManaged(
                runtimeDirectory,
                dataDirectory,
                logDirectory,
                workspaceRoot,
                fixedPort,
                pluginRoot,
                skillsRoot),
            EnterpriseDirectLocalRuntimeProfile =>
                DshRuntimeOptions.CreateEnterpriseDirectLocal(
                    runtimeDirectory,
                    dataDirectory,
                    logDirectory,
                    workspaceRoot,
                    fixedPort,
                    pluginRoot,
                    skillsRoot),
            _ => throw new ArgumentException(
                "The Runtime Host requires one exact supported Enterprise runtime profile.",
                nameof(runtimeProfile)),
        };

    private static bool MatchesExpectedPolicy(
        EnterprisePluginPolicyArchiveInspection inspection,
        string policyId,
        long generation,
        string policySha256,
        string archiveSha256) =>
        string.Equals(inspection.PolicyId, policyId, StringComparison.Ordinal)
        && inspection.Generation == generation
        && string.Equals(inspection.PolicySha256, policySha256, StringComparison.Ordinal)
        && string.Equals(inspection.ArchiveSha256, archiveSha256, StringComparison.Ordinal);

    private static bool ArtifactMatchesCurrent(
        EnterpriseReleaseArtifact artifact,
        EnterpriseReleaseComponentPointer current) =>
        string.Equals(artifact.ReleaseId, current.ReleaseId, StringComparison.Ordinal)
        && string.Equals(artifact.Sha256, current.ArchiveSha256, StringComparison.Ordinal)
        && string.Equals(
            artifact.CompleteTreeSha256,
            current.CompleteTreeSha256,
            StringComparison.Ordinal);

    private static bool ComponentPointersMatch(
        EnterpriseReleaseComponentPointer left,
        EnterpriseReleaseComponentPointer right) =>
        string.Equals(left.ReleaseId, right.ReleaseId, StringComparison.Ordinal)
        && string.Equals(left.ArchiveSha256, right.ArchiveSha256, StringComparison.Ordinal)
        && string.Equals(
            left.CompleteTreeSha256,
            right.CompleteTreeSha256,
            StringComparison.Ordinal);

    private static bool ReleaseSetCurrentMatches(
        EnterpriseReleaseSetReference left,
        EnterpriseReleaseSetReference right) =>
        string.Equals(left.ReleaseSetId, right.ReleaseSetId, StringComparison.Ordinal)
        && left.Generation == right.Generation
        && left.Sequence == right.Sequence
        && left.MinAcceptedSequence == right.MinAcceptedSequence
        && string.Equals(left.HealthState, right.HealthState, StringComparison.Ordinal)
        && ComponentPointersMatch(left.Launcher, right.Launcher)
        && ComponentPointersMatch(left.Runtime, right.Runtime)
        && ((left.PluginPolicy is null && right.PluginPolicy is null)
            || (left.PluginPolicy is not null
                && right.PluginPolicy is not null
                && ComponentPointersMatch(left.PluginPolicy, right.PluginPolicy)));

    private static bool IsInitialReleasePointer(EnterpriseReleaseSetPointer pointer) =>
        pointer.Previous is null
        && pointer.Current.Generation == 0
        && pointer.Current.Sequence == 0
        && pointer.Current.MinAcceptedSequence == 0
        && pointer.Current.PluginPolicy is null
        && pointer.Current.HealthState == EnterpriseReleaseHealthStates.Healthy
        && pointer.Current.HealthToken is null;

    private static string Base64Url(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed class StaticHandler(IReadOnlyDictionary<Uri, byte[]> content)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (request.RequestUri is null
                || !content.TryGetValue(request.RequestUri, out var bytes))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    RequestMessage = request,
                });
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = request,
                Content = new ByteArrayContent(bytes),
            });
        }
    }

    private static async Task<object> RunApplyReleaseUpdateAsync(RunnerOptions options)
    {
        var localAppDataRoot = RequireOption(options.LocalAppDataRoot, "local-app-data-root");
        var userProfileRoot = RequireOption(options.UserProfileRoot, "user-profile-root");
        var launcherArchivePath = RequireOption(options.LauncherArchivePath, "launcher-archive");
        var initialRuntimeArchivePath = RequireOption(options.RuntimeArchivePath, "runtime-archive");
        var initialPluginPolicyArchivePath = RequireOption(
            options.PluginPolicyArchivePath,
            "plugin-policy-archive");
        var target = options.GetTargetReleaseTuple();
        var runtimeArchivePath = target?.RuntimeArchivePath ?? initialRuntimeArchivePath;
        var pluginPolicyArchivePath = target?.PluginPolicyArchivePath
            ?? initialPluginPolicyArchivePath;
        var manifestPath = RequireOption(options.UpdateManifestPath, "update-manifest");
        var privateKeyPath = RequireOption(
            options.ReleasePrivateKeyPath,
            "release-private-key");
        var manifestBytes = ReadArtifactBytes(
            manifestPath,
            HashFile(manifestPath),
            512 * 1024);
        var manifest = EnterpriseReleaseSetManifest.Parse(manifestBytes);
        if (manifest.Channel != "lab"
            || manifest.Environment != EnterpriseReleaseSetContract.DevelopmentE2EEnvironment
            || manifest.Sequence != 2
            || manifest.Generation != 2
            || manifest.MinAcceptedSequence != 1)
        {
            throw new InvalidDataException(
                "Development managed update manifest has an unexpected release identity.");
        }
        var manifestRuntime = manifest.Artifacts.Single(artifact =>
            string.Equals(
                artifact.Component,
                EnterpriseReleaseSetContract.RuntimeComponent,
                StringComparison.Ordinal));
        if (target is not null
            && !string.Equals(
                manifestRuntime.ReleaseId,
                target.RuntimeReleaseId,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Development managed update runtime release identity does not match its target tuple.");
        }

        var archives = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [EnterpriseReleaseSetContract.LauncherComponent] = launcherArchivePath,
            [EnterpriseReleaseSetContract.RuntimeComponent] = runtimeArchivePath,
            [EnterpriseReleaseSetContract.PluginPolicyComponent] = pluginPolicyArchivePath,
        };
        var content = new Dictionary<Uri, byte[]> { [SignedLabManifestUri] = manifestBytes };
        foreach (var artifact in manifest.Artifacts)
        {
            if (!archives.TryGetValue(artifact.Component, out var archivePath))
            {
                throw new InvalidDataException(
                    "Development managed update contains an unexpected artifact component.");
            }
            content.Add(
                artifact.Uri,
                ReadArtifactBytes(archivePath, artifact.Sha256, artifact.SizeBytes));
        }
        RequireManifestHttpContentMap(
            manifest,
            manifestBytes,
            content,
            requireExactCount: true);

        var keyBytes = ReadArtifactBytes(
            privateKeyPath,
            HashFile(privateKeyPath),
            1024 * 1024);
        using var signer = ECDsa.Create();
        try
        {
            signer.ImportPkcs8PrivateKey(keyBytes, out var consumed);
            if (consumed != keyBytes.Length)
            {
                throw new InvalidDataException(
                    "Development release private key contains trailing bytes.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }
        var publicParameters = signer.ExportParameters(false);
        var trust = new EnterpriseReleaseTrustPolicy
        {
            Product = EnterpriseReleaseSetContract.Product,
            Environment = EnterpriseReleaseSetContract.DevelopmentE2EEnvironment,
            ExpectedChannel = EnterpriseReleaseSetContract.LabChannel,
            CurrentStartupStubProtocol =
                EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
            ManifestOrigin = new Uri("https://updates.example/"),
            ArtifactOrigin = DevelopmentArtifactOrigin,
            TrustedKeys = [new EnterpriseReleasePublicKey(
                DevelopmentReleaseKeyId,
                Base64Url(publicParameters.Q.X!),
                Base64Url(publicParameters.Q.Y!))],
        };
        var compiledReleaseTrust = new EnterpriseCompiledReleaseTrust(
            SignedLabManifestUri,
            trust);
        EnterpriseReleaseSetValidator.Verify(manifest, trust, DateTimeOffset.UtcNow);

        var layout = EnterpriseInstallationLayout.CreateDevelopmentE2E(
            localAppDataRoot,
            userProfileRoot);
        var before = new EnterpriseReleaseSetPointerStore(layout).ReadRequired();
        if (before.Current.Sequence != 1
            || before.Current.HealthState != EnterpriseReleaseHealthStates.Healthy)
        {
            throw new InvalidDataException(
                "Development managed update did not begin from healthy sequence 1.");
        }
        if (target is not null
            && (string.Equals(
                    before.Current.Runtime.ReleaseId,
                    manifestRuntime.ReleaseId,
                    StringComparison.Ordinal)
                || string.Equals(
                    before.Current.Runtime.ArchiveSha256,
                    manifestRuntime.Sha256,
                    StringComparison.Ordinal)
                || string.Equals(
                    before.Current.Runtime.CompleteTreeSha256,
                    manifestRuntime.CompleteTreeSha256,
                    StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "Development managed update target runtime does not differ from the healthy initial runtime.");
        }
        var dataBefore = EnsureLocalDataSentinels(
            EnterpriseManagedPaths.CreateDevelopmentE2E(localAppDataRoot, userProfileRoot),
            options.IsolationIdentifier);
        using var httpClient = new HttpClient(new StaticHandler(content));
        var staged = await new EnterpriseReleaseStartupCoordinator(
                layout,
                SignedLabManifestUri,
                trust,
                httpClient)
            .CheckOnEveryStartupAsync()
            .ConfigureAwait(false);
        if (!staged.RequiresBootstrapHealthCheck || staged.State != "pending-health")
        {
            throw new InvalidDataException(
                "Development sequence 2 did not enter pending health verification.");
        }
        var healthProbeDiagnostics = new DevelopmentLauncherHealthProbeDiagnostics();
        var health = await new EnterpriseBootstrapHealthGate(
                layout,
                EnterpriseBootstrapHealthGate.ColdStartTimeout,
                compiledReleaseTrust)
            .EnsureHealthyAsync((launcherPath, healthToken, timeout, cancellationToken) =>
                RunInstalledLauncherHealthProbeAsync(
                    layout,
                    launcherPath,
                    healthToken,
                    timeout,
                    cancellationToken,
                    compiledReleaseTrust,
                    options,
                    healthProbeDiagnostics))
            .ConfigureAwait(false);
        if (!health.Healthy)
        {
            throw new DevelopmentLauncherHealthProbeException(healthProbeDiagnostics);
        }
        var afterStore = new EnterpriseReleaseSetPointerStore(layout);
        var after = afterStore.ReadRequired();
        var activePolicyAfter = target is null ? null : afterStore.ReadActivePluginPolicyRequired();
        var feedState = new EnterpriseReleaseFeedStateStore(
            layout,
            trust.ExpectedChannel).TryRead()
            ?? throw new InvalidDataException(
                "Development sequence 2 signed-feed state is missing.");
        var dataAfter = EnsureLocalDataSentinels(
            EnterpriseManagedPaths.CreateDevelopmentE2E(localAppDataRoot, userProfileRoot),
            options.IsolationIdentifier,
            requireExisting: true);
        if (after.Current.HealthState != EnterpriseReleaseHealthStates.Healthy
            || after.Current.Sequence != manifest.Sequence
            || after.Current.Generation != manifest.Generation
            || !string.Equals(after.Current.ReleaseSetId, manifest.ReleaseSetId, StringComparison.Ordinal)
            || !string.Equals(feedState.LastManifestSha256, Hash(manifestBytes), StringComparison.Ordinal)
            || dataAfter != dataBefore)
        {
            throw new InvalidDataException(
                "Development sequence 2 activation or local-data preservation failed.");
        }

        if (target is not null
            && (!string.Equals(
                    after.Current.Runtime.ReleaseId,
                    manifestRuntime.ReleaseId,
                    StringComparison.Ordinal)
                || !string.Equals(
                    after.Current.Runtime.ArchiveSha256,
                    manifestRuntime.Sha256,
                    StringComparison.Ordinal)
                || !string.Equals(
                    after.Current.Runtime.CompleteTreeSha256,
                    manifestRuntime.CompleteTreeSha256,
                    StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "Development sequence 2 did not activate the exact target runtime tuple.");
        }
        if (target is not null
            && (!string.Equals(
                    after.Current.PluginPolicy?.ReleaseId,
                    target.PluginPolicyReleaseId,
                    StringComparison.Ordinal)
                || activePolicyAfter is null
                || !string.Equals(
                    activePolicyAfter.PolicyId,
                    target.PluginPolicyId,
                    StringComparison.Ordinal)
                || activePolicyAfter.Generation != target.PluginPolicyGeneration
                || !string.Equals(
                    activePolicyAfter.PolicySha256,
                    target.PluginPolicySha256,
                    StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "Development sequence 2 did not activate the exact target plugin-policy identity.");
        }

        return new
        {
            releaseSetId = after.Current.ReleaseSetId,
            generation = after.Current.Generation,
            sequence = after.Current.Sequence,
            minAcceptedSequence = after.Current.MinAcceptedSequence,
            manifestSha256 = feedState.LastManifestSha256,
            healthState = after.Current.HealthState,
            workspaceSentinelSha256 = dataAfter.WorkspaceSha256,
            historySentinelSha256 = dataAfter.HistorySha256,
            runtimeDownloaded = false,
            distinctRuntimeActivated = target is not null,
            genuineDistinctRuntimeUpgradeCovered = false,
            runtimeReleaseId = after.Current.Runtime.ReleaseId,
            runtimeArchiveSha256 = after.Current.Runtime.ArchiveSha256,
            runtimeCompleteTreeSha256 = after.Current.Runtime.CompleteTreeSha256,
            signedFeedInstalled = true,
        };
    }

    private static Task<object> RunPrepareLauncherUpdateAsync(RunnerOptions options)
    {
        var localAppDataRoot = RequireOption(options.LocalAppDataRoot, "local-app-data-root");
        var userProfileRoot = RequireOption(options.UserProfileRoot, "user-profile-root");
        var launcherReleaseId = RequireOption(options.LauncherReleaseId, "launcher-release-id");
        var runtimeReleaseId = RequireOption(options.RuntimeReleaseId, "runtime-release-id");
        var pluginPolicyReleaseId = RequireOption(
            options.PluginPolicyReleaseId,
            "plugin-policy-release-id");
        var launcherArchivePath = RequireOption(options.LauncherArchivePath, "launcher-archive");
        var runtimeArchivePath = RequireOption(options.RuntimeArchivePath, "runtime-archive");
        var pluginPolicyArchivePath = RequireOption(
            options.PluginPolicyArchivePath,
            "plugin-policy-archive");
        var targetLauncher = options.GetTargetLauncherTuple()
            ?? throw new ArgumentException(
                "prepare-launcher-update requires a complete target Launcher tuple.");
        if (options.GetTargetReleaseTuple() is not null)
        {
            throw new ArgumentException(
                "prepare-launcher-update does not accept a target runtime tuple.");
        }

        var expectedPolicyId = RequireOption(options.ExpectedPluginPolicyId, "plugin-policy-id");
        var expectedPolicyGeneration = options.ExpectedPluginPolicyGeneration
            ?? throw new ArgumentException("--plugin-policy-generation is required.");
        var expectedPolicySha256 = RequireOption(
            options.ExpectedPluginPolicySha256,
            "plugin-policy-sha256");
        var expectedPluginArchiveSha256 = RequireOption(
            options.ExpectedPluginArchiveSha256,
            "plugin-archive-sha256");
        var privateKeyPath = RequireOption(options.ReleasePrivateKeyPath, "release-private-key");
        var manifestOutputPath = RequireOption(options.UpdateManifestOutputPath, "update-manifest-output");
        var journalOutputPath = RequireOption(options.UpdateJournalOutputPath, "update-journal-output");
        var promotionResultOutputPath = RequireOption(
            options.UpdatePromotionResultOutputPath,
            "update-promotion-result-output");

        var layout = EnterpriseInstallationLayout.CreateDevelopmentE2E(
            localAppDataRoot,
            userProfileRoot);
        var pointerStore = new EnterpriseReleaseSetPointerStore(layout);
        var before = pointerStore.ReadRequired();
        var currentPolicy = before.Current.PluginPolicy
            ?? throw new InvalidDataException(
                "Launcher-update preparation requires the active sequence-2 plugin policy.");
        if (before.Current.Sequence != 2
            || before.Current.Generation != 2
            || before.Current.MinAcceptedSequence != 1
            || before.Current.HealthState != EnterpriseReleaseHealthStates.Healthy
            || !string.Equals(
                before.Current.Launcher.ReleaseId,
                launcherReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                before.Current.Runtime.ReleaseId,
                runtimeReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                currentPolicy.ReleaseId,
                pluginPolicyReleaseId,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Launcher-update preparation did not begin from the exact healthy sequence-2 tuple.");
        }

        var launcherBytes = ReadArtifactBytes(
            launcherArchivePath,
            before.Current.Launcher.ArchiveSha256,
            1L * 1024 * 1024 * 1024);
        var runtimeBytes = ReadArtifactBytes(
            runtimeArchivePath,
            before.Current.Runtime.ArchiveSha256,
            8L * 1024 * 1024 * 1024);
        var pluginPolicyBytes = ReadArtifactBytes(
            pluginPolicyArchivePath,
            currentPolicy.ArchiveSha256,
            512L * 1024 * 1024);
        if (!string.Equals(currentPolicy.ArchiveSha256, expectedPluginArchiveSha256, StringComparison.Ordinal)
            || !string.Equals(
                CompleteTreeSha256(launcherBytes),
                before.Current.Launcher.CompleteTreeSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                CompleteTreeSha256(runtimeBytes),
                before.Current.Runtime.CompleteTreeSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                CompleteTreeSha256(pluginPolicyBytes),
                currentPolicy.CompleteTreeSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Launcher-update preparation current archive bytes do not bind the healthy sequence-2 tuple.");
        }

        var targetLauncherBytes = ReadArtifactBytes(
            targetLauncher.LauncherArchivePath,
            HashFile(targetLauncher.LauncherArchivePath),
            1L * 1024 * 1024 * 1024);
        var targetLauncherTreeSha256 = CompleteTreeSha256(targetLauncherBytes);
        if (string.Equals(
                targetLauncher.LauncherReleaseId,
                before.Current.Launcher.ReleaseId,
                StringComparison.Ordinal)
            || string.Equals(
                Hash(targetLauncherBytes),
                before.Current.Launcher.ArchiveSha256,
                StringComparison.Ordinal)
            || string.Equals(
                targetLauncherTreeSha256,
                before.Current.Launcher.CompleteTreeSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "A target Launcher tuple must differ in release identity, archive bytes, and complete tree.");
        }

        var capturedPolicyDirectory = RequireDevelopmentFixtureSnapshotDirectory(
            Path.Combine(
                localAppDataRoot,
                DevelopmentFixtureInputDirectoryName,
                $".lifecycle-policy-{Guid.NewGuid():N}"),
            localAppDataRoot,
            layout.ManagedRoot,
            layout.PackageRoot);
        Directory.CreateDirectory(capturedPolicyDirectory);
        var capturedPolicyPath = Path.Combine(capturedPolicyDirectory, "plugin-policy.zip");
        try
        {
            File.WriteAllBytes(capturedPolicyPath, pluginPolicyBytes);
            var currentInspection = EnterprisePluginPolicyArchiveValidator.Validate(
                capturedPolicyPath,
                before.Current.Launcher.ReleaseId,
                before.Current.Runtime.ReleaseId);
            var targetInspection = EnterprisePluginPolicyArchiveValidator.Validate(
                capturedPolicyPath,
                targetLauncher.LauncherReleaseId,
                before.Current.Runtime.ReleaseId);
            if (!MatchesExpectedPolicy(
                    currentInspection,
                    expectedPolicyId,
                    expectedPolicyGeneration,
                    expectedPolicySha256,
                    expectedPluginArchiveSha256)
                || !MatchesExpectedPolicy(
                    targetInspection,
                    expectedPolicyId,
                    expectedPolicyGeneration,
                    expectedPolicySha256,
                    expectedPluginArchiveSha256))
            {
                throw new InvalidDataException(
                    "The active plugin policy is not bound to both current and target Launcher tuples.");
            }
            pointerStore.ReadActivePluginPolicyRequired().RequireLeaseBinding(
                expectedPolicyId,
                expectedPolicyGeneration,
                expectedPolicySha256);

            var content = new Dictionary<Uri, byte[]>();
            var releaseSetId = $"{before.Current.ReleaseSetId}-launcher-update";
            var artifacts = CreateReleaseArtifacts(
                releaseSetId,
                targetLauncher.LauncherReleaseId,
                targetLauncherBytes,
                before.Current.Runtime.ReleaseId,
                runtimeBytes,
                currentPolicy.ReleaseId,
                pluginPolicyBytes,
                content);
            var manifestLauncher = artifacts.Single(artifact => string.Equals(
                artifact.Component,
                EnterpriseReleaseSetContract.LauncherComponent,
                StringComparison.Ordinal));
            var manifestRuntime = artifacts.Single(artifact => string.Equals(
                artifact.Component,
                EnterpriseReleaseSetContract.RuntimeComponent,
                StringComparison.Ordinal));
            var manifestPolicy = artifacts.Single(artifact => string.Equals(
                artifact.Component,
                EnterpriseReleaseSetContract.PluginPolicyComponent,
                StringComparison.Ordinal));
            if (!string.Equals(manifestLauncher.CompleteTreeSha256, targetLauncherTreeSha256, StringComparison.Ordinal)
                || !ArtifactMatchesCurrent(manifestRuntime, before.Current.Runtime)
                || !ArtifactMatchesCurrent(manifestPolicy, currentPolicy))
            {
                throw new InvalidDataException(
                    "Launcher-update manifest did not preserve exact runtime and plugin-policy bytes.");
            }

            var privateKeyBytes = ReadArtifactBytes(
                privateKeyPath,
                HashFile(privateKeyPath),
                1024 * 1024);
            using var signer = ECDsa.Create();
            try
            {
                signer.ImportPkcs8PrivateKey(privateKeyBytes, out var consumed);
                if (consumed != privateKeyBytes.Length)
                {
                    throw new InvalidDataException(
                        "Launcher-update private key contains trailing bytes.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privateKeyBytes);
            }

            var issuedAtUtc = WholeSecond(DateTimeOffset.UtcNow.AddMinutes(-1));
            var manifest = CreateSignedManifest(
                signer,
                releaseSetId,
                generation: 3,
                sequence: 3,
                minAcceptedSequence: 2,
                issuedAtUtc,
                issuedAtUtc.AddHours(4),
                artifacts);
            var manifestBytes = SerializeReleaseDocument(manifest);
            RequireCanonicalUtcTimestamps(manifestBytes, expectedCount: 2);
            RequireManifestArtifactContent(manifest, content);
            var publicParameters = signer.ExportParameters(false);
            var releasePublicKey = new EnterpriseReleasePublicKey(
                DevelopmentReleaseKeyId,
                Base64Url(publicParameters.Q.X!),
                Base64Url(publicParameters.Q.Y!));
            var promotion = PromoteDevelopmentCandidate(
                Path.Combine(Path.GetDirectoryName(promotionResultOutputPath)!, "feed-sequence-3"),
                promotionResultOutputPath,
                manifest,
                manifestBytes,
                content,
                releasePublicKey);
            WriteNewFile(manifestOutputPath, File.ReadAllBytes(promotion.ChannelManifestPath));
            WriteNewFile(journalOutputPath, File.ReadAllBytes(promotion.JournalEntryPath));

            var after = pointerStore.ReadRequired();
            if (!ReleaseSetCurrentMatches(after.Current, before.Current)
                || after.Current.Sequence != 2
                || after.Current.Generation != 2
                || after.Current.HealthState != EnterpriseReleaseHealthStates.Healthy)
            {
                throw new InvalidDataException(
                    "Launcher-update preparation changed the active sequence-2 release set.");
            }

            return Task.FromResult<object>(new
            {
                activationDeferred = true,
                releaseSetId = manifest.ReleaseSetId,
                generation = manifest.Generation,
                sequence = manifest.Sequence,
                minAcceptedSequence = manifest.MinAcceptedSequence,
                manifestSha256 = Hash(manifestBytes),
                targetLauncherReleaseId = manifestLauncher.ReleaseId,
                targetLauncherArchiveSha256 = manifestLauncher.Sha256,
                targetLauncherCompleteTreeSha256 = manifestLauncher.CompleteTreeSha256,
                runtimeReleaseId = manifestRuntime.ReleaseId,
                runtimeArchiveSha256 = manifestRuntime.Sha256,
                runtimeCompleteTreeSha256 = manifestRuntime.CompleteTreeSha256,
                pluginPolicyReleaseId = manifestPolicy.ReleaseId,
                pluginPolicyArchiveSha256 = manifestPolicy.Sha256,
                pluginPolicyCompleteTreeSha256 = manifestPolicy.CompleteTreeSha256,
                currentSequence = after.Current.Sequence,
                currentHealthState = after.Current.HealthState,
                signedPromotionPrepared = true,
            });
        }
        finally
        {
            if (Directory.Exists(capturedPolicyDirectory))
            {
                Directory.Delete(
                    RequireDevelopmentFixtureSnapshotDirectory(
                        capturedPolicyDirectory,
                        localAppDataRoot,
                        layout.ManagedRoot,
                        layout.PackageRoot),
                    recursive: true);
            }
        }
    }

    private static async Task<object> RunAutomaticReleaseUpdateAsync(RunnerOptions options)
    {
        if (options.ReadySignalPath is null
            || options.ContinueSignalPath is null
            || options.SignalToken is null)
        {
            throw new ArgumentException(
                "automatic-release-update requires both signal files and a signal token.");
        }

        var launcherArchivePath = RequireOption(options.LauncherArchivePath, "launcher-archive");
        var initialRuntimeArchivePath = RequireOption(options.RuntimeArchivePath, "runtime-archive");
        var initialPluginPolicyArchivePath = RequireOption(
            options.PluginPolicyArchivePath,
            "plugin-policy-archive");
        var target = options.GetTargetReleaseTuple();
        var targetLauncher = options.GetTargetLauncherTuple();
        var isLauncherUpdate = targetLauncher is not null;
        var expectedSequence = isLauncherUpdate ? 3 : 2;
        var expectedGeneration = isLauncherUpdate ? 3 : 2;
        var expectedMinimumSequence = isLauncherUpdate ? 2 : 1;
        var expectedCurrentSequence = isLauncherUpdate ? 2 : 1;
        var selectedLauncherArchivePath = targetLauncher?.LauncherArchivePath ?? launcherArchivePath;
        var runtimeArchivePath = target?.RuntimeArchivePath ?? initialRuntimeArchivePath;
        var pluginPolicyArchivePath = target?.PluginPolicyArchivePath
            ?? initialPluginPolicyArchivePath;
        var manifestPath = RequireOption(options.UpdateManifestPath, "update-manifest");
        var privateKeyPath = RequireOption(
            options.ReleasePrivateKeyPath,
            "release-private-key");
        var manifestBytes = ReadArtifactBytes(
            manifestPath,
            HashFile(manifestPath),
            512 * 1024);
        var manifest = EnterpriseReleaseSetManifest.Parse(manifestBytes);
        if (manifest.Channel != EnterpriseReleaseSetContract.LabChannel
            || manifest.Environment != EnterpriseReleaseSetContract.DevelopmentE2EEnvironment
            || manifest.Sequence != expectedSequence
            || manifest.Generation != expectedGeneration
            || manifest.MinAcceptedSequence != expectedMinimumSequence)
        {
            throw new InvalidDataException(
                "Automatic managed update manifest has an unexpected release identity.");
        }
        var manifestRuntime = manifest.Artifacts.Single(artifact =>
            string.Equals(
                artifact.Component,
                EnterpriseReleaseSetContract.RuntimeComponent,
                StringComparison.Ordinal));
        var manifestLauncher = manifest.Artifacts.Single(artifact =>
            string.Equals(
                artifact.Component,
                EnterpriseReleaseSetContract.LauncherComponent,
                StringComparison.Ordinal));
        if (target is not null
            && !string.Equals(
                manifestRuntime.ReleaseId,
                target.RuntimeReleaseId,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Automatic managed update runtime release identity does not match its target tuple.");
        }
        if (targetLauncher is not null
            && !string.Equals(
                manifestLauncher.ReleaseId,
                targetLauncher.LauncherReleaseId,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Automatic managed update Launcher release identity does not match its target tuple.");
        }

        var archives = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [EnterpriseReleaseSetContract.LauncherComponent] = selectedLauncherArchivePath,
            [EnterpriseReleaseSetContract.RuntimeComponent] = runtimeArchivePath,
            [EnterpriseReleaseSetContract.PluginPolicyComponent] = pluginPolicyArchivePath,
        };
        var content = new Dictionary<Uri, byte[]> { [SignedLabManifestUri] = manifestBytes };
        foreach (var artifact in manifest.Artifacts)
        {
            if (!archives.TryGetValue(artifact.Component, out var archivePath))
            {
                throw new InvalidDataException(
                    "Automatic managed update contains an unexpected artifact component.");
            }
            content.Add(
                artifact.Uri,
                ReadArtifactBytes(archivePath, artifact.Sha256, artifact.SizeBytes));
        }
        RequireManifestHttpContentMap(
            manifest,
            manifestBytes,
            content,
            requireExactCount: true);

        var keyBytes = ReadArtifactBytes(
            privateKeyPath,
            HashFile(privateKeyPath),
            1024 * 1024);
        using var signer = ECDsa.Create();
        try
        {
            signer.ImportPkcs8PrivateKey(keyBytes, out var consumed);
            if (consumed != keyBytes.Length)
            {
                throw new InvalidDataException(
                    "Automatic managed update private key contains trailing bytes.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }
        var publicParameters = signer.ExportParameters(false);
        var trust = new EnterpriseReleaseTrustPolicy
        {
            Product = EnterpriseReleaseSetContract.Product,
            Environment = EnterpriseReleaseSetContract.DevelopmentE2EEnvironment,
            ExpectedChannel = EnterpriseReleaseSetContract.LabChannel,
            CurrentStartupStubProtocol =
                EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
            ManifestOrigin = new Uri("https://updates.example/"),
            ArtifactOrigin = DevelopmentArtifactOrigin,
            TrustedKeys = [new EnterpriseReleasePublicKey(
                DevelopmentReleaseKeyId,
                Base64Url(publicParameters.Q.X!),
                Base64Url(publicParameters.Q.Y!))],
        };
        var compiledReleaseTrust = new EnterpriseCompiledReleaseTrust(
            SignedLabManifestUri,
            trust);
        EnterpriseReleaseSetValidator.Verify(manifest, trust, DateTimeOffset.UtcNow);
        using var authorization = options.Phase == RunnerPhase.InstalledLauncherUpdate
            ? new DevelopmentFeedAuthorizationForwarder(
                options.ControlOrigin ?? throw new InvalidDataException("Control origin is required."),
                options.ServerCertificateSha256 ?? throw new InvalidDataException("Control TLS pin is required."),
                Environment.GetEnvironmentVariable("ENSOU_DSH_E2E_FEED_INTERNAL_SECRET")
                    ?? throw new InvalidDataException("The isolated feed internal secret is required."))
            : null;
        await using var artifactServer = await DevelopmentHttpsArtifactServer.StartAsync(content, authorization: authorization)
            .ConfigureAwait(false);

        if (options.Phase == RunnerPhase.InstalledLauncherUpdate)
        {
            return await RunInstalledLauncherUpdateAsync(options, manifest, compiledReleaseTrust, artifactServer)
                .ConfigureAwait(false);
        }

        var preReadyProgress = new AutomaticReleaseUpdateProgressSink(options.EvidencePath);
        var preReadyStage = AutomaticReleaseUpdateProgressStage.ContextCreate;
        preReadyProgress.RecordEntered(preReadyStage);
        RuntimeContext context;
        try
        {
            context = await RuntimeContext.CreateAsync(
                    options,
                    realRuntimeHost: true,
                    automaticProgress: preReadyProgress)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            preReadyProgress.RecordFailure(preReadyStage, exception);
            throw new InvalidDataException(
                "Automatic managed update did not reach the Ready signal at safe stage context-create.",
                exception);
        }
        await using var contextLifetime = context;
        var beforeRelease = new EnterpriseReleaseSetPointerStore(context.InstallationLayout)
            .ReadRequired();
        if (beforeRelease.Current.Sequence != expectedCurrentSequence
            || beforeRelease.Current.HealthState != EnterpriseReleaseHealthStates.Healthy)
        {
            throw new InvalidDataException(
                "Automatic managed update did not begin from the expected healthy release sequence.");
        }
        if (target is not null
            && (string.Equals(
                    beforeRelease.Current.Runtime.ReleaseId,
                    manifestRuntime.ReleaseId,
                    StringComparison.Ordinal)
                || string.Equals(
                    beforeRelease.Current.Runtime.ArchiveSha256,
                    manifestRuntime.Sha256,
                    StringComparison.Ordinal)
                || string.Equals(
                    beforeRelease.Current.Runtime.CompleteTreeSha256,
                    manifestRuntime.CompleteTreeSha256,
                    StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "Automatic managed update target runtime does not differ from the healthy initial runtime.");
        }
        if (targetLauncher is not null
            && (string.Equals(
                    beforeRelease.Current.Launcher.ReleaseId,
                    manifestLauncher.ReleaseId,
                    StringComparison.Ordinal)
                || string.Equals(
                    beforeRelease.Current.Launcher.ArchiveSha256,
                    manifestLauncher.Sha256,
                    StringComparison.Ordinal)
                || string.Equals(
                    beforeRelease.Current.Launcher.CompleteTreeSha256,
                    manifestLauncher.CompleteTreeSha256,
                    StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "Automatic managed update target Launcher does not differ from the healthy current Launcher.");
        }
        ActualRuntimeHarnessHost actualHost;
        EnterpriseEnrollmentDeviceContext device;
        try
        {
            preReadyStage = AutomaticReleaseUpdateProgressStage.DevicePrepare;
            preReadyProgress.RecordEntered(preReadyStage);
            device = await context.DevicePreparation.PrepareAsync().ConfigureAwait(false);
            preReadyStage = AutomaticReleaseUpdateProgressStage.AuthorizationHydrateRefresh;
            preReadyProgress.RecordEntered(preReadyStage);
            var initial = await context.AuthorizationLifecycle.HydrateAndRefreshAsync(device)
                .ConfigureAwait(false);
            if (!initial.HasCommittedBinding
                || !initial.RefreshCompleted
                || initial.AccessDecision.ClientState != EnterpriseClientState.Ready
                || !initial.AccessDecision.MayCallManagedApi)
            {
                throw new InvalidDataException(
                    "Automatic managed update could not establish its initial Ready state.");
            }

            context.RequireActivePluginPolicyBinding();
            // This includes retained inventory admission before the Host's own
            // 45-second web-health deadline starts; it is not a health bypass.
            using var beforeReadyCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(120));
            preReadyStage = AutomaticReleaseUpdateProgressStage.RuntimeStart;
            preReadyProgress.RecordEntered(preReadyStage);
            await context.Session.EnsureStartedAsync(beforeReadyCancellation.Token)
                .ConfigureAwait(false);
            actualHost = context.RequireActualRuntimeHost();
            preReadyStage = AutomaticReleaseUpdateProgressStage.OwnedHealth;
            preReadyProgress.RecordEntered(preReadyStage);
            if (context.Host.StartCount != 1
                || !await actualHost.IsHealthyAsync(beforeReadyCancellation.Token)
                    .ConfigureAwait(false))
            {
                throw new InvalidDataException(
                    "The production managed DSH Host did not start with an owned healthy Runtime.");
            }
        }
        catch (Exception exception)
        {
            preReadyProgress.RecordFailure(preReadyStage, exception);
            throw new InvalidDataException(
                $"Automatic managed update did not reach the Ready signal at safe stage {ToWireValue(preReadyStage)}.",
                exception);
        }
        context.RequireActivePluginPolicyBinding();
        var dataBefore = EnsureLocalDataSentinels(context.Paths, options.IsolationIdentifier);
        var credentialBefore = await context.CredentialStore.ReadCommittedAsync()
            .ConfigureAwait(false)
            ?? throw new InvalidDataException(
                "Automatic managed update has no committed binding before policy advance.");
        WriteSignal(options.ReadySignalPath, options.SignalToken);
        var postReadyStage = AutomaticReleaseUpdateProgressStage.WaitContinue;
        preReadyProgress.RecordEntered(postReadyStage);
        try
        {
            await WaitForSignalAsync(
                    options.ContinueSignalPath,
                    options.SignalToken,
                    TimeSpan.FromSeconds(90))
                .ConfigureAwait(false);
            preReadyProgress.RecordCompleted(postReadyStage);
        }
        catch (Exception exception)
        {
            preReadyProgress.RecordFailure(postReadyStage, exception);
            throw;
        }

        postReadyStage = context.IsEnterpriseDirectLocal
            ? AutomaticReleaseUpdateProgressStage.AuthorizationRefresh
            : AutomaticReleaseUpdateProgressStage.GatewayDenialRefresh;
        preReadyProgress.RecordEntered(postReadyStage);
        GatewayUpdateDenialEvidence? gatewayDenial = null;
        if (context.IsEnterpriseDirectLocal)
        {
            context.RequireDirectLocalNoGatewayTransport();
        }
        else
        {
            gatewayDenial = await context.SendExpectedGatewayUpdateRequiredAsync()
                .ConfigureAwait(false);
        }
        var refreshed = await context.AuthorizationLifecycle.RefreshInPlaceAsync(device)
            .ConfigureAwait(false);
        preReadyProgress.RecordCompleted(postReadyStage);
        var credentialAfterRefresh = await context.CredentialStore.ReadCommittedAsync()
            .ConfigureAwait(false)
            ?? throw new InvalidDataException(
                "Automatic managed update removed the committed binding credential.");
        if (!refreshed.HasCommittedBinding
            || !refreshed.RefreshCompleted
            || refreshed.AccessDecision.ClientState != EnterpriseClientState.UpdateRequired
            || refreshed.AccessDecision.MayStartHarness
            || refreshed.AccessDecision.MayCallManagedApi
            || refreshed.AccessDecision.ErrorCode != EnterpriseErrorCodes.ClientUpdateRequired
            || refreshed.AccessDecision.ResetScope != EnterpriseResetScope.None
            || context.Host.StopCount != 0
            || context.Host.StartCount != 1
            || !string.Equals(
                credentialAfterRefresh.Receipt.BindingId,
                credentialBefore.Receipt.BindingId,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The update-required refresh did not preserve the owned Runtime and verified binding.");
        }
        var restarts = 0;
        var shutdowns = 0;
        var restores = 0;
        var updates = EnterpriseAuthenticatedReleaseUpdateCoordinator.Create(
            context.Session,
            context.InstallationLayout,
            SignedLabManifestUri,
            trust,
            // The transaction transport is local, pinned HTTPS and fresh per
            // attempt; it serves only the exact signed manifest and archive
            // bytes after the real authorization lifecycle has admitted stage.
            () => artifactServer.CreateClient(),
            () => { restarts++; return Task.CompletedTask; },
            () => shutdowns++,
            EnterpriseProductIdentity.DevelopmentE2EDefaultPort);
        var automatic = new EnterpriseAutomaticReleaseUpdateCoordinator(
            updates,
            (operationId, cancellationToken) => actualHost.StopForManagedUpdateAsync(
                operationId,
                cancellationToken),
            () => EnterpriseHarnessWriterGuard.RequireQuiescentLoopbackPort(
                EnterpriseProductIdentity.DevelopmentE2EDefaultPort),
            async cancellationToken =>
            {
                _ = cancellationToken;
                restores++;
                _ = await context.Session.EnsureStartedAsync(CancellationToken.None)
                    .ConfigureAwait(false);
            });
        postReadyStage = AutomaticReleaseUpdateProgressStage.AutomaticStage;
        preReadyProgress.RecordEntered(postReadyStage);
        var staged = await automatic.RunAsync(
                refreshed.RefreshCompleted,
                refreshed.AccessDecision)
            .ConfigureAwait(false);
        preReadyProgress.RecordCompleted(postReadyStage);
        if (staged.Disposition != EnterpriseAuthenticatedReleaseUpdateDisposition.Restarting
            || staged.FailureKind != EnterpriseAuthenticatedReleaseUpdateFailureKind.None
            || staged.UpdateOutcome is not { RequiresBootstrapHealthCheck: true }
            || context.Host.StopCount != 1
            || restarts != 1
            || shutdowns != 1
            || restores != 0)
        {
            throw new InvalidDataException(
                "Automatic managed update did not prove drain, exclusive signed staging, and bootstrap handoff.");
        }

        postReadyStage = AutomaticReleaseUpdateProgressStage.BootstrapHealth;
        preReadyProgress.RecordEntered(postReadyStage);
        var healthProbeDiagnostics = new DevelopmentLauncherHealthProbeDiagnostics();
        var health = await new EnterpriseBootstrapHealthGate(
                context.InstallationLayout,
                EnterpriseBootstrapHealthGate.ColdStartTimeout,
                compiledReleaseTrust)
            .EnsureHealthyAsync((launcherPath, healthToken, timeout, cancellationToken) =>
                RunInstalledLauncherHealthProbeAsync(
                    context.InstallationLayout,
                    launcherPath,
                    healthToken,
                    timeout,
                    cancellationToken,
                    compiledReleaseTrust,
                    options,
                    healthProbeDiagnostics))
            .ConfigureAwait(false);
        preReadyProgress.RecordCompleted(postReadyStage);
        if (!health.Healthy)
        {
            throw new DevelopmentLauncherHealthProbeException(healthProbeDiagnostics);
        }

        postReadyStage = AutomaticReleaseUpdateProgressStage.PostPointerAssertion;
        preReadyProgress.RecordEntered(postReadyStage);
        var afterStore = new EnterpriseReleaseSetPointerStore(context.InstallationLayout);
        var after = afterStore.ReadRequired();
        var activePolicyAfter = target is null ? null : afterStore.ReadActivePluginPolicyRequired();
        var feedState = new EnterpriseReleaseFeedStateStore(
            context.InstallationLayout,
            trust.ExpectedChannel).TryRead()
            ?? throw new InvalidDataException(
                "Automatic managed update signed-feed state is missing.");
        var dataAfter = EnsureLocalDataSentinels(
            context.Paths,
            options.IsolationIdentifier,
            requireExisting: true);
        var runtimeMatchesBefore = string.Equals(
            after.Current.Runtime.ReleaseId,
            beforeRelease.Current.Runtime.ReleaseId,
            StringComparison.Ordinal)
            && string.Equals(
                after.Current.Runtime.ArchiveSha256,
                beforeRelease.Current.Runtime.ArchiveSha256,
                StringComparison.Ordinal)
            && string.Equals(
                after.Current.Runtime.CompleteTreeSha256,
                beforeRelease.Current.Runtime.CompleteTreeSha256,
                StringComparison.Ordinal);
        var runtimeMatchesManifest = string.Equals(
            after.Current.Runtime.ReleaseId,
            manifestRuntime.ReleaseId,
            StringComparison.Ordinal)
            && string.Equals(
                after.Current.Runtime.ArchiveSha256,
                manifestRuntime.Sha256,
                StringComparison.Ordinal)
            && string.Equals(
                after.Current.Runtime.CompleteTreeSha256,
                manifestRuntime.CompleteTreeSha256,
                StringComparison.Ordinal);
        var launcherMatchesBefore = string.Equals(
            after.Current.Launcher.ReleaseId,
            beforeRelease.Current.Launcher.ReleaseId,
            StringComparison.Ordinal)
            && string.Equals(
                after.Current.Launcher.ArchiveSha256,
                beforeRelease.Current.Launcher.ArchiveSha256,
                StringComparison.Ordinal)
            && string.Equals(
                after.Current.Launcher.CompleteTreeSha256,
                beforeRelease.Current.Launcher.CompleteTreeSha256,
                StringComparison.Ordinal);
        var launcherMatchesManifest = string.Equals(
            after.Current.Launcher.ReleaseId,
            manifestLauncher.ReleaseId,
            StringComparison.Ordinal)
            && string.Equals(
                after.Current.Launcher.ArchiveSha256,
                manifestLauncher.Sha256,
                StringComparison.Ordinal)
            && string.Equals(
                after.Current.Launcher.CompleteTreeSha256,
                manifestLauncher.CompleteTreeSha256,
                StringComparison.Ordinal);
        var pluginMatchesBefore = after.Current.PluginPolicy is not null
            && beforeRelease.Current.PluginPolicy is not null
            && ComponentPointersMatch(after.Current.PluginPolicy, beforeRelease.Current.PluginPolicy);
        if (after.Current.HealthState != EnterpriseReleaseHealthStates.Healthy
            || after.Current.Sequence != manifest.Sequence
            || after.Current.Generation != manifest.Generation
            || !string.Equals(after.Current.ReleaseSetId, manifest.ReleaseSetId, StringComparison.Ordinal)
            || !string.Equals(feedState.LastManifestSha256, Hash(manifestBytes), StringComparison.Ordinal)
            || (target is null ? !runtimeMatchesBefore : !runtimeMatchesManifest || runtimeMatchesBefore)
            || (targetLauncher is null
                ? !launcherMatchesBefore
                : !launcherMatchesManifest || launcherMatchesBefore)
            || (targetLauncher is not null && !pluginMatchesBefore)
            || dataAfter != dataBefore)
        {
            throw new InvalidDataException(
                "Automatic managed update activation or local-data preservation failed.");
        }
        if (target is not null
            && (!string.Equals(
                    after.Current.PluginPolicy?.ReleaseId,
                    target.PluginPolicyReleaseId,
                    StringComparison.Ordinal)
                || activePolicyAfter is null
                || !string.Equals(
                    activePolicyAfter.PolicyId,
                    target.PluginPolicyId,
                    StringComparison.Ordinal)
                || activePolicyAfter.Generation != target.PluginPolicyGeneration
                || !string.Equals(
                    activePolicyAfter.PolicySha256,
                    target.PluginPolicySha256,
                    StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "Automatic managed update did not activate the exact target plugin-policy identity.");
        }
        if (target is not null
            && (after.Current.Launcher.ReleaseId != beforeRelease.Current.Launcher.ReleaseId
                || after.Current.Launcher.ArchiveSha256 != beforeRelease.Current.Launcher.ArchiveSha256
                || after.Current.Launcher.CompleteTreeSha256 != beforeRelease.Current.Launcher.CompleteTreeSha256
                || after.Current.PluginPolicy is null
                || beforeRelease.Current.PluginPolicy is null
                || after.Current.PluginPolicy.ReleaseId != beforeRelease.Current.PluginPolicy.ReleaseId
                || after.Current.PluginPolicy.ArchiveSha256 != beforeRelease.Current.PluginPolicy.ArchiveSha256
                || after.Current.PluginPolicy.CompleteTreeSha256 != beforeRelease.Current.PluginPolicy.CompleteTreeSha256))
        {
            throw new InvalidDataException(
                "Runtime-only automatic update changed the Launcher or plugin-policy component.");
        }
        if (targetLauncher is not null
            && (!runtimeMatchesBefore || !pluginMatchesBefore))
        {
            throw new InvalidDataException(
                "Launcher-only automatic update changed the Runtime or plugin-policy component.");
        }
        var successfulArtifactRequests = artifactServer.SuccessfulRequests;
        var manifestFetchCount = successfulArtifactRequests.Count(request =>
            request.Uri == SignedLabManifestUri && request.Bytes == manifestBytes.Length);
        if (manifestFetchCount == 0)
        {
            throw new InvalidDataException(
                "Automatic managed update did not retrieve its signed manifest over local pinned HTTPS.");
        }
        var runtimeFetchCount = successfulArtifactRequests.Count(request =>
            request.Uri == manifestRuntime.Uri && request.Bytes == manifestRuntime.SizeBytes);
        var launcherFetchCount = successfulArtifactRequests.Count(request =>
            request.Uri == manifestLauncher.Uri && request.Bytes == manifestLauncher.SizeBytes);
        var manifestPluginPolicy = manifest.Artifacts.Single(artifact => string.Equals(
            artifact.Component,
            EnterpriseReleaseSetContract.PluginPolicyComponent,
            StringComparison.Ordinal));
        var pluginPolicyFetchCount = successfulArtifactRequests.Count(request =>
            request.Uri == manifestPluginPolicy.Uri
            && request.Bytes == manifestPluginPolicy.SizeBytes);
        if (target is not null && runtimeFetchCount == 0)
        {
            throw new InvalidDataException(
                "Automatic managed update did not retrieve its exact target runtime over local pinned HTTPS.");
        }
        if (targetLauncher is not null
            && (launcherFetchCount == 0 || runtimeFetchCount != 0 || pluginPolicyFetchCount != 0))
        {
            throw new InvalidDataException(
                "Launcher-only automatic update did not fetch exactly its target Launcher over local pinned HTTPS.");
        }
        preReadyProgress.RecordCompleted(postReadyStage);

        return new
        {
            clientState = "UPDATE_REQUIRED",
            errorCode = EnterpriseErrorCodes.ClientUpdateRequired,
            runtimeProfile = context.RuntimeProfile,
            gatewayProbeSkipped = context.IsEnterpriseDirectLocal,
            gatewayStatus = gatewayDenial?.StatusCode,
            gatewayErrorCode = gatewayDenial?.ErrorCode,
            bindingId = credentialAfterRefresh.Receipt.BindingId,
            refreshCompleted = true,
            hostStarted = true,
            hostDrainConfirmed = true,
            hostStopCount = context.Host.StopCount,
            exclusivePortGuardPassed = true,
            automaticStage = "RESTARTING",
            bootstrapRestartRequested = restarts == 1,
            launcherShutdownRequested = shutdowns == 1,
            runtimeRestoreSkippedForBootstrap = restores == 0,
            releaseSetId = after.Current.ReleaseSetId,
            generation = after.Current.Generation,
            sequence = after.Current.Sequence,
            manifestSha256 = feedState.LastManifestSha256,
            healthState = after.Current.HealthState,
            runtimeDownloaded = target is not null,
            distinctRuntimeActivated = target is not null,
            launcherDownloaded = targetLauncher is not null,
            distinctLauncherActivated = targetLauncher is not null,
            genuineDistinctRuntimeUpgradeCovered = false,
            artifactTransport = "LOCAL_PINNED_HTTPS",
            runtimeOnlyComponentsUnchanged = target is not null,
            launcherOnlyComponentsUnchanged = targetLauncher is not null,
            artifactTransportPubliclyReachable = false,
            artifactHttpsSuccessfulRequestCount = successfulArtifactRequests.Count,
            artifactHttpsManifestFetchCount = manifestFetchCount,
            targetRuntimeHttpsFetchCount = target is null ? 0 : runtimeFetchCount,
            targetLauncherHttpsFetchCount = targetLauncher is null ? 0 : launcherFetchCount,
            unchangedRuntimeHttpsFetchCount = targetLauncher is null ? (int?)null : runtimeFetchCount,
            unchangedPluginPolicyHttpsFetchCount = targetLauncher is null ? (int?)null : pluginPolicyFetchCount,
            artifactHttpsTargetRuntimeUriPath = target is null
                ? null
                : manifestRuntime.Uri.AbsolutePath,
            artifactHttpsTargetLauncherUriPath = targetLauncher is null
                ? null
                : manifestLauncher.Uri.AbsolutePath,
            artifactHttpsRequests = successfulArtifactRequests.Select(request => new
            {
                uriPath = request.Uri.AbsolutePath,
                bytes = request.Bytes,
            }).ToArray(),
            runtimeReleaseId = after.Current.Runtime.ReleaseId,
            runtimeArchiveSha256 = after.Current.Runtime.ArchiveSha256,
            runtimeCompleteTreeSha256 = after.Current.Runtime.CompleteTreeSha256,
            launcherReleaseId = after.Current.Launcher.ReleaseId,
            launcherArchiveSha256 = after.Current.Launcher.ArchiveSha256,
            launcherCompleteTreeSha256 = after.Current.Launcher.CompleteTreeSha256,
            workspaceSentinelSha256 = dataAfter.WorkspaceSha256,
            historySentinelSha256 = dataAfter.HistorySha256,
            signedFeedInstalled = true,
        };
    }

    private static async Task<object> RunEnrollChatAsync(RunnerOptions options)
    {
        if (!string.Equals(
                options.RuntimeProfile,
                EnterpriseDirectLocalRuntimeProfile,
                StringComparison.Ordinal))
        {
            return await RunEnrollChatCoreAsync(options, null, null).ConfigureAwait(false);
        }

        var fixture = ReadInitialDirectReleaseFeedFixture(options);
        var internalSecret = Environment.GetEnvironmentVariable(
                "ENSOU_DSH_E2E_FEED_INTERNAL_SECRET")
            ?? throw new InvalidDataException(
                "Direct-local initial enrollment requires the isolated feed authorization secret.");
        using var authorization = new DevelopmentFeedAuthorizationForwarder(
            options.ControlOrigin
                ?? throw new InvalidDataException("Control origin is required."),
            options.ServerCertificateSha256
                ?? throw new InvalidDataException("Control TLS pin is required."),
            internalSecret);
        await using var artifactServer = await DevelopmentHttpsArtifactServer.StartAsync(
                fixture.Content,
                authorization: authorization)
            .ConfigureAwait(false);
        const string certificateVariable = "ENSOU_DSH_E2E_UPDATE_TLS_CERT_SHA256";
        const string portVariable = "ENSOU_DSH_E2E_UPDATE_LOOPBACK_PORT";
        var previousCertificate = Environment.GetEnvironmentVariable(certificateVariable);
        var previousPort = Environment.GetEnvironmentVariable(portVariable);
        Environment.SetEnvironmentVariable(
            certificateVariable,
            artifactServer.LeafCertificateSha256);
        Environment.SetEnvironmentVariable(
            portVariable,
            artifactServer.LoopbackPort.ToString(System.Globalization.CultureInfo.InvariantCulture));
        try
        {
            return await RunEnrollChatCoreAsync(
                    options,
                    fixture,
                    artifactServer)
                .ConfigureAwait(false);
        }
        finally
        {
            Environment.SetEnvironmentVariable(certificateVariable, previousCertificate);
            Environment.SetEnvironmentVariable(portVariable, previousPort);
        }
    }

    private static async Task<object> RunEnrollChatCoreAsync(
        RunnerOptions options,
        DevelopmentInitialReleaseFeedFixture? initialRelease,
        DevelopmentHttpsArtifactServer? initialFeedServer)
    {
        await using var context = await RuntimeContext.CreateAsync(
                options,
                initialReleaseTrust: initialRelease?.CompiledTrust)
            .ConfigureAwait(false);
        var enrollmentProgress = new EnrollmentProgressCapture();
        var activationCode = Environment.GetEnvironmentVariable(
            "ENSOU_DSH_E2E_ACTIVATION_CODE")
            ?? throw new InvalidOperationException(
                "Development E2E activation code is not present in the runner environment.");
        Environment.SetEnvironmentVariable("ENSOU_DSH_E2E_ACTIVATION_CODE", null);
        EnterpriseQrProtocol.ValidateActivationCode(activationCode);
        EnterpriseQrEnrollmentOutcome outcome;
        try
        {
            outcome = await context.EnrollmentCoordinator.BeginAsync(
                    activationCode,
                    enrollmentProgress)
                .ConfigureAwait(false);
        }
        finally
        {
            activationCode = string.Empty;
        }
        if (!outcome.BindingCompleted
            || outcome.BindingCompletion is null
            || outcome.BindingCompletion.AccessDecision.ClientState != EnterpriseClientState.Ready
            || !outcome.BindingCompletion.AccessDecision.MayCallManagedApi)
        {
            throw new DevelopmentEnrollmentOutcomeException(outcome.State, outcome.Error);
        }

        var activePolicy = context.RequireActivePluginPolicyBinding();
        StreamingEvidence? stream = null;
        if (context.IsEnterpriseDirectLocal)
        {
            if (initialRelease is null
                || initialFeedServer is null
                || !context.RequiresLauncherRestart
                || context.Host.StartCount != 0)
            {
                throw new InvalidDataException(
                    "Direct-local enrollment did not complete the authenticated initial release without starting the sequence-zero Host.");
            }
            context.RequireDirectLocalNoGatewayTransport();
            var pointer = new EnterpriseReleaseSetPointerStore(
                context.InstallationLayout,
                initialRelease.CompiledTrust).ReadRequired();
            if (pointer.Current.HealthState != EnterpriseReleaseHealthStates.Healthy
                || pointer.Current.HealthToken is not null
                || pointer.Current.Generation != initialRelease.Manifest.Generation
                || pointer.Current.Sequence != initialRelease.Manifest.Sequence
                || pointer.Current.MinAcceptedSequence != initialRelease.Manifest.MinAcceptedSequence
                || !string.Equals(
                    pointer.Current.ReleaseSetId,
                    initialRelease.Manifest.ReleaseSetId,
                    StringComparison.Ordinal)
                || !string.Equals(
                    pointer.Current.PluginPolicy?.ReleaseId,
                    activePolicy.ReleaseId,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Direct-local enrollment did not activate the exact signed initial release as healthy.");
            }
            RequireExpectedPluginPolicyAndAlternateRawRejection(options, activePolicy);
            RequireAuthenticatedInitialReleaseFeedRequests(initialRelease, initialFeedServer);
        }
        else
        {
            if (initialRelease is not null || initialFeedServer is not null)
            {
                throw new InvalidDataException(
                    "Managed enrollment received a direct-local initial release fixture.");
            }
            _ = await context.Session.EnsureStartedAsync().ConfigureAwait(false);
            activePolicy = context.RequireActivePluginPolicyBinding();
            stream = await context.SendStreamingChatAsync().ConfigureAwait(false);
        }
        // Enrollment is the only lifecycle phase that seeds synthetic user data.
        // All continuation phases must check existing data without repairing it.
        var data = EnsureLocalDataSentinels(
            context.Paths, options.IsolationIdentifier, requireExisting: false);
        var confirmation = enrollmentProgress.RequireIssuedConfirmation();
        return new
        {
            clientState = "READY",
            bindingId = outcome.BindingCompletion.BindingId,
            activationClaimSubmitted = true,
            pollStatus = QrSessionStateContract.ToWireValue(outcome.State),
            deviceDisplayName = confirmation.DeviceDisplayName,
            confirmationCodeValidated = true,
            confirmationCodeSha256 = Hash(Encoding.ASCII.GetBytes(confirmation.ConfirmationCode)),
            hostStarted = context.Host.StartCount == 1,
            launcherRestartRequired = context.RequiresLauncherRestart,
            runtimeProfile = context.RuntimeProfile,
            releaseSetId = initialRelease?.Manifest.ReleaseSetId,
            releaseGeneration = initialRelease?.Manifest.Generation,
            releaseSequence = initialRelease?.Manifest.Sequence,
            healthState = context.IsEnterpriseDirectLocal
                ? EnterpriseReleaseHealthStates.Healthy
                : null,
            policyReleaseId = activePolicy.ReleaseId,
            policyId = activePolicy.PolicyId,
            policyGeneration = activePolicy.Generation,
            policySha256 = activePolicy.PolicySha256,
            skillsTreeSha256 = activePolicy.SkillsTreeSha256,
            alternateRawPolicyBindingRejected = context.IsEnterpriseDirectLocal,
            authenticatedInitialFeedRequestCount = initialFeedServer?.AuthorizedRequests.Count,
            modelTransport = context.IsEnterpriseDirectLocal
                ? "DIRECT_LOCAL_DEVICE_KEY_NOT_EXERCISED"
                : "MANAGED_LOOPBACK_GATEWAY",
            sseChunkCount = stream?.ChunkCount,
            sseDone = stream?.Done,
            workspaceSentinelSha256 = data.WorkspaceSha256,
            historySentinelSha256 = data.HistorySha256,
        };
    }

    private static DevelopmentInitialReleaseFeedFixture ReadInitialDirectReleaseFeedFixture(
        RunnerOptions options)
    {
        var layout = EnterpriseInstallationLayout.CreateDevelopmentE2E(
            RequireOption(options.LocalAppDataRoot, "local-app-data-root"),
            RequireOption(options.UserProfileRoot, "user-profile-root"));
        var compiledTrust = EnterpriseCompiledReleaseTrustLoader.LoadRequired(
            typeof(Program).Assembly,
            layout);
        if (compiledTrust.ManifestUri != SignedLabManifestUri
            || compiledTrust.Policy.ManifestOrigin != new Uri("https://updates.example/")
            || compiledTrust.Policy.ArtifactOrigin != DevelopmentArtifactOrigin
            || compiledTrust.Policy.TrustedKeys.Count != 1
            || !string.Equals(
                compiledTrust.Policy.TrustedKeys[0].KeyId,
                DevelopmentReleaseKeyId,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Direct-local initial enrollment has unexpected public release trust.");
        }

        var manifestPath = RequireOption(options.UpdateManifestPath, "update-manifest");
        var manifestBytes = ReadArtifactBytes(
            manifestPath,
            HashFile(manifestPath),
            512 * 1024);
        var manifest = EnterpriseReleaseSetManifest.Parse(manifestBytes);
        EnterpriseReleaseSetValidator.Verify(
            manifest,
            compiledTrust.Policy,
            DateTimeOffset.UtcNow);
        if (manifest.Generation != 1
            || manifest.Sequence != 1
            || manifest.MinAcceptedSequence != 0
            || !string.Equals(
                manifest.Channel,
                EnterpriseReleaseSetContract.LabChannel,
                StringComparison.Ordinal)
            || !string.Equals(
                manifest.Environment,
                EnterpriseReleaseSetContract.DevelopmentE2EEnvironment,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Direct-local enrollment requires the exact initial signed release manifest.");
        }

        var archivePaths = new Dictionary<string, (string Path, string ReleaseId)>(
            StringComparer.Ordinal)
        {
            [EnterpriseReleaseSetContract.LauncherComponent] = (
                RequireOption(options.LauncherArchivePath, "launcher-archive"),
                RequireOption(options.LauncherReleaseId, "launcher-release-id")),
            [EnterpriseReleaseSetContract.RuntimeComponent] = (
                RequireOption(options.RuntimeArchivePath, "runtime-archive"),
                RequireOption(options.RuntimeReleaseId, "runtime-release-id")),
            [EnterpriseReleaseSetContract.PluginPolicyComponent] = (
                RequireOption(options.PluginPolicyArchivePath, "plugin-policy-archive"),
                RequireOption(options.PluginPolicyReleaseId, "plugin-policy-release-id")),
        };
        var content = new Dictionary<Uri, byte[]>
        {
            [SignedLabManifestUri] = manifestBytes,
        };
        foreach (var artifact in manifest.Artifacts)
        {
            if (!archivePaths.TryGetValue(artifact.Component, out var expected)
                || !string.Equals(
                    artifact.ReleaseId,
                    expected.ReleaseId,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Direct-local initial release contains an unexpected component identity.");
            }
            content.Add(
                artifact.Uri,
                ReadArtifactBytes(expected.Path, artifact.Sha256, artifact.SizeBytes));
        }
        RequireManifestHttpContentMap(
            manifest,
            manifestBytes,
            content,
            requireExactCount: true);
        return new DevelopmentInitialReleaseFeedFixture(
            compiledTrust,
            manifest,
            content);
    }

    private static void RequireExpectedPluginPolicyAndAlternateRawRejection(
        RunnerOptions options,
        EnterpriseActivePluginPolicy activePolicy)
    {
        var expectedPolicyId = RequireOption(options.ExpectedPluginPolicyId, "plugin-policy-id");
        var expectedGeneration = options.ExpectedPluginPolicyGeneration
            ?? throw new ArgumentException("--plugin-policy-generation is required.");
        var expectedPolicySha256 = RequireOption(
            options.ExpectedPluginPolicySha256,
            "plugin-policy-sha256");
        activePolicy.RequireLeaseBinding(
            expectedPolicyId,
            expectedGeneration,
            expectedPolicySha256);

        var archivePath = RequireOption(
            options.PluginPolicyArchivePath,
            "plugin-policy-archive");
        var archiveSha256 = RequireOption(
            options.ExpectedPluginArchiveSha256,
            "plugin-archive-sha256");
        var rawPolicyBytes = ReadPolicyBytes(ReadArtifactBytes(
            archivePath,
            archiveSha256,
            512L * 1024 * 1024));
        var alternateRawBytes = new byte[rawPolicyBytes.Length + 1];
        rawPolicyBytes.CopyTo(alternateRawBytes, 0);
        alternateRawBytes[^1] = (byte)' ';
        var alternatePolicy = EnterprisePluginPolicy.Parse(alternateRawBytes);
        var alternatePolicySha256 = Hash(alternateRawBytes);
        if (!string.Equals(
                alternatePolicy.PolicyId,
                expectedPolicyId,
                StringComparison.Ordinal)
            || alternatePolicy.Generation != expectedGeneration
            || string.Equals(
                alternatePolicySha256,
                expectedPolicySha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The direct-local alternate raw-policy negative case is invalid.");
        }
        AssertThrows<InvalidDataException>(() => activePolicy.RequireLeaseBinding(
            expectedPolicyId,
            expectedGeneration,
            alternatePolicySha256));
    }

    private static void RequireAuthenticatedInitialReleaseFeedRequests(
        DevelopmentInitialReleaseFeedFixture fixture,
        DevelopmentHttpsArtifactServer server)
    {
        var pluginPolicyUri = fixture.Manifest.Artifacts.Single(artifact =>
            string.Equals(
                artifact.Component,
                EnterpriseReleaseSetContract.PluginPolicyComponent,
                StringComparison.Ordinal)).Uri;
        var requiredUris = new HashSet<Uri>
        {
            fixture.CompiledTrust.ManifestUri,
            pluginPolicyUri,
        };
        var knownUris = fixture.Content.Keys.ToHashSet();
        var successfulUris = server.SuccessfulRequests.Select(request => request.Uri).ToArray();
        var authorizedUris = server.AuthorizedRequests.Select(request => request.Uri).ToArray();
        if (!requiredUris.IsSubsetOf(successfulUris)
            || !requiredUris.IsSubsetOf(authorizedUris)
            || successfulUris.Any(uri => !knownUris.Contains(uri))
            || authorizedUris.Any(uri => !knownUris.Contains(uri))
            || !successfulUris.OrderBy(uri => uri.AbsoluteUri, StringComparer.Ordinal).SequenceEqual(
                authorizedUris.OrderBy(uri => uri.AbsoluteUri, StringComparer.Ordinal)))
        {
            throw new InvalidDataException(
                "Direct-local initial release was not fetched exclusively through authenticated feed decisions.");
        }
    }

    private static async Task<object> RunRefreshChatAsync(RunnerOptions options)
    {
        await using var context = await RuntimeContext.CreateAsync(options).ConfigureAwait(false);
        var device = await context.DevicePreparation.PrepareAsync().ConfigureAwait(false);
        var hydrated = await context.AuthorizationLifecycle.HydrateAndRefreshAsync(device)
            .ConfigureAwait(false);
        if (!hydrated.HasCommittedBinding
            || !hydrated.RefreshCompleted
            || hydrated.AccessDecision.ClientState != EnterpriseClientState.Ready
            || !hydrated.AccessDecision.MayCallManagedApi)
        {
            throw new InvalidDataException("Clean process restart did not rotate into Ready.");
        }

        context.RequireActivePluginPolicyBinding();
        _ = await context.Session.EnsureStartedAsync().ConfigureAwait(false);
        context.RequireActivePluginPolicyBinding();
        StreamingEvidence? stream = null;
        if (context.IsEnterpriseDirectLocal)
        {
            context.RequireDirectLocalNoGatewayTransport();
        }
        else
        {
            stream = await context.SendStreamingChatAsync().ConfigureAwait(false);
        }
        var credential = await context.CredentialStore.ReadCommittedAsync().ConfigureAwait(false)
            ?? throw new InvalidDataException("Refreshed credential was not committed.");
        var data = EnsureLocalDataSentinels(context.Paths, options.IsolationIdentifier);
        return new
        {
            clientState = "READY",
            bindingId = credential.Receipt.BindingId,
            refreshCompleted = true,
            hostStarted = context.Host.StartCount == 1,
            runtimeProfile = context.RuntimeProfile,
            modelTransport = context.IsEnterpriseDirectLocal
                ? "DIRECT_LOCAL_DEVICE_KEY_NOT_EXERCISED"
                : "MANAGED_LOOPBACK_GATEWAY",
            sseChunkCount = stream?.ChunkCount,
            sseDone = stream?.Done,
            workspaceSentinelSha256 = data.WorkspaceSha256,
            historySentinelSha256 = data.HistorySha256,
        };
    }

    private static async Task<object> RunRefreshUpdateRequiredAsync(RunnerOptions options)
    {
        if (options.ReadySignalPath is null
            || options.ContinueSignalPath is null
            || options.SignalToken is null)
        {
            throw new ArgumentException(
                "refresh-update-required requires both signal files and a signal token.");
        }

        await using var context = await RuntimeContext.CreateAsync(options).ConfigureAwait(false);
        var device = await context.DevicePreparation.PrepareAsync().ConfigureAwait(false);
        var initial = await context.AuthorizationLifecycle.HydrateAndRefreshAsync(device)
            .ConfigureAwait(false);
        if (!initial.HasCommittedBinding
            || !initial.RefreshCompleted
            || initial.AccessDecision.ClientState != EnterpriseClientState.Ready
            || !initial.AccessDecision.MayCallManagedApi)
        {
            throw new InvalidDataException(
                "Update-required phase could not establish its initial Ready state.");
        }

        context.RequireActivePluginPolicyBinding();
        _ = await context.Session.EnsureStartedAsync().ConfigureAwait(false);
        if (context.IsEnterpriseDirectLocal)
        {
            context.RequireDirectLocalNoGatewayTransport();
        }
        else
        {
            _ = await context.SendStreamingChatAsync().ConfigureAwait(false);
        }
        var before = EnsureLocalDataSentinels(context.Paths, options.IsolationIdentifier);
        var credentialBefore = await context.CredentialStore.ReadCommittedAsync()
            .ConfigureAwait(false)
            ?? throw new InvalidDataException(
                "Update-required phase has no committed binding before policy advance.");
        WriteSignal(options.ReadySignalPath, options.SignalToken);
        await WaitForSignalAsync(
                options.ContinueSignalPath,
                options.SignalToken,
                TimeSpan.FromSeconds(90))
            .ConfigureAwait(false);

        GatewayUpdateDenialEvidence? gatewayDenial = null;
        if (context.IsEnterpriseDirectLocal)
        {
            context.RequireDirectLocalNoGatewayTransport();
        }
        else
        {
            gatewayDenial = await context.SendExpectedGatewayUpdateRequiredAsync()
                .ConfigureAwait(false);
        }
        var refreshed = await context.AuthorizationLifecycle.HydrateAndRefreshAsync(device)
            .ConfigureAwait(false);
        var credentialAfter = await context.CredentialStore.ReadCommittedAsync()
            .ConfigureAwait(false)
            ?? throw new InvalidDataException(
                "Update-required gate removed the committed binding credential.");
        var after = EnsureLocalDataSentinels(
            context.Paths,
            options.IsolationIdentifier,
            requireExisting: true);
        if (!refreshed.HasCommittedBinding
            || !refreshed.RefreshCompleted
            || refreshed.AccessDecision.ClientState != EnterpriseClientState.UpdateRequired
            || refreshed.AccessDecision.MayStartHarness
            || refreshed.AccessDecision.MayCallManagedApi
            || refreshed.AccessDecision.ErrorCode != EnterpriseErrorCodes.ClientUpdateRequired
            || refreshed.AccessDecision.ResetScope != EnterpriseResetScope.None
            || context.Host.StopCount != 1
            || !string.Equals(
                credentialAfter.Receipt.BindingId,
                credentialBefore.Receipt.BindingId,
                StringComparison.Ordinal)
            || before != after)
        {
            throw new InvalidDataException(
                "Grace-expired old release did not lock without resetting local state.");
        }

        return new
        {
            clientState = "UPDATE_REQUIRED",
            errorCode = EnterpriseErrorCodes.ClientUpdateRequired,
            resetScope = "NONE",
            bindingId = credentialAfter.Receipt.BindingId,
            runtimeProfile = context.RuntimeProfile,
            gatewayProbeSkipped = context.IsEnterpriseDirectLocal,
            gatewayStatus = gatewayDenial?.StatusCode,
            gatewayErrorCode = gatewayDenial?.ErrorCode,
            gatewayClientState = gatewayDenial?.ClientState,
            gatewayResetScope = gatewayDenial?.ResetScope,
            refreshCompleted = true,
            hostStopCount = context.Host.StopCount,
            credentialsPreserved = true,
            workspaceSentinelSha256 = after.WorkspaceSha256,
            historySentinelSha256 = after.HistorySha256,
        };
    }

    private static async Task<object> RunRefreshWaitDeniedAsync(RunnerOptions options)
    {
        if (options.ExpectedErrorCode is null
            || options.ExpectedResetScope is null
            || options.ReadySignalPath is null
            || options.ContinueSignalPath is null
            || options.SignalToken is null)
        {
            throw new ArgumentException(
                "refresh-wait-denied requires expected error/reset values and both signal files.");
        }

        var progress = new AutomaticReleaseUpdateProgressSink(options.EvidencePath);
        var stage = AutomaticReleaseUpdateProgressStage.ContextCreate;
        progress.RecordEntered(stage);
        RuntimeContext context;
        try
        {
            context = await RuntimeContext.CreateAsync(options).ConfigureAwait(false);
            progress.RecordCompleted(stage);
        }
        catch (Exception exception)
        {
            progress.RecordFailure(stage, exception);
            throw;
        }
        await using var contextLifetime = context;
        stage = AutomaticReleaseUpdateProgressStage.DevicePrepare;
        progress.RecordEntered(stage);
        var device = await context.DevicePreparation.PrepareAsync().ConfigureAwait(false);
        progress.RecordCompleted(stage);
        stage = AutomaticReleaseUpdateProgressStage.AuthorizationHydrateRefresh;
        progress.RecordEntered(stage);
        var hydrated = await context.AuthorizationLifecycle.HydrateAndRefreshAsync(device)
            .ConfigureAwait(false);
        progress.RecordCompleted(stage);
        if (hydrated.AccessDecision.ClientState != EnterpriseClientState.Ready)
        {
            throw new InvalidDataException("Denial phase could not establish its initial Ready state.");
        }

        stage = AutomaticReleaseUpdateProgressStage.PolicyBeforeStart;
        progress.RecordEntered(stage);
        context.RequireActivePluginPolicyBinding();
        progress.RecordCompleted(stage);
        stage = AutomaticReleaseUpdateProgressStage.SessionStart;
        progress.RecordEntered(stage);
        _ = await context.Session.EnsureStartedAsync().ConfigureAwait(false);
        progress.RecordCompleted(stage);
        stage = AutomaticReleaseUpdateProgressStage.PolicyAfterStart;
        progress.RecordEntered(stage);
        context.RequireActivePluginPolicyBinding();
        progress.RecordCompleted(stage);
        stage = context.IsEnterpriseDirectLocal
            ? AutomaticReleaseUpdateProgressStage.DirectLocalNoModelTraffic
            : AutomaticReleaseUpdateProgressStage.StreamingChat;
        progress.RecordEntered(stage);
        if (context.IsEnterpriseDirectLocal)
        {
            context.RequireDirectLocalNoGatewayTransport();
        }
        else
        {
            _ = await context.SendStreamingChatAsync().ConfigureAwait(false);
        }
        progress.RecordCompleted(stage);
        var sentinel = EnsureWorkspaceSentinel(context.Paths, options.IsolationIdentifier);
        stage = AutomaticReleaseUpdateProgressStage.ReadySignal;
        progress.RecordEntered(stage);
        WriteSignal(options.ReadySignalPath, options.SignalToken);
        progress.RecordCompleted(stage);
        stage = AutomaticReleaseUpdateProgressStage.AwaitContinue;
        progress.RecordEntered(stage);
        await WaitForSignalAsync(
                options.ContinueSignalPath,
                options.SignalToken,
                TimeSpan.FromSeconds(90))
            .ConfigureAwait(false);
        progress.RecordCompleted(stage);

        EnterpriseApiError error;
        stage = AutomaticReleaseUpdateProgressStage.DenialRefresh;
        progress.RecordEntered(stage);
        try
        {
            _ = await context.AuthorizationLifecycle.HydrateAndRefreshAsync(device)
                .ConfigureAwait(false);
            throw new InvalidOperationException("Expected the control plane to deny the refreshed session.");
        }
        catch (EnterpriseControlPlaneException exception)
        {
            error = exception.Error;
            progress.RecordCompleted(stage);
        }
        catch (Exception exception)
        {
            progress.RecordFailure(stage, exception);
            throw DevelopmentDenialAssertionException.Create(
                "REFRESH_DENIAL",
                error: null,
                context,
                exception);
        }

        if (!string.Equals(error.Code, options.ExpectedErrorCode, StringComparison.Ordinal)
            || error.ResetScope != options.ExpectedResetScope.Value
            || context.Session.CurrentDecision.MayStartHarness
            || context.Session.CurrentDecision.MayCallManagedApi
            || context.Host.StopCount != 1)
        {
            throw DevelopmentDenialAssertionException.Create(
                "ACCESS_CONTRACT",
                error,
                context);
        }

        LocalDataSentinelEvidence dataAfter;
        try
        {
            AssertResetPostconditions(context, error.ResetScope, sentinel);
            dataAfter = EnsureLocalDataSentinels(context.Paths, options.IsolationIdentifier);
        }
        catch (Exception exception)
        {
            throw DevelopmentDenialAssertionException.Create(
                "RESET_POSTCONDITION",
                error,
                context,
                exception);
        }
        return new
        {
            errorCode = error.Code,
            resetScope = ToResetScopeWire(error.ResetScope),
            hostStopCount = context.Host.StopCount,
            managedApiAllowed = context.Session.CurrentDecision.MayCallManagedApi,
            runtimeProfile = context.RuntimeProfile,
            gatewayModelTrafficSkipped = context.IsEnterpriseDirectLocal,
            workspaceSentinelSha256 = dataAfter.WorkspaceSha256,
            historySentinelSha256 = dataAfter.HistorySha256,
        };
    }

    private static object AssertEnrollmentRequired(RunnerOptions options)
    {
        var paths = CreatePaths(options);
        var protectedCredential = paths.Resolve(EnterpriseManagedArtifact.RefreshTokenDpapi);
        var receipt = paths.Resolve(EnterpriseManagedArtifact.DeviceBindingReceipt);
        var lease = paths.Resolve(EnterpriseManagedArtifact.AuthorizationLease);
        var data = EnsureLocalDataSentinels(paths, options.IsolationIdentifier);
        if (File.Exists(protectedCredential) || File.Exists(receipt) || File.Exists(lease))
        {
            throw new InvalidDataException(
                "Security reset left an enterprise credential projection on disk.");
        }

        return new
        {
            clientState = "QR_REQUIRED",
            securityCredentialsPresent = false,
            workspaceSentinelSha256 = data.WorkspaceSha256,
            historySentinelSha256 = data.HistorySha256,
        };
    }

    private static EnterpriseManagedPaths CreatePaths(RunnerOptions options)
    {
        if (options.LocalAppDataRoot is null || options.UserProfileRoot is null)
        {
            throw new ArgumentException("This phase requires both isolated filesystem roots.");
        }

        return EnterpriseManagedPaths.CreateDevelopmentE2E(
            options.LocalAppDataRoot,
            options.UserProfileRoot);
    }

    private static void AssertResetPostconditions(
        RuntimeContext context,
        EnterpriseResetScope scope,
        string sentinel)
    {
        if (!File.Exists(sentinel))
        {
            throw new InvalidDataException("Enterprise reset removed the local workspace sentinel.");
        }

        foreach (var artifact in EnterpriseResetPlanner.Create(scope, context.Paths).ExactFiles)
        {
            if (File.Exists(context.Paths.Resolve(artifact)))
            {
                throw new InvalidDataException($"Reset left the managed artifact {artifact} on disk.");
            }
        }

        var probe = Encoding.UTF8.GetBytes("ensou-development-e2e-key-probe");
        try
        {
            if (scope == EnterpriseResetScope.SecurityCredentials)
            {
                try
                {
                    _ = context.DeviceKeyStore.Sign(probe);
                    throw new InvalidDataException("Security reset did not remove the device proof key.");
                }
                catch (CryptographicException)
                {
                    // Expected: the exact isolated CurrentUser key no longer exists.
                }
            }
            else
            {
                var signature = context.DeviceKeyStore.Sign(probe);
                CryptographicOperations.ZeroMemory(signature);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(probe);
        }
    }

    private static string EnsureWorkspaceSentinel(
        EnterpriseManagedPaths paths,
        string isolationIdentifier,
        bool requireExisting = true)
    {
        if (requireExisting)
        {
            if (!Directory.Exists(paths.WorkspaceRoot))
            {
                throw new InvalidDataException(
                    "Workspace sentinel directory was removed during the lifecycle phase.");
            }
        }
        else
        {
            paths.EnsureWorkspaceRoot();
        }
        var path = Path.Combine(paths.WorkspaceRoot, "development-e2e-preserve.txt");
        var expected = $"Ensou Development E2E workspace sentinel {isolationIdentifier}";
        if (File.Exists(path))
        {
            if (!string.Equals(File.ReadAllText(path), expected, StringComparison.Ordinal))
            {
                throw new InvalidDataException("Workspace sentinel changed across lifecycle phases.");
            }
        }
        else if (requireExisting)
        {
            throw new InvalidDataException(
                "Workspace sentinel was removed during the lifecycle phase.");
        }
        else
        {
            File.WriteAllText(path, expected, new UTF8Encoding(false));
        }

        return path;
    }

    private static LocalDataSentinelEvidence EnsureLocalDataSentinels(
        EnterpriseManagedPaths paths,
        string isolationIdentifier,
        bool requireExisting = true)
    {
        var workspace = EnsureWorkspaceSentinel(paths, isolationIdentifier, requireExisting);
        var historyDirectory = Path.Combine(paths.HarnessHome, "history");
        if (requireExisting)
        {
            if (!Directory.Exists(historyDirectory))
            {
                throw new InvalidDataException(
                    "Harness history sentinel directory was removed during the lifecycle phase.");
            }
        }
        else
        {
            Directory.CreateDirectory(historyDirectory);
        }
        var history = Path.Combine(historyDirectory, "development-e2e-history.jsonl");
        var expected = $"{{\"run_id\":\"{isolationIdentifier}\",\"preserved\":true}}";
        if (File.Exists(history))
        {
            if (!string.Equals(File.ReadAllText(history), expected, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Harness history sentinel changed across update-policy phases.");
            }
        }
        else if (requireExisting)
        {
            throw new InvalidDataException(
                "Harness history sentinel was removed during the lifecycle phase.");
        }
        else
        {
            File.WriteAllText(history, expected, new UTF8Encoding(false));
        }

        return new LocalDataSentinelEvidence(HashFile(workspace), HashFile(history));
    }

    private static string HashFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    private static void WriteSignal(string path, string token)
    {
        var fullPath = Path.GetFullPath(path);
        if (File.Exists(fullPath))
        {
            throw new IOException("Development E2E ready signal already exists.");
        }

        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        File.WriteAllText(fullPath, token, new UTF8Encoding(false));
    }

    private static async Task WaitForSignalAsync(
        string path,
        string expectedToken,
        TimeSpan timeout)
    {
        using var cancellation = new CancellationTokenSource(timeout);
        while (true)
        {
            cancellation.Token.ThrowIfCancellationRequested();
            if (File.Exists(path))
            {
                var value = await File.ReadAllTextAsync(path, cancellation.Token)
                    .ConfigureAwait(false);
                if (!string.Equals(value, expectedToken, StringComparison.Ordinal))
                {
                    throw new InvalidDataException("Development E2E continuation token mismatch.");
                }

                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(100), cancellation.Token)
                .ConfigureAwait(false);
        }
    }

    private static void WriteEvidence(string path, object value)
    {
        var fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        var temporary = fullPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        File.WriteAllText(
            temporary,
            JsonSerializer.Serialize(
                value,
                new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true }),
            new UTF8Encoding(false));
        File.Move(temporary, fullPath, overwrite: true);
    }

    private static void TryWriteFailureEvidence(RunnerOptions options, Exception exception)
    {
        try
        {
            var controlError = exception as EnterpriseControlPlaneException;
            var enrollmentOutcome = exception as DevelopmentEnrollmentOutcomeException;
            var denialAssertion = exception as DevelopmentDenialAssertionException;
            var launcherHealthProbe = exception as DevelopmentLauncherHealthProbeException;
            var launcherHealthDiagnostics = launcherHealthProbe?.Diagnostics;
            var stableError = controlError?.Error
                ?? enrollmentOutcome?.Error
                ?? denialAssertion?.Error;
            WriteEvidence(options.EvidencePath, new
            {
                schemaVersion = 1,
                status = "failed",
                phase = RunnerOptions.ToWireValue(options.Phase),
                failedAtUtc = DateTimeOffset.UtcNow,
                exceptionType = SanitizeDevelopmentFailureEvidenceType(exception),
                failureMessage = SanitizeDevelopmentFailureEvidenceMessage(exception.Message),
                innerExceptionType = exception.InnerException is null
                    ? null
                    : SanitizeDevelopmentFailureEvidenceType(exception.InnerException),
                innerFailureMessage = exception.InnerException is null
                    ? null
                    : SanitizeDevelopmentFailureEvidenceMessage(exception.InnerException.Message),
                failureStage = denialAssertion?.FailureStage,
                pollStatus = enrollmentOutcome is null
                    ? null
                    : QrSessionStateContract.ToWireValue(enrollmentOutcome.State),
                controlErrorCode = stableError?.Code,
                resetScope = stableError is null
                    ? null
                    : ToResetScopeWire(stableError.ResetScope),
                observedClientState = denialAssertion is null
                    ? null
                    : EnterpriseClientStateContract.ToWireValue(denialAssertion.ClientState),
                observedDecisionResetScope = denialAssertion is null
                    ? null
                    : ToResetScopeWire(denialAssertion.DecisionResetScope),
                observedHostStopCount = denialAssertion?.HostStopCount,
                launcherHealthProbeExitCode = launcherHealthDiagnostics?.ExitCode,
                launcherHealthProbeDiagnosticStatus =
                    launcherHealthDiagnostics?.DiagnosticStatus,
                launcherHealthProbeExceptionType = launcherHealthDiagnostics?.ExceptionType,
                launcherHealthProbeMessage = launcherHealthDiagnostics?.Message,
                launcherHealthProbeStderrLength =
                    launcherHealthDiagnostics?.StandardErrorLength,
                launcherHealthProbeStderrTruncated =
                    launcherHealthDiagnostics?.StandardErrorTruncated,
            });
        }
        catch
        {
            // The original fail-closed result remains authoritative.
        }
    }

    private static string ToResetScopeWire(EnterpriseResetScope scope) => scope switch
    {
        EnterpriseResetScope.None => "NONE",
        EnterpriseResetScope.ManagedConfig => "MANAGED_CONFIG",
        EnterpriseResetScope.SecurityCredentials => "SECURITY_CREDENTIALS",
        _ => throw new ArgumentOutOfRangeException(nameof(scope)),
    };

    private sealed class RuntimeContext : IAsyncDisposable
    {
        private readonly EnterpriseInstallationLayout _installationLayout;
        private readonly EnterpriseActivePluginPolicy? _activePluginPolicy;
        private readonly EnterpriseInitialReleaseDeviceUpdateGate? _initialReleaseGate;
        private readonly HttpClient _controlClient;
        private readonly HttpClient? _gatewayClient;
        private readonly EnterpriseLoopbackModelProxy? _proxy;

        private RuntimeContext(
            EnterpriseManagedPaths paths,
            EnterpriseInstallationLayout installationLayout,
            EnterpriseActivePluginPolicy? activePluginPolicy,
            EnterpriseInitialReleaseDeviceUpdateGate? initialReleaseGate,
            EnterpriseDeviceProofKeyStore deviceKeyStore,
            EnterpriseDeviceEnrollmentPreparation devicePreparation,
            EnterpriseBindingCredentialStore credentialStore,
            EnterpriseAuthorizationLifecycle authorizationLifecycle,
            EnterpriseQrEnrollmentCoordinator enrollmentCoordinator,
            IRuntimeHarnessHost host,
            EnterpriseHarnessSession session,
            HttpClient controlClient,
            HttpClient? gatewayClient,
            EnterpriseLoopbackModelProxy? proxy,
            string runtimeProfile)
        {
            Paths = paths;
            _installationLayout = installationLayout;
            _activePluginPolicy = activePluginPolicy;
            _initialReleaseGate = initialReleaseGate;
            DeviceKeyStore = deviceKeyStore;
            DevicePreparation = devicePreparation;
            CredentialStore = credentialStore;
            AuthorizationLifecycle = authorizationLifecycle;
            EnrollmentCoordinator = enrollmentCoordinator;
            Host = host;
            Session = session;
            _controlClient = controlClient;
            _gatewayClient = gatewayClient;
            _proxy = proxy;
            RuntimeProfile = runtimeProfile;
        }

        public EnterpriseManagedPaths Paths { get; }
        public EnterpriseDeviceProofKeyStore DeviceKeyStore { get; }
        public EnterpriseDeviceEnrollmentPreparation DevicePreparation { get; }
        public EnterpriseBindingCredentialStore CredentialStore { get; }
        public EnterpriseAuthorizationLifecycle AuthorizationLifecycle { get; }
        public EnterpriseQrEnrollmentCoordinator EnrollmentCoordinator { get; }
        public IRuntimeHarnessHost Host { get; }
        public EnterpriseHarnessSession Session { get; }
        public EnterpriseInstallationLayout InstallationLayout => _installationLayout;
        public string RuntimeProfile { get; }
        public bool IsEnterpriseDirectLocal => string.Equals(
            RuntimeProfile,
            EnterpriseDirectLocalRuntimeProfile,
            StringComparison.Ordinal);
        public bool RequiresLauncherRestart =>
            _initialReleaseGate?.RequiresLauncherRestart == true;

        public static async Task<RuntimeContext> CreateAsync(
            RunnerOptions options,
            bool realRuntimeHost = false,
            AutomaticReleaseUpdateProgressSink? automaticProgress = null,
            EnterpriseCompiledReleaseTrust? initialReleaseTrust = null)
        {
            if (!realRuntimeHost && automaticProgress is not null)
            {
                throw new ArgumentException(
                    "Automatic release update progress is limited to the real Runtime Host.",
                    nameof(automaticProgress));
            }
            var runtimeProfile = RequireNetworkRuntimeProfile(
                options.RuntimeProfile,
                options.GatewayOrigin);
            var directLocal = string.Equals(
                runtimeProfile,
                EnterpriseDirectLocalRuntimeProfile,
                StringComparison.Ordinal);
            if (options.ControlOrigin is null
                || options.LeaseKeyId is null
                || options.LeaseKeyX is null
                || options.LeaseKeyY is null
                || options.ServerCertificateSha256 is null
                || options.LauncherReleaseId is null
                || options.RuntimeReleaseId is null)
            {
                throw new ArgumentException("The network lifecycle phase is missing its trust inputs.");
            }
            var paths = CreatePaths(options);
            paths.EnsureWorkspaceRoot();
            var installationLayout = EnterpriseInstallationLayout.CreateDevelopmentE2E(
                options.LocalAppDataRoot!,
                options.UserProfileRoot!);
            initialReleaseTrust?.Validate(installationLayout);
            var releaseSetStore = new EnterpriseReleaseSetPointerStore(
                installationLayout,
                initialReleaseTrust);
            var releasePointer = releaseSetStore.ReadRequired();
            var initialDirectEnrollment = directLocal
                && !realRuntimeHost
                && options.Phase == RunnerPhase.EnrollChat
                && IsInitialReleasePointer(releasePointer);
            if (initialDirectEnrollment != (initialReleaseTrust is not null))
            {
                throw new InvalidDataException(
                    "Only exact direct-local sequence-zero enrollment may receive initial signed release trust.");
            }
            var activeRuntime = releasePointer.Current.Runtime;
            var activePluginPolicy = initialDirectEnrollment
                ? null
                : releaseSetStore.ReadActivePluginPolicyRequired();
            if (activePluginPolicy is not null)
            {
                paths.ValidateManagedSkillsRoot(activePluginPolicy.SkillsRoot);
            }
            var keyStore = EnterpriseDeviceProofKeyStore.CreateDevelopmentE2E(
                options.IsolationIdentifier);
            var preparation = new EnterpriseDeviceEnrollmentPreparation(
                new EnterpriseInstallationIdentityStore(paths),
                keyStore);
            var protectedStore = new EnterpriseProtectedArtifactStore(
                paths,
                $"com.ensou.dsh.enterprise.development-e2e.{options.IsolationIdentifier}");
            var controlOptions = new EnterpriseControlPlaneOptions(
                options.ControlOrigin,
                options.ControlOrigin);
            var leaseKeys = new[]
            {
                new EnterpriseAuthorizationLeasePublicKey(
                    options.LeaseKeyId,
                    options.LeaseKeyX,
                    options.LeaseKeyY),
            };
            var leasePolicy = directLocal
                ? EnterpriseAuthorizationLeaseTrustPolicy.CreateEnterpriseDirectLocal(
                    options.ControlOrigin,
                    options.ControlOrigin,
                    leaseKeys)
                : new EnterpriseAuthorizationLeaseTrustPolicy(
                    options.ControlOrigin,
                    options.GatewayOrigin!,
                    options.ControlOrigin,
                    leaseKeys);
            var proofFactory = new EnterpriseDpopProofFactory(keyStore);
            var controlClient = new HttpClient(
                PinnedCertificateHandler.Create(options.ServerCertificateSha256),
                disposeHandler: true)
            {
                Timeout = TimeSpan.FromSeconds(15),
            };
            var trustedTimeStore = new EnterpriseTrustedTimeStore(protectedStore);
            EnterpriseHarnessSession? session = null;
            Action<string, Exception?>? hostDiagnostic = automaticProgress is null
                ? null
                : automaticProgress.RecordHostTransition;
            IRuntimeHarnessHost host = realRuntimeHost
                ? new ActualRuntimeHarnessHost(() => new DshHostAdapter(
                    CreateRuntimeHostOptions(
                        runtimeProfile,
                        activeRuntime.Directory,
                        paths.HarnessHome,
                        paths.LogDirectory,
                        paths.WorkspaceRoot,
                        EnterpriseProductIdentity.DevelopmentE2EDefaultPort,
                        paths.PluginRoot,
                        (activePluginPolicy ?? throw new InvalidDataException(
                            "A real Runtime Host requires an active signed plugin policy.")).SkillsRoot),
                    () => ValidateActiveReleaseSet(
                        releaseSetStore,
                        activeRuntime,
                        activePluginPolicy ?? throw new InvalidDataException(
                            "A real Runtime Host lost its active signed plugin policy."),
                        paths,
                        session?.CurrentAccessSnapshot,
                        installationLayout),
                    installationLayout,
                    diagnostic: hostDiagnostic))
                : new ProbeHarnessHost();
            session = new EnterpriseHarnessSession(
                new EnterpriseStartupGate(TimeProvider.System),
                host,
                EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot(),
                new EnterpriseResetExecutor(paths, keyStore, protectedStore),
                trustedTimeStore);
            EnterpriseHarnessSession activeSession = session
                ?? throw new InvalidOperationException(
                    "Development lifecycle session initialization unexpectedly failed.");
            var vault = new EnterpriseAccessTokenVault();
            var verifier = new EnterpriseAuthorizationLeaseVerifier(leasePolicy);
            var credentialStore = new EnterpriseBindingCredentialStore(paths, protectedStore);
            IEnterpriseDeviceUpdateGate deviceUpdateGate = new EnterpriseDeviceUpdateGate(
                new EnterpriseDeviceUpdateManagementClient(
                    controlClient,
                    controlOptions,
                    proofFactory,
                    vault),
                new EnterpriseInstalledReleaseEvidenceProvider(
                    installationLayout,
                    initialReleaseTrust?.ManifestUri ?? SignedLabManifestUri,
                    EnterpriseReleaseSetContract.LabChannel,
                    initialReleaseTrust?.Policy),
                new EnterprisePendingUpdateReceiptTransactionStore(protectedStore));
            EnterpriseInitialReleaseDeviceUpdateGate? initialReleaseGate = null;
            if (initialDirectEnrollment)
            {
                var compiledTrust = initialReleaseTrust
                    ?? throw new InvalidDataException(
                        "Direct-local initial enrollment lost its signed release trust.");
                initialReleaseGate = new EnterpriseInitialReleaseDeviceUpdateGate(
                    installationLayout,
                    compiledTrust,
                    deviceUpdateGate,
                    () => EnterpriseUpdateFeedTransport.CreateTransactionClient(
                        compiledTrust.ManifestUri,
                        compiledTrust.Policy.ArtifactOrigin,
                        proofFactory,
                        vault),
                    async cancellationToken =>
                    {
                        var diagnostics = new DevelopmentLauncherHealthProbeDiagnostics();
                        var health = await new EnterpriseBootstrapHealthGate(
                                installationLayout,
                                EnterpriseBootstrapHealthGate.ColdStartTimeout,
                                compiledTrust)
                            .EnsureHealthyAsync((launcherPath, healthToken, timeout, token) =>
                                RunInstalledLauncherHealthProbeAsync(
                                    installationLayout,
                                    launcherPath,
                                    healthToken,
                                    timeout,
                                    token,
                                    compiledTrust,
                                    options,
                                    diagnostics))
                            .ConfigureAwait(false);
                        if (!health.Healthy)
                        {
                            throw new DevelopmentLauncherHealthProbeException(diagnostics);
                        }
                        cancellationToken.ThrowIfCancellationRequested();
                    },
                    EnterpriseProductIdentity.DevelopmentE2EDefaultPort);
                deviceUpdateGate = initialReleaseGate;
            }
            var bindingWorkflow = new EnterpriseDeviceBindingWorkflow(
                new EnterpriseDeviceBindingClient(
                    controlClient,
                    controlOptions,
                    proofFactory),
                keyStore,
                verifier,
                credentialStore,
                new EnterprisePendingBindingTransactionStore(protectedStore),
                vault,
                activeSession,
                deviceUpdateGate);
            var lifecycle = new EnterpriseAuthorizationLifecycle(
                new EnterpriseRefreshClient(
                    controlClient,
                    controlOptions,
                    proofFactory),
                verifier,
                credentialStore,
                new EnterprisePendingRefreshTransactionStore(protectedStore),
                vault,
                activeSession,
                trustedTimeStore,
                deviceUpdateGate);
            var coordinator = new EnterpriseQrEnrollmentCoordinator(
                preparation,
                new EnterpriseQrEnrollmentClient(
                    controlClient,
                    controlOptions,
                    proofFactory),
                protectedStore,
                activeSession,
                options.LauncherReleaseId,
                options.RuntimeReleaseId,
                "windows-x64",
                bindingWorkflow: bindingWorkflow,
                deviceLabel: "Ensou lifecycle E2E");
            HttpClient? gatewayClient = null;
            EnterpriseLoopbackModelProxy? proxy = null;
            if (!directLocal)
            {
                var gatewayOrigin = options.GatewayOrigin
                    ?? throw new InvalidOperationException(
                        "Managed Runtime gateway origin disappeared after validation.");
                gatewayClient = new HttpClient(
                    new EnterpriseGatewayAuthorizationHandler(
                        gatewayOrigin,
                        proofFactory,
                        vault,
                        activeSession,
                        PinnedCertificateHandler.Create(options.ServerCertificateSha256),
                        EnterprisePhase1GatewayProfile.Routes),
                    disposeHandler: true)
                {
                    Timeout = TimeSpan.FromSeconds(30),
                };
                proxy = new EnterpriseLoopbackModelProxy(
                    gatewayOrigin,
                    EnterprisePhase1GatewayProfile.Routes,
                    gatewayClient);
                await proxy.StartAsync().ConfigureAwait(false);
                if (host is ActualRuntimeHarnessHost actualRuntimeHost)
                {
                    actualRuntimeHost.ConfigureControlledEnvironment(
                        proxy.CreateDshControlledEnvironment());
                }
            }
            return new RuntimeContext(
                paths,
                installationLayout,
                activePluginPolicy,
                initialReleaseGate,
                keyStore,
                preparation,
                credentialStore,
                lifecycle,
                coordinator,
                host,
                activeSession,
                controlClient,
                gatewayClient,
                proxy,
                runtimeProfile);
        }

        public EnterpriseActivePluginPolicy RequireActivePluginPolicyBinding()
        {
            var current = new EnterpriseReleaseSetPointerStore(_installationLayout)
                .ReadActivePluginPolicyRequired();
            if (_activePluginPolicy is { } captured
                && (!string.Equals(
                        current.ReleaseId,
                        captured.ReleaseId,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        current.PolicyId,
                        captured.PolicyId,
                        StringComparison.Ordinal)
                    || current.Generation != captured.Generation
                    || !string.Equals(
                        current.PolicySha256,
                        captured.PolicySha256,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        current.SkillsTreeSha256,
                        captured.SkillsTreeSha256,
                        StringComparison.Ordinal)))
            {
                throw new InvalidDataException(
                    "The active plugin policy changed during the Development lifecycle phase.");
            }
            if (_activePluginPolicy is null && !RequiresLauncherRestart)
            {
                throw new InvalidDataException(
                    "Sequence-zero enrollment did not complete the authenticated initial signed release.");
            }
            Paths.ValidateManagedSkillsRoot(current.SkillsRoot);
            var snapshot = Session.CurrentAccessSnapshot;
            if (snapshot.PluginPolicyId is not { } policyId
                || snapshot.PluginPolicyGeneration is not { } policyGeneration
                || snapshot.PluginPolicySha256 is not { } policySha256)
            {
                throw new InvalidDataException(
                    "The verified lifecycle lease is missing its plugin-policy binding.");
            }
            current.RequireLeaseBinding(policyId, policyGeneration, policySha256);
            return current;
        }

        public ActualRuntimeHarnessHost RequireActualRuntimeHost() => Host as ActualRuntimeHarnessHost
            ?? throw new InvalidOperationException(
                "The automatic release update phase requires the production DSH Host adapter.");

        public void RequireDirectLocalNoGatewayTransport()
        {
            if (!IsEnterpriseDirectLocal || _gatewayClient is not null || _proxy is not null)
            {
                throw new InvalidOperationException(
                    "The direct-local Runtime context must not create or use a gateway transport.");
            }
        }

        private static void ValidateActiveReleaseSet(
            EnterpriseReleaseSetPointerStore releaseSetStore,
            EnterpriseReleaseComponentPointer capturedRuntime,
            EnterpriseActivePluginPolicy capturedPluginPolicy,
            EnterpriseManagedPaths paths,
            EnterpriseAccessSnapshot? accessSnapshot,
            EnterpriseInstallationLayout installationLayout)
        {
            paths.ValidateWorkspaceRoot();
            EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHome(installationLayout);
            ArgumentNullException.ThrowIfNull(accessSnapshot);
            var current = releaseSetStore.ReadRequired();
            if (current.Current.HealthState != EnterpriseReleaseHealthStates.Healthy
                || !string.Equals(
                    current.Current.Runtime.ReleaseId,
                    capturedRuntime.ReleaseId,
                    StringComparison.Ordinal)
                || !string.Equals(
                    current.Current.Runtime.Directory,
                    capturedRuntime.Directory,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "The current signed release set no longer authorizes the captured managed Runtime.");
            }

            var feed = new EnterpriseReleaseFeedStateStore(
                installationLayout,
                EnterpriseReleaseSetContract.LabChannel);
            if (!feed.IsCurrentAllowedOffline(current.Current, out _))
            {
                throw new InvalidDataException(
                    "The current signed release set is not allowed by the verified development feed state.");
            }

            var activePolicy = releaseSetStore.ReadActivePluginPolicyRequired(current);
            if (!string.Equals(activePolicy.ReleaseId, capturedPluginPolicy.ReleaseId, StringComparison.Ordinal)
                || !string.Equals(activePolicy.PolicyId, capturedPluginPolicy.PolicyId, StringComparison.Ordinal)
                || activePolicy.Generation != capturedPluginPolicy.Generation
                || !string.Equals(activePolicy.PolicySha256, capturedPluginPolicy.PolicySha256, StringComparison.Ordinal)
                || !string.Equals(
                    activePolicy.SkillsRoot,
                    capturedPluginPolicy.SkillsRoot,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "The active signed plugin policy changed during the managed Runtime session.");
            }

            paths.ValidateManagedSkillsRoot(activePolicy.SkillsRoot);
            if (accessSnapshot.PluginPolicyId is not { } policyId
                || accessSnapshot.PluginPolicyGeneration is not { } policyGeneration
                || accessSnapshot.PluginPolicySha256 is not { } policySha256)
            {
                throw new InvalidDataException(
                    "The managed Runtime has no verified lease binding for the active plugin policy.");
            }
            activePolicy.RequireLeaseBinding(policyId, policyGeneration, policySha256);
        }

        public async Task<StreamingEvidence> SendStreamingChatAsync()
        {
            var controlled = RequireManagedProxy().CreateDshControlledEnvironment();
            var uri = new Uri(controlled["DEEPSEEK_BASE_URL"] + "/chat/completions");
            using var handler = new HttpClientHandler { UseProxy = false };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
            using var request = new HttpRequestMessage(HttpMethod.Post, uri)
            {
                Content = new StringContent(
                    "{\"model\":\"deepseek-v4-flash\",\"messages\":[],\"max_tokens\":8,\"stream\":true}",
                    Encoding.UTF8,
                    "application/json"),
            };
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer",
                controlled["DEEPSEEK_API_KEY"]);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
            using var response = await client.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead)
                .ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.OK
                || response.Content.Headers.ContentType?.MediaType != "text/event-stream")
            {
                throw new InvalidDataException(
                    $"Loopback gateway returned status {(int)response.StatusCode} instead of SSE 200.");
            }

            var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            var chunks = body.Split("data: ", StringSplitOptions.RemoveEmptyEntries).Length;
            var done = body.EndsWith("data: [DONE]\n\n", StringComparison.Ordinal);
            if (chunks < 2
                || !done
                || !body.Contains("E2E gateway is ready.", StringComparison.Ordinal))
            {
                throw new InvalidDataException("Deterministic gateway did not stream the expected SSE sequence.");
            }

            return new StreamingEvidence(chunks, done);
        }

        public async Task<GatewayUpdateDenialEvidence> SendExpectedGatewayUpdateRequiredAsync()
        {
            var controlled = RequireManagedProxy().CreateDshControlledEnvironment();
            var uri = new Uri(controlled["DEEPSEEK_BASE_URL"] + "/chat/completions");
            using var handler = new HttpClientHandler { UseProxy = false };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
            using var request = new HttpRequestMessage(HttpMethod.Post, uri)
            {
                Content = new StringContent(
                    "{\"model\":\"deepseek-v4-flash\",\"messages\":[],\"max_tokens\":8,\"stream\":true}",
                    Encoding.UTF8,
                    "application/json"),
            };
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer",
                controlled["DEEPSEEK_API_KEY"]);
            using var response = await client.SendAsync(request).ConfigureAwait(false);
            var body = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.Forbidden || body.Length is <= 0 or > 64 * 1024)
            {
                throw new InvalidDataException(
                    $"Old release gateway denial returned HTTP {(int)response.StatusCode}.");
            }
            using var document = JsonDocument.Parse(body);
            var error = document.RootElement.GetProperty("error");
            var code = error.GetProperty("code").GetString();
            var clientState = error.GetProperty("client_state").GetString();
            var resetScope = error.GetProperty("reset_scope").GetString();
            if (code != EnterpriseErrorCodes.ClientUpdateRequired
                || clientState != "UPDATE_REQUIRED"
                || resetScope != "NONE")
            {
                throw new InvalidDataException(
                    "Old release gateway denial did not carry CLIENT_UPDATE_REQUIRED/NONE.");
            }
            return new GatewayUpdateDenialEvidence(
                (int)response.StatusCode,
                code,
                clientState,
                resetScope);
        }

        public async ValueTask DisposeAsync()
        {
            if (_proxy is not null)
            {
                await _proxy.DisposeAsync().ConfigureAwait(false);
            }
            _gatewayClient?.Dispose();
            _controlClient.Dispose();
            await Session.DisposeAsync().ConfigureAwait(false);
        }

        private EnterpriseLoopbackModelProxy RequireManagedProxy()
        {
            if (IsEnterpriseDirectLocal || _proxy is null || _gatewayClient is null)
            {
                throw new InvalidOperationException(
                    "Managed gateway model traffic is unavailable for this Runtime profile.");
            }
            return _proxy;
        }
    }

    private sealed record StreamingEvidence(int ChunkCount, bool Done);

    private sealed record GatewayUpdateDenialEvidence(
        int StatusCode,
        string ErrorCode,
        string ClientState,
        string ResetScope);

    private sealed record LocalDataSentinelEvidence(
        string WorkspaceSha256,
        string HistorySha256);

    private sealed class EnrollmentProgressCapture : IProgress<EnterpriseQrEnrollmentProgress>
    {
        private readonly List<EnterpriseQrEnrollmentProgress> _updates = [];

        public void Report(EnterpriseQrEnrollmentProgress value)
        {
            lock (_updates)
            {
                _updates.Add(value);
            }
        }

        public EnterpriseQrEnrollmentProgress RequireIssuedConfirmation()
        {
            EnterpriseQrEnrollmentProgress[] issued;
            lock (_updates)
            {
                issued = _updates.Where(update => update.State == QrSessionState.Issued).ToArray();
            }

            if (issued.Length != 1)
            {
                throw new InvalidDataException(
                    "Development enrollment did not report exactly one issued device confirmation.");
            }

            var confirmation = issued[0];
            var normalized = EnterpriseQrProtocol.NormalizeDeviceDisplayName(
                confirmation.DeviceDisplayName);
            if (!string.Equals(
                    normalized,
                    confirmation.DeviceDisplayName,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Development enrollment reported a noncanonical device display name.");
            }

            EnterpriseQrProtocol.ValidateConfirmationCode(confirmation.ConfirmationCode);
            return confirmation;
        }
    }

    private sealed class DevelopmentEnrollmentOutcomeException(
        QrSessionState state,
        EnterpriseApiError? error)
        : Exception("Development QR polling did not produce a bound Ready session.")
    {
        public QrSessionState State { get; } = state;

        public EnterpriseApiError? Error { get; } = error;
    }

    private sealed record BoundedStandardError(string Text, bool Truncated);

    private sealed class DevelopmentLauncherHealthProbeDiagnostics
    {
        public int? ExitCode { get; private set; }

        public string DiagnosticStatus { get; private set; } = "not-run";

        public string? ExceptionType { get; private set; }

        public string? Message { get; private set; }

        public int StandardErrorLength { get; private set; }

        public bool StandardErrorTruncated { get; private set; }

        public void CaptureTimeout() => DiagnosticStatus = "timeout";

        public void Capture(int exitCode, BoundedStandardError standardError)
        {
            ArgumentNullException.ThrowIfNull(standardError);
            ExitCode = exitCode;
            StandardErrorLength = standardError.Text.Length;
            StandardErrorTruncated = standardError.Truncated;
            if (standardError.Truncated)
            {
                DiagnosticStatus = "truncated";
                return;
            }

            var line = standardError.Text.TrimEnd('\r', '\n');
            if (line.Length == 0)
            {
                DiagnosticStatus = "empty";
                return;
            }
            var fields = line.Split('\t');
            if (fields.Length != 3
                || !string.Equals(
                    fields[0],
                    DevelopmentMachineFailurePrefix,
                    StringComparison.Ordinal)
                || fields[1].Length is < 1 or > 128
                || fields[1].Any(character => !char.IsAsciiLetterOrDigit(character))
                || fields[2].Length is < 1 or > MaximumDevelopmentMachineFailureMessageLength
                || fields[2].Any(char.IsControl)
                || ContainsSensitiveDiagnosticLabel(fields[2])
                || ContainsLongDiagnosticValue(fields[2]))
            {
                DiagnosticStatus = "invalid";
                return;
            }

            ExceptionType = fields[1];
            Message = fields[2];
            DiagnosticStatus = "parsed";
        }

        private static bool ContainsSensitiveDiagnosticLabel(string value) => new[]
        {
            "api key", "api_key", "api-key", "authorization", "bearer",
            "cookie", "password", "private key", "secret",
        }.Any(label => value.Contains(label, StringComparison.OrdinalIgnoreCase));

        private static bool ContainsLongDiagnosticValue(string value)
        {
            for (var index = 0; index < value.Length;)
            {
                if (!IsPotentialDiagnosticSecretCharacter(value[index]))
                {
                    index++;
                    continue;
                }
                var end = index + 1;
                while (end < value.Length && IsPotentialDiagnosticSecretCharacter(value[end]))
                {
                    end++;
                }
                if (end - index >= 32)
                {
                    return true;
                }
                index = end;
            }
            return false;
        }

        private static bool IsPotentialDiagnosticSecretCharacter(char value) =>
            char.IsAsciiLetterOrDigit(value) || value is '_' or '-' or '+' or '=';
    }

    private sealed class DevelopmentLauncherHealthProbeException(
        DevelopmentLauncherHealthProbeDiagnostics diagnostics)
        : Exception("Installed Launcher rejected the active plugin-policy health probe.")
    {
        public DevelopmentLauncherHealthProbeDiagnostics Diagnostics { get; } = diagnostics;
    }

    private sealed class DevelopmentDenialAssertionException : Exception
    {
        private DevelopmentDenialAssertionException(
            string failureStage,
            EnterpriseApiError? error,
            EnterpriseAccessDecision decision,
            int hostStopCount,
            Exception? innerException)
            : base("Development denial phase failed a stable lifecycle assertion.", innerException)
        {
            FailureStage = failureStage;
            Error = error;
            ClientState = decision.ClientState;
            DecisionResetScope = decision.ResetScope;
            HostStopCount = hostStopCount;
        }

        public string FailureStage { get; }

        public EnterpriseApiError? Error { get; }

        public EnterpriseClientState ClientState { get; }

        public EnterpriseResetScope DecisionResetScope { get; }

        public int HostStopCount { get; }

        public static DevelopmentDenialAssertionException Create(
            string failureStage,
            EnterpriseApiError? error,
            RuntimeContext context,
            Exception? innerException = null) => new(
                failureStage,
                error,
                context.Session.CurrentDecision,
                context.Host.StopCount,
                innerException);
    }

    private sealed class ProbeHarnessHost : IRuntimeHarnessHost
    {
        private bool _running;

        public Uri WebUiUri { get; } = new("http://127.0.0.1:1/");
        public int StartCount { get; private set; }
        public int StopCount { get; private set; }

        public Task EnsureStartedAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!_running)
            {
                _running = true;
                StartCount++;
            }
            return Task.CompletedTask;
        }

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(_running);
        }

        public Task OpenWebUiAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!_running)
            {
                throw new InvalidOperationException(
                    "The probe Harness has no running browser session.");
            }
            return Task.CompletedTask;
        }

        public Task StopOwnedProcessAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_running)
            {
                _running = false;
                StopCount++;
            }
            return Task.CompletedTask;
        }

        public async ValueTask DisposeAsync()
        {
            await StopOwnedProcessAsync().ConfigureAwait(false);
        }
    }

    private static class PinnedCertificateHandler
    {
        public static HttpClientHandler Create(string expectedSha256)
        {
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                UseProxy = false,
            };
            handler.ServerCertificateCustomValidationCallback =
                (_, certificate, _, errors) => Validate(certificate, errors, expectedSha256);
            return handler;
        }

        private static bool Validate(
            X509Certificate2? certificate,
            SslPolicyErrors errors,
            string expectedSha256)
        {
            if (certificate is null
                || (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None)
            {
                return false;
            }

            return string.Equals(
                certificate.GetCertHashString(HashAlgorithmName.SHA256),
                expectedSha256,
                StringComparison.OrdinalIgnoreCase);
        }
    }

    private enum AutomaticReleaseUpdateProgressStage
    {
        ContextCreate,
        DevicePrepare,
        AuthorizationHydrateRefresh,
        RuntimeStart,
        OwnedHealth,
        WaitContinue,
        GatewayDenialRefresh,
        AuthorizationRefresh,
        AutomaticStage,
        BootstrapHealth,
        PostPointerAssertion,
        PolicyBeforeStart,
        SessionStart,
        PolicyAfterStart,
        StreamingChat,
        DirectLocalNoModelTraffic,
        ReadySignal,
        AwaitContinue,
        DenialRefresh,
    }

    private static string ToWireValue(AutomaticReleaseUpdateProgressStage stage) => stage switch
    {
        AutomaticReleaseUpdateProgressStage.ContextCreate => "context-create",
        AutomaticReleaseUpdateProgressStage.DevicePrepare => "device-prepare",
        AutomaticReleaseUpdateProgressStage.AuthorizationHydrateRefresh =>
            "authorization-hydrate-refresh",
        AutomaticReleaseUpdateProgressStage.RuntimeStart => "runtime-start",
        AutomaticReleaseUpdateProgressStage.OwnedHealth => "owned-health",
        AutomaticReleaseUpdateProgressStage.WaitContinue => "wait-continue",
        AutomaticReleaseUpdateProgressStage.GatewayDenialRefresh => "gateway-denial-refresh",
        AutomaticReleaseUpdateProgressStage.AuthorizationRefresh => "authorization-refresh",
        AutomaticReleaseUpdateProgressStage.AutomaticStage => "automatic-stage",
        AutomaticReleaseUpdateProgressStage.BootstrapHealth => "bootstrap-health",
        AutomaticReleaseUpdateProgressStage.PostPointerAssertion => "post-pointer-assertion",
        AutomaticReleaseUpdateProgressStage.PolicyBeforeStart => "policy-before-start",
        AutomaticReleaseUpdateProgressStage.SessionStart => "session-start",
        AutomaticReleaseUpdateProgressStage.PolicyAfterStart => "policy-after-start",
        AutomaticReleaseUpdateProgressStage.StreamingChat => "streaming-chat",
        AutomaticReleaseUpdateProgressStage.DirectLocalNoModelTraffic =>
            "direct-local-no-model-traffic",
        AutomaticReleaseUpdateProgressStage.ReadySignal => "ready-signal",
        AutomaticReleaseUpdateProgressStage.AwaitContinue => "await-continue",
        AutomaticReleaseUpdateProgressStage.DenialRefresh => "denial-refresh",
        _ => throw new ArgumentOutOfRangeException(nameof(stage)),
    };

    private sealed class AutomaticReleaseUpdateProgressSink
    {
        private const int MaximumRecords = 128;
        private const int MaximumBytes = 64 * 1024;
        private static readonly HashSet<string> AllowedHostPhases = new(StringComparer.Ordinal)
        {
            "host_admission_failed",
            "host_health_cancelled",
            "host_health_deadline_arm",
            "host_health_deadline_expired",
            "host_health_passed",
            "host_home_session_begin",
            "host_home_session_end",
            "host_inventory_begin",
            "host_inventory_end",
            "host_job_create_begin",
            "host_job_create_end",
            "host_job_empty_observed",
            "host_job_empty_recorded",
            "host_output_drain_begin",
            "host_output_drain_end",
            "host_release_begin",
            "host_release_job_disposed",
            "host_runtime_lease_begin",
            "host_runtime_lease_end",
            "host_startup_failed",
            "host_suspended_start_assigned",
            "host_suspended_start_begin",
            "host_suspended_start_end",
            "host_suspended_start_validated",
        };

        private readonly object _gate = new();
        private readonly string _path;
        private readonly long _startedAt = Stopwatch.GetTimestamp();
        private int _recordCount;
        private int _writtenBytes;

        public AutomaticReleaseUpdateProgressSink(string evidencePath)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(evidencePath);
            _path = evidencePath + ".progress.jsonl";
        }

        public void RecordEntered(AutomaticReleaseUpdateProgressStage stage) =>
            TryAppend("runner-" + ToWireValue(stage), "entered", exception: null);

        public void RecordFailure(AutomaticReleaseUpdateProgressStage stage, Exception exception) =>
            TryAppend("runner-" + ToWireValue(stage), "failed", exception);

        public void RecordCompleted(AutomaticReleaseUpdateProgressStage stage) =>
            TryAppend("runner-" + ToWireValue(stage), "completed", exception: null);

        public void RecordHostTransition(string phase, Exception? exception)
        {
            if (AllowedHostPhases.Contains(phase))
            {
                TryAppend(phase, exception is null ? "observed" : "failed", exception);
            }
        }

        private void TryAppend(string phase, string transition, Exception? exception)
        {
            try
            {
                var exceptionType = SafeExceptionType(exception);
                var line = JsonSerializer.Serialize(new
                {
                    schemaVersion = 1,
                    phase,
                    transition,
                    elapsedMilliseconds = (long)Stopwatch.GetElapsedTime(_startedAt)
                        .TotalMilliseconds,
                    exceptionType,
                }) + "\n";
                var bytes = Encoding.UTF8.GetBytes(line);
                lock (_gate)
                {
                    if (_recordCount >= MaximumRecords
                        || _writtenBytes > MaximumBytes - bytes.Length)
                    {
                        return;
                    }

                    using var stream = new FileStream(
                        _path,
                        FileMode.Append,
                        FileAccess.Write,
                        FileShare.Read,
                        bufferSize: 4096,
                        FileOptions.WriteThrough);
                    stream.Write(bytes);
                    stream.Flush(flushToDisk: true);
                    _recordCount++;
                    _writtenBytes += bytes.Length;
                }
            }
            catch
            {
                // Test diagnostics must never affect runtime admission or cleanup.
            }
        }

        private static string? SafeExceptionType(Exception? exception)
        {
            var type = exception?.GetType().Name;
            return type is not null
                && type.Length is > 0 and <= 128
                && type.All(character => char.IsAsciiLetterOrDigit(character))
                    ? type
                    : null;
        }
    }

    private enum RunnerPhase
    {
        ArtifactFixtureContract,
        HttpsArtifactFixtureContract,
        InstallPluginPolicy,
        ApplyReleaseUpdate,
        PrepareLauncherUpdate,
        AutomaticReleaseUpdate,
        InstalledLauncherUpdate,
        EnrollChat,
        RefreshChat,
        RefreshUpdateRequired,
        RefreshWaitDenied,
        AssertEnrollmentRequired,
    }

    private sealed record TargetReleaseTuple(
        string RuntimeReleaseId,
        string RuntimeArchivePath,
        string PluginPolicyReleaseId,
        string PluginPolicyArchivePath,
        string PluginPolicyId,
        long PluginPolicyGeneration,
        string PluginPolicySha256,
        string PluginArchiveSha256);

    private sealed record TargetLauncherTuple(
        string LauncherReleaseId,
        string LauncherArchivePath);

    private sealed record DevelopmentInitialReleaseFeedFixture(
        EnterpriseCompiledReleaseTrust CompiledTrust,
        EnterpriseReleaseSetManifest Manifest,
        Dictionary<Uri, byte[]> Content);

    private sealed record RunnerOptions(
        RunnerPhase Phase,
        string IsolationIdentifier,
        string EvidencePath,
        string? LocalAppDataRoot,
        string? UserProfileRoot,
        string? LauncherReleaseId,
        string? RuntimeReleaseId,
        string? PluginPolicyReleaseId,
        string? LauncherArchivePath,
        string? RuntimeArchivePath,
        string? PluginPolicyArchivePath,
        string? TargetLauncherReleaseId,
        string? TargetLauncherArchivePath,
        string? TargetRuntimeReleaseId,
        string? TargetRuntimeArchivePath,
        string? TargetPluginPolicyReleaseId,
        string? TargetPluginPolicyArchivePath,
        string? ExpectedTargetPluginPolicyId,
        long? ExpectedTargetPluginPolicyGeneration,
        string? ExpectedTargetPluginPolicySha256,
        string? ExpectedTargetPluginArchiveSha256,
        string? ExpectedPluginPolicyId,
        long? ExpectedPluginPolicyGeneration,
        string? ExpectedPluginPolicySha256,
        string? ExpectedPluginArchiveSha256,
        string? ReleasePrivateKeyPath,
        string? InitialManifestOutputPath,
        string? InitialJournalOutputPath,
        string? InitialPromotionResultOutputPath,
        string? UpdateManifestOutputPath,
        string? UpdateJournalOutputPath,
        string? UpdatePromotionResultOutputPath,
        string? UpdateManifestPath,
        string? RuntimeProfile,
        Uri? ControlOrigin,
        Uri? GatewayOrigin,
        string? LeaseKeyId,
        string? LeaseKeyX,
        string? LeaseKeyY,
        string? ServerCertificateSha256,
        string? ExpectedErrorCode,
        EnterpriseResetScope? ExpectedResetScope,
        string? ReadySignalPath,
        string? ContinueSignalPath,
        string? SignalToken)
    {
        public static RunnerOptions Parse(string[] args)
        {
            if (args.Length % 2 != 0)
            {
                throw new ArgumentException("Every Development E2E option requires one value.");
            }

            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            for (var index = 0; index < args.Length; index += 2)
            {
                var key = args[index];
                if (!key.StartsWith("--", StringComparison.Ordinal)
                    || !values.TryAdd(key[2..], args[index + 1]))
                {
                    throw new ArgumentException("Development E2E options must be unique --name value pairs.");
                }
            }

            var allowed = new HashSet<string>(StringComparer.Ordinal)
            {
                "phase", "isolation-id", "evidence", "local-app-data-root",
                "user-profile-root", "launcher-release-id", "runtime-release-id",
                "plugin-policy-release-id", "launcher-archive", "runtime-archive",
                "plugin-policy-archive", "plugin-policy-id", "plugin-policy-generation",
                "plugin-policy-sha256", "plugin-archive-sha256",
                "target-launcher-release-id", "target-launcher-archive",
                "target-runtime-release-id", "target-runtime-archive",
                "target-plugin-policy-release-id", "target-plugin-policy-archive",
                "target-plugin-policy-id", "target-plugin-policy-generation",
                "target-plugin-policy-sha256", "target-plugin-archive-sha256",
                "release-private-key", "initial-manifest-output", "initial-journal-output",
                "initial-promotion-result-output", "update-manifest-output",
                "update-journal-output", "update-promotion-result-output", "update-manifest",
                "runtime-profile", "control-origin", "gateway-origin", "lease-key-id",
                "lease-key-x", "lease-key-y", "server-cert-sha256", "expected-error-code",
                "expected-reset-scope", "ready-signal", "continue-signal", "signal-token",
            };
            var unknown = values.Keys.FirstOrDefault(key => !allowed.Contains(key));
            if (unknown is not null)
            {
                throw new ArgumentException($"Unknown Development E2E option --{unknown}.");
            }

            var phase = Require(values, "phase") switch
            {
                "artifact-fixture-contract" => RunnerPhase.ArtifactFixtureContract,
                "https-artifact-fixture-contract" => RunnerPhase.HttpsArtifactFixtureContract,
                "install-plugin-policy" => RunnerPhase.InstallPluginPolicy,
                "apply-release-update" => RunnerPhase.ApplyReleaseUpdate,
                "prepare-launcher-update" => RunnerPhase.PrepareLauncherUpdate,
                "automatic-release-update" => RunnerPhase.AutomaticReleaseUpdate,
                "installed-launcher-update" => RunnerPhase.InstalledLauncherUpdate,
                "enroll-chat" => RunnerPhase.EnrollChat,
                "refresh-chat" => RunnerPhase.RefreshChat,
                "refresh-update-required" => RunnerPhase.RefreshUpdateRequired,
                "refresh-wait-denied" => RunnerPhase.RefreshWaitDenied,
                "assert-enrollment-required" => RunnerPhase.AssertEnrollmentRequired,
                _ => throw new ArgumentException("Unknown Development E2E phase."),
            };
            var isolation = Require(values, "isolation-id");
            _ = EnterpriseDeviceProofKeyStore.CreateDevelopmentE2E(isolation);
            var evidence = RequireAbsolutePath(values, "evidence");
            var local = OptionalAbsolutePath(values, "local-app-data-root");
            var profile = OptionalAbsolutePath(values, "user-profile-root");
            var policyGeneration = OptionalPositiveInt64(values, "plugin-policy-generation");
            var targetPolicyGeneration = OptionalPositiveInt64(
                values,
                "target-plugin-policy-generation");
            var targetOptionNames = new[]
            {
                "target-runtime-release-id", "target-runtime-archive",
                "target-plugin-policy-release-id", "target-plugin-policy-archive",
                "target-plugin-policy-id", "target-plugin-policy-generation",
                "target-plugin-policy-sha256", "target-plugin-archive-sha256",
            };
            var suppliedTargetOptionCount = targetOptionNames.Count(values.ContainsKey);
            var targetLauncherOptionNames = new[]
            {
                "target-launcher-release-id", "target-launcher-archive",
            };
            var suppliedTargetLauncherOptionCount = targetLauncherOptionNames.Count(values.ContainsKey);
            ValidateTargetOptionCounts(suppliedTargetOptionCount, suppliedTargetLauncherOptionCount);
            if (suppliedTargetLauncherOptionCount != 0
                && phase is not (RunnerPhase.PrepareLauncherUpdate or RunnerPhase.AutomaticReleaseUpdate
                    or RunnerPhase.InstalledLauncherUpdate))
            {
                throw new ArgumentException(
                    "A target Launcher tuple is supported only by launcher-update preparation or automatic update.");
            }
            var control = OptionalOrigin(values, "control-origin");
            var gateway = OptionalOrigin(values, "gateway-origin");
            var runtimeProfile = OptionalRuntimeProfile(values);
            if (phase == RunnerPhase.InstalledLauncherUpdate && runtimeProfile is null)
            {
                throw new ArgumentException(
                    "Installed Launcher update requires one explicit runtime profile.");
            }
            var certificate = values.GetValueOrDefault("server-cert-sha256");
            if (certificate is not null
                && (certificate.Length != 64
                    || certificate.Any(character => !Uri.IsHexDigit(character))))
            {
                throw new ArgumentException("Server certificate SHA-256 must be exactly 64 hex characters.");
            }

            EnterpriseResetScope? resetScope = values.GetValueOrDefault("expected-reset-scope") switch
            {
                null => null,
                "MANAGED_CONFIG" => EnterpriseResetScope.ManagedConfig,
                "SECURITY_CREDENTIALS" => EnterpriseResetScope.SecurityCredentials,
                _ => throw new ArgumentException("Expected reset scope is not supported."),
            };
            return new RunnerOptions(
                phase,
                isolation,
                evidence,
                local,
                profile,
                OptionalReleaseId(values, "launcher-release-id"),
                OptionalReleaseId(values, "runtime-release-id"),
                OptionalReleaseId(values, "plugin-policy-release-id"),
                OptionalAbsolutePath(values, "launcher-archive"),
                OptionalAbsolutePath(values, "runtime-archive"),
                OptionalAbsolutePath(values, "plugin-policy-archive"),
                OptionalReleaseId(values, "target-launcher-release-id"),
                OptionalAbsolutePath(values, "target-launcher-archive"),
                OptionalReleaseId(values, "target-runtime-release-id"),
                OptionalAbsolutePath(values, "target-runtime-archive"),
                OptionalReleaseId(values, "target-plugin-policy-release-id"),
                OptionalAbsolutePath(values, "target-plugin-policy-archive"),
                values.GetValueOrDefault("target-plugin-policy-id"),
                targetPolicyGeneration,
                OptionalSha256(values, "target-plugin-policy-sha256"),
                OptionalSha256(values, "target-plugin-archive-sha256"),
                values.GetValueOrDefault("plugin-policy-id"),
                policyGeneration,
                OptionalSha256(values, "plugin-policy-sha256"),
                OptionalSha256(values, "plugin-archive-sha256"),
                OptionalAbsolutePath(values, "release-private-key"),
                OptionalAbsolutePath(values, "initial-manifest-output"),
                OptionalAbsolutePath(values, "initial-journal-output"),
                OptionalAbsolutePath(values, "initial-promotion-result-output"),
                OptionalAbsolutePath(values, "update-manifest-output"),
                OptionalAbsolutePath(values, "update-journal-output"),
                OptionalAbsolutePath(values, "update-promotion-result-output"),
                OptionalAbsolutePath(values, "update-manifest"),
                runtimeProfile,
                control,
                gateway,
                values.GetValueOrDefault("lease-key-id"),
                values.GetValueOrDefault("lease-key-x"),
                values.GetValueOrDefault("lease-key-y"),
                certificate?.ToLowerInvariant(),
                values.GetValueOrDefault("expected-error-code"),
                resetScope,
                OptionalAbsolutePath(values, "ready-signal"),
                OptionalAbsolutePath(values, "continue-signal"),
                values.GetValueOrDefault("signal-token"));
        }

        internal static void ValidateTargetOptionCounts(
            int suppliedRuntimeOptionCount,
            int suppliedLauncherOptionCount)
        {
            if (suppliedRuntimeOptionCount is not 0 and not 8)
            {
                throw new ArgumentException(
                    "The target release tuple must supply every target runtime and plugin-policy option.");
            }
            if (suppliedLauncherOptionCount is not 0 and not 2)
            {
                throw new ArgumentException(
                    "The target Launcher tuple must supply both release id and archive options.");
            }
            if (suppliedRuntimeOptionCount != 0 && suppliedLauncherOptionCount != 0)
            {
                throw new ArgumentException(
                    "A target runtime tuple and target Launcher tuple are mutually exclusive per phase.");
            }
        }

        public TargetLauncherTuple? GetTargetLauncherTuple()
        {
            if (TargetLauncherReleaseId is null && TargetLauncherArchivePath is null)
            {
                return null;
            }
            if (TargetLauncherReleaseId is null || TargetLauncherArchivePath is null)
            {
                throw new InvalidOperationException("The parsed target Launcher tuple is incomplete.");
            }
            return new TargetLauncherTuple(TargetLauncherReleaseId, TargetLauncherArchivePath);
        }

        public TargetReleaseTuple? GetTargetReleaseTuple()
        {
            if (TargetRuntimeReleaseId is null
                && TargetRuntimeArchivePath is null
                && TargetPluginPolicyReleaseId is null
                && TargetPluginPolicyArchivePath is null
                && ExpectedTargetPluginPolicyId is null
                && ExpectedTargetPluginPolicyGeneration is null
                && ExpectedTargetPluginPolicySha256 is null
                && ExpectedTargetPluginArchiveSha256 is null)
            {
                return null;
            }

            if (TargetRuntimeReleaseId is null
                || TargetRuntimeArchivePath is null
                || TargetPluginPolicyReleaseId is null
                || TargetPluginPolicyArchivePath is null
                || ExpectedTargetPluginPolicyId is null
                || ExpectedTargetPluginPolicyGeneration is null
                || ExpectedTargetPluginPolicySha256 is null
                || ExpectedTargetPluginArchiveSha256 is null)
            {
                throw new InvalidOperationException("The parsed target release tuple is incomplete.");
            }

            return new TargetReleaseTuple(
                TargetRuntimeReleaseId,
                TargetRuntimeArchivePath,
                TargetPluginPolicyReleaseId,
                TargetPluginPolicyArchivePath,
                ExpectedTargetPluginPolicyId,
                ExpectedTargetPluginPolicyGeneration.Value,
                ExpectedTargetPluginPolicySha256,
                ExpectedTargetPluginArchiveSha256);
        }

        public static string ToWireValue(RunnerPhase phase) => phase switch
        {
            RunnerPhase.ArtifactFixtureContract => "artifact-fixture-contract",
            RunnerPhase.HttpsArtifactFixtureContract => "https-artifact-fixture-contract",
            RunnerPhase.InstallPluginPolicy => "install-plugin-policy",
            RunnerPhase.ApplyReleaseUpdate => "apply-release-update",
            RunnerPhase.PrepareLauncherUpdate => "prepare-launcher-update",
            RunnerPhase.AutomaticReleaseUpdate => "automatic-release-update",
            RunnerPhase.InstalledLauncherUpdate => "installed-launcher-update",
            RunnerPhase.EnrollChat => "enroll-chat",
            RunnerPhase.RefreshChat => "refresh-chat",
            RunnerPhase.RefreshUpdateRequired => "refresh-update-required",
            RunnerPhase.RefreshWaitDenied => "refresh-wait-denied",
            RunnerPhase.AssertEnrollmentRequired => "assert-enrollment-required",
            _ => throw new ArgumentOutOfRangeException(nameof(phase)),
        };

        private static string Require(IReadOnlyDictionary<string, string> values, string key) =>
            values.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
                ? value
                : throw new ArgumentException($"--{key} is required.");

        private static string RequireAbsolutePath(
            IReadOnlyDictionary<string, string> values,
            string key) => OptionalAbsolutePath(values, key)
                ?? throw new ArgumentException($"--{key} is required.");

        private static string? OptionalAbsolutePath(
            IReadOnlyDictionary<string, string> values,
            string key)
        {
            if (!values.TryGetValue(key, out var value))
            {
                return null;
            }
            if (!Path.IsPathFullyQualified(value)
                || value.StartsWith("\\\\", StringComparison.Ordinal)
                || value.StartsWith("//", StringComparison.Ordinal))
            {
                throw new ArgumentException($"--{key} must be an absolute local path.");
            }

            return Path.GetFullPath(value);
        }

        private static string? OptionalReleaseId(
            IReadOnlyDictionary<string, string> values,
            string key)
        {
            if (!values.TryGetValue(key, out var value))
            {
                return null;
            }
            if (string.IsNullOrWhiteSpace(value)
                || value.Length > 128
                || value.Any(character => !(char.IsAsciiLetterOrDigit(character)
                    || character is '.' or '_' or '+' or '-')))
            {
                throw new ArgumentException($"--{key} is not a canonical release id.");
            }
            return value;
        }

        private static long? OptionalPositiveInt64(
            IReadOnlyDictionary<string, string> values,
            string key)
        {
            if (!values.TryGetValue(key, out var value))
            {
                return null;
            }
            if (!long.TryParse(
                    value,
                    System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture,
                    out var parsed)
                || parsed is <= 0 or > 9_007_199_254_740_991L)
            {
                throw new ArgumentException($"--{key} is not a positive safe integer.");
            }
            return parsed;
        }

        private static string? OptionalSha256(
            IReadOnlyDictionary<string, string> values,
            string key)
        {
            if (!values.TryGetValue(key, out var value))
            {
                return null;
            }
            if (value.Length != 64
                || value.Any(character => character is not (>= '0' and <= '9')
                    and not (>= 'a' and <= 'f')))
            {
                throw new ArgumentException($"--{key} must be 64 lowercase hex characters.");
            }
            return value;
        }

        private static Uri? OptionalOrigin(
            IReadOnlyDictionary<string, string> values,
            string key)
        {
            if (!values.TryGetValue(key, out var value))
            {
                return null;
            }

            var origin = new Uri(value, UriKind.Absolute);
            if (origin.Scheme != Uri.UriSchemeHttps
                || !string.IsNullOrEmpty(origin.UserInfo)
                || !string.IsNullOrEmpty(origin.Query)
                || !string.IsNullOrEmpty(origin.Fragment)
                || origin.AbsolutePath != "/")
            {
                throw new ArgumentException($"--{key} must be one exact HTTPS origin.");
            }
            return origin;
        }

        private static string? OptionalRuntimeProfile(
            IReadOnlyDictionary<string, string> values)
        {
            if (!values.TryGetValue("runtime-profile", out var value))
            {
                return null;
            }

            return value switch
            {
                EnterpriseManagedRuntimeProfile => value,
                EnterpriseDirectLocalRuntimeProfile => value,
                _ => throw new ArgumentException(
                    "--runtime-profile is not an exact supported Enterprise runtime profile."),
            };
        }
    }

}
