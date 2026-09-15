using System.Text.Json;

namespace Ensou.Dsh.Enterprise.Installation;

public sealed partial class EnterpriseInstallationService
{
    internal async Task<EnterpriseLegacyMigrationCandidate>
        StageLegacyMigrationCandidateUnderExistingLeaseAsync(
            string candidateManagedRoot,
            IEnterprisePayloadSource source,
            EnterpriseLegacyMigrationTrustedInstallerLease trustedInstaller,
            CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(candidateManagedRoot);
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(trustedInstaller);
        var candidateLayout = EnterpriseInstallationLayout.CreateMigrationCandidate(
            _layout,
            candidateManagedRoot);
        return await new EnterpriseInstallationService(
                candidateLayout,
                beforeLegacySqliteCommitForTest: null,
                _requireNoPossibleHarnessWriter)
            .StageLegacyMigrationCandidateCoreAsync(
                source,
                trustedInstaller,
                cancellationToken)
            .ConfigureAwait(false);
    }

    internal Task<EnterpriseInstallResult> FinalizeLegacyMigrationCandidateUnderExistingLeaseAsync(
        EnterpriseInstallManifest manifest,
        EnterpriseLegacyMigrationCandidate candidate,
        bool developmentUnsignedPayload,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(timeProvider);
        cancellationToken.ThrowIfCancellationRequested();
        if (!string.Equals(manifest.LayoutProfile, _layout.LayoutProfile, StringComparison.Ordinal)
            || !string.Equals(
                manifest.LauncherReleaseId,
                candidate.LauncherReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                manifest.RuntimeReleaseId,
                candidate.RuntimeReleaseId,
                StringComparison.Ordinal)
            || developmentUnsignedPayload != _layout.IsDevelopmentE2E)
        {
            throw new InvalidDataException(
                "Enterprise migration finalization identity does not match the verified payload.");
        }

        EnterpriseStableBootstrapperVerifier.WriteReceipt(
            _layout,
            manifest.BootstrapperSha256);
        var runtime = new EnterpriseRuntimePointerStore(_layout)
            .Activate(candidate.RuntimeReleaseId);
        var launcher = new EnterpriseLauncherPointerStore(_layout)
            .Activate(candidate.LauncherReleaseId);
        var releaseSet = new EnterpriseReleaseSetPointerStore(_layout)
            .ActivateInitialHealthy(
                candidate.LauncherReleaseId,
                candidate.RuntimeReleaseId);
        if (!string.Equals(
                runtime.ReleaseId,
                candidate.RuntimeReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                launcher.ReleaseId,
                candidate.LauncherReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                releaseSet.Current.Launcher.ReleaseId,
                candidate.LauncherReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                releaseSet.Current.Runtime.ReleaseId,
                candidate.RuntimeReleaseId,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise migration component activation did not commit exactly.");
        }

        var nowUtc = RequireUtc(timeProvider);
        var receipt = new EnterpriseInstallationReceipt(
            1,
            _layout.LayoutProfile,
            candidate.LauncherReleaseId,
            candidate.RuntimeReleaseId,
            developmentUnsignedPayload,
            nowUtc);
        EnterprisePathGuard.WriteFileAtomically(
            Path.Combine(_layout.StateRoot, InstallationReceiptFileName),
            JsonSerializer.SerializeToUtf8Bytes(receipt, EnterpriseInstallJson.Options),
            _layout.ManagedRoot);
        return Task.FromResult(new EnterpriseInstallResult(
            candidate.LauncherReleaseId,
            candidate.RuntimeReleaseId,
            _layout.BootstrapperPath,
            developmentUnsignedPayload));
    }

    internal async Task<EnterpriseInstallResult>
        RepairTrustedProductionStableShellAndRegisterAsync(
            EnterpriseLegacyMigrationTrustedInstallerLease trustedInstaller,
            string currentLauncherReleaseId,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(trustedInstaller);
        trustedInstaller.RequireIdentityUnchanged();
        var result = await RepairStableShellAndRegisterAsync(
            trustedInstaller.RequirePayloadSource(),
            trustedInstaller.InstallerPath,
            currentLauncherReleaseId,
            developmentUnsignedPayload: false,
            EnterpriseWindowsRegistrationContext.CreateDefault(_layout),
            cancellationToken).ConfigureAwait(false);
        trustedInstaller.RequireIdentityUnchanged();
        return result;
    }

    internal async Task<EnterpriseInstallResult>
        RepairDevelopmentStableShellAndRegisterAsync(
            string payloadDirectory,
            string installerExecutablePath,
            string currentLauncherReleaseId,
            EnterpriseWindowsRegistrationContext registrationContext,
            CancellationToken cancellationToken = default)
    {
        if (!_layout.IsDevelopmentE2E)
        {
            throw new InvalidDataException(
                "Unsigned stable-shell repair is restricted to Development E2E.");
        }
        using var source = EnterpriseDirectoryPayloadSource.OpenExplicitDevelopmentPayload(
            payloadDirectory);
        return await RepairStableShellAndRegisterAsync(
            source,
            installerExecutablePath,
            currentLauncherReleaseId,
            developmentUnsignedPayload: true,
            registrationContext,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<EnterpriseLegacyMigrationCandidate>
        StageLegacyMigrationCandidateCoreAsync(
            IEnterprisePayloadSource source,
            EnterpriseLegacyMigrationTrustedInstallerLease trustedInstaller,
            CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        trustedInstaller.RequireIdentityUnchanged();
        var manifest = trustedInstaller.Manifest;
        if (!string.Equals(manifest.LayoutProfile, _layout.LayoutProfile, StringComparison.Ordinal)
            || Directory.Exists(_layout.ManagedRoot)
            || File.Exists(_layout.ManagedRoot))
        {
            throw new InvalidDataException(
                "Enterprise migration candidate root or payload profile is invalid.");
        }

        EnterpriseLegacyMigrationDurability.EnsureDirectory(
            _layout.LocalAppDataRoot,
            _layout.ManagedRoot);
        foreach (var directory in new[]
                 {
                     _layout.LauncherVersionsRoot,
                     _layout.RuntimeVersionsRoot,
                     _layout.PluginPolicyVersionsRoot,
                     _layout.StateRoot,
                     _layout.PackageRoot,
                 })
        {
            EnterprisePathGuard.EnsureDirectoryChain(_layout.ManagedRoot, directory);
        }

        var operationDirectory = Path.Combine(
            _layout.PackageRoot,
            $".migration-stage-{Guid.NewGuid():N}");
        EnterprisePathGuard.EnsureDirectoryChain(_layout.ManagedRoot, operationDirectory);
        var launcherPackagePath = Path.Combine(operationDirectory, manifest.LauncherArchive);
        var runtimePackagePath = Path.Combine(operationDirectory, manifest.RuntimeArchive);
        var bootstrapperPackagePath = Path.Combine(
            operationDirectory,
            manifest.BootstrapperFile);
        await CopyAndVerifyPayloadAsync(
            source,
            manifest.LauncherArchive,
            launcherPackagePath,
            manifest.LauncherArchiveSizeBytes,
            manifest.LauncherArchiveSha256,
            cancellationToken).ConfigureAwait(false);
        await CopyAndVerifyPayloadAsync(
            source,
            manifest.RuntimeArchive,
            runtimePackagePath,
            manifest.RuntimeArchiveSizeBytes,
            manifest.RuntimeArchiveSha256,
            cancellationToken).ConfigureAwait(false);
        await CopyAndVerifyPayloadAsync(
            source,
            manifest.BootstrapperFile,
            bootstrapperPackagePath,
            manifest.BootstrapperSizeBytes,
            manifest.BootstrapperSha256,
            cancellationToken).ConfigureAwait(false);

        await InstallLegacyMigrationArchiveAsync(
            launcherPackagePath,
            manifest.LauncherReleaseId,
            manifest.LauncherArchiveSha256,
            launcher: true,
            cancellationToken).ConfigureAwait(false);
        await InstallLegacyMigrationArchiveAsync(
            runtimePackagePath,
            manifest.RuntimeReleaseId,
            manifest.RuntimeArchiveSha256,
            launcher: false,
            cancellationToken).ConfigureAwait(false);
        InstallStableFile(
            bootstrapperPackagePath,
            _layout.BootstrapperPath,
            manifest.BootstrapperSha256);
        EnterprisePathGuard.WriteFileAtomically(
            _layout.BuildProfileMarkerPath,
            EnterpriseBuildProfileMarker.CreateCanonical(_layout.LayoutProfile),
            _layout.ManagedRoot);
        InstallStableFile(
            trustedInstaller.InstallerPath,
            _layout.InstalledInstallerPath,
            trustedInstaller.InstallerSha256);
        trustedInstaller.RequireIdentityUnchanged();
        DeleteInstallOperationDirectory(operationDirectory);
        return new EnterpriseLegacyMigrationCandidate(
            manifest.LauncherReleaseId,
            manifest.RuntimeReleaseId);
    }

    private async Task InstallLegacyMigrationArchiveAsync(
        string archivePath,
        string releaseId,
        string archiveSha256,
        bool launcher,
        CancellationToken cancellationToken)
    {
        EnterprisePathGuard.ValidateReleaseId(releaseId);
        var versionRoot = launcher
            ? _layout.LauncherVersionsRoot
            : _layout.RuntimeVersionsRoot;
        var finalDirectory = EnterprisePathGuard.CombineExactChild(versionRoot, releaseId);
        if (Directory.Exists(finalDirectory) || File.Exists(finalDirectory))
        {
            throw new InvalidDataException(
                "Enterprise migration candidate release directory already exists.");
        }
        var stagingDirectory = Path.Combine(
            versionRoot,
            $".{releaseId}.staging-{Guid.NewGuid():N}");
        EnterprisePathGuard.EnsureDirectoryChain(_layout.ManagedRoot, stagingDirectory);
        await ExtractArchiveSafelyAsync(
            archivePath,
            stagingDirectory,
            cancellationToken).ConfigureAwait(false);

        var primaryRelativePath = launcher
            ? EnterpriseInstallationLayout.LauncherExecutableName
            : "node.exe";
        var secondaryRelativePath = launcher
            ? null
            : "node_modules/@deepseek-ai/dsh/lib/bin.js";
        var primaryPath = ResolveArchiveOutput(stagingDirectory, primaryRelativePath);
        var secondaryPath = secondaryRelativePath is null
            ? null
            : ResolveArchiveOutput(stagingDirectory, secondaryRelativePath);
        if (!File.Exists(primaryPath)
            || secondaryPath is not null && !File.Exists(secondaryPath))
        {
            throw new InvalidDataException(
                "Enterprise migration archive is missing a required runtime entry.");
        }
        if (launcher)
        {
            EnterpriseBuildProfileMarker.ReadAndValidate(
                Path.Combine(
                    stagingDirectory,
                    EnterpriseInstallationLayout.BuildProfileMarkerFileName),
                _layout.LayoutProfile);
            foreach (var name in new[]
                     {
                         EnterpriseInstallationLayout.LauncherExecutableName,
                         EnterpriseInstallationLayout.ClientBootstrapperExecutableName,
                         EnterpriseInstallationLayout.MaintenanceExecutableName,
                     })
            {
                var executable = ResolveArchiveOutput(stagingDirectory, name);
                if (!File.Exists(executable))
                {
                    throw new InvalidDataException(
                        "Enterprise migration client bundle is incomplete.");
                }
                EnterpriseAuthenticodeVerifier.RequireTrustedSignature(executable, _layout);
            }
        }
        EnterprisePathGuard.ValidateSafeTree(stagingDirectory, _layout.ManagedRoot);
        var runtimeManifestSha256 = launcher
            ? null
            : EnterpriseRuntimeFileManifest.ValidateCompleteTree(stagingDirectory);
        var receipt = new EnterpriseInstalledReleaseReceipt(
            1,
            releaseId,
            archiveSha256,
            EnterpriseHash.ComputeFile(primaryPath),
            secondaryPath is null ? null : EnterpriseHash.ComputeFile(secondaryPath),
            DateTimeOffset.UtcNow);
        if (launcher)
        {
            EnterpriseLauncherPointerStore.WriteReceipt(
                stagingDirectory,
                receipt,
                _layout.ManagedRoot);
        }
        else
        {
            EnterpriseRuntimePointerStore.WriteReceipt(
                stagingDirectory,
                receipt,
                _layout.ManagedRoot);
        }
        var artifactReceipt = new EnterpriseReleaseArtifactReceiptV2(
            2,
            launcher
                ? EnterpriseReleaseSetContract.LauncherComponent
                : EnterpriseReleaseSetContract.RuntimeComponent,
            releaseId,
            archiveSha256,
            EnterpriseTreeHash.Compute(stagingDirectory),
            runtimeManifestSha256,
            DateTimeOffset.UtcNow);
        EnterprisePathGuard.WriteFileAtomically(
            Path.Combine(stagingDirectory, EnterpriseTreeHash.ReceiptFileName),
            EnterprisePointerJson.Serialize(artifactReceipt),
            _layout.ManagedRoot);
        Directory.Move(stagingDirectory, finalDirectory);
    }

    private async Task<EnterpriseInstallResult> RepairStableShellAndRegisterAsync(
        IEnterprisePayloadSource source,
        string installerExecutablePath,
        string currentLauncherReleaseId,
        bool developmentUnsignedPayload,
        EnterpriseWindowsRegistrationContext registrationContext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentException.ThrowIfNullOrWhiteSpace(installerExecutablePath);
        EnterprisePathGuard.ValidateReleaseId(currentLauncherReleaseId);
        ArgumentNullException.ThrowIfNull(registrationContext);
        EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHomeAndNoWriter(
            _layout,
            _requireNoPossibleHarnessWriter);
        await using var operationLease = await EnterpriseManagedUpdateOperationLease
            .AcquireRequiredAsync(_layout, cancellationToken)
            .ConfigureAwait(false);
        EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHomeAndNoWriter(
            _layout,
            _requireNoPossibleHarnessWriter);
        EnterpriseManagedOperationRecovery.RecoverInterruptedUnderLease(_layout);
        EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHomeAndNoWriter(
            _layout,
            _requireNoPossibleHarnessWriter);

        EnterpriseInstallManifest manifest;
        await using (var manifestStream = source.Open(
                         EnterpriseEmbeddedPayloadSource.ManifestFileName))
        {
            manifest = EnterpriseInstallManifest.Parse(await ReadBoundedAsync(
                manifestStream,
                128 * 1024,
                cancellationToken).ConfigureAwait(false));
        }
        if (!string.Equals(manifest.LayoutProfile, _layout.LayoutProfile, StringComparison.Ordinal)
            || developmentUnsignedPayload != _layout.IsDevelopmentE2E)
        {
            throw new InvalidDataException(
                "Enterprise stable-shell repair payload profile is invalid.");
        }
        EnterpriseManagedGcPathSafety.ValidateSafeTreeWithSingleLinks(
            _layout.ManagedRoot,
            _layout.LocalAppDataRoot);
        EnterpriseBuildProfileMarker.ReadAndValidate(
            _layout.BuildProfileMarkerPath,
            _layout.LayoutProfile);
        var current = new EnterpriseReleaseSetPointerStore(_layout).ReadRequired();
        if (!string.Equals(
                current.Current.Launcher.ReleaseId,
                currentLauncherReleaseId,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise stable-shell repair current release changed before commit.");
        }
        EnterpriseReleaseSetValidator.ValidateStartupStubCompatibility(
            current.Current.StartupStub,
            EnterpriseReleaseSetContract.CurrentStartupStubProtocol);

        var cleanContext = registrationContext.WithoutObservers();
        var registrationSnapshot = EnterpriseWindowsRegistration.CaptureRollbackSnapshot(
            _layout,
            cleanContext);
        var transaction = new EnterpriseInstallRollbackTransaction(
            _layout,
            cleanContext,
            registrationSnapshot);
        var operationDirectory = Path.Combine(
            _layout.PackageRoot,
            $".stable-shell-repair-{Guid.NewGuid():N}");
        try
        {
            EnterprisePathGuard.EnsureDirectoryChain(_layout.ManagedRoot, operationDirectory);
            var bootstrapperPackagePath = Path.Combine(
                operationDirectory,
                manifest.BootstrapperFile);
            await CopyAndVerifyPayloadAsync(
                source,
                manifest.BootstrapperFile,
                bootstrapperPackagePath,
                manifest.BootstrapperSizeBytes,
                manifest.BootstrapperSha256,
                cancellationToken).ConfigureAwait(false);
            EnterpriseAuthenticodeVerifier.RequireTrustedSignature(
                bootstrapperPackagePath,
                _layout);
            transaction.CaptureFile(_layout.BootstrapperPath);
            InstallStableFile(
                bootstrapperPackagePath,
                _layout.BootstrapperPath,
                manifest.BootstrapperSha256);
            transaction.CaptureFile(_layout.BootstrapperReceiptPath);
            EnterpriseStableBootstrapperVerifier.WriteReceipt(
                _layout,
                manifest.BootstrapperSha256);
            transaction.CaptureFile(_layout.InstalledInstallerPath);
            InstallStableFile(
                installerExecutablePath,
                _layout.InstalledInstallerPath,
                EnterpriseHash.ComputeFile(installerExecutablePath));
            DeleteInstallOperationDirectory(operationDirectory);
            _ = EnterpriseWindowsRegistration.Install(
                _layout,
                currentLauncherReleaseId,
                developmentUnsignedPayload,
                registrationContext);
            _beforeLegacySqliteCommitForTest?.Invoke();
            EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHomeAndNoWriter(
                _layout,
                _requireNoPossibleHarnessWriter);
            transaction.Commit();
            return new EnterpriseInstallResult(
                current.Current.Launcher.ReleaseId,
                current.Current.Runtime.ReleaseId,
                _layout.BootstrapperPath,
                developmentUnsignedPayload);
        }
        catch (Exception repairFailure)
        {
            var rollbackFailures = new List<Exception>();
            try
            {
                DeleteInstallOperationDirectory(operationDirectory);
            }
            catch (Exception exception)
            {
                rollbackFailures.Add(exception);
            }
            try
            {
                transaction.Rollback();
            }
            catch (Exception exception)
            {
                rollbackFailures.Add(exception);
            }
            if (rollbackFailures.Count > 0)
            {
                if (EnterpriseLegacySqliteUpgradeGuard.IsBlockedFailure(repairFailure))
                {
                    throw new InvalidOperationException(
                        EnterpriseLegacySqliteUpgradeGuard
                            .RepairRollbackFailureMessage);
                }
                throw new AggregateException(
                    "Enterprise stable-shell repair failed and rollback could not be certified.",
                    new[] { repairFailure }.Concat(rollbackFailures));
            }
            throw;
        }
        finally
        {
            transaction.Dispose();
        }
    }

    private static DateTimeOffset RequireUtc(TimeProvider timeProvider)
    {
        var now = timeProvider.GetUtcNow();
        if (now.Offset != TimeSpan.Zero)
        {
            throw new InvalidOperationException(
                "Enterprise installation TimeProvider must return UTC.");
        }
        return now;
    }
}
