using System.Reflection;

namespace Ensou.Dsh.Enterprise.Installation;

/// <summary>
/// External signed-Installer entry point for the one-time schema-2 migration.
/// The verified Installer handle remains open through candidate replacement
/// and every post-classification repair operation.
/// </summary>
public static class EnterpriseLegacyMigrationInstallerFacade
{
    public static void RequireEmbeddedProductionMigrationPayload(
        EnterpriseInstallationLayout layout,
        Assembly installerAssembly,
        string installerExecutablePath)
    {
        using var trustedInstaller = EnterpriseLegacyMigrationTrustedInstallerLease
            .OpenProduction(layout, installerAssembly, installerExecutablePath);
        trustedInstaller.RequireIdentityUnchanged();
    }

    public static async Task<EnterpriseInstallResult>
        InstallOrRepairEmbeddedProductionPayloadAndRegisterAsync(
            EnterpriseInstallationLayout layout,
            Assembly installerAssembly,
            string installerExecutablePath,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(installerAssembly);
        ArgumentException.ThrowIfNullOrWhiteSpace(installerExecutablePath);
        using var trustedInstaller = EnterpriseLegacyMigrationTrustedInstallerLease
            .OpenProduction(layout, installerAssembly, installerExecutablePath);
        var registrationContext = EnterpriseWindowsRegistrationContext.CreateDefault(layout);
        var migration = await MigrateWithTrustedInstallerAsync(
            layout,
            trustedInstaller,
            registrationContext,
            TimeProvider.System,
            cancellationToken).ConfigureAwait(false);
        trustedInstaller.RequireIdentityUnchanged();

        var service = new EnterpriseInstallationService(layout);
        EnterpriseInstallResult result;
        switch (migration.Disposition)
        {
            case EnterpriseLegacyMigrationDisposition.Migrated:
            case EnterpriseLegacyMigrationDisposition.RegistrationRecovered:
                result = ResultFromMigration(layout, migration, development: false);
                break;

            case EnterpriseLegacyMigrationDisposition.FreshInstallRequired:
                result = await service.InstallEmbeddedProductionPayloadAndRegisterAsync(
                    installerAssembly,
                    installerExecutablePath,
                    cancellationToken).ConfigureAwait(false);
                break;

            case EnterpriseLegacyMigrationDisposition.CurrentInstallationAlreadyTrusted:
                var currentLauncher = migration.LauncherReleaseId
                    ?? throw new InvalidDataException(
                        "Trusted Enterprise installation has no Launcher release identity.");
                var currentRuntime = migration.RuntimeReleaseId
                    ?? throw new InvalidDataException(
                        "Trusted Enterprise installation has no runtime release identity.");
                if (string.Equals(
                        currentLauncher,
                        trustedInstaller.Manifest.LauncherReleaseId,
                        StringComparison.Ordinal)
                    && string.Equals(
                        currentRuntime,
                        trustedInstaller.Manifest.RuntimeReleaseId,
                        StringComparison.Ordinal))
                {
                    result = await service.InstallEmbeddedProductionPayloadAndRegisterAsync(
                        installerAssembly,
                        installerExecutablePath,
                        cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    result = await service
                        .RepairTrustedProductionStableShellAndRegisterAsync(
                            trustedInstaller,
                            currentLauncher,
                            cancellationToken)
                        .ConfigureAwait(false);
                }
                break;

            default:
                throw new InvalidDataException(
                    "Enterprise legacy migration returned an unsupported disposition.");
        }
        trustedInstaller.RequireIdentityUnchanged();
        return result;
    }

    /// <summary>
    /// Production external-Installer uninstall. If a one-time migration was
    /// interrupted, the exact journal-bound Installer first resumes it to a
    /// fully authenticated state. Resume and uninstall share one operation
    /// lease, so no update, health commit, repair, or GC can interleave.
    /// </summary>
    public static async Task<EnterpriseUninstallCommitResult>
        UninstallAfterRecoveringLegacyMigrationAsync(
            EnterpriseInstallationLayout layout,
            Assembly installerAssembly,
            string installerExecutablePath,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(installerAssembly);
        ArgumentException.ThrowIfNullOrWhiteSpace(installerExecutablePath);
        using var trustedInstaller = EnterpriseLegacyMigrationTrustedInstallerLease
            .OpenProduction(layout, installerAssembly, installerExecutablePath);
        var registrationContext = EnterpriseWindowsRegistrationContext.CreateDefault(layout);
        await using var operationLease = await EnterpriseManagedUpdateOperationLease
            .AcquireRequiredAsync(layout, cancellationToken)
            .ConfigureAwait(false);
        _ = await MigrateWithTrustedInstallerUnderExistingLeaseAsync(
            layout,
            trustedInstaller,
            registrationContext,
            TimeProvider.System,
            cancellationToken).ConfigureAwait(false);
        trustedInstaller.RequireIdentityUnchanged();
        EnterpriseManagedOperationRecovery.RecoverInterruptedUnderLease(layout);
        var result = new EnterpriseMaintenanceOperations(layout, registrationContext)
            .UninstallManagedProgramFilesUnderLease();
        trustedInstaller.RequireIdentityUnchanged();
        return result;
    }

    internal static Task<EnterpriseLegacyMigrationResult>
        MigrateWithTrustedInstallerForTestAsync(
            EnterpriseInstallationLayout layout,
            EnterpriseLegacyMigrationTrustedInstallerLease trustedInstaller,
            EnterpriseWindowsRegistrationContext registrationContext,
            TimeProvider? timeProvider = null,
            CancellationToken cancellationToken = default) =>
        MigrateWithTrustedInstallerAsync(
            layout,
            trustedInstaller,
            registrationContext,
            timeProvider ?? TimeProvider.System,
            cancellationToken);

    internal static async Task<EnterpriseInstallResult>
        InstallOrRepairDevelopmentPayloadAndRegisterForTestAsync(
            EnterpriseInstallationLayout layout,
            string payloadDirectory,
            string installerExecutablePath,
            EnterpriseWindowsRegistrationContext registrationContext,
            TimeProvider? timeProvider = null,
            CancellationToken cancellationToken = default)
    {
        if (!layout.IsDevelopmentE2E)
        {
            throw new InvalidDataException(
                "The unsigned migration facade test seam requires Development E2E.");
        }
        using var source = EnterpriseDirectoryPayloadSource.OpenExplicitDevelopmentPayload(
            payloadDirectory);
        using var trustedInstaller = EnterpriseLegacyMigrationTrustedInstallerLease.OpenForTest(
            layout,
            installerExecutablePath,
            source);
        var migration = await MigrateWithTrustedInstallerAsync(
            layout,
            trustedInstaller,
            registrationContext,
            timeProvider ?? TimeProvider.System,
            cancellationToken).ConfigureAwait(false);
        var service = new EnterpriseInstallationService(layout);
        switch (migration.Disposition)
        {
            case EnterpriseLegacyMigrationDisposition.Migrated:
            case EnterpriseLegacyMigrationDisposition.RegistrationRecovered:
                return ResultFromMigration(layout, migration, development: true);

            case EnterpriseLegacyMigrationDisposition.FreshInstallRequired:
                return await service.InstallExternalDevelopmentPayloadAndRegisterAsync(
                    payloadDirectory,
                    installerExecutablePath,
                    registrationContext,
                    cancellationToken).ConfigureAwait(false);

            case EnterpriseLegacyMigrationDisposition.CurrentInstallationAlreadyTrusted:
                var currentLauncher = migration.LauncherReleaseId
                    ?? throw new InvalidDataException(
                        "Trusted test installation has no Launcher release identity.");
                var currentRuntime = migration.RuntimeReleaseId
                    ?? throw new InvalidDataException(
                        "Trusted test installation has no runtime release identity.");
                if (string.Equals(
                        currentLauncher,
                        trustedInstaller.Manifest.LauncherReleaseId,
                        StringComparison.Ordinal)
                    && string.Equals(
                        currentRuntime,
                        trustedInstaller.Manifest.RuntimeReleaseId,
                        StringComparison.Ordinal))
                {
                    return await service.InstallExternalDevelopmentPayloadAndRegisterAsync(
                        payloadDirectory,
                        installerExecutablePath,
                        registrationContext,
                        cancellationToken).ConfigureAwait(false);
                }
                return await service.RepairDevelopmentStableShellAndRegisterAsync(
                    payloadDirectory,
                    installerExecutablePath,
                    currentLauncher,
                    registrationContext,
                    cancellationToken).ConfigureAwait(false);

            default:
                throw new InvalidDataException(
                    "Enterprise test migration returned an unsupported disposition.");
        }
    }

    internal static async Task<EnterpriseUninstallCommitResult>
        UninstallDevelopmentPayloadAfterRecoveringLegacyMigrationForTestAsync(
            EnterpriseInstallationLayout layout,
            string payloadDirectory,
            string installerExecutablePath,
            EnterpriseWindowsRegistrationContext registrationContext,
            TimeProvider? timeProvider = null,
            CancellationToken cancellationToken = default)
    {
        if (!layout.IsDevelopmentE2E)
        {
            throw new InvalidDataException(
                "The unsigned migration uninstall test seam requires Development E2E.");
        }
        using var source = EnterpriseDirectoryPayloadSource.OpenExplicitDevelopmentPayload(
            payloadDirectory);
        using var trustedInstaller = EnterpriseLegacyMigrationTrustedInstallerLease.OpenForTest(
            layout,
            installerExecutablePath,
            source);
        await using var operationLease = await EnterpriseManagedUpdateOperationLease
            .AcquireRequiredAsync(layout, cancellationToken)
            .ConfigureAwait(false);
        _ = await MigrateWithTrustedInstallerUnderExistingLeaseAsync(
            layout,
            trustedInstaller,
            registrationContext,
            timeProvider ?? TimeProvider.System,
            cancellationToken).ConfigureAwait(false);
        trustedInstaller.RequireIdentityUnchanged();
        EnterpriseManagedOperationRecovery.RecoverInterruptedUnderLease(layout);
        var result = new EnterpriseMaintenanceOperations(layout, registrationContext)
            .UninstallManagedProgramFilesUnderLease();
        trustedInstaller.RequireIdentityUnchanged();
        return result;
    }

    private static async Task<EnterpriseLegacyMigrationResult>
        MigrateWithTrustedInstallerAsync(
            EnterpriseInstallationLayout layout,
            EnterpriseLegacyMigrationTrustedInstallerLease trustedInstaller,
            EnterpriseWindowsRegistrationContext registrationContext,
            TimeProvider timeProvider,
            CancellationToken cancellationToken)
    {
        var service = new EnterpriseInstallationService(layout);
        var callbacks = CreateCallbacks(
            layout,
            service,
            trustedInstaller,
            registrationContext,
            timeProvider);
        return await new EnterpriseLegacyTestInstallationMigrator(layout, timeProvider)
            .MigrateIfRequiredAsync(
                trustedInstaller,
                callbacks,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static EnterpriseLegacyMigrationCallbacks CreateCallbacks(
        EnterpriseInstallationLayout layout,
        EnterpriseInstallationService service,
        EnterpriseLegacyMigrationTrustedInstallerLease trustedInstaller,
        EnterpriseWindowsRegistrationContext registrationContext,
        TimeProvider timeProvider) =>
        new(
            (candidateRoot, source, token) =>
                service.StageLegacyMigrationCandidateUnderExistingLeaseAsync(
                    candidateRoot,
                    source,
                    trustedInstaller,
                    token),
            async (candidate, token) =>
            {
                _ = await service
                    .FinalizeLegacyMigrationCandidateUnderExistingLeaseAsync(
                        trustedInstaller.Manifest,
                        candidate,
                        layout.IsDevelopmentE2E,
                        timeProvider,
                        token)
                    .ConfigureAwait(false);
            },
            candidate => ValidateFinalized(layout, candidate),
            (candidate, token) => RegisterAsync(
                layout,
                registrationContext,
                candidate,
                token),
            candidate => _ = EnterpriseWindowsRegistration.ReadAndValidate(
                layout,
                candidate.LauncherReleaseId,
                layout.IsDevelopmentE2E,
                registrationContext));

    private static async Task<EnterpriseLegacyMigrationResult>
        MigrateWithTrustedInstallerUnderExistingLeaseAsync(
            EnterpriseInstallationLayout layout,
            EnterpriseLegacyMigrationTrustedInstallerLease trustedInstaller,
            EnterpriseWindowsRegistrationContext registrationContext,
            TimeProvider timeProvider,
            CancellationToken cancellationToken)
    {
        var service = new EnterpriseInstallationService(layout);
        var callbacks = CreateCallbacks(
            layout,
            service,
            trustedInstaller,
            registrationContext,
            timeProvider);
        return await new EnterpriseLegacyTestInstallationMigrator(layout, timeProvider)
            .MigrateIfRequiredUnderExistingLeaseAsync(
                trustedInstaller,
                callbacks,
                enforceLegacySqliteGuard: false,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static Task RegisterAsync(
        EnterpriseInstallationLayout layout,
        EnterpriseWindowsRegistrationContext registrationContext,
        EnterpriseLegacyMigrationCandidate candidate,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _ = EnterpriseWindowsRegistration.Install(
            layout,
            candidate.LauncherReleaseId,
            layout.IsDevelopmentE2E,
            registrationContext);
        return Task.CompletedTask;
    }

    private static void ValidateFinalized(
        EnterpriseInstallationLayout layout,
        EnterpriseLegacyMigrationCandidate candidate)
    {
        EnterpriseStableBootstrapperVerifier.RequireTrusted(layout);
        var releaseSet = new EnterpriseReleaseSetPointerStore(layout).ReadRequired();
        if (!string.Equals(
                releaseSet.Current.Launcher.ReleaseId,
                candidate.LauncherReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                releaseSet.Current.Runtime.ReleaseId,
                candidate.RuntimeReleaseId,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise migration facade finalized another component tuple.");
        }
    }

    private static EnterpriseInstallResult ResultFromMigration(
        EnterpriseInstallationLayout layout,
        EnterpriseLegacyMigrationResult migration,
        bool development) => new(
        migration.LauncherReleaseId
            ?? throw new InvalidDataException(
                "Completed Enterprise migration has no Launcher release identity."),
        migration.RuntimeReleaseId
            ?? throw new InvalidDataException(
                "Completed Enterprise migration has no runtime release identity."),
        layout.BootstrapperPath,
        development);
}
