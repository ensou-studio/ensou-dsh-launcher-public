namespace Ensou.Dsh.Enterprise.Installation;

/// <summary>
/// Recovery preamble for callers that already hold the external managed
/// operation lease. It intentionally acquires no lease of its own.
/// </summary>
internal static class EnterpriseManagedOperationRecovery
{
    public static void RecoverInterruptedUnderLease(
        EnterpriseInstallationLayout layout)
    {
        ArgumentNullException.ThrowIfNull(layout);
        EnterpriseLegacyMigrationBarrier.RequireNoActiveMigrationForUnrelatedOperation(
            layout);
        RecoverInstallerTransactions(layout);
    }

    /// <summary>
    /// The only recovery admission that may continue while a legacy migration
    /// journal is active. The caller must still hold the external operation
    /// lease, and the exact external Installer handle stays bound while the
    /// migrator authenticates and consumes that journal.
    /// </summary>
    public static void RecoverInterruptedUnderLease(
        EnterpriseInstallationLayout layout,
        EnterpriseLegacyMigrationTrustedInstallerLease trustedInstaller)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(trustedInstaller);
        trustedInstaller.RequireIdentityUnchanged();
        RecoverInstallerTransactions(layout);
        trustedInstaller.RequireIdentityUnchanged();
    }

    private static void RecoverInstallerTransactions(EnterpriseInstallationLayout layout)
    {
        EnterpriseInstallRollbackTransaction.RecoverInterrupted(layout);
        EnterpriseUninstallRollbackTransaction.RecoverInterrupted(layout);
    }
}

/// <summary>
/// Fail-closed barrier between an interrupted one-time legacy migration and
/// every unrelated managed-tree or registration mutator. Only the exact
/// external Installer admitted above can resume the authenticated journal.
/// </summary>
internal static class EnterpriseLegacyMigrationBarrier
{
    public static void RequireNoActiveMigrationForUnrelatedOperation(
        EnterpriseInstallationLayout layout)
    {
        ArgumentNullException.ThrowIfNull(layout);
        var store = new EnterpriseLegacyMigrationJournalStore(layout);
        if (store.HasActiveJournal())
        {
            throw new InvalidOperationException(
                "An authenticated Enterprise legacy migration is incomplete. "
                + "Resume it with the exact external signed Installer before "
                + "updating, repairing, rolling back, health-committing, or uninstalling.");
        }
    }
}
