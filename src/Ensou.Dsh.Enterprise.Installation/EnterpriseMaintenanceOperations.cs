using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.Enterprise.Installation;

public sealed record EnterpriseActiveMaintenanceBinding(
    string ReleaseSetId,
    string ClientBundleDirectory,
    string MaintenancePath,
    string MaintenanceSha256);

internal sealed record EnterpriseManagedProgramQuarantine(string Directory);

public sealed record EnterpriseUninstallCommitResult(
    bool ActiveInstallationRemoved,
    bool QuarantineDeleted);

public static class EnterpriseMaintenanceIntegrity
{
    private static readonly string[] RequiredClientExecutables =
    [
        EnterpriseInstallationLayout.LauncherExecutableName,
        EnterpriseInstallationLayout.ClientBootstrapperExecutableName,
        EnterpriseInstallationLayout.MaintenanceExecutableName,
    ];

    public static EnterpriseActiveMaintenanceBinding RequireActiveMaintenance(
        EnterpriseInstallationLayout layout)
    {
        ArgumentNullException.ThrowIfNull(layout);
        var pointer = new EnterpriseReleaseSetPointerStore(layout).ReadRequired();
        var current = pointer.Current;
        var expectedDirectory = layout.GetLauncherVersionDirectory(
            current.Launcher.ReleaseId);
        if (!string.Equals(
                EnterprisePathGuard.NormalizeDirectory(current.Launcher.Directory),
                expectedDirectory,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Enterprise Maintenance is not bound to the current authenticated client-bundle.");
        }

        EnterprisePathGuard.ValidateSafeTree(expectedDirectory, layout.ManagedRoot);
        RequireCurrentCompleteTree(layout, current, expectedDirectory);
        EnterpriseBuildProfileMarker.ReadAndValidate(
            Path.Combine(
                expectedDirectory,
                EnterpriseInstallationLayout.BuildProfileMarkerFileName),
            layout.LayoutProfile);

        var requiredPaths = RequiredClientExecutables
            .Select(fileName => Path.GetFullPath(Path.Combine(expectedDirectory, fileName)))
            .ToArray();
        foreach (var path in requiredPaths)
        {
            if (!EnterprisePathGuard.IsSameOrDescendant(path, expectedDirectory)
                || string.Equals(path, expectedDirectory, StringComparison.OrdinalIgnoreCase)
                || !File.Exists(path)
                || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "The current enterprise client-bundle is incomplete or linked.");
            }
            RequireSingleLinkFile(path);
            EnterpriseAuthenticodeVerifier.RequireTrustedSignature(path, layout);
        }

        var maintenancePath = requiredPaths[2];
        return new EnterpriseActiveMaintenanceBinding(
            current.ReleaseSetId,
            expectedDirectory,
            maintenancePath,
            ComputeSha256(maintenancePath));
    }

    public static string RequireExactActiveMaintenanceProcess(
        EnterpriseInstallationLayout layout,
        string processPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(processPath);
        var active = RequireActiveMaintenance(layout);
        if (!string.Equals(
                Path.GetFullPath(processPath),
                active.MaintenancePath,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Enterprise Maintenance is not running from the current authenticated client-bundle.");
        }
        return active.MaintenanceSha256;
    }

    public static string ComputeSha256(string path)
    {
        using var stream = new FileStream(
            Path.GetFullPath(path),
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.SequentialScan);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    internal static void RequireSingleLinkFile(string path)
    {
        using var handle = CreateFile(
            ToExtendedWindowsPath(path),
            GenericRead,
            ShareRead,
            IntPtr.Zero,
            OpenExisting,
            0,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            throw new IOException(
                "Unable to lock the enterprise executable identity.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw new IOException(
                "Unable to inspect the enterprise executable identity.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }
        if (information.NumberOfLinks != 1)
        {
            throw new InvalidDataException(
                "Enterprise executable identity must not have hard-link aliases.");
        }
    }

    internal static string ToExtendedWindowsPath(string path)
    {
        var absolutePath = Path.GetFullPath(path);
        return absolutePath.StartsWith("\\\\?\\", StringComparison.Ordinal)
            ? absolutePath
            : "\\\\?\\" + absolutePath;
    }

    private static void RequireCurrentCompleteTree(
        EnterpriseInstallationLayout layout,
        EnterpriseReleaseSetReference current,
        string directory)
    {
        var receiptPath = Path.Combine(directory, EnterpriseTreeHash.ReceiptFileName);
        EnterprisePathGuard.ValidateExistingPathWithin(
            receiptPath,
            layout.ManagedRoot,
            requireDirectory: false);
        var receipt = EnterprisePointerJson.Deserialize<EnterpriseReleaseArtifactReceiptV2>(
            File.ReadAllBytes(receiptPath));
        if (receipt.SchemaVersion != 2
            || !string.Equals(
                receipt.Component,
                EnterpriseReleaseSetContract.LauncherComponent,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.ReleaseId,
                current.Launcher.ReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.ArchiveSha256,
                current.Launcher.ArchiveSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.TreeSha256,
                current.Launcher.CompleteTreeSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                current.Launcher.CompleteTreeSha256,
                EnterpriseTreeHash.Compute(directory),
                StringComparison.Ordinal)
            || receipt.RuntimeFilesManifestSha256 is not null)
        {
            throw new InvalidDataException(
                "The current enterprise client-bundle complete tree is not authenticated.");
        }
    }

    private const uint GenericRead = 0x80000000;
    private const uint ShareRead = 0x00000001;
    private const uint OpenExisting = 3;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }
}

public sealed class EnterpriseMaintenanceOperations
{
    private const string WorkerRootName = "DshEnterpriseUninstall";
    private readonly EnterpriseInstallationLayout _layout;
    private readonly EnterpriseWindowsRegistrationContext _registrationContext;
    private readonly Func<EnterpriseManagedProgramQuarantine, bool> _deleteQuarantine;

    public EnterpriseMaintenanceOperations(EnterpriseInstallationLayout layout)
        : this(layout, EnterpriseWindowsRegistrationContext.CreateDefault(layout), null)
    {
    }

    internal EnterpriseMaintenanceOperations(
        EnterpriseInstallationLayout layout,
        EnterpriseWindowsRegistrationContext registrationContext,
        Func<EnterpriseManagedProgramQuarantine, bool>? deleteQuarantine = null)
    {
        _layout = layout ?? throw new ArgumentNullException(nameof(layout));
        _registrationContext = registrationContext
            ?? throw new ArgumentNullException(nameof(registrationContext));
        _deleteQuarantine = deleteQuarantine ?? TryDeleteQuarantine;
    }

    public EnterpriseWindowsRegistrationSnapshot RepairShell(
        string processPath,
        CancellationToken cancellationToken = default)
    {
        using var operationLease = EnterpriseManagedUpdateOperationLease
            .AcquireRequiredAsync(_layout, cancellationToken)
            .GetAwaiter()
            .GetResult();
        EnterpriseManagedOperationRecovery.RecoverInterruptedUnderLease(_layout);
        var active = EnterpriseMaintenanceIntegrity.RequireActiveMaintenance(_layout);
        if (!string.Equals(
                Path.GetFullPath(processPath),
                active.MaintenancePath,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Enterprise shell repair must run from the active Maintenance executable.");
        }
        EnterpriseStableBootstrapperVerifier.RequireTrusted(_layout);
        var rollbackContext = _registrationContext.WithoutObservers();
        var registrationSnapshot = EnterpriseWindowsRegistration.CaptureRollbackSnapshot(
            _layout,
            rollbackContext);
        var transaction = new EnterpriseInstallRollbackTransaction(
            _layout,
            rollbackContext,
            registrationSnapshot);
        try
        {
            var result = EnterpriseWindowsRegistration.Install(
                _layout,
                active.ReleaseSetId,
                developmentUnsignedPayload: _layout.IsDevelopmentE2E,
                _registrationContext);
            transaction.Commit();
            return result;
        }
        catch (Exception repairFailure)
        {
            try
            {
                transaction.Rollback();
            }
            catch (Exception rollbackFailure)
            {
                throw new AggregateException(
                    "Enterprise shell repair failed and registration rollback could not be certified.",
                    repairFailure,
                    rollbackFailure);
            }
            throw;
        }
    }

    public string RequireActiveMaintenanceSource(string processPath) =>
        EnterpriseMaintenanceIntegrity.RequireExactActiveMaintenanceProcess(
            _layout,
            processPath);

    public string RequireInstalledInstallerSource(string processPath)
    {
        _ = EnterpriseMaintenanceIntegrity.RequireActiveMaintenance(_layout);
        var absolutePath = Path.GetFullPath(processPath);
        if (!string.Equals(
                absolutePath,
                Path.GetFullPath(_layout.InstalledInstallerPath),
                StringComparison.OrdinalIgnoreCase)
            || !File.Exists(absolutePath)
            || (File.GetAttributes(absolutePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Installed enterprise Installer is not the exact managed Installer path.");
        }
        RejectLinkedAncestors(Path.GetDirectoryName(absolutePath)!);
        EnterpriseMaintenanceIntegrity.RequireSingleLinkFile(absolutePath);
        EnterpriseAuthenticodeVerifier.RequireTrustedSignature(absolutePath, _layout);
        return EnterpriseMaintenanceIntegrity.ComputeSha256(absolutePath);
    }

    public string RequireExternalInstallerSource(string processPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(processPath);
        var absolutePath = Path.GetFullPath(processPath);
        if (EnterprisePathGuard.IsSameOrDescendant(absolutePath, _layout.ManagedRoot)
            || !File.Exists(absolutePath)
            || (File.GetAttributes(absolutePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "External enterprise Installer must be an ordinary file outside ManagedRoot.");
        }
        RejectLinkedAncestors(Path.GetDirectoryName(absolutePath)!);
        EnterpriseMaintenanceIntegrity.RequireSingleLinkFile(absolutePath);
        EnterpriseAuthenticodeVerifier.RequireTrustedSignature(absolutePath, _layout);
        return EnterpriseMaintenanceIntegrity.ComputeSha256(absolutePath);
    }

    public void RequireDetachedMaintenanceWorker(
        string detachedProcessPath,
        string expectedActiveMaintenanceSha256)
    {
        RequireDetachedMaintenanceWorkerFile(
            detachedProcessPath,
            expectedActiveMaintenanceSha256);
        var active = EnterpriseMaintenanceIntegrity.RequireActiveMaintenance(_layout);
        if (!FixedHashEquals(active.MaintenanceSha256, expectedActiveMaintenanceSha256))
        {
            throw new InvalidDataException(
                "Detached enterprise Maintenance does not match the current active bytes.");
        }
    }

    private void RequireDetachedMaintenanceWorkerFile(
        string detachedProcessPath,
        string expectedActiveMaintenanceSha256)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(detachedProcessPath);
        if (!EnterpriseHash.IsSha256(expectedActiveMaintenanceSha256)
            || !string.Equals(
                expectedActiveMaintenanceSha256,
                expectedActiveMaintenanceSha256.ToLowerInvariant(),
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Detached enterprise Maintenance hash is invalid.");
        }
        RequireExactDetachedWorkerPath(
            detachedProcessPath,
            EnterpriseInstallationLayout.MaintenanceExecutableName);
        var detachedHash = EnterpriseMaintenanceIntegrity.ComputeSha256(detachedProcessPath);
        if (!FixedHashEquals(expectedActiveMaintenanceSha256, detachedHash))
        {
            throw new InvalidDataException(
                "Detached enterprise Maintenance does not match its admitted bytes.");
        }
        EnterpriseMaintenanceIntegrity.RequireSingleLinkFile(detachedProcessPath);
        EnterpriseAuthenticodeVerifier.RequireTrustedSignature(detachedProcessPath, _layout);
    }

    public EnterpriseUninstallCommitResult UninstallManagedProgramFiles(
        CancellationToken cancellationToken = default)
    {
        using var operationLease = EnterpriseManagedUpdateOperationLease
            .AcquireRequiredAsync(_layout, cancellationToken)
            .GetAwaiter()
            .GetResult();
        EnterpriseManagedOperationRecovery.RecoverInterruptedUnderLease(_layout);
        return UninstallManagedProgramFilesUnderLease();
    }

    public EnterpriseUninstallCommitResult UninstallFromDetachedWorker(
        string detachedProcessPath,
        string expectedActiveMaintenanceSha256,
        CancellationToken cancellationToken = default)
    {
        using var operationLease = EnterpriseManagedUpdateOperationLease
            .AcquireRequiredAsync(_layout, cancellationToken)
            .GetAwaiter()
            .GetResult();
        EnterpriseManagedOperationRecovery.RecoverInterruptedUnderLease(_layout);
        if (!Directory.Exists(_layout.ManagedRoot))
        {
            RequireDetachedMaintenanceWorkerFile(
                detachedProcessPath,
                expectedActiveMaintenanceSha256);
            EnterpriseWindowsRegistration.Remove(_layout, _registrationContext);
            return new EnterpriseUninstallCommitResult(
                ActiveInstallationRemoved: true,
                QuarantineDeleted: !EnterpriseUninstallRollbackTransaction
                    .HasPendingJournal(_layout));
        }
        RequireDetachedMaintenanceWorker(
            detachedProcessPath,
            expectedActiveMaintenanceSha256);
        return UninstallManagedProgramFilesUnderLease();
    }

    internal EnterpriseUninstallCommitResult UninstallManagedProgramFilesUnderLease()
    {
        if (!Directory.Exists(_layout.ManagedRoot))
        {
            EnterpriseWindowsRegistration.Remove(_layout, _registrationContext);
            return new EnterpriseUninstallCommitResult(
                ActiveInstallationRemoved: true,
                QuarantineDeleted: true);
        }

        var transaction = new EnterpriseUninstallRollbackTransaction(
            _layout,
            _registrationContext,
            _deleteQuarantine);
        try
        {
            _ = transaction.QuarantineManagedRoot();
            transaction.RemoveRegistration();
            transaction.Commit();
            var quarantineDeleted = transaction.CompleteCommittedCleanup();
            return new EnterpriseUninstallCommitResult(
                ActiveInstallationRemoved: true,
                QuarantineDeleted: quarantineDeleted);
        }
        catch (Exception uninstallFailure)
        {
            try
            {
                transaction.Rollback();
            }
            catch (Exception rollbackFailure)
            {
                throw new AggregateException(
                    "Enterprise uninstall failed and rollback could not be certified.",
                    uninstallFailure,
                    rollbackFailure);
            }
            throw;
        }
    }

    internal EnterpriseManagedProgramQuarantine? QuarantineManagedProgramFiles()
    {
        if (!Directory.Exists(_layout.ManagedRoot))
        {
            return null;
        }

        RequireIndependentDataBoundary();
        _ = EnterpriseMaintenanceIntegrity.RequireActiveMaintenance(_layout);
        EnterpriseStableBootstrapperVerifier.RequireTrusted(_layout);
        ValidateSafeDeletionTree(_layout.ManagedRoot);
        RejectRunningManagedProcesses(_layout.ManagedRoot);

        var parent = Path.GetDirectoryName(_layout.ManagedRoot)
            ?? throw new InvalidDataException(
                "Enterprise ManagedRoot has no parent directory.");
        var leaf = Path.GetFileName(_layout.ManagedRoot);
        var quarantinePath = Path.Combine(
            parent,
            $".{leaf}.uninstall-quarantine-{Guid.NewGuid():N}");
        ValidateQuarantinePath(quarantinePath);
        if (File.Exists(quarantinePath) || Directory.Exists(quarantinePath))
        {
            throw new IOException(
                "Enterprise uninstall quarantine already exists unexpectedly.");
        }

        using (var lease = EnterpriseManagedTreeRenameLease.Acquire(_layout.ManagedRoot))
        {
            ValidateSafeDeletionTree(_layout.ManagedRoot);
            RejectRunningManagedProcesses(_layout.ManagedRoot);
        }
        // Windows prevents renaming a parent while descendant delete-probe
        // handles remain open. The atomic sibling rename is therefore the
        // commit point: a new incompatible handle fails here before shell state
        // is changed.
        Directory.Move(_layout.ManagedRoot, quarantinePath);
        if (Directory.Exists(_layout.ManagedRoot)
            || !Directory.Exists(quarantinePath))
        {
            throw new IOException(
                "Enterprise uninstall quarantine rename did not commit atomically.");
        }
        ValidateSafeDeletionTree(quarantinePath);
        return new EnterpriseManagedProgramQuarantine(quarantinePath);
    }

    internal EnterpriseUninstallCommitResult CommitQuarantinedUninstall(
        EnterpriseManagedProgramQuarantine? quarantine)
    {
        try
        {
            EnterpriseWindowsRegistration.Remove(_layout, _registrationContext);
        }
        catch (Exception removalFailure)
        {
            if (quarantine is null)
            {
                throw;
            }
            try
            {
                RestoreQuarantine(quarantine);
                RestoreWindowsRegistrationFromAuthenticatedPointer();
            }
            catch (Exception restoreFailure)
            {
                throw new AggregateException(
                    "Enterprise uninstall registration failed and rollback could not be certified.",
                    removalFailure,
                    restoreFailure);
            }
            throw;
        }

        var quarantineDeleted = quarantine is null || _deleteQuarantine(quarantine);
        return new EnterpriseUninstallCommitResult(
            ActiveInstallationRemoved: true,
            QuarantineDeleted: quarantineDeleted);
    }

    internal bool TryDeleteQuarantine(EnterpriseManagedProgramQuarantine quarantine)
    {
        ArgumentNullException.ThrowIfNull(quarantine);
        var path = ValidateQuarantinePath(quarantine.Directory);
        if (!Directory.Exists(path))
        {
            return true;
        }
        ValidateSafeDeletionTree(path);
        try
        {
            Directory.Delete(path, recursive: true);
            return !Directory.Exists(path);
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    internal void RestoreQuarantine(EnterpriseManagedProgramQuarantine quarantine)
    {
        ArgumentNullException.ThrowIfNull(quarantine);
        var path = ValidateQuarantinePath(quarantine.Directory);
        if (!Directory.Exists(path)
            || Directory.Exists(_layout.ManagedRoot)
            || File.Exists(_layout.ManagedRoot))
        {
            throw new IOException(
                "Enterprise uninstall quarantine cannot be restored safely.");
        }
        ValidateSafeDeletionTree(path);
        Directory.Move(path, _layout.ManagedRoot);
        if (!Directory.Exists(_layout.ManagedRoot) || Directory.Exists(path))
        {
            throw new IOException(
                "Enterprise uninstall quarantine restore did not commit atomically.");
        }
    }

    public static string GetWorkerRoot() => Path.Combine(
        Path.GetTempPath(),
        "Ensou",
        WorkerRootName);

    public static void RequireExactDetachedWorkerPath(
        string processPath,
        string expectedExecutableName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(processPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedExecutableName);
        var absolutePath = Path.GetFullPath(processPath);
        var expectedRoot = EnterprisePathGuard.NormalizeDirectory(GetWorkerRoot());
        var parent = Path.GetDirectoryName(absolutePath)
            ?? throw new InvalidDataException(
                "Detached enterprise worker has no parent directory.");
        if (!string.Equals(
                Path.GetDirectoryName(parent),
                expectedRoot,
                StringComparison.OrdinalIgnoreCase)
            || !Guid.TryParseExact(Path.GetFileName(parent), "N", out _)
            || !string.Equals(
                Path.GetFileName(absolutePath),
                expectedExecutableName,
                StringComparison.Ordinal)
            || !File.Exists(absolutePath)
            || (File.GetAttributes(absolutePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Detached enterprise worker path is not the exact controlled Temp path.");
        }
        RejectLinkedAncestors(parent);
    }

    private void RestoreWindowsRegistrationFromAuthenticatedPointer()
    {
        var active = EnterpriseMaintenanceIntegrity.RequireActiveMaintenance(_layout);
        EnterpriseStableBootstrapperVerifier.RequireTrusted(_layout);
        _ = EnterpriseWindowsRegistration.Install(
            _layout,
            active.ReleaseSetId,
            developmentUnsignedPayload: _layout.IsDevelopmentE2E,
            _registrationContext);
    }

    private void RequireIndependentDataBoundary()
    {
        if (EnterprisePathGuard.IsSameOrDescendant(
                _layout.HarnessHome,
                _layout.ManagedRoot)
            || EnterprisePathGuard.IsSameOrDescendant(
                _layout.ManagedRoot,
                _layout.HarnessHome)
            || EnterprisePathGuard.IsSameOrDescendant(
                _layout.HarnessRecoveryRoot,
                _layout.ManagedRoot)
            || EnterprisePathGuard.IsSameOrDescendant(
                _layout.ManagedRoot,
                _layout.HarnessRecoveryRoot))
        {
            throw new InvalidDataException(
                "Enterprise Harness data/recovery overlaps managed program files.");
        }
    }

    private string ValidateQuarantinePath(string path)
    {
        var absolutePath = EnterprisePathGuard.NormalizeDirectory(path);
        var parent = Path.GetDirectoryName(_layout.ManagedRoot)
            ?? throw new InvalidDataException(
                "Enterprise ManagedRoot has no parent directory.");
        var prefix = $".{Path.GetFileName(_layout.ManagedRoot)}.uninstall-quarantine-";
        var suffix = Path.GetFileName(absolutePath);
        if (!string.Equals(
                Path.GetDirectoryName(absolutePath),
                parent,
                StringComparison.OrdinalIgnoreCase)
            || !suffix.StartsWith(prefix, StringComparison.Ordinal)
            || !Guid.TryParseExact(suffix[prefix.Length..], "N", out _))
        {
            throw new InvalidDataException(
                "Enterprise uninstall quarantine escaped its exact sibling boundary.");
        }
        return absolutePath;
    }

    private void ValidateSafeDeletionTree(string directory) =>
        EnterprisePathGuard.ValidateSafeTree(directory, _layout.LocalAppDataRoot);

    private static bool FixedHashEquals(string left, string right)
    {
        var leftBytes = Convert.FromHexString(left);
        var rightBytes = Convert.FromHexString(right);
        try
        {
            return leftBytes.Length == 32
                && rightBytes.Length == 32
                && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(leftBytes);
            CryptographicOperations.ZeroMemory(rightBytes);
        }
    }

    internal static void RejectRunningManagedProcesses(string managedRoot)
    {
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    if (process.Id == Environment.ProcessId)
                    {
                        continue;
                    }
                    if (process.MainModule?.FileName is { } executable
                        && EnterprisePathGuard.IsSameOrDescendant(
                            executable,
                            managedRoot))
                    {
                        throw new IOException(
                            $"An executable is still running from Enterprise ManagedRoot: {process.Id}");
                    }
                    foreach (ProcessModule module in process.Modules)
                    {
                        if (EnterprisePathGuard.IsSameOrDescendant(
                                module.FileName,
                                managedRoot))
                        {
                            throw new IOException(
                                $"A process still has a module loaded from Enterprise ManagedRoot: {process.Id}");
                        }
                    }
                }
                catch (Win32Exception)
                {
                    // Protected unrelated processes cannot load user-writable files.
                }
                catch (InvalidOperationException)
                {
                    // The process exited during enumeration.
                }
            }
        }
    }

    private static void RejectLinkedAncestors(string path)
    {
        for (var current = new DirectoryInfo(Path.GetFullPath(path));
             current is not null;
             current = current.Parent)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Enterprise maintenance path crosses a filesystem link.");
            }
        }
    }

    internal sealed class EnterpriseManagedTreeRenameLease : IDisposable
    {
        private const uint GenericRead = 0x80000000;
        private const uint Delete = 0x00010000;
        private const uint ShareRead = 0x00000001;
        private const uint ShareWrite = 0x00000002;
        private const uint ShareDelete = 0x00000004;
        private const uint OpenExisting = 3;
        private const uint BackupSemantics = 0x02000000;
        private readonly List<SafeFileHandle> _handles;

        private EnterpriseManagedTreeRenameLease(List<SafeFileHandle> handles)
        {
            _handles = handles;
        }

        public static EnterpriseManagedTreeRenameLease Acquire(string root)
        {
            var paths = new List<(string Path, bool Directory)> { (root, true) };
            paths.AddRange(Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories)
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .Select(path => (path, true)));
            paths.AddRange(Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .Select(path => (path, false)));

            var handles = new List<SafeFileHandle>(paths.Count);
            try
            {
                foreach (var entry in paths)
                {
                    var handle = CreateFile(
                        EnterpriseMaintenanceIntegrity.ToExtendedWindowsPath(entry.Path),
                        GenericRead | Delete,
                        ShareRead | ShareWrite | ShareDelete,
                        IntPtr.Zero,
                        OpenExisting,
                        entry.Directory ? BackupSemantics : 0,
                        IntPtr.Zero);
                    if (handle.IsInvalid)
                    {
                        var error = new Win32Exception(Marshal.GetLastWin32Error());
                        handle.Dispose();
                        throw new IOException(
                            $"Enterprise managed file is open or cannot be delete-locked: {entry.Path}",
                            error);
                    }
                    if (!entry.Directory)
                    {
                        if (!GetFileInformationByHandle(handle, out var information))
                        {
                            var error = new Win32Exception(Marshal.GetLastWin32Error());
                            handle.Dispose();
                            throw new IOException(
                                $"Enterprise managed file identity cannot be inspected: {entry.Path}",
                                error);
                        }
                        if (information.NumberOfLinks != 1)
                        {
                            handle.Dispose();
                            throw new InvalidDataException(
                                $"Enterprise managed file has a hard-link alias: {entry.Path}");
                        }
                    }
                    handles.Add(handle);
                }
                return new EnterpriseManagedTreeRenameLease(handles);
            }
            catch
            {
                foreach (var handle in handles)
                {
                    handle.Dispose();
                }
                throw;
            }
        }

        public void Dispose()
        {
            foreach (var handle in _handles)
            {
                handle.Dispose();
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out ByHandleFileInformation information);

        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }
    }
}
