using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Ensou.Dsh.Contracts;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.UpdateEngine;

public sealed class PersonalBinaryRepairRequiresInstallerException : IOException
{
    private const string RequiredAction =
        " Binary repair requires the original Authenticode-signed Ensou installer; "
        + "offline shell repair never replaces program binaries.";

    public PersonalBinaryRepairRequiresInstallerException(string message)
        : base(message + RequiredAction)
    {
    }

    public PersonalBinaryRepairRequiresInstallerException(
        string message,
        Exception innerException)
        : base(message + RequiredAction, innerException)
    {
    }
}

public static class PersonalMaintenanceIntegrity
{
    private static readonly string[] RequiredClientExecutables =
    [
        PersonalInstallationLayout.ClientBootstrapperExecutableName,
        PersonalInstallationLayout.LauncherExecutableName,
        PersonalInstallationLayout.MaintenanceExecutableName,
    ];

    public static string RequireActiveMaintenanceExecutable(
        PersonalInstallationLayout layout,
        PersonalInstalledReleaseSetReference current) =>
        RequireActiveClientBundle(layout, current)[2];

    public static PersonalTrustedExecutableLaunchLease
        AcquireActiveMaintenanceExecutableLaunchLease(
            PersonalInstallationLayout layout,
            PersonalInstalledReleaseSetReference current,
            PersonalCompiledTrustFingerprint expectedTrust)
    {
        ArgumentNullException.ThrowIfNull(expectedTrust);
        return AcquireActiveMaintenanceExecutableLaunchLeaseCore(
            layout,
            current,
            (path, verifyWhileExecutableLocked) =>
                PersonalCompiledTrustProcessVerifier
                    .AcquireExecutableLaunchLeaseWithAdmission(
                        path,
                        PersonalInstallationLayout.MaintenanceExecutableName,
                        expectedTrust,
                        verifyWhileExecutableLocked));
    }

    internal static PersonalTrustedExecutableLaunchLease
        AcquireActiveMaintenanceExecutableLaunchLeaseForTests(
            PersonalInstallationLayout layout,
            PersonalInstalledReleaseSetReference current,
            Func<string, Action, PersonalTrustedExecutableLaunchLease>
                acquireExecutable) =>
        AcquireActiveMaintenanceExecutableLaunchLeaseCore(
            layout,
            current,
            acquireExecutable);

    private static PersonalTrustedExecutableLaunchLease
        AcquireActiveMaintenanceExecutableLaunchLeaseCore(
            PersonalInstallationLayout layout,
            PersonalInstalledReleaseSetReference current,
            Func<string, Action, PersonalTrustedExecutableLaunchLease>
                acquireExecutable)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(acquireExecutable);
        var maintenancePath = Path.GetFullPath(Path.Combine(
            layout.GetClientBundleDirectory(current.ClientBundle.ReleaseId),
            PersonalInstallationLayout.MaintenanceExecutableName));
        var verificationCount = 0;
        var lease = acquireExecutable(
            maintenancePath,
            () =>
            {
                if (Interlocked.Increment(ref verificationCount) != 1)
                {
                    throw new InvalidOperationException(
                        "Personal Maintenance locked launch admission ran more than once.");
                }
                var admittedPath = RequireActiveMaintenanceExecutable(layout, current);
                if (!string.Equals(
                        Path.GetFullPath(admittedPath),
                        maintenancePath,
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new PersonalBinaryRepairRequiresInstallerException(
                        "The admitted personal Maintenance path changed during its locked launch admission.");
                }
            })
            ?? throw new InvalidOperationException(
                "Personal Maintenance locked launch admission returned no executable lease.");
        if (Volatile.Read(ref verificationCount) == 1)
        {
            return lease;
        }
        lease.Dispose();
        throw new InvalidOperationException(
            "Personal Maintenance complete-tree admission did not run while its executable was locked.");
    }

    public static IReadOnlyList<string> RequireActiveClientBundle(
        PersonalInstallationLayout layout,
        PersonalInstalledReleaseSetReference current)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(current);
        try
        {
            var expectedDirectory = layout.GetClientBundleDirectory(
                current.ClientBundle.ReleaseId);
            if (!string.Equals(
                    PersonalPathGuard.NormalizeDirectory(current.ClientBundle.Directory),
                    expectedDirectory,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "The active client-bundle directory is outside its immutable version root.");
            }
            PersonalPathGuard.ValidateSafeTree(expectedDirectory, layout.ManagedRoot);
            PersonalReleaseArtifactInstaller.VerifyInstalledComponentTree(
                expectedDirectory,
                PersonalReleaseSetContract.ClientBundleComponent,
                current.ClientBundle.ReleaseId,
                current.ClientBundle.CompleteTreeSha256);

            var paths = RequiredClientExecutables
                .Select(fileName => Path.GetFullPath(Path.Combine(expectedDirectory, fileName)))
                .ToArray();
            foreach (var path in paths)
            {
                if (!PersonalPathGuard.IsStrictDescendant(path, expectedDirectory)
                    || !File.Exists(path)
                    || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                {
                    throw new InvalidDataException(
                        "The active client-bundle is missing a required executable or contains a link.");
                }
                PersonalAuthenticodeVerifier.RequireTrustedEnsouExecutable(path);
            }
            return paths;
        }
        catch (PersonalBinaryRepairRequiresInstallerException)
        {
            throw;
        }
        catch (Exception exception) when (exception is InvalidDataException
            or InvalidOperationException
            or IOException
            or UnauthorizedAccessException)
        {
            throw new PersonalBinaryRepairRequiresInstallerException(
                "The installed personal client-bundle failed complete-tree or Authenticode validation.",
                exception);
        }
    }

    public static void RequireExactActiveMaintenanceProcess(
        PersonalInstallationLayout layout,
        PersonalInstalledReleaseSetReference current,
        string processPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(processPath);
        var expected = RequireActiveMaintenanceExecutable(layout, current);
        if (!string.Equals(
                Path.GetFullPath(processPath),
                expected,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new PersonalBinaryRepairRequiresInstallerException(
                "The maintenance host is not running from the active immutable client-bundle.");
        }
    }
}

public sealed class PersonalMaintenanceOperations
{
    private readonly PersonalInstallationLayout _layout;
    private readonly PersonalWindowsRegistrationContext _registrationContext;
    private readonly Func<PersonalManagedProgramQuarantine, bool> _deleteQuarantine;

    public PersonalMaintenanceOperations(PersonalInstallationLayout layout)
        : this(layout, PersonalWindowsRegistrationContext.CreateDefault(), null)
    {
    }

    internal PersonalMaintenanceOperations(
        PersonalInstallationLayout layout,
        PersonalWindowsRegistrationContext registrationContext,
        Func<PersonalManagedProgramQuarantine, bool>? deleteQuarantine = null)
    {
        _layout = layout ?? throw new ArgumentNullException(nameof(layout));
        _registrationContext = registrationContext
            ?? throw new ArgumentNullException(nameof(registrationContext));
        _deleteQuarantine = deleteQuarantine ?? TryDeleteQuarantine;
    }

    public PersonalWindowsRegistrationSnapshot RepairShell(string processPath)
    {
        var pointer = ReadRequiredForMaintenance();
        PersonalMaintenanceIntegrity.RequireExactActiveMaintenanceProcess(
            _layout,
            pointer.Current,
            processPath);
        return PersonalWindowsRegistration.Install(
            _layout,
            pointer.Current.ReleaseSetId,
            _registrationContext);
    }

    public string RequireSafeUninstallSource(string processPath)
    {
        var pointer = ReadRequiredForMaintenance();
        PersonalMaintenanceIntegrity.RequireExactActiveMaintenanceProcess(
            _layout,
            pointer.Current,
            processPath);
        return ComputeSha256(processPath);
    }

    public void RequireDetachedUninstallWorker(
        string detachedProcessPath,
        string expectedActiveMaintenanceSha256)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(detachedProcessPath);
        if (!PersonalReleaseSetValidator.IsSha256(expectedActiveMaintenanceSha256))
        {
            throw new InvalidDataException(
                "Detached personal uninstall worker hash is invalid.");
        }
        var pointer = ReadRequiredForMaintenance();
        var activePath = PersonalMaintenanceIntegrity.RequireActiveMaintenanceExecutable(
            _layout,
            pointer.Current);
        var activeHash = ComputeSha256(activePath);
        var detachedHash = ComputeSha256(detachedProcessPath);
        if (!FixedHashEquals(activeHash, expectedActiveMaintenanceSha256)
            || !FixedHashEquals(activeHash, detachedHash))
        {
            throw new PersonalBinaryRepairRequiresInstallerException(
                "The detached uninstall worker does not match the active complete-tree Maintenance bytes.");
        }
        PersonalPathGuard.RequireSingleLinkFile(detachedProcessPath);
        PersonalAuthenticodeVerifier.RequireTrustedEnsouExecutable(detachedProcessPath);
    }

    public PersonalManagedProgramQuarantine? QuarantineManagedProgramFiles()
    {
        if (!Directory.Exists(_layout.ManagedRoot))
        {
            return null;
        }
        RequireIndependentDataBoundary();
        ValidateSafeDeletionTree(_layout.ManagedRoot);
        RejectRunningManagedProcesses(_layout.ManagedRoot);

        var parent = Path.GetDirectoryName(_layout.ManagedRoot)
            ?? throw new InvalidDataException(
                "Personal managed program root has no parent directory.");
        var leaf = Path.GetFileName(_layout.ManagedRoot);
        var quarantinePath = Path.Combine(
            parent,
            $".{leaf}.uninstall-quarantine-{Guid.NewGuid():N}");
        ValidateQuarantinePath(quarantinePath);
        if (File.Exists(quarantinePath) || Directory.Exists(quarantinePath))
        {
            throw new IOException(
                "Personal uninstall quarantine already exists unexpectedly.");
        }

        using (var lease = PersonalManagedTreeRenameLease.Acquire(_layout.ManagedRoot))
        {
            ValidateSafeDeletionTree(_layout.ManagedRoot);
            RejectRunningManagedProcesses(_layout.ManagedRoot);
        }
        // Windows does not permit renaming a parent directory while descendant
        // delete-probe handles are retained. The immediately preceding lease
        // proves every descendant can be delete-opened; the atomic rename remains
        // the commit point and fails before shell registration changes if a new
        // incompatible handle wins this narrow boundary race.
        Directory.Move(_layout.ManagedRoot, quarantinePath);
        if (Directory.Exists(_layout.ManagedRoot)
            || !Directory.Exists(quarantinePath))
        {
            throw new IOException(
                "Personal managed program quarantine rename did not commit atomically.");
        }
        ValidateSafeDeletionTree(quarantinePath);
        return new PersonalManagedProgramQuarantine(quarantinePath);
    }

    public bool TryDeleteQuarantine(PersonalManagedProgramQuarantine quarantine)
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

    public void RestoreQuarantine(PersonalManagedProgramQuarantine quarantine)
    {
        ArgumentNullException.ThrowIfNull(quarantine);
        var path = ValidateQuarantinePath(quarantine.Directory);
        if (!Directory.Exists(path)
            || Directory.Exists(_layout.ManagedRoot)
            || File.Exists(_layout.ManagedRoot))
        {
            throw new IOException(
                "Personal uninstall quarantine cannot be restored safely.");
        }
        ValidateSafeDeletionTree(path);
        Directory.Move(path, _layout.ManagedRoot);
        if (!Directory.Exists(_layout.ManagedRoot) || Directory.Exists(path))
        {
            throw new IOException(
                "Personal uninstall quarantine restore did not commit atomically.");
        }
    }

    internal void RemoveWindowsRegistration() =>
        PersonalWindowsRegistration.Remove(_layout, _registrationContext);

    public PersonalUninstallCommitResult CommitQuarantinedUninstall(
        PersonalManagedProgramQuarantine? quarantine)
    {
        try
        {
            PersonalWindowsRegistration.Remove(_layout, _registrationContext);
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
                    "Personal uninstall registration failed and its full rollback could not be certified.",
                    removalFailure,
                    restoreFailure);
            }
            throw;
        }

        var quarantineDeleted = quarantine is null || _deleteQuarantine(quarantine);
        return new PersonalUninstallCommitResult(
            ActiveInstallationRemoved: true,
            QuarantineDeleted: quarantineDeleted);
    }

    private PersonalInstalledReleaseSetPointer ReadRequiredForMaintenance()
    {
        try
        {
            return new PersonalReleaseSetPointerStore(_layout).ReadRequired();
        }
        catch (PersonalBinaryRepairRequiresInstallerException)
        {
            throw;
        }
        catch (Exception exception) when (exception is InvalidDataException
            or InvalidOperationException
            or IOException
            or UnauthorizedAccessException)
        {
            throw new PersonalBinaryRepairRequiresInstallerException(
                "The installed release cannot authorize offline shell maintenance.",
                exception);
        }
    }

    private void RestoreWindowsRegistrationFromAuthenticatedPointer()
    {
        var pointer = ReadRequiredForMaintenance();
        _ = PersonalMaintenanceIntegrity.RequireActiveClientBundle(
            _layout,
            pointer.Current);
        _ = PersonalWindowsRegistration.Install(
            _layout,
            pointer.Current.ReleaseSetId,
            _registrationContext);
    }

    private void RequireIndependentDataBoundary()
    {
        if (PersonalPathGuard.IsSameOrDescendant(
                _layout.HarnessHome,
                _layout.ManagedRoot)
            || PersonalPathGuard.IsSameOrDescendant(
                _layout.ManagedRoot,
                _layout.HarnessHome)
            || PersonalPathGuard.IsSameOrDescendant(
                _layout.HarnessRecoveryRoot,
                _layout.ManagedRoot)
            || PersonalPathGuard.IsSameOrDescendant(
                _layout.ManagedRoot,
                _layout.HarnessRecoveryRoot))
        {
            throw new InvalidDataException(
                "Personal Harness data/recovery and managed program files unexpectedly overlap.");
        }
    }

    private string ValidateQuarantinePath(string path)
    {
        var absolutePath = PersonalPathGuard.NormalizeDirectory(path);
        var parent = Path.GetDirectoryName(_layout.ManagedRoot)
            ?? throw new InvalidDataException(
                "Personal managed program root has no parent directory.");
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
                "Personal uninstall quarantine path is outside its exact sibling boundary.");
        }
        return absolutePath;
    }

    private static string ComputeSha256(string path)
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

    private static void RejectRunningManagedProcesses(string managedRoot)
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
                        && PersonalPathGuard.IsSameOrDescendant(executable, managedRoot))
                    {
                        throw new IOException(
                            $"A process is still running from the personal managed root: {process.Id}");
                    }
                    foreach (ProcessModule module in process.Modules)
                    {
                        if (PersonalPathGuard.IsSameOrDescendant(
                                module.FileName,
                                managedRoot))
                        {
                            throw new IOException(
                                $"A process still has a module loaded from the personal managed root: {process.Id}");
                        }
                    }
                }
                catch (Win32Exception)
                {
                    // Protected unrelated processes cannot load user-writable managed files.
                }
                catch (InvalidOperationException)
                {
                    // The process exited during enumeration.
                }
            }
        }
    }

    private static void ValidateSafeDeletionTree(string directory)
    {
        var root = PersonalPathGuard.NormalizeDirectory(directory);
        for (var current = new DirectoryInfo(root);
             current is not null;
             current = current.Parent)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Personal managed program path crosses a filesystem link.");
            }
        }
        foreach (var entry in Directory.EnumerateFileSystemEntries(
                     root,
                     "*",
                     SearchOption.AllDirectories))
        {
            if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Personal managed program tree contains a filesystem link.");
            }
        }
    }

    private sealed class PersonalManagedTreeRenameLease : IDisposable
    {
        private const uint GenericRead = 0x80000000;
        private const uint Delete = 0x00010000;
        private const uint ShareRead = 0x00000001;
        private const uint ShareWrite = 0x00000002;
        private const uint ShareDelete = 0x00000004;
        private const uint OpenExisting = 3;
        private const uint BackupSemantics = 0x02000000;
        private readonly List<SafeFileHandle> _handles;

        private PersonalManagedTreeRenameLease(List<SafeFileHandle> handles)
        {
            _handles = handles;
        }

        public static PersonalManagedTreeRenameLease Acquire(string root)
        {
            var paths = new List<(string Path, bool Directory)>();
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
                        entry.Path,
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
                            $"Personal managed program file is still open or cannot be delete-locked: {entry.Path}",
                            error);
                    }
                    handles.Add(handle);
                }
                return new PersonalManagedTreeRenameLease(handles);
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
    }
}

public sealed record PersonalManagedProgramQuarantine(string Directory);

public sealed record PersonalUninstallCommitResult(
    bool ActiveInstallationRemoved,
    bool QuarantineDeleted);
