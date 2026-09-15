using System.Runtime.InteropServices;
using System.Reflection;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.UpdateEngine;

public sealed class PersonalInstallationLayout
{
    public const string StartupStubExecutableName = "Ensou.Dsh.Bootstrapper.exe";
    public const string ClientBootstrapperExecutableName = "Ensou.Dsh.ClientBootstrapper.exe";
    public const string LauncherExecutableName = "Ensou.Dsh.Launcher.exe";
    public const string MaintenanceExecutableName = "Ensou.Dsh.Personal.Maintenance.exe";

    public PersonalInstallationLayout(
        string managedRoot,
        string harnessHome,
        string? updateSecurityWitnessPath = null)
    {
        ManagedRoot = PersonalPathGuard.NormalizeDirectory(managedRoot);
        HarnessHome = PersonalPathGuard.NormalizeDirectory(harnessHome);
        if (PersonalPathGuard.IsSameOrDescendant(ManagedRoot, HarnessHome)
            || PersonalPathGuard.IsSameOrDescendant(HarnessHome, ManagedRoot))
        {
            throw new InvalidDataException(
                "Personal managed binaries and Harness home must not overlap.");
        }

        ClientBundleVersionsRoot = Path.Combine(ManagedRoot, "client-bundle-versions");
        LegacyLauncherVersionsRoot = Path.Combine(ManagedRoot, "launcher-versions");
        RuntimeVersionsRoot = Path.Combine(ManagedRoot, "runtimes");
        StateRoot = Path.Combine(ManagedRoot, "state");
        PackageRoot = Path.Combine(ManagedRoot, "packages");
        PartialCacheRoot = Path.Combine(PackageRoot, "update-partials-v2");
        var managedParent = Path.GetDirectoryName(ManagedRoot)
            ?? throw new InvalidDataException("Personal managed root has no parent directory.");
        UpdateOperationLockRoot = Path.Combine(managedParent, ".DshLauncherLocks");
        UpdateOperationLockPath = Path.Combine(
            UpdateOperationLockRoot,
            "managed-update-operation.v1.lock");
        if (PersonalPathGuard.IsSameOrDescendant(UpdateOperationLockRoot, ManagedRoot)
            || PersonalPathGuard.IsSameOrDescendant(ManagedRoot, UpdateOperationLockRoot)
            || PersonalPathGuard.IsSameOrDescendant(UpdateOperationLockRoot, HarnessHome)
            || PersonalPathGuard.IsSameOrDescendant(HarnessHome, UpdateOperationLockRoot))
        {
            throw new InvalidDataException(
                "Personal update operation locks must be independent from program and user data roots.");
        }
        HealthSignalRoot = Path.Combine(StateRoot, "health-signals-v2");
        ReleaseSetPointerPath = Path.Combine(StateRoot, "personal-release-set-current.v2.json");
        InstallationIdentityReceiptPath = Path.Combine(
            StateRoot,
            "personal-installation-identity.v1.json");
        InstallationIdentityProtectedPath = Path.Combine(
            StateRoot,
            "personal-installation-identity.v1.dpapi");
        LegacyLauncherPointerPath = Path.Combine(StateRoot, "current.json");
        LegacyRuntimePointerPath = Path.Combine(StateRoot, "runtime-current.json");
        UpdateSecurityStatePath = Path.Combine(StateRoot, "personal-update-security.v2.dpapi");
        UpdateSecurityWitnessPath = PersonalPathGuard.NormalizeFilePath(
            updateSecurityWitnessPath
                ?? PersonalV2MigrationFootprintStore.DeriveIndependentWitnessPath(
                    ManagedRoot,
                    UpdateSecurityStatePath));
        if (PersonalPathGuard.IsSameOrDescendant(
                UpdateSecurityWitnessPath,
                ManagedRoot)
            || PersonalPathGuard.IsSameOrDescendant(
                UpdateSecurityWitnessPath,
                HarnessHome))
        {
            throw new InvalidDataException(
                "Personal update security witness must be independent from managed binaries and Harness user data.");
        }
        V2MigrationFootprintPath = PersonalV2MigrationFootprintStore.DerivePath(
            UpdateSecurityStatePath,
            UpdateSecurityWitnessPath);
        if (PersonalPathGuard.IsSameOrDescendant(
                V2MigrationFootprintPath,
                ManagedRoot)
            || PersonalPathGuard.IsSameOrDescendant(
                V2MigrationFootprintPath,
                HarnessHome))
        {
            throw new InvalidDataException(
                "Personal v2 migration footprint must be independent from managed binaries and Harness user data.");
        }
        StartupStubPath = Path.Combine(ManagedRoot, StartupStubExecutableName);
        LegacyColocatedLauncherPath = Path.Combine(ManagedRoot, LauncherExecutableName);

        var homeParent = Path.GetDirectoryName(HarnessHome)
            ?? throw new InvalidDataException("Personal Harness home has no parent directory.");
        HarnessRecoveryRoot = Path.Combine(
            homeParent,
            $".{Path.GetFileName(HarnessHome)}.ensou-recovery");
        if (!string.Equals(
                Path.GetPathRoot(HarnessHome),
                Path.GetPathRoot(HarnessRecoveryRoot),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Personal Harness home and recovery root must share one volume.");
        }
    }

    public string ManagedRoot { get; }

    public string HarnessHome { get; }

    public string HarnessRecoveryRoot { get; }

    public string ClientBundleVersionsRoot { get; }

    public string LegacyLauncherVersionsRoot { get; }

    public string RuntimeVersionsRoot { get; }

    public string StateRoot { get; }

    public string PackageRoot { get; }

    public string PartialCacheRoot { get; }

    public string UpdateOperationLockRoot { get; }

    public string UpdateOperationLockPath { get; }

    public string HealthSignalRoot { get; }

    public string ReleaseSetPointerPath { get; }

    public string InstallationIdentityReceiptPath { get; }

    public string InstallationIdentityProtectedPath { get; }

    public string LegacyLauncherPointerPath { get; }

    public string LegacyRuntimePointerPath { get; }

    public string UpdateSecurityStatePath { get; }

    public string UpdateSecurityWitnessPath { get; }

    public string V2MigrationFootprintPath { get; }

    public string StartupStubPath { get; }

    public string LegacyColocatedLauncherPath { get; }

    public static PersonalInstallationLayout CreateDefault()
    {
        var localAppData = Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData);
        var roamingAppData = Environment.GetFolderPath(
            Environment.SpecialFolder.ApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return new PersonalInstallationLayout(
            Path.Combine(localAppData, "Ensou", "DshLauncher"),
            Path.Combine(userProfile, ".dsh"),
            Path.Combine(
                roamingAppData,
                "Ensou",
                "DshLauncherSecurity",
                "personal-update-security.v2.witness.dpapi"));
    }

    /// <summary>
    /// Creates the only non-default Personal layout accepted by the compiled
    /// development E2E lane. This deliberately does not create directories:
    /// admission must happen before any install side effect.
    /// </summary>
    public static PersonalInstallationLayout CreateDevelopmentE2E(
        string managedRoot,
        string harnessHome,
        string updateSecurityWitnessPath) =>
        new(
            PersonalDevelopmentE2ELayoutArguments.RequireCanonicalLocalPath(
                managedRoot,
                "managed root",
                directory: true),
            PersonalDevelopmentE2ELayoutArguments.RequireCanonicalLocalPath(
                harnessHome,
                "Harness home",
                directory: true),
            PersonalDevelopmentE2ELayoutArguments.RequireCanonicalLocalPath(
                updateSecurityWitnessPath,
                "update-security witness",
                directory: false));

    public string GetClientBundleDirectory(string releaseId)
    {
        PersonalPathGuard.ValidateReleaseId(releaseId);
        return PersonalPathGuard.CombineExactChild(ClientBundleVersionsRoot, releaseId);
    }

    public string GetRuntimeDirectory(string releaseId)
    {
        PersonalPathGuard.ValidateReleaseId(releaseId);
        return PersonalPathGuard.CombineExactChild(RuntimeVersionsRoot, releaseId);
    }

    public void EnsureManagedRoots()
    {
        PersonalPathGuard.EnsureDirectoryChain(ManagedRoot, ClientBundleVersionsRoot);
        PersonalPathGuard.EnsureDirectoryChain(ManagedRoot, LegacyLauncherVersionsRoot);
        PersonalPathGuard.EnsureDirectoryChain(ManagedRoot, RuntimeVersionsRoot);
        PersonalPathGuard.EnsureDirectoryChain(ManagedRoot, StateRoot);
        PersonalPathGuard.EnsureDirectoryChain(ManagedRoot, PackageRoot);
        PersonalPathGuard.EnsureDirectoryChain(PackageRoot, PartialCacheRoot);
        PersonalPathGuard.EnsureDirectoryChain(StateRoot, HealthSignalRoot);
        EnsureUpdateOperationLockRoot();
        PersonalPathGuard.EnsureIndependentDirectory(
            Path.GetDirectoryName(UpdateSecurityWitnessPath)
                ?? throw new InvalidDataException(
                    "Personal update security witness has no parent directory."));
        PersonalPathGuard.EnsureIndependentDirectory(
            Path.GetDirectoryName(V2MigrationFootprintPath)
                ?? throw new InvalidDataException(
                    "Personal v2 migration footprint has no parent directory."));
    }

    public void EnsureUpdateOperationLockRoot() =>
        PersonalPathGuard.EnsureIndependentDirectory(UpdateOperationLockRoot);
}

/// <summary>
/// An explicit, process-forwarded development-only layout envelope. It is not
/// environment-derived, so Windows Known Folders cannot redirect an install or
/// health child back into the caller's real profile.
/// </summary>
public sealed class PersonalDevelopmentE2ELayoutArguments
{
    public const string LayoutArgument = "--dev-e2e-layout";
    public const string ManagedRootArgument = "--dev-managed-root";
    public const string HarnessHomeArgument = "--dev-harness-home";
    public const string UpdateSecurityWitnessArgument = "--dev-update-security-witness";
    private const string MetadataKey = "PersonalDevelopmentE2E";

    private PersonalDevelopmentE2ELayoutArguments(PersonalInstallationLayout layout)
    {
        Layout = layout;
    }

    public PersonalInstallationLayout Layout { get; }

    public static bool IsIntent(IReadOnlyList<string> args) => args.Any(argument =>
        string.Equals(argument, LayoutArgument, StringComparison.Ordinal)
        || string.Equals(argument, ManagedRootArgument, StringComparison.Ordinal)
        || string.Equals(argument, HarnessHomeArgument, StringComparison.Ordinal)
        || string.Equals(argument, UpdateSecurityWitnessArgument, StringComparison.Ordinal));

    public static bool IsCompiled(Assembly assembly)
    {
        var values = assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .Where(attribute => string.Equals(
                attribute.Key,
                MetadataKey,
                StringComparison.Ordinal))
            .Select(attribute => attribute.Value)
            .ToArray();
        if (values.Length != 1)
        {
            throw new InvalidDataException(
                "Personal development E2E compilation metadata is missing or ambiguous.");
        }
        return string.Equals(values[0], "true", StringComparison.Ordinal);
    }

    public static PersonalDevelopmentE2ELayoutArguments Create(
        string managedRoot,
        string harnessHome,
        string updateSecurityWitnessPath) =>
        new(PersonalInstallationLayout.CreateDevelopmentE2E(
            managedRoot,
            harnessHome,
            updateSecurityWitnessPath));

    /// <summary>Strips one exact envelope and retains the process command.</summary>
    public static PersonalDevelopmentE2ELayoutArguments? ParseAndStrip(
        IReadOnlyList<string> arguments,
        bool developmentE2ECompiled,
        out string[] commandArguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        if (!IsIntent(arguments))
        {
            commandArguments = arguments.ToArray();
            return null;
        }
        if (!developmentE2ECompiled)
        {
            throw new InvalidOperationException(
                "Personal development E2E arguments are unavailable in this compiled binary.");
        }

        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var retained = new List<string>();
        var layoutCount = 0;
        for (var index = 0; index < arguments.Count; index++)
        {
            var argument = arguments[index];
            if (string.Equals(argument, LayoutArgument, StringComparison.Ordinal))
            {
                layoutCount++;
                continue;
            }
            if (argument is ManagedRootArgument or HarnessHomeArgument or UpdateSecurityWitnessArgument)
            {
                if (index + 1 >= arguments.Count
                    || !values.TryAdd(argument, arguments[++index]))
                {
                    throw new ArgumentException(
                        "Personal development E2E layout arguments must occur exactly once.");
                }
                continue;
            }
            retained.Add(argument);
        }
        if (layoutCount != 1
            || values.Count != 3
            || !values.TryGetValue(ManagedRootArgument, out var managedRoot)
            || !values.TryGetValue(HarnessHomeArgument, out var harnessHome)
            || !values.TryGetValue(UpdateSecurityWitnessArgument, out var witnessPath))
        {
            throw new ArgumentException(
                "Personal development E2E layout requires one explicit managed root, Harness home, and update-security witness.");
        }
        commandArguments = retained.ToArray();
        return Create(managedRoot, harnessHome, witnessPath);
    }

    public IEnumerable<string> ToArguments()
    {
        yield return LayoutArgument;
        yield return ManagedRootArgument;
        yield return Layout.ManagedRoot;
        yield return HarnessHomeArgument;
        yield return Layout.HarnessHome;
        yield return UpdateSecurityWitnessArgument;
        yield return Layout.UpdateSecurityWitnessPath;
    }

    internal static string RequireCanonicalLocalPath(
        string path,
        string label,
        bool directory)
    {
        if (string.IsNullOrWhiteSpace(path)
            || path.StartsWith("\\\\", StringComparison.Ordinal)
            || path.StartsWith("//", StringComparison.Ordinal)
            || !Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException(
                $"Personal development {label} must be one absolute local path.");
        }
        var normalized = directory
            ? Path.TrimEndingDirectorySeparator(Path.GetFullPath(path))
            : Path.GetFullPath(path);
        if (!string.Equals(normalized, path, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"Personal development {label} must be canonical.");
        }
        var start = directory
            ? new DirectoryInfo(normalized)
            : new DirectoryInfo(Path.GetDirectoryName(normalized)
                ?? throw new InvalidDataException(
                    $"Personal development {label} has no parent directory."));
        for (var current = start; current is not null; current = current.Parent)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    $"Personal development {label} crosses a filesystem link.");
            }
        }
        return normalized;
    }
}

internal static class PersonalPathGuard
{
    public static string NormalizeFilePath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.GetFullPath(path);
        var parent = Path.GetDirectoryName(fullPath)
            ?? throw new InvalidDataException("Personal managed file path has no parent.");
        _ = NormalizeDirectory(parent);
        return fullPath;
    }

    public static string NormalizeDirectory(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path)
            || path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                .Any(segment => segment == ".."))
        {
            throw new InvalidDataException("Personal managed paths must be absolute and canonical.");
        }
        var normalized = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        var root = Path.TrimEndingDirectorySeparator(Path.GetPathRoot(normalized) ?? string.Empty);
        if (string.IsNullOrWhiteSpace(root)
            || string.Equals(normalized, root, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Personal managed paths must not be a volume root.");
        }
        return normalized;
    }

    public static void ValidateReleaseId(string releaseId) =>
        Ensou.Dsh.Contracts.PersonalReleaseSetValidator.ValidateReleaseId(
            releaseId,
            "personal installed releaseId");

    public static string CombineExactChild(string root, string child)
    {
        ValidateReleaseId(child);
        var normalizedRoot = NormalizeDirectory(root);
        var result = Path.GetFullPath(Path.Combine(normalizedRoot, child));
        if (!IsStrictDescendant(result, normalizedRoot)
            || !string.Equals(Path.GetFileName(result), child, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Personal release path escaped its version root.");
        }
        return result;
    }

    public static void EnsureDirectoryChain(string root, string directory)
    {
        var normalizedRoot = NormalizeDirectory(root);
        var normalizedDirectory = NormalizeDirectory(directory);
        if (!IsSameOrDescendant(normalizedDirectory, normalizedRoot))
        {
            throw new InvalidDataException("Personal directory escaped its managed root.");
        }
        Directory.CreateDirectory(normalizedDirectory);
        RejectReparseChain(normalizedDirectory, normalizedRoot);
    }

    public static void EnsureIndependentDirectory(string directory)
    {
        var normalized = NormalizeDirectory(directory);
        Directory.CreateDirectory(normalized);
        for (var current = new DirectoryInfo(normalized);
             current is not null;
             current = current.Parent)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Personal independent directory crosses a filesystem link.");
            }
        }
    }

    public static void ValidateSafeTree(string directory, string managedRoot)
    {
        var root = NormalizeDirectory(managedRoot);
        var candidate = NormalizeDirectory(directory);
        if (!Directory.Exists(candidate) || !IsStrictDescendant(candidate, root))
        {
            throw new InvalidDataException("Personal installed tree escaped its managed root.");
        }
        RejectReparseChain(candidate, root);
        foreach (var entry in Directory.EnumerateFileSystemEntries(
                     candidate,
                     "*",
                     SearchOption.AllDirectories))
        {
            if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Personal installed trees must not contain filesystem links.");
            }
            if (File.Exists(entry))
            {
                RequireSingleLinkFile(entry);
            }
        }
    }

    public static void RequireSingleLinkFile(string path)
    {
        var absolutePath = Path.GetFullPath(path);
        if (!File.Exists(absolutePath)
            || (File.GetAttributes(absolutePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Personal managed file is missing or is a filesystem link.");
        }
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        using var handle = File.OpenHandle(
            absolutePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read);
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw new IOException(
                "Unable to read the personal managed file link count.",
                Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error()));
        }
        if (information.NumberOfLinks != 1)
        {
            throw new InvalidDataException(
                "Personal managed files must not be shared through external hard links.");
        }
    }

    public static bool IsSameOrDescendant(string candidate, string root)
    {
        var normalizedCandidate = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate));
        var normalizedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        return string.Equals(normalizedCandidate, normalizedRoot, StringComparison.OrdinalIgnoreCase)
            || normalizedCandidate.StartsWith(
                normalizedRoot + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsStrictDescendant(string candidate, string root) =>
        !string.Equals(
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate)),
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)),
            StringComparison.OrdinalIgnoreCase)
        && IsSameOrDescendant(candidate, root);

    private static void RejectReparseChain(string path, string stopAt)
    {
        var current = new DirectoryInfo(path);
        var stop = NormalizeDirectory(stopAt);
        while (true)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Personal managed path crosses a filesystem link.");
            }
            if (string.Equals(
                    Path.TrimEndingDirectorySeparator(current.FullName),
                    stop,
                    StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
            current = current.Parent
                ?? throw new InvalidDataException(
                    "Personal managed path did not reach its expected root.");
        }
    }

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
