using System.Text.RegularExpressions;

namespace Ensou.Dsh.Enterprise.Installation;

public sealed record EnterpriseInstallationLayout
{
    public const string ManagedRootName = "DshEnterpriseLauncher";
    public const string HarnessHomeName = ".dsh-enterprise";
    public const string DevelopmentE2EManagedRootName = "DshEnterpriseLauncherDevE2E";
    public const string DevelopmentE2EHarnessHomeName = ".dsh-enterprise-dev-e2e";
    public const string ProductionLayoutProfile = "enterprise";
    public const string DevelopmentE2ELayoutProfile = "development-e2e";
    public const string BuildProfileMarkerFileName = "enterprise-build-profile.json";
    public const string BootstrapperExecutableName = "Ensou.Dsh.Enterprise.Bootstrapper.exe";
    public const string ClientBootstrapperExecutableName =
        "Ensou.Dsh.Enterprise.ClientBootstrapper.exe";
    public const string MaintenanceExecutableName = "Ensou.Dsh.Enterprise.Maintenance.exe";
    public const string InstallerExecutableName = "Ensou.Dsh.Enterprise.Installer.exe";
    public const string LauncherExecutableName = "Ensou.Dsh.Enterprise.Launcher.exe";

    private EnterpriseInstallationLayout(
        string localAppDataRoot,
        string userProfileRoot,
        string managedRootName,
        string harnessHomeName,
        string layoutProfile,
        string? managedRootOverride = null)
    {
        LocalAppDataRoot = EnterprisePathGuard.NormalizeDirectory(localAppDataRoot);
        UserProfileRoot = EnterprisePathGuard.NormalizeDirectory(userProfileRoot);
        ManagedRoot = managedRootOverride is null
            ? Path.Combine(LocalAppDataRoot, "Ensou", managedRootName)
            : EnterprisePathGuard.NormalizeDirectory(managedRootOverride);
        HarnessHome = Path.Combine(UserProfileRoot, harnessHomeName);
        HarnessRecoveryRoot = Path.Combine(UserProfileRoot, $"{harnessHomeName}-recovery");
        LauncherVersionsRoot = Path.Combine(ManagedRoot, "launcher-versions");
        RuntimeVersionsRoot = Path.Combine(ManagedRoot, "runtimes");
        PluginPolicyVersionsRoot = Path.Combine(ManagedRoot, "plugins");
        StateRoot = Path.Combine(ManagedRoot, "state");
        PackageRoot = Path.Combine(ManagedRoot, "packages");
        UpdatePartialCacheRoot = Path.Combine(PackageRoot, "update-partials-v2");
        UpdateOperationLockRoot = Path.Combine(
            LocalAppDataRoot,
            "Ensou",
            ".DshEnterpriseLocks",
            layoutProfile);
        UpdateOperationLockPath = Path.Combine(
            UpdateOperationLockRoot,
            "managed-update-operation.v1.lock");
        UpdateReceiptRoot = Path.Combine(StateRoot, "update-receipts");
        HealthSignalRoot = Path.Combine(StateRoot, "health-signals");
        ReleaseSecurityWitnessRoot = Path.Combine(
            UserProfileRoot,
            ".ensou-dsh-enterprise-security",
            layoutProfile);
        BootstrapperPath = Path.Combine(ManagedRoot, BootstrapperExecutableName);
        InstalledInstallerPath = Path.Combine(ManagedRoot, InstallerExecutableName);
        BuildProfileMarkerPath = Path.Combine(ManagedRoot, BuildProfileMarkerFileName);
        LayoutProfile = layoutProfile;

        if (EnterprisePathGuard.IsSameOrDescendant(ManagedRoot, HarnessHome)
            || EnterprisePathGuard.IsSameOrDescendant(HarnessHome, ManagedRoot)
            || EnterprisePathGuard.IsSameOrDescendant(HarnessRecoveryRoot, HarnessHome)
            || EnterprisePathGuard.IsSameOrDescendant(HarnessHome, HarnessRecoveryRoot)
            || EnterprisePathGuard.IsSameOrDescendant(ManagedRoot, HarnessRecoveryRoot)
            || EnterprisePathGuard.IsSameOrDescendant(HarnessRecoveryRoot, ManagedRoot)
            || EnterprisePathGuard.IsSameOrDescendant(UpdateOperationLockRoot, ManagedRoot)
            || EnterprisePathGuard.IsSameOrDescendant(ManagedRoot, UpdateOperationLockRoot)
            || EnterprisePathGuard.IsSameOrDescendant(UpdateOperationLockRoot, HarnessHome)
            || EnterprisePathGuard.IsSameOrDescendant(HarnessHome, UpdateOperationLockRoot))
        {
            throw new InvalidDataException(
                "Enterprise program files and Harness user data must not overlap.");
        }
    }

    public string LocalAppDataRoot { get; }

    public string UserProfileRoot { get; }

    public string ManagedRoot { get; }

    public string HarnessHome { get; }

    public string HarnessRecoveryRoot { get; }

    public string LauncherVersionsRoot { get; }

    public string RuntimeVersionsRoot { get; }

    public string PluginPolicyVersionsRoot { get; }

    public string StateRoot { get; }

    public string PackageRoot { get; }

    public string UpdatePartialCacheRoot { get; }

    public string UpdateOperationLockRoot { get; }

    public string UpdateOperationLockPath { get; }

    public string UpdateReceiptRoot { get; }

    public string HealthSignalRoot { get; }

    public string ReleaseSecurityWitnessRoot { get; }

    public string BootstrapperPath { get; }

    public string InstalledInstallerPath { get; }

    public string BuildProfileMarkerPath { get; }

    public string LayoutProfile { get; }

    public bool IsDevelopmentE2E => string.Equals(
        LayoutProfile,
        DevelopmentE2ELayoutProfile,
        StringComparison.Ordinal);

    public string LauncherPointerPath => Path.Combine(StateRoot, "launcher-current.json");

    public string RuntimePointerPath => Path.Combine(StateRoot, "runtime-current.json");

    /// <summary>
    /// Schema-v2 authoritative pointer. Launcher and runtime are always selected as one tuple.
    /// The schema-v1 component pointers remain repair metadata only.
    /// </summary>
    public string ReleaseSetPointerPath => Path.Combine(StateRoot, "release-set-current.v2.json");

    public string UpdateSecurityStatePath => Path.Combine(
        StateRoot,
        "release-feed-security.v3.dpapi");

    public string UpdateSecurityAnchorPath => UpdateSecurityStatePath + ".anchor";

    public string UpdateSecurityPendingAnchorPath => UpdateSecurityStatePath + ".anchor.pending";

    public string UpdateSecurityWitnessPath => Path.Combine(
        ReleaseSecurityWitnessRoot,
        "release-feed-security.v3.witness.dpapi");

    public string UpdateStatusPath => Path.Combine(StateRoot, "release-update-status.v2.json");

    public string BootstrapperReceiptPath => Path.Combine(
        StateRoot,
        "bootstrapper-current.v2.json");

    public string HealthQuarantinePath => Path.Combine(
        StateRoot,
        "release-health-quarantine.v2.json");

    public static EnterpriseInstallationLayout CreateDefault()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Create(localAppData, userProfile);
    }

    public static EnterpriseInstallationLayout Create(
        string localAppDataRoot,
        string userProfileRoot)
    {
        EnterprisePathGuard.ValidateTrustedLocalRoot(localAppDataRoot, nameof(localAppDataRoot));
        EnterprisePathGuard.ValidateTrustedLocalRoot(userProfileRoot, nameof(userProfileRoot));
        return new EnterpriseInstallationLayout(
            localAppDataRoot,
            userProfileRoot,
            ManagedRootName,
            HarnessHomeName,
            ProductionLayoutProfile);
    }

    public static EnterpriseInstallationLayout CreateDevelopmentE2E()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return CreateDevelopmentE2E(localAppData, userProfile);
    }

    public static EnterpriseInstallationLayout CreateDevelopmentE2E(
        string localAppDataRoot,
        string userProfileRoot)
    {
        EnterprisePathGuard.ValidateTrustedLocalRoot(
            localAppDataRoot,
            nameof(localAppDataRoot));
        EnterprisePathGuard.ValidateTrustedLocalRoot(
            userProfileRoot,
            nameof(userProfileRoot));
        return new EnterpriseInstallationLayout(
            localAppDataRoot,
            userProfileRoot,
            DevelopmentE2EManagedRootName,
            DevelopmentE2EHarnessHomeName,
            DevelopmentE2ELayoutProfile);
    }

    internal static EnterpriseInstallationLayout CreateMigrationCandidate(
        EnterpriseInstallationLayout finalLayout,
        string candidateManagedRoot)
    {
        ArgumentNullException.ThrowIfNull(finalLayout);
        ArgumentException.ThrowIfNullOrWhiteSpace(candidateManagedRoot);
        var candidate = EnterprisePathGuard.NormalizeDirectory(candidateManagedRoot);
        var managedParent = Path.GetDirectoryName(finalLayout.ManagedRoot)
            ?? throw new InvalidDataException("Enterprise ManagedRoot has no parent directory.");
        var prefix = $".{Path.GetFileName(finalLayout.ManagedRoot)}.migration-candidate-";
        var candidateLeaf = Path.GetFileName(candidate);
        if (!string.Equals(
                Path.GetDirectoryName(candidate),
                managedParent,
                StringComparison.OrdinalIgnoreCase)
            || !candidateLeaf.StartsWith(prefix, StringComparison.Ordinal)
            || !Guid.TryParseExact(candidateLeaf[prefix.Length..], "N", out _)
            || !string.Equals(
                Path.GetPathRoot(candidate),
                Path.GetPathRoot(finalLayout.ManagedRoot),
                StringComparison.OrdinalIgnoreCase)
            || EnterprisePathGuard.IsSameOrDescendant(candidate, finalLayout.ManagedRoot)
            || EnterprisePathGuard.IsSameOrDescendant(finalLayout.ManagedRoot, candidate))
        {
            throw new InvalidDataException(
                "Enterprise migration candidate must be the exact same-volume ManagedRoot sibling.");
        }

        var managedRootName = finalLayout.IsDevelopmentE2E
            ? DevelopmentE2EManagedRootName
            : ManagedRootName;
        var harnessHomeName = finalLayout.IsDevelopmentE2E
            ? DevelopmentE2EHarnessHomeName
            : HarnessHomeName;
        return new EnterpriseInstallationLayout(
            finalLayout.LocalAppDataRoot,
            finalLayout.UserProfileRoot,
            managedRootName,
            harnessHomeName,
            finalLayout.LayoutProfile,
            candidate);
    }

    public string GetLauncherVersionDirectory(string releaseId)
    {
        EnterprisePathGuard.ValidateReleaseId(releaseId);
        return EnterprisePathGuard.CombineExactChild(LauncherVersionsRoot, releaseId);
    }

    public string GetRuntimeVersionDirectory(string releaseId)
    {
        EnterprisePathGuard.ValidateReleaseId(releaseId);
        return EnterprisePathGuard.CombineExactChild(RuntimeVersionsRoot, releaseId);
    }

    public string GetPluginPolicyVersionDirectory(string releaseId)
    {
        EnterprisePathGuard.ValidateReleaseId(releaseId);
        return EnterprisePathGuard.CombineExactChild(PluginPolicyVersionsRoot, releaseId);
    }

    public void EnsureManagedRoots()
    {
        EnterprisePathGuard.EnsureDirectoryChain(LocalAppDataRoot, ManagedRoot);
        EnterprisePathGuard.EnsureDirectoryChain(ManagedRoot, LauncherVersionsRoot);
        EnterprisePathGuard.EnsureDirectoryChain(ManagedRoot, RuntimeVersionsRoot);
        EnterprisePathGuard.EnsureDirectoryChain(ManagedRoot, PluginPolicyVersionsRoot);
        EnterprisePathGuard.EnsureDirectoryChain(ManagedRoot, StateRoot);
        EnterprisePathGuard.EnsureDirectoryChain(ManagedRoot, PackageRoot);
        EnterprisePathGuard.EnsureDirectoryChain(PackageRoot, UpdatePartialCacheRoot);
        EnsureUpdateOperationLockRoot();
        EnterprisePathGuard.EnsureDirectoryChain(ManagedRoot, UpdateReceiptRoot);
        EnterprisePathGuard.EnsureDirectoryChain(ManagedRoot, HealthSignalRoot);
        EnterprisePathGuard.EnsureDirectoryChain(
            UserProfileRoot,
            ReleaseSecurityWitnessRoot);
    }

    public void EnsureUpdateOperationLockRoot() =>
        EnterprisePathGuard.EnsureDirectoryChain(LocalAppDataRoot, UpdateOperationLockRoot);
}

internal static partial class EnterprisePathGuard
{
    private static readonly Regex ReleaseIdPattern = ReleaseIdRegex();

    public static string NormalizeDirectory(string path) =>
        Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

    public static void ValidateTrustedLocalRoot(string path, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.GetFullPath(path);
        if (!Path.IsPathFullyQualified(path)
            || !Path.IsPathFullyQualified(fullPath)
            || HasUntrustedWindowsPrefix(path)
            || HasUntrustedWindowsPrefix(fullPath)
            || fullPath.IndexOf(':', 2) >= 0
            || path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                .Any(segment => string.Equals(segment, "..", StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                $"{parameterName} must be a canonical local Windows path.");
        }
    }

    public static void ValidateReleaseId(string releaseId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(releaseId);
        if (!ReleaseIdPattern.IsMatch(releaseId))
        {
            throw new InvalidDataException("Enterprise releaseId is not canonical.");
        }
    }

    public static string CombineExactChild(string root, string childName)
    {
        var normalizedRoot = NormalizeDirectory(root);
        var combined = NormalizeDirectory(Path.Combine(normalizedRoot, childName));
        if (!string.Equals(
                Path.GetDirectoryName(combined)?.TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar),
                normalizedRoot,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Enterprise managed child escaped its root.");
        }

        return combined;
    }

    public static bool IsSameOrDescendant(string candidatePath, string rootPath)
    {
        var candidate = NormalizeDirectory(candidatePath);
        var root = NormalizeDirectory(rootPath);
        return string.Equals(candidate, root, StringComparison.OrdinalIgnoreCase)
            || candidate.StartsWith(
                root + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase);
    }

    public static void EnsureDirectoryChain(string trustedRoot, string requestedDirectory)
    {
        var root = NormalizeDirectory(trustedRoot);
        var requested = NormalizeDirectory(requestedDirectory);
        if (!IsSameOrDescendant(requested, root))
        {
            throw new InvalidDataException("Enterprise directory escaped its trusted root.");
        }

        if (!Directory.Exists(root))
        {
            throw new DirectoryNotFoundException(
                $"Trusted enterprise installation root does not exist: {root}");
        }

        RejectReparsePoint(root);
        var relative = Path.GetRelativePath(root, requested);
        if (relative == ".")
        {
            return;
        }

        var current = root;
        foreach (var segment in relative.Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            if (segment is "." or "..")
            {
                throw new InvalidDataException("Enterprise directory contains traversal.");
            }

            current = Path.Combine(current, segment);
            if (File.Exists(current) && !Directory.Exists(current))
            {
                throw new InvalidDataException(
                    $"Enterprise directory boundary is occupied by a file: {current}");
            }

            Directory.CreateDirectory(current);
            RejectReparsePoint(current);
        }
    }

    public static void ValidateExistingPathWithin(
        string candidatePath,
        string managedRoot,
        bool requireDirectory)
    {
        var candidate = Path.GetFullPath(candidatePath);
        var root = NormalizeDirectory(managedRoot);
        if (!IsSameOrDescendant(candidate, root)
            || string.Equals(NormalizeDirectory(candidate), root, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Enterprise path escaped its managed boundary.");
        }

        var relative = Path.GetRelativePath(root, candidate);
        var current = root;
        RejectReparsePoint(current);
        foreach (var segment in relative.Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if (Directory.Exists(current) || File.Exists(current))
            {
                RejectReparsePoint(current);
            }
        }

        if (requireDirectory && !Directory.Exists(candidate))
        {
            throw new DirectoryNotFoundException(candidate);
        }

        if (!requireDirectory && !File.Exists(candidate))
        {
            throw new FileNotFoundException("Enterprise managed file is missing.", candidate);
        }
    }

    public static void ValidateSafeTree(string directory, string managedRoot)
    {
        ValidateExistingPathWithin(directory, managedRoot, requireDirectory: true);
        var pending = new Stack<DirectoryInfo>();
        pending.Push(new DirectoryInfo(directory));
        while (pending.Count > 0)
        {
            var current = pending.Pop();
            foreach (var entry in current.EnumerateFileSystemInfos("*", SearchOption.TopDirectoryOnly))
            {
                RejectReparsePoint(entry.FullName);
                if (!IsSameOrDescendant(entry.FullName, directory))
                {
                    throw new InvalidDataException("Enterprise tree enumeration escaped its root.");
                }

                if (entry is DirectoryInfo childDirectory)
                {
                    pending.Push(childDirectory);
                }
            }
        }
    }

    public static void DeleteDirectoryTree(string directory, string managedRoot)
    {
        if (!Directory.Exists(directory))
        {
            return;
        }

        ValidateSafeTree(directory, managedRoot);
        Directory.Delete(directory, recursive: true);
    }

    public static void WriteFileAtomically(string path, ReadOnlySpan<byte> contents, string managedRoot)
    {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath)
            ?? throw new InvalidDataException("Enterprise state path has no parent directory.");
        EnsureDirectoryChain(managedRoot, directory);
        if (File.Exists(fullPath))
        {
            ValidateExistingPathWithin(fullPath, managedRoot, requireDirectory: false);
        }

        var temporaryPath = Path.Combine(
            directory,
            $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 4096,
                       FileOptions.WriteThrough))
            {
                stream.Write(contents);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, fullPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static void RejectReparsePoint(string path)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                $"Enterprise installation paths may not cross filesystem links: {path}");
        }
    }

    private static bool HasUntrustedWindowsPrefix(string path) =>
        path.StartsWith("\\\\", StringComparison.Ordinal)
        || path.StartsWith("//", StringComparison.Ordinal)
        || path.StartsWith("\\\\?\\", StringComparison.Ordinal)
        || path.StartsWith("\\\\.\\", StringComparison.Ordinal)
        || path.StartsWith("//?/", StringComparison.Ordinal)
        || path.StartsWith("//./", StringComparison.Ordinal);

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex ReleaseIdRegex();
}
