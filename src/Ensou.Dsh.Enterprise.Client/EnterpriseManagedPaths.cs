using System.Diagnostics;

namespace Ensou.Dsh.Enterprise.Client;

public sealed record EnterpriseManagedPaths
{
    private EnterpriseManagedPaths(string managedRoot, string harnessHome)
    {
        ManagedRoot = NormalizeDirectory(managedRoot);
        HarnessHome = NormalizeDirectory(harnessHome);
        WorkspaceRoot = NormalizeDirectory(Path.Combine(HarnessHome, "workspaces"));
        RuntimeRoot = Path.Combine(ManagedRoot, "runtimes");
        LauncherStateDirectory = Path.Combine(ManagedRoot, "state");
        CacheDirectory = Path.Combine(ManagedRoot, "cache");
        SecurityDirectory = Path.Combine(ManagedRoot, "security");
        PackageDirectory = Path.Combine(ManagedRoot, "packages");
        PluginRoot = Path.Combine(ManagedRoot, "plugins");
        LogDirectory = Path.Combine(ManagedRoot, "logs");
        InstallationIdentityPath = Path.Combine(LauncherStateDirectory, "installation-id.json");

        Validate();
    }

    public string ManagedRoot { get; }

    public string HarnessHome { get; }

    /// <summary>
    /// Employee-owned local workspaces. This is deliberately below HarnessHome
    /// and outside every managed program/update/reset root.
    /// </summary>
    public string WorkspaceRoot { get; }

    public string RuntimeRoot { get; }

    public string LauncherStateDirectory { get; }

    public string CacheDirectory { get; }

    public string SecurityDirectory { get; }

    public string PackageDirectory { get; }

    public string PluginRoot { get; }

    public string LogDirectory { get; }

    public string InstallationIdentityPath { get; }

    public static EnterpriseManagedPaths CreateDefault()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Create(localAppData, userProfile);
    }

    public static EnterpriseManagedPaths CreateDevelopmentE2E()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return CreateDevelopmentE2E(localAppData, userProfile);
    }

    public static EnterpriseManagedPaths CreateDevelopmentE2E(
        string localAppDataRoot,
        string userProfileRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(localAppDataRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(userProfileRoot);
        ValidateTrustedLocalRoot(localAppDataRoot, nameof(localAppDataRoot));
        ValidateTrustedLocalRoot(userProfileRoot, nameof(userProfileRoot));
        return new EnterpriseManagedPaths(
            Path.Combine(
                localAppDataRoot,
                "Ensou",
                EnterpriseProductIdentity.DevelopmentE2EManagedRootName),
            Path.Combine(
                userProfileRoot,
                EnterpriseProductIdentity.DevelopmentE2EHarnessHomeName));
    }

    public static EnterpriseManagedPaths Create(string localAppDataRoot, string userProfileRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(localAppDataRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(userProfileRoot);
        ValidateTrustedLocalRoot(localAppDataRoot, nameof(localAppDataRoot));
        ValidateTrustedLocalRoot(userProfileRoot, nameof(userProfileRoot));

        return new EnterpriseManagedPaths(
            Path.Combine(localAppDataRoot, "Ensou", EnterpriseProductIdentity.ManagedRootName),
            Path.Combine(userProfileRoot, EnterpriseProductIdentity.HarnessHomeName));
    }

    public bool IsInsideManagedRoot(string candidatePath) =>
        IsSameOrDescendant(candidatePath, ManagedRoot);

    public bool IsInsideHarnessHome(string candidatePath) =>
        IsSameOrDescendant(candidatePath, HarnessHome);

    public bool IsInsideWorkspaceRoot(string candidatePath) =>
        IsSameOrDescendant(candidatePath, WorkspaceRoot);

    public bool IsInsidePluginRoot(string candidatePath) =>
        IsSameOrDescendant(candidatePath, PluginRoot);

    public void EnsureWorkspaceRoot()
    {
        Directory.CreateDirectory(HarnessHome);
        RejectReparsePoint(HarnessHome);
        Directory.CreateDirectory(WorkspaceRoot);
        ValidateWorkspaceRoot();
    }

    public void ValidateWorkspaceRoot()
    {
        var expected = NormalizeDirectory(Path.Combine(HarnessHome, "workspaces"));
        if (!string.Equals(WorkspaceRoot, expected, StringComparison.OrdinalIgnoreCase)
            || !IsInsideHarnessHome(WorkspaceRoot)
            || IsInsideManagedRoot(WorkspaceRoot)
            || !Directory.Exists(HarnessHome)
            || !Directory.Exists(WorkspaceRoot))
        {
            throw new InvalidDataException(
                "Enterprise workspace root is missing or escaped HarnessHome.");
        }
        RejectReparsePoint(HarnessHome);
        RejectReparsePoint(WorkspaceRoot);
    }

    public void ValidateManagedSkillsRoot(string skillsRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(skillsRoot);
        var normalized = NormalizeDirectory(skillsRoot);
        if (!string.Equals(skillsRoot, normalized, StringComparison.OrdinalIgnoreCase)
            || !IsInsidePluginRoot(normalized)
            || string.Equals(normalized, PluginRoot, StringComparison.OrdinalIgnoreCase)
            || !Directory.Exists(ManagedRoot)
            || !Directory.Exists(PluginRoot)
            || !Directory.Exists(normalized))
        {
            throw new InvalidDataException(
                "Enterprise managed skills root is missing or escaped the plugin root.");
        }

        RejectReparseChain(ManagedRoot, normalized);
    }

    public ProcessStartInfo CreateOpenWorkspaceStartInfo()
    {
        EnsureWorkspaceRoot();
        return new ProcessStartInfo
        {
            FileName = WorkspaceRoot,
            WorkingDirectory = WorkspaceRoot,
            UseShellExecute = true,
        };
    }

    public string Resolve(EnterpriseManagedArtifact artifact)
    {
        var resolved = artifact switch
        {
            EnterpriseManagedArtifact.AuthorizationLease =>
                Path.Combine(CacheDirectory, "authorization-lease.json"),
            EnterpriseManagedArtifact.ApiAllocationCache =>
                Path.Combine(CacheDirectory, "api-allocation.json"),
            EnterpriseManagedArtifact.PluginPolicyCache =>
                Path.Combine(CacheDirectory, "plugin-policy.json"),
            EnterpriseManagedArtifact.DeviceBindingReceipt =>
                Path.Combine(LauncherStateDirectory, "device-binding.json"),
            EnterpriseManagedArtifact.RefreshTokenDpapi =>
                Path.Combine(SecurityDirectory, "refresh-token.dpapi"),
            EnterpriseManagedArtifact.EnrollmentSessionDpapi =>
                Path.Combine(SecurityDirectory, "enrollment-session.dpapi"),
            EnterpriseManagedArtifact.PendingBindingTransactionDpapi =>
                Path.Combine(SecurityDirectory, "pending-binding-transaction.dpapi"),
            EnterpriseManagedArtifact.PendingRefreshTransactionDpapi =>
                Path.Combine(SecurityDirectory, "pending-refresh-transaction.dpapi"),
            EnterpriseManagedArtifact.PendingUpdateReceiptTransactionDpapi =>
                Path.Combine(SecurityDirectory, "pending-update-receipt-transaction.dpapi"),
            EnterpriseManagedArtifact.ResetBarrierDpapi =>
                Path.Combine(SecurityDirectory, "reset-barrier.dpapi"),
            EnterpriseManagedArtifact.TrustedTimeHighWaterDpapi =>
                Path.Combine(SecurityDirectory, "trusted-time-high-water.dpapi"),
            _ => throw new ArgumentOutOfRangeException(
                nameof(artifact),
                artifact,
                "Unknown enterprise managed artifact."),
        };

        if (!IsInsideManagedRoot(resolved)
            || IsInsideHarnessHome(resolved)
            || string.Equals(resolved, ManagedRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Enterprise artifact escaped its managed boundary.");
        }

        return resolved;
    }

    private void Validate()
    {
        if (!Path.IsPathFullyQualified(ManagedRoot) || !Path.IsPathFullyQualified(HarnessHome))
        {
            throw new InvalidDataException("Enterprise managed and Harness roots must be absolute.");
        }

        if (IsSameOrDescendant(ManagedRoot, HarnessHome)
            || IsSameOrDescendant(HarnessHome, ManagedRoot)
            || !string.Equals(
                WorkspaceRoot,
                NormalizeDirectory(Path.Combine(HarnessHome, "workspaces")),
                StringComparison.OrdinalIgnoreCase)
            || !IsSameOrDescendant(WorkspaceRoot, HarnessHome)
            || IsSameOrDescendant(WorkspaceRoot, ManagedRoot))
        {
            throw new InvalidDataException(
                "Enterprise managed files, Harness data, and workspaces have an invalid boundary.");
        }
    }

    private static string NormalizeDirectory(string path) =>
        Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

    private static void ValidateTrustedLocalRoot(string path, string parameterName)
    {
        var fullPath = Path.GetFullPath(path);
        if (!Path.IsPathFullyQualified(fullPath)
            || HasUntrustedWindowsPrefix(path)
            || HasUntrustedWindowsPrefix(fullPath)
            || fullPath.IndexOf(':', 2) >= 0
            || path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                .Any(segment => string.Equals(segment, "..", StringComparison.Ordinal)))
        {
            throw new InvalidDataException($"{parameterName} must be a canonical local Windows path.");
        }
    }

    private static bool HasUntrustedWindowsPrefix(string path) =>
        path.StartsWith("\\\\", StringComparison.Ordinal)
        || path.StartsWith("//", StringComparison.Ordinal)
        || path.StartsWith("\\\\?\\", StringComparison.Ordinal)
        || path.StartsWith("\\\\.\\", StringComparison.Ordinal)
        || path.StartsWith("//?/", StringComparison.Ordinal)
        || path.StartsWith("//./", StringComparison.Ordinal);

    private static void RejectReparsePoint(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                $"Enterprise workspace boundary may not be a filesystem link: {path}");
        }
    }

    private static void RejectReparseChain(string root, string descendant)
    {
        var normalizedRoot = NormalizeDirectory(root);
        var current = NormalizeDirectory(descendant);
        if (!IsSameOrDescendant(current, normalizedRoot))
        {
            throw new InvalidDataException(
                "Enterprise managed path escaped its trusted root.");
        }

        while (true)
        {
            RejectReparsePoint(current);
            if (string.Equals(current, normalizedRoot, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
            current = Path.GetDirectoryName(current)
                ?? throw new InvalidDataException(
                    "Enterprise managed path has no trusted parent.");
        }
    }

    private static bool IsSameOrDescendant(string candidatePath, string rootPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(candidatePath);
        var candidate = NormalizeDirectory(candidatePath);
        var root = NormalizeDirectory(rootPath);
        if (string.Equals(candidate, root, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return candidate.StartsWith(
            root + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase);
    }
}

public enum EnterpriseManagedArtifact
{
    AuthorizationLease = 0,
    ApiAllocationCache = 1,
    PluginPolicyCache = 2,
    DeviceBindingReceipt = 3,
    RefreshTokenDpapi = 4,
    EnrollmentSessionDpapi = 5,
    PendingBindingTransactionDpapi = 6,
    PendingRefreshTransactionDpapi = 7,
    ResetBarrierDpapi = 8,
    TrustedTimeHighWaterDpapi = 9,
    PendingUpdateReceiptTransactionDpapi = 10,
}
