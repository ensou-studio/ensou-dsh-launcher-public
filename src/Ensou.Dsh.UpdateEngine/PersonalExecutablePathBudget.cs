using System.Reflection;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.UpdateEngine;

/// <summary>Admission for the executable paths supported by the Personal Process.Start chain.</summary>
public static class PersonalExecutablePathBudget
{
    public const int MaximumExecutablePathCharacters = 259;
    public const string ErrorCode = "PERSONAL_EXECUTABLE_PATH_TOO_LONG";
    private const string TransactionIdShape = "00000000000000000000000000000000";

    public static void RequireCandidate(
        PersonalInstallationLayout layout,
        PersonalReleaseSetManifest manifest) =>
        RequireCandidate(layout, manifest, IsProductionBuild());

    internal static void RequireInstallerCandidate(
        PersonalInstallationLayout layout,
        PersonalReleaseSetManifest manifest,
        bool productionBuild)
    {
        RequireCandidate(layout, manifest, productionBuild);
        if (productionBuild)
            RequirePath(Path.Combine(
                layout.UpdateOperationLockRoot, "personal-installer-staging",
                TransactionIdShape, PersonalInstallationLayout.StartupStubExecutableName),
                "安装验证组件");
    }

    internal static void RequireArchiveVerification(string component) =>
        RequireArchiveVerification(component, IsProductionBuild(), Path.GetTempPath());

    internal static void RequireArchiveVerification(string component, bool productionBuild, string temporaryRoot)
    {
        if (productionBuild && component == PersonalReleaseSetContract.ClientBundleComponent)
            RequireClientPaths(Path.Combine(temporaryRoot, "ensou-personal-candidate-verification", TransactionIdShape), "临时验证");
    }

    internal static void RequireCandidate(
        PersonalInstallationLayout layout,
        PersonalReleaseSetManifest manifest,
        bool productionBuild)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(manifest.ClientBundle);
        ArgumentNullException.ThrowIfNull(manifest.Runtime);
        string client = layout.GetClientBundleDirectory(manifest.ClientBundle.ReleaseId);
        string runtime = layout.GetRuntimeDirectory(manifest.Runtime.ReleaseId);
        RequirePath(layout.StartupStubPath, "启动组件");
        RequireClientPaths(client);
        RequirePath(Path.Combine(runtime, "node.exe"), "运行组件");

        // Production executes binary self-checks before the client staging tree is renamed.
        // The generated GUID has a fixed width; this admission performs no filesystem writes.
        if (productionBuild)
        {
            RequireArchiveVerification(PersonalReleaseSetContract.ClientBundleComponent, true, Path.GetTempPath());
            RequireClientPaths(Path.Combine(
                layout.ClientBundleVersionsRoot,
                $".{manifest.ClientBundle.ReleaseId}.staging-{TransactionIdShape}"));
        }
    }

    private static void RequireClientPaths(string directory, string prefix = "")
    {
        RequirePath(Path.Combine(directory, PersonalInstallationLayout.ClientBootstrapperExecutableName), prefix + "客户端启动组件");
        RequirePath(Path.Combine(directory, PersonalInstallationLayout.LauncherExecutableName), prefix + "客户端组件");
        RequirePath(Path.Combine(directory, PersonalInstallationLayout.MaintenanceExecutableName), prefix + "维护组件");
    }

    private static void RequirePath(string path, string component)
    {
        if (Path.GetFullPath(path).Length > MaximumExecutablePathCharacters)
        {
            throw new PersonalInstallPreflightException(
                ErrorCode,
                $"{component}的程序路径超过支持的 259 个字符；未安装或切换此候选版本。请联系支持人员选择受支持的较短安装位置或版本，请勿手动移动现有安装。对话和工作区数据路径不受此限制。");
        }
    }

    private static bool IsProductionBuild()
    {
        var values = typeof(PersonalExecutablePathBudget).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .Where(attribute => attribute.Key == "PersonalProductionBuild")
            .Select(attribute => attribute.Value).ToArray();
        if (values.Length != 1 || !bool.TryParse(values[0], out bool productionBuild))
            throw new InvalidOperationException("Personal executable path admission requires unique production-build metadata.");
        return productionBuild;
    }
}
