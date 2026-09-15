using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using Microsoft.Win32;

namespace Ensou.Dsh.Enterprise.Installation;

public static partial class EnterpriseWindowsRegistration
{
    private const string ProductionUninstallRegistryPath =
        @"Software\Microsoft\Windows\CurrentVersion\Uninstall\Ensou.Dsh.Enterprise.Launcher";
    private const string DevelopmentUninstallRegistryPath =
        @"Software\Microsoft\Windows\CurrentVersion\Uninstall\Ensou.Dsh.Enterprise.Launcher.DevE2E";

    internal static EnterpriseWindowsRegistrationSnapshot Install(
        EnterpriseInstallationLayout layout,
        string displayVersion,
        bool developmentUnsignedPayload)
        => Install(
            layout,
            displayVersion,
            developmentUnsignedPayload,
            EnterpriseWindowsRegistrationContext.CreateDefault(layout));

    internal static void Remove(EnterpriseInstallationLayout layout) =>
        Remove(layout, EnterpriseWindowsRegistrationContext.CreateDefault(layout));

    private static string GetDesktopShortcutPath(EnterpriseInstallationLayout layout)
    {
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        if (string.IsNullOrWhiteSpace(desktop) || !Path.IsPathFullyQualified(desktop))
        {
            throw new InvalidOperationException("无法定位当前用户桌面目录。");
        }

        return Path.Combine(desktop, GetShortcutName(layout));
    }

    private static string GetStartMenuShortcutPath(EnterpriseInstallationLayout layout)
    {
        var programs = Environment.GetFolderPath(Environment.SpecialFolder.Programs);
        if (string.IsNullOrWhiteSpace(programs) || !Path.IsPathFullyQualified(programs))
        {
            throw new InvalidOperationException("无法定位当前用户开始菜单目录。");
        }

        return Path.Combine(programs, "Ensou", GetShortcutName(layout));
    }

    private static void CreateShortcut(
        string shortcutPath,
        EnterpriseInstallationLayout layout)
    {
        if (!File.Exists(layout.BootstrapperPath))
        {
            throw new FileNotFoundException(
                "企业 Bootstrapper 尚未安装。",
                layout.BootstrapperPath);
        }

        var directory = Path.GetDirectoryName(shortcutPath)
            ?? throw new InvalidDataException("快捷方式路径没有父目录。");
        Directory.CreateDirectory(directory);
        RejectLinkedExistingPath(directory);
        RejectShortcutDirectory(shortcutPath);
        if (File.Exists(shortcutPath))
        {
            RejectLinkedExistingPath(shortcutPath);
        }

        var temporaryPath = BuildShortcutTemporaryPath(shortcutPath);
        IShellLinkW? shellLink = null;
        try
        {
            shellLink = (IShellLinkW)(object)new ShellLink();
            shellLink.SetPath(layout.BootstrapperPath);
            shellLink.SetWorkingDirectory(layout.ManagedRoot);
            shellLink.SetDescription(EnterpriseBrandContract.ShortcutDescription);
            shellLink.SetIconLocation(layout.BootstrapperPath, 0);
            ((IPersistFile)shellLink).Save(temporaryPath, true);
            if (!File.Exists(temporaryPath))
            {
                throw new IOException(
                    "Windows ShellLink did not persist the Enterprise shortcut at its exact staging path.");
            }
            RejectLinkedExistingPath(temporaryPath);
            RejectLinkedExistingPath(directory);
            RejectShortcutDirectory(shortcutPath);
            if (File.Exists(shortcutPath))
            {
                RejectLinkedExistingPath(shortcutPath);
            }
            File.Move(temporaryPath, shortcutPath, overwrite: true);
        }
        finally
        {
            if (shellLink is not null)
            {
                Marshal.FinalReleaseComObject(shellLink);
            }

            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static void DeleteOwnedShortcut(string path)
    {
        RejectShortcutDirectory(path);
        if (!File.Exists(path))
        {
            return;
        }

        RejectLinkedExistingPath(path);
        File.Delete(path);
        var parent = Path.GetDirectoryName(path);
        if (parent is not null
            && string.Equals(Path.GetFileName(parent), "Ensou", StringComparison.Ordinal)
            && Directory.Exists(parent)
            && !Directory.EnumerateFileSystemEntries(parent).Any())
        {
            Directory.Delete(parent);
        }
    }

    internal static string BuildShortcutTemporaryPath(string shortcutPath)
    {
        var directory = Path.GetDirectoryName(shortcutPath)
            ?? throw new InvalidDataException("快捷方式路径没有父目录。");
        return Path.Combine(directory, $".{Guid.NewGuid():N}.lnk");
    }

    private static void RejectShortcutDirectory(string path)
    {
        if (Directory.Exists(path))
        {
            throw new InvalidDataException(
                $"Enterprise shortcut path must not be a directory: {path}");
        }
    }

    private static void RejectLinkedExistingPath(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException($"Windows shell path must not be linked: {path}");
        }
    }

    private static string Quote(string path) => $"\"{path}\"";

    private static string GetShortcutName(EnterpriseInstallationLayout layout) =>
        layout.IsDevelopmentE2E
            ? "DeepSeek Harness 企业版 (Dev E2E).lnk"
            : EnterpriseBrandContract.ShortcutFileName;

    private static string GetUninstallRegistryPath(EnterpriseInstallationLayout layout) =>
        layout.IsDevelopmentE2E
            ? DevelopmentUninstallRegistryPath
            : ProductionUninstallRegistryPath;

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Enterprise Windows registration is only available on Windows.");
        }
    }

    [ComImport]
    [Guid("00021401-0000-0000-C000-000000000046")]
    private sealed class ShellLink;

    [ComImport]
    [Guid("000214F9-0000-0000-C000-000000000046")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellLinkW
    {
        void GetPath(
            [Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder file,
            int maximumPath,
            IntPtr findData,
            uint flags);

        void GetIDList(out IntPtr itemIdList);

        void SetIDList(IntPtr itemIdList);

        void GetDescription(
            [Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder description,
            int maximumName);

        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string description);

        void GetWorkingDirectory(
            [Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder directory,
            int maximumPath);

        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string directory);

        void GetArguments(
            [Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder arguments,
            int maximumPath);

        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string arguments);

        void GetHotkey(out short hotkey);

        void SetHotkey(short hotkey);

        void GetShowCmd(out int showCommand);

        void SetShowCmd(int showCommand);

        void GetIconLocation(
            [Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder iconPath,
            int maximumPath,
            out int iconIndex);

        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string iconPath, int iconIndex);

        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string path, uint reserved);

        void Resolve(IntPtr window, uint flags);

        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string path);
    }
}
