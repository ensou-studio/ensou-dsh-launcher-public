using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using Microsoft.Win32;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.Enterprise.Installation;

public sealed record EnterpriseWindowsRegistrationSnapshot(
    string RegistrySubKey,
    string DisplayName,
    string DisplayVersion,
    string Publisher,
    string DisplayIcon,
    string InstallLocation,
    string? ModifyPath,
    string UninstallString,
    string QuietUninstallString,
    int NoModify,
    string DesktopShortcutPath,
    string StartMenuShortcutPath,
    string ShortcutTarget);

internal sealed record EnterpriseRegistryValueRollbackSnapshot(
    string Name,
    RegistryValueKind Kind,
    object Value);

internal sealed record EnterpriseWindowsRegistrationRollbackSnapshot(
    string RegistrySubKey,
    bool RegistryExisted,
    IReadOnlyList<EnterpriseRegistryValueRollbackSnapshot> RegistryValues,
    byte[]? DesktopShortcutBytes,
    byte[]? StartMenuShortcutBytes,
    string? BackgroundStartupCommand);

internal enum EnterpriseWindowsRegistrationRemovalStage
{
    DesktopShortcutRemoved,
    StartMenuShortcutRemoved,
    RegistryRemoved,
}

internal enum EnterpriseWindowsRegistrationInstallStage
{
    DesktopShortcutInstalled,
    StartMenuShortcutInstalled,
    RegistryInstalled,
}

internal sealed record EnterpriseWindowsRegistrationContext(
    string RegistrySubKey,
    string DesktopShortcutPath,
    string StartMenuShortcutPath,
    Action<EnterpriseWindowsRegistrationRemovalStage>? RemovalObserver = null,
    Action<EnterpriseWindowsRegistrationInstallStage>? InstallObserver = null,
    IUserRunValueStore? BackgroundStartupStore = null)
{
    public static EnterpriseWindowsRegistrationContext CreateDefault(
        EnterpriseInstallationLayout layout) => new(
            EnterpriseWindowsRegistration.GetRegistryPath(layout),
            EnterpriseWindowsRegistration.GetDesktopPath(layout),
            EnterpriseWindowsRegistration.GetStartMenuPath(layout),
            BackgroundStartupStore: WindowsBackgroundStartupRegistration.OpenCurrentUser());

    public EnterpriseWindowsRegistrationContext WithoutObservers() => this with
    {
        RemovalObserver = null,
        InstallObserver = null,
    };
}

public static partial class EnterpriseWindowsRegistration
{
    public const string BackgroundStartupValueName = "Ensou.Dsh.Enterprise.Launcher";
    private const int MaximumRollbackRegistryValues = 64;
    private const int MaximumRollbackShortcutBytes = 1024 * 1024;

    internal static EnterpriseWindowsRegistrationRollbackSnapshot CaptureRollbackSnapshot(
        EnterpriseInstallationLayout layout,
        EnterpriseWindowsRegistrationContext context)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(context);
        EnsureWindows();
        ValidateContext(layout, context);

        var values = new List<EnterpriseRegistryValueRollbackSnapshot>();
        var registryExisted = false;
        using (var key = Registry.CurrentUser.OpenSubKey(
                   context.RegistrySubKey,
                   writable: false))
        {
            if (key is not null)
            {
                registryExisted = true;
                if (key.GetSubKeyNames().Length != 0)
                {
                    throw new InvalidDataException(
                        "Enterprise registration rollback does not accept nested registry state.");
                }
                var names = key.GetValueNames()
                    .Order(StringComparer.Ordinal)
                    .ToArray();
                if (names.Length > MaximumRollbackRegistryValues)
                {
                    throw new InvalidDataException(
                        "Enterprise registration contains too many values to roll back safely.");
                }
                foreach (var name in names)
                {
                    var kind = key.GetValueKind(name);
                    var value = key.GetValue(
                            name,
                            defaultValue: null,
                            RegistryValueOptions.DoNotExpandEnvironmentNames)
                        ?? throw new InvalidDataException(
                            "Enterprise registration value disappeared during snapshot.");
                    values.Add(new EnterpriseRegistryValueRollbackSnapshot(
                        name,
                        kind,
                        CloneRegistryValue(kind, value)));
                }
            }
        }

        return new EnterpriseWindowsRegistrationRollbackSnapshot(
            context.RegistrySubKey,
            registryExisted,
            values,
            ReadShortcutBytes(context.DesktopShortcutPath),
            ReadShortcutBytes(context.StartMenuShortcutPath),
            context.BackgroundStartupStore?.Read(BackgroundStartupValueName)?.Command);
    }

    internal static void ValidateRollbackContext(
        EnterpriseInstallationLayout layout,
        EnterpriseWindowsRegistrationContext context)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(context);
        EnsureWindows();
        ValidateContext(layout, context);
    }

    internal static void RestoreRollbackSnapshot(
        EnterpriseInstallationLayout layout,
        EnterpriseWindowsRegistrationContext context,
        EnterpriseWindowsRegistrationRollbackSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(snapshot);
        EnsureWindows();
        ValidateContext(layout, context);
        if (!string.Equals(
                snapshot.RegistrySubKey,
                context.RegistrySubKey,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise registration rollback snapshot targets another registry key.");
        }

        var cleanContext = context.WithoutObservers();
        Remove(layout, cleanContext, manageBackgroundStartup: false);
        RestoreShortcutBytes(
            cleanContext.DesktopShortcutPath,
            snapshot.DesktopShortcutBytes);
        RestoreShortcutBytes(
            cleanContext.StartMenuShortcutPath,
            snapshot.StartMenuShortcutBytes);
        if (snapshot.RegistryExisted)
        {
            using var key = Registry.CurrentUser.CreateSubKey(
                    cleanContext.RegistrySubKey,
                    writable: true)
                ?? throw new InvalidOperationException(
                    "Unable to recreate Enterprise registration during rollback.");
            foreach (var value in snapshot.RegistryValues)
            {
                key.SetValue(
                    value.Name,
                    CloneRegistryValue(value.Kind, value.Value),
                    value.Kind);
            }
            key.Flush();
        }
        var startupStore = context.BackgroundStartupStore;
        var expectedStartup = WindowsBackgroundStartupRegistration.CreateCommand(
            layout.BootstrapperPath);
        if (startupStore is not null && snapshot.BackgroundStartupCommand is null)
        {
            if (string.Equals(
                    startupStore.Read(BackgroundStartupValueName)?.Command,
                    expectedStartup,
                    StringComparison.Ordinal))
            {
                WindowsBackgroundStartupRegistration.RemoveOwned(
                    startupStore,
                    BackgroundStartupValueName,
                    layout.BootstrapperPath);
            }
        }
        else if (startupStore is not null && string.Equals(snapshot.BackgroundStartupCommand, expectedStartup, StringComparison.Ordinal))
        {
            _ = WindowsBackgroundStartupRegistration.EnsureOwned(
                startupStore,
                BackgroundStartupValueName,
                layout.BootstrapperPath);
        }

        RequireRollbackSnapshotRestored(layout, cleanContext, snapshot);
    }

    internal static EnterpriseWindowsRegistrationSnapshot Install(
        EnterpriseInstallationLayout layout,
        string displayVersion,
        bool developmentUnsignedPayload,
        EnterpriseWindowsRegistrationContext context)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentException.ThrowIfNullOrWhiteSpace(displayVersion);
        ArgumentNullException.ThrowIfNull(context);
        EnsureWindows();
        ValidateContext(layout, context);
        EnterpriseStableBootstrapperVerifier.RequireTrusted(layout);

        if (context.BackgroundStartupStore is not null)
        {
            _ = WindowsBackgroundStartupRegistration.EnsureOwned(
                context.BackgroundStartupStore,
                BackgroundStartupValueName,
                layout.BootstrapperPath);
        }

        CreateShortcut(context.DesktopShortcutPath, layout);
        context.InstallObserver?.Invoke(
            EnterpriseWindowsRegistrationInstallStage.DesktopShortcutInstalled);
        CreateShortcut(context.StartMenuShortcutPath, layout);
        context.InstallObserver?.Invoke(
            EnterpriseWindowsRegistrationInstallStage.StartMenuShortcutInstalled);
        using (var key = Registry.CurrentUser.CreateSubKey(
                   context.RegistrySubKey,
                   writable: true)
               ?? throw new InvalidOperationException(
                   "无法写入当前用户卸载注册信息。"))
        {
            key.SetValue(
                "DisplayName",
                DisplayName(layout),
                RegistryValueKind.String);
            key.SetValue("DisplayVersion", displayVersion, RegistryValueKind.String);
            key.SetValue(
                "Publisher",
                EnterpriseBrandContract.DeveloperName,
                RegistryValueKind.String);
            key.SetValue("DisplayIcon", layout.BootstrapperPath, RegistryValueKind.String);
            key.SetValue("InstallLocation", layout.ManagedRoot, RegistryValueKind.String);
            key.SetValue(
                "UninstallString",
                UninstallCommand(layout, quiet: false),
                RegistryValueKind.String);
            key.SetValue(
                "QuietUninstallString",
                UninstallCommand(layout, quiet: true),
                RegistryValueKind.String);
            if (developmentUnsignedPayload)
            {
                key.DeleteValue("ModifyPath", throwOnMissingValue: false);
            }
            else
            {
                key.SetValue(
                    "ModifyPath",
                    RepairCommand(layout),
                    RegistryValueKind.String);
            }
            key.SetValue(
                "NoModify",
                developmentUnsignedPayload ? 1 : 0,
                RegistryValueKind.DWord);
            key.SetValue("NoRepair", 0, RegistryValueKind.DWord);
            key.Flush();
        }
        context.InstallObserver?.Invoke(
            EnterpriseWindowsRegistrationInstallStage.RegistryInstalled);

        return ReadAndValidate(
            layout,
            displayVersion,
            developmentUnsignedPayload,
            context);
    }

    internal static void Remove(
        EnterpriseInstallationLayout layout,
        EnterpriseWindowsRegistrationContext context,
        bool manageBackgroundStartup = true)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(context);
        EnsureWindows();
        ValidateContext(layout, context);
        if (manageBackgroundStartup && context.BackgroundStartupStore is not null)
        {
            WindowsBackgroundStartupRegistration.RemoveOwned(
                context.BackgroundStartupStore,
                BackgroundStartupValueName,
                layout.BootstrapperPath);
        }
        DeleteOwnedShortcut(context.DesktopShortcutPath);
        context.RemovalObserver?.Invoke(
            EnterpriseWindowsRegistrationRemovalStage.DesktopShortcutRemoved);
        DeleteOwnedShortcut(context.StartMenuShortcutPath);
        context.RemovalObserver?.Invoke(
            EnterpriseWindowsRegistrationRemovalStage.StartMenuShortcutRemoved);
        Registry.CurrentUser.DeleteSubKeyTree(
            context.RegistrySubKey,
            throwOnMissingSubKey: false);
        context.RemovalObserver?.Invoke(
            EnterpriseWindowsRegistrationRemovalStage.RegistryRemoved);

        using var key = Registry.CurrentUser.OpenSubKey(
            context.RegistrySubKey,
            writable: false);
        if (key is not null
            || File.Exists(context.DesktopShortcutPath)
            || Directory.Exists(context.DesktopShortcutPath)
            || File.Exists(context.StartMenuShortcutPath)
            || Directory.Exists(context.StartMenuShortcutPath))
        {
            throw new IOException(
                "Enterprise current-user registration was not removed completely.");
        }
    }

    internal static EnterpriseWindowsRegistrationSnapshot ReadAndValidate(
        EnterpriseInstallationLayout layout,
        string displayVersion,
        bool developmentUnsignedPayload,
        EnterpriseWindowsRegistrationContext context)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentException.ThrowIfNullOrWhiteSpace(displayVersion);
        ArgumentNullException.ThrowIfNull(context);
        ValidateContext(layout, context);
        using var key = Registry.CurrentUser.OpenSubKey(
            context.RegistrySubKey,
            writable: false)
            ?? throw new InvalidDataException(
                "Enterprise current-user registration is missing after write.");
        var expectedModify = developmentUnsignedPayload
            ? null
            : RepairCommand(layout);
        var expectedUninstall = UninstallCommand(layout, quiet: false);
        var expectedQuiet = UninstallCommand(layout, quiet: true);
        RequireRegistryString(key, "DisplayName", DisplayName(layout));
        RequireRegistryString(key, "DisplayVersion", displayVersion);
        RequireRegistryString(
            key,
            "Publisher",
            EnterpriseBrandContract.DeveloperName);
        RequireRegistryString(key, "DisplayIcon", layout.BootstrapperPath);
        RequireRegistryString(key, "InstallLocation", layout.ManagedRoot);
        RequireRegistryString(key, "UninstallString", expectedUninstall);
        RequireRegistryString(key, "QuietUninstallString", expectedQuiet);
        if (expectedModify is null)
        {
            if (key.GetValue("ModifyPath", null, RegistryValueOptions.DoNotExpandEnvironmentNames)
                is not null)
            {
                throw new InvalidDataException(
                    "Development-E2E registration unexpectedly exposes ModifyPath.");
            }
        }
        else
        {
            RequireRegistryString(key, "ModifyPath", expectedModify);
        }
        var noModify = developmentUnsignedPayload ? 1 : 0;
        RequireRegistryDword(key, "NoModify", noModify);
        RequireRegistryDword(key, "NoRepair", 0);
        RequireShortcut(context.DesktopShortcutPath, layout);
        RequireShortcut(context.StartMenuShortcutPath, layout);

        return new EnterpriseWindowsRegistrationSnapshot(
            context.RegistrySubKey,
            DisplayName(layout),
            displayVersion,
            EnterpriseBrandContract.DeveloperName,
            layout.BootstrapperPath,
            layout.ManagedRoot,
            expectedModify,
            expectedUninstall,
            expectedQuiet,
            noModify,
            context.DesktopShortcutPath,
            context.StartMenuShortcutPath,
            layout.BootstrapperPath);
    }

    internal static string GetRegistryPath(EnterpriseInstallationLayout layout) =>
        GetUninstallRegistryPath(layout);

    internal static string GetDesktopPath(EnterpriseInstallationLayout layout) =>
        GetDesktopShortcutPath(layout);

    internal static string GetStartMenuPath(EnterpriseInstallationLayout layout) =>
        GetStartMenuShortcutPath(layout);

    private static void ValidateContext(
        EnterpriseInstallationLayout layout,
        EnterpriseWindowsRegistrationContext context)
    {
        if (!context.RegistrySubKey.StartsWith("Software\\", StringComparison.Ordinal)
            || context.RegistrySubKey.Split('\\').Any(segment =>
                string.IsNullOrWhiteSpace(segment) || segment is "." or "..")
            || !Path.IsPathFullyQualified(context.DesktopShortcutPath)
            || !Path.IsPathFullyQualified(context.StartMenuShortcutPath)
            || !string.Equals(
                Path.GetExtension(context.DesktopShortcutPath),
                ".lnk",
                StringComparison.OrdinalIgnoreCase)
            || !string.Equals(
                Path.GetExtension(context.StartMenuShortcutPath),
                ".lnk",
                StringComparison.OrdinalIgnoreCase)
            || string.Equals(
                Path.GetFullPath(context.DesktopShortcutPath),
                Path.GetFullPath(context.StartMenuShortcutPath),
                StringComparison.OrdinalIgnoreCase)
            || EnterprisePathGuard.IsSameOrDescendant(
                context.DesktopShortcutPath,
                layout.ManagedRoot)
            || EnterprisePathGuard.IsSameOrDescendant(
                context.StartMenuShortcutPath,
                layout.ManagedRoot))
        {
            throw new InvalidDataException(
                "Enterprise Windows registration context is invalid.");
        }
        RejectLinkedAncestors(Path.GetDirectoryName(
            Path.GetFullPath(context.DesktopShortcutPath))!);
        RejectLinkedAncestors(Path.GetDirectoryName(
            Path.GetFullPath(context.StartMenuShortcutPath))!);
    }

    private static byte[]? ReadShortcutBytes(string path)
    {
        if (Directory.Exists(path))
        {
            throw new InvalidDataException(
                "Enterprise shortcut rollback snapshot cannot treat a directory as a shortcut.");
        }
        if (!File.Exists(path))
        {
            return null;
        }
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Enterprise shortcut rollback snapshot cannot read a linked file.");
        }
        var bytes = File.ReadAllBytes(path);
        if (bytes.Length is <= 0 or > MaximumRollbackShortcutBytes)
        {
            throw new InvalidDataException(
                "Enterprise shortcut rollback snapshot size is invalid.");
        }
        return bytes;
    }

    private static void RestoreShortcutBytes(string path, byte[]? bytes)
    {
        if (bytes is null)
        {
            if (File.Exists(path) || Directory.Exists(path))
            {
                DeleteOwnedShortcut(path);
            }
            return;
        }
        if (bytes.Length is <= 0 or > MaximumRollbackShortcutBytes)
        {
            throw new InvalidDataException(
                "Enterprise shortcut rollback bytes are invalid.");
        }
        var directory = Path.GetDirectoryName(path)
            ?? throw new InvalidDataException(
                "Enterprise shortcut rollback target has no parent.");
        Directory.CreateDirectory(directory);
        RejectLinkedAncestors(directory);
        var temporary = Path.Combine(
            directory,
            $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.rollback.tmp");
        try
        {
            using (var stream = new FileStream(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 4_096,
                       FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private static void RequireRollbackSnapshotRestored(
        EnterpriseInstallationLayout layout,
        EnterpriseWindowsRegistrationContext context,
        EnterpriseWindowsRegistrationRollbackSnapshot snapshot)
    {
        _ = layout;
        RequireBytesEqual(
            snapshot.DesktopShortcutBytes,
            ReadShortcutBytes(context.DesktopShortcutPath),
            "desktop shortcut");
        RequireBytesEqual(
            snapshot.StartMenuShortcutBytes,
            ReadShortcutBytes(context.StartMenuShortcutPath),
            "Start-menu shortcut");
        if (context.BackgroundStartupStore is not null
            && !string.Equals(
                snapshot.BackgroundStartupCommand,
                context.BackgroundStartupStore.Read(BackgroundStartupValueName)?.Command,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise background-startup registration was not restored exactly.");
        }

        using var key = Registry.CurrentUser.OpenSubKey(
            context.RegistrySubKey,
            writable: false);
        if (!snapshot.RegistryExisted)
        {
            if (key is not null)
            {
                throw new InvalidDataException(
                    "Enterprise registration rollback unexpectedly left a registry key.");
            }
            return;
        }
        if (key is null
            || key.GetSubKeyNames().Length != 0
            || !key.GetValueNames()
                .Order(StringComparer.Ordinal)
                .SequenceEqual(
                    snapshot.RegistryValues.Select(value => value.Name),
                    StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise registration rollback registry shape differs from its snapshot.");
        }
        foreach (var expected in snapshot.RegistryValues)
        {
            if (key.GetValueKind(expected.Name) != expected.Kind
                || key.GetValue(
                        expected.Name,
                        defaultValue: null,
                        RegistryValueOptions.DoNotExpandEnvironmentNames) is not { } actual
                || !RegistryValuesEqual(expected.Value, actual))
            {
                throw new InvalidDataException(
                    $"Enterprise registration rollback value '{expected.Name}' differs from its snapshot.");
            }
        }
    }

    private static object CloneRegistryValue(RegistryValueKind kind, object value) =>
        kind switch
        {
            RegistryValueKind.String or RegistryValueKind.ExpandString
                when value is string text => text,
            RegistryValueKind.DWord when value is int number => number,
            RegistryValueKind.QWord when value is long number => number,
            RegistryValueKind.Binary when value is byte[] bytes => bytes.ToArray(),
            RegistryValueKind.MultiString when value is string[] strings => strings.ToArray(),
            _ => throw new InvalidDataException(
                "Enterprise registration contains an unsupported rollback value kind."),
        };

    private static bool RegistryValuesEqual(object expected, object actual) =>
        (expected, actual) switch
        {
            (byte[] left, byte[] right) => left.AsSpan().SequenceEqual(right),
            (string[] left, string[] right) => left.SequenceEqual(right, StringComparer.Ordinal),
            _ => Equals(expected, actual),
        };

    private static void RequireBytesEqual(
        byte[]? expected,
        byte[]? actual,
        string description)
    {
        if ((expected is null) != (actual is null)
            || expected is not null
                && actual is not null
                && !expected.AsSpan().SequenceEqual(actual))
        {
            throw new InvalidDataException(
                $"Enterprise registration rollback {description} differs from its snapshot.");
        }
    }

    private static void RequireShortcut(
        string shortcutPath,
        EnterpriseInstallationLayout layout)
    {
        var absolutePath = Path.GetFullPath(shortcutPath);
        if (!File.Exists(absolutePath)
            || (File.GetAttributes(absolutePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Enterprise Launcher shortcut is missing or linked after write.");
        }
        RejectLinkedAncestors(Path.GetDirectoryName(absolutePath)!);

        IShellLinkW? shellLink = null;
        try
        {
            shellLink = (IShellLinkW)(object)new ShellLink();
            ((IPersistFile)shellLink).Load(absolutePath, 0);
            var target = new System.Text.StringBuilder(32_768);
            var arguments = new System.Text.StringBuilder(4_096);
            var workingDirectory = new System.Text.StringBuilder(32_768);
            var description = new System.Text.StringBuilder(1_024);
            var icon = new System.Text.StringBuilder(32_768);
            shellLink.GetPath(target, target.Capacity, IntPtr.Zero, 4);
            shellLink.GetArguments(arguments, arguments.Capacity);
            shellLink.GetWorkingDirectory(workingDirectory, workingDirectory.Capacity);
            shellLink.GetDescription(description, description.Capacity);
            shellLink.GetIconLocation(icon, icon.Capacity, out var iconIndex);
            if (!SamePath(target.ToString(), layout.BootstrapperPath)
                || arguments.Length != 0
                || !SamePath(workingDirectory.ToString(), layout.ManagedRoot)
                || !string.Equals(
                    description.ToString(),
                    EnterpriseBrandContract.ShortcutDescription,
                    StringComparison.Ordinal)
                || !SamePath(icon.ToString(), layout.BootstrapperPath)
                || iconIndex != 0)
            {
                throw new InvalidDataException(
                    "Enterprise Launcher shortcut does not point exactly to the stable Startup Stub.");
            }
        }
        finally
        {
            if (shellLink is not null)
            {
                Marshal.FinalReleaseComObject(shellLink);
            }
        }
    }

    private static void RequireRegistryString(
        RegistryKey key,
        string name,
        string expected)
    {
        if (key.GetValueKind(name) != RegistryValueKind.String
            || key.GetValue(
                name,
                defaultValue: null,
                RegistryValueOptions.DoNotExpandEnvironmentNames) is not string actual
            || !string.Equals(actual, expected, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Enterprise registration value '{name}' failed read-back validation.");
        }
    }

    private static void RequireRegistryDword(
        RegistryKey key,
        string name,
        int expected)
    {
        if (key.GetValueKind(name) != RegistryValueKind.DWord
            || key.GetValue(name) is not int actual
            || actual != expected)
        {
            throw new InvalidDataException(
                $"Enterprise registration value '{name}' failed read-back validation.");
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
                    "Enterprise Windows registration path crosses a filesystem link.");
            }
        }
    }

    private static string DisplayName(EnterpriseInstallationLayout layout) =>
        layout.IsDevelopmentE2E
            ? "Ensou DSH Enterprise Launcher (Dev E2E)"
            : EnterpriseBrandContract.ProductFamilyName;

    private static string RepairCommand(EnterpriseInstallationLayout layout) =>
        Quote(layout.BootstrapperPath) + " --maintenance-repair";

    private static string UninstallCommand(
        EnterpriseInstallationLayout layout,
        bool quiet) =>
        Quote(layout.BootstrapperPath)
        + " --maintenance-uninstall"
        + (quiet ? " --quiet" : string.Empty);

    private static bool SamePath(string left, string right) =>
        !string.IsNullOrWhiteSpace(left)
        && string.Equals(
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)),
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)),
            StringComparison.OrdinalIgnoreCase);
}
