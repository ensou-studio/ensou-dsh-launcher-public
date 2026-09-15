using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using Microsoft.Win32;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.UpdateEngine;

public sealed record PersonalWindowsRegistrationSnapshot(
    string RegistrySubKey,
    string DisplayName,
    string DisplayVersion,
    string Publisher,
    string DisplayIcon,
    string InstallLocation,
    string ModifyPath,
    string UninstallString,
    string QuietUninstallString,
    string DesktopShortcutPath,
    string StartMenuShortcutPath,
    string ShortcutTarget);

internal sealed record PersonalWindowsRegistrationContext(
    string RegistrySubKey,
    string DesktopShortcutPath,
    string StartMenuShortcutPath,
    Action<PersonalWindowsRegistrationRemovalStage>? RemovalObserver = null,
    Action<PersonalWindowsRegistrationInstallStage>? InstallObserver = null,
    IUserRunValueStore? BackgroundStartupStore = null)
{
    public static PersonalWindowsRegistrationContext CreateDefault()
    {
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        var programs = Environment.GetFolderPath(Environment.SpecialFolder.Programs);
        if (string.IsNullOrWhiteSpace(desktop)
            || string.IsNullOrWhiteSpace(programs)
            || !Path.IsPathFullyQualified(desktop)
            || !Path.IsPathFullyQualified(programs))
        {
            throw new InvalidOperationException(
                "Unable to resolve the current user's Windows shell directories.");
        }
        return new PersonalWindowsRegistrationContext(
            PersonalWindowsRegistration.UninstallRegistrySubKey,
            Path.Combine(desktop, PersonalWindowsRegistration.ShortcutFileName),
            Path.Combine(
                programs,
                "Ensou",
                PersonalWindowsRegistration.ShortcutFileName),
            BackgroundStartupStore: WindowsBackgroundStartupRegistration.OpenCurrentUser());
    }
}

internal enum PersonalWindowsRegistrationRemovalStage
{
    DesktopShortcutRemoved,
    StartMenuShortcutRemoved,
    RegistryRemoved,
}

internal enum PersonalWindowsRegistrationInstallStage
{
    DesktopShortcutWritten,
    StartMenuShortcutWritten,
    RegistryReset,
    RegistryDisplayNameWritten,
    RegistryDisplayVersionWritten,
    RegistryPublisherWritten,
    RegistryDisplayIconWritten,
    RegistryInstallLocationWritten,
    RegistryModifyPathWritten,
    RegistryUninstallStringWritten,
    RegistryQuietUninstallStringWritten,
    RegistryNoModifyWritten,
    RegistryNoRepairWritten,
    RegistryFlushed,
}

internal sealed record PersonalRegistrationFileSnapshot(
    byte[] Bytes,
    FileAttributes Attributes);

internal sealed record PersonalRegistrationRegistryValueSnapshot(
    RegistryValueKind Kind,
    object Value);

internal sealed record PersonalWindowsRegistrationState(
    PersonalRegistrationFileSnapshot? DesktopShortcut,
    PersonalRegistrationFileSnapshot? StartMenuShortcut,
    IReadOnlyDictionary<string, PersonalRegistrationRegistryValueSnapshot>? RegistryValues);

public static class PersonalWindowsRegistration
{
    public const string BackgroundStartupValueName = "Ensou.Dsh.Personal.Launcher";
    public const string UninstallRegistrySubKey =
        @"Software\Microsoft\Windows\CurrentVersion\Uninstall\Ensou.Dsh.Personal.Launcher";
    public const string ShortcutFileName = "DeepSeek Harness Launcher.lnk";
    public const string ProductDisplayName = "DeepSeek Harness Launcher";
    public const string PublisherName = "ensou studio";
    public const string ShortcutDescription =
        "Start DeepSeek Harness through the signed Ensou Startup Stub";

    public static PersonalWindowsRegistrationSnapshot Install(
        PersonalInstallationLayout layout,
        string displayVersion) =>
        Install(layout, displayVersion, PersonalWindowsRegistrationContext.CreateDefault());

    internal static PersonalWindowsRegistrationSnapshot Install(
        PersonalInstallationLayout layout,
        string displayVersion,
        PersonalWindowsRegistrationContext context)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentException.ThrowIfNullOrWhiteSpace(displayVersion);
        ArgumentNullException.ThrowIfNull(context);
        EnsureWindows();
        ValidateContext(layout, context);
        RequireStableStartupStub(layout);
        var previous = CaptureState(context);
        var startupStore = context.BackgroundStartupStore;
        var startupCreated = false;
        try
        {
            WriteShortcut(context.DesktopShortcutPath, layout);
            context.InstallObserver?.Invoke(
                PersonalWindowsRegistrationInstallStage.DesktopShortcutWritten);
            WriteShortcut(context.StartMenuShortcutPath, layout);
            context.InstallObserver?.Invoke(
                PersonalWindowsRegistrationInstallStage.StartMenuShortcutWritten);

            Registry.CurrentUser.DeleteSubKeyTree(
                context.RegistrySubKey,
                throwOnMissingSubKey: false);
            context.InstallObserver?.Invoke(
                PersonalWindowsRegistrationInstallStage.RegistryReset);
            using (var key = Registry.CurrentUser.CreateSubKey(
                       context.RegistrySubKey,
                       writable: true)
                   ?? throw new InvalidOperationException(
                       "Unable to create the current-user uninstall registration."))
            {
                SetValue(key, "DisplayName", ProductDisplayName, RegistryValueKind.String,
                    PersonalWindowsRegistrationInstallStage.RegistryDisplayNameWritten, context);
                SetValue(key, "DisplayVersion", displayVersion, RegistryValueKind.String,
                    PersonalWindowsRegistrationInstallStage.RegistryDisplayVersionWritten, context);
                SetValue(key, "Publisher", PublisherName, RegistryValueKind.String,
                    PersonalWindowsRegistrationInstallStage.RegistryPublisherWritten, context);
                SetValue(key, "DisplayIcon", layout.StartupStubPath, RegistryValueKind.String,
                    PersonalWindowsRegistrationInstallStage.RegistryDisplayIconWritten, context);
                SetValue(key, "InstallLocation", layout.ManagedRoot, RegistryValueKind.String,
                    PersonalWindowsRegistrationInstallStage.RegistryInstallLocationWritten, context);
                SetValue(
                    key,
                    "ModifyPath",
                    Command(layout.StartupStubPath, "--maintenance-repair"),
                    RegistryValueKind.String,
                    PersonalWindowsRegistrationInstallStage.RegistryModifyPathWritten,
                    context);
                SetValue(
                    key,
                    "UninstallString",
                    Command(layout.StartupStubPath, "--maintenance-uninstall"),
                    RegistryValueKind.String,
                    PersonalWindowsRegistrationInstallStage.RegistryUninstallStringWritten,
                    context);
                SetValue(
                    key,
                    "QuietUninstallString",
                    Command(layout.StartupStubPath, "--maintenance-uninstall --quiet"),
                    RegistryValueKind.String,
                    PersonalWindowsRegistrationInstallStage.RegistryQuietUninstallStringWritten,
                    context);
                SetValue(key, "NoModify", 0, RegistryValueKind.DWord,
                    PersonalWindowsRegistrationInstallStage.RegistryNoModifyWritten, context);
                SetValue(key, "NoRepair", 0, RegistryValueKind.DWord,
                    PersonalWindowsRegistrationInstallStage.RegistryNoRepairWritten, context);
                key.Flush();
                context.InstallObserver?.Invoke(
                    PersonalWindowsRegistrationInstallStage.RegistryFlushed);
            }

            if (startupStore is not null)
            {
                startupCreated = WindowsBackgroundStartupRegistration.EnsureOwned(
                    startupStore,
                    BackgroundStartupValueName,
                    layout.StartupStubPath).Created;
            }
            return ReadAndValidate(layout, displayVersion, context);
        }
        catch (Exception installFailure)
        {
            try
            {
                if (startupCreated)
                {
                    WindowsBackgroundStartupRegistration.RemoveOwned(
                        startupStore!,
                        BackgroundStartupValueName,
                        layout.StartupStubPath);
                }
                RestoreState(context, previous);
            }
            catch (Exception rollbackFailure)
            {
                throw new AggregateException(
                    "Personal Windows registration failed and its exact prior state could not be restored.",
                    installFailure,
                    rollbackFailure);
            }
            System.Runtime.ExceptionServices.ExceptionDispatchInfo
                .Capture(installFailure)
                .Throw();
            throw;
        }
    }

    private static void SetValue(
        RegistryKey key,
        string name,
        object value,
        RegistryValueKind kind,
        PersonalWindowsRegistrationInstallStage stage,
        PersonalWindowsRegistrationContext context)
    {
        key.SetValue(name, value, kind);
        context.InstallObserver?.Invoke(stage);
    }

    private static PersonalWindowsRegistrationState CaptureState(
        PersonalWindowsRegistrationContext context)
    {
        var desktop = CaptureFile(context.DesktopShortcutPath);
        var startMenu = CaptureFile(context.StartMenuShortcutPath);
        using var key = Registry.CurrentUser.OpenSubKey(
            context.RegistrySubKey,
            writable: false);
        if (key is null)
        {
            return new PersonalWindowsRegistrationState(desktop, startMenu, null);
        }

        if (key.GetSubKeyNames().Length != 0)
        {
            throw new InvalidDataException(
                "The existing personal uninstall registration contains unexpected subkeys.");
        }
        var names = key.GetValueNames();
        if (names.Length > 64)
        {
            throw new InvalidDataException(
                "The existing personal uninstall registration has too many values to restore safely.");
        }
        var values = new Dictionary<string, PersonalRegistrationRegistryValueSnapshot>(
            StringComparer.Ordinal);
        foreach (var name in names)
        {
            var kind = key.GetValueKind(name);
            var value = key.GetValue(
                    name,
                    defaultValue: null,
                    RegistryValueOptions.DoNotExpandEnvironmentNames)
                ?? throw new InvalidDataException(
                    $"The existing personal uninstall value '{name}' could not be captured.");
            values.Add(name, new PersonalRegistrationRegistryValueSnapshot(
                kind,
                CloneRegistryValue(kind, value)));
        }
        return new PersonalWindowsRegistrationState(desktop, startMenu, values);
    }

    private static PersonalRegistrationFileSnapshot? CaptureFile(string path)
    {
        var absolutePath = Path.GetFullPath(path);
        var parent = Path.GetDirectoryName(absolutePath)
            ?? throw new InvalidDataException("Shortcut path has no parent directory.");
        RejectLinkedAncestors(parent);
        if (!File.Exists(absolutePath))
        {
            return null;
        }
        var attributes = File.GetAttributes(absolutePath);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new InvalidDataException(
                "An existing Launcher shortcut is not a regular file.");
        }
        PersonalPathGuard.RequireSingleLinkFile(absolutePath);
        var information = new FileInfo(absolutePath);
        if (information.Length > 16 * 1024 * 1024)
        {
            throw new InvalidDataException(
                "An existing Launcher shortcut is too large to restore safely.");
        }
        var bytes = File.ReadAllBytes(absolutePath);
        if (bytes.LongLength != information.Length)
        {
            throw new IOException(
                "The existing Launcher shortcut changed while it was captured.");
        }
        PersonalPathGuard.RequireSingleLinkFile(absolutePath);
        return new PersonalRegistrationFileSnapshot(bytes, attributes);
    }

    private static object CloneRegistryValue(
        RegistryValueKind kind,
        object value) => (kind, value) switch
    {
        (RegistryValueKind.Binary or RegistryValueKind.None, byte[] bytes)
            when bytes.LongLength <= 1024 * 1024 => bytes.ToArray(),
        (RegistryValueKind.String or RegistryValueKind.ExpandString, string text)
            when text.Length <= 32_768 => text,
        (RegistryValueKind.MultiString, string[] strings) when strings.Length <= 256
            && strings.All(value => value.Length <= 32_768) => strings.ToArray(),
        (RegistryValueKind.DWord, int number) => number,
        (RegistryValueKind.QWord, long number) => number,
        _ => throw new InvalidDataException(
            "The existing personal uninstall registration contains an unsupported value."),
    };

    private static void RestoreState(
        PersonalWindowsRegistrationContext context,
        PersonalWindowsRegistrationState previous)
    {
        var failures = new List<Exception>();
        TryRestore(() => RestoreFile(context.DesktopShortcutPath, previous.DesktopShortcut), failures);
        TryRestore(() => RestoreFile(context.StartMenuShortcutPath, previous.StartMenuShortcut), failures);
        TryRestore(() => RestoreRegistry(context, previous.RegistryValues), failures);
        if (failures.Count == 0)
        {
            try
            {
                RequireStateEqual(previous, CaptureState(context));
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
        }
        if (failures.Count != 0)
        {
            throw new AggregateException(
                "The previous personal Windows registration was not restored exactly.",
                failures);
        }
    }

    private static void TryRestore(Action action, ICollection<Exception> failures)
    {
        try
        {
            action();
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }
    }

    private static void RestoreFile(
        string path,
        PersonalRegistrationFileSnapshot? previous)
    {
        var absolutePath = Path.GetFullPath(path);
        if (previous is null)
        {
            DeleteOwnedShortcut(absolutePath);
            return;
        }

        var directory = Path.GetDirectoryName(absolutePath)
            ?? throw new InvalidDataException("Shortcut path has no parent directory.");
        RejectLinkedAncestors(directory);
        Directory.CreateDirectory(directory);
        RejectLinkedAncestors(directory);
        if (File.Exists(absolutePath)
            && (File.GetAttributes(absolutePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Refusing to replace a linked Launcher shortcut during rollback.");
        }

        var temporaryPath = Path.Combine(
            directory,
            $".{Path.GetFileName(absolutePath)}.{Guid.NewGuid():N}.rollback.tmp");
        try
        {
            using (var output = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       64 * 1024,
                       FileOptions.WriteThrough))
            {
                output.Write(previous.Bytes);
                output.Flush(flushToDisk: true);
            }
            PersonalPathGuard.RequireSingleLinkFile(temporaryPath);
            File.Move(temporaryPath, absolutePath, overwrite: true);
            File.SetAttributes(absolutePath, previous.Attributes);
            PersonalPathGuard.RequireSingleLinkFile(absolutePath);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static void RestoreRegistry(
        PersonalWindowsRegistrationContext context,
        IReadOnlyDictionary<string, PersonalRegistrationRegistryValueSnapshot>? previous)
    {
        Registry.CurrentUser.DeleteSubKeyTree(
            context.RegistrySubKey,
            throwOnMissingSubKey: false);
        if (previous is null)
        {
            return;
        }

        using var key = Registry.CurrentUser.CreateSubKey(
                context.RegistrySubKey,
                writable: true)
            ?? throw new InvalidOperationException(
                "Unable to restore the current-user uninstall registration.");
        foreach (var pair in previous.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            key.SetValue(
                pair.Key,
                CloneRegistryValue(pair.Value.Kind, pair.Value.Value),
                pair.Value.Kind);
        }
        key.Flush();
    }

    private static void RequireStateEqual(
        PersonalWindowsRegistrationState expected,
        PersonalWindowsRegistrationState actual)
    {
        RequireFileSnapshotEqual(expected.DesktopShortcut, actual.DesktopShortcut);
        RequireFileSnapshotEqual(expected.StartMenuShortcut, actual.StartMenuShortcut);
        if (expected.RegistryValues is null || actual.RegistryValues is null)
        {
            if (expected.RegistryValues is not null || actual.RegistryValues is not null)
            {
                throw new IOException(
                    "The uninstall registration key was not restored exactly.");
            }
            return;
        }
        if (expected.RegistryValues.Count != actual.RegistryValues.Count)
        {
            throw new IOException(
                "The uninstall registration values were not restored exactly.");
        }
        foreach (var pair in expected.RegistryValues)
        {
            if (!actual.RegistryValues.TryGetValue(pair.Key, out var restored)
                || pair.Value.Kind != restored.Kind
                || !RegistryValueEquals(pair.Value.Value, restored.Value))
            {
                throw new IOException(
                    $"The uninstall registration value '{pair.Key}' was not restored exactly.");
            }
        }
    }

    private static void RequireFileSnapshotEqual(
        PersonalRegistrationFileSnapshot? expected,
        PersonalRegistrationFileSnapshot? actual)
    {
        if (expected is null || actual is null)
        {
            if (expected is not null || actual is not null)
            {
                throw new IOException("A Launcher shortcut was not restored exactly.");
            }
            return;
        }
        if (expected.Attributes != actual.Attributes
            || !expected.Bytes.AsSpan().SequenceEqual(actual.Bytes))
        {
            throw new IOException("A Launcher shortcut was not restored exactly.");
        }
    }

    private static bool RegistryValueEquals(object expected, object actual) =>
        (expected, actual) switch
        {
            (byte[] left, byte[] right) => left.AsSpan().SequenceEqual(right),
            (string[] left, string[] right) => left.SequenceEqual(right, StringComparer.Ordinal),
            _ => Equals(expected, actual),
        };

    public static void Remove(PersonalInstallationLayout layout) =>
        Remove(layout, PersonalWindowsRegistrationContext.CreateDefault());

    internal static void Remove(
        PersonalInstallationLayout layout,
        PersonalWindowsRegistrationContext context)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(context);
        EnsureWindows();
        ValidateContext(layout, context);
        if (context.BackgroundStartupStore is not null)
        {
            WindowsBackgroundStartupRegistration.RemoveOwned(
                context.BackgroundStartupStore,
                BackgroundStartupValueName,
                layout.StartupStubPath);
        }
        DeleteOwnedShortcut(context.DesktopShortcutPath);
        context.RemovalObserver?.Invoke(
            PersonalWindowsRegistrationRemovalStage.DesktopShortcutRemoved);
        DeleteOwnedShortcut(context.StartMenuShortcutPath);
        context.RemovalObserver?.Invoke(
            PersonalWindowsRegistrationRemovalStage.StartMenuShortcutRemoved);
        Registry.CurrentUser.DeleteSubKeyTree(
            context.RegistrySubKey,
            throwOnMissingSubKey: false);
        context.RemovalObserver?.Invoke(
            PersonalWindowsRegistrationRemovalStage.RegistryRemoved);

        using var key = Registry.CurrentUser.OpenSubKey(context.RegistrySubKey, writable: false);
        if (key is not null
            || File.Exists(context.DesktopShortcutPath)
            || File.Exists(context.StartMenuShortcutPath))
        {
            throw new IOException(
                "Current-user Launcher registration was not removed completely.");
        }
    }

    internal static PersonalWindowsRegistrationSnapshot ReadAndValidate(
        PersonalInstallationLayout layout,
        string displayVersion,
        PersonalWindowsRegistrationContext context)
    {
        using var key = Registry.CurrentUser.OpenSubKey(
            context.RegistrySubKey,
            writable: false)
            ?? throw new InvalidDataException(
                "Current-user uninstall registration is missing after repair.");
        var expectedValueNames = new[]
        {
            "DisplayIcon",
            "DisplayName",
            "DisplayVersion",
            "InstallLocation",
            "ModifyPath",
            "NoModify",
            "NoRepair",
            "Publisher",
            "QuietUninstallString",
            "UninstallString",
        };
        if (key.GetSubKeyNames().Length != 0
            || !key.GetValueNames()
                .Order(StringComparer.Ordinal)
                .SequenceEqual(expectedValueNames, StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "Current-user registration is not the exact owned value set after repair.");
        }
        var expectedModify = Command(layout.StartupStubPath, "--maintenance-repair");
        var expectedUninstall = Command(layout.StartupStubPath, "--maintenance-uninstall");
        var expectedQuiet = Command(
            layout.StartupStubPath,
            "--maintenance-uninstall --quiet");
        RequireRegistryString(key, "DisplayName", ProductDisplayName);
        RequireRegistryString(key, "DisplayVersion", displayVersion);
        RequireRegistryString(key, "Publisher", PublisherName);
        RequireRegistryString(key, "DisplayIcon", layout.StartupStubPath);
        RequireRegistryString(key, "InstallLocation", layout.ManagedRoot);
        RequireRegistryString(key, "ModifyPath", expectedModify);
        RequireRegistryString(key, "UninstallString", expectedUninstall);
        RequireRegistryString(key, "QuietUninstallString", expectedQuiet);
        RequireRegistryDword(key, "NoModify", 0);
        RequireRegistryDword(key, "NoRepair", 0);

        RequireShortcut(context.DesktopShortcutPath, layout);
        RequireShortcut(context.StartMenuShortcutPath, layout);
        return new PersonalWindowsRegistrationSnapshot(
            context.RegistrySubKey,
            ProductDisplayName,
            displayVersion,
            PublisherName,
            layout.StartupStubPath,
            layout.ManagedRoot,
            expectedModify,
            expectedUninstall,
            expectedQuiet,
            context.DesktopShortcutPath,
            context.StartMenuShortcutPath,
            layout.StartupStubPath);
    }

    private static void RequireStableStartupStub(PersonalInstallationLayout layout)
    {
        var path = Path.GetFullPath(layout.StartupStubPath);
        if (!PersonalPathGuard.IsStrictDescendant(path, layout.ManagedRoot)
            || !File.Exists(path)
            || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new PersonalBinaryRepairRequiresInstallerException(
                "The stable Startup Stub is missing or linked.");
        }
        RejectLinkedAncestors(Path.GetDirectoryName(path)!);
        PersonalPathGuard.RequireSingleLinkFile(path);
        try
        {
            PersonalAuthenticodeVerifier.RequireTrustedEnsouExecutable(path);
        }
        catch (Exception exception) when (exception is InvalidDataException
            or InvalidOperationException
            or IOException
            or UnauthorizedAccessException)
        {
            throw new PersonalBinaryRepairRequiresInstallerException(
                "The stable Startup Stub did not pass Authenticode verification.",
                exception);
        }
    }

    private static void ValidateContext(
        PersonalInstallationLayout layout,
        PersonalWindowsRegistrationContext context)
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
            || PersonalPathGuard.IsSameOrDescendant(
                context.DesktopShortcutPath,
                layout.ManagedRoot)
            || PersonalPathGuard.IsSameOrDescendant(
                context.StartMenuShortcutPath,
                layout.ManagedRoot))
        {
            throw new InvalidDataException(
                "Personal Windows registration paths are invalid.");
        }
    }

    private static void WriteShortcut(
        string shortcutPath,
        PersonalInstallationLayout layout)
    {
        var absolutePath = Path.GetFullPath(shortcutPath);
        var directory = Path.GetDirectoryName(absolutePath)
            ?? throw new InvalidDataException("Shortcut path has no parent directory.");
        RejectLinkedAncestors(directory);
        Directory.CreateDirectory(directory);
        RejectLinkedAncestors(directory);
        if (File.Exists(absolutePath)
            && (File.GetAttributes(absolutePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "An existing Launcher shortcut is a filesystem link.");
        }

        var temporaryPath = Path.Combine(
            directory,
            $".{Path.GetFileName(absolutePath)}.{Guid.NewGuid():N}.tmp");
        IShellLinkW? shellLink = null;
        try
        {
            shellLink = (IShellLinkW)(object)new ShellLink();
            shellLink.SetPath(layout.StartupStubPath);
            shellLink.SetArguments(string.Empty);
            shellLink.SetWorkingDirectory(layout.ManagedRoot);
            shellLink.SetDescription(ShortcutDescription);
            shellLink.SetIconLocation(layout.StartupStubPath, 0);
            ((IPersistFile)shellLink).Save(temporaryPath, true);
            File.Move(temporaryPath, absolutePath, overwrite: true);
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

    private static void RequireShortcut(
        string shortcutPath,
        PersonalInstallationLayout layout)
    {
        var absolutePath = Path.GetFullPath(shortcutPath);
        if (!File.Exists(absolutePath)
            || (File.GetAttributes(absolutePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Launcher shortcut is missing or linked after repair.");
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
            if (!SamePath(target.ToString(), layout.StartupStubPath)
                || arguments.Length != 0
                || !SamePath(workingDirectory.ToString(), layout.ManagedRoot)
                || !string.Equals(
                    description.ToString(),
                    ShortcutDescription,
                    StringComparison.Ordinal)
                || !SamePath(icon.ToString(), layout.StartupStubPath)
                || iconIndex != 0)
            {
                throw new InvalidDataException(
                    "Launcher shortcut does not point exactly to the stable Startup Stub.");
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

    private static void DeleteOwnedShortcut(string shortcutPath)
    {
        var absolutePath = Path.GetFullPath(shortcutPath);
        if (!File.Exists(absolutePath))
        {
            return;
        }
        if ((File.GetAttributes(absolutePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Refusing to remove a linked Launcher shortcut.");
        }
        RejectLinkedAncestors(Path.GetDirectoryName(absolutePath)!);
        File.Delete(absolutePath);
        var parent = Path.GetDirectoryName(absolutePath);
        if (parent is not null
            && string.Equals(Path.GetFileName(parent), "Ensou", StringComparison.Ordinal)
            && Directory.Exists(parent)
            && !Directory.EnumerateFileSystemEntries(parent).Any())
        {
            Directory.Delete(parent);
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
                $"Current-user registration value '{name}' failed read-back validation.");
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
                $"Current-user registration value '{name}' failed read-back validation.");
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
                    "Windows registration path crosses a filesystem link.");
            }
        }
    }

    private static string Command(string executablePath, string arguments) =>
        $"\"{executablePath}\" {arguments}";

    private static bool SamePath(string left, string right) =>
        !string.IsNullOrWhiteSpace(left)
        && string.Equals(
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)),
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)),
            StringComparison.OrdinalIgnoreCase);

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Personal Windows registration is available only on Windows.");
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
