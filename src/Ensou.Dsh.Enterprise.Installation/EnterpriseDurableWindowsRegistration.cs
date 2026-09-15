using System.Text.Json.Serialization;
using Microsoft.Win32;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.Enterprise.Installation;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record EnterpriseDurableWindowsRegistration(
    string RegistrySubKey,
    string DesktopShortcutPath,
    string StartMenuShortcutPath,
    bool RegistryExisted,
    IReadOnlyList<EnterpriseDurableRegistryValue> RegistryValues,
    string? DesktopShortcutBase64,
    string? StartMenuShortcutBase64,
    string? BackgroundStartupCommand)
{
    public static EnterpriseDurableWindowsRegistration Create(
        EnterpriseWindowsRegistrationContext context,
        EnterpriseWindowsRegistrationRollbackSnapshot snapshot) => new(
        context.RegistrySubKey,
        context.DesktopShortcutPath,
        context.StartMenuShortcutPath,
        snapshot.RegistryExisted,
        snapshot.RegistryValues.Select(EnterpriseDurableRegistryValue.Create).ToArray(),
        snapshot.DesktopShortcutBytes is null
            ? null
            : Convert.ToBase64String(snapshot.DesktopShortcutBytes),
        snapshot.StartMenuShortcutBytes is null
            ? null
            : Convert.ToBase64String(snapshot.StartMenuShortcutBytes),
        snapshot.BackgroundStartupCommand);

    public void Validate(EnterpriseInstallationLayout layout)
    {
        var (context, snapshot) = ToRuntime();
        EnterpriseWindowsRegistration.ValidateRollbackContext(layout, context);
        if (!string.Equals(
                snapshot.RegistrySubKey,
                RegistrySubKey,
                StringComparison.Ordinal)
            || RegistryValues.Count > 64)
        {
            throw new InvalidDataException(
                "Enterprise durable registration snapshot is invalid.");
        }
        if (BackgroundStartupCommand?.Length > 32_767)
        {
            throw new InvalidDataException(
                "Enterprise durable background-startup snapshot is too large.");
        }
    }

    public (
        EnterpriseWindowsRegistrationContext Context,
        EnterpriseWindowsRegistrationRollbackSnapshot Snapshot) ToRuntime()
    {
        var context = new EnterpriseWindowsRegistrationContext(
            RegistrySubKey,
            DesktopShortcutPath,
            StartMenuShortcutPath,
            BackgroundStartupStore: WindowsBackgroundStartupRegistration.OpenCurrentUser());
        byte[]? desktop = DesktopShortcutBase64 is null
            ? null
            : Convert.FromBase64String(DesktopShortcutBase64);
        byte[]? startMenu = StartMenuShortcutBase64 is null
            ? null
            : Convert.FromBase64String(StartMenuShortcutBase64);
        if (desktop?.Length > 1024 * 1024 || startMenu?.Length > 1024 * 1024)
        {
            throw new InvalidDataException(
                "Enterprise durable shortcut rollback snapshot is too large.");
        }
        var snapshot = new EnterpriseWindowsRegistrationRollbackSnapshot(
            RegistrySubKey,
            RegistryExisted,
            RegistryValues.Select(value => value.ToRuntime()).ToArray(),
            desktop,
            startMenu,
            BackgroundStartupCommand);
        return (context, snapshot);
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record EnterpriseDurableRegistryValue(
    string Name,
    RegistryValueKind Kind,
    string? Text,
    long? Number,
    IReadOnlyList<string>? Strings,
    string? Base64)
{
    public static EnterpriseDurableRegistryValue Create(
        EnterpriseRegistryValueRollbackSnapshot snapshot) => snapshot.Value switch
        {
            string text => new(snapshot.Name, snapshot.Kind, text, null, null, null),
            int number => new(snapshot.Name, snapshot.Kind, null, number, null, null),
            long number => new(snapshot.Name, snapshot.Kind, null, number, null, null),
            string[] strings => new(snapshot.Name, snapshot.Kind, null, null, strings, null),
            byte[] bytes => new(
                snapshot.Name,
                snapshot.Kind,
                null,
                null,
                null,
                Convert.ToBase64String(bytes)),
            _ => throw new InvalidDataException(
                "Enterprise registry rollback value cannot be serialized durably."),
        };

    public EnterpriseRegistryValueRollbackSnapshot ToRuntime()
    {
        object value = Kind switch
        {
            RegistryValueKind.String or RegistryValueKind.ExpandString
                when Text is not null
                     && Number is null
                     && Strings is null
                     && Base64 is null => Text,
            RegistryValueKind.DWord
                when Number is >= int.MinValue and <= int.MaxValue
                     && Text is null
                     && Strings is null
                     && Base64 is null => (int)Number.Value,
            RegistryValueKind.QWord
                when Number is not null
                     && Text is null
                     && Strings is null
                     && Base64 is null => Number.Value,
            RegistryValueKind.MultiString
                when Strings is not null
                     && Text is null
                     && Number is null
                     && Base64 is null => Strings.ToArray(),
            RegistryValueKind.Binary
                when Base64 is not null
                     && Text is null
                     && Number is null
                     && Strings is null => Convert.FromBase64String(Base64),
            _ => throw new InvalidDataException(
                "Enterprise durable registry rollback value is invalid."),
        };
        return new EnterpriseRegistryValueRollbackSnapshot(Name, Kind, value);
    }
}
