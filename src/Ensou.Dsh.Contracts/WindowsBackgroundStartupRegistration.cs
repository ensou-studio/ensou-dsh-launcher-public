using Microsoft.Win32;
using System.Runtime.Versioning;

namespace Ensou.Dsh.Contracts;

public interface IUserRunValueStore
{
    UserRunValue? Read(string valueName);
    void Write(string valueName, string command);
    void Delete(string valueName);
}

public enum UserRunValueKind
{
    String,
    Other,
}

public sealed record UserRunValue(string? Command, UserRunValueKind Kind);

public readonly record struct BackgroundStartupRegistrationResult(bool Created);

public static class WindowsBackgroundStartupRegistration
{
    public const string CommandArgument = "--background-startup";

    public static string CreateCommand(string stableStartupStubPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stableStartupStubPath);
        if (!Path.IsPathFullyQualified(stableStartupStubPath))
        {
            throw new ArgumentException("Stable Startup Stub path is invalid.", nameof(stableStartupStubPath));
        }
        var path = Path.GetFullPath(stableStartupStubPath);
        if (path.Contains('"'))
        {
            throw new ArgumentException("Stable Startup Stub path is invalid.", nameof(stableStartupStubPath));
        }
        return $"\"{path}\" {CommandArgument}";
    }

    public static BackgroundStartupRegistrationResult EnsureOwned(
        IUserRunValueStore store,
        string valueName,
        string stableStartupStubPath)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentException.ThrowIfNullOrWhiteSpace(valueName);
        var expected = CreateCommand(stableStartupStubPath);
        var existing = store.Read(valueName);
        if (existing is not null)
        {
            if (existing.Kind != UserRunValueKind.String
                || !string.Equals(existing.Command, expected, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "The per-user startup value exists but is not owned by this installation.");
            }
            return new BackgroundStartupRegistrationResult(false);
        }

        store.Write(valueName, expected);
        if (store.Read(valueName) is not { Kind: UserRunValueKind.String } written
            || !string.Equals(written.Command, expected, StringComparison.Ordinal))
        {
            try
            {
                if (store.Read(valueName) is
                    { Kind: UserRunValueKind.String, Command: var current }
                    && string.Equals(current, expected, StringComparison.Ordinal))
                {
                    store.Delete(valueName);
                }
            }
            catch { }
            throw new IOException("The per-user startup value could not be verified.");
        }
        return new BackgroundStartupRegistrationResult(true);
    }

    public static void RemoveOwned(
        IUserRunValueStore store,
        string valueName,
        string stableStartupStubPath)
    {
        ArgumentNullException.ThrowIfNull(store);
        var expected = CreateCommand(stableStartupStubPath);
        var existing = store.Read(valueName);
        if (existing is null)
        {
            return;
        }
        if (existing.Kind != UserRunValueKind.String
            || !string.Equals(existing.Command, expected, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The per-user startup value no longer belongs to this installation.");
        }
        store.Delete(valueName);
    }

    [SupportedOSPlatform("windows")]
    public static IUserRunValueStore OpenCurrentUser()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Per-user startup registration requires Windows.");
        }
        return new CurrentUserRunValueStore();
    }

    [SupportedOSPlatform("windows")]
    private sealed class CurrentUserRunValueStore : IUserRunValueStore
    {
        private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";

        public UserRunValue? Read(string valueName)
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey, writable: false);
            if (key is null)
            {
                return null;
            }
            var value = key.GetValue(
                valueName,
                null,
                RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (value is null)
            {
                return null;
            }
            var kind = key.GetValueKind(valueName);
            return new UserRunValue(
                value as string,
                kind == RegistryValueKind.String
                    ? UserRunValueKind.String
                    : UserRunValueKind.Other);
        }

        public void Write(string valueName, string command)
        {
            using var key = Registry.CurrentUser.CreateSubKey(RunKey, writable: true)
                ?? throw new IOException("Unable to open the per-user startup registry key.");
            key.SetValue(valueName, command, RegistryValueKind.String);
            key.Flush();
        }

        public void Delete(string valueName)
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey, writable: true);
            key?.DeleteValue(valueName, throwOnMissingValue: false);
            key?.Flush();
        }
    }
}
