using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Ensou.Dsh.WindowsPilotObserver;

public static class ObservationPrivacy
{
    private static readonly HashSet<string> ForbiddenPropertyNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "commandLine",
        "environment",
        "apiKey",
        "accessToken",
        "bearerToken",
        "refreshToken",
        "userName",
        "macAddress",
        "serialNumber",
    };

    public static string HashSensitiveText(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    public static string NormalizePrivatePath(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var replacements = new (string? Prefix, string Replacement)[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "<user-profile>"),
            (Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "<local-app-data>"),
            (Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "<roaming-app-data>"),
            (Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "<program-files>"),
            (Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "<program-files-x86>"),
        };
        foreach (var replacement in replacements
                     .Where(static item => !string.IsNullOrWhiteSpace(item.Prefix))
                     .OrderByDescending(static item => item.Prefix!.Length))
        {
            var prefix = Path.TrimEndingDirectorySeparator(Path.GetFullPath(replacement.Prefix!));
            if (string.Equals(fullPath, prefix, StringComparison.OrdinalIgnoreCase))
            {
                return replacement.Replacement;
            }
            var withSeparator = prefix + Path.DirectorySeparatorChar;
            if (fullPath.StartsWith(withSeparator, StringComparison.OrdinalIgnoreCase))
            {
                return replacement.Replacement + Path.DirectorySeparatorChar + fullPath[withSeparator.Length..];
            }
        }
        return fullPath;
    }

    public static string ClassifyTitle(string title)
    {
        if (title.Contains("Application Error", StringComparison.OrdinalIgnoreCase))
        {
            return "application-error";
        }
        if (title.Contains("unhandled exception", StringComparison.OrdinalIgnoreCase)
            || title.Contains("fatal error", StringComparison.OrdinalIgnoreCase))
        {
            return "unhandled-error";
        }
        if (title.Contains("Windows Security", StringComparison.OrdinalIgnoreCase))
        {
            return "security-prompt";
        }
        return string.IsNullOrWhiteSpace(title) ? "empty" : "other";
    }

    public static void AssertSafePayload(JsonElement element)
    {
        AssertSafePayloadCore(element, "$", 0);
    }

    private static void AssertSafePayloadCore(JsonElement element, string path, int depth)
    {
        if (depth > 32)
        {
            throw new InvalidDataException("Evidence payload depth exceeds the contract limit.");
        }
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (ForbiddenPropertyNames.Contains(property.Name))
                {
                    throw new InvalidDataException($"Forbidden evidence property at {path}.{property.Name}.");
                }
                AssertSafePayloadCore(property.Value, $"{path}.{property.Name}", depth + 1);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                AssertSafePayloadCore(item, path + "[]", depth + 1);
            }
        }
        else if (element.ValueKind == JsonValueKind.String)
        {
            var text = element.GetString() ?? string.Empty;
            var userName = Environment.UserName;
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if ((!string.IsNullOrWhiteSpace(userName)
                 && string.Equals(text, userName, StringComparison.OrdinalIgnoreCase))
                || (!string.IsNullOrWhiteSpace(userProfile)
                    && text.Contains(userProfile, StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidDataException($"Evidence value at {path} contains private account data.");
            }
        }
    }
}
