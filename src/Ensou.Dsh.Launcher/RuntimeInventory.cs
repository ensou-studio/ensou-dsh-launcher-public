using System.IO;
using System.Text.Json;

namespace Ensou.Dsh.Launcher;

internal static class RuntimeInventory
{
    public static string ReadInstalledDshVersion(string runtimeDirectory)
    {
        var packagePath = Path.Combine(
            runtimeDirectory,
            "node_modules",
            "@deepseek-ai",
            "dsh",
            "package.json");

        if (!File.Exists(packagePath))
        {
            return "未安装";
        }

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(packagePath));
            return document.RootElement.TryGetProperty("version", out var version)
                ? version.GetString() ?? "未知"
                : "未知";
        }
        catch (JsonException)
        {
            return "无法识别";
        }
    }
}
