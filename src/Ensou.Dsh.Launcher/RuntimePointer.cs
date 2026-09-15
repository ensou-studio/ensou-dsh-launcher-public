using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Ensou.Dsh.Launcher;

internal sealed record RuntimePointer(
    int SchemaVersion,
    string ReleaseId,
    string RuntimeDirectory,
    string? PreviousReleaseId,
    string? PreviousRuntimeDirectory,
    bool PendingHealthValidation,
    string? SnapshotDirectory,
    DateTimeOffset UpdatedAtUtc)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    public static string StatePath()
    {
        var root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(root, "Ensou", "DshLauncher", "state", "runtime-current.json");
    }

    public static RuntimePointer? TryRead(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        var pointer = JsonSerializer.Deserialize<RuntimePointer>(File.ReadAllText(path), JsonOptions)
            ?? throw new InvalidDataException("DSH 运行时指针为空。");
        if (pointer.SchemaVersion != 1 ||
            string.IsNullOrWhiteSpace(pointer.ReleaseId) ||
            string.IsNullOrWhiteSpace(pointer.RuntimeDirectory) ||
            !Path.IsPathFullyQualified(pointer.RuntimeDirectory))
        {
            throw new InvalidDataException("DSH 运行时指针无效。");
        }

        return pointer;
    }

    public static void WriteAtomically(RuntimePointer pointer)
    {
        var path = StatePath();
        var directory = Path.GetDirectoryName(path)
            ?? throw new InvalidOperationException("DSH 运行时状态目录无效。");
        Directory.CreateDirectory(directory);

        var temporaryPath = path + ".tmp";
        File.WriteAllText(temporaryPath, JsonSerializer.Serialize(pointer, JsonOptions));
        File.Move(temporaryPath, path, overwrite: true);
    }

    public void ValidateForRuntimeRoot(string runtimeRoot)
    {
        if (!Regex.IsMatch(
                ReleaseId,
                "^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$",
                RegexOptions.CultureInvariant))
        {
            throw new InvalidDataException("DSH 运行时指针中的 releaseId 无效。");
        }

        var root = Path.GetFullPath(runtimeRoot).TrimEnd(Path.DirectorySeparatorChar);
        var expected = Path.GetFullPath(Path.Combine(root, ReleaseId));
        var actual = Path.GetFullPath(RuntimeDirectory).TrimEnd(Path.DirectorySeparatorChar);
        if (!string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("DSH 运行时指针越过了 Launcher 管理目录。");
        }

        RejectReparsePointsBetween(actual, root);

        var markerPath = Path.Combine(actual, ".ensou-release.json");
        if (!File.Exists(markerPath))
        {
            throw new InvalidDataException("DSH 运行时缺少安装收据。");
        }

        using var marker = JsonDocument.Parse(File.ReadAllText(markerPath));
        var rootElement = marker.RootElement;
        var markerReleaseId = rootElement.GetProperty("releaseId").GetString();
        var artifactSha256 = rootElement.GetProperty("artifactSha256").GetString();
        if (!string.Equals(markerReleaseId, ReleaseId, StringComparison.Ordinal) ||
            artifactSha256 is null ||
            !Regex.IsMatch(artifactSha256, "^[0-9a-f]{64}$", RegexOptions.CultureInvariant))
        {
            throw new InvalidDataException("DSH 运行时安装收据与版本指针不匹配。");
        }

        var nodePath = Path.Combine(actual, "node.exe");
        var entryPath = Path.Combine(actual, "node_modules", "@deepseek-ai", "dsh", "lib", "bin.js");
        if (!File.Exists(nodePath) || !File.Exists(entryPath))
        {
            throw new InvalidDataException("DSH 运行时文件不完整。");
        }

        if ((File.GetAttributes(markerPath) & FileAttributes.ReparsePoint) != 0 ||
            (File.GetAttributes(nodePath) & FileAttributes.ReparsePoint) != 0 ||
            (File.GetAttributes(entryPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("DSH 运行时关键文件不得是文件系统链接。");
        }
    }

    public static RuntimePointer MarkHealthy(string releaseId)
    {
        var current = TryRead(StatePath())
            ?? throw new InvalidDataException("无法确认运行时：当前指针不存在。");
        if (!string.Equals(current.ReleaseId, releaseId, StringComparison.Ordinal) ||
            !current.PendingHealthValidation)
        {
            throw new InvalidDataException("无法确认运行时：待验证 releaseId 已变化。");
        }

        var healthy = current with
        {
            PendingHealthValidation = false,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };
        WriteAtomically(healthy);
        return healthy;
    }

    public static string? RollbackPending(string failedReleaseId)
    {
        var current = TryRead(StatePath())
            ?? throw new InvalidDataException("无法回滚运行时：当前指针不存在。");
        if (!current.PendingHealthValidation ||
            !string.Equals(current.ReleaseId, failedReleaseId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("无法回滚运行时：待验证 releaseId 已变化。");
        }

        if (string.IsNullOrWhiteSpace(current.PreviousReleaseId) ||
            string.IsNullOrWhiteSpace(current.PreviousRuntimeDirectory))
        {
            File.Delete(StatePath());
            return null;
        }

        var rollback = new RuntimePointer(
            SchemaVersion: 1,
            ReleaseId: current.PreviousReleaseId,
            RuntimeDirectory: current.PreviousRuntimeDirectory,
            PreviousReleaseId: current.ReleaseId,
            PreviousRuntimeDirectory: current.RuntimeDirectory,
            PendingHealthValidation: false,
            SnapshotDirectory: null,
            UpdatedAtUtc: DateTimeOffset.UtcNow);
        WriteAtomically(rollback);
        return rollback.RuntimeDirectory;
    }

    private static void RejectReparsePointsBetween(string directory, string managedRoot)
    {
        var current = new DirectoryInfo(directory);
        while (true)
        {
            if (!current.Exists)
            {
                throw new DirectoryNotFoundException($"DSH 运行时目录不存在：{current.FullName}");
            }

            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException($"DSH 运行时路径不得穿过文件系统链接：{current.FullName}");
            }

            if (string.Equals(
                    current.FullName.TrimEnd(Path.DirectorySeparatorChar),
                    managedRoot,
                    StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            current = current.Parent
                ?? throw new InvalidDataException("DSH 运行时路径未到达受管理根目录。");
        }
    }
}
