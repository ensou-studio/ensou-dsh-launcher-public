using System.IO;
using System.Text.Json;

namespace Ensou.Dsh.Launcher;

internal static class DataSnapshotService
{
    private static readonly string[] ManagedDirectories = ["sessions", "storages", "profiles"];
    private static readonly string[] ManagedFiles = ["settings.yaml"];
    private const int MaximumFiles = 500_000;
    private const long MaximumBytes = 8L * 1024 * 1024 * 1024;

    public static async Task<string> CreateAsync(
        string dshDataDirectory,
        string releaseId,
        CancellationToken cancellationToken = default)
    {
        var dataRoot = ValidateDataRoot(dshDataDirectory);
        var snapshotRoot = SnapshotRoot();
        Directory.CreateDirectory(snapshotRoot);

        var snapshotName = $"before-{releaseId}-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}";
        var finalDirectory = Path.Combine(snapshotRoot, snapshotName);
        var stagingDirectory = finalDirectory + ".staging";
        Directory.CreateDirectory(stagingDirectory);

        var existingDirectories = new Dictionary<string, bool>(StringComparer.Ordinal);
        var existingFiles = new Dictionary<string, bool>(StringComparer.Ordinal);
        var budget = new CopyBudget();
        try
        {
            foreach (var name in ManagedDirectories)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var source = Path.Combine(dataRoot, name);
                var exists = Directory.Exists(source);
                existingDirectories[name] = exists;
                if (exists)
                {
                    await CopyDirectoryAsync(
                        source,
                        Path.Combine(stagingDirectory, name),
                        skipNodeModules: name == "profiles",
                        budget,
                        cancellationToken);
                }
            }

            foreach (var name in ManagedFiles)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var source = Path.Combine(dataRoot, name);
                var exists = File.Exists(source);
                existingFiles[name] = exists;
                if (exists)
                {
                    await CopyFileAsync(source, Path.Combine(stagingDirectory, name), budget, cancellationToken);
                }
            }

            var manifest = new SnapshotManifest(
                1,
                releaseId,
                dataRoot,
                DateTimeOffset.UtcNow,
                existingDirectories,
                existingFiles,
                budget.FileCount,
                budget.TotalBytes);
            await File.WriteAllTextAsync(
                Path.Combine(stagingDirectory, "snapshot.json"),
                JsonSerializer.Serialize(manifest, new JsonSerializerOptions(JsonSerializerDefaults.Web)
                {
                    WriteIndented = true
                }),
                cancellationToken);

            Directory.Move(stagingDirectory, finalDirectory);
            return finalDirectory;
        }
        catch
        {
            if (Directory.Exists(stagingDirectory))
            {
                DeleteTreeWithoutFollowingLinks(stagingDirectory);
            }

            throw;
        }
    }

    public static async Task RestoreAsync(
        string snapshotDirectory,
        string dshDataDirectory,
        CancellationToken cancellationToken = default)
    {
        var snapshotRoot = Path.GetFullPath(SnapshotRoot()) + Path.DirectorySeparatorChar;
        var snapshot = Path.GetFullPath(snapshotDirectory);
        if (!snapshot.StartsWith(snapshotRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("数据恢复点不在 Launcher 管理目录内。");
        }

        var manifestPath = Path.Combine(snapshot, "snapshot.json");
        var manifest = JsonSerializer.Deserialize<SnapshotManifest>(
            await File.ReadAllTextAsync(manifestPath, cancellationToken),
            new JsonSerializerOptions(JsonSerializerDefaults.Web))
            ?? throw new InvalidDataException("数据恢复点清单为空。");
        if (manifest.SchemaVersion != 1)
        {
            throw new InvalidDataException("不支持的数据恢复点版本。");
        }

        var dataRoot = ValidateDataRoot(dshDataDirectory);
        if (!string.Equals(dataRoot, Path.GetFullPath(manifest.SourceDataDirectory), StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("数据恢复点不属于当前 DSH_HOME。");
        }

        ValidateSnapshotPayload(snapshot, manifest);

        Directory.CreateDirectory(dataRoot);
        foreach (var name in ManagedDirectories)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var target = Path.Combine(dataRoot, name);
            var existed = manifest.ExistingDirectories.TryGetValue(name, out var recorded) && recorded;
            if (string.Equals(name, "profiles", StringComparison.Ordinal))
            {
                if (existed)
                {
                    await RestoreDirectoryOverlayAsync(
                        Path.Combine(snapshot, name),
                        target,
                        cancellationToken);
                }

                continue;
            }

            if (Directory.Exists(target))
            {
                DeleteTreeWithoutFollowingLinks(target);
            }

            if (existed)
            {
                await CopyDirectoryAsync(
                    Path.Combine(snapshot, name),
                    target,
                    skipNodeModules: false,
                    new CopyBudget(),
                    cancellationToken);
            }
        }

        foreach (var name in ManagedFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var target = Path.Combine(dataRoot, name);
            if (File.Exists(target))
            {
                File.Delete(target);
            }

            if (manifest.ExistingFiles.TryGetValue(name, out var existed) && existed)
            {
                await CopyFileAsync(
                    Path.Combine(snapshot, name),
                    target,
                    new CopyBudget(),
                    cancellationToken);
            }
        }
    }

    private static void ValidateSnapshotPayload(string snapshot, SnapshotManifest manifest)
    {
        foreach (var name in ManagedDirectories)
        {
            if (manifest.ExistingDirectories.TryGetValue(name, out var existed) &&
                existed &&
                !Directory.Exists(Path.Combine(snapshot, name)))
            {
                throw new InvalidDataException($"数据恢复点缺少目录：{name}");
            }
        }

        foreach (var name in ManagedFiles)
        {
            if (manifest.ExistingFiles.TryGetValue(name, out var existed) &&
                existed &&
                !File.Exists(Path.Combine(snapshot, name)))
            {
                throw new InvalidDataException($"数据恢复点缺少文件：{name}");
            }
        }
    }

    private static async Task RestoreDirectoryOverlayAsync(
        string source,
        string destination,
        CancellationToken cancellationToken)
    {
        if (Directory.Exists(destination) &&
            (File.GetAttributes(destination) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException($"拒绝向文件系统链接恢复 profile：{destination}");
        }

        Directory.CreateDirectory(destination);
        foreach (var entry in Directory.EnumerateFileSystemEntries(source))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var attributes = File.GetAttributes(entry);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException($"数据恢复点不接受文件系统链接：{entry}");
            }

            var target = Path.Combine(destination, Path.GetFileName(entry));
            if ((attributes & FileAttributes.Directory) != 0)
            {
                await RestoreDirectoryOverlayAsync(entry, target, cancellationToken);
            }
            else
            {
                if (Directory.Exists(target) ||
                    (File.Exists(target) &&
                        (File.GetAttributes(target) & FileAttributes.ReparsePoint) != 0))
                {
                    throw new InvalidDataException($"profile 恢复目标类型冲突：{target}");
                }

                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                await using var input = new FileStream(
                    entry,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    128 * 1024,
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
                await using var output = new FileStream(
                    target,
                    FileMode.Create,
                    FileAccess.Write,
                    FileShare.None,
                    128 * 1024,
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
                await input.CopyToAsync(output, cancellationToken);
            }
        }
    }

    private static string SnapshotRoot()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(localAppData, "Ensou", "DshLauncher", "snapshots");
    }

    private static string ValidateDataRoot(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException("DSH_HOME 必须是绝对路径。");
        }

        var fullPath = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
        var root = Path.GetPathRoot(fullPath)?.TrimEnd(Path.DirectorySeparatorChar);
        if (string.IsNullOrWhiteSpace(root) ||
            string.Equals(fullPath, root, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("DSH_HOME 不能是磁盘根目录。");
        }

        return fullPath;
    }

    private static async Task CopyDirectoryAsync(
        string source,
        string destination,
        bool skipNodeModules,
        CopyBudget budget,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(destination);
        foreach (var entry in Directory.EnumerateFileSystemEntries(source))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var info = File.GetAttributes(entry);
            if ((info & FileAttributes.ReparsePoint) != 0)
            {
                if (skipNodeModules &&
                    string.Equals(Path.GetFileName(entry), "node_modules", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                throw new InvalidDataException($"数据恢复点不接受文件系统链接：{entry}");
            }

            var target = Path.Combine(destination, Path.GetFileName(entry));
            if ((info & FileAttributes.Directory) != 0)
            {
                if (skipNodeModules &&
                    string.Equals(Path.GetFileName(entry), "node_modules", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                await CopyDirectoryAsync(entry, target, skipNodeModules, budget, cancellationToken);
            }
            else
            {
                await CopyFileAsync(entry, target, budget, cancellationToken);
            }
        }
    }

    private static async Task CopyFileAsync(
        string source,
        string destination,
        CopyBudget budget,
        CancellationToken cancellationToken)
    {
        var length = new FileInfo(source).Length;
        budget.AddFile(length);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        await using var input = new FileStream(
            source,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using var output = new FileStream(
            destination,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await input.CopyToAsync(output, cancellationToken);
    }

    private static void DeleteTreeWithoutFollowingLinks(string directory)
    {
        var root = new DirectoryInfo(directory);
        if ((root.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            Directory.Delete(root.FullName);
            return;
        }

        foreach (var entry in root.EnumerateFileSystemInfos())
        {
            if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                if (entry is DirectoryInfo)
                {
                    Directory.Delete(entry.FullName);
                }
                else
                {
                    File.Delete(entry.FullName);
                }
            }
            else if (entry is DirectoryInfo childDirectory)
            {
                DeleteTreeWithoutFollowingLinks(childDirectory.FullName);
            }
            else
            {
                entry.Delete();
            }
        }

        root.Delete();
    }

    private sealed class CopyBudget
    {
        public int FileCount { get; private set; }

        public long TotalBytes { get; private set; }

        public void AddFile(long length)
        {
            FileCount = checked(FileCount + 1);
            TotalBytes = checked(TotalBytes + length);
            if (FileCount > MaximumFiles || TotalBytes > MaximumBytes)
            {
                throw new InvalidDataException("DSH_HOME 数据恢复点超过安全大小上限。");
            }
        }
    }

    private sealed record SnapshotManifest(
        int SchemaVersion,
        string TargetReleaseId,
        string SourceDataDirectory,
        DateTimeOffset CreatedAtUtc,
        IReadOnlyDictionary<string, bool> ExistingDirectories,
        IReadOnlyDictionary<string, bool> ExistingFiles,
        int FileCount,
        long TotalBytes);
}
