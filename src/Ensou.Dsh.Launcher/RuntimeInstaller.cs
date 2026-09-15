using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;

namespace Ensou.Dsh.Launcher;

internal sealed record RuntimeInstallResult(
    string ReleaseId,
    string RuntimeDirectory,
    string? PreviousRuntimeDirectory);

internal static class RuntimeInstaller
{
    private const int MaximumEntries = 200_000;
    private const long MaximumExpandedBytes = 8L * 1024 * 1024 * 1024;

    public static async Task<RuntimeInstallResult> InstallAsync(
        LauncherSettings settings,
        UpdateCheckOutcome outcome,
        string packagePath,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ValidateReleaseId(outcome.ReleaseId);
        if (!File.Exists(packagePath))
        {
            throw new FileNotFoundException("已验证的更新包不存在。", packagePath);
        }

        var runtimeRoot = settings.GetRuntimeRootDirectory();
        Directory.CreateDirectory(runtimeRoot);
        var finalDirectory = Path.Combine(runtimeRoot, outcome.ReleaseId);
        var stagingDirectory = Path.Combine(runtimeRoot, $".{outcome.ReleaseId}.staging-{Guid.NewGuid():N}");

        try
        {
            if (!Directory.Exists(finalDirectory))
            {
                Directory.CreateDirectory(stagingDirectory);
                await using var packageStream = new FileStream(
                    packagePath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    bufferSize: 128 * 1024,
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
                await VerifyLockedPackageAsync(packageStream, outcome, cancellationToken);
                packageStream.Position = 0;
                using var archive = new ZipArchive(packageStream, ZipArchiveMode.Read, leaveOpen: true);
                await ExtractSafelyAsync(archive, stagingDirectory, progress, cancellationToken);
                ValidateRuntime(stagingDirectory);
                await WriteReleaseMarkerAsync(stagingDirectory, outcome, cancellationToken);
                Directory.Move(stagingDirectory, finalDirectory);
            }
            else
            {
                await ValidateExistingReleaseAsync(finalDirectory, outcome, cancellationToken);
            }

            var previous = RuntimePointer.TryRead(RuntimePointer.StatePath());
            var next = new RuntimePointer(
                SchemaVersion: 1,
                ReleaseId: outcome.ReleaseId,
                RuntimeDirectory: finalDirectory,
                PreviousReleaseId: previous?.ReleaseId,
                PreviousRuntimeDirectory: previous?.RuntimeDirectory,
                PendingHealthValidation: true,
                SnapshotDirectory: null,
                UpdatedAtUtc: DateTimeOffset.UtcNow);
            RuntimePointer.WriteAtomically(next);
            progress?.Report(1);

            return new RuntimeInstallResult(
                outcome.ReleaseId,
                finalDirectory,
                previous?.RuntimeDirectory);
        }
        catch
        {
            if (Directory.Exists(stagingDirectory))
            {
                Directory.Delete(stagingDirectory, recursive: true);
            }

            throw;
        }
    }

    private static async Task ExtractSafelyAsync(
        ZipArchive archive,
        string stagingDirectory,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        if (archive.Entries.Count > MaximumEntries)
        {
            throw new InvalidDataException("更新包文件数量超过安全上限。");
        }

        var totalExpandedBytes = archive.Entries.Sum(static entry => entry.Length);
        if (totalExpandedBytes <= 0 || totalExpandedBytes > MaximumExpandedBytes)
        {
            throw new InvalidDataException("更新包解压后大小超出安全范围。");
        }

        var destinationRoot = Path.GetFullPath(stagingDirectory) + Path.DirectorySeparatorChar;
        var extractedBytes = 0L;
        foreach (var entry in archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RejectLinkEntry(entry);

            var destinationPath = Path.GetFullPath(Path.Combine(stagingDirectory, entry.FullName));
            if (!destinationPath.StartsWith(destinationRoot, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("更新包包含越界路径。");
            }

            if (string.IsNullOrEmpty(entry.Name))
            {
                Directory.CreateDirectory(destinationPath);
                continue;
            }

            var parent = Path.GetDirectoryName(destinationPath)
                ?? throw new InvalidDataException("更新包文件路径无效。");
            Directory.CreateDirectory(parent);
            await using var input = entry.Open();
            await using var output = new FileStream(
                destinationPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            await input.CopyToAsync(output, cancellationToken);
            extractedBytes += entry.Length;
            progress?.Report(0.95 * extractedBytes / totalExpandedBytes);
        }
    }

    private static async Task VerifyLockedPackageAsync(
        FileStream packageStream,
        UpdateCheckOutcome outcome,
        CancellationToken cancellationToken)
    {
        if (packageStream.Length != outcome.ArtifactSizeBytes)
        {
            throw new InvalidDataException("更新包在安装前大小发生变化，已拒绝解压。");
        }

        var actualHash = await SHA256.HashDataAsync(packageStream, cancellationToken);
        byte[] expectedHash;
        try
        {
            expectedHash = Convert.FromHexString(outcome.ArtifactSha256);
        }
        catch (FormatException)
        {
            throw new InvalidDataException("更新清单中的 SHA-256 无效。");
        }

        if (expectedHash.Length != 32 ||
            !CryptographicOperations.FixedTimeEquals(expectedHash, actualHash))
        {
            throw new InvalidDataException("更新包在安装前内容发生变化，已拒绝解压。");
        }
    }

    private static void RejectLinkEntry(ZipArchiveEntry entry)
    {
        var unixFileType = (entry.ExternalAttributes >> 16) & 0xF000;
        if (unixFileType is not (0 or 0x4000 or 0x8000))
        {
            throw new InvalidDataException("更新包不得包含链接或特殊设备文件。");
        }

        if (entry.FullName.Contains(':'))
        {
            throw new InvalidDataException("更新包不得包含 NTFS 数据流路径。");
        }
    }

    private static void ValidateRuntime(string directory)
    {
        var nodePath = Path.Combine(directory, "node.exe");
        var entryPoint = Path.Combine(
            directory,
            "node_modules",
            "@deepseek-ai",
            "dsh",
            "lib",
            "bin.js");
        if (!File.Exists(nodePath) || !File.Exists(entryPoint))
        {
            throw new InvalidDataException("更新包不是完整的 Windows DSH 运行时。");
        }
    }

    private static async Task WriteReleaseMarkerAsync(
        string directory,
        UpdateCheckOutcome outcome,
        CancellationToken cancellationToken)
    {
        var marker = new RuntimeReleaseMarker(
            1,
            outcome.ReleaseId,
            outcome.AvailableVersion,
            outcome.ArtifactSha256,
            DateTimeOffset.UtcNow);
        var json = JsonSerializer.Serialize(marker, new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            WriteIndented = true
        });
        await File.WriteAllTextAsync(
            Path.Combine(directory, ".ensou-release.json"),
            json,
            cancellationToken);
    }

    private static async Task ValidateExistingReleaseAsync(
        string directory,
        UpdateCheckOutcome outcome,
        CancellationToken cancellationToken)
    {
        var markerPath = Path.Combine(directory, ".ensou-release.json");
        if (!File.Exists(markerPath))
        {
            throw new InvalidDataException("同名运行时目录已存在，但缺少发布标记，拒绝覆盖。");
        }

        var marker = JsonSerializer.Deserialize<RuntimeReleaseMarker>(
            await File.ReadAllTextAsync(markerPath, cancellationToken),
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        if (marker is null ||
            !string.Equals(marker.ReleaseId, outcome.ReleaseId, StringComparison.Ordinal) ||
            !string.Equals(marker.ArtifactSha256, outcome.ArtifactSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException("同一 releaseId 对应不同制品，已按不可变发布规则拒绝。");
        }

        ValidateRuntime(directory);
    }

    private static void ValidateReleaseId(string releaseId)
    {
        if (string.IsNullOrWhiteSpace(releaseId) ||
            releaseId is "." or ".." ||
            releaseId.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
            releaseId.IndexOfAny(['/', '\\']) >= 0)
        {
            throw new InvalidDataException("releaseId 不能用作安全的版本目录名。");
        }
    }

    private sealed record RuntimeReleaseMarker(
        int SchemaVersion,
        string ReleaseId,
        string DshVersion,
        string ArtifactSha256,
        DateTimeOffset InstalledAtUtc);
}
