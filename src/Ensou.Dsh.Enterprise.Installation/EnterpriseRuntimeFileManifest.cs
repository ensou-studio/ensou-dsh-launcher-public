using System.Text;
using System.Text.RegularExpressions;

namespace Ensou.Dsh.Enterprise.Installation;

public static partial class EnterpriseRuntimeFileManifest
{
    public const string FileName = "runtime-files.sha256";
    private const int MaximumManifestBytes = 32 * 1024 * 1024;
    private const int MaximumEntries = 250_000;

    public static string ValidateCompleteTree(string runtimeDirectory) =>
        ValidateCompleteTreeCore(
                runtimeDirectory,
                computeCompleteTreeSha256: false,
                observeContentRead: null)
            .RuntimeFilesManifestSha256;

    internal static EnterpriseRuntimeIntegrityValidation ValidateCompleteTreeAndComputeTree(
        string runtimeDirectory) =>
        ValidateCompleteTreeCore(
            runtimeDirectory,
            computeCompleteTreeSha256: true,
            observeContentRead: null);

    internal static EnterpriseRuntimeIntegrityValidation ValidateCompleteTreeAndComputeTree(
        string runtimeDirectory,
        Action<string> observeContentRead) =>
        ValidateCompleteTreeCore(
            runtimeDirectory,
            computeCompleteTreeSha256: true,
            observeContentRead ?? throw new ArgumentNullException(nameof(observeContentRead)));

    private static EnterpriseRuntimeIntegrityValidation ValidateCompleteTreeCore(
        string runtimeDirectory,
        bool computeCompleteTreeSha256,
        Action<string>? observeContentRead)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeDirectory);
        var root = EnterprisePathGuard.NormalizeDirectory(runtimeDirectory);
        var manifestPath = Path.Combine(root, FileName);
        if (!File.Exists(manifestPath)
            || (File.GetAttributes(manifestPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Enterprise runtime has no safe runtime-files.sha256 manifest.");
        }

        // Keep this handle open through the scan. The exact manifest bytes below
        // provide both its tree-file digest and its receipt binding.
        using var manifestStream = new FileStream(
            manifestPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.SequentialScan);
        if (manifestStream.Length is <= 0 or > MaximumManifestBytes)
        {
            throw new InvalidDataException(
                "Enterprise runtime file manifest is not bounded ASCII.");
        }
        var manifestBytes = new byte[checked((int)manifestStream.Length)];
        manifestStream.ReadExactly(manifestBytes);
        observeContentRead?.Invoke(FileName);
        if (manifestBytes.Any(value => value > 0x7f))
        {
            throw new InvalidDataException(
                "Enterprise runtime file manifest is not bounded ASCII.");
        }

        var expected = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var text = Encoding.ASCII.GetString(manifestBytes);
        var lines = text.Split('\n');
        for (var index = 0; index < lines.Length; index++)
        {
            var rawLine = lines[index];
            var line = rawLine.EndsWith('\r') ? rawLine[..^1] : rawLine;
            if (line.Length == 0 && index == lines.Length - 1)
            {
                continue;
            }
            var match = RuntimeFileLineRegex().Match(line);
            if (!match.Success)
            {
                throw new InvalidDataException(
                    "Enterprise runtime file manifest has a malformed line.");
            }
            var relative = match.Groups["path"].Value;
            ValidateRelativePath(relative);
            if (!expected.TryAdd(relative, match.Groups["hash"].Value))
            {
                throw new InvalidDataException(
                    "Enterprise runtime file manifest repeats a path.");
            }
            if (expected.Count > MaximumEntries)
            {
                throw new InvalidDataException(
                    "Enterprise runtime file manifest has too many entries.");
            }
        }
        if (expected.Count == 0)
        {
            throw new InvalidDataException("Enterprise runtime file manifest is empty.");
        }

        var actualPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        List<(string RelativePath, byte[] Sha256)>? treeFiles =
            computeCompleteTreeSha256 ? [] : null;
        var manifestSha256 = System.Security.Cryptography.SHA256.HashData(manifestBytes);
        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Enterprise runtime tree contains a filesystem link.");
            }
            var relative = Path.GetRelativePath(root, file).Replace('\\', '/');
            var excludedFromManifest = IsManifestExcluded(relative);
            var includedInCompleteTree = !EnterpriseTreeHash.IsInstallerReceipt(relative);
            byte[]? fileSha256 = null;
            if (includedInCompleteTree || !excludedFromManifest)
            {
                if (string.Equals(relative, FileName, StringComparison.Ordinal))
                {
                    fileSha256 = manifestSha256;
                }
                else
                {
                    using var stream = new FileStream(
                        file,
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.Read,
                        128 * 1024,
                        FileOptions.SequentialScan);
                    fileSha256 = System.Security.Cryptography.SHA256.HashData(stream);
                    observeContentRead?.Invoke(relative);
                }
            }
            if (includedInCompleteTree && treeFiles is not null)
            {
                treeFiles.Add((relative, fileSha256!));
            }

            // These are the only legacy runtime-manifest exclusions. Launcher
            // and plugin receipts remain ordinary manifest-bound files even
            // though the complete-tree digest excludes every receipt kind.
            if (excludedFromManifest)
            {
                continue;
            }
            if (!actualPaths.Add(relative)
                || !expected.TryGetValue(relative, out var expectedHash))
            {
                throw new InvalidDataException(
                    $"Enterprise runtime contains an unlisted file: {relative}");
            }
            if (!string.Equals(
                    Convert.ToHexStringLower(fileSha256!),
                    expectedHash,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Enterprise runtime file hash mismatch: {relative}");
            }
        }

        var missing = expected.Keys.FirstOrDefault(path => !actualPaths.Contains(path));
        if (missing is not null)
        {
            throw new InvalidDataException(
                $"Enterprise runtime file manifest references a missing file: {missing}");
        }
        return new EnterpriseRuntimeIntegrityValidation(
            treeFiles is null
                ? string.Empty
                : EnterpriseTreeHash.ComputeFromFileHashes(treeFiles),
            Convert.ToHexStringLower(manifestSha256));
    }

    private static bool IsManifestExcluded(string relativePath) =>
        relativePath is FileName
            or ".ensou-enterprise-runtime.json"
            or EnterpriseTreeHash.ReceiptFileName;

    private static void ValidateRelativePath(string relative)
    {
        if (string.IsNullOrWhiteSpace(relative)
            || relative.Length > 1024
            || relative.Contains('\\')
            || relative.StartsWith('/')
            || relative.EndsWith('/')
            || string.Equals(relative, FileName, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Enterprise runtime file manifest contains an unsafe path.");
        }
        var segments = relative.Split('/');
        foreach (var segment in segments)
        {
            if (segment is "" or "." or ".."
                || segment.EndsWith(' ')
                || segment.EndsWith('.')
                || segment.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            {
                throw new InvalidDataException(
                    "Enterprise runtime file manifest contains an unsafe path segment.");
            }
        }
    }

    [GeneratedRegex(
        "^(?<hash>[0-9a-f]{64})  (?<path>[^\\r\\n]+)$",
        RegexOptions.CultureInvariant)]
    private static partial Regex RuntimeFileLineRegex();
}

internal sealed record EnterpriseRuntimeIntegrityValidation(
    string CompleteTreeSha256,
    string RuntimeFilesManifestSha256);
