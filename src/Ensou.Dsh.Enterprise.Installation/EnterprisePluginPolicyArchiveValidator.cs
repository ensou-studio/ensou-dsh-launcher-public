using System.IO.Compression;
using System.Security.Cryptography;

namespace Ensou.Dsh.Enterprise.Installation;

public sealed record EnterprisePluginPolicyArchiveInspection(
    string PolicyId,
    long Generation,
    string PolicySha256,
    long PolicySizeBytes,
    string ArchiveSha256,
    long ArchiveSizeBytes,
    IReadOnlyList<string> LauncherReleaseIds,
    IReadOnlyList<string> RuntimeReleaseIds,
    bool Critical,
    IReadOnlyList<EnterprisePluginSkillPackInspection> SkillPacks);

public sealed record EnterprisePluginSkillPackInspection(
    string SkillId,
    string Version,
    string Root,
    string DeclaredTreeSha256);

public static class EnterprisePluginPolicyArchiveValidator
{
    private const int MaximumEntries = 10_001;
    private const long MaximumExpandedBytes = 516L * 1024 * 1024;
    private const int MaximumPolicyBytes = 4 * 1024 * 1024;

    public static EnterprisePluginPolicyArchiveInspection Validate(
        string archivePath,
        string launcherReleaseId,
        string runtimeReleaseId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);
        EnterprisePathGuard.ValidateReleaseId(launcherReleaseId);
        EnterprisePathGuard.ValidateReleaseId(runtimeReleaseId);
        var fullPath = Path.GetFullPath(archivePath);
        var archiveInfo = new FileInfo(fullPath);
        if (!Path.IsPathFullyQualified(archivePath)
            || !File.Exists(fullPath)
            || (File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0
            || archiveInfo.Length is <= 0 or > MaximumExpandedBytes + 16L * 1024 * 1024)
        {
            throw new InvalidDataException(
                "Enterprise plugin-policy archive must be an existing absolute regular file.");
        }

        using var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.SequentialScan);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        if (archive.Entries.Count is <= 0 or > MaximumEntries)
        {
            throw new InvalidDataException(
                "Enterprise plugin-policy archive entry count is invalid.");
        }

        var entries = new Dictionary<string, ZipArchiveEntry>(
            StringComparer.OrdinalIgnoreCase);
        long expandedBytes = 0;
        foreach (var entry in archive.Entries)
        {
            var path = ValidateEntry(entry);
            if (!entries.TryAdd(path, entry))
            {
                throw new InvalidDataException(
                    "Enterprise plugin-policy archive has duplicate or case-colliding paths.");
            }
            expandedBytes = checked(expandedBytes + entry.Length);
            if (expandedBytes > MaximumExpandedBytes)
            {
                throw new InvalidDataException(
                    "Enterprise plugin-policy archive expands beyond its limit.");
            }
        }

        if (!entries.TryGetValue(
                EnterprisePluginPolicyContract.PolicyFileName,
                out var policyEntry)
            || !string.Equals(
                policyEntry.FullName,
                EnterprisePluginPolicyContract.PolicyFileName,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise plugin-policy archive is missing root plugin-policy.json.");
        }
        var policyBytes = ReadEntry(policyEntry, MaximumPolicyBytes);
        var policy = EnterprisePluginPolicy.Parse(policyBytes);
        policy.RequireCompatible(launcherReleaseId, runtimeReleaseId);
        if (policy.Revoked)
        {
            throw new InvalidDataException(
                "Enterprise plugin-policy archive contains a revoked policy.");
        }

        var expected = policy.SkillPacks
            .SelectMany(pack => pack.Files)
            .ToDictionary(file => file.Path, StringComparer.OrdinalIgnoreCase);
        if (entries.Count != expected.Count + 1)
        {
            throw new InvalidDataException(
                "Enterprise plugin-policy archive contains missing or unexpected files.");
        }
        foreach (var pair in entries)
        {
            if (string.Equals(
                    pair.Key,
                    EnterprisePluginPolicyContract.PolicyFileName,
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            if (!expected.TryGetValue(pair.Key, out var declared)
                || !string.Equals(pair.Key, declared.Path, StringComparison.Ordinal)
                || pair.Value.Length != declared.SizeBytes
                || !string.Equals(
                    HashEntry(pair.Value),
                    declared.Sha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Enterprise plugin-policy archive file bytes do not match policy declarations.");
            }
        }

        return new EnterprisePluginPolicyArchiveInspection(
            policy.PolicyId,
            policy.Generation,
            Convert.ToHexStringLower(SHA256.HashData(policyBytes)),
            policyBytes.LongLength,
            EnterpriseHash.ComputeFile(fullPath),
            archiveInfo.Length,
            policy.Compatibility.LauncherReleaseIds.ToArray(),
            policy.Compatibility.RuntimeReleaseIds.ToArray(),
            policy.Critical,
            policy.SkillPacks
                .OrderBy(pack => pack.SkillId, StringComparer.Ordinal)
                .Select(pack => new EnterprisePluginSkillPackInspection(
                    pack.SkillId,
                    pack.Version,
                    pack.Root,
                    ComputeDeclaredTree(pack)))
                .ToArray());
    }

    private static string ComputeDeclaredTree(EnterprisePluginSkillPack pack)
    {
        using var aggregate = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var file in pack.Files.OrderBy(file => file.Path, StringComparer.Ordinal))
        {
            Append(aggregate, file.Path);
            Append(aggregate, file.SizeBytes.ToString(
                System.Globalization.CultureInfo.InvariantCulture));
            Append(aggregate, file.Sha256);
        }
        return Convert.ToHexStringLower(aggregate.GetHashAndReset());
    }

    private static void Append(IncrementalHash hash, string value)
    {
        hash.AppendData(System.Text.Encoding.UTF8.GetBytes(value));
        hash.AppendData([0]);
    }

    private static string ValidateEntry(ZipArchiveEntry entry)
    {
        if ((entry.ExternalAttributes & (int)FileAttributes.ReparsePoint) != 0
            || ((entry.ExternalAttributes >> 16) & 0xF000) == 0xA000
            || string.IsNullOrWhiteSpace(entry.FullName)
            || entry.FullName.Contains('\\')
            || entry.FullName.EndsWith("/", StringComparison.Ordinal)
            || string.IsNullOrEmpty(entry.Name))
        {
            throw new InvalidDataException(
                "Enterprise plugin-policy archive contains a link, directory, or non-canonical path.");
        }
        EnterprisePluginPolicy.ValidateRelativePath(entry.FullName, "archive entry");
        return entry.FullName;
    }

    private static byte[] ReadEntry(ZipArchiveEntry entry, int maximumBytes)
    {
        if (entry.Length is <= 0 || entry.Length > maximumBytes)
        {
            throw new InvalidDataException(
                "Enterprise plugin-policy entry size is invalid.");
        }
        using var input = entry.Open();
        using var output = new MemoryStream(checked((int)entry.Length));
        input.CopyTo(output);
        if (output.Length != entry.Length)
        {
            throw new InvalidDataException(
                "Enterprise plugin-policy entry length changed while reading.");
        }
        return output.ToArray();
    }

    private static string HashEntry(ZipArchiveEntry entry)
    {
        using var input = entry.Open();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[128 * 1024];
        long total = 0;
        while (true)
        {
            var read = input.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                break;
            }
            total = checked(total + read);
            if (total > entry.Length)
            {
                throw new InvalidDataException(
                    "Enterprise plugin-policy entry exceeded its declared length.");
            }
            hash.AppendData(buffer, 0, read);
        }
        if (total != entry.Length)
        {
            throw new InvalidDataException(
                "Enterprise plugin-policy entry length changed while hashing.");
        }
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }
}
