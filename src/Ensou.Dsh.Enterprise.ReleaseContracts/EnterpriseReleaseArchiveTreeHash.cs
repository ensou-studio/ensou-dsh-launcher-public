using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace Ensou.Dsh.Enterprise.Installation;

/// <summary>
/// Computes the immutable installed-tree identity directly from a release ZIP.
/// The publisher signs this value and the installer later compares the extracted
/// tree against it, so user-writable installation receipts are never the trust
/// root for component reuse.
/// </summary>
public static class EnterpriseReleaseArchiveTreeHash
{
    private const int MaximumArchiveEntries = 200_000;
    private const long MaximumExpandedArchiveBytes = 8L * 1024 * 1024 * 1024;

    public static string Compute(Stream archiveStream)
    {
        ArgumentNullException.ThrowIfNull(archiveStream);
        if (!archiveStream.CanRead)
        {
            throw new InvalidDataException("Enterprise release archive is not readable.");
        }

        using var archive = new ZipArchive(
            archiveStream,
            ZipArchiveMode.Read,
            leaveOpen: true);
        if (archive.Entries.Count is <= 0 or > MaximumArchiveEntries)
        {
            throw new InvalidDataException(
                "Enterprise release archive entry count is invalid.");
        }

        var files = new List<(string RelativePath, byte[] Sha256)>(archive.Entries.Count);
        var canonicalPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long expandedBytes = 0;
        foreach (var entry in archive.Entries)
        {
            var relative = ValidateArchiveEntry(entry);
            if (!canonicalPaths.Add(relative))
            {
                throw new InvalidDataException(
                    "Enterprise release archive repeats a canonical path.");
            }
            try
            {
                expandedBytes = checked(expandedBytes + entry.Length);
            }
            catch (OverflowException exception)
            {
                throw new InvalidDataException(
                    "Enterprise release archive expands beyond its bound.",
                    exception);
            }
            if (expandedBytes > MaximumExpandedArchiveBytes)
            {
                throw new InvalidDataException(
                    "Enterprise release archive expands beyond its bound.");
            }
            if (relative.EndsWith("/", StringComparison.Ordinal))
            {
                continue;
            }
            if (IsInstallerReceipt(relative))
            {
                throw new InvalidDataException(
                    "Enterprise release archives may not supply installer-owned receipt files.");
            }

            using var entryStream = entry.Open();
            files.Add((relative, SHA256.HashData(entryStream)));
        }

        using var aggregate = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var file in files.OrderBy(
                     file => file.RelativePath,
                     StringComparer.Ordinal))
        {
            aggregate.AppendData(Encoding.UTF8.GetBytes(file.RelativePath));
            aggregate.AppendData([0]);
            aggregate.AppendData(file.Sha256);
            aggregate.AppendData([0]);
        }
        return Convert.ToHexStringLower(aggregate.GetHashAndReset());
    }

    private static string ValidateArchiveEntry(ZipArchiveEntry entry)
    {
        if ((entry.ExternalAttributes & (int)FileAttributes.ReparsePoint) != 0
            || ((entry.ExternalAttributes >> 16) & 0xF000) == 0xA000)
        {
            throw new InvalidDataException(
                "Enterprise release archive contains a filesystem link.");
        }
        var normalized = entry.FullName.Replace('\\', '/');
        if (string.IsNullOrWhiteSpace(normalized)
            || normalized.StartsWith("/", StringComparison.Ordinal)
            || normalized.Length > 1024)
        {
            throw new InvalidDataException(
                "Enterprise release archive entry path is invalid.");
        }
        var isDirectory = normalized.EndsWith("/", StringComparison.Ordinal);
        var segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0)
        {
            throw new InvalidDataException(
                "Enterprise release archive path is empty.");
        }
        foreach (var segment in segments)
        {
            var firstName = segment.Split('.', 2)[0];
            if (segment is "." or ".."
                || segment.EndsWith(' ')
                || segment.EndsWith('.')
                || segment.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0
                || firstName.Equals("CON", StringComparison.OrdinalIgnoreCase)
                || firstName.Equals("PRN", StringComparison.OrdinalIgnoreCase)
                || firstName.Equals("AUX", StringComparison.OrdinalIgnoreCase)
                || firstName.Equals("NUL", StringComparison.OrdinalIgnoreCase)
                || (firstName.Length == 4
                    && firstName[..3].Equals("COM", StringComparison.OrdinalIgnoreCase)
                    && firstName[3] is >= '1' and <= '9')
                || (firstName.Length == 4
                    && firstName[..3].Equals("LPT", StringComparison.OrdinalIgnoreCase)
                    && firstName[3] is >= '1' and <= '9'))
            {
                throw new InvalidDataException(
                    "Enterprise release archive has an unsafe path segment.");
            }
        }
        return string.Join('/', segments) + (isDirectory ? "/" : string.Empty);
    }

    private static bool IsInstallerReceipt(string relativePath) =>
        relativePath is ".ensou-enterprise-launcher.json"
            or ".ensou-enterprise-runtime.json"
            or ".ensou-enterprise-plugin-policy.v2.json"
            or ".ensou-enterprise-artifact.v2.json";
}
