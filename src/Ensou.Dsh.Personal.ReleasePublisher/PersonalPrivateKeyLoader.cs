using System.Security.Cryptography;

namespace Ensou.Dsh.Personal.ReleasePublisher;

internal static class PersonalPrivateKeyLoader
{
    private const int MaximumPkcs8Bytes = 64 * 1024;

    public static async Task<ECDsa> LoadAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException("Personal signing key path must be absolute.");
        }
        var full = Path.GetFullPath(path);
        RejectLinkAncestors(Path.GetDirectoryName(full)!);
        if (!File.Exists(full)
            || (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
        {
            throw new FileNotFoundException(
                "Personal signing key is missing or linked.",
                full);
        }
        var info = new FileInfo(full);
        if (info.Length is <= 0 or > MaximumPkcs8Bytes)
        {
            throw new InvalidDataException("Personal PKCS#8 signing key size is invalid.");
        }

        byte[] keyBytes;
        await using (var stream = new FileStream(
                         full,
                         FileMode.Open,
                         FileAccess.Read,
                         FileShare.Read,
                         64 * 1024,
                         FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            keyBytes = new byte[checked((int)stream.Length)];
            await stream.ReadExactlyAsync(keyBytes, cancellationToken).ConfigureAwait(false);
            if (stream.ReadByte() != -1 || stream.Length != keyBytes.LongLength)
            {
                CryptographicOperations.ZeroMemory(keyBytes);
                throw new IOException("Personal signing key changed while it was read.");
            }
        }

        var key = ECDsa.Create();
        try
        {
            key.ImportPkcs8PrivateKey(keyBytes, out var bytesRead);
            if (bytesRead != keyBytes.Length)
            {
                throw new InvalidDataException(
                    "Personal signing key contains trailing PKCS#8 data.");
            }
            var parameters = key.ExportParameters(includePrivateParameters: false);
            if (parameters.Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
            {
                throw new InvalidDataException("Personal signing key must use P-256.");
            }
            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }
    }

    private static void RejectLinkAncestors(string path)
    {
        for (var current = new DirectoryInfo(Path.GetFullPath(path));
             current is not null;
             current = current.Parent)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Personal signing key path may not cross a filesystem link.");
            }
        }
    }
}
