using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.Enterprise.Client;

internal static class EnterpriseLocalStateSecurity
{
    public static Task<byte[]> ReadBoundedAsync(
        string exactPath,
        string managedRoot,
        CancellationToken cancellationToken) =>
        WindowsLocalStateSecurity.ReadBoundedAsync(exactPath, managedRoot, cancellationToken);

    public static Task WriteAtomicAsync(
        string exactPath,
        string managedRoot,
        ReadOnlyMemory<byte> bytes,
        bool overwrite,
        CancellationToken cancellationToken) =>
        WindowsLocalStateSecurity.WriteAtomicAsync(
            exactPath,
            managedRoot,
            bytes,
            overwrite,
            cancellationToken);

    public static void DeleteExactFile(string exactPath, string managedRoot) =>
        WindowsLocalStateSecurity.DeleteExactFile(exactPath, managedRoot);

    public static void EnsureSecureDirectory(string directoryPath) =>
        WindowsLocalStateSecurity.EnsureSecureDirectory(directoryPath);
}
