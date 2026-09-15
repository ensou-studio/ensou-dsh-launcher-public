using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.UpdateEngine;

public sealed record PersonalProductionPayloadExpectation(
    string ReleaseSetId,
    string RawManifestSha256,
    long ManifestSizeBytes,
    string StartupStubSha256,
    long StartupStubSizeBytes,
    string ClientBundleSha256,
    long ClientBundleSizeBytes,
    string RuntimeSha256,
    long RuntimeSizeBytes)
{
    public static PersonalProductionPayloadExpectation Parse(
        IReadOnlyList<string> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Count != 9)
        {
            throw new ArgumentException(
                "Personal production payload self-check requires releaseSetId plus exact manifest, Startup Stub, client, and Runtime size/hash values.");
        }
        PersonalReleaseSetValidator.ValidateReleaseId(values[0], "self-check releaseSetId");
        return new PersonalProductionPayloadExpectation(
            values[0],
            RequireSha256(values[1], "manifest"),
            RequireSize(values[2], "manifest"),
            RequireSha256(values[3], "Startup Stub"),
            RequireSize(values[4], "Startup Stub"),
            RequireSha256(values[5], "client bundle"),
            RequireSize(values[6], "client bundle"),
            RequireSha256(values[7], "Runtime"),
            RequireSize(values[8], "Runtime"));
    }

    private static string RequireSha256(string value, string label) =>
        PersonalReleaseSetValidator.IsSha256(value)
            ? value
            : throw new InvalidDataException(
                $"Personal production payload {label} SHA-256 is invalid.");

    private static long RequireSize(string value, string label) =>
        long.TryParse(
            value,
            System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture,
            out var parsed)
        && parsed > 0
            ? parsed
            : throw new InvalidDataException(
                $"Personal production payload {label} size is invalid.");
}

public static class PersonalInstallerPayloadSelfCheck
{
    public static async Task VerifyDevelopmentPayloadAsync(
        IPersonalInstallerPayloadSource payload,
        PersonalInstallerTrustConfiguration trust,
        PersonalInstallerExecutableLease installerExecutableLease,
        PersonalProductionPayloadExpectation expected,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentNullException.ThrowIfNull(installerExecutableLease);
        ArgumentNullException.ThrowIfNull(expected);
        if (trust.ProductionBuild)
        {
            throw new InvalidOperationException(
                "Personal development payload self-check refuses a production Installer.");
        }
        using var retainedInstallerIdentity = installerExecutableLease.Retain();
        await VerifyPayloadCoreAsync(payload, trust, expected, cancellationToken)
            .ConfigureAwait(false);
        installerExecutableLease.RequireLive();
    }

    public static async Task VerifyProductionPayloadAsync(
        IPersonalInstallerPayloadSource payload,
        PersonalInstallerTrustConfiguration trust,
        PersonalInstallerExecutableLease installerExecutableLease,
        PersonalProductionPayloadExpectation expected,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentNullException.ThrowIfNull(installerExecutableLease);
        ArgumentNullException.ThrowIfNull(expected);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Personal production payload self-check requires Windows Authenticode.");
        }
        if (!trust.ProductionBuild)
        {
            throw new InvalidOperationException(
                "Personal production payload self-check refuses a development Installer.");
        }
        using var retainedInstallerIdentity = installerExecutableLease.Retain();
        await VerifyPayloadCoreAsync(payload, trust, expected, cancellationToken)
            .ConfigureAwait(false);
        installerExecutableLease.RequireLive();
    }

    internal static Task VerifyPayloadForTestsAsync(
        IPersonalInstallerPayloadSource payload,
        PersonalInstallerTrustConfiguration trust,
        PersonalProductionPayloadExpectation expected,
        CancellationToken cancellationToken = default) =>
        VerifyPayloadCoreAsync(payload, trust, expected, cancellationToken);

    private static async Task VerifyPayloadCoreAsync(
        IPersonalInstallerPayloadSource payload,
        PersonalInstallerTrustConfiguration trust,
        PersonalProductionPayloadExpectation expected,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentNullException.ThrowIfNull(expected);
        var manifestBytes = await ReadExactAsync(
                payload.OpenSignedReleaseManifest(),
                expected.ManifestSizeBytes,
                2L * 1024 * 1024,
                cancellationToken)
            .ConfigureAwait(false);
        try
        {
            RequireHash(manifestBytes, expected.RawManifestSha256, "manifest");
            var verified = PersonalReleaseSetValidator.ParseAndVerify(
                manifestBytes,
                trust.ReleasePolicy,
                DateTimeOffset.UtcNow);
            if (!string.Equals(
                    verified.Manifest.ReleaseSetId,
                    expected.ReleaseSetId,
                    StringComparison.Ordinal)
                || !string.Equals(
                    verified.Manifest.ClientBundle.Sha256,
                    expected.ClientBundleSha256,
                    StringComparison.Ordinal)
                || verified.Manifest.ClientBundle.SizeBytes != expected.ClientBundleSizeBytes
                || !string.Equals(
                    verified.Manifest.Runtime.Sha256,
                    expected.RuntimeSha256,
                    StringComparison.Ordinal)
                || verified.Manifest.Runtime.SizeBytes != expected.RuntimeSizeBytes)
            {
                throw new InvalidDataException(
                    "Personal production payload expectation differs from its signed manifest.");
            }

            var root = Path.Combine(
                Path.GetTempPath(),
                $"ensou-personal-installer-self-check-{Guid.NewGuid():N}");
            Directory.CreateDirectory(root);
            RejectLinkedPath(root);
            try
            {
                var stubPath = Path.Combine(
                    root,
                    PersonalInstallationLayout.StartupStubExecutableName);
                var clientPath = Path.Combine(root, "client-bundle.zip");
                var runtimePath = Path.Combine(root, "runtime.zip");
                await WriteExactAsync(
                        stubPath,
                        payload.OpenStartupStub(),
                        expected.StartupStubSizeBytes,
                        expected.StartupStubSha256,
                        512L * 1024 * 1024,
                        cancellationToken)
                    .ConfigureAwait(false);
                await WriteExactAsync(
                        clientPath,
                        payload.OpenClientBundleArchive(),
                        expected.ClientBundleSizeBytes,
                        expected.ClientBundleSha256,
                        4L * 1024 * 1024 * 1024,
                        cancellationToken)
                    .ConfigureAwait(false);
                await WriteExactAsync(
                        runtimePath,
                        payload.OpenRuntimeArchive(),
                        expected.RuntimeSizeBytes,
                        expected.RuntimeSha256,
                        8L * 1024 * 1024 * 1024,
                        cancellationToken)
                    .ConfigureAwait(false);
                PersonalAuthenticodeVerifier.RequireTrustedEnsouExecutable(stubPath);
                if (trust.ProductionBuild)
                {
                    _ = PersonalCompiledTrustProcessVerifier.RequireExecutable(
                        stubPath,
                        PersonalInstallationLayout.StartupStubExecutableName,
                        PersonalCompiledTrustFingerprint.Create(trust));
                }

                var clientTree = ExtractCompleteTree(
                    clientPath,
                    root,
                    "client-complete-tree.json");
                var runtimeTree = ExtractCompleteTree(
                    runtimePath,
                    root,
                    "runtime-complete-tree.json");
                _ = await PersonalReleaseArtifactInstaller.VerifyCandidateArchiveAsync(
                        clientPath,
                        clientTree,
                        PersonalReleaseSetContract.ClientBundleComponent,
                        verified.Manifest.ClientBundle.ReleaseId,
                        cancellationToken)
                    .ConfigureAwait(false);
                _ = await PersonalReleaseArtifactInstaller.VerifyCandidateArchiveAsync(
                        runtimePath,
                        runtimeTree,
                        PersonalReleaseSetContract.RuntimeComponent,
                        verified.Manifest.Runtime.ReleaseId,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                DeleteTemporaryTree(root);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(manifestBytes);
        }
    }

    private static async Task<byte[]> ReadExactAsync(
        Stream source,
        long expectedSize,
        long maximumSize,
        CancellationToken cancellationToken)
    {
        await using (source.ConfigureAwait(false))
        {
            if (expectedSize <= 0 || expectedSize > maximumSize || expectedSize > int.MaxValue)
            {
                throw new InvalidDataException(
                    "Personal production payload expected size is unbounded.");
            }
            using var output = new MemoryStream((int)expectedSize);
            var buffer = new byte[128 * 1024];
            long total = 0;
            while (true)
            {
                var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }
                total = checked(total + read);
                if (total > expectedSize || total > maximumSize)
                {
                    throw new InvalidDataException(
                        "Personal production payload resource exceeded its exact size.");
                }
                output.Write(buffer, 0, read);
            }
            if (total != expectedSize)
            {
                throw new InvalidDataException(
                    "Personal production payload resource size is not exact.");
            }
            return output.ToArray();
        }
    }

    private static async Task WriteExactAsync(
        string path,
        Stream source,
        long expectedSize,
        string expectedSha256,
        long maximumSize,
        CancellationToken cancellationToken)
    {
        await using (source.ConfigureAwait(false))
        await using (var output = new FileStream(
                         path,
                         FileMode.CreateNew,
                         FileAccess.Write,
                         FileShare.None,
                         128 * 1024,
                         FileOptions.Asynchronous | FileOptions.WriteThrough))
        using (var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            var buffer = new byte[128 * 1024];
            long total = 0;
            while (true)
            {
                var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }
                total = checked(total + read);
                if (total > expectedSize || total > maximumSize)
                {
                    throw new InvalidDataException(
                        "Personal production payload resource exceeded its exact size.");
                }
                digest.AppendData(buffer, 0, read);
                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken)
                    .ConfigureAwait(false);
            }
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            output.Flush(flushToDisk: true);
            var actualSha256 = Convert.ToHexStringLower(digest.GetHashAndReset());
            if (total != expectedSize
                || !string.Equals(actualSha256, expectedSha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Personal production payload resource size or SHA-256 is not exact.");
            }
        }
        PersonalPathGuard.RequireSingleLinkFile(path);
    }

    private static string ExtractCompleteTree(
        string archivePath,
        string root,
        string fileName)
    {
        using var archive = ZipFile.OpenRead(archivePath);
        var entries = archive.Entries.Where(entry => string.Equals(
                entry.FullName,
                ".ensou-complete-tree.v1.json",
                StringComparison.Ordinal))
            .ToArray();
        if (entries.Length != 1 || entries[0].Length is <= 0 or > 64L * 1024 * 1024)
        {
            throw new InvalidDataException(
                "Personal production archive has no unique bounded complete-tree manifest.");
        }
        var path = Path.Combine(root, fileName);
        using var input = entries[0].Open();
        using (var output = new FileStream(
                   path,
                   FileMode.CreateNew,
                   FileAccess.Write,
                   FileShare.None,
                   16 * 1024,
                   FileOptions.WriteThrough))
        {
            input.CopyTo(output);
            output.Flush(flushToDisk: true);
        }
        PersonalPathGuard.RequireSingleLinkFile(path);
        return path;
    }

    private static void RequireHash(
        ReadOnlySpan<byte> bytes,
        string expectedSha256,
        string label)
    {
        var actual = Convert.ToHexStringLower(SHA256.HashData(bytes));
        if (!string.Equals(actual, expectedSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Personal production payload {label} SHA-256 is not exact.");
        }
    }

    private static void DeleteTemporaryTree(string root)
    {
        if (!Directory.Exists(root))
        {
            return;
        }
        RejectLinkedPath(root);
        foreach (var entry in Directory.EnumerateFileSystemEntries(
                     root,
                     "*",
                     SearchOption.AllDirectories))
        {
            if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Personal production payload temporary tree contains a filesystem link.");
            }
            if (File.Exists(entry))
            {
                PersonalPathGuard.RequireSingleLinkFile(entry);
            }
        }
        Directory.Delete(root, recursive: true);
    }

    private static void RejectLinkedPath(string path)
    {
        for (var current = new DirectoryInfo(Path.GetFullPath(path));
             current is not null;
             current = current.Parent)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Personal production payload temporary path crosses a filesystem link.");
            }
        }
    }
}
