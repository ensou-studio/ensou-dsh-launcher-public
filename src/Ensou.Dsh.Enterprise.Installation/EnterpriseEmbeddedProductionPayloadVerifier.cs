using System.Reflection;
using System.Security.Cryptography;

namespace Ensou.Dsh.Enterprise.Installation;

public sealed record EnterpriseProductionPayloadExpectation(
    string LauncherReleaseId,
    string RuntimeReleaseId,
    string LauncherArchiveSha256,
    string RuntimeArchiveSha256,
    string BootstrapperSha256)
{
    public void Validate()
    {
        EnterprisePathGuard.ValidateReleaseId(LauncherReleaseId);
        EnterprisePathGuard.ValidateReleaseId(RuntimeReleaseId);
        if (!EnterpriseHash.IsSha256(LauncherArchiveSha256)
            || !EnterpriseHash.IsSha256(RuntimeArchiveSha256)
            || !EnterpriseHash.IsSha256(BootstrapperSha256))
        {
            throw new InvalidDataException(
                "Production payload expectation requires lowercase SHA-256 values.");
        }
    }
}

public static class EnterpriseEmbeddedProductionPayloadVerifier
{
    private const int MaximumManifestBytes = 128 * 1024;

    public static EnterpriseInstallManifest VerifyEmbedded(
        Assembly installerAssembly,
        EnterpriseProductionPayloadExpectation expected)
    {
        ArgumentNullException.ThrowIfNull(installerAssembly);
        using var source = new EnterpriseEmbeddedPayloadSource(installerAssembly);
        return Verify(source, expected);
    }

    public static EnterpriseInstallManifest VerifyEmbeddedDevelopmentE2E(
        Assembly installerAssembly,
        EnterpriseProductionPayloadExpectation expected)
    {
        ArgumentNullException.ThrowIfNull(installerAssembly);
        using var source = new EnterpriseEmbeddedPayloadSource(installerAssembly);
        return VerifyDevelopmentE2E(source, expected);
    }

    public static EnterpriseInstallManifest Verify(
        IEnterprisePayloadSource source,
        EnterpriseProductionPayloadExpectation expected)
        => VerifyForLayout(
            source,
            expected,
            EnterpriseInstallationLayout.ProductionLayoutProfile);

    public static EnterpriseInstallManifest VerifyDevelopmentE2E(
        IEnterprisePayloadSource source,
        EnterpriseProductionPayloadExpectation expected)
        => VerifyForLayout(
            source,
            expected,
            EnterpriseInstallationLayout.DevelopmentE2ELayoutProfile);

    private static EnterpriseInstallManifest VerifyForLayout(
        IEnterprisePayloadSource source,
        EnterpriseProductionPayloadExpectation expected,
        string requiredLayoutProfile)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(expected);
        expected.Validate();

        EnterpriseInstallManifest manifest;
        using (var manifestStream = source.Open(
                   EnterpriseEmbeddedPayloadSource.ManifestFileName))
        {
            manifest = EnterpriseInstallManifest.Parse(
                ReadBounded(manifestStream, MaximumManifestBytes, "manifest"));
        }

        if (!string.Equals(
                manifest.LayoutProfile,
                requiredLayoutProfile,
                StringComparison.Ordinal)
            || !string.Equals(
                manifest.LauncherReleaseId,
                expected.LauncherReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                manifest.RuntimeReleaseId,
                expected.RuntimeReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                manifest.LauncherArchiveSha256,
                expected.LauncherArchiveSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                manifest.RuntimeArchiveSha256,
                expected.RuntimeArchiveSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                manifest.BootstrapperSha256,
                expected.BootstrapperSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Embedded Installer payload does not bind the exact admitted release-set and layout.");
        }

        VerifyPayload(
            source,
            manifest.LauncherArchive,
            manifest.LauncherArchiveSizeBytes,
            manifest.LauncherArchiveSha256);
        VerifyPayload(
            source,
            manifest.RuntimeArchive,
            manifest.RuntimeArchiveSizeBytes,
            manifest.RuntimeArchiveSha256);
        VerifyPayload(
            source,
            manifest.BootstrapperFile,
            manifest.BootstrapperSizeBytes,
            manifest.BootstrapperSha256);
        return manifest;
    }

    private static void VerifyPayload(
        IEnterprisePayloadSource source,
        string fileName,
        long expectedLength,
        string expectedSha256)
    {
        using var stream = source.Open(fileName);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        long total = 0;
        while (true)
        {
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                break;
            }
            total = checked(total + read);
            if (total > expectedLength)
            {
                throw new InvalidDataException(
                    "Embedded production payload exceeds its manifest size.");
            }
            hash.AppendData(buffer, 0, read);
        }
        if (total != expectedLength
            || !string.Equals(
                Convert.ToHexStringLower(hash.GetHashAndReset()),
                expectedSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Embedded production payload bytes differ from the signed Installer manifest.");
        }
    }

    private static byte[] ReadBounded(Stream stream, int maximumBytes, string field)
    {
        using var output = new MemoryStream();
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                break;
            }
            if (output.Length + read > maximumBytes)
            {
                throw new InvalidDataException(
                    $"Embedded production payload {field} exceeds its bounded size.");
            }
            output.Write(buffer, 0, read);
        }
        if (output.Length == 0)
        {
            throw new InvalidDataException(
                $"Embedded production payload {field} is empty.");
        }
        return output.ToArray();
    }
}
