using System.Text.Json.Serialization;

namespace Ensou.Dsh.Enterprise.Installation;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseStableBootstrapperReceipt(
    int SchemaVersion,
    string Sha256,
    DateTimeOffset InstalledAtUtc);

public static class EnterpriseStableBootstrapperVerifier
{
    public static void WriteReceipt(
        EnterpriseInstallationLayout layout,
        string expectedSha256)
    {
        ArgumentNullException.ThrowIfNull(layout);
        if (!EnterpriseHash.IsSha256(expectedSha256)
            || !File.Exists(layout.BootstrapperPath)
            || !string.Equals(
                EnterpriseHash.ComputeFile(layout.BootstrapperPath),
                expectedSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Stable enterprise Bootstrapper does not match its installation hash.");
        }
        var receipt = new EnterpriseStableBootstrapperReceipt(
            2,
            expectedSha256,
            DateTimeOffset.UtcNow);
        EnterprisePathGuard.WriteFileAtomically(
            layout.BootstrapperReceiptPath,
            EnterprisePointerJson.Serialize(receipt),
            layout.ManagedRoot);
    }

    public static void RequireTrusted(EnterpriseInstallationLayout layout)
    {
        ArgumentNullException.ThrowIfNull(layout);
        EnterprisePathGuard.ValidateExistingPathWithin(
            layout.BootstrapperPath,
            layout.ManagedRoot,
            requireDirectory: false);
        EnterprisePathGuard.ValidateExistingPathWithin(
            layout.BootstrapperReceiptPath,
            layout.ManagedRoot,
            requireDirectory: false);
        var receipt = EnterprisePointerJson.Deserialize<EnterpriseStableBootstrapperReceipt>(
            File.ReadAllBytes(layout.BootstrapperReceiptPath));
        if (receipt.SchemaVersion != 2
            || !EnterpriseHash.IsSha256(receipt.Sha256)
            || !string.Equals(
                receipt.Sha256,
                EnterpriseHash.ComputeFile(layout.BootstrapperPath),
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Stable enterprise Bootstrapper was replaced or its receipt is invalid.");
        }
        EnterpriseAuthenticodeVerifier.RequireTrustedSignature(
            layout.BootstrapperPath,
            layout);
    }
}
