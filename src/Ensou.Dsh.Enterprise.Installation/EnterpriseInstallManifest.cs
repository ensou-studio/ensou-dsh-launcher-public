using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ensou.Dsh.Enterprise.Installation;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseInstallManifest
{
    public required int SchemaVersion { get; init; }

    public required string LayoutProfile { get; init; }

    public required string LauncherReleaseId { get; init; }

    public required string RuntimeReleaseId { get; init; }

    public required string LauncherArchive { get; init; }

    public required long LauncherArchiveSizeBytes { get; init; }

    public required string LauncherArchiveSha256 { get; init; }

    public required string RuntimeArchive { get; init; }

    public required long RuntimeArchiveSizeBytes { get; init; }

    public required string RuntimeArchiveSha256 { get; init; }

    public required string BootstrapperFile { get; init; }

    public required long BootstrapperSizeBytes { get; init; }

    public required string BootstrapperSha256 { get; init; }

    public required DateTimeOffset PublishedAtUtc { get; init; }

    public void Validate()
    {
        if (SchemaVersion != 1)
        {
            throw new InvalidDataException("Unsupported enterprise install manifest version.");
        }

        EnterprisePathGuard.ValidateReleaseId(LauncherReleaseId);
        EnterprisePathGuard.ValidateReleaseId(RuntimeReleaseId);
        if (LayoutProfile is not EnterpriseInstallationLayout.ProductionLayoutProfile
            and not EnterpriseInstallationLayout.DevelopmentE2ELayoutProfile)
        {
            throw new InvalidDataException("Enterprise install manifest layout profile is invalid.");
        }
        ValidatePayloadFileName(LauncherArchive, nameof(LauncherArchive));
        ValidatePayloadFileName(RuntimeArchive, nameof(RuntimeArchive));
        ValidatePayloadFileName(BootstrapperFile, nameof(BootstrapperFile));
        if (string.Equals(LauncherArchive, RuntimeArchive, StringComparison.OrdinalIgnoreCase)
            || string.Equals(LauncherArchive, BootstrapperFile, StringComparison.OrdinalIgnoreCase)
            || string.Equals(RuntimeArchive, BootstrapperFile, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Enterprise payload filenames must be unique.");
        }

        ValidateSize(LauncherArchiveSizeBytes, 1L * 1024 * 1024 * 1024, nameof(LauncherArchive));
        ValidateSize(RuntimeArchiveSizeBytes, 8L * 1024 * 1024 * 1024, nameof(RuntimeArchive));
        ValidateSize(BootstrapperSizeBytes, 512L * 1024 * 1024, nameof(BootstrapperFile));
        if (!EnterpriseHash.IsSha256(LauncherArchiveSha256)
            || !EnterpriseHash.IsSha256(RuntimeArchiveSha256)
            || !EnterpriseHash.IsSha256(BootstrapperSha256))
        {
            throw new InvalidDataException(
                "Enterprise payload SHA-256 values must be lowercase hexadecimal.");
        }

        if (PublishedAtUtc.Offset != TimeSpan.Zero
            || PublishedAtUtc <= DateTimeOffset.UnixEpoch
            || PublishedAtUtc > DateTimeOffset.UtcNow.AddDays(1))
        {
            throw new InvalidDataException("Enterprise payload publication time is invalid.");
        }
    }

    public static EnterpriseInstallManifest Parse(ReadOnlySpan<byte> utf8Json)
    {
        var manifest = JsonSerializer.Deserialize<EnterpriseInstallManifest>(
            utf8Json,
            EnterpriseInstallJson.Options)
            ?? throw new InvalidDataException("Enterprise install manifest is empty.");
        manifest.Validate();
        return manifest;
    }

    private static void ValidatePayloadFileName(string fileName, string field)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        if (!string.Equals(Path.GetFileName(fileName), fileName, StringComparison.Ordinal)
            || fileName is "." or ".."
            || fileName.Length > 128
            || fileName.EndsWith(' ')
            || fileName.EndsWith('.')
            || fileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            throw new InvalidDataException($"{field} must be one canonical payload filename.");
        }
    }

    private static void ValidateSize(long value, long maximum, string field)
    {
        if (value <= 0 || value > maximum)
        {
            throw new InvalidDataException($"{field} size is outside its bounded range.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseInstallationReceipt(
    int SchemaVersion,
    string LayoutProfile,
    string LauncherReleaseId,
    string RuntimeReleaseId,
    bool DevelopmentUnsignedPayload,
    DateTimeOffset InstalledAtUtc);

internal static class EnterpriseInstallJson
{
    public static JsonSerializerOptions Options { get; } = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };
}
