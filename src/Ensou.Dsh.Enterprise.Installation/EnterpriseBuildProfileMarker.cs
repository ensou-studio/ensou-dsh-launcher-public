using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ensou.Dsh.Enterprise.Installation;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseBuildProfileMarker(int SchemaVersion, string LayoutProfile)
{
    public void Validate(string expectedLayoutProfile)
    {
        if (SchemaVersion != 1
            || !IsKnownProfile(LayoutProfile)
            || !string.Equals(
                LayoutProfile,
                expectedLayoutProfile,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise binary build profile does not match the selected installation layout.");
        }
    }

    public static EnterpriseBuildProfileMarker ReadAndValidate(
        string markerPath,
        string expectedLayoutProfile)
    {
        if (!File.Exists(markerPath)
            || (File.GetAttributes(markerPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Enterprise binary build profile marker is missing or linked.");
        }

        var marker = JsonSerializer.Deserialize<EnterpriseBuildProfileMarker>(
            File.ReadAllBytes(markerPath),
            EnterpriseInstallJson.Options)
            ?? throw new InvalidDataException("Enterprise build profile marker is empty.");
        marker.Validate(expectedLayoutProfile);
        return marker;
    }

    public static byte[] CreateCanonical(string layoutProfile)
    {
        if (!IsKnownProfile(layoutProfile))
        {
            throw new InvalidDataException("Unknown enterprise build profile.");
        }

        return JsonSerializer.SerializeToUtf8Bytes(
            new EnterpriseBuildProfileMarker(1, layoutProfile),
            EnterpriseInstallJson.Options);
    }

    private static bool IsKnownProfile(string profile) =>
        string.Equals(
            profile,
            EnterpriseInstallationLayout.ProductionLayoutProfile,
            StringComparison.Ordinal)
        || string.Equals(
            profile,
            EnterpriseInstallationLayout.DevelopmentE2ELayoutProfile,
            StringComparison.Ordinal);
}
