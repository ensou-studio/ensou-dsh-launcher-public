using System.Reflection;

namespace Ensou.Dsh.Enterprise.Installation;

/// <summary>
/// Public release trust compiled into each executable that can select or start
/// versioned enterprise code. It contains no private material.
/// </summary>
public sealed record EnterpriseCompiledReleaseTrust(
    Uri ManifestUri,
    EnterpriseReleaseTrustPolicy Policy)
{
    public void Validate(EnterpriseInstallationLayout layout)
    {
        ArgumentNullException.ThrowIfNull(layout);
        Policy.Validate();
        if (!ManifestUri.IsAbsoluteUri
            || !string.Equals(
                ManifestUri.Scheme,
                Uri.UriSchemeHttps,
                StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(ManifestUri.UserInfo)
            || !string.IsNullOrEmpty(ManifestUri.Query)
            || !string.IsNullOrEmpty(ManifestUri.Fragment)
            || !string.Equals(
                ManifestUri.GetLeftPart(UriPartial.Authority),
                Policy.ManifestOrigin.GetLeftPart(UriPartial.Authority),
                StringComparison.OrdinalIgnoreCase)
            || !string.Equals(
                Policy.Product,
                EnterpriseReleaseSetContract.Product,
                StringComparison.Ordinal)
            || !string.Equals(
                Policy.Environment,
                EnterpriseReleaseSetContract.EnvironmentForDevelopmentE2E(
                    layout.IsDevelopmentE2E),
                StringComparison.Ordinal)
            || !layout.IsDevelopmentE2E && !string.Equals(
                Policy.ExpectedChannel,
                EnterpriseReleaseSetContract.StableChannel,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Compiled enterprise release trust does not match this installation layout.");
        }
    }
}

/// <summary>
/// Loads public update trust from signed executable metadata. Development-E2E
/// uses the same explicit environment inputs as the Launcher test profile.
/// </summary>
public static class EnterpriseCompiledReleaseTrustLoader
{
    public static EnterpriseCompiledReleaseTrust LoadRequired(
        Assembly assembly,
        EnterpriseInstallationLayout layout)
    {
        ArgumentNullException.ThrowIfNull(assembly);
        ArgumentNullException.ThrowIfNull(layout);
        var values = layout.IsDevelopmentE2E
            ? ReadDevelopmentInputs()
            : ReadAssemblyInputs(assembly);
        if (values.Any(string.IsNullOrWhiteSpace))
        {
            throw new InvalidDataException(
                "Enterprise executable has no complete compiled release trust.");
        }

        var trust = new EnterpriseCompiledReleaseTrust(
            new Uri(values[0], UriKind.Absolute),
            new EnterpriseReleaseTrustPolicy
            {
                Product = EnterpriseReleaseSetContract.Product,
                Environment = EnterpriseReleaseSetContract.EnvironmentForDevelopmentE2E(
                    layout.IsDevelopmentE2E),
                ExpectedChannel = EnterpriseReleaseSetContract.ChannelForDevelopmentE2E(
                    layout.IsDevelopmentE2E),
                CurrentStartupStubProtocol =
                    EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                ManifestOrigin = new Uri(values[1], UriKind.Absolute),
                ArtifactOrigin = new Uri(values[2], UriKind.Absolute),
                TrustedKeys =
                [
                    new EnterpriseReleasePublicKey(values[3], values[4], values[5]),
                ],
            });
        trust.Validate(layout);
        return trust;
    }

    private static string[] ReadAssemblyInputs(Assembly assembly)
    {
        var metadata = assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .Where(value => value.Value is not null)
            .ToDictionary(
                value => value.Key,
                value => value.Value!,
                StringComparer.Ordinal);
        return
        [
            Read(metadata, "EnterpriseUpdateManifestUri"),
            Read(metadata, "EnterpriseUpdateManifestOrigin"),
            Read(metadata, "EnterpriseUpdateArtifactOrigin"),
            Read(metadata, "EnterpriseUpdateReleaseKeyId"),
            Read(metadata, "EnterpriseUpdateReleaseKeyX"),
            Read(metadata, "EnterpriseUpdateReleaseKeyY"),
        ];
    }

    private static string[] ReadDevelopmentInputs() =>
    [
        Environment.GetEnvironmentVariable("ENSOU_DSH_E2E_UPDATE_MANIFEST_URI")
            ?? string.Empty,
        Environment.GetEnvironmentVariable("ENSOU_DSH_E2E_UPDATE_MANIFEST_ORIGIN")
            ?? string.Empty,
        Environment.GetEnvironmentVariable("ENSOU_DSH_E2E_UPDATE_ARTIFACT_ORIGIN")
            ?? string.Empty,
        Environment.GetEnvironmentVariable("ENSOU_DSH_E2E_UPDATE_KEY_ID")
            ?? string.Empty,
        Environment.GetEnvironmentVariable("ENSOU_DSH_E2E_UPDATE_KEY_X")
            ?? string.Empty,
        Environment.GetEnvironmentVariable("ENSOU_DSH_E2E_UPDATE_KEY_Y")
            ?? string.Empty,
    ];

    private static string Read(
        IReadOnlyDictionary<string, string> metadata,
        string key) => metadata.TryGetValue(key, out var value)
        ? value
        : string.Empty;
}
