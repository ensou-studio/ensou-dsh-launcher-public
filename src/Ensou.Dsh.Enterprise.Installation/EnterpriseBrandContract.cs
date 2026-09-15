using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace Ensou.Dsh.Enterprise.Installation;

/// <summary>
/// Exact production brand presentation admitted for the enterprise client.
/// Changing any value requires a new independently signed brand authorization.
/// </summary>
public static class EnterpriseBrandContract
{
    public const string ContractId = "ensou-dsh-enterprise-brand-profile-v1";
    public const string BrandProfileId = "ensou-dsh-enterprise-official-whale-v1";
    public const string ProductFamilyName = "Ensou DSH Enterprise Launcher";
    public const string LauncherProductName = "Ensou DSH Enterprise Launcher";
    public const string BootstrapperProductName = "Ensou DSH Enterprise Bootstrapper";
    public const string InstallerProductName = "Ensou DSH Enterprise Installer";
    public const string DeveloperName = "ensou studio";
    public const string PresentationHeading = "DeepSeek Harness 企业版";
    public const string BasedOnNotice = "基于 DeepSeek Harness 构建";
    public const string NonOfficialNotice = "企业受管客户端 · 非 DeepSeek 官方产品";
    public const string ShortcutDescription = "DeepSeek Harness 企业版启动器";
    public const string ShortcutFileName = "DeepSeek Harness 企业版.lnk";

    public const string OfficialWhaleSvgSha256 =
        "c61a62a9d47d8660f9cfe08aac6775ff0476f7d6c5053f7659c1f8493fd6d814";
    public const string LauncherWhalePngSha256 =
        "9cac1a227c684c848a2d29cf9ebf380b8ec819ccb95c5c3c5c40ca5ef8a27100";
    public const string WindowsWhaleIcoSha256 =
        "7dc1bd71556ddb9eb1c05bdc3c9b3283c8737a742b08cec063702b7f6d2b0b00";

    public const string LauncherComponent = "launcher";
    public const string BootstrapperComponent = "bootstrapper";
    public const string InstallerComponent = "installer";

    public const string OfficialWhaleSvgResourceName =
        "Ensou.Dsh.Enterprise.Brand.dsh-official-whale.svg";
    public const string LauncherWhalePngResourceName =
        "Ensou.Dsh.Enterprise.Brand.dsh-official-whale.png";
    public const string WindowsWhaleIcoResourceName =
        "Ensou.Dsh.Enterprise.Brand.dsh-official-whale.ico";

    public static string PresentationSha256 => HashCanonical(
        ContractId,
        ProductFamilyName,
        LauncherProductName,
        BootstrapperProductName,
        InstallerProductName,
        DeveloperName,
        PresentationHeading,
        BasedOnNotice,
        NonOfficialNotice,
        ShortcutDescription,
        ShortcutFileName);

    public static string ProfileSha256 => HashCanonical(
        ContractId,
        BrandProfileId,
        PresentationSha256,
        OfficialWhaleSvgSha256,
        LauncherWhalePngSha256,
        WindowsWhaleIcoSha256);

    public static void RequireCurrentBinary(
        Assembly assembly,
        string executablePath,
        string component,
        string expectedProfileSha256)
    {
        ArgumentNullException.ThrowIfNull(assembly);
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        if (!string.Equals(expectedProfileSha256, ProfileSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise binary brand profile does not match the authorized profile.");
        }

        var expectedProduct = component switch
        {
            LauncherComponent => LauncherProductName,
            BootstrapperComponent => BootstrapperProductName,
            InstallerComponent => InstallerProductName,
            _ => throw new InvalidDataException("Enterprise brand component is invalid."),
        };
        var assemblyProduct = assembly.GetCustomAttribute<AssemblyProductAttribute>()?.Product;
        var assemblyCompany = assembly.GetCustomAttribute<AssemblyCompanyAttribute>()?.Company;
        if (!string.Equals(assemblyProduct, expectedProduct, StringComparison.Ordinal)
            || !string.Equals(assemblyCompany, DeveloperName, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise binary product or developer metadata is not authorized.");
        }

        var fullExecutablePath = Path.GetFullPath(executablePath);
        if (!File.Exists(fullExecutablePath)
            || !string.Equals(
                Path.GetExtension(fullExecutablePath),
                ".exe",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Enterprise brand self-check requires an executable.");
        }
        var version = FileVersionInfo.GetVersionInfo(fullExecutablePath);
        if (!string.Equals(version.ProductName, expectedProduct, StringComparison.Ordinal)
            || !string.Equals(version.CompanyName, DeveloperName, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise executable product or developer metadata is not authorized.");
        }

        RequireEmbeddedAsset(
            assembly,
            OfficialWhaleSvgResourceName,
            OfficialWhaleSvgSha256,
            "official whale SVG");
        RequireEmbeddedAsset(
            assembly,
            LauncherWhalePngResourceName,
            LauncherWhalePngSha256,
            "Launcher whale PNG");
        RequireEmbeddedAsset(
            assembly,
            WindowsWhaleIcoResourceName,
            WindowsWhaleIcoSha256,
            "Windows whale icon");
    }

    private static void RequireEmbeddedAsset(
        Assembly assembly,
        string resourceName,
        string expectedSha256,
        string label)
    {
        using var stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidDataException($"Enterprise {label} resource is absent.");
        var actualSha256 = Convert.ToHexStringLower(SHA256.HashData(stream));
        if (!string.Equals(actualSha256, expectedSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Enterprise {label} resource is not authorized.");
        }
    }

    private static string HashCanonical(params string[] fields) =>
        Convert.ToHexStringLower(SHA256.HashData(
            Encoding.UTF8.GetBytes(string.Join('\n', fields))));
}
