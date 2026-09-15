using System.Reflection;

namespace Ensou.Dsh.Enterprise.Installation;

public interface IEnterprisePayloadSource : IDisposable
{
    Stream Open(string fileName);
}

public sealed class EnterpriseDirectoryPayloadSource : IEnterprisePayloadSource
{
    public const string DevelopmentConsentFileName =
        "ALLOW-UNSIGNED-DEVELOPMENT-PAYLOAD.txt";
    public const string DevelopmentConsentText =
        "UNSIGNED ENTERPRISE DEVELOPMENT PAYLOAD - NOT FOR EMPLOYEE DEPLOYMENT";
    private readonly string _root;

    private EnterpriseDirectoryPayloadSource(string root)
    {
        _root = root;
    }

    public static EnterpriseDirectoryPayloadSource OpenExplicitDevelopmentPayload(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        var absoluteRoot = EnterprisePathGuard.NormalizeDirectory(root);
        if (!Directory.Exists(absoluteRoot)
            || HasLinkedAncestor(absoluteRoot))
        {
            throw new InvalidDataException(
                "The development enterprise payload directory is missing or linked.");
        }

        var consentPath = Path.Combine(absoluteRoot, DevelopmentConsentFileName);
        if (!File.Exists(consentPath)
            || (File.GetAttributes(consentPath) & FileAttributes.ReparsePoint) != 0
            || !string.Equals(
                File.ReadAllText(consentPath).Trim(),
                DevelopmentConsentText,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Unsigned development payload use requires the exact consent marker.");
        }

        return new EnterpriseDirectoryPayloadSource(absoluteRoot);
    }

    public Stream Open(string fileName)
    {
        var path = Resolve(fileName);
        if (!File.Exists(path)
            || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new FileNotFoundException("Enterprise payload file is missing or linked.", path);
        }

        return new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 128 * 1024,
            FileOptions.SequentialScan);
    }

    public void Dispose()
    {
    }

    private string Resolve(string fileName)
    {
        if (!string.Equals(Path.GetFileName(fileName), fileName, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Enterprise payload filename escaped its directory.");
        }

        var path = Path.GetFullPath(Path.Combine(_root, fileName));
        if (!EnterprisePathGuard.IsSameOrDescendant(path, _root))
        {
            throw new InvalidDataException("Enterprise payload file escaped its directory.");
        }

        return path;
    }

    private static bool HasLinkedAncestor(string path)
    {
        DirectoryInfo? current = new(path);
        while (current is not null)
        {
            if (!current.Exists
                || (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                return true;
            }

            current = current.Parent;
        }

        return false;
    }
}

public sealed class EnterpriseEmbeddedPayloadSource : IEnterprisePayloadSource
{
    public const string ManifestFileName = "enterprise-install-manifest.json";
    private const string ResourcePrefix =
        "Ensou.Dsh.Enterprise.Installer.Payload.";
    private readonly Assembly _assembly;

    public EnterpriseEmbeddedPayloadSource(Assembly assembly)
    {
        _assembly = assembly ?? throw new ArgumentNullException(nameof(assembly));
    }

    public Stream Open(string fileName)
    {
        if (!string.Equals(Path.GetFileName(fileName), fileName, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Embedded enterprise payload name is invalid.");
        }

        return _assembly.GetManifestResourceStream(ResourcePrefix + fileName)
            ?? throw new FileNotFoundException(
                "This installer build does not contain a production payload resource.",
                fileName);
    }

    public void Dispose()
    {
    }
}
