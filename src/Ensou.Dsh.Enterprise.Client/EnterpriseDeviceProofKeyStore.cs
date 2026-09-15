using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace Ensou.Dsh.Enterprise.Client;

public sealed record EnterpriseDevicePublicIdentity(
    string KeyType,
    string Curve,
    string X,
    string Y,
    string Thumbprint);

public interface IEnterpriseDeviceProofKeyStore
{
    EnterpriseDevicePublicIdentity GetOrCreatePublicIdentity();

    byte[] Sign(ReadOnlySpan<byte> payload);

    void DeleteForSecurityReset();
}

[SupportedOSPlatform("windows")]
public sealed class EnterpriseDeviceProofKeyStore : IEnterpriseDeviceProofKeyStore
{
    private static readonly CngProvider Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;
    private readonly string _keyName;

    public EnterpriseDeviceProofKeyStore()
        : this(EnterpriseProductIdentity.DeviceKeyName)
    {
    }

    public static EnterpriseDeviceProofKeyStore CreateDevelopmentE2E() =>
        new(EnterpriseProductIdentity.DevelopmentE2EDeviceKeyName);

    /// <summary>
    /// Creates a Development-E2E-only key name that is isolated from both the
    /// production key and the ordinary local Development-E2E key. The caller's
    /// identifier is hashed before it enters the CurrentUser CNG namespace.
    /// </summary>
    public static EnterpriseDeviceProofKeyStore CreateDevelopmentE2E(
        string isolationIdentifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(isolationIdentifier);
        if (isolationIdentifier.Length > 128
            || isolationIdentifier.Any(character =>
                !char.IsAsciiLetterOrDigit(character)
                && character is not '-' and not '_' and not '.'))
        {
            throw new ArgumentException(
                "Development E2E key isolation identifiers must be bounded ASCII tokens.",
                nameof(isolationIdentifier));
        }

        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(isolationIdentifier));
        try
        {
            return new EnterpriseDeviceProofKeyStore(
                $"{EnterpriseProductIdentity.DevelopmentE2EDeviceKeyName}." +
                Convert.ToHexStringLower(digest));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    internal EnterpriseDeviceProofKeyStore(string keyName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        _keyName = keyName;
    }

    public EnterpriseDevicePublicIdentity GetOrCreatePublicIdentity()
    {
        using var key = OpenOrCreate();
        ValidateKey(key);
        using var algorithm = new ECDsaCng(key);
        return CreatePublicIdentity(algorithm);
    }

    public byte[] Sign(ReadOnlySpan<byte> payload)
    {
        if (payload.IsEmpty)
        {
            throw new ArgumentException("Device proof payload must not be empty.", nameof(payload));
        }

        using var key = OpenExisting();
        ValidateKey(key);
        using var algorithm = new ECDsaCng(key);
        return algorithm.SignData(
            payload,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    public void DeleteForSecurityReset()
    {
        if (!CngKey.Exists(_keyName, Provider, CngKeyOpenOptions.UserKey))
        {
            return;
        }

        using var key = OpenExisting();
        key.Delete();
    }

    internal static EnterpriseDevicePublicIdentity CreatePublicIdentity(ECDsa algorithm)
    {
        ArgumentNullException.ThrowIfNull(algorithm);
        var parameters = algorithm.ExportParameters(includePrivateParameters: false);
        var x = EncodeCoordinate(parameters.Q.X);
        var y = EncodeCoordinate(parameters.Q.Y);
        var canonicalJwk = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
        var thumbprint = Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalJwk)));
        return new EnterpriseDevicePublicIdentity("EC", "P-256", x, y, thumbprint);
    }

    private CngKey OpenOrCreate()
    {
        if (CngKey.Exists(_keyName, Provider, CngKeyOpenOptions.UserKey))
        {
            return OpenExisting();
        }

        var creation = new CngKeyCreationParameters
        {
            ExportPolicy = CngExportPolicies.None,
            KeyCreationOptions = CngKeyCreationOptions.None,
            KeyUsage = CngKeyUsages.Signing,
            Provider = Provider,
            UIPolicy = new CngUIPolicy(CngUIProtectionLevels.None),
        };

        try
        {
            return CngKey.Create(CngAlgorithm.ECDsaP256, _keyName, creation);
        }
        catch (CryptographicException) when (
            CngKey.Exists(_keyName, Provider, CngKeyOpenOptions.UserKey))
        {
            return OpenExisting();
        }
    }

    private CngKey OpenExisting() => CngKey.Open(
        _keyName,
        Provider,
        CngKeyOpenOptions.UserKey);

    private static void ValidateKey(CngKey key)
    {
        if (key.AlgorithmGroup != CngAlgorithmGroup.ECDsa
            || key.KeySize != 256
            || (key.KeyUsage & CngKeyUsages.Signing) == 0
            || key.ExportPolicy != CngExportPolicies.None)
        {
            throw new CryptographicException("Enterprise device proof key does not satisfy the production policy.");
        }
    }

    private static string EncodeCoordinate(byte[]? coordinate)
    {
        if (coordinate is null || coordinate.Length != 32)
        {
            throw new CryptographicException("Enterprise device public key is not P-256.");
        }

        return Base64UrlEncode(coordinate);
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
