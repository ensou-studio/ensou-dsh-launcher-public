using System.Diagnostics.CodeAnalysis;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace Ensou.Dsh.Personal.Client;

/// <summary>Per-origin, per-installation CurrentUser CNG key; construction never creates a key.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsPersonalDeviceProofKey : IPersonalDeviceProofKey
{
    private const int NteExists = unchecked((int)0x8009000F);
    private static readonly CngProvider Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;
    private readonly string _keyName;

    internal string KeyNameForTesting => _keyName;

    public WindowsPersonalDeviceProofKey(Uri origin, string installationId)
    {
        var canonicalOrigin = PersonalAccountFormat.RequireOrigin(origin);
        PersonalAccountFormat.RequireUuid(installationId);
        var binding = Encoding.UTF8.GetBytes(canonicalOrigin.AbsoluteUri + "\n" + installationId);
        try { _keyName = "Ensou.Dsh.Personal.DeviceProof.v1." + Convert.ToHexStringLower(SHA256.HashData(binding)); }
        finally { CryptographicOperations.ZeroMemory(binding); }
    }

    /// <summary>Explicit first-enrollment operation. Never called automatically while signing.</summary>
    public void EnsureCreated()
    {
        if (TryCreateNew(out var created))
        {
            created.Dispose();
            return;
        }

        using var existing = OpenExisting();
        Validate(existing);
    }

    /// <summary>
    /// Atomically creates this exact user key without opening a pre-existing
    /// key. The returned handle proves ownership of this creation attempt.
    /// </summary>
    internal bool TryCreateNew([NotNullWhen(true)] out CngKey? ownedKey)
    {
        ownedKey = null;
        var creation = new CngKeyCreationParameters
        {
            Provider = Provider,
            KeyCreationOptions = CngKeyCreationOptions.None,
            KeyUsage = CngKeyUsages.Signing,
            ExportPolicy = CngExportPolicies.None,
            UIPolicy = new CngUIPolicy(CngUIProtectionLevels.None),
        };
        CngKey? key = null;
        try
        {
            try
            {
                key = CngKey.Create(CngAlgorithm.ECDsaP256, _keyName, creation);
            }
            catch (CryptographicException exception) when (exception.HResult == NteExists)
            {
                return false;
            }

            try
            {
                Validate(key);
            }
            catch (Exception validationException)
            {
                try
                {
                    key.Delete();
                }
                catch (Exception cleanupException)
                {
                    throw new AggregateException(
                        "A newly created Personal device key was invalid and could not be removed safely.",
                        validationException,
                        cleanupException);
                }

                throw;
            }

            ownedKey = key;
            key = null;
            return true;
        }
        finally
        {
            key?.Dispose();
        }
    }

    public PersonalDevicePublicKey ReadPublicKey()
    {
        using var key = OpenExisting();
        Validate(key);
        using var algorithm = new ECDsaCng(key);
        var parameters = algorithm.ExportParameters(includePrivateParameters: false);
        if (parameters.Q.X is not { Length: 32 } || parameters.Q.Y is not { Length: 32 })
            throw new CryptographicException("Personal device key is invalid.");
        return new PersonalDevicePublicKey(Encode(parameters.Q.X), Encode(parameters.Q.Y));
    }

    public byte[] Sign(ReadOnlySpan<byte> signingInput)
    {
        if (signingInput.IsEmpty || signingInput.Length > 16 * 1024)
            throw new ArgumentException("Personal proof input is invalid.");
        using var key = OpenExisting();
        Validate(key);
        using var algorithm = new ECDsaCng(key);
        return algorithm.SignData(signingInput, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    private CngKey OpenExisting() => CngKey.Open(_keyName, Provider, CngKeyOpenOptions.UserKey);
    private static void Validate(CngKey key)
    {
        if (key.Algorithm != CngAlgorithm.ECDsaP256 || key.KeySize != 256
            || key.KeyUsage != CngKeyUsages.Signing || key.ExportPolicy != CngExportPolicies.None || key.IsMachineKey)
            throw new CryptographicException("Personal device key does not satisfy the signing policy.");
    }
    private static string Encode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
