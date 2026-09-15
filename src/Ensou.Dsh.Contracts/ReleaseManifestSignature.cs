using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Ensou.Dsh.Contracts;

public sealed class ManifestSignatureException : Exception
{
    public ManifestSignatureException(string message)
        : base(message)
    {
    }

    public ManifestSignatureException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public static partial class ReleaseManifestSignature
{
    public const string Algorithm = "ES256";

    public static ReleaseManifest CreateSignedManifest(
        ReleaseManifest unsignedManifest,
        string keyId,
        ECDsa signingKey)
    {
        ArgumentNullException.ThrowIfNull(unsignedManifest);
        ArgumentNullException.ThrowIfNull(signingKey);
        ValidateKeyId(keyId);
        EnsureP256(signingKey);

        var manifest = unsignedManifest with { Signature = null };
        var canonicalPayload = ReleaseManifestJson.CreateCanonicalPayload(manifest);
        var signatureBytes = signingKey.SignData(
            canonicalPayload,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        return manifest with
        {
            Signature = new ReleaseSignature
            {
                Algorithm = Algorithm,
                KeyId = keyId,
                Value = Base64Url.Encode(signatureBytes),
            },
        };
    }

    public static byte[] CreateSignedJson(
        ReleaseManifest unsignedManifest,
        string keyId,
        ECDsa signingKey) =>
        ReleaseManifestJson.SerializeSigned(CreateSignedManifest(unsignedManifest, keyId, signingKey));

    public static VerifiedReleaseManifest ParseAndVerify(
        ReadOnlySpan<byte> json,
        ECDsa verificationKey,
        string? expectedKeyId = null)
    {
        var manifest = ReleaseManifestJson.ParseAndValidate(json);
        return Verify(manifest, verificationKey, expectedKeyId);
    }

    public static VerifiedReleaseManifest ParseAndVerify(
        ReadOnlySpan<byte> json,
        string publicKeyPem,
        string? expectedKeyId = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(publicKeyPem);
        try
        {
            using var key = ECDsa.Create();
            key.ImportFromPem(publicKeyPem);
            return ParseAndVerify(json, key, expectedKeyId);
        }
        catch (ManifestSignatureException)
        {
            throw;
        }
        catch (CryptographicException exception)
        {
            throw new ManifestSignatureException("Release verification public key is invalid.", exception);
        }
    }

    public static VerifiedReleaseManifest Verify(
        ReleaseManifest manifest,
        ECDsa verificationKey,
        string? expectedKeyId = null)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(verificationKey);
        EnsureP256(verificationKey);
        ReleaseManifestValidator.ValidateAndThrow(manifest);

        var signature = manifest.Signature!;
        if (!string.Equals(signature.Algorithm, Algorithm, StringComparison.Ordinal))
        {
            throw new ManifestSignatureException($"Unsupported signature algorithm '{signature.Algorithm}'.");
        }

        ValidateKeyId(signature.KeyId);
        if (expectedKeyId is not null &&
            !string.Equals(signature.KeyId, expectedKeyId, StringComparison.Ordinal))
        {
            throw new ManifestSignatureException("Manifest key id does not match the trusted key id.");
        }

        byte[] signatureBytes;
        try
        {
            signatureBytes = Base64Url.Decode(signature.Value);
        }
        catch (FormatException exception)
        {
            throw new ManifestSignatureException("Manifest signature is not valid base64url.", exception);
        }

        if (signatureBytes.Length != 64)
        {
            throw new ManifestSignatureException("ES256 signature must contain exactly 64 bytes.");
        }

        var canonicalPayload = ReleaseManifestJson.CreateCanonicalPayload(manifest);
        if (!verificationKey.VerifyData(
                canonicalPayload,
                signatureBytes,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            throw new ManifestSignatureException("Release manifest signature is invalid.");
        }

        return new VerifiedReleaseManifest(
            manifest,
            signature.KeyId,
            signature.Algorithm,
            Convert.ToHexStringLower(SHA256.HashData(canonicalPayload)));
    }

    private static void EnsureP256(ECDsa key)
    {
        if (key.KeySize != 256)
        {
            throw new ManifestSignatureException("ES256 requires an ECDSA P-256 key.");
        }
    }

    private static void ValidateKeyId(string? keyId)
    {
        if (string.IsNullOrWhiteSpace(keyId) || !KeyIdPattern().IsMatch(keyId))
        {
            throw new ManifestSignatureException("Manifest key id is invalid.");
        }
    }

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex KeyIdPattern();

    private static class Base64Url
    {
        public static string Encode(ReadOnlySpan<byte> value) =>
            Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        public static byte[] Decode(string value)
        {
            if (string.IsNullOrEmpty(value) || value.Any(character =>
                    !(char.IsAsciiLetterOrDigit(character) || character is '-' or '_')))
            {
                throw new FormatException("Value is not unpadded base64url.");
            }

            var padding = (value.Length % 4) switch
            {
                0 => string.Empty,
                2 => "==",
                3 => "=",
                _ => throw new FormatException("Invalid base64url length."),
            };
            return Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + padding);
        }
    }
}
