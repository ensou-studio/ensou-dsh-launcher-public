using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Ensou.Dsh.Enterprise.Contracts;

namespace Ensou.Dsh.Enterprise.Client;

public static class EnterpriseBindingPayloadBuilder
{
    public const int PayloadVersion = 1;
    private const string DomainSeparator = "ENSOU-DSH-BINDING-V1";
    private const int MaximumCanonicalPayloadBytes = 512;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static EnterpriseDeviceBindingCompleteRequest CreateSignedRequest(
        EnterpriseBindingChallenge challenge,
        string installId,
        string deviceKeyThumbprint,
        string deviceLabel,
        IEnterpriseDeviceProofKeyStore deviceKeyStore)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(deviceKeyStore);
        var canonicalInstallId = EnterpriseBindingValidation.CanonicalizeUuid(
            installId,
            nameof(installId));
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            deviceKeyThumbprint,
            nameof(deviceKeyThumbprint),
            32);
        EnterpriseBindingValidation.ValidateDeviceLabel(deviceLabel, nameof(deviceLabel));

        var payload = Build(challenge, canonicalInstallId, deviceKeyThumbprint);
        byte[]? signature = null;
        try
        {
            signature = deviceKeyStore.Sign(payload);
            if (signature.Length != 64)
            {
                throw new CryptographicException(
                    "Enterprise binding signature must use fixed-width ES256 P1363 format.");
            }

            return new EnterpriseDeviceBindingCompleteRequest
            {
                BindingPayloadVersion = PayloadVersion,
                BindGrant = challenge.BindGrant,
                SessionId = challenge.SessionId,
                InstallId = canonicalInstallId,
                DeviceKeyThumbprint = deviceKeyThumbprint,
                DeviceLabel = deviceLabel,
                BindingChallenge = challenge.Challenge,
                BindingChallengeExpiresAtUtc = challenge.ExpiresAtUtc,
                DeviceSignature = EnterpriseBindingValidation.Base64UrlEncode(signature),
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            if (signature is not null)
            {
                CryptographicOperations.ZeroMemory(signature);
            }
        }
    }

    public static byte[] Build(
        EnterpriseBindingChallenge challenge,
        string installId,
        string deviceKeyThumbprint)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        var canonicalSessionId = EnterpriseBindingValidation.CanonicalizeUuid(
            challenge.SessionId,
            nameof(challenge.SessionId));
        var canonicalInstallId = EnterpriseBindingValidation.CanonicalizeUuid(
            installId,
            nameof(installId));
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            challenge.BindGrant,
            nameof(challenge.BindGrant),
            32);
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            challenge.Challenge,
            nameof(challenge.Challenge),
            32);
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            deviceKeyThumbprint,
            nameof(deviceKeyThumbprint),
            32);
        EnterpriseBindingValidation.ValidateCanonicalUtcSecond(
            challenge.ExpiresAtUtc,
            nameof(challenge.ExpiresAtUtc));
        if (challenge.ExpiresAtUtc.ToUnixTimeSeconds() <= 0)
        {
            throw new InvalidDataException("Binding challenge expiry must be positive Unix time.");
        }

        var grantBytes = StrictUtf8.GetBytes(challenge.BindGrant);
        byte[]? grantHash = null;
        try
        {
            grantHash = SHA256.HashData(grantBytes);
            var grantHashText = EnterpriseBindingValidation.Base64UrlEncode(grantHash);
            var expiry = challenge.ExpiresAtUtc
                .ToUnixTimeSeconds()
                .ToString(CultureInfo.InvariantCulture);
            var canonical = string.Join(
                '\n',
                DomainSeparator,
                canonicalSessionId,
                canonicalInstallId,
                deviceKeyThumbprint,
                challenge.Challenge,
                grantHashText,
                expiry);
            var payload = StrictUtf8.GetBytes(canonical);
            if (payload.Length > MaximumCanonicalPayloadBytes)
            {
                CryptographicOperations.ZeroMemory(payload);
                throw new InvalidDataException("Canonical binding payload exceeds its wire bound.");
            }

            return payload;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(grantBytes);
            if (grantHash is not null)
            {
                CryptographicOperations.ZeroMemory(grantHash);
            }
        }
    }
}

internal static class EnterpriseBindingValidation
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static string CanonicalizeUuid(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length != 36
            || !Guid.TryParseExact(value, "D", out var parsed)
            || parsed == Guid.Empty
            || !string.Equals(value, parsed.ToString("D"), StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"{parameterName} must be a non-empty lowercase canonical D-format UUID.");
        }

        return parsed.ToString("D");
    }

    public static void ValidateCanonicalUtcSecond(DateTimeOffset value, string parameterName)
    {
        if (value.Offset != TimeSpan.Zero || value.Ticks % TimeSpan.TicksPerSecond != 0)
        {
            throw new InvalidDataException(
                $"{parameterName} must be UTC with whole-second precision.");
        }
    }

    public static void ValidateOpaqueToken(
        string value,
        string parameterName,
        int minimumLength,
        int maximumLength)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length < minimumLength
            || value.Length > maximumLength
            || value.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '-' and not '_'))
        {
            throw new InvalidDataException($"{parameterName} is not a canonical opaque token.");
        }
    }

    public static void ValidateBoundedText(
        string value,
        string parameterName,
        int minimumLength,
        int maximumLength)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length < minimumLength
            || value.Length > maximumLength
            || value.Any(char.IsControl))
        {
            throw new InvalidDataException($"{parameterName} is not valid bounded text.");
        }
    }

    public static void ValidateDeviceLabel(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (!string.Equals(value, value.Trim(), StringComparison.Ordinal)
            || !value.IsNormalized(NormalizationForm.FormC)
            || value.Any(character => char.IsControl(character)
                || char.GetUnicodeCategory(character) is UnicodeCategory.LineSeparator
                    or UnicodeCategory.ParagraphSeparator))
        {
            throw new InvalidDataException(
                $"{parameterName} must be trimmed NFC text without control or separator characters.");
        }

        int byteCount;
        try
        {
            byteCount = StrictUtf8.GetByteCount(value);
        }
        catch (EncoderFallbackException exception)
        {
            throw new InvalidDataException($"{parameterName} is not valid Unicode text.", exception);
        }

        if (byteCount > 128)
        {
            throw new InvalidDataException($"{parameterName} exceeds 128 UTF-8 bytes.");
        }
    }

    public static void ValidateCanonicalBase64Url(
        string value,
        string parameterName,
        int expectedBytes)
    {
        var decoded = Base64UrlDecode(value, parameterName, expectedBytes);
        try
        {
            if (decoded.Length != expectedBytes)
            {
                throw new InvalidDataException(
                    $"{parameterName} must encode exactly {expectedBytes} bytes.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decoded);
        }
    }

    public static void ValidateCanonicalLowercaseSha256(
        string value,
        string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length != 64
            || value.Any(character => !char.IsAsciiDigit(character)
                && character is not (>= 'a' and <= 'f')))
        {
            throw new InvalidDataException(
                $"{parameterName} must be exactly 64 lowercase hexadecimal characters.");
        }
    }

    public static void ValidateP256PublicIdentity(
        EnterpriseDevicePublicIdentity identity,
        string parameterName)
    {
        ArgumentNullException.ThrowIfNull(identity, parameterName);
        if (identity.KeyType != "EC" || identity.Curve != "P-256")
        {
            throw new InvalidDataException($"{parameterName} must be an EC P-256 public identity.");
        }

        var x = Base64UrlDecode(identity.X, $"{parameterName}.x", 32);
        var y = Base64UrlDecode(identity.Y, $"{parameterName}.y", 32);
        var submittedThumbprint = Base64UrlDecode(
            identity.Thumbprint,
            $"{parameterName}.thumbprint",
            32);
        byte[]? canonicalJwk = null;
        byte[]? expectedThumbprint = null;
        try
        {
            if (x.Length != 32 || y.Length != 32 || submittedThumbprint.Length != 32)
            {
                throw new InvalidDataException($"{parameterName} must use 32-byte P-256 coordinates and thumbprint.");
            }

            try
            {
                using var publicKey = ECDsa.Create(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint { X = x, Y = y },
                });
            }
            catch (Exception exception) when (
                exception is CryptographicException or PlatformNotSupportedException)
            {
                throw new InvalidDataException($"{parameterName} is not a valid P-256 public point.", exception);
            }

            canonicalJwk = StrictUtf8.GetBytes(
                $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{identity.X}\",\"y\":\"{identity.Y}\"}}");
            expectedThumbprint = SHA256.HashData(canonicalJwk);
            if (!CryptographicOperations.FixedTimeEquals(
                    submittedThumbprint,
                    expectedThumbprint))
            {
                throw new InvalidDataException(
                    $"{parameterName} thumbprint does not match its RFC 7638 public JWK.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(x);
            CryptographicOperations.ZeroMemory(y);
            CryptographicOperations.ZeroMemory(submittedThumbprint);
            if (canonicalJwk is not null)
            {
                CryptographicOperations.ZeroMemory(canonicalJwk);
            }

            if (expectedThumbprint is not null)
            {
                CryptographicOperations.ZeroMemory(expectedThumbprint);
            }
        }
    }

    public static bool MatchesPublicIdentity(
        EnterpriseDevicePublicIdentity expected,
        EnterpriseDevicePublicIdentity actual) =>
        string.Equals(expected.KeyType, actual.KeyType, StringComparison.Ordinal)
        && string.Equals(expected.Curve, actual.Curve, StringComparison.Ordinal)
        && string.Equals(expected.X, actual.X, StringComparison.Ordinal)
        && string.Equals(expected.Y, actual.Y, StringComparison.Ordinal)
        && string.Equals(expected.Thumbprint, actual.Thumbprint, StringComparison.Ordinal);

    public static void VerifyP256Signature(
        EnterpriseDevicePublicIdentity identity,
        ReadOnlySpan<byte> payload,
        string signature,
        string parameterName)
    {
        ValidateP256PublicIdentity(identity, nameof(identity));
        var x = Base64UrlDecode(identity.X, "device_identity.x", 32);
        var y = Base64UrlDecode(identity.Y, "device_identity.y", 32);
        var signatureBytes = Base64UrlDecode(signature, parameterName, 64);
        try
        {
            using var publicKey = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y },
            });
            if (!publicKey.VerifyData(
                    payload,
                    signatureBytes,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                throw new InvalidDataException(
                    $"{parameterName} does not verify against the device proof key.");
            }
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                $"{parameterName} cannot be verified as an ES256 P1363 signature.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(x);
            CryptographicOperations.ZeroMemory(y);
            CryptographicOperations.ZeroMemory(signatureBytes);
        }
    }

    public static string Base64UrlEncode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    public static byte[] Base64UrlDecode(string value, string parameterName, int maximumBytes)
    {
        ValidateOpaqueToken(value, parameterName, 1, checked(maximumBytes * 2));
        var padding = (value.Length % 4) switch
        {
            0 => string.Empty,
            2 => "==",
            3 => "=",
            _ => throw new InvalidDataException($"{parameterName} is not canonical base64url."),
        };

        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(
                value.Replace('-', '+').Replace('_', '/') + padding);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException($"{parameterName} is not canonical base64url.", exception);
        }

        if (decoded.Length > maximumBytes
            || !string.Equals(Base64UrlEncode(decoded), value, StringComparison.Ordinal))
        {
            CryptographicOperations.ZeroMemory(decoded);
            throw new InvalidDataException($"{parameterName} is not canonical base64url.");
        }

        return decoded;
    }
}
