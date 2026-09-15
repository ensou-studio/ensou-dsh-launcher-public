using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Ensou.Dsh.Enterprise.Client;

public sealed class EnterpriseDpopProofFactory
{
    private readonly IEnterpriseDeviceProofKeyStore _deviceKeyStore;
    private readonly TimeProvider _timeProvider;

    public EnterpriseDpopProofFactory(
        IEnterpriseDeviceProofKeyStore deviceKeyStore,
        TimeProvider? timeProvider = null)
    {
        _deviceKeyStore = deviceKeyStore ?? throw new ArgumentNullException(nameof(deviceKeyStore));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public EnterpriseDevicePublicIdentity GetOrCreatePublicIdentity() =>
        _deviceKeyStore.GetOrCreatePublicIdentity();

    public string Create(
        HttpMethod method,
        Uri requestUri,
        string? nonce = null,
        string? authorizationSecret = null)
    {
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(requestUri);
        if (nonce is not null)
        {
            ValidateToken(nonce, nameof(nonce), 32, 256);
        }
        if (!requestUri.IsAbsoluteUri
            || !string.Equals(requestUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(requestUri.Fragment))
        {
            throw new ArgumentException("DPoP request URI must be absolute HTTPS.", nameof(requestUri));
        }

        var publicIdentity = GetOrCreatePublicIdentity();
        var header = JsonSerializer.SerializeToUtf8Bytes(new
        {
            alg = "ES256",
            typ = "dpop+jwt",
            jwk = new
            {
                kty = publicIdentity.KeyType,
                crv = publicIdentity.Curve,
                x = publicIdentity.X,
                y = publicIdentity.Y,
            },
        });
        byte[]? authorizationSecretBytes = null;
        byte[]? authorizationHash = null;
        byte[] payload;
        try
        {
            if (authorizationSecret is not null)
            {
                authorizationSecretBytes = Encoding.ASCII.GetBytes(authorizationSecret);
                authorizationHash = SHA256.HashData(authorizationSecretBytes);
            }

            payload = JsonSerializer.SerializeToUtf8Bytes(new DpopPayload
            {
                HttpMethod = method.Method.ToUpperInvariant(),
                HttpUri = requestUri.GetLeftPart(UriPartial.Path),
                IssuedAt = _timeProvider.GetUtcNow().ToUnixTimeSeconds(),
                JwtId = Guid.NewGuid().ToString("N"),
                Nonce = nonce,
                AuthorizationHash = authorizationHash is null
                    ? null
                    : Base64UrlEncode(authorizationHash),
            });
        }
        finally
        {
            if (authorizationSecretBytes is not null)
            {
                CryptographicOperations.ZeroMemory(authorizationSecretBytes);
            }

            if (authorizationHash is not null)
            {
                CryptographicOperations.ZeroMemory(authorizationHash);
            }
        }

        var signingInput = $"{Base64UrlEncode(header)}.{Base64UrlEncode(payload)}";
        var signature = _deviceKeyStore.Sign(Encoding.ASCII.GetBytes(signingInput));
        if (signature.Length != 64)
        {
            throw new CryptographicException("Enterprise DPoP signature must use fixed-width ES256 format.");
        }

        return $"{signingInput}.{Base64UrlEncode(signature)}";
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static void ValidateToken(
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
            throw new ArgumentException("Enterprise proof token is not canonical base64url.", parameterName);
        }
    }

    private sealed class DpopPayload
    {
        [System.Text.Json.Serialization.JsonPropertyName("htm")]
        public required string HttpMethod { get; init; }

        [System.Text.Json.Serialization.JsonPropertyName("htu")]
        public required string HttpUri { get; init; }

        [System.Text.Json.Serialization.JsonPropertyName("iat")]
        public required long IssuedAt { get; init; }

        [System.Text.Json.Serialization.JsonPropertyName("jti")]
        public required string JwtId { get; init; }

        [System.Text.Json.Serialization.JsonPropertyName("nonce")]
        [System.Text.Json.Serialization.JsonIgnore(
            Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
        public string? Nonce { get; init; }

        [System.Text.Json.Serialization.JsonPropertyName("ath")]
        [System.Text.Json.Serialization.JsonIgnore(
            Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
        public string? AuthorizationHash { get; init; }
    }
}
