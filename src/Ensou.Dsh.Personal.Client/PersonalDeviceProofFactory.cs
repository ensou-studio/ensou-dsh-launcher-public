using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Ensou.Dsh.Personal.Client;

public sealed class PersonalDeviceProofFactory
{
    private const string RequestBindingDomain = "ensou.dsh.personal.device-proof.request.v1";
    private const string PersonalLogin = "personal.login";
    private const string SessionAccess = "personal.session.access";
    private const string SessionRefresh = "personal.session.refresh";
    private readonly IPersonalDeviceProofKey _key;
    private readonly string _installationId;
    private readonly TimeProvider _clock;

    public PersonalDeviceProofFactory(
        IPersonalDeviceProofKey key, string installationId, TimeProvider? clock = null)
    {
        _key = key ?? throw new ArgumentNullException(nameof(key));
        _installationId = PersonalAccountFormat.RequireUuid(installationId);
        _clock = clock ?? TimeProvider.System;
    }

    public string Create(Uri targetUri, string operation, string value, string nonce)
    {
        ArgumentNullException.ThrowIfNull(targetUri);
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(nonce);

        var description = Describe(operation, value);
        var target = RequireTargetUri(targetUri, description.Path);
        PersonalAccountFormat.RequireBase64Url(nonce, 32);

        var requestHash = ComputeRequestHash(
            description.WireOperation, description.Purpose, description.ChallengeId,
            description.CanonicalEmail, description.SessionTokenDigest);
        var jtiBytes = RandomNumberGenerator.GetBytes(32);
        var jti = Encode(jtiBytes);
        byte[]? headerBytes = null;
        byte[]? payloadBytes = null;
        byte[]? signingInput = null;
        byte[]? signature = null;
        try
        {
            var publicKey = _key.ReadPublicKey() ?? throw InvalidArgument();
            var xText = PersonalAccountFormat.RequireBase64Url(publicKey.X, 32);
            var yText = PersonalAccountFormat.RequireBase64Url(publicKey.Y, 32);
            using var verifier = CreateVerifier(xText, yText);
            var header = JsonSerializer.Serialize(new
            {
                alg = "ES256",
                typ = "dpop+jwt",
                jwk = new { kty = "EC", crv = "P-256", x = xText, y = yText },
            });
            var issuedAt = _clock.GetUtcNow().ToUniversalTime().ToUnixTimeSeconds();
            var payload = JsonSerializer.Serialize(new
            {
                htm = "POST",
                htu = target,
                iat = issuedAt,
                jti,
                nonce,
                installation_id = _installationId,
                operation = description.WireOperation,
                purpose = description.Purpose,
                request_hash = Encode(requestHash),
            });
            headerBytes = Encoding.UTF8.GetBytes(header);
            payloadBytes = Encoding.UTF8.GetBytes(payload);
            var headerText = Encode(headerBytes);
            var payloadText = Encode(payloadBytes);
            signingInput = Encoding.ASCII.GetBytes($"{headerText}.{payloadText}");
            signature = _key.Sign(signingInput) ?? throw InvalidArgument();
            if (signature.Length != 64 || !verifier.VerifyData(
                    signingInput, signature, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                throw InvalidArgument();
            return $"{headerText}.{payloadText}.{Encode(signature)}";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(requestHash);
            CryptographicOperations.ZeroMemory(jtiBytes);
            Zero(headerBytes);
            Zero(payloadBytes);
            Zero(signingInput);
            Zero(signature);
        }
    }

    private static OperationDescription Describe(string operation, string value) => operation switch
    {
        "issue" => new(
            "issue", PersonalLogin, "/v1/personal/email/request",
            null, PersonalAccountFormat.CanonicalizeEmail(value), null),
        "redeem" => new(
            "redeem", PersonalLogin, "/v1/personal/sessions/sign-in",
            RequireChallenge(value), null, null),
        "session-access" => new(
            "session-access", SessionAccess, "/v1/personal/sessions/access",
            null, null, PersonalAccountFormat.HashToken(value, "psa_")),
        "session-refresh" => new(
            "session-refresh", SessionRefresh, "/v1/personal/sessions/refresh",
            null, null, PersonalAccountFormat.HashToken(value, "psr_")),
        _ => throw InvalidArgument(),
    };

    private static string RequireChallenge(string value)
    {
        if (value.Length != 32
            || value.Any(static c => !char.IsAsciiLetterOrDigit(c) && c is not '-' and not '_'))
            throw InvalidArgument();
        return value;
    }

    private static string RequireTargetUri(Uri value, string expectedPath)
    {
        if (!value.IsAbsoluteUri
            || !string.Equals(value.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !value.IsDefaultPort || value.Port != 443
            || value.AbsolutePath != expectedPath
            || value.Query.Length != 0 || value.Fragment.Length != 0 || value.UserInfo.Length != 0
            || value.HostNameType != UriHostNameType.Dns || value.Host.EndsWith(".", StringComparison.Ordinal)
            || value.Host.Length == 0
            || value.OriginalString.Any(static c => c > 127 || char.IsControl(c)))
            throw InvalidArgument();
        var origin = PersonalAccountFormat.RequireOrigin(new UriBuilder(Uri.UriSchemeHttps, value.Host, 443).Uri);
        return origin.GetLeftPart(UriPartial.Authority) + expectedPath;
    }

    private static byte[] ComputeRequestHash(
        string operation, string purpose, string? challengeId,
        string? canonicalEmail, string? sessionTokenDigest)
    {
        var semanticValue = operation switch
        {
            "issue" when challengeId is null && sessionTokenDigest is null && canonicalEmail is not null => canonicalEmail,
            "redeem" when challengeId is not null && canonicalEmail is null && sessionTokenDigest is null => challengeId,
            "session-access" when challengeId is null && canonicalEmail is null && sessionTokenDigest is not null => sessionTokenDigest,
            "session-refresh" when challengeId is null && canonicalEmail is null && sessionTokenDigest is not null => sessionTokenDigest,
            _ => throw InvalidArgument(),
        };
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        AppendField(hash, RequestBindingDomain);
        AppendField(hash, operation);
        AppendField(hash, purpose);
        AppendField(hash, semanticValue);
        return hash.GetHashAndReset();
    }

    private static void AppendField(IncrementalHash hash, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)bytes.Length));
        try
        {
            hash.AppendData(length);
            hash.AppendData(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            CryptographicOperations.ZeroMemory(length);
        }
    }

    private static ECDsa CreateVerifier(string xText, string yText)
    {
        byte[]? x = null;
        byte[]? y = null;
        try
        {
            x = Decode(xText);
            y = Decode(yText);
            return ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x.ToArray(), Y = y.ToArray() },
            });
        }
        catch (CryptographicException)
        {
            throw InvalidArgument();
        }
        finally
        {
            Zero(x);
            Zero(y);
        }
    }

    private static byte[] Decode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/') + "=";
        return Convert.FromBase64String(padded);
    }

    private static string Encode(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static void Zero(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }

    private static ArgumentException InvalidArgument() =>
        new("The personal device proof value is invalid.");

    private sealed record OperationDescription(
        string WireOperation, string Purpose, string Path,
        string? ChallengeId, string? CanonicalEmail, string? SessionTokenDigest);
}
