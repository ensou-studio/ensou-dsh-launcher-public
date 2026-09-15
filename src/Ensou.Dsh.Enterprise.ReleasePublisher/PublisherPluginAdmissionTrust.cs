using System.Reflection;
using System.Security.Cryptography;

namespace Ensou.Dsh.Enterprise.ReleasePublisher;

internal sealed record PublisherPluginAdmissionTrust
{
    public required string KeyId { get; init; }
    public required string X { get; init; }
    public required string Y { get; init; }

    public void Validate()
    {
        PublisherRuntimeAdmissionEncoding.ValidateToken(
            KeyId,
            "plugin-admission keyId",
            64);
        var x = DecodeCoordinate(X, "plugin-admission key x");
        var y = DecodeCoordinate(Y, "plugin-admission key y");
        try
        {
            using var verifier = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y },
            });
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                "Plugin-admission trust is not a valid P-256 public key.",
                exception);
        }
    }

    public void RequireIndependentFrom(
        PublisherRuntimeAdmissionTrust runtimeAdmissionTrust,
        PublisherBrandAuthorizationTrust brandAuthorizationTrust,
        PublisherLeaseVerificationTrust leaseVerificationTrust,
        string releaseKeyId)
    {
        ArgumentNullException.ThrowIfNull(runtimeAdmissionTrust);
        ArgumentNullException.ThrowIfNull(brandAuthorizationTrust);
        ArgumentNullException.ThrowIfNull(leaseVerificationTrust);
        Validate();
        runtimeAdmissionTrust.Validate();
        brandAuthorizationTrust.Validate();
        leaseVerificationTrust.Validate();
        RequireIndependent(
            (runtimeAdmissionTrust.KeyId, runtimeAdmissionTrust.X, runtimeAdmissionTrust.Y),
            (brandAuthorizationTrust.KeyId, brandAuthorizationTrust.X, brandAuthorizationTrust.Y),
            (leaseVerificationTrust.KeyId, leaseVerificationTrust.X, leaseVerificationTrust.Y));
        if (string.Equals(KeyId, releaseKeyId, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Plugin admission and release-signing key IDs must be independent.");
        }
    }

    public void RequireIndependentFromReleaseKey(string releaseKeyId, ECParameters releaseKey)
    {
        Validate();
        if (releaseKey.Q.X?.Length != 32 || releaseKey.Q.Y?.Length != 32)
        {
            throw new InvalidDataException("Release-signing key must use P-256.");
        }
        var pluginX = DecodeCoordinate(X, "plugin-admission key x");
        var pluginY = DecodeCoordinate(Y, "plugin-admission key y");
        if (string.Equals(KeyId, releaseKeyId, StringComparison.Ordinal)
            || (CryptographicOperations.FixedTimeEquals(pluginX, releaseKey.Q.X)
                && CryptographicOperations.FixedTimeEquals(pluginY, releaseKey.Q.Y)))
        {
            throw new InvalidDataException(
                "Plugin admission and release-signing trust roots must be independent.");
        }
    }

    private void RequireIndependent(
        params (string KeyId, string X, string Y)[] otherTrustRoots)
    {
        var pluginX = DecodeCoordinate(X, "plugin-admission key x");
        var pluginY = DecodeCoordinate(Y, "plugin-admission key y");
        foreach (var other in otherTrustRoots)
        {
            var otherX = DecodeCoordinate(other.X, "independent trust key x");
            var otherY = DecodeCoordinate(other.Y, "independent trust key y");
            if (string.Equals(KeyId, other.KeyId, StringComparison.Ordinal)
                || (CryptographicOperations.FixedTimeEquals(pluginX, otherX)
                    && CryptographicOperations.FixedTimeEquals(pluginY, otherY)))
            {
                throw new InvalidDataException(
                    "Plugin admission, runtime admission, brand authorization, and lease trust roots must be independent.");
            }
        }
    }

    private static byte[] DecodeCoordinate(string value, string field) =>
        PublisherRuntimeAdmissionEncoding.DecodeBase64Url(value, field, 32);
}

internal sealed record PublisherLeaseVerificationTrust
{
    public required string KeyId { get; init; }
    public required string X { get; init; }
    public required string Y { get; init; }

    public void Validate()
    {
        PublisherRuntimeAdmissionEncoding.ValidateToken(KeyId, "lease keyId", 64);
        var x = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(X, "lease public key x", 32);
        var y = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(Y, "lease public key y", 32);
        try
        {
            using var verifier = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y },
            });
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                "Compiled lease trust is not a valid P-256 public key.",
                exception);
        }
    }
}

internal static class PublisherLeaseVerificationTrustResolver
{
    private const string KeyIdName = "EnterpriseLeaseKeyId";
    private const string KeyXName = "EnterpriseLeaseKeyX";
    private const string KeyYName = "EnterpriseLeaseKeyY";

    public static PublisherLeaseVerificationTrust ResolveProduction()
    {
        var metadata = typeof(Program).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .ToArray();
        var trust = new PublisherLeaseVerificationTrust
        {
            KeyId = RequireSingle(metadata, KeyIdName),
            X = RequireSingle(metadata, KeyXName),
            Y = RequireSingle(metadata, KeyYName),
        };
        trust.Validate();
        return trust;
    }

    private static string RequireSingle(
        IReadOnlyList<AssemblyMetadataAttribute> metadata,
        string name)
    {
        var values = metadata
            .Where(value => string.Equals(value.Key, name, StringComparison.Ordinal))
            .Select(value => value.Value)
            .ToArray();
        if (values.Length != 1 || string.IsNullOrWhiteSpace(values[0]))
        {
            throw new InvalidDataException(
                $"Production publisher assembly is missing exact {name} trust metadata.");
        }
        return values[0]!;
    }
}

internal static class PublisherPluginAdmissionTrustResolver
{
    private const string KeyIdName = "EnterprisePluginAdmissionKeyId";
    private const string KeyXName = "EnterprisePluginAdmissionKeyX";
    private const string KeyYName = "EnterprisePluginAdmissionKeyY";

    public static PublisherPluginAdmissionTrust ResolveProduction()
    {
        var metadata = typeof(Program).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .ToArray();
        var trust = new PublisherPluginAdmissionTrust
        {
            KeyId = RequireSingle(metadata, KeyIdName),
            X = RequireSingle(metadata, KeyXName),
            Y = RequireSingle(metadata, KeyYName),
        };
        trust.Validate();
        return trust;
    }

    private static string RequireSingle(
        IReadOnlyList<AssemblyMetadataAttribute> metadata,
        string name)
    {
        var values = metadata
            .Where(value => string.Equals(value.Key, name, StringComparison.Ordinal))
            .Select(value => value.Value)
            .ToArray();
        if (values.Length != 1 || string.IsNullOrWhiteSpace(values[0]))
        {
            throw new InvalidDataException(
                $"Production publisher assembly is missing exact {name} trust metadata.");
        }
        return values[0]!;
    }
}
