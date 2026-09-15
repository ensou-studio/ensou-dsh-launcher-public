using System.IO;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.Launcher;

internal static class TrustedReleaseKeyProvider
{
    private const string DevelopmentKeyGate = "ENSOU_DSH_ALLOW_DEVELOPMENT_KEY";

    public static bool IsProductionTrustCompiled => ReadProductionTrust() is not null;

    public static async Task<PersonalReleaseTrustPolicy> GetPersonalV2PolicyAsync(
        LauncherSettings settings,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(settings);
        PersonalReleaseSetValidator.ValidateChannel(settings.Channel);
        if (ReadProductionTrust() is { } production)
        {
            return new PersonalReleaseTrustPolicy
            {
                Product = PersonalReleaseSetContract.Product,
                Environment = PersonalReleaseSetContract.ProductionEnvironment,
                Channel = settings.Channel,
                ArtifactOrigin = production.ArtifactOrigin,
                StartupStubVersion = production.StartupStubVersion,
                CanonicalLowSFromSequence = production.CanonicalLowSFromSequence,
                TrustedKeys = [production.ReleaseKey],
            };
        }

        RequireDevelopmentGate();
        var hasArtifactOrigin = Uri.TryCreate(
            settings.DevelopmentArtifactOrigin,
            UriKind.Absolute,
            out var artifactOrigin);
        if (!File.Exists(settings.DevelopmentManifestPublicKeyPath)
            || (File.GetAttributes(settings.DevelopmentManifestPublicKeyPath)
                & FileAttributes.ReparsePoint) != 0
            || !hasArtifactOrigin)
        {
            throw new InvalidOperationException(
                "Personal production update trust is not compiled into this Launcher. "
                + "Development trust requires an explicit key gate and pinned artifact origin.");
        }
        var pem = await File.ReadAllTextAsync(
            settings.DevelopmentManifestPublicKeyPath,
            cancellationToken).ConfigureAwait(false);
        using var key = ECDsa.Create();
        key.ImportFromPem(pem);
        var policy = new PersonalReleaseTrustPolicy
        {
            Product = PersonalReleaseSetContract.Product,
            Environment = PersonalReleaseSetContract.ProductionEnvironment,
            Channel = settings.Channel,
            ArtifactOrigin = artifactOrigin!,
            StartupStubVersion = settings.DevelopmentStartupStubVersion,
            CanonicalLowSFromSequence = 1,
            TrustedKeys =
            [
                PersonalReleaseSetSigner.ExportPublicKey(
                    settings.DevelopmentManifestKeyId,
                    key),
            ],
        };
        policy.Validate();
        return policy;
    }

    public static Uri GetPersonalManifestUri(LauncherSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        PersonalReleaseSetValidator.ValidateChannel(settings.Channel);
        if (ReadProductionTrust() is { } production)
        {
            return new Uri(
                production.ManifestOrigin,
                $"v2/channels/{settings.Channel}/release-set.v2.json");
        }
        RequireDevelopmentGate();
        if (!Uri.TryCreate(settings.ManifestUrl, UriKind.Absolute, out var configured))
        {
            throw new InvalidDataException("Development personal manifest URL is invalid.");
        }
        var expectedPath = $"/v2/channels/{settings.Channel}/release-set.v2.json";
        if (!string.Equals(configured.AbsolutePath, expectedPath, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Personal update source path must be exactly {expectedPath}.");
        }
        return configured;
    }

    public static async Task<string> GetPublicKeyPemAsync(
        string keyId,
        LauncherSettings settings,
        CancellationToken cancellationToken)
    {
        if (ReadProductionTrust() is { } production
            && string.Equals(production.ReleaseKey.KeyId, keyId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Schema-v2 production keys use compiled P-256 coordinates, not mutable PEM files.");
        }
        RequireDevelopmentGate();
        if (File.Exists(settings.DevelopmentManifestPublicKeyPath))
        {
            return await File.ReadAllTextAsync(
                settings.DevelopmentManifestPublicKeyPath,
                cancellationToken).ConfigureAwait(false);
        }
        throw new InvalidOperationException(
            $"更新签名 keyId '{keyId}' 不在 Launcher 的生产信任库中，请联系管理员更新 Launcher。");
    }

    private static PersonalProductionTrust? ReadProductionTrust()
    {
        var metadata = typeof(TrustedReleaseKeyProvider).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .ToDictionary(attribute => attribute.Key, attribute => attribute.Value, StringComparer.Ordinal);
        var production = metadata.TryGetValue("PersonalProductionBuild", out var build)
            && string.Equals(build, "true", StringComparison.OrdinalIgnoreCase);
        if (!production)
        {
            return null;
        }
        var manifestOrigin = RequireMetadata(metadata, "PersonalManifestOrigin");
        var artifactOrigin = RequireMetadata(metadata, "PersonalArtifactOrigin");
        var keyId = RequireMetadata(metadata, "PersonalReleaseKeyId");
        var keyX = RequireMetadata(metadata, "PersonalReleaseKeyX");
        var keyY = RequireMetadata(metadata, "PersonalReleaseKeyY");
        var stubVersion = RequireMetadata(metadata, "PersonalStartupStubVersion");
        var canonicalLowSFromSequence = RequirePositiveSafeIntegerMetadata(
            metadata,
            "PersonalCanonicalLowSFromSequence");
        _ = PersonalAuthenticodeVerifier.RequireSha256Thumbprint(RequireMetadata(
            metadata,
            "PersonalAuthenticodeSignerSha256Thumbprint"));
        if (!Uri.TryCreate(manifestOrigin, UriKind.Absolute, out var manifestUri)
            || !Uri.TryCreate(artifactOrigin, UriKind.Absolute, out var artifactUri))
        {
            throw new InvalidOperationException(
                "Compiled Personal production update origins are invalid.");
        }
        RequireCanonicalOrigin(manifestUri, "manifest");
        var releaseKey = new PersonalReleasePublicKey(keyId, keyX, keyY);
        var validation = new PersonalReleaseTrustPolicy
        {
            Product = PersonalReleaseSetContract.Product,
            Environment = PersonalReleaseSetContract.ProductionEnvironment,
            Channel = "stable",
            ArtifactOrigin = artifactUri,
            StartupStubVersion = stubVersion,
            CanonicalLowSFromSequence = canonicalLowSFromSequence,
            TrustedKeys = [releaseKey],
        };
        validation.Validate();
        return new PersonalProductionTrust(
            manifestUri,
            artifactUri,
            releaseKey,
            stubVersion,
            canonicalLowSFromSequence);
    }

    private static string RequireMetadata(
        IReadOnlyDictionary<string, string?> metadata,
        string key) => metadata.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidOperationException(
                $"Production Personal update metadata '{key}' is not compiled into this build.");

    private static long RequirePositiveSafeIntegerMetadata(
        IReadOnlyDictionary<string, string?> metadata,
        string key)
    {
        var value = RequireMetadata(metadata, key);
        if (!long.TryParse(
                value,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var parsed)
            || parsed is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger)
        {
            throw new InvalidOperationException(
                $"Production Personal update metadata '{key}' is not a positive safe integer.");
        }
        return parsed;
    }

    private static void RequireCanonicalOrigin(Uri uri, string label)
    {
        if (!uri.IsAbsoluteUri
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || !string.Equals(uri.AbsolutePath, "/", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Compiled Personal {label} origin must be one canonical HTTPS origin.");
        }
    }

    private static void RequireDevelopmentGate()
    {
        if (!string.Equals(
                Environment.GetEnvironmentVariable(DevelopmentKeyGate),
                "1",
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Personal production update trust is unavailable and development trust is not enabled.");
        }
    }

    private sealed record PersonalProductionTrust(
        Uri ManifestOrigin,
        Uri ArtifactOrigin,
        PersonalReleasePublicKey ReleaseKey,
        string StartupStubVersion,
        long CanonicalLowSFromSequence);
}
