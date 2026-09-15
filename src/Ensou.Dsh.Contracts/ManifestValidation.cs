using System.Text.RegularExpressions;

namespace Ensou.Dsh.Contracts;

public sealed record ManifestValidationError(string Path, string Code, string Message);

public sealed class ManifestValidationException : Exception
{
    public ManifestValidationException(IReadOnlyList<ManifestValidationError> errors)
        : base(CreateMessage(errors))
    {
        Errors = errors;
    }

    public IReadOnlyList<ManifestValidationError> Errors { get; }

    private static string CreateMessage(IReadOnlyList<ManifestValidationError> errors) =>
        errors.Count == 0
            ? "The release manifest is invalid."
            : $"The release manifest is invalid: {string.Join("; ", errors.Select(x => $"{x.Path}: {x.Message}"))}";
}

public static partial class ReleaseManifestValidator
{
    private const long MaximumArtifactSize = 8L * 1024 * 1024 * 1024;

    public static IReadOnlyList<ManifestValidationError> Validate(
        ReleaseManifest? manifest,
        bool requireSignature = true)
    {
        var errors = new List<ManifestValidationError>();
        if (manifest is null)
        {
            errors.Add(new("$", "required", "Manifest is required."));
            return errors;
        }

        if (manifest.SchemaVersion != 1)
        {
            errors.Add(new("$.schemaVersion", "unsupported", "Only schema version 1 is supported."));
        }

        if (string.IsNullOrWhiteSpace(manifest.ReleaseId) ||
            !ReleaseIdPattern().IsMatch(manifest.ReleaseId))
        {
            errors.Add(new(
                "$.releaseId",
                "format",
                "Release id must use managed-vYYYY.MM.DD.N with a positive sequence."));
        }

        if (!Enum.IsDefined(manifest.Channel))
        {
            errors.Add(new("$.channel", "enum", "Channel is unknown."));
        }

        ValidateVersion(manifest.LauncherVersion, "$.launcherVersion", errors);
        ValidateVersion(manifest.DshVersion, "$.dshVersion", errors);
        ValidateVersion(manifest.MinimumBootstrapperVersion, "$.minimumBootstrapperVersion", errors);

        if (manifest.PublishedAtUtc == default)
        {
            errors.Add(new("$.publishedAtUtc", "required", "Publication time is required."));
        }
        else if (manifest.PublishedAtUtc.Offset != TimeSpan.Zero)
        {
            errors.Add(new("$.publishedAtUtc", "utc", "Publication time must use the UTC offset."));
        }

        ValidateArtifact(manifest.Artifact, errors);
        ValidateSignature(manifest.Signature, requireSignature, errors);
        return errors;
    }

    public static void ValidateAndThrow(ReleaseManifest? manifest, bool requireSignature = true)
    {
        var errors = Validate(manifest, requireSignature);
        if (errors.Count != 0)
        {
            throw new ManifestValidationException(errors);
        }
    }

    private static void ValidateArtifact(
        ReleaseArtifact? artifact,
        List<ManifestValidationError> errors)
    {
        if (artifact is null)
        {
            errors.Add(new("$.artifact", "required", "Artifact is required."));
            return;
        }

        if (!Uri.TryCreate(artifact.Url, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Fragment) ||
            artifact.Url.Any(character =>
                !char.IsAscii(character) ||
                character <= ' ' ||
                character is '"' or '\\'))
        {
            errors.Add(new(
                "$.artifact.url",
                "format",
                "Artifact URL must be printable ASCII HTTPS without user information, a fragment, quotes, or backslashes."));
        }

        if (string.IsNullOrWhiteSpace(artifact.FileName) ||
            artifact.FileName.Length > 180 ||
            !ArtifactFileNamePattern().IsMatch(artifact.FileName))
        {
            errors.Add(new("$.artifact.fileName", "format", "Artifact file name must be one safe path segment."));
        }

        if (artifact.SizeBytes <= 0 || artifact.SizeBytes > MaximumArtifactSize)
        {
            errors.Add(new(
                "$.artifact.sizeBytes",
                "range",
                "Artifact size must be between 1 byte and 8 GiB."));
        }

        if (string.IsNullOrEmpty(artifact.Sha256) || !Sha256Pattern().IsMatch(artifact.Sha256))
        {
            errors.Add(new(
                "$.artifact.sha256",
                "format",
                "SHA-256 must contain exactly 64 lowercase hexadecimal characters."));
        }
    }

    private static void ValidateSignature(
        ReleaseSignature? signature,
        bool required,
        List<ManifestValidationError> errors)
    {
        if (signature is null)
        {
            if (required)
            {
                errors.Add(new("$.signature", "required", "Signature is required."));
            }

            return;
        }

        if (!string.Equals(signature.Algorithm, ReleaseManifestSignature.Algorithm, StringComparison.Ordinal))
        {
            errors.Add(new("$.signature.algorithm", "unsupported", "Only ES256 is supported."));
        }

        if (string.IsNullOrWhiteSpace(signature.KeyId) ||
            !KeyIdPattern().IsMatch(signature.KeyId))
        {
            errors.Add(new("$.signature.keyId", "format", "Signature key id is invalid."));
        }

        if (string.IsNullOrWhiteSpace(signature.Value) ||
            signature.Value.Length != 86 ||
            !Base64UrlPattern().IsMatch(signature.Value))
        {
            errors.Add(new(
                "$.signature.value",
                "format",
                "ES256 signature must be an unpadded base64url value encoding 64 bytes."));
        }
    }

    private static void ValidateVersion(
        string? value,
        string path,
        List<ManifestValidationError> errors)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 128 || !VersionPattern().IsMatch(value))
        {
            errors.Add(new(
                path,
                "format",
                "Version must use numeric dot-separated components with optional prerelease/build metadata."));
        }
    }

    [GeneratedRegex(
        "^managed-v[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}\\.[1-9][0-9]*$",
        RegexOptions.CultureInvariant)]
    private static partial Regex ReleaseIdPattern();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex KeyIdPattern();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]*$", RegexOptions.CultureInvariant)]
    private static partial Regex ArtifactFileNamePattern();

    [GeneratedRegex("^[A-Za-z0-9_-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex Base64UrlPattern();

    [GeneratedRegex(
        "^[0-9]+\\.[0-9]+\\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$",
        RegexOptions.CultureInvariant)]
    private static partial Regex VersionPattern();

    [GeneratedRegex("^[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256Pattern();
}
