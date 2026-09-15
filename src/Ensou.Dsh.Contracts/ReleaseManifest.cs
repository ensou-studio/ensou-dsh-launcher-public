namespace Ensou.Dsh.Contracts;

public enum ReleaseChannel
{
    Lab,
    Pilot,
    Stable,
}

public sealed record ReleaseArtifact
{
    public required string Url { get; init; }

    public required string FileName { get; init; }

    public required long SizeBytes { get; init; }

    public required string Sha256 { get; init; }
}

public sealed record ReleaseSignature
{
    public required string Algorithm { get; init; }

    public required string KeyId { get; init; }

    /// <summary>
    /// Base64url-encoded IEEE-P1363 signature bytes. Padding is not permitted.
    /// </summary>
    public required string Value { get; init; }
}

public sealed record ReleaseManifest
{
    public int SchemaVersion { get; init; } = 1;

    public required string ReleaseId { get; init; }

    public required ReleaseChannel Channel { get; init; }

    /// <summary>
    /// Minimum Launcher version that is allowed to install this DSH runtime artifact.
    /// Launcher itself is delivered through a separate Bootstrapper feed.
    /// </summary>
    public required string LauncherVersion { get; init; }

    public required string DshVersion { get; init; }

    public required DateTimeOffset PublishedAtUtc { get; init; }

    public required string MinimumBootstrapperVersion { get; init; }

    public required ReleaseArtifact Artifact { get; init; }

    /// <summary>
    /// Excluded from the canonical payload. It is required for a distributable manifest.
    /// </summary>
    public ReleaseSignature? Signature { get; init; }
}

public sealed record VerifiedReleaseManifest(
    ReleaseManifest Manifest,
    string KeyId,
    string Algorithm,
    string CanonicalPayloadSha256);
