namespace Ensou.Dsh.Launcher;

internal sealed record UpdateCheckOutcome(
    string Title,
    string Detail,
    string AvailableVersion,
    bool UpdateAvailable,
    string ReleaseId,
    string ArtifactUrl,
    string ArtifactFileName,
    long ArtifactSizeBytes,
    string ArtifactSha256);
