namespace Ensou.Dsh.Bootstrapper;

internal sealed record LauncherPointer(
    int SchemaVersion,
    string LauncherDirectory,
    string? PreviousLauncherDirectory,
    DateTimeOffset UpdatedAtUtc);
