using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.UpdateEngine;

public sealed record InstalledReleaseState
{
    public string? ReleaseId { get; init; }

    public string? LauncherVersion { get; init; }

    public string? DshVersion { get; init; }

    public required string BootstrapperVersion { get; init; }

    public IReadOnlyCollection<string> BlockedReleaseIds { get; init; } = Array.Empty<string>();
}

public enum ReleaseStateDisposition
{
    InstallRequired,
    Current,
    UpdateAvailable,
    ReplacementAvailable,
    LauncherUpdateRequired,
    BootstrapperUpdateRequired,
    DowngradeBlocked,
    Blocked,
}

public sealed record ReleaseStateComparison(
    ReleaseStateDisposition Disposition,
    bool ShouldInstallTarget,
    bool CanLaunchCurrent,
    string Reason);

public static class ReleaseStateComparer
{
    public static ReleaseStateComparison Compare(
        InstalledReleaseState state,
        ReleaseManifest target)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(target);
        ReleaseManifestValidator.ValidateAndThrow(target);

        if (state.BlockedReleaseIds?.Contains(target.ReleaseId, StringComparer.Ordinal) == true)
        {
            return Result(
                ReleaseStateDisposition.Blocked,
                shouldInstall: false,
                canLaunch: HasActiveRuntime(state),
                "Target release is blocked on this machine.");
        }

        var bootstrapperComparison = CompareVersionStrings(
            state.BootstrapperVersion,
            target.MinimumBootstrapperVersion);
        if (bootstrapperComparison < 0)
        {
            return Result(
                ReleaseStateDisposition.BootstrapperUpdateRequired,
                shouldInstall: false,
                canLaunch: HasActiveRuntime(state),
                "Bootstrapper must update before this release can be installed.");
        }

        if (string.IsNullOrWhiteSpace(state.LauncherVersion))
        {
            throw new ArgumentException("Installed Launcher version is required.", nameof(state));
        }

        if (CompareVersionStrings(state.LauncherVersion, target.LauncherVersion) < 0)
        {
            return Result(
                ReleaseStateDisposition.LauncherUpdateRequired,
                shouldInstall: false,
                canLaunch: HasActiveRuntime(state),
                "Launcher must update through Bootstrapper before this DSH runtime can be installed.");
        }

        if (!HasActiveRuntime(state))
        {
            if (state.ReleaseId is not null || state.DshVersion is not null)
            {
                throw new ArgumentException("Installed DSH runtime state is incomplete.", nameof(state));
            }

            return Result(
                ReleaseStateDisposition.InstallRequired,
                shouldInstall: true,
                canLaunch: false,
                "No active release is installed.");
        }

        if (string.IsNullOrWhiteSpace(state.ReleaseId) ||
            string.IsNullOrWhiteSpace(state.DshVersion))
        {
            throw new ArgumentException("Installed DSH runtime state is incomplete.", nameof(state));
        }

        var dshComparison = CompareVersionStrings(target.DshVersion, state.DshVersion);
        if (dshComparison < 0)
        {
            return Result(
                ReleaseStateDisposition.DowngradeBlocked,
                shouldInstall: false,
                canLaunch: true,
                "Automatic downgrade is blocked.");
        }

        if (dshComparison > 0)
        {
            return Result(
                ReleaseStateDisposition.UpdateAvailable,
                shouldInstall: true,
                canLaunch: true,
                "A newer Harness runtime is available.");
        }

        if (string.Equals(state.ReleaseId, target.ReleaseId, StringComparison.Ordinal))
        {
            return Result(
                ReleaseStateDisposition.Current,
                shouldInstall: false,
                canLaunch: true,
                "Installed release matches the target release.");
        }

        return Result(
            ReleaseStateDisposition.ReplacementAvailable,
            shouldInstall: true,
            canLaunch: true,
            "A different signed release packages the same component versions.");
    }

    public static int CompareVersionStrings(string left, string right)
    {
        var leftVersion = ReleaseVersion.Parse(left, nameof(left));
        var rightVersion = ReleaseVersion.Parse(right, nameof(right));
        return leftVersion.CompareTo(rightVersion);
    }

    private static bool HasActiveRuntime(InstalledReleaseState state) =>
        state.ReleaseId is not null && state.DshVersion is not null;

    private static ReleaseStateComparison Result(
        ReleaseStateDisposition disposition,
        bool shouldInstall,
        bool canLaunch,
        string reason) =>
        new(disposition, shouldInstall, canLaunch, reason);

    private sealed class ReleaseVersion : IComparable<ReleaseVersion>
    {
        private ReleaseVersion(ulong[] core, string[] prerelease)
        {
            Core = core;
            Prerelease = prerelease;
        }

        private ulong[] Core { get; }

        private string[] Prerelease { get; }

        public static ReleaseVersion Parse(string value, string parameterName)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
            if (value.Length > 128)
            {
                throw new ArgumentException("Version is too long.", parameterName);
            }

            var withoutMetadata = value.Split('+', 2)[0];
            var versionParts = withoutMetadata.Split('-', 2);
            var coreText = versionParts[0];
            var prerelease = versionParts.Length == 2
                ? versionParts[1].Split('.', StringSplitOptions.None)
                : Array.Empty<string>();
            var coreParts = coreText.Split('.', StringSplitOptions.None);
            if (coreParts.Length is < 2 or > 4 || prerelease.Any(string.IsNullOrEmpty))
            {
                throw new ArgumentException("Version format is invalid.", parameterName);
            }

            var core = new ulong[coreParts.Length];
            for (var index = 0; index < coreParts.Length; index++)
            {
                if (!ulong.TryParse(coreParts[index], out core[index]))
                {
                    throw new ArgumentException("Version numeric component is invalid.", parameterName);
                }
            }

            if (prerelease.Any(x => x.Any(character =>
                    !(char.IsAsciiLetterOrDigit(character) || character == '-'))))
            {
                throw new ArgumentException("Version prerelease component is invalid.", parameterName);
            }

            return new ReleaseVersion(core, prerelease);
        }

        public int CompareTo(ReleaseVersion? other)
        {
            if (other is null)
            {
                return 1;
            }

            var componentCount = Math.Max(Core.Length, other.Core.Length);
            for (var index = 0; index < componentCount; index++)
            {
                var left = index < Core.Length ? Core[index] : 0;
                var right = index < other.Core.Length ? other.Core[index] : 0;
                var comparison = left.CompareTo(right);
                if (comparison != 0)
                {
                    return comparison;
                }
            }

            if (Prerelease.Length == 0 && other.Prerelease.Length == 0)
            {
                return 0;
            }

            if (Prerelease.Length == 0)
            {
                return 1;
            }

            if (other.Prerelease.Length == 0)
            {
                return -1;
            }

            var prereleaseCount = Math.Max(Prerelease.Length, other.Prerelease.Length);
            for (var index = 0; index < prereleaseCount; index++)
            {
                if (index >= Prerelease.Length)
                {
                    return -1;
                }

                if (index >= other.Prerelease.Length)
                {
                    return 1;
                }

                var comparison = ComparePrerelease(Prerelease[index], other.Prerelease[index]);
                if (comparison != 0)
                {
                    return comparison;
                }
            }

            return 0;
        }

        private static int ComparePrerelease(string left, string right)
        {
            var leftIsNumeric = ulong.TryParse(left, out var leftNumber);
            var rightIsNumeric = ulong.TryParse(right, out var rightNumber);
            if (leftIsNumeric && rightIsNumeric)
            {
                return leftNumber.CompareTo(rightNumber);
            }

            if (leftIsNumeric)
            {
                return -1;
            }

            if (rightIsNumeric)
            {
                return 1;
            }

            return string.Compare(left, right, StringComparison.Ordinal);
        }
    }
}
