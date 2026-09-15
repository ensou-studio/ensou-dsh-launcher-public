namespace Ensou.Dsh.Enterprise.Installation;

public static class EnterpriseInstallerArgumentPolicy
{
    private static readonly string[] DevelopmentOnlyOptions =
    [
        "--dev-unsigned",
        "--dev-e2e-layout",
        "--dev-e2e-no-shell-registration",
        "--dev-e2e-local-app-data-root",
        "--dev-e2e-user-profile-root",
        "--payload",
    ];

    public static void EnsureBuildAllowsDevelopmentOptions(
        IReadOnlyList<string> args,
        bool developmentE2EEnabled)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (developmentE2EEnabled)
        {
            return;
        }

        foreach (var argument in args)
        {
            if (DevelopmentOnlyOptions.Contains(argument, StringComparer.Ordinal))
            {
                throw new ArgumentException(
                    "Development E2E options are not available in the production Installer.");
            }
        }
    }

    /// <summary>
    /// Resolves the adjacent payload convenience used only by Development-E2E bundles.
    /// Production builds must never infer an external payload from a double-click.
    /// </summary>
    public static bool TryInferAdjacentDevelopmentPayload(
        IReadOnlyList<string> args,
        bool developmentE2EEnabled,
        string baseDirectory,
        out string? payloadDirectory)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentException.ThrowIfNullOrWhiteSpace(baseDirectory);
        payloadDirectory = null;
        if (!developmentE2EEnabled || args.Count != 0)
        {
            return false;
        }

        var adjacentPayload = Path.GetFullPath(
            Path.Combine(baseDirectory, "payload"));
        if (!Directory.Exists(adjacentPayload))
        {
            return false;
        }

        payloadDirectory = adjacentPayload;
        return true;
    }
}
