using System.Security.Cryptography;

namespace Ensou.Dsh.Personal.ReleasePublisher;

internal static class Program
{
    public static Task<int> Main(string[] args) => RunAsync(
        args,
        ledgerAnchorAuthorityRoot: null,
        Console.Out,
        Console.Error);

    internal static async Task<int> RunAsync(
        string[] args,
        string? ledgerAnchorAuthorityRoot,
        TextWriter output,
        TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        try
        {
            if (args is ["--check-signing-ledger-upgrade-ready", "--config", var readinessConfigPath])
            {
                var readinessConfig = PersonalReleasePublisherConfig.Parse(
                    await File.ReadAllBytesAsync(Path.GetFullPath(readinessConfigPath))
                        .ConfigureAwait(false));
                var readiness = PersonalPublisherSigningLedger
                    .CheckSigningLedgerUpgradeReady(
                        readinessConfig,
                        ledgerAnchorAuthorityRoot);
                await output.WriteLineAsync(readiness).ConfigureAwait(false);
                return 0;
            }

            if (args is ["--initialize-signing-ledger-anchor", "--config", var initializationConfigPath])
            {
                var initializationConfig = PersonalReleasePublisherConfig.Parse(
                    await File.ReadAllBytesAsync(Path.GetFullPath(initializationConfigPath))
                        .ConfigureAwait(false));
                var anchorPath = PersonalPublisherSigningLedger.InitializeAnchor(
                    initializationConfig,
                    ledgerAnchorAuthorityRoot);
                await output.WriteLineAsync(anchorPath).ConfigureAwait(false);
                return 0;
            }

            if (args.Length != 2 || !string.Equals(args[0], "--config", StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "Usage: Ensou.Dsh.Personal.ReleasePublisher --config <absolute-config-path> | "
                    + "--initialize-signing-ledger-anchor --config <absolute-config-path> | "
                    + "--check-signing-ledger-upgrade-ready --config <absolute-config-path>");
            }

            var configPath = Path.GetFullPath(args[1]);
            var config = PersonalReleasePublisherConfig.Parse(
                await File.ReadAllBytesAsync(configPath).ConfigureAwait(false));
            using var signingKey = await PersonalPrivateKeyLoader.LoadAsync(
                config.SigningPrivateKeyPkcs8Path).ConfigureAwait(false);
            var result = await new PersonalReleasePublisher(
                    ledgerCheckpoint: null,
                    ledgerAnchorAuthorityRoot)
                .PublishAsync(config, signingKey, DateTimeOffset.UtcNow)
                .ConfigureAwait(false);
            await output.WriteLineAsync(result.OutputManifestPath).ConfigureAwait(false);
            await output.WriteLineAsync(result.Sha256).ConfigureAwait(false);
            return 0;
        }
        catch (Exception exception)
        {
            await error.WriteLineAsync(exception.Message).ConfigureAwait(false);
            return 1;
        }
    }
}
