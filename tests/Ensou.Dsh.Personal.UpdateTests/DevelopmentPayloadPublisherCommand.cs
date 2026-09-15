using Ensou.Dsh.Contracts;
using Ensou.Dsh.Personal.ReleasePublisher;

namespace Ensou.Dsh.Personal.UpdateTests;

internal static class DevelopmentPayloadPublisherCommand
{
    private const string CommandName = "--development-payload-publish";
    private const string ConfigOption = "--config";
    private const string ConfigFileName = "publisher-config.json";
    private const string InitialReleaseSetId = "ci-personal-installer-v1";
    private const string RuntimeUpdateReleaseSetId = "ci-personal-update-v2";
    private const string ClientUpdateReleaseSetId = "ci-personal-update-v3";
    private const string SigningLedgerDirectoryName = "signing-ledger";
    private const string AnchorAuthorityDirectoryName =
        "signing-ledger-anchor-authority";

    public static async Task<int> RunAsync(string[] args)
    {
        try
        {
            if (args is not [CommandName, ConfigOption, var configPath])
            {
                throw new ArgumentException(
                    $"Usage: {CommandName} {ConfigOption} <absolute-config-path>");
            }
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException(
                    "The Personal development payload publisher requires Windows DPAPI.");
            }
            if (!Path.IsPathFullyQualified(configPath))
            {
                throw new ArgumentException(
                    "The Personal development publisher config path must be absolute.");
            }

            var fullConfigPath = Path.GetFullPath(configPath);
            if (!string.Equals(
                    Path.GetFileName(fullConfigPath),
                    ConfigFileName,
                    StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    $"The Personal development publisher config must be named {ConfigFileName}.");
            }
            var configInfo = new FileInfo(fullConfigPath);
            if (!configInfo.Exists
                || configInfo.Length is <= 0 or > 512 * 1024
                || (configInfo.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "The Personal development publisher config file is invalid.");
            }

            var config = PersonalReleasePublisherConfig.Parse(
                await File.ReadAllBytesAsync(fullConfigPath).ConfigureAwait(false));
            var workRoot = Path.GetDirectoryName(fullConfigPath)
                ?? throw new InvalidDataException(
                    "The Personal development publisher config has no work directory.");
            var expectedLedgerRoot = Path.Combine(
                workRoot,
                SigningLedgerDirectoryName);
            if (!string.Equals(
                    Path.GetFullPath(config.SigningLedgerRoot),
                    Path.GetFullPath(expectedLedgerRoot),
                    StringComparison.OrdinalIgnoreCase)
                || !string.Equals(
                    config.Environment,
                    PersonalReleaseSetContract.ProductionEnvironment,
                    StringComparison.Ordinal)
                || !string.Equals(config.Channel, "stable", StringComparison.Ordinal)
                || !IsAllowedReleaseIdentity(config)
                || !string.Equals(
                    config.ArtifactOrigin.AbsoluteUri,
                    "https://updates.example.test/",
                    StringComparison.Ordinal)
                || !string.Equals(
                    config.Provenance.HarnessSourceTag,
                    "dsh-ci-only",
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "The Personal development publisher config is outside the isolated CI contract.");
            }

            var anchorAuthorityRoot = Path.Combine(
                workRoot,
                AnchorAuthorityDirectoryName);
            _ = PersonalPublisherSigningLedger.InitializeAnchor(
                config,
                anchorAuthorityRoot);
            using var signingKey = await PersonalPrivateKeyLoader.LoadAsync(
                    config.SigningPrivateKeyPkcs8Path)
                .ConfigureAwait(false);
            var result = await new PersonalReleasePublisher(
                    ledgerCheckpoint: null,
                    ledgerAnchorAuthorityRoot: anchorAuthorityRoot)
                .PublishAsync(config, signingKey, DateTimeOffset.UtcNow)
                .ConfigureAwait(false);
            Console.WriteLine(
                $"PERSONAL-DEVELOPMENT-PAYLOAD-PUBLISH-PASS {result.Sha256}");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(
                $"Personal development payload publish failed closed: {exception.Message}");
            return 1;
        }
    }

    private static bool IsAllowedReleaseIdentity(PersonalReleasePublisherConfig config) =>
        string.Equals(config.ReleaseSetId, InitialReleaseSetId, StringComparison.Ordinal)
        || string.Equals(config.ReleaseSetId, RuntimeUpdateReleaseSetId, StringComparison.Ordinal)
            && config.Generation == 2
            && config.Sequence == 2
        || string.Equals(config.ReleaseSetId, ClientUpdateReleaseSetId, StringComparison.Ordinal)
            && config.Generation == 3
            && config.Sequence == 3;
}
