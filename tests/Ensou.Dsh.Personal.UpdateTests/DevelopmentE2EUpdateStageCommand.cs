using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.Launcher;
using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.Personal.UpdateTests;
/// <summary>
/// Test-binary-only bridge for staging a real signed Personal update from a
/// local HTTPS fixture. It deliberately stops before health or activation.
/// </summary>
internal static class DevelopmentE2EUpdateStageCommand
{
    internal const string CommandName = "--development-e2e-stage-update";
    private const string ServerName = "updates.example.test";
    private const string Origin = "https://updates.example.test/";
    private const int HealthPort = 3080;
    private const int MinimumLoopbackPort = 49152;
    private const int MaximumConfigBytes = 512 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 32,
        NumberHandling = JsonNumberHandling.Strict,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = false,
    };
    internal static async Task<int> RunAsync(string[] args)
    {
        if (args is not [CommandName, var configPath])
        {
            Console.Error.WriteLine("PERSONAL_DEV_E2E_STAGE_USAGE");
            return 2;
        }
        try
        {
            var config = ReadConfig(configPath);
            var layout = PersonalInstallationLayout.CreateDevelopmentE2E(
                config.ManagedRoot,
                config.HarnessHome,
                config.UpdateSecurityWitnessPath);
            var settings = new LauncherSettings
            {
                Channel = config.TrustedPolicy.Channel,
                DshDataDirectory = layout.HarnessHome,
                Port = PersonalDevelopmentE2EHealthPort.Resolve(
                    HealthPort, developmentLayoutAdmitted: true),
                OpenWebUiAfterStart = false,
            };
            using var handler = CreateHandler(config);
            using var client = new HttpClient(handler, disposeHandler: true)
            {
                Timeout = TimeSpan.FromHours(2),
                DefaultRequestVersion = HttpVersion.Version11,
                DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
            };
            var outcome = await PersonalUpdateCoordinatorV2.CheckAsync(
                settings, layout, config.ManifestUri, config.TrustedPolicy,
                client, DateTimeOffset.UtcNow).ConfigureAwait(false);
            if (!outcome.UpdateAvailable)
            {
                throw new InvalidOperationException("The manifest does not describe an update.");
            }
            var acquired = await PersonalUpdateCoordinatorV2.DownloadAsync(
                layout, client, outcome).ConfigureAwait(false);
            var installed = await PersonalUpdateCoordinatorV2.StageAsync(
                settings, layout, outcome, acquired).ConfigureAwait(false);
            RequirePending(installed);
            Console.Out.WriteLine(JsonSerializer.Serialize(new StageSummary
            {
                SchemaVersion = 1,
                Status = "pending-health",
                ReleaseSetId = installed.Pointer.Current.ReleaseSetId,
                Sequence = installed.Pointer.Current.Sequence,
                ClientBundleReleaseId = installed.Pointer.Current.ClientBundle.ReleaseId,
                RuntimeReleaseId = installed.Pointer.Current.Runtime.ReleaseId,
                DownloadedComponents = Components(acquired, downloaded: true),
                ReusedComponents = Components(acquired, downloaded: false),
                HealthCommitted = false,
            }, JsonOptions));
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"PERSONAL_DEV_E2E_STAGE_FAILED:{exception.GetType().Name}");
            return 1;
        }
    }
    private static StageConfig ReadConfig(string path)
    {
        var configPath = PersonalDevelopmentE2ELayoutArguments.RequireCanonicalLocalPath(
            path, "configuration file", directory: false);
        if (!File.Exists(configPath))
        {
            throw new FileNotFoundException("Development E2E configuration is missing.");
        }
        var file = new FileInfo(configPath);
        if ((file.Attributes & FileAttributes.ReparsePoint) != 0
            || file.Length is <= 0 or > MaximumConfigBytes)
        {
            throw new InvalidDataException("Development E2E configuration file is unsafe.");
        }
        using var document = JsonDocument.Parse(File.ReadAllBytes(configPath), new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 32,
        });
        NoDuplicateProperties(document.RootElement);
        var config = document.RootElement.Deserialize<StageConfig>(JsonOptions)
            ?? throw new InvalidDataException("Development E2E configuration is empty.");
        if (config.SchemaVersion != 1)
        {
            throw new InvalidDataException("Development E2E configuration version is invalid.");
        }
        var root = PersonalDevelopmentE2ELayoutArguments.RequireCanonicalLocalPath(
            Path.GetDirectoryName(configPath)
                ?? throw new InvalidDataException("Configuration has no parent."),
            "isolation root", directory: true);
        var managed = StrictChild(root, config.ManagedRoot, "managed root", directory: true);
        var home = StrictChild(root, config.HarnessHome, "Harness home", directory: true);
        var witness = StrictChild(root, config.UpdateSecurityWitnessPath,
            "update-security witness", directory: false);
        Disjoint(managed, home, "managed root", "Harness home");
        Disjoint(managed, witness, "managed root", "update-security witness");
        Disjoint(home, witness, "Harness home", "update-security witness");
        config.TrustedPolicy.Validate();
        if (!string.Equals(config.TrustedPolicy.Environment,
                PersonalReleaseSetContract.ProductionEnvironment, StringComparison.Ordinal)
            || !string.Equals(config.TrustedPolicy.ArtifactOrigin.AbsoluteUri,
                Origin, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Development E2E trust policy scope is invalid.");
        }
        RequireManifestUri(config.ManifestUri, config.TrustedPolicy.Channel);
        if (config.LoopbackPort is < MinimumLoopbackPort or > ushort.MaxValue)
        {
            throw new InvalidDataException("Development E2E loopback port is not a high port.");
        }
        var certificateHash = RequireSha256(config.ExpectedTlsCertificateDerSha256);
        _ = Convert.FromHexString(certificateHash);
        return config with
        {
            ManagedRoot = managed,
            HarnessHome = home,
            UpdateSecurityWitnessPath = witness,
            ExpectedTlsCertificateDerSha256 = certificateHash.ToLowerInvariant(),
        };
    }

    private static SocketsHttpHandler CreateHandler(StageConfig config)
    {
        var expectedHash = Convert.FromHexString(config.ExpectedTlsCertificateDerSha256);
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            MaxConnectionsPerServer = 2,
            PooledConnectionLifetime = TimeSpan.Zero,
            UseCookies = false,
            UseProxy = false,
        };
        handler.ConnectCallback = async (context, cancellationToken) =>
        {
            if (!string.Equals(context.DnsEndPoint.Host, ServerName,
                    StringComparison.OrdinalIgnoreCase)
                || context.DnsEndPoint.Port != 443)
            {
                throw new HttpRequestException("Development E2E destination is not admitted.");
            }
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
            {
                NoDelay = true,
            };
            try
            {
                await socket.ConnectAsync(IPAddress.Loopback, config.LoopbackPort,
                    cancellationToken).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        };
        handler.SslOptions = new SslClientAuthenticationOptions
        {
            TargetHost = ServerName,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                CertificateMatches(certificate, expectedHash),
        };
        return handler;
    }

    private static bool CertificateMatches(X509Certificate? certificate, byte[] expectedHash)
    {
        if (certificate is null)
        {
            return false;
        }
        using var received = X509CertificateLoader.LoadCertificate(
            certificate.Export(X509ContentType.Cert));
        var now = DateTime.UtcNow;
        return CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(received.RawData), expectedHash)
            && now >= received.NotBefore.ToUniversalTime()
            && now <= received.NotAfter.ToUniversalTime()
            && received.MatchesHostname(ServerName,
                allowWildcards: false, allowCommonName: false);
    }

    private static void RequireManifestUri(Uri uri, string channel)
    {
        if (!uri.IsAbsoluteUri
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(uri.IdnHost, ServerName, StringComparison.OrdinalIgnoreCase)
            || uri.Port != 443
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || !string.Equals(uri.AbsolutePath,
                $"/v2/channels/{channel}/release-set.v2.json", StringComparison.Ordinal))
        {
            throw new InvalidDataException("Development E2E manifest URI is invalid.");
        }
    }

    private static string StrictChild(string root, string path, string label, bool directory)
    {
        var admitted = PersonalDevelopmentE2ELayoutArguments.RequireCanonicalLocalPath(
            path, label, directory);
        var prefix = Path.TrimEndingDirectorySeparator(root) + Path.DirectorySeparatorChar;
        if (!admitted.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"Development E2E {label} is outside the isolation root.");
        }
        if (!directory && File.Exists(admitted)
            && (File.GetAttributes(admitted) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException($"Development E2E {label} is a filesystem link.");
        }
        return admitted;
    }

    private static void Disjoint(string left, string right, string leftName, string rightName)
    {
        var leftPrefix = Path.TrimEndingDirectorySeparator(left) + Path.DirectorySeparatorChar;
        var rightPrefix = Path.TrimEndingDirectorySeparator(right) + Path.DirectorySeparatorChar;
        if (string.Equals(left, right, StringComparison.OrdinalIgnoreCase)
            || left.StartsWith(rightPrefix, StringComparison.OrdinalIgnoreCase)
            || right.StartsWith(leftPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"Development E2E {leftName} and {rightName} overlap.");
        }
    }

    private static string RequireSha256(string value)
    {
        if (value.Length != 64 || value.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new InvalidDataException("Development E2E TLS certificate hash is invalid.");
        }
        return value;
    }

    private static void NoDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidDataException("Configuration has duplicate properties.");
                }
                NoDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                NoDuplicateProperties(item);
            }
        }
    }

    private static void RequirePending(PersonalReleaseSetInstallationResult result)
    {
        if (result.Pointer.Current.HealthState != PersonalReleaseHealthStates.Pending
            || string.IsNullOrWhiteSpace(result.Pointer.Current.HealthToken))
        {
            throw new InvalidDataException("Stage did not produce a pending release.");
        }
    }

    private static IReadOnlyList<string> Components(PersonalAcquiredReleaseSet set, bool downloaded)
    {
        var result = new List<string>(2);
        Add("client-bundle", set.ClientBundle);
        Add("runtime", set.Runtime);
        return result;

        void Add(string name, PersonalReleaseArtifactSource source)
        {
            if ((source.ArchivePath is not null) == downloaded)
            {
                result.Add(name);
            }
        }
    }

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record StageConfig
    {
        public required int SchemaVersion { get; init; }
        public required string ManagedRoot { get; init; }
        public required string HarnessHome { get; init; }
        public required string UpdateSecurityWitnessPath { get; init; }
        public required Uri ManifestUri { get; init; }
        public required int LoopbackPort { get; init; }
        public required string ExpectedTlsCertificateDerSha256 { get; init; }
        public required PersonalReleaseTrustPolicy TrustedPolicy { get; init; }
    }

    private sealed record StageSummary
    {
        public required int SchemaVersion { get; init; }
        public required string Status { get; init; }
        public required string ReleaseSetId { get; init; }
        public required long Sequence { get; init; }
        public required string ClientBundleReleaseId { get; init; }
        public required string RuntimeReleaseId { get; init; }
        public required IReadOnlyList<string> DownloadedComponents { get; init; }
        public required IReadOnlyList<string> ReusedComponents { get; init; }
        public required bool HealthCommitted { get; init; }
    }
}
